// api_request: make an authenticated HTTPS request using a stored secret, entirely server-side.
// The model supplies the secret NAME; the Worker reads the value from Infisical, injects it, calls the API
// and returns only the response (with the secret redacted). A secret can only be sent to the hosts in its own
// comment (`hosts: ...`), which are fixed when it is created (see hosts.ts), so a prompt-injected client
// cannot point an existing token at an attacker's server.
import { AwsClient } from "aws4fetch";
import { commentHosts } from "./hosts";
import { infisical } from "./infisical";
import { extensionFor, fetchStored, MAX_STORED_BYTES, saveStored, uploadsConfigured, type UploadEnv } from "./uploads";

export interface ApiCallEnv extends UploadEnv {
  INFISICAL_HOST: string;
  INFISICAL_CLIENT_ID: string;
  INFISICAL_CLIENT_SECRET: string;
  INFISICAL_PROJECT_ID: string;
  DEFAULT_ENVIRONMENT: string;
}

export interface ApiCallArgs {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: unknown;
  body_base64?: string; // raw binary request body (e.g. PUT an object to S3)
  body_source?: string; // a file stored by get_upload_url (its download URL or key): the Worker reads it and sends it as the raw body
  multipart?: { fields?: Record<string, string>; files: { field?: string; filename?: string; content_type?: string; data_base64?: string; source?: string }[] };
  auth_type?: "bearer" | "header" | "basic" | "query" | "aws_sigv4";
  secret?: string;
  header_name?: string;
  header_prefix?: string;
  query_param?: string;
  username?: string;
  aws_service?: string;
  aws_region?: string;
  aws_access_key_secret?: string;
  aws_secret_key_secret?: string;
  aws_session_token_secret?: string;
  save_response?: boolean; // store a 2xx response body in R2 and return a download URL instead of the body (e.g. generated audio)
  environment?: string;
  path?: string;
}

const MAX_BODY = 60_000;
const MAX_UPLOAD = 5 * 1024 * 1024; // decoded bytes, per request
const TIMEOUT_MS = 25_000;
const KEEP_HEADERS = ["content-type", "link", "location", "retry-after", "etag", "x-request-id", "x-amzn-requestid", "x-ratelimit-remaining", "x-ratelimit-reset"];

// Approved hosts for a secret: only what its own comment says (`hosts: a.com, *.b.com`).
export function approvedHosts(comment?: string | null): string[] {
  return commentHosts(comment);
}

export function hostAllowed(host: string, patterns: string[] | undefined): boolean {
  if (!patterns || patterns.length === 0) return false;
  const h = host.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.toLowerCase();
    return p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p;
  });
}

// Read a response body, refusing more than cap bytes without buffering the rest.
async function readCapped(res: Response, cap: number): Promise<Uint8Array> {
  const tooBig = () => new Error(`Response is too large to save (max ${cap / 1024 / 1024} MB)`);
  if (Number(res.headers.get("content-length") ?? 0) > cap) { await res.body?.cancel(); throw tooBig(); }
  const reader = res.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > cap) { await reader.cancel(); throw tooBig(); }
    chunks.push(value);
  }
  const out = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.length; }
  return out;
}

function containsBytes(hay: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return false;
  for (let i = hay.indexOf(needle[0]); i !== -1 && i <= hay.length - needle.length; i = hay.indexOf(needle[0], i + 1)) {
    let j = 1;
    while (j < needle.length && hay[i + j] === needle[j]) j++;
    if (j === needle.length) return true;
  }
  return false;
}

// filename="x.mp3" or filename*=UTF-8''x.mp3
function dispositionName(v: string | null): string | undefined {
  const m = v?.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
  if (!m) return undefined;
  try { return decodeURIComponent(m[1]); } catch { return m[1]; }
}

function decodeBase64(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, "");
  if (Math.floor((clean.length * 3) / 4) > MAX_UPLOAD + 3) throw new Error(`Upload too large (max ${MAX_UPLOAD / 1024 / 1024} MB)`);
  let bin: string;
  try { bin = atob(clean); } catch { throw new Error("data is not valid base64"); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function callApi(env: ApiCallEnv, a: ApiCallArgs): Promise<unknown> {
  const url = new URL(a.url);
  if (url.protocol !== "https:") throw new Error("Only https:// URLs are allowed");
  if (url.username || url.password) throw new Error("Credentials in the URL are not allowed");
  if (url.port && url.port !== "443") throw new Error("Only the default HTTPS port is allowed");
  for (const [k, v] of Object.entries(a.query ?? {})) url.searchParams.set(k, v);

  const method = (a.method ?? "GET").toUpperCase();
  const authType = a.auth_type ?? "bearer";
  const scope = { projectId: env.INFISICAL_PROJECT_ID, environment: a.environment ?? env.DEFAULT_ENVIRONMENT };
  const used: string[] = []; // secret values, for redaction
  const read = async (name: string) => {
    // No path given: find the secret by name in any folder, but never guess between several.
    let secretPath = a.path;
    if (secretPath === undefined) {
      const paths = await infisical.findSecretPaths(env, name, scope);
      if (paths.length === 0) throw new Error(`Secret ${name} not found in environment ${scope.environment}`);
      if (paths.length > 1) throw new Error(`Secret ${name} exists in several folders (${paths.join(", ")}); pass path to choose one`);
      secretPath = paths[0];
    }
    const secret = await infisical.getSecretValue(env, name, { ...scope, secretPath });
    const approved = approvedHosts(secret.comment);
    if (!hostAllowed(url.hostname, approved)) {
      throw new Error(
        `Secret ${name} is not allowed to be sent to ${url.hostname}. ` +
        (approved.length ? `Approved hosts for it: ${approved.join(", ")}. ` : "No hosts are approved for it. ") +
        "Hosts come from the secret's comment (a 'hosts: ...' line), are set when the secret is stored (add_secret hosts) and cannot be changed through this server; the owner can edit the comment in Infisical.",
      );
    }
    used.push(secret.value);
    return secret.value;
  };

  const headers = new Headers(a.headers ?? {});
  for (const h of ["host", "content-length", "connection", "proxy-authorization", "cookie"]) headers.delete(h);
  // A POST that an API treats as DELETE would dodge the approval required for DELETE.
  for (const h of ["x-http-method-override", "x-method-override", "x-http-method"]) {
    if (headers.has(h)) throw new Error(`The ${h} header is not allowed`);
  }

  if (a.save_response) {
    // Checked before the call, so a paid API (e.g. text-to-speech) is not charged for output that cannot be kept.
    if (!uploadsConfigured(env)) throw new Error("File storage is not set up on this server, so save_response cannot be used (see get_upload_url for the setup steps)");
    if (method === "HEAD") throw new Error("save_response needs a response body; HEAD has none");
  }

  const given = [a.body !== undefined && a.body !== null, !!a.body_base64, !!a.body_source, !!a.multipart].filter(Boolean).length;
  if (given > 1) throw new Error("Send only one of body, body_base64, body_source, multipart");
  let body: string | Uint8Array | FormData | undefined;
  let uploadBytes = 0;
  if (a.body !== undefined && a.body !== null) {
    if (typeof a.body === "string") body = a.body;
    else {
      body = JSON.stringify(a.body);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
  } else if (a.body_base64) {
    body = decodeBase64(a.body_base64);
    uploadBytes = body.length;
  } else if (a.body_source) {
    const f = await fetchStored(env, a.body_source);
    body = f.bytes;
    uploadBytes = f.bytes.length;
    if (!headers.has("content-type")) headers.set("content-type", f.contentType);
  } else if (a.multipart) {
    if (a.auth_type === "aws_sigv4") throw new Error("multipart is not supported with aws_sigv4; use body_base64");
    const fd = new FormData();
    for (const [k, v] of Object.entries(a.multipart.fields ?? {})) fd.append(k, v);
    for (const f of a.multipart.files) {
      if (!!f.data_base64 === !!f.source) throw new Error("Each file needs exactly one of data_base64 or source");
      let bytes: Uint8Array, type = f.content_type, name = f.filename;
      if (f.source) {
        const st = await fetchStored(env, f.source);
        bytes = st.bytes; type ??= st.contentType; name ??= st.name;
      } else {
        bytes = decodeBase64(f.data_base64!);
      }
      if (!name) throw new Error("filename is required with data_base64");
      uploadBytes += bytes.length;
      const cap = a.multipart.files.some((x) => x.source) ? MAX_STORED_BYTES : MAX_UPLOAD;
      if (uploadBytes > cap) throw new Error(`Upload too large (max ${cap / 1024 / 1024} MB in total)`);
      fd.append(f.field ?? "file", new Blob([bytes], { type: type ?? "application/octet-stream" }), name);
    }
    headers.delete("content-type"); // fetch sets multipart/form-data with the boundary
    body = fd;
  }

  const need = (v: string | undefined, what: string) => {
    if (!v) throw new Error(`${what} is required for auth_type=${authType}`);
    return v;
  };
  const injected = (name: string) => {
    if (headers.has(name)) throw new Error(`Do not send your own ${name} header; it is set from the secret`);
  };

  let req: Request;
  if (authType === "aws_sigv4") {
    const accessKey = await read(a.aws_access_key_secret ?? "AWS_ACCESS_KEY_ID");
    const secretKey = await read(a.aws_secret_key_secret ?? "AWS_SECRET_ACCESS_KEY");
    const tokenName = a.aws_session_token_secret ?? "AWS_SESSION_TOKEN";
    let sessionToken: string | undefined;
    try { sessionToken = await read(tokenName); } catch { /* optional; also skipped if not approved for this host */ }
    const client = new AwsClient({
      accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken,
      service: need(a.aws_service, "aws_service"), region: need(a.aws_region, "aws_region"),
    });
    req = await client.sign(url.toString(), { method, headers, body: body as BodyInit | undefined });
  } else {
    const value = await read(need(a.secret, "secret"));
    if (authType === "bearer") { injected("authorization"); headers.set("authorization", `Bearer ${value}`); }
    else if (authType === "header") {
      const name = need(a.header_name, "header_name");
      injected(name.toLowerCase());
      headers.set(name, a.header_prefix ? `${a.header_prefix} ${value}` : value);
    } else if (authType === "basic") {
      injected("authorization");
      const cred = a.username !== undefined ? `${a.username}:${value}` : value;
      if (!cred.includes(":")) throw new Error("basic auth needs 'user:password' in the secret, or pass username with the password as the secret");
      headers.set("authorization", `Basic ${btoa(cred)}`);
      used.push(btoa(cred));
    } else if (authType === "query") {
      url.searchParams.set(need(a.query_param, "query_param"), value);
    } else throw new Error(`Unknown auth_type ${authType}`);
    req = new Request(url.toString(), { method, headers, body: method === "GET" || method === "HEAD" ? undefined : (body as BodyInit | undefined) });
  }

  // Never follow redirects: the next hop could be a host the secret is not bound to.
  const res = await fetch(req, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
  const redact = (s: string) => used.filter((u) => u.length >= 6).reduce((t, u) => t.split(u).join("[REDACTED]"), s);
  const out: Record<string, string> = {};
  for (const k of KEEP_HEADERS) { const v = res.headers.get(k); if (v) out[k] = redact(v); }

  if (a.save_response && res.ok) {
    const bytes = await readCapped(res, MAX_STORED_BYTES);
    // Binary output cannot be redacted without corrupting it, so a response that carries the credential is not stored at all.
    const enc = new TextEncoder();
    if (used.some((u) => u.length >= 6 && containsBytes(bytes, enc.encode(u)))) throw new Error("The response contains the credential itself, so it was not saved");
    const contentType = (res.headers.get("content-type") ?? "application/octet-stream").slice(0, 200);
    const filename = dispositionName(res.headers.get("content-disposition")) ?? `response.${extensionFor(contentType)}`;
    const saved = await saveStored(env, bytes, { filename, contentType });
    console.log(JSON.stringify({ api_request: { host: url.hostname, method, status: res.status, auth: authType, upload_bytes: uploadBytes || undefined, saved_bytes: bytes.length } }));
    return { status: res.status, ok: res.ok, headers: out, saved };
  }

  const text = await res.text();
  console.log(JSON.stringify({ api_request: { host: url.hostname, method, status: res.status, auth: authType, upload_bytes: uploadBytes || undefined } }));
  return {
    status: res.status,
    ok: res.ok,
    headers: out,
    body: redact(text.length > MAX_BODY ? text.slice(0, MAX_BODY) : text),
    truncated: text.length > MAX_BODY,
    ...(res.status >= 300 && res.status < 400 ? { note: "Redirects are not followed; call the Location URL explicitly if its host is allowed." } : {}),
    ...(a.save_response && !res.ok ? { not_saved: "The API did not return a success status, so its body is shown instead of being saved." } : {}),
  };
}
