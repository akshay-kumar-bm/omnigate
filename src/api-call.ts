// api_request: make an authenticated HTTPS request using a stored secret, entirely server-side.
// The model supplies the secret NAME; the Worker reads the value from Infisical, injects it, calls the API
// and returns only the response (with the secret redacted). A secret can only be sent to hosts approved for it:
// the built-in list (default-hosts.ts) plus the API_HOSTS config var, both changeable only by the Worker owner
// (redeploy), so a prompt-injected client cannot point a token at an attacker's server.
import { AwsClient } from "aws4fetch";
import { commentHosts, DEFAULT_API_HOSTS } from "./default-hosts";
import { infisical } from "./infisical";

export interface ApiCallEnv {
  INFISICAL_HOST: string;
  INFISICAL_CLIENT_ID: string;
  INFISICAL_CLIENT_SECRET: string;
  INFISICAL_PROJECT_ID: string;
  DEFAULT_ENVIRONMENT: string;
  API_HOSTS: string; // JSON overrides/additions to the built-in list: { "SECRET_NAME": ["api.example.com", "*.example.com"] }
}

export interface ApiCallArgs {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: unknown;
  body_base64?: string; // raw binary request body (e.g. PUT an object to S3)
  multipart?: { fields?: Record<string, string>; files: { field?: string; filename: string; content_type?: string; data_base64: string }[] };
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
  environment?: string;
  path?: string;
}

const MAX_BODY = 60_000;
const MAX_UPLOAD = 5 * 1024 * 1024; // decoded bytes, per request
const TIMEOUT_MS = 25_000;
const KEEP_HEADERS = ["content-type", "link", "location", "retry-after", "etag", "x-request-id", "x-amzn-requestid", "x-ratelimit-remaining", "x-ratelimit-reset"];

function parseHosts(env: ApiCallEnv): Record<string, unknown> {
  try {
    const m = JSON.parse(env.API_HOSTS || "{}");
    return m && typeof m === "object" && !Array.isArray(m) ? m : {};
  } catch {
    throw new Error("API_HOSTS config is not valid JSON");
  }
}

// Approved hosts for a secret. An API_HOSTS entry for the name wins outright ([] disables everything for it);
// otherwise the built-in list plus the hosts in the secret's own comment.
export function approvedHosts(env: ApiCallEnv, name: string, comment?: string | null): string[] {
  const custom = parseHosts(env);
  const own = (o: object) => Object.prototype.hasOwnProperty.call(o, name);
  if (own(custom)) {
    const v = custom[name];
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  }
  return [...new Set([...(own(DEFAULT_API_HOSTS) ? DEFAULT_API_HOSTS[name] : []), ...commentHosts(comment)])];
}

export function hostAllowed(host: string, patterns: string[] | undefined): boolean {
  if (!patterns || patterns.length === 0) return false;
  const h = host.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.toLowerCase();
    return p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p;
  });
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
  const loc = { projectId: env.INFISICAL_PROJECT_ID, environment: a.environment ?? env.DEFAULT_ENVIRONMENT, secretPath: a.path ?? "/" };
  const used: string[] = []; // secret values, for redaction
  const read = async (name: string) => {
    const secret = await infisical.getSecretValue(env, name, loc);
    const approved = approvedHosts(env, name, secret.comment);
    if (!hostAllowed(url.hostname, approved)) {
      throw new Error(
        `Secret ${name} is not allowed to be sent to ${url.hostname}. ` +
        (approved.length ? `Approved hosts for it: ${approved.join(", ")}. ` : "No hosts are approved for it. ") +
        "Hosts are set when the secret is stored (add_secret hosts) and cannot be changed through this server; the owner can edit the secret's comment in Infisical or add an API_HOSTS entry.",
      );
    }
    used.push(secret.value);
    return secret.value;
  };

  const headers = new Headers(a.headers ?? {});
  for (const h of ["host", "content-length", "connection", "proxy-authorization", "cookie"]) headers.delete(h);

  const given = [a.body !== undefined && a.body !== null, !!a.body_base64, !!a.multipart].filter(Boolean).length;
  if (given > 1) throw new Error("Send only one of body, body_base64, multipart");
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
  } else if (a.multipart) {
    if (a.auth_type === "aws_sigv4") throw new Error("multipart is not supported with aws_sigv4; use body_base64");
    const fd = new FormData();
    for (const [k, v] of Object.entries(a.multipart.fields ?? {})) fd.append(k, v);
    for (const f of a.multipart.files) {
      const bytes = decodeBase64(f.data_base64);
      uploadBytes += bytes.length;
      if (uploadBytes > MAX_UPLOAD) throw new Error(`Upload too large (max ${MAX_UPLOAD / 1024 / 1024} MB in total)`);
      fd.append(f.field ?? "file", new Blob([bytes], { type: f.content_type ?? "application/octet-stream" }), f.filename);
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
  const text = await res.text();
  const out: Record<string, string> = {};
  for (const k of KEEP_HEADERS) { const v = res.headers.get(k); if (v) out[k] = redact(v); }
  console.log(JSON.stringify({ api_request: { host: url.hostname, method, status: res.status, auth: authType, upload_bytes: uploadBytes || undefined } }));
  return {
    status: res.status,
    ok: res.ok,
    headers: out,
    body: redact(text.length > MAX_BODY ? text.slice(0, MAX_BODY) : text),
    truncated: text.length > MAX_BODY,
    ...(res.status >= 300 && res.status < 400 ? { note: "Redirects are not followed; call the Location URL explicitly if its host is allowed." } : {}),
  };
}
