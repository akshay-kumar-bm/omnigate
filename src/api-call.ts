// api_request: make an authenticated HTTPS request using a stored secret, entirely server-side.
// The model supplies the secret NAME; the Worker reads the value from Infisical, injects it, calls the API
// and returns only the response (with the secret redacted). A secret can only be sent to the hosts in its own
// comment (`hosts: ...`), which are fixed when it is created (see hosts.ts), so a prompt-injected client
// cannot point an existing token at an attacker's server.
import { AwsClient } from "aws4fetch";
import { awsCredentials, classifyAws, isAwsHost, parseAwsSecret, SECRET_FIELDS, serviceFromHost, SSM_VALUE_ACTIONS, xmlToJson } from "./aws";
import { commentHosts } from "./hosts";
import { infisical } from "./infisical";
import { getPath, isVaultName, randomSuffix, substitute, substituteDeep, vaultAllowHost, vaultGet, vaultHosts, vaultPut, vaultRefs, DEFAULT_TTL } from "./vault";
import { extensionFor, fetchStored, MAX_STORED_BYTES, saveStored, uploadsConfigured, type UploadEnv } from "./uploads";

export interface ApiCallEnv extends UploadEnv {
  OAUTH_KV: KVNamespace;
  APPROVAL_STORE?: DurableObjectNamespace<import("./approval-store").ApprovalStore>;
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
  auth_type?: "bearer" | "header" | "basic" | "query" | "oauth2_refresh" | "aws";
  secret?: string; // an Infisical secret name, or a session vault handle "vault:<name>"
  header_name?: string;
  header_prefix?: string;
  query_param?: string;
  username?: string;
  save_response?: boolean; // store a 2xx response body in R2 and return a download URL instead of the body (e.g. generated audio)
  aws_service?: string; // signing name, e.g. s3, dynamodb, ssm; guessed from the host when left out
  aws_region?: string;  // guessed from the host, then the secret's region, then us-east-1
  capture?: Record<string, string>; // vault name -> JSON path in the response body ($.a.b[0].c); value kept server-side
  capture_minutes?: number;         // how long captured values live (default 60, max 1440)
  environment?: string;
  path?: string;
}

// Set only by server code after a human approved the call (never accepted from a client).
export interface Internal {
  _raw_body?: Uint8Array;  // gateway: forward these bytes as the body
  _vault_ok?: boolean;     // a human approved sending the referenced vault values to this host
  _full_body?: boolean;    // run_code: return the whole (redacted) body, up to 5 MB; run-code.ts applies its own limits
}

const MAX_BODY = 60_000;
const MAX_UPLOAD = 5 * 1024 * 1024; // decoded bytes, per request
const TIMEOUT_MS = 180_000; // slow APIs (e.g. high-quality image generation) take minutes to respond
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

export function containsBytes(hay: Uint8Array, needle: Uint8Array): boolean {
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

// oauth2_refresh: the secret is JSON {client_id, client_secret?, refresh_token, token_url, scope?} written by the owner.
// The Worker trades the refresh token for a short-lived access token (cached per isolate until a minute before it
// expires) and sends that as Bearer. token_url comes only from the secret and its host must also be in the secret's
// hosts line, so the refresh token can only go where the owner allowed. Providers that invalidate the old refresh
// token on every refresh are not supported: this server cannot write the new one back to Infisical.
const tokenCache = new Map<string, { token: string; expires: number }>();

export function isOAuthSecret(value: string): boolean {
  if (!value.trimStart().startsWith("{")) return false;
  try {
    const v = JSON.parse(value);
    return typeof v?.refresh_token === "string" && typeof v?.token_url === "string";
  } catch { return false; }
}

async function oauthAccessToken(name: string, value: string, approved: string[], used: string[]): Promise<string> {
  let cfg: Record<string, unknown>;
  try { cfg = JSON.parse(value); } catch { cfg = {}; }
  const str = (k: string) => (typeof cfg[k] === "string" && cfg[k] ? (cfg[k] as string) : undefined);
  const refreshToken = str("refresh_token"), tokenUrl = str("token_url"), clientId = str("client_id"), clientSecret = str("client_secret");
  if (!refreshToken || !tokenUrl || !clientId) {
    throw new Error(`Secret ${name} must be JSON with client_id, refresh_token and token_url (client_secret and scope optional) for auth_type=oauth2_refresh`);
  }
  for (const v of [refreshToken, clientSecret]) if (v) used.push(v);
  const tu = new URL(tokenUrl);
  if (tu.protocol !== "https:" || tu.username || tu.password || (tu.port && tu.port !== "443")) throw new Error(`token_url in ${name} must be a plain https:// URL`);
  if (!hostAllowed(tu.hostname, approved)) throw new Error(`token_url host ${tu.hostname} is not in the hosts line of ${name}; the owner must add it in Infisical`);

  const key = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))), (b) => b.toString(16).padStart(2, "0")).join("");
  const hit = tokenCache.get(key);
  if (hit && hit.expires > Date.now()) { used.push(hit.token); return hit.token; }

  const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
  if (clientSecret) form.set("client_secret", clientSecret);
  if (str("scope")) form.set("scope", str("scope")!);
  const res = await fetch(tu.toString(), {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(30_000),
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: form,
  });
  const text = await res.text();
  const data = (() => { try { return JSON.parse(text) as Record<string, unknown>; } catch { return {}; } })();
  if (typeof data.access_token === "string" && data.access_token) used.push(data.access_token);
  if (!res.ok || typeof data.access_token !== "string" || !data.access_token) {
    const why = [data.error, data.error_description].filter((x) => typeof x === "string").join(": ") || `HTTP ${res.status}`;
    const hint = data.error === "invalid_grant"
      ? " The refresh token expired or was revoked; the owner must get a new one and update the secret in Infisical (Google expires them after 7 days while the OAuth app is in Testing mode)."
      : "";
    throw new Error(`Could not get an access token for ${name} from ${tu.hostname}: ${used.reduce((t, u) => t.split(u).join("[REDACTED]"), why).slice(0, 300)}.${hint}`);
  }
  const ttl = typeof data.expires_in === "number" ? data.expires_in : Number(data.expires_in) || 3600;
  if (tokenCache.size > 100) tokenCache.clear();
  tokenCache.set(key, { token: data.access_token, expires: Date.now() + Math.max(0, ttl - 60) * 1000 });
  return data.access_token;
}

// Per-run cache (run_code): the secret index and each secret are read from Infisical once per run instead of on every
// call (the approval check and the call itself both need the secret). On the free plan a request may make only 50
// outbound requests, so this is what lets a run make dozens of API calls. Lives only as long as the run's env wrapper.
interface SecretCache { index?: Promise<Map<string, string[]>>; values: Map<string, Promise<{ value: string; comment: string }>> }
const CACHE = Symbol("secretCache");
export function withSecretCache<E extends object>(env: E): E {
  const e = Object.create(env) as E & { [CACHE]: SecretCache };
  e[CACHE] = { values: new Map() };
  return e;
}
const cacheOf = (env: ApiCallEnv) => (env as unknown as { [CACHE]?: SecretCache })[CACHE];
function cached<T>(map: { get(k: string): Promise<T> | undefined; set(k: string, v: Promise<T>): unknown; delete(k: string): unknown }, key: string, make: () => Promise<T>): Promise<T> {
  let p = map.get(key);
  if (!p) { p = make(); map.set(key, p); p.catch(() => map.delete(key)); }
  return p;
}

// No path given: find the secret by name in any folder, but never guess between several.
export async function loadSecret(env: ApiCallEnv, name: string, a: Pick<ApiCallArgs, "environment" | "path">) {
  const scope = { projectId: env.INFISICAL_PROJECT_ID, environment: a.environment ?? env.DEFAULT_ENVIRONMENT };
  const cache = cacheOf(env);
  let secretPath = a.path;
  if (secretPath === undefined) {
    let paths: string[];
    if (cache && scope.environment === env.DEFAULT_ENVIRONMENT) {
      cache.index ??= infisical.secretIndex(env, scope);
      cache.index.catch(() => { cache.index = undefined; });
      paths = (await cache.index).get(name) ?? [];
    } else paths = await infisical.findSecretPaths(env, name, scope);
    if (paths.length === 0) throw new Error(`Secret ${name} not found in environment ${scope.environment}`);
    if (paths.length > 1) throw new Error(`Secret ${name} exists in several folders (${paths.join(", ")}); pass path to choose one`);
    secretPath = paths[0];
  }
  const read = () => infisical.getSecretValue(env, name, { ...scope, secretPath: secretPath! });
  return cache ? cached(cache.values, `${scope.environment}|${secretPath}|${name}`, read) : read();
}

// An Infisical secret or a vault handle: its value, its comment (hosts/approve/allow lines) and approved hosts.
export async function resolveSecret(env: ApiCallEnv, name: string, a: Pick<ApiCallArgs, "environment" | "path">) {
  if (isVaultName(name)) {
    const rec = await vaultGet(env, name.slice(6));
    if (!rec) throw new Error(`${name} does not exist or has expired`);
    return { value: rec.value, comment: rec.comment, approved: vaultHosts(rec) };
  }
  const s = await loadSecret(env, name, a);
  return { value: s.value, comment: s.comment ?? "", approved: approvedHosts(s.comment) };
}

// Vault values referenced as {{vault:x}} whose host binding does not cover this host (they need an approval).
export async function vaultHostProblems(env: ApiCallEnv, a: ApiCallArgs): Promise<string[]> {
  const host = (() => { try { return new URL(substitute(a.url, new Map())).hostname; } catch { return ""; } })();
  const out: string[] = [];
  const names = vaultRefs(a.url, a.headers, a.query, a.body);
  if (a.secret && isVaultName(a.secret)) names.push(a.secret.slice(6));
  for (const n of names) {
    const r = await vaultGet(env, n);
    if (r && !hostAllowed(host, vaultHosts(r))) out.push(`vault:${n}`);
  }
  return out;
}

export interface Prepared {
  req: Request; url: URL; method: string; authType: string; used: string[]; comment: string;
  aws?: { service: string; region: string }; uploadBytes: number;
}

export async function prepareRequest(env: ApiCallEnv, a: ApiCallArgs & Internal): Promise<Prepared> {
  const used: string[] = []; // secret values, for redaction
  // {{vault:x}} references: substituted right before sending, only to hosts the value is bound to (or approved for).
  const refs = vaultRefs(a.url, a.headers, a.query, a.body);
  const values = new Map<string, string>();
  if (refs.length) {
    let host = "";
    try { host = new URL(a.url.replace(/\{\{vault:[^}]*\}\}/g, "x")).hostname; } catch { /* checked below */ }
    for (const n of refs) {
      const r = await vaultGet(env, n);
      if (!r) throw new Error(`vault:${n} does not exist or has expired`);
      if (!hostAllowed(host, vaultHosts(r))) {
        if (!a._vault_ok) throw new Error(`vault:${n} may only be sent to ${vaultHosts(r).join(", ") || "no host"}; sending it to ${host} needs the user's approval`);
        await vaultAllowHost(env, n, host);
      }
      values.set(n, r.value);
      used.push(r.value);
    }
    a = {
      ...a, url: substitute(a.url, values),
      headers: a.headers ? (substituteDeep(a.headers, values) as Record<string, string>) : undefined,
      query: a.query ? (substituteDeep(a.query, values) as Record<string, string>) : undefined,
      body: substituteDeep(a.body, values),
    };
  }
  const url = new URL(a.url);
  if (url.protocol !== "https:") throw new Error("Only https:// URLs are allowed");
  if (url.username || url.password) throw new Error("Credentials in the URL are not allowed");
  if (url.port && url.port !== "443") throw new Error("Only the default HTTPS port is allowed");
  for (const [k, v] of Object.entries(a.query ?? {})) url.searchParams.set(k, v);

  const method = (a.method ?? "GET").toUpperCase();
  let authType = a.auth_type ?? "bearer"; // may become oauth2_refresh or aws once the secret is read (see below)
  const read = async (name: string) => {
    const secret = await resolveSecret(env, name, a);
    const approved = secret.approved;
    if (!hostAllowed(url.hostname, approved) && isVaultName(name) && a._vault_ok) {
      await vaultAllowHost(env, name.slice(6), url.hostname); // a human approved this host for the vault value
      approved.push(url.hostname);
    }
    if (!hostAllowed(url.hostname, approved)) {
      throw new Error(
        `Secret ${name} is not allowed to be sent to ${url.hostname}. ` +
        (approved.length ? `Approved hosts for it: ${approved.join(", ")}. ` : "No hosts are approved for it. ") +
        "Hosts come from the secret's comment (a 'hosts: ...' line), and only the owner can set them, in Infisical. Tell the user.",
      );
    }
    used.push(secret.value);
    return { value: secret.value, approved, comment: secret.comment };
  };

  const headers = new Headers(a.headers ?? {});
  for (const h of ["host", "content-length", "connection", "proxy-authorization", "cookie"]) headers.delete(h);
  // A POST that an API treats as DELETE would dodge the approval required for DELETE.
  for (const h of ["x-http-method-override", "x-method-override", "x-http-method"]) {
    if (headers.has(h)) throw new Error(`The ${h} header is not allowed`);
  }

  const given = [a.body !== undefined && a.body !== null, !!a.body_base64, !!a.body_source, !!a.multipart, !!a._raw_body].filter(Boolean).length;
  if (given > 1) throw new Error("Send only one of body, body_base64, body_source, multipart");
  let body: string | Uint8Array | FormData | undefined;
  let uploadBytes = 0;
  if (a._raw_body) {
    body = a._raw_body;
    uploadBytes = body.length;
  } else if (a.body !== undefined && a.body !== null) {
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

  const { value, approved, comment } = await read(need(a.secret, "secret"));
  // An AWS secret (JSON with access_key_id + secret_access_key) is only ever used to sign; never sent as a token.
  const awsSecret = parseAwsSecret(value);
  if (awsSecret) {
    if (authType !== "bearer" && authType !== "aws") throw new Error(`Secret ${a.secret} is an AWS secret; use auth_type "aws" (or leave auth_type out)`);
    authType = "aws";
  } else if (authType === "aws") throw new Error(`Secret ${a.secret} is not an AWS secret: it must be JSON with access_key_id and secret_access_key`);
  if (authType === "aws") {
    if (body instanceof FormData) throw new Error("multipart is not supported for AWS requests; use body, body_base64 or body_source");
    for (const h of ["authorization", "x-amz-security-token", "x-amz-date", "x-amz-content-sha256"]) headers.delete(h);
    const guess = serviceFromHost(url.hostname);
    const service = a.aws_service ?? guess.service;
    const region = a.aws_region ?? guess.region ?? awsSecret!.region ?? "us-east-1";
    if (!service) throw new Error("Could not tell the AWS service from the URL; pass aws_service (e.g. s3, dynamodb, ssm)");
    const creds = await awsCredentials(a.secret!, awsSecret!, (h) => hostAllowed(h, approved), used);
    const client = new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken, service, region, retries: 0 });
    const req = await client.sign(url.toString(), { method, headers, body: method === "GET" || method === "HEAD" ? undefined : (body as BodyInit | undefined) });
    return { req, url, method, authType, used, comment, aws: { service, region }, uploadBytes };
  }
  // An OAuth secret (JSON with a refresh token) must never be sent as is: as a Bearer token it is useless (the API
  // answers 401) and it would put the refresh token and client secret in a request header. Models often leave
  // auth_type out, so bearer (the default) on such a secret means oauth2_refresh; any other type is refused.
  if (authType !== "oauth2_refresh" && isOAuthSecret(value)) {
    if (authType !== "bearer") throw new Error(`Secret ${a.secret} is an OAuth refresh-token secret; call api_request with auth_type "oauth2_refresh" (or leave auth_type out)`);
    authType = "oauth2_refresh";
  }
  if (authType === "bearer") { injected("authorization"); headers.set("authorization", `Bearer ${value}`); }
  else if (authType === "oauth2_refresh") {
    injected("authorization");
    headers.set("authorization", `Bearer ${await oauthAccessToken(a.secret!, value, approved, used)}`);
  } else if (authType === "header") {
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
  const req = new Request(url.toString(), { method, headers, body: method === "GET" || method === "HEAD" ? undefined : (body as BodyInit | undefined) });
  return { req, url, method, authType, used, comment, uploadBytes };
}

// Prepare and send. Never follows redirects: the next hop could be a host the secret is not bound to.
export async function brokerFetch(env: ApiCallEnv, a: ApiCallArgs & Internal): Promise<{ res: Response; p: Prepared }> {
  const p = await prepareRequest(env, a);
  const res = await fetch(p.req, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
  return { res, p };
}

export const redactor = (used: string[]) => (s: string) => used.filter((u) => u.length >= 6).reduce((t, u) => t.split(u).join("[REDACTED]"), s);

// Values to move into the vault from a response: the caller's `capture` paths, plus the secret fields of AWS
// actions that return secrets (GetSecretValue, AssumeRole, CreateAccessKey, kms Decrypt, ...).
export async function captureValues(
  env: ApiCallEnv, a: ApiCallArgs, p: Prepared, text: string, contentType: string, bodyText?: string,
): Promise<{ text: string; vault: Record<string, string> }> {
  const vault: Record<string, string> = {};
  let awsSecretAction: string | undefined;
  if (p.aws || isAwsHost(p.url.hostname)) {
    const sent = bodyText ?? (typeof a.body === "string" ? a.body : a.body ? JSON.stringify(a.body) : "");
    const info = classifyAws({ service: p.aws?.service, region: p.aws?.region, method: p.method, url: p.url, headers: p.req.headers, bodyText: sent });
    if (info.kind === "secret") awsSecretAction = `${info.service}:${info.action}`;
  }
  if (!a.capture && !awsSecretAction) return { text, vault };
  const parsed: unknown = (() => {
    const t = text.trimStart();
    if (t.startsWith("{") || t.startsWith("[")) { try { return JSON.parse(text); } catch { return undefined; } }
    if (t.startsWith("<") || /xml/.test(contentType)) return xmlToJson(text);
    return undefined;
  })();
  const ttl = Math.min(Math.max(1, a.capture_minutes ?? DEFAULT_TTL / 60), 1440) * 60;
  const found: [string, string][] = [];
  for (const [name, path] of Object.entries(a.capture ?? {})) {
    const v = getPath(parsed, path);
    if (typeof v === "string" || typeof v === "number") found.push([name, String(v)]);
    else throw new Error(`capture ${name}: nothing at ${path} in the response (only strings and numbers can be captured)`);
  }
  if (awsSecretAction) {
    const walk = (v: unknown, depth = 0) => {
      if (depth > 12 || !v || typeof v !== "object") return;
      const o = v as Record<string, unknown>;
      for (const [k, x] of Object.entries(o)) {
        const secretField = SECRET_FIELDS.includes(k) || (k === "Value" && SSM_VALUE_ACTIONS.has(awsSecretAction!) && o.Type === "SecureString");
        if (secretField && typeof x === "string" && x.length > 0) found.push([`${awsSecretAction!.split(":")[1]}_${k}_${randomSuffix()}`, x]);
        else walk(x, depth + 1);
      }
    };
    walk(parsed);
  }
  for (const [name, value] of found) {
    const handle = await vaultPut(env, name, { value, source: a.secret ?? "", comment: p.comment, extra_hosts: [] }, ttl);
    vault[name] = handle;
    if (value.length >= 4) {
      text = text.split(value).join(handle);
      const escaped = JSON.stringify(value).slice(1, -1);
      if (escaped !== value) text = text.split(escaped).join(handle);
    }
  }
  return { text, vault };
}

export async function callApi(env: ApiCallEnv, a: ApiCallArgs & Internal): Promise<unknown> {
  if (a.save_response) {
    // Checked before the call, so a paid API (e.g. text-to-speech) is not charged for output that cannot be kept.
    if (!uploadsConfigured(env)) throw new Error("File storage is not set up on this server, so save_response cannot be used (see get_upload_url for the setup steps)");
    if ((a.method ?? "GET").toUpperCase() === "HEAD") throw new Error("save_response needs a response body; HEAD has none");
  }
  const { res, p } = await brokerFetch(env, a);
  const { url, method, authType, used, uploadBytes } = p;
  const redact = redactor(used);
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

  const raw = await res.text();
  console.log(JSON.stringify({ api_request: { host: url.hostname, method, status: res.status, auth: authType, upload_bytes: uploadBytes || undefined } }));
  // Captured values are replaced by their vault handles before anything else sees the text.
  const cap = res.ok ? await captureValues(env, a, p, raw, res.headers.get("content-type") ?? "") : { text: raw, vault: {} };
  const text = cap.text;
  const bodyCap = a._full_body ? 5_000_000 : MAX_BODY;
  return {
    status: res.status,
    ok: res.ok,
    headers: out,
    body: redact(text.length > bodyCap ? text.slice(0, bodyCap) : text),
    truncated: text.length > bodyCap,
    ...(Object.keys(cap.vault).length ? { vault: cap.vault, vault_note: "These values were kept server-side; use the handles as secret or {{vault:name}} in later calls." } : {}),
    ...(res.status >= 300 && res.status < 400 ? { note: "Redirects are not followed; call the Location URL explicitly if its host is allowed." } : {}),
    ...(a.save_response && !res.ok ? { not_saved: "The API did not return a success status, so its body is shown instead of being saved." } : {}),
  };
}
