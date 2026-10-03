// call_api: make an authenticated HTTPS request using a stored secret, entirely server-side.
// The model supplies the secret NAME; the Worker reads the value from Infisical, injects it, calls the API
// and returns only the response (with the secret redacted). A secret can only be sent to hosts listed for it
// in the API_HOSTS config var, which only the Worker owner can change (redeploy), so a prompt-injected
// client cannot point a token at an attacker's server.
import { AwsClient } from "aws4fetch";
import { infisical } from "./infisical";

export interface ApiCallEnv {
  INFISICAL_HOST: string;
  INFISICAL_CLIENT_ID: string;
  INFISICAL_CLIENT_SECRET: string;
  INFISICAL_PROJECT_ID: string;
  DEFAULT_ENVIRONMENT: string;
  API_HOSTS: string; // JSON: { "SECRET_NAME": ["api.example.com", "*.example.com"] }
}

export interface ApiCallArgs {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: unknown;
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
const TIMEOUT_MS = 25_000;
const KEEP_HEADERS = ["content-type", "link", "location", "retry-after", "etag", "x-request-id", "x-amzn-requestid", "x-ratelimit-remaining", "x-ratelimit-reset"];

function parseHosts(env: ApiCallEnv): Record<string, string[]> {
  try {
    const m = JSON.parse(env.API_HOSTS || "{}");
    return m && typeof m === "object" ? m : {};
  } catch {
    throw new Error("API_HOSTS config is not valid JSON");
  }
}

export function hostAllowed(host: string, patterns: string[] | undefined): boolean {
  if (!patterns) return false;
  const h = host.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.toLowerCase();
    return p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p;
  });
}

export async function callApi(env: ApiCallEnv, a: ApiCallArgs): Promise<unknown> {
  const url = new URL(a.url);
  if (url.protocol !== "https:") throw new Error("Only https:// URLs are allowed");
  if (url.username || url.password) throw new Error("Credentials in the URL are not allowed");
  if (url.port && url.port !== "443") throw new Error("Only the default HTTPS port is allowed");
  for (const [k, v] of Object.entries(a.query ?? {})) url.searchParams.set(k, v);

  const method = (a.method ?? "GET").toUpperCase();
  const authType = a.auth_type ?? "bearer";
  const hosts = parseHosts(env);
  const loc = { projectId: env.INFISICAL_PROJECT_ID, environment: a.environment ?? env.DEFAULT_ENVIRONMENT, secretPath: a.path ?? "/" };
  const used: string[] = []; // secret values, for redaction
  const read = async (name: string) => {
    if (!hostAllowed(url.hostname, hosts[name])) {
      throw new Error(`Secret ${name} is not allowed to be sent to ${url.hostname}. Add it to API_HOSTS in wrangler.jsonc and redeploy.`);
    }
    const v = await infisical.getSecretValue(env, name, loc);
    used.push(v);
    return v;
  };

  const headers = new Headers(a.headers ?? {});
  for (const h of ["host", "content-length", "connection", "proxy-authorization", "cookie"]) headers.delete(h);

  let body: string | undefined;
  if (a.body !== undefined && a.body !== null) {
    if (typeof a.body === "string") body = a.body;
    else {
      body = JSON.stringify(a.body);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
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
    if (hosts[tokenName]) { try { sessionToken = await read(tokenName); } catch { /* optional */ } }
    const client = new AwsClient({
      accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken,
      service: need(a.aws_service, "aws_service"), region: need(a.aws_region, "aws_region"),
    });
    req = await client.sign(url.toString(), { method, headers, body });
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
    req = new Request(url.toString(), { method, headers, body: method === "GET" || method === "HEAD" ? undefined : body });
  }

  // Never follow redirects: the next hop could be a host the secret is not bound to.
  const res = await fetch(req, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
  const redact = (s: string) => used.filter((u) => u.length >= 6).reduce((t, u) => t.split(u).join("[REDACTED]"), s);
  const text = await res.text();
  const out: Record<string, string> = {};
  for (const k of KEEP_HEADERS) { const v = res.headers.get(k); if (v) out[k] = redact(v); }
  console.log(JSON.stringify({ call_api: { host: url.hostname, method, status: res.status, auth: authType } }));
  return {
    status: res.status,
    ok: res.ok,
    headers: out,
    body: redact(text.length > MAX_BODY ? text.slice(0, MAX_BODY) : text),
    truncated: text.length > MAX_BODY,
    ...(res.status >= 300 && res.status < 400 ? { note: "Redirects are not followed; call the Location URL explicitly if its host is allowed." } : {}),
  };
}
