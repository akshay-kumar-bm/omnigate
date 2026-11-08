// Gateway: lets an agent with a shell (Claude Code, cloud sessions) use curl, SDKs and the real `aws` CLI with the
// stored credentials, without installing anything and without ever holding a real credential.
//
// open_gateway (always approved by a human) creates a short-lived session for named secrets and returns a gateway
// token. That token only works against this Worker, only for those secrets, only until it expires. Requests:
//  - HTTP APIs:  https://<worker>/gw/<SECRET>/<api-host>/<path>  with the gateway token where the API key would go
//                (Authorization: Bearer, Basic, x-api-key or x-gateway-token). The Worker swaps in the real credential.
//  - AWS:        AWS_ENDPOINT_URL=https://<worker>, AWS_ACCESS_KEY_ID=<per-secret gateway key id>,
//                AWS_SESSION_TOKEN=<gateway token>. The CLI signs with a dummy key; the Worker checks the gateway token
//                (sent in X-Amz-Security-Token), reads service and region from the signature's credential scope, maps
//                them to the real endpoint and signs again with the real (or AssumeRole) credentials.
// Every request goes through the same policy as api_request (policy.ts). A request that needs approval gets an error
// with the link; once approved, simply re-running the identical request goes through (the approval is bound to the
// session and the request), so CLIs that cannot add headers work too.
import { brokerFetch, captureValues, containsBytes, redactor, resolveSecret, type ApiCallArgs } from "./api-call";
import { checkApproval, fingerprint, requestApproval, store } from "./approvals";
import { classifyAws, decodeAwsChunked, endpointFor, parseAwsSecret } from "./aws";
import { approvalNeed, approvalSpec } from "./policy";
import type { Env } from "./server";

export const MAX_GATEWAY_MINUTES = 60;
const MAX_BODY = 50 * 1024 * 1024;
const MAX_TEXT = 40 * 1024 * 1024;

interface Session {
  id: string; tokenHash: string; purpose: string; expires: number;
  secrets: { name: string; aws: boolean; keyId?: string; region?: string; hosts: string[] }[];
}

const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n: number) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const alnum = (n: number) => Array.from(crypto.getRandomValues(new Uint8Array(n)), (b) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[b % 32]).join("");
const sha = async (s: string | Uint8Array) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", typeof s === "string" ? new TextEncoder().encode(s) : s))].map((x) => x.toString(16).padStart(2, "0")).join("");

async function sessionByToken(env: Env, token: string): Promise<Session | null> {
  if (!/^gwt_[A-Za-z0-9_-]{30,80}$/.test(token)) return null;
  const h = await sha(token);
  const id = await store(env).get(`gwtok:${h}`);
  if (!id) return null;
  const raw = await store(env).get(`gw:${id}`);
  const s = raw ? (JSON.parse(raw) as Session) : null;
  return s && s.tokenHash === h && s.expires > Date.now() ? s : null;
}

// ---- open_gateway --------------------------------------------------------------------------------------------
export async function describeGatewaySecrets(env: Env, names: string[]) {
  const out: Session["secrets"] = [];
  for (const name of names) {
    const s = await resolveSecret(env, name, {});
    if (!s.approved.length) throw new Error(`Secret ${name} has no hosts line, so it can never be sent; the owner must add one in Infisical`);
    const aws = parseAwsSecret(s.value);
    out.push({ name, aws: !!aws, region: aws?.region, hosts: s.approved });
  }
  return out;
}

export async function openGateway(env: Env, a: { secrets: string[]; minutes: number; purpose: string }) {
  const secrets = await describeGatewaySecrets(env, a.secrets);
  const id = rand(9);
  const token = `gwt_${rand(32)}`;
  const minutes = Math.min(Math.max(5, a.minutes), MAX_GATEWAY_MINUTES);
  for (const s of secrets) if (s.aws) s.keyId = `GW${alnum(18)}`;
  const session: Session = { id, tokenHash: await sha(token), purpose: a.purpose, expires: Date.now() + minutes * 60_000, secrets };
  const st = store(env);
  const ttl = minutes * 60;
  await st.put(`gw:${id}`, JSON.stringify(session), ttl);
  await st.put(`gwtok:${session.tokenHash}`, id, ttl);
  for (const s of secrets) if (s.keyId) await st.put(`gwkey:${s.keyId}`, JSON.stringify({ id, secret: s.name }), ttl);

  const base = env.PUBLIC_URL;
  const http = secrets.filter((s) => !s.aws).map((s) => {
    const host = s.hosts.find((h) => !h.startsWith("*.")) ?? s.hosts[0].replace(/^\*\./, "<sub>.");
    return {
      secret: s.name, hosts: s.hosts,
      base_url: `${base}/gw/${s.name}/${host}`,
      example: `curl -sS -H "Authorization: Bearer $GATEWAY_TOKEN" ${base}/gw/${s.name}/${host}/<path>`,
    };
  });
  const aws = secrets.filter((s) => s.aws).map((s) => ({
    secret: s.name,
    env: [
      `export AWS_ACCESS_KEY_ID=${s.keyId}`, "export AWS_SECRET_ACCESS_KEY=gateway-dummy-key",
      "export AWS_SESSION_TOKEN=\"$GATEWAY_TOKEN\"", `export AWS_ENDPOINT_URL=${base}`,
      `export AWS_REGION=${s.region ?? "us-east-1"} AWS_DEFAULT_REGION=${s.region ?? "us-east-1"}`, "export AWS_REQUEST_CHECKSUM_CALCULATION=when_required",
      "export AWS_RESPONSE_CHECKSUM_VALIDATION=when_required", "aws configure set default.s3.addressing_style path",
    ],
    try_first: "aws sts get-caller-identity",
  }));
  return {
    gateway_token: token,
    expires_at: new Date(session.expires).toISOString(),
    setup: `export GATEWAY_TOKEN='${token}'`,
    ...(http.length ? { http } : {}),
    ...(aws.length ? { aws } : {}),
    how_it_works:
      "These are gateway credentials, not real ones: they only work against this server, for the listed secrets, until expires_at. " +
      "HTTP: send requests to base_url + the API path with the gateway token where the API key would go (Authorization: Bearer, Basic, x-api-key or x-gateway-token); for other auth styles add x-gateway-auth: header|query|basic plus x-gateway-header-name / x-gateway-header-prefix / x-gateway-query-param / x-gateway-username. " +
      "AWS: run the env lines, then use the aws CLI, boto3 or any AWS SDK normally. " +
      "If a request needs the user's approval, the error contains a link: give it to the user, wait for them to approve, then run the identical command again. " +
      "Not supported through the gateway: aws s3 presign, aws eks get-token, aws rds generate-db-auth-token, interactive ssm start-session; use run_code for SSM SendCommand instead of SSH. " +
      "Treat the gateway token as a secret: do not print it, commit it or send it anywhere else.",
  };
}

// ---- Request handling -----------------------------------------------------------------------------------------
const STRIP = new Set(["host", "content-length", "connection", "cookie", "x-real-ip", "cdn-loop", "true-client-ip", "expect", "keep-alive", "transfer-encoding", "upgrade", "proxy-authorization"]);
function forwardHeaders(req: Request, drop: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  req.headers.forEach((v, k) => {
    const l = k.toLowerCase();
    if (STRIP.has(l) || l.startsWith("cf-") || l.startsWith("x-forwarded-") || l.startsWith("x-gateway-") || drop.includes(l)) return;
    out[l] = v;
  });
  return out;
}

const TEXTUAL = /json|xml|text|javascript|x-www-form-urlencoded|graphql/i;
const IDEMPOTENCY = ["ClientToken", "ClientRequestToken", "IdempotencyToken", "idempotencyToken", "clientToken"];

// Hash of the body for the approval fingerprint, ignoring tokens SDKs generate fresh on every run.
async function bodyHash(bytes: Uint8Array, contentType: string): Promise<string> {
  if (bytes.length === 0) return "";
  if (bytes.length < 1_000_000 && TEXTUAL.test(contentType)) {
    const t = new TextDecoder().decode(bytes);
    try {
      const o = JSON.parse(t);
      if (o && typeof o === "object") for (const k of IDEMPOTENCY) delete o[k];
      return sha(JSON.stringify(o));
    } catch { /* not JSON */ }
    if (/x-www-form-urlencoded/.test(contentType)) {
      const f = new URLSearchParams(t);
      for (const k of IDEMPOTENCY) f.delete(k);
      return sha(f.toString());
    }
  }
  return sha(bytes);
}

type Gate = { ok: true } | { ok: false; url: string; id: string };

// Approval bound to the session + exact request: re-sending the identical request after approval goes through.
async function sessionGate(env: Env, session: Session, explicitId: string | null, approvalArgs: Record<string, unknown>, spec: ReturnType<typeof approvalSpec>): Promise<Gate> {
  const st = store(env);
  const k = `gwap:${session.id}:${await fingerprint("gateway", approvalArgs)}`;
  const id = explicitId ?? (await st.get(k));
  if (id) {
    const c = await checkApproval(env, id, "gateway", approvalArgs);
    if (c.ok) { await st.delete(k); return { ok: true }; }
    if (/Not approved yet/.test(c.reason)) return { ok: false, url: `${env.PUBLIC_URL}/approve/${id}`, id };
  }
  const r = await requestApproval(env, "gateway", approvalArgs, spec);
  await st.put(k, r.id, 15 * 60);
  return { ok: false, url: r.url, id: r.id };
}

const approvalMessage = (g: { url: string; id: string }) =>
  `Approval required. Ask the user to open ${g.url} and approve; then run the identical request again (approval_id ${g.id}, valid 15 minutes, once).`;

function awsError(code: string, message: string, status: number, json: boolean) {
  if (json) return new Response(JSON.stringify({ __type: code, message }), { status, headers: { "content-type": "application/x-amz-json-1.1" } });
  const esc = message.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  return new Response(`<?xml version="1.0" encoding="UTF-8"?><ErrorResponse><Error><Type>Sender</Type><Code>${code}</Code><Message>${esc}</Message></Error></ErrorResponse>`, { status, headers: { "content-type": "text/xml" } });
}
const httpError = (status: number, error: string, extra: Record<string, unknown> = {}) =>
  new Response(JSON.stringify({ error, ...extra }), { status, headers: { "content-type": "application/json" } });

// Responses: text is buffered so captured/secret values can be replaced and the credential redacted; binary is
// passed through unless it contains the credential (checked on bodies up to 40 MB).
async function relay(env: Env, res: Response, a: ApiCallArgs, p: Awaited<ReturnType<typeof brokerFetch>>["p"], bodyText: string): Promise<Response> {
  const headers = new Headers();
  res.headers.forEach((v, k) => { if (!["set-cookie", "content-length", "content-encoding", "transfer-encoding", "connection"].includes(k)) headers.set(k, v); });
  const ct = res.headers.get("content-type") ?? "";
  const redact = redactor(p.used);
  if (TEXTUAL.test(ct) || !ct) {
    const len = Number(res.headers.get("content-length") ?? 0);
    if (len > MAX_TEXT) return httpError(502, "Response too large to relay");
    let text = await res.text();
    if (res.ok) text = (await captureValues(env, a, p, text, ct, bodyText)).text;
    return new Response(redact(text), { status: res.status, headers });
  }
  // Binary from a token-authenticated API: checked for the credential, like save_response.
  if (Number(res.headers.get("content-length") ?? 0) > MAX_TEXT) return httpError(502, "Response too large to relay");
  const bytes = new Uint8Array(await res.arrayBuffer());
  const enc = new TextEncoder();
  if (p.used.some((u) => u.length >= 6 && containsBytes(bytes, enc.encode(u)))) return httpError(502, "The response contains the credential itself, so it was not relayed");
  return new Response(bytes, { status: res.status, headers });
}

export async function handleGateway(req: Request, env: Env): Promise<Response | null> {
  const url = new URL(req.url);
  const auth = req.headers.get("authorization") ?? "";
  if (url.pathname.startsWith("/gw/")) return handleHttp(req, env, url);
  if (/^AWS4-HMAC-SHA256\s+Credential=GW[A-Z2-7]{18}\//.test(auth)) return handleAws(req, env, url, auth);
  return null;
}

async function readBody(req: Request): Promise<Uint8Array> {
  if (req.method === "GET" || req.method === "HEAD") return new Uint8Array();
  if (Number(req.headers.get("content-length") ?? 0) > MAX_BODY) throw new Error(`Request body too large (max ${MAX_BODY / 1024 / 1024} MB)`);
  const b = new Uint8Array(await req.arrayBuffer());
  if (b.length > MAX_BODY) throw new Error(`Request body too large (max ${MAX_BODY / 1024 / 1024} MB)`);
  return b;
}

async function handleHttp(req: Request, env: Env, url: URL): Promise<Response> {
  const m = url.pathname.match(/^\/gw\/([A-Za-z0-9_.\-]+)\/([a-z0-9.-]+)(\/.*)?$/i);
  if (!m) return httpError(400, "Use /gw/<SECRET>/<api-host>/<path>");
  const [, secret, host, rest = "/"] = m;
  // The gateway token may arrive wherever the client puts an API key.
  const candidates: [string, string][] = [];
  const authz = req.headers.get("authorization") ?? "";
  if (/^bearer\s+/i.test(authz)) candidates.push(["authorization", authz.replace(/^bearer\s+/i, "").trim()]);
  if (/^basic\s+/i.test(authz)) { try { for (const p of atob(authz.slice(6).trim()).split(":")) candidates.push(["authorization", p]); } catch { /* ignore */ } }
  for (const h of ["x-api-key", "x-gateway-token", "api-key"]) { const v = req.headers.get(h); if (v) candidates.push([h, v.trim()]); }
  let session: Session | null = null, tokenHeader = "";
  for (const [h, v] of candidates) { session = await sessionByToken(env, v); if (session) { tokenHeader = h; break; } }
  if (!session) return httpError(401, "Missing or expired gateway token. Call open_gateway for a new one.");
  if (!session.secrets.some((s) => s.name === secret && !s.aws)) return httpError(403, `Secret ${secret} is not part of this gateway session (or is an AWS secret: use AWS_ENDPOINT_URL instead)`);

  let body: Uint8Array;
  try { body = await readBody(req); } catch (e) { return httpError(413, String((e as Error).message)); }
  const ct = req.headers.get("content-type") ?? "";
  const bodyText = body.length && body.length < 1_000_000 && TEXTUAL.test(ct) ? new TextDecoder().decode(body) : "";
  const g = (k: string) => req.headers.get(`x-gateway-${k}`) ?? undefined;
  const a: ApiCallArgs = {
    url: `https://${host.toLowerCase()}${rest}${url.search}`, method: req.method, headers: forwardHeaders(req, [tokenHeader]), secret,
    auth_type: (g("auth") as ApiCallArgs["auth_type"]) ?? undefined, header_name: g("header-name"), header_prefix: g("header-prefix"),
    query_param: g("query-param"), username: g("username"),
  };
  try {
    const need = await approvalNeed(env, { ...a, body: bodyText || undefined });
    let vaultOk = false;
    if (need) {
      const spec = approvalSpec({ ...a, body: bodyText || (body.length ? `(${body.length} bytes)` : undefined) }, need, [["Asked by", `gateway session (${session.purpose})`]]);
      const gate = await sessionGate(env, session, req.headers.get("x-approval-id"), { session: session.id, secret, method: a.method, url: a.url, body: await bodyHash(body, ct) }, spec);
      if (!gate.ok) return httpError(428, approvalMessage(gate), { approval_required: true, approve_url: gate.url, approval_id: gate.id });
      vaultOk = true;
    }
    const { res, p } = await brokerFetch(env, { ...a, _raw_body: body.length ? body : undefined, _vault_ok: vaultOk });
    return relay(env, res, a, p, bodyText);
  } catch (e) {
    return httpError(400, String((e as Error).message ?? e));
  }
}

async function handleAws(req: Request, env: Env, url: URL, auth: string): Promise<Response> {
  const json = req.headers.has("x-amz-target");
  const scope = auth.match(/Credential=(GW[A-Z2-7]{18})\/\d{8}\/([a-z0-9-]+)\/([a-z0-9-]+)\/aws4_request/);
  if (!scope) return awsError("InvalidClientTokenId", "Malformed gateway credential", 403, json);
  const [, keyId, region, service] = scope;
  const st = store(env);
  const k = await st.get(`gwkey:${keyId}`);
  const token = req.headers.get("x-amz-security-token") ?? "";
  const session = await sessionByToken(env, token);
  if (!k || !session || JSON.parse(k).id !== session.id) return awsError("ExpiredToken", "Gateway session missing or expired. Call open_gateway for a new one and export its values again.", 403, json);
  const secret = JSON.parse(k).secret as string;

  let body: Uint8Array;
  try { body = await readBody(req); } catch (e) { return awsError("EntityTooLarge", String((e as Error).message), 413, json); }
  const drop = ["authorization", "x-amz-security-token", "x-amz-date", "x-amz-content-sha256", "x-amz-decoded-content-length", "x-amz-trailer"];
  const headers = forwardHeaders(req, drop);
  const sha256Header = req.headers.get("x-amz-content-sha256") ?? "";
  const encoding = req.headers.get("content-encoding") ?? "";
  if (sha256Header.startsWith("STREAMING-") || /aws-chunked/i.test(encoding)) {
    try {
      const d = decodeAwsChunked(body);
      body = d.body;
      Object.assign(headers, d.trailers);
    } catch (e) { return awsError("IncompleteBody", String((e as Error).message), 400, json); }
    const rest = encoding.split(",").map((x) => x.trim()).filter((x) => x && x.toLowerCase() !== "aws-chunked");
    if (rest.length) headers["content-encoding"] = rest.join(", "); else delete headers["content-encoding"];
  }
  let host: string;
  try { host = endpointFor(service, region, url.pathname); } catch (e) { return awsError("InvalidEndpoint", String((e as Error).message), 400, json); }
  const ct = headers["content-type"] ?? "";
  const bodyText = body.length && body.length < 1_000_000 && (TEXTUAL.test(ct) || json) ? new TextDecoder().decode(body) : "";
  const a: ApiCallArgs = { url: `https://${host}${url.pathname}${url.search}`, method: req.method, headers, secret, auth_type: "aws", aws_service: service, aws_region: region };
  try {
    const need = await approvalNeed(env, { ...a, body: bodyText || undefined }, new Headers(headers));
    let vaultOk = false;
    if (need) {
      const spec = approvalSpec({ ...a, body: bodyText || (body.length ? `(${body.length} bytes)` : undefined) }, need, [["Asked by", `gateway session (${session.purpose}), aws CLI/SDK`]]);
      const gate = await sessionGate(env, session, req.headers.get("x-approval-id"), { session: session.id, secret, method: a.method, url: a.url, target: headers["x-amz-target"] ?? "", body: await bodyHash(body, ct || (json ? "application/json" : "")) }, spec);
      if (!gate.ok) return awsError("ApprovalRequired", approvalMessage(gate), 428, json);
      vaultOk = true;
    }
    const { res, p } = await brokerFetch(env, { ...a, _raw_body: body.length ? body : undefined, _vault_ok: vaultOk });
    const info = classifyAws({ service, region, method: a.method!, url: p.url, headers: new Headers(headers), bodyText });
    if (info.kind === "secret" || TEXTUAL.test(res.headers.get("content-type") ?? "")) return relay(env, res, a, p, bodyText);
    const out = new Headers();
    res.headers.forEach((v, h) => { if (!["set-cookie", "connection", "transfer-encoding"].includes(h)) out.set(h, v); });
    return new Response(res.body, { status: res.status, headers: out }); // streamed (large S3 downloads)
  } catch (e) {
    // 4xx, not 5xx: SDKs retry 5xx, and a refusal (host not allowed, bad arguments) will not change on retry.
    return awsError("GatewayRefused", String((e as Error).message ?? e), 400, json);
  }
}
