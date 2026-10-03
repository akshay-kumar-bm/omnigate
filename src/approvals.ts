// Human approval for destructive actions, enforced by the server (not by the model).
//
// Flow: a tool that needs approval is called without `approval_id` -> requestApproval() stores a pending record
// bound to a fingerprint of the exact tool + arguments and returns a link. The human opens the link, signs in with
// Google (an account in ALLOWED_EMAILS) and presses Approve. The model then repeats the identical call with the
// approval_id; checkApproval() verifies the fingerprint, consumes the record (single use) and lets it run.
// A model cannot approve its own request: that needs a Google sign-in (done once; it leaves a 12-hour HttpOnly session
// cookie in the human's browser) plus a one-time confirm nonce, and the confirming request must carry that cookie.
import type { Env } from "./server";

type ApprovalEnv = Pick<Env, "OAUTH_KV" | "APPROVAL_STORE" | "PUBLIC_URL" | "GOOGLE_CLIENT_ID" | "GOOGLE_CLIENT_SECRET" | "ALLOWED_EMAILS">;

interface ApprovalRecord {
  id: string;
  tool: string;
  summary: string[];
  fp: string;
  status: "pending" | "approved";
  approver?: string;
  created: number;
}

// Approvals, sessions, nonces and sign-in state live in a Durable Object (strongly consistent). Workers KV is only
// eventually consistent, so an approval made in one region could still read as "pending" elsewhere for up to a minute.
// KV is the fallback only when the binding is absent (local tests).
interface Store { get(k: string): Promise<string | null>; put(k: string, v: string, ttlSeconds: number): Promise<void>; delete(k: string): Promise<void> }
const store = (env: ApprovalEnv): Store => {
  if (env.APPROVAL_STORE) {
    const s = env.APPROVAL_STORE.get(env.APPROVAL_STORE.idFromName("global"));
    return { get: (k) => s.get(k), put: (k, v, t) => s.put(k, v, t), delete: (k) => s.delete(k) };
  }
  const kv = env.OAUTH_KV;
  return { get: (k) => kv.get(k), put: (k, v, t) => kv.put(k, v, { expirationTtl: Math.max(60, t) }), delete: (k) => kv.delete(k) };
};

const TTL_SECONDS = 15 * 60;
const SESSION_SECONDS = 12 * 60 * 60;
const COOKIE = "__Host-ap_session";
const ID_RE = /^[A-Za-z0-9_-]{16,64}$/;

const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n = 18) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

async function sha256Hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v as object).sort().filter((k) => (v as any)[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

// Identifies the exact action; `approval_id` is excluded so the retry matches the original call.
export const fingerprint = (tool: string, args: Record<string, unknown>) => {
  const { approval_id: _ignored, ...rest } = args;
  return sha256Hex(`${tool}\n${canonical(rest)}`);
};

const load = async (env: ApprovalEnv, id: string): Promise<ApprovalRecord | null> => {
  if (!ID_RE.test(id)) return null;
  const raw = await store(env).get(`approval:${id}`);
  return raw ? (JSON.parse(raw) as ApprovalRecord) : null;
};
const save = (env: ApprovalEnv, r: ApprovalRecord) => store(env).put(`approval:${r.id}`, JSON.stringify(r), TTL_SECONDS);
export const approvalUrl = (env: ApprovalEnv, id: string) => `${env.PUBLIC_URL}/approve/${id}`;

export async function requestApproval(env: ApprovalEnv, tool: string, args: Record<string, unknown>, summary: string[]) {
  const id = rand();
  await save(env, { id, tool, summary, fp: await fingerprint(tool, args), status: "pending", created: Date.now() });
  return { id, url: approvalUrl(env, id), expiresInMinutes: TTL_SECONDS / 60 };
}

// Single use: an approved record that matches is deleted as it is accepted.
export async function checkApproval(env: ApprovalEnv, id: string, tool: string, args: Record<string, unknown>): Promise<{ ok: true } | { ok: false; reason: string }> {
  const r = await load(env, id);
  if (!r) return { ok: false, reason: "That approval does not exist or has expired." };
  if (r.tool !== tool || r.fp !== (await fingerprint(tool, args))) return { ok: false, reason: "That approval was given for a different action. Request a new one." };
  if (r.status !== "approved") return { ok: false, reason: `Not approved yet. Ask the user to open ${approvalUrl(env, id)} and press Approve.` };
  await store(env).delete(`approval:${id}`);
  return { ok: true };
}

// ---- Approval pages ---------------------------------------------------------------------------------------

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
};
const page = (title: string, body: string, status = 200, extra: Record<string, string> = {}) =>
  new Response(
    `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<body style="font-family:system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.45"><h2>${esc(title)}</h2>${body}</body>`,
    { status, headers: { ...PAGE_HEADERS, ...extra } },
  );
const details = (r: ApprovalRecord) =>
  `<div style="background:#f3f3f3;border-radius:8px;padding:.8rem 1rem;font-family:ui-monospace,monospace;font-size:.9rem;word-break:break-all">${r.summary.map((l) => `<div>${esc(l)}</div>`).join("")}</div>`;
const button = (label: string, danger = false) =>
  `<button style="padding:.6rem 1.2rem;font-size:1rem;margin-right:.5rem;${danger ? "background:#b3261e;color:#fff;border:0;border-radius:6px" : ""}">${esc(label)}</button>`;

// ---- Browser session: Google sign-in once, then approvals are one click --------------------------------------
const sessionCookie = (token: string, maxAge: number) => `${COOKIE}=${token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
const cookieValue = (req: Request) => (req.headers.get("cookie") ?? "").split(/;\s*/).map((c) => c.split("=")).find(([k]) => k === COOKIE)?.[1] ?? "";

export async function createSession(env: ApprovalEnv, email: string): Promise<string> {
  const token = rand(24);
  await store(env).put(`apsession:${token}`, JSON.stringify({ email, created: Date.now() }), SESSION_SECONDS);
  return sessionCookie(token, SESSION_SECONDS);
}
async function getSession(req: Request, env: ApprovalEnv): Promise<{ email: string } | null> {
  const token = cookieValue(req);
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(token)) return null;
  const raw = await store(env).get(`apsession:${token}`);
  return raw ? (JSON.parse(raw) as { email: string }) : null;
}

// The review page: exact action + Approve / Deny. The nonce is bound to this approval and this signed-in email.
async function reviewPage(env: ApprovalEnv, r: ApprovalRecord, email: string, extra: Record<string, string> = {}) {
  const nonce = rand(24);
  await store(env).put(`apconfirm:${nonce}`, JSON.stringify({ id: r.id, email }), 300);
  return page(
    "Approve this action?",
    `<p>An assistant wants to:</p>${details(r)}<p style="color:#555;font-size:.9rem">Signed in as ${esc(email)}. Only approve if you asked for exactly this.</p>
<form method=post action="/approve/${esc(r.id)}/confirm" style="display:inline"><input type=hidden name=nonce value="${esc(nonce)}">${button("Approve")}</form>
<form method=post action="/approve/${esc(r.id)}/deny" style="display:inline"><input type=hidden name=nonce value="${esc(nonce)}">${button("Deny", true)}</form>
<form method=post action="/approve/signout" style="margin-top:1.5rem"><button style="background:none;border:0;color:#555;text-decoration:underline;cursor:pointer;padding:0">Sign out of approvals</button></form>`,
    200,
    extra,
  );
}

// Sends the human to Google (no account chooser if only one Google account is signed in), returning to /callback with state "ap.*".
async function startGoogle(env: ApprovalEnv, origin: string, id: string): Promise<Response> {
  const state = `ap.${rand()}`;
  const verifier = rand(32) + rand(32);
  await store(env).put(`apstate:${state}`, JSON.stringify({ id, verifier }), 600);
  const challenge = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const g = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  g.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID, redirect_uri: `${origin}/callback`, response_type: "code", scope: "openid email",
    state, code_challenge: challenge, code_challenge_method: "S256",
  }).toString();
  return new Response(null, { status: 302, headers: { Location: g.toString(), "cache-control": "no-store" } });
}

// Routes: GET /approve/:id, POST /approve/:id/{start,confirm,deny}, POST /approve/signout. Returns null if not ours.
export async function handleApprovalRequest(req: Request, env: ApprovalEnv): Promise<Response | null> {
  const url = new URL(req.url);

  if (url.pathname === "/approve/signout" && req.method === "POST") {
    const token = cookieValue(req);
    if (token) await store(env).delete(`apsession:${token}`);
    return page("Signed out", "<p>You are signed out of approvals. The next approval link will ask you to sign in with Google again.</p>", 200, { "set-cookie": sessionCookie("", 0) });
  }

  const m = url.pathname.match(/^\/approve\/([^/]+)(?:\/(start|confirm|deny))?$/);
  if (!m) return null;
  const [, id, action] = m;
  const r = await load(env, id);
  if (!r) return page("Approval not found", "<p>This approval link is invalid, already used, or expired (links last 15 minutes). Ask the assistant to start the action again.</p>", 404);

  if (!action && req.method === "GET") {
    if (r.status === "approved") return page("Already approved", `${details(r)}<p>Approved by ${esc(r.approver ?? "you")}. Tell the assistant to repeat the action.</p>`);
    const session = await getSession(req, env);
    if (session) return reviewPage(env, r, session.email); // signed in: straight to the one-click page
    return startGoogle(env, url.origin, id); // first time (or session ended): Google sign-in, then back here
  }

  if (action === "start" && req.method === "POST") return startGoogle(env, url.origin, id);

  if ((action === "confirm" || action === "deny") && req.method === "POST") {
    const form = await req.formData();
    const nonce = String(form.get("nonce") ?? "");
    const key = `apconfirm:${nonce}`;
    const raw = nonce ? await store(env).get(key) : null;
    const c = raw ? (JSON.parse(raw) as { id: string; email: string }) : null;
    const session = await getSession(req, env);
    // The nonce alone is not enough: the request must also carry the session cookie of the same signed-in person.
    if (!c || c.id !== id || !session || session.email !== c.email) return page("Session expired", "<p>Open the approval link again.</p>", 400);
    await store(env).delete(key);
    if (action === "deny") {
      await store(env).delete(`approval:${id}`);
      return page("Denied", "<p>The action was denied and will not run.</p>");
    }
    await save(env, { ...r, status: "approved", approver: c.email });
    return page("Approved", `${details(r)}<p>Approved as ${esc(c.email)}. Tell the assistant to repeat the action; it works once, within 15 minutes.</p>`);
  }

  return page("Not allowed", "<p>Unsupported request.</p>", 405);
}

// Google redirects here (same /callback as the MCP sign-in) with state "ap.*".
export async function finishApprovalSignIn(req: Request, env: ApprovalEnv): Promise<Response> {
  const url = new URL(req.url);
  const state = url.searchParams.get("state") ?? "";
  const raw = await store(env).get(`apstate:${state}`);
  if (!raw) return page("Sign-in expired", "<p>Open the approval link again.</p>", 400);
  await store(env).delete(`apstate:${state}`);
  const { id, verifier } = JSON.parse(raw) as { id: string; verifier: string };
  const code = url.searchParams.get("code");
  if (url.searchParams.get("error") || !code) return page("Sign-in cancelled", "<p>Nothing was approved.</p>", 400);

  const tr = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: `${url.origin}/callback`, grant_type: "authorization_code", code_verifier: verifier }),
  });
  if (!tr.ok) return page("Sign-in failed", "<p>Google token exchange failed.</p>", 502);
  const { access_token } = (await tr.json()) as { access_token: string };
  const ur = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { authorization: `Bearer ${access_token}` } });
  if (!ur.ok) return page("Sign-in failed", "<p>Google userinfo failed.</p>", 502);
  const u = (await ur.json()) as { email?: string; email_verified?: boolean };
  const allowed = env.ALLOWED_EMAILS.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  if (!u.email || !u.email_verified || !allowed.includes(u.email.toLowerCase())) return page("Not allowed", "<p>This Google account may not approve actions.</p>", 403);

  const r = await load(env, id);
  const cookie = await createSession(env, u.email);
  if (!r) return page("Signed in", "<p>You are signed in, but that approval was already used or has expired. Ask the assistant to start the action again.</p>", 404, { "set-cookie": cookie });
  return reviewPage(env, r, u.email, { "set-cookie": cookie });
}
