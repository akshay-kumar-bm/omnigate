// Human approval for risky actions, enforced by the server (not by the model).
//
// Flow: a tool that needs approval is called without `approval_id` -> requestApproval() stores a pending record
// bound to a fingerprint of the exact tool + arguments and returns a link. The human opens the link, signs in with
// Google (an account in ALLOWED_EMAILS) and presses Approve. The model then repeats the identical call with the
// approval_id; checkApproval() verifies the fingerprint, consumes the record (single use) and lets it run.
// A model cannot approve its own request: that needs a Google sign-in (done once; it leaves a 12-hour HttpOnly session
// cookie in the human's browser) plus a one-time confirm nonce, and the confirming request must carry that cookie.
// Some requests (handing out a token) also carry an `ack`: a checkbox the human must tick, enforced here on the server.
import type { Env } from "./server";

type ApprovalEnv = Pick<Env, "OAUTH_KV" | "APPROVAL_STORE" | "PUBLIC_URL" | "GOOGLE_CLIENT_ID" | "GOOGLE_CLIENT_SECRET" | "ALLOWED_EMAILS">;

// What the human is shown. `risk` picks the colour and wording; `ack` (if set) is a checkbox that must be ticked to approve.
export interface ApprovalSpec {
  title: string;
  risk?: "danger" | "token";
  rows: ([label: string, value: string] | [label: string, value: string, flag: "warn"])[];
  ack?: string;
}

interface ApprovalRecord {
  id: string;
  tool: string;
  title?: string;
  risk?: "danger" | "token";
  rows?: ([string, string] | [string, string, "warn"])[];
  ack?: string;
  summary: string[]; // plain-text version of the rows; also what older records contain
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

export async function requestApproval(env: ApprovalEnv, tool: string, args: Record<string, unknown>, spec: ApprovalSpec) {
  const id = rand();
  await save(env, {
    id, tool, title: spec.title, risk: spec.risk, rows: spec.rows, ack: spec.ack,
    summary: [spec.title, ...spec.rows.map((x) => `${x[0]}: ${x[1]}`)],
    fp: await fingerprint(tool, args), status: "pending", created: Date.now(),
  });
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

// ---- Page design ------------------------------------------------------------------------------------------
// No scripts: CSP forbids them. The "tick the box" gate is enforced on the server; CSS (:has) only dims the button.

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
};

const CSS = `
:root{--bg:#f4f5f7;--card:#fff;--ink:#14171a;--mute:#5b6670;--line:#e2e5e9;--soft:#f7f8fa;--on:#fff;--danger:#b3261e;--token:#8a5200;--ok:#17653f;--neutral:#4b5563}
@media (prefers-color-scheme:dark){:root{--bg:#0e1113;--card:#171b1f;--ink:#eef1f4;--mute:#99a4ae;--line:#293038;--soft:#1d2227;--on:#101315;--danger:#ff8a80;--token:#f2b955;--ok:#59d49a;--neutral:#aab4be}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:16px}
.card{max-width:34rem;margin:24px auto;background:var(--card);border:1px solid var(--line);border-top:6px solid var(--tone);border-radius:16px;padding:24px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.tone-danger{--tone:var(--danger)}.tone-token{--tone:var(--token)}.tone-ok{--tone:var(--ok)}.tone-neutral{--tone:var(--neutral)}
.head{display:flex;gap:14px;align-items:center}
.badge{flex:none;width:44px;height:44px;border-radius:50%;display:grid;place-items:center;background:var(--tone);color:var(--on);font-size:22px;font-weight:700}
.eyebrow{margin:0;font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:var(--tone);font-weight:700}
h1{margin:2px 0 0;font-size:1.35rem;line-height:1.25}
.lead{color:var(--mute);margin:16px 0 4px}
.rows{margin:16px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--soft)}
.rows div{display:grid;grid-template-columns:7rem 1fr;gap:12px;padding:10px 14px;border-top:1px solid var(--line)}
.rows div:first-child{border-top:0}
dt{color:var(--mute);font-size:.85rem;padding-top:1px}
dd{margin:0;font:.9rem ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
.rows .warn{background:color-mix(in srgb,var(--danger) 10%,transparent)}
.rows .warn dd{color:var(--danger);font-weight:700}
.meta{font-size:.85rem;color:var(--mute);margin:8px 0 0}
.ack{display:flex;gap:12px;align-items:flex-start;padding:14px;border:2px solid var(--tone);border-radius:12px;margin:16px 0 0;cursor:pointer}
.ack input{flex:none;width:22px;height:22px;margin:2px 0 0;accent-color:var(--tone)}
.ack span{font-weight:600}
.err{background:color-mix(in srgb,var(--danger) 12%,transparent);border:1px solid var(--danger);color:var(--ink);border-radius:10px;padding:10px 14px;margin:16px 0 0}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}
button{min-height:46px;padding:0 22px;font:inherit;font-weight:700;border-radius:10px;border:2px solid var(--ink);background:transparent;color:var(--ink);cursor:pointer}
button.primary{background:var(--tone);border-color:var(--tone);color:var(--on)}
button:focus-visible{outline:3px solid var(--tone);outline-offset:2px}
form.gated:has(.ack input:not(:checked)) button.primary{opacity:.35;cursor:not-allowed}
.foot{margin-top:22px;padding-top:14px;border-top:1px solid var(--line);font-size:.85rem;color:var(--mute);display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.foot form{margin:0}
.link{min-height:0;padding:0;border:0;font-weight:400;color:var(--mute);text-decoration:underline;font-size:.85rem}
p{margin:12px 0}
`;

type Tone = "danger" | "token" | "ok" | "neutral";
const GLYPH: Record<Tone, string> = { danger: "!", token: "&#128273;", ok: "&#10003;", neutral: "i" };
const EYEBROW: Record<Tone, string> = { danger: "Destructive action", token: "Token request", ok: "Done", neutral: "Approvals" };

const shell = (title: string, tone: Tone, inner: string, status = 200, extra: Record<string, string> = {}, eyebrow?: string) =>
  new Response(
    `<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><meta name=color-scheme content="light dark"><title>${esc(title)}</title><style>${CSS}</style>
<main class="card tone-${tone}"><div class=head><div class=badge aria-hidden=true>${GLYPH[tone]}</div><div><p class=eyebrow>${esc(eyebrow ?? EYEBROW[tone])}</p><h1>${esc(title)}</h1></div></div>${inner}</main></html>`,
    { status, headers: { ...PAGE_HEADERS, ...extra } },
  );

const rowsOf = (r: ApprovalRecord): ([string, string] | [string, string, "warn"])[] =>
  r.rows ?? r.summary.map((l) => { const i = l.indexOf(": "); return (i > 0 ? [l.slice(0, i), l.slice(i + 2)] : ["", l]) as [string, string]; });
const titleOf = (r: ApprovalRecord) => r.title ?? "Approve this action?";
const toneOf = (r: ApprovalRecord): Tone => r.risk ?? "danger";
const rowsHtml = (r: ApprovalRecord) =>
  `<dl class=rows>${rowsOf(r).map((x) => `<div${x[2] === "warn" ? " class=warn" : ""}><dt>${esc(x[0])}</dt><dd>${esc(x[1])}</dd></div>`).join("")}</dl>`;
const hhmm = (ms: number) => new Date(ms).toISOString().slice(11, 16) + " UTC";

const message = (title: string, tone: Tone, body: string, status = 200, extra: Record<string, string> = {}) =>
  shell(title, tone, `<p class=lead>${body}</p>`, status, extra);

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

// The review page: the exact action, an optional must-tick box, Approve / Deny. The nonce is bound to this approval
// and this signed-in email.
async function reviewPage(env: ApprovalEnv, r: ApprovalRecord, email: string, extra: Record<string, string> = {}, error?: string) {
  const nonce = rand(24);
  await store(env).put(`apconfirm:${nonce}`, JSON.stringify({ id: r.id, email }), 300);
  const tone = toneOf(r);
  const lead = tone === "token"
    ? "An AI assistant is asking for a temporary access token. Whoever holds it can use it until it expires."
    : "An AI assistant wants to make a change that can't be undone. Nothing happens unless you approve.";
  const ack = r.ack ? `<label class=ack><input type=checkbox name=ack value=on required><span>${esc(r.ack)}</span></label>` : "";
  return shell(
    titleOf(r),
    tone,
    `<p class=lead>${lead}</p>${rowsHtml(r)}
<p class=meta>Requested ${hhmm(r.created)} &middot; this link expires ${hhmm(r.created + TTL_SECONDS * 1000)} &middot; works once</p>
${error ? `<div class=err role=alert>${esc(error)}</div>` : ""}
<form method=post action="/approve/${esc(r.id)}/confirm" class="${r.ack ? "gated" : ""}"><input type=hidden name=nonce value="${esc(nonce)}">${ack}
<div class=actions><button class=primary>${r.ack ? "Give token" : "Approve"}</button><button type=submit formaction="/approve/${esc(r.id)}/deny" formnovalidate>Deny</button></div></form>
<div class=foot><span>Signed in as ${esc(email)}</span><form method=post action="/approve/signout"><button class=link>Sign out of approvals</button></form></div>`,
    200,
    extra,
    tone === "token" ? "Token request" : "Approval needed",
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
    return message("Signed out", "neutral", "You are signed out of approvals. The next approval link will ask you to sign in with Google again.", 200, { "set-cookie": sessionCookie("", 0) });
  }

  const m = url.pathname.match(/^\/approve\/([^/]+)(?:\/(start|confirm|deny))?$/);
  if (!m) return null;
  const [, id, action] = m;
  const r = await load(env, id);
  if (!r) return message("Approval not found", "neutral", "This approval link is invalid, already used, or expired (links last 15 minutes). Ask the assistant to start the action again.", 404);

  if (!action && req.method === "GET") {
    if (r.status === "approved") {
      return shell("Already approved", "ok", `<p class=lead>Approved by ${esc(r.approver ?? "you")}. Tell the assistant to repeat the action.</p>${rowsHtml(r)}`);
    }
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
    if (!c || c.id !== id || !session || session.email !== c.email) return message("Session expired", "neutral", "Open the approval link again.", 400);
    await store(env).delete(key);
    if (action === "deny") {
      await store(env).delete(`approval:${id}`);
      return message("Denied", "neutral", "The action was denied and will not run.");
    }
    // Enforced here, not in the browser: a request that needs the box ticked is not approved without it.
    if (r.ack && form.get("ack") !== "on") return reviewPage(env, r, c.email, {}, "Tick the box to confirm. Nothing was approved.");
    await save(env, { ...r, status: "approved", approver: c.email });
    return shell(r.ack ? "Token approved" : "Approved", "ok", `<p class=lead>Approved as ${esc(c.email)}. Tell the assistant to repeat the action. It works once, within 15 minutes.</p>${rowsHtml(r)}`);
  }

  return message("Not allowed", "neutral", "Unsupported request.", 405);
}

// Google redirects here (same /callback as the MCP sign-in) with state "ap.*".
export async function finishApprovalSignIn(req: Request, env: ApprovalEnv): Promise<Response> {
  const url = new URL(req.url);
  const state = url.searchParams.get("state") ?? "";
  const raw = await store(env).get(`apstate:${state}`);
  if (!raw) return message("Sign-in expired", "neutral", "Open the approval link again.", 400);
  await store(env).delete(`apstate:${state}`);
  const { id, verifier } = JSON.parse(raw) as { id: string; verifier: string };
  const code = url.searchParams.get("code");
  if (url.searchParams.get("error") || !code) return message("Sign-in cancelled", "neutral", "Nothing was approved.", 400);

  const tr = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: `${url.origin}/callback`, grant_type: "authorization_code", code_verifier: verifier }),
  });
  if (!tr.ok) return message("Sign-in failed", "neutral", "Google token exchange failed.", 502);
  const { access_token } = (await tr.json()) as { access_token: string };
  const ur = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { authorization: `Bearer ${access_token}` } });
  if (!ur.ok) return message("Sign-in failed", "neutral", "Google userinfo failed.", 502);
  const u = (await ur.json()) as { email?: string; email_verified?: boolean };
  const allowed = env.ALLOWED_EMAILS.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
  if (!u.email || !u.email_verified || !allowed.includes(u.email.toLowerCase())) return message("Not allowed", "neutral", "This Google account may not approve actions.", 403);

  const r = await load(env, id);
  const cookie = await createSession(env, u.email);
  if (!r) return message("Signed in", "neutral", "You are signed in, but that approval was already used or has expired. Ask the assistant to start the action again.", 404, { "set-cookie": cookie });
  return reviewPage(env, r, u.email, { "set-cookie": cookie });
}
