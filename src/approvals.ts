// Human approval for destructive actions, enforced by the server (not by the model).
//
// Flow: a tool that needs approval is called without `approval_id` -> requestApproval() stores a pending record
// bound to a fingerprint of the exact tool + arguments and returns a link. The human opens the link, signs in with
// Google (an account in ALLOWED_EMAILS) and presses Approve. The model then repeats the identical call with the
// approval_id; checkApproval() verifies the fingerprint, consumes the record (single use) and lets it run.
// A model cannot approve its own request: that needs a Google sign-in plus a one-time confirm nonce that only the
// browser that signed in receives.
import type { Env } from "./server";

type ApprovalEnv = Pick<Env, "OAUTH_KV" | "PUBLIC_URL" | "GOOGLE_CLIENT_ID" | "GOOGLE_CLIENT_SECRET" | "ALLOWED_EMAILS">;

interface ApprovalRecord {
  id: string;
  tool: string;
  summary: string[];
  fp: string;
  status: "pending" | "approved";
  approver?: string;
  created: number;
}

const TTL_SECONDS = 15 * 60;
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
  const raw = await env.OAUTH_KV.get(`approval:${id}`);
  return raw ? (JSON.parse(raw) as ApprovalRecord) : null;
};
const save = (env: ApprovalEnv, r: ApprovalRecord) => env.OAUTH_KV.put(`approval:${r.id}`, JSON.stringify(r), { expirationTtl: TTL_SECONDS });
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
  await env.OAUTH_KV.delete(`approval:${id}`);
  return { ok: true };
}

// ---- Approval pages ---------------------------------------------------------------------------------------

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
};
const page = (title: string, body: string, status = 200) =>
  new Response(
    `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<body style="font-family:system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.45"><h2>${esc(title)}</h2>${body}</body>`,
    { status, headers: PAGE_HEADERS },
  );
const details = (r: ApprovalRecord) =>
  `<div style="background:#f3f3f3;border-radius:8px;padding:.8rem 1rem;font-family:ui-monospace,monospace;font-size:.9rem;word-break:break-all">${r.summary.map((l) => `<div>${esc(l)}</div>`).join("")}</div>`;
const button = (label: string, danger = false) =>
  `<button style="padding:.6rem 1.2rem;font-size:1rem;margin-right:.5rem;${danger ? "background:#b3261e;color:#fff;border:0;border-radius:6px" : ""}">${esc(label)}</button>`;

// Routes: GET /approve/:id, POST /approve/:id/start, POST /approve/:id/confirm, POST /approve/:id/deny. Returns null if not ours.
export async function handleApprovalRequest(req: Request, env: ApprovalEnv): Promise<Response | null> {
  const url = new URL(req.url);
  const m = url.pathname.match(/^\/approve\/([^/]+)(?:\/(start|confirm|deny))?$/);
  if (!m) return null;
  const [, id, action] = m;
  const r = await load(env, id);
  if (!r) return page("Approval not found", "<p>This approval link is invalid, already used, or expired (links last 15 minutes). Ask the assistant to start the action again.</p>", 404);

  if (!action && req.method === "GET") {
    if (r.status === "approved") return page("Already approved", `${details(r)}<p>Approved by ${esc(r.approver ?? "you")}. Tell the assistant to repeat the action.</p>`);
    return page(
      "Approval needed",
      `<p>An assistant wants to do this:</p>${details(r)}<p>Only continue if you asked for exactly this. Sign in to review and approve.</p>
<form method=post action="/approve/${esc(id)}/start">${button("Sign in with Google")}</form>`,
    );
  }

  if (action === "start" && req.method === "POST") {
    const state = `ap.${rand()}`;
    const verifier = rand(32) + rand(32);
    await env.OAUTH_KV.put(`apstate:${state}`, JSON.stringify({ id, verifier }), { expirationTtl: 600 });
    const challenge = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
    const g = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    g.search = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID, redirect_uri: `${url.origin}/callback`, response_type: "code", scope: "openid email",
      state, code_challenge: challenge, code_challenge_method: "S256", prompt: "select_account",
    }).toString();
    return new Response(null, { status: 302, headers: { Location: g.toString(), "cache-control": "no-store" } });
  }

  if ((action === "confirm" || action === "deny") && req.method === "POST") {
    const form = await req.formData();
    const nonce = String(form.get("nonce") ?? "");
    const key = `apconfirm:${nonce}`;
    const raw = nonce ? await env.OAUTH_KV.get(key) : null;
    const c = raw ? (JSON.parse(raw) as { id: string; email: string }) : null;
    if (!c || c.id !== id) return page("Session expired", "<p>Sign in again from the approval link.</p>", 400);
    await env.OAUTH_KV.delete(key);
    if (action === "deny") {
      await env.OAUTH_KV.delete(`approval:${id}`);
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
  const raw = await env.OAUTH_KV.get(`apstate:${state}`);
  if (!raw) return page("Sign-in expired", "<p>Open the approval link again.</p>", 400);
  await env.OAUTH_KV.delete(`apstate:${state}`);
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
  if (!r) return page("Approval not found", "<p>It was already used or has expired.</p>", 404);
  const nonce = rand(24);
  await env.OAUTH_KV.put(`apconfirm:${nonce}`, JSON.stringify({ id, email: u.email }), { expirationTtl: 300 });
  return page(
    "Review and approve",
    `<p>Signed in as ${esc(u.email)}. The assistant wants to:</p>${details(r)}
<form method=post action="/approve/${esc(id)}/confirm" style="display:inline"><input type=hidden name=nonce value="${esc(nonce)}">${button("Approve this action")}</form>
<form method=post action="/approve/${esc(id)}/deny" style="display:inline"><input type=hidden name=nonce value="${esc(nonce)}">${button("Deny", true)}</form>`,
  );
}
