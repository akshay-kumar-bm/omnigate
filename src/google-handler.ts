// Google sign-in behind the Workers OAuth provider. Only emails in ALLOWED_EMAILS get a token.
// Uses the library's consent/upstream helpers (CSRF-bound consent, bound state, no framing).
import { finishApprovalSignIn, handleApprovalRequest } from "./approvals";
import type { Env } from "./index";

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export const GoogleHandler = {
  // Bad or missing OAuth params make the provider helpers throw; answer 400 instead of crashing the Worker (error 1101).
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await handle(req, env);
    } catch (e) {
      console.error("oauth handler error", e instanceof Error ? e.message : e);
      return new Response(`Bad request: ${e instanceof Error ? e.message : "invalid OAuth request"}`, { status: 400 });
    }
  },
};

async function handle(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const oauth = env.OAUTH_PROVIDER;
    const redirectUri = `${url.origin}/callback`;

    // Human approval of destructive actions (see approvals.ts). Its Google sign-in returns to /callback with state "ap.*".
    const approval = await handleApprovalRequest(req, env);
    if (approval) return approval;
    if (url.pathname === "/callback" && (url.searchParams.get("state") ?? "").startsWith("ap.")) return finishApprovalSignIn(req, env);

    if (url.pathname === "/authorize" && req.method === "GET") {
      const request = await oauth.parseAuthRequest(req);
      const client = await oauth.lookupClient(request.clientId);
      const consent = await oauth.beginConsent(request);
      const html = `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Authorize</title><body style="font-family:system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem">
<h2>Authorize MCP client</h2>
<p><b>${esc(client?.clientName ?? request.clientId)}</b> wants access to your Infisical secrets MCP server.</p>
<form method=post action=/authorize><input type=hidden name=handle value="${esc(consent.handle)}">
<button style="padding:.6rem 1.2rem;font-size:1rem">Continue with Google</button></form></body>`;
      consent.headers.set("content-type", "text/html; charset=utf-8");
      return new Response(html, { headers: consent.headers });
    }

    if (url.pathname === "/authorize" && req.method === "POST") {
      const form = await req.formData();
      const approved = await oauth.approveConsent(req, String(form.get("handle")));
      const verifier = crypto.randomUUID() + crypto.randomUUID();
      const challenge = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)))))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const { state, headers } = await oauth.beginUpstream(approved.request, { data: { verifier }, headers: approved.headers });
      const g = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      g.search = new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID, redirect_uri: redirectUri, response_type: "code",
        scope: "openid email profile", state, code_challenge: challenge, code_challenge_method: "S256",
        prompt: "select_account",
      }).toString();
      headers.set("Location", g.toString());
      return new Response(null, { status: 302, headers });
    }

    if (url.pathname === "/callback" && req.method === "GET") {
      const { request: original, data, headers } = await oauth.finishUpstream(req) as { request: any; data: { verifier: string }; headers: Headers };
      if (url.searchParams.get("error") || !url.searchParams.get("code")) return new Response("Sign-in was cancelled.", { status: 400, headers });

      const tr = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code: url.searchParams.get("code")!, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: redirectUri, grant_type: "authorization_code", code_verifier: data.verifier,
        }),
      });
      if (!tr.ok) return new Response("Google token exchange failed", { status: 502 });
      const { access_token } = (await tr.json()) as { access_token: string };
      const ur = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { authorization: `Bearer ${access_token}` } });
      if (!ur.ok) return new Response("Google userinfo failed", { status: 502 });
      const u = (await ur.json()) as { sub: string; email?: string; email_verified?: boolean; name?: string };

      const allowed = env.ALLOWED_EMAILS.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
      if (!u.email || !u.email_verified || !allowed.includes(u.email.toLowerCase())) {
        return new Response("This Google account is not allowed.", { status: 403, headers });
      }
      const { redirectTo } = await oauth.completeAuthorization({
        request: original, userId: u.sub, metadata: { label: u.email }, scope: original.scope,
        props: { email: u.email, name: u.name ?? u.email },
      });
      headers.set("Location", redirectTo);
      return new Response(null, { status: 302, headers });
    }

    return new Response("Not found", { status: 404 });
}
