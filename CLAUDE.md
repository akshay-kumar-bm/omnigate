# universal-api-mcp

Remote MCP server (Cloudflare Worker, TypeScript) that lets Claude call **any HTTPS API or integration**
(GitHub, Jira, Notion, Stripe, AWS, ...) using credentials kept in Infisical. The model passes a secret
**name**; the Worker reads the value, adds the auth, calls the API and returns the response with the secret
redacted. The model never sees a token. Sign-in is Google OAuth, limited to `ALLOWED_EMAILS`.

- Repo: `shipengineai/universal-api-mcp` (formerly `infisical-mcp`). The Worker is still named `infisical-mcp`.
- Live URL: `https://infisical-mcp.shipengine-ai.workers.dev` (MCP endpoint: `/mcp`). Google redirect URI: `/callback`.
- Infisical: US cloud (`https://us.infisical.com`), project id in `wrangler.jsonc`, default env `dev`.

## Layout
- `src/index.ts`: wires the OAuth provider (`/mcp`, `/authorize`, `/token`, `/register`) around the MCP server.
- `src/server.ts`: the MCP server and its tools (no Cloudflare-only imports, so it runs under Node for tests).
- `src/api-call.ts`: the `api_request` logic (auth types, host check, uploads, redaction).
- `src/approval-store.ts` / `src/store-core.ts`: the Durable Object and its Node-testable logic (expiry, sweep).
- `src/destructive.ts`: best-effort detection of destructive api_request calls beyond HTTP DELETE.
- `src/approvals.ts`: approval records (Durable Object `ApprovalStore`, strongly consistent; KV only as a test fallback), the `/approve/*` pages, and the approval Google sign-in via `/callback` (state `ap.*`).
- `src/temp-token.ts` / `src/guide.ts`: agent-identity token minting; guide text (also generates `docs/agent-access.md`).
- `src/uploads.ts`: `get_upload_url` (R2 presigned URLs; setup text lives here).
- `src/hosts.ts`: validation and parsing of the `hosts:` comment line.
- `src/infisical.ts`: thin Infisical REST client (Universal Auth). `getSecretValue` is server-side only.
- `src/google-handler.ts`: Google sign-in, consent page, `/callback`. Bad OAuth params return 400, not a crash.
- `wrangler.jsonc`: config vars and the KV binding. No separate config file.

## Tools
- **`api_request`** (main): authenticated HTTPS call. `auth_type`: bearer (default), header, basic, query,
  aws_sigv4. Uploads: `multipart` or `body_base64` (5 MB cap). Redirects are not followed.
- `issue_temp_token`: short-lived Infisical token (limited agent identity) for CLIs like aws; ALWAYS needs approval with a
  must-tick "give token" box; refuses lifetimes over 1 h; shows the identity's measured access (read scope, can it write?). The agent identity belongs only to a separate small project (`AGENT_PROJECT_ID`, "cli-secrets"), not the main one: Infisical's plan has no per-folder roles, so a separate project is the only way to limit what a token can read. `access_guide`: setup text only. See `docs/agent-access.md`.
- `get_upload_url`: NO approval by design. Returns a presigned R2 PUT (5 min, signs `If-None-Match: *` so only the first write to the random key succeeds) for the assistant to `curl -T <file>`, plus a presigned GET (1 h) to hand to other APIs. Objects live under `tmp/` and a bucket lifecycle rule deletes them after 1 day (the shortest R2 allows); the tool reports whether that rule exists. Needs `R2_ACCOUNT_ID`, `R2_BUCKET` (vars) and `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` (Worker secrets); until set it returns the setup steps.
- Supporting: `list_environments`, `list_folders`, `list_secrets`, `get_secret`, `add_secret`, `update_secret`,
  `delete_secret` (needs `confirm: true`). These never return secret values.

**Approvals:** `delete_secret`, `update_secret` (new value or name) and destructive `api_request` calls (DELETE, GraphQL
delete/archive-style mutations, bodies setting archived/trashed/deleted true; see `src/destructive.ts`) need a human: the
first call returns `approval_required` + a link (`src/approvals.ts`); the user signs in with Google once (12 h session cookie), then each link is one click; the repeat
call with `approval_id` runs once, only for the exact same arguments, within 15 minutes. Never bypass or weaken this.

The approval page (`src/approvals.ts`) is script-free; a request can carry an `ack` checkbox that the server enforces.

**Folders:** secrets live in one Infisical folder per service (`/notion`, `/github`, `/linear`, `/tavily`, `/firecrawl`).
`api_request` finds a secret by name in any folder (error if the name exists in several; pass `path`).

**Host binding (deny by default):** a secret can only be sent to the hosts in its own comment, a `hosts: a.com, *.b.com`
line, written by `add_secret`'s `hosts` argument and locked afterwards (`update_secret` preserves it and strips any
`hosts:` in new comment text). No built-in list, no config var; no `hosts:` line means never sent. Wildcards need 2
labels and are refused on shared-hosting domains. `${REF}` secret references are never expanded. Only the owner
(Infisical dashboard) changes hosts on an existing secret.

## Run
```
npm install --legacy-peer-deps      # flag required by this repo; deps are pinned, keep them pinned
npm run dev                         # wrangler dev; needs .dev.vars (below)
npm run deploy                      # wrangler deploy (needs CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID)
```
**Auto-deploy:** every push to `main` runs `.github/workflows/deploy.yml` (install, typecheck, `wrangler deploy`) using
the repo secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Merging a PR therefore deploys it. The Worker's
own secrets are not part of a deploy.
`.dev.vars` (git-ignored): `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, `PUBLIC_URL=http://localhost:8787`. Production secrets are Worker secrets:
`npx wrangler secret put <NAME>` (pipe the bare value in; no `NAME=` prefix or whitespace).

## Test
There is no test suite. Before pushing run `npm run typecheck`. To exercise `api_request` without OAuth, call
`callApi` from `src/api-call.ts`, or drive the real tools with `createServer` from `src/server.ts` and an in-memory MCP
client (`InMemoryTransport` from `@modelcontextprotocol/client`), in a throwaway script (`npx tsx x.mts`, kept under the
git-ignored `.wrangler/`) using real Infisical credentials from the environment; check status codes and redaction only. Check a deploy with:
- `curl .../.well-known/oauth-authorization-server` returns 200.
- `curl -i .../mcp` returns 401 with `WWW-Authenticate` (no token).
- A bare `/authorize` or `/callback` returns 400 (expected; real clients send params).
The full flow (Google sign-in, tools) can only be checked from a Claude client connected to `/mcp`.

## Rules
- Never print, log or commit secret values or tokens. Report lengths or status codes instead.
- Do not return raw secret values to the MCP client; do not follow redirects in `api_request`.
- Only the owner widens a secret's `hosts:` comment or `ALLOWED_EMAILS`; do not do it unprompted.
- Avoid renaming the Worker: that changes the URL and breaks the Google redirect URI and connectors.
- Develop on the branch you are given; open a draft PR into `main`.
