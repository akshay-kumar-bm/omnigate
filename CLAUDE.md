# universal-api-mcp

Remote MCP server (Cloudflare Worker, TypeScript) that lets Claude call **any HTTPS API or integration**
(GitHub, Jira, Notion, Stripe, Google, ...) using credentials kept in Infisical. The model passes a secret
**name**; the Worker reads the value, adds the auth, calls the API and returns the response with the secret
redacted. The model never sees a token. Sign-in is Google OAuth, limited to `ALLOWED_EMAILS`.

- Repo: `shipengineai/universal-api-mcp` (formerly `infisical-mcp`). The Worker is still named `infisical-mcp`.
- Live URL: `https://infisical-mcp.shipengine-ai.workers.dev` (MCP endpoint: `/mcp`). Google redirect URI: `/callback`.
- Infisical: US cloud (`https://us.infisical.com`), project id in `wrangler.jsonc`, default env `dev`.

## Layout
- `src/index.ts`: wires the OAuth provider (`/mcp`, `/authorize`, `/token`, `/register`) around the MCP server.
- `src/server.ts`: the MCP server and its tools (no Cloudflare-only imports, so it runs under Node for tests).
- `src/api-call.ts`: the `api_request` logic (auth types incl. aws, host check, uploads, redaction, vault refs/capture); `brokerFetch` is the one place a credential is attached, used by all three entry points.
- `src/api-schema.ts`: the zod schema of api_request arguments (shared with run_code so sandbox calls are validated the same way).
- `src/policy.ts`: the ONE approval policy for api_request, run_code and the gateway (destructive patterns, AWS actions, vault host binding, `approve:`/`allow:` lines) and the approval page spec.
- `src/aws.ts`: AWS secrets (JSON, optional role_arn -> AssumeRole), endpoints, building JSON/query calls, classifying every AWS request by action (read/secret/write/destructive), XML->JSON, aws-chunked decoding.
- `src/vault.ts`: session vault (Durable Object, TTL): captured values, `vault:<name>` handles, `{{vault:name}}` substitution, host binding.
- `src/run-code.ts` / `src/broker-rpc.ts`: run_code (Worker Loader sandbox, no network; `Broker` RPC entrypoint; journal + pause/replay for approvals). broker-rpc.ts is the only file importing cloudflare:workers for this.
- `src/gateway.ts`: open_gateway sessions and the `/gw/...` + AWS-CLI gateway (routed in index.ts before the OAuth provider).
- `src/approval-store.ts` / `src/store-core.ts`: the Durable Object and its Node-testable logic (expiry, sweep).
- `src/destructive.ts`: best-effort detection of destructive api_request calls beyond HTTP DELETE.
- `src/preview.ts`: what the approval page shows for an api_request (pure; decodes Gmail RFC 822 messages).
- `src/approvals.ts`: approval records (Durable Object `ApprovalStore`, strongly consistent; KV only as a test fallback), the `/approve/*` pages, and the approval Google sign-in via `/callback` (state `ap.*`).
- `src/temp-token.ts` / `src/guide.ts`: agent-identity token minting; setup/usage text returned by `issue_temp_token` (full guide: `docs/agent-access.md`).
- `src/uploads.ts`: `get_upload_url` (R2 presigned URLs; setup text lives here).
- `src/hosts.ts`: validation and parsing of the `hosts:`, `approve:` and `allow:` comment lines.
- `src/infisical.ts`: thin Infisical REST client (Universal Auth). `getSecretValue` is server-side only.
- `src/google-handler.ts`: Google sign-in, consent page, `/callback`. Bad OAuth params return 400, not a crash.
- `wrangler.jsonc`: config vars, the KV binding and the `LOADER` Worker Loader binding (run_code). No separate config file.

## Tools
- **`api_request`** (main): authenticated HTTPS call. `auth_type`: bearer (default), header, basic, query,
  oauth2_refresh, aws. `secret` is always required (an Infisical name or a vault handle `vault:<name>`). `aws`: the secret is JSON
  `{access_key_id, secret_access_key, region?, role_arn?, external_id?, session_seconds?, session_token?}`, detected automatically;
  with role_arn the stored keys only call sts:AssumeRole (STS host must be in `hosts:`). AWS approvals go by action (`classifyAws`).
  `capture: {name: "$.path"}` keeps response values in the session vault; AWS secret-returning reads are captured automatically.
  `oauth2_refresh` (Google, Microsoft, ...): the secret is JSON `{client_id, client_secret?, refresh_token, token_url, scope?}`;
  the Worker posts the refresh token to `token_url` (its host must also be in the secret's `hosts:` line), caches the access
  token per isolate until a minute before expiry, sends it as Bearer and redacts all three values. A secret whose value is
  such JSON is never sent as is: with auth_type left out (or bearer) it uses oauth2_refresh automatically, and any other
  auth_type is refused (`isOAuthSecret`). `auth_type` has no schema default, so "left out" stays visible to the server. Providers that invalidate
  the old refresh token on each refresh are not supported (the server cannot write secrets). Uploads: `multipart` or `body_base64` (5 MB cap), or `body_source` / a multipart file's `source` = the download URL (or key) from `get_upload_url`: the Worker reads the stored file from R2 itself and forwards it (40 MB cap, held in memory); only keys under `tmp/<uuid>/` in our bucket are readable, never other URLs (`fetchStored` in `src/uploads.ts`). Redirects are not followed. Upstream timeout is 3 minutes (`TIMEOUT_MS` in `src/api-call.ts`; high-quality image generation needs it).
  Downloads: `save_response: true` stores a 2xx body in R2 (`saveStored`, same `tmp/<uuid>/` keys) and returns a presigned
  download URL instead of the body (40 MB cap; refused if the bytes contain the secret; storage checked before the call).
- `issue_temp_token`: short-lived Infisical token (limited agent identity) for CLIs like aws; ALWAYS needs approval with a
  must-tick "give token" box; refuses lifetimes over 1 h; shows the identity's measured access (read scope, can it write?). The agent identity belongs only to a separate small project (`AGENT_PROJECT_ID`, "cli-secrets"), not the main one: Infisical's plan has no per-folder roles, so a separate project is the only way to limit what a token can read. See `docs/agent-access.md`.
- `get_upload_url`: NO approval by design. Returns a presigned R2 PUT (5 min, signs `If-None-Match: *` so only the first write to the random key succeeds) for the assistant to `curl -T <file>` (the curl also sends a `Content-Type` guessed from the file name, which Notion checks), plus a presigned GET (1 h) to hand to other APIs. Objects live under `tmp/` and a bucket lifecycle rule deletes them after 1 day (the shortest R2 allows); the tool reports whether that rule exists. Needs `R2_ACCOUNT_ID`, `R2_BUCKET` (vars) and `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` (Worker secrets); until set it returns the setup steps.
- `run_code`: the assistant's JavaScript runs in a Dynamic Worker (Worker Loader) with `globalOutbound: null`; it can only call
  `api.*`, `aws.call/request`, `vault.*` via the `Broker` RPC stub, which go through `callApi` + `approvalNeed` like api_request.
  A call needing approval pauses the run; the repeat call with approval_id replays journaled calls (no repeats). Never give the
  sandbox env, secrets or a network.
- `open_gateway`: ALWAYS needs approval (tick box). Returns a gateway token (`gwt_...`, max 60 min) for named secrets: HTTP via
  `/gw/<SECRET>/<host>/<path>`, AWS CLI via `AWS_ENDPOINT_URL=<worker>` + gateway key id + token as `AWS_SESSION_TOKEN` (the Worker
  re-signs). Same policy; approvals are bound to session + request so re-running the identical command works after approval.
- `list_secrets`: name, folder, approved `hosts` and any note per secret (plus the environment once). Never values; no timestamps or other
  metadata, to save tokens. That is the whole tool list (6 tools), kept short for small models. There are deliberately NO tools to
  add, update or delete secrets, list folders/environments or show guides: the owner manages secrets in the Infisical dashboard and
  always uses `dev`. Do not add them back without being asked. All tool results are compact JSON (no indentation).

**Approvals:** destructive `api_request` calls (DELETE, GraphQL delete/archive-style mutations, bodies setting
archived/trashed/deleted true, URLs ending in /trash, /delete, /batchDelete, /emptyTrash or `:delete`, and Gmail send; see `src/destructive.ts`) and every `issue_temp_token` need a human: the
first call returns `approval_required` + a link (`src/approvals.ts`); the user signs in with Google once (12 h session cookie), then each link is one click; the repeat
call with `approval_id` runs once, only for the exact same arguments, within 15 minutes. Never bypass or weaken this.
The same policy (`src/policy.ts`) covers api_request, every run_code call and every gateway request; also AWS destructive /
always-ask actions (`src/aws.ts`), sending a vault value to a host it was not created for, and `approve: all` (every call).

**Strict mode (per secret):** an `approve:` line in the secret's comment (owner-written, like `hosts:`) makes EVERY write
(POST/PUT/PATCH/DELETE) with it need approval, except `allow: METHOD host/path` lines (POST/PUT/PATCH only, exact host,
whole path, `*` = within one segment, encoded `/` never matches; `commentPolicy` / `writeAllowed` in `src/hosts.ts`,
`writeApprovalReason` in `src/api-call.ts`). Allow lines never waive the destructive patterns. Fail closed: any `approve:`
value turns it on; invalid allow lines are ignored. `list_secrets` shows `approval` and `allow`. The approval page text
comes from `src/preview.ts` (decodes Gmail messages: From/To/Cc/Bcc/Reply-To/Subject/body/attachments; for `drafts/send`
the server reads the draft's headers first).

The approval page (`src/approvals.ts`) is script-free; a request can carry an `ack` checkbox that the server enforces.

**Folders:** secrets live in one Infisical folder per service (`/notion`, `/github`, `/linear`, `/tavily`, `/firecrawl`, `/google`).
`api_request` finds a secret by name in any folder (error if the name exists in several; pass `path`).

**Host binding (deny by default):** a secret can only be sent to the hosts in its own comment, a `hosts: a.com, *.b.com`
line that only the owner writes, in the Infisical dashboard (no tool can create or edit a secret). No built-in list, no config var; no `hosts:` line means never sent. Wildcards need 2
labels and are refused on shared-hosting domains. `${REF}` secret references are never expanded.

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
git-ignored `.wrangler/`) using real Infisical credentials from the environment; check status codes and redaction only. Without Infisical credentials, monkeypatch `infisical.getSecretValue`/`findSecretPaths`
and `globalThis.fetch` in the script and pass an in-memory `OAUTH_KV` (no `APPROVAL_STORE`). run_code needs workerd: run a tiny
test entry (exporting `Broker`, calling `runCode`) with `wrangler dev -c <test config>` that has `worker_loaders` and a local KV.
Check a deploy with:
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
