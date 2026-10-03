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
- `src/default-hosts.ts`: built-in approved hosts, plus validation/parsing of the `hosts:` comment line.
- `src/infisical.ts`: thin Infisical REST client (Universal Auth). `getSecretValue` is server-side only.
- `src/google-handler.ts`: Google sign-in, consent page, `/callback`. Bad OAuth params return 400, not a crash.
- `wrangler.jsonc`: config vars and the KV binding. No separate config file.

## Tools
- **`api_request`** (main): authenticated HTTPS call. `auth_type`: bearer (default), header, basic, query,
  aws_sigv4. Uploads: `multipart` or `body_base64` (5 MB cap). Redirects are not followed.
- Supporting: `list_environments`, `list_folders`, `list_secrets`, `get_secret`, `add_secret`, `update_secret`,
  `delete_secret` (needs `confirm: true`). These never return secret values.

**Host binding (deny by default):** a secret can only be sent to approved hosts: (1) built-in per well-known secret name
(`src/default-hosts.ts`), (2) a `hosts: a.com, *.b.com` line in the secret's own comment, written by `add_secret`'s `hosts`
argument and locked afterwards (`update_secret` preserves it and strips any `hosts:` in new comment text), (3) the
`API_HOSTS` var in `wrangler.jsonc`, which wins over both (`"NAME": []` disables). Wildcards need 2 labels and are
refused on shared-hosting domains. `${REF}` secret references are never expanded. Only the owner changes approvals.

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
- Only the owner widens approved hosts (`API_HOSTS`, `default-hosts.ts`, a secret's `hosts:` comment) or `ALLOWED_EMAILS`; do not do it unprompted.
- Avoid renaming the Worker: that changes the URL and breaks the Google redirect URI and connectors.
- Develop on the branch you are given; open a draft PR into `main`.
