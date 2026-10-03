# infisical-mcp

Remote MCP server on Cloudflare Workers (free plan) for Infisical secrets, behind Google sign-in.

Tools: `list_environments`, `list_folders`, `list_secrets`, `get_secret`, `add_secret`, `update_secret`, `delete_secret` (needs `confirm: true`).

**Values never come back.** List/get use `viewSecretValue=false` and responses are redacted. `get_secret` returns metadata plus a placeholder like `infisical-agent-proxy:dev:MY_KEY`. Configure a matching *proxied service* in Infisical so an Infisical Agent Proxy swaps the placeholder for the real credential on outbound requests. (The proxy is a CLI forward proxy and cannot run inside a Worker.) Note `add_secret`/`update_secret` do pass the new value through the MCP client once.

## Deploy
1. `npm install --legacy-peer-deps`
2. `npx wrangler login`
3. `npx wrangler kv namespace create OAUTH_KV` -> put the id in `wrangler.jsonc`
4. Infisical: create a Universal Auth Machine Identity, grant it access to the project (read/create/edit/delete secrets as you want). Put the project ID in `INFISICAL_PROJECT_ID`; use `https://eu.infisical.com` for `INFISICAL_HOST` if on EU cloud.
5. Google Cloud Console -> APIs & Services -> Credentials -> OAuth client (Web). Authorized redirect URI: `https://<PUBLIC_URL host>/callback`.
6. Set `PUBLIC_URL` (e.g. `https://infisical-mcp.<you>.workers.dev`) and `ALLOWED_EMAILS` in `wrangler.jsonc`.
7. Secrets:
   ```
   npx wrangler secret put INFISICAL_CLIENT_ID
   npx wrangler secret put INFISICAL_CLIENT_SECRET
   npx wrangler secret put GOOGLE_CLIENT_ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET
   ```
8. `npx wrangler deploy`
9. In Claude: Settings -> Connectors -> Add custom connector -> `https://<PUBLIC_URL host>/mcp`.

## Notes
- Verified against Infisical docs: v4 list/get/delete secrets, v2 folders. v4 create/update and the environments lookup follow the same shape but were not checked live; test them first.
- Local dev: `.dev.vars` with the four secrets, `PUBLIC_URL=http://localhost:8787`, `npx wrangler dev`.
