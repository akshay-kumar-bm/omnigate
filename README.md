# universal-api-mcp

Universal API MCP server. (The Cloudflare Worker is still named `infisical-mcp`, so its URL and the Google redirect URI are unchanged.)

One MCP server that lets Claude call **any HTTPS API or integration** (GitHub, Jira, Notion, Stripe, Slack, AWS, ...) with credentials kept in Infisical, so the model never sees a token. Runs on Cloudflare Workers (free plan) behind Google sign-in.

Main tool: **`api_request`**. Supporting tools for the credentials it uses: `list_environments`, `list_folders`, `list_secrets`, `get_secret`, `add_secret`, `update_secret`, `delete_secret` (needs `confirm: true`).

**Values never come back to the client.** List/get use `viewSecretValue=false` and responses are redacted. `add_secret`/`update_secret` do pass the new value through the MCP client once.

## Making API calls: `api_request`
Connect this MCP to any Claude session and it can call any HTTPS API or integration with a stored token without ever seeing the token. To connect a new integration: `add_secret` its token, `add_secret` its token with `hosts`. No redeploy needed. The model passes the secret *name*; the Worker reads the value from Infisical, adds the auth, calls the API and returns only the response (the token is redacted from it).

```
api_request { url: "https://api.notion.com/v1/users/me", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" } }
api_request { url: "https://api.github.com/user", secret: "GH_TOKEN" }
api_request { url: "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", auth_type: "aws_sigv4", aws_service: "sts", aws_region: "us-east-1" }
```
`auth_type`: `bearer` (default), `header` (`header_name`, `header_prefix`), `basic` (`secret` = `user:pass`, or `username` + secret as password), `query` (`query_param`), `aws_sigv4` (uses the secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`).

**File uploads.** `multipart` sends a `multipart/form-data` form with files; `body_base64` sends raw bytes. Both take base64 data, up to 5 MB decoded per request, and cannot be combined with `body`. Example, uploading an image to a Notion row (the same two calls the Notion docs describe):
```
1. api_request { url: "https://api.notion.com/v1/file_uploads", method: "POST", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, body: { filename: "card.png", content_type: "image/png" } }          -> id
2. api_request { url: "https://api.notion.com/v1/file_uploads/<id>/send", method: "POST", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, multipart: { files: [{ filename: "card.png", content_type: "image/png", data_base64: "<...>" }] } }
3. api_request { url: "https://api.notion.com/v1/pages/<page>", method: "PATCH", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, body: { properties: { Image: { files: [{ name: "card.png", type: "file_upload", file_upload: { id: "<id>" } }] } } } }
```
S3: `PUT https://<bucket>.s3.<region>.amazonaws.com/<key>` with `auth_type: aws_sigv4`, `aws_service: s3` and `body_base64`.

**Safety rules**
- A secret can only be sent to the hosts in **its own comment**, a line like `hosts: api.example.com, *.example.com`. There is no built-in list and no config var: no `hosts:` line means the secret is never sent anywhere (fine for IDs and config).
  - `add_secret` takes `hosts` and writes that line. It is visible in Infisical and as `approved_hosts` in `list_secrets`/`get_secret`.
  - Hosts are **fixed at creation**: `update_secret` keeps the line and drops any `hosts:` typed into a new comment, so a tricked model can't point an existing token at another site. The owner can edit the comment in the Infisical dashboard.
  - Hosts must be bare hostnames (no scheme, path, port, IP or internal domain). Wildcards need two labels (`*.example.com`, matches any subdomain depth, never the bare domain) and are refused on shared-hosting domains such as `*.workers.dev` or `*.github.io`.
  - To connect a new service: `add_secret` its token with `hosts` (e.g. `["api.linear.app"]`). No redeploy.
- Secret references (`${OTHER}`) are not expanded when `api_request` reads a value, so a secret can't be used to leak another secret.
- HTTPS only, default port only, redirects are not followed, 25 s timeout, response body capped at 60 KB, uploads capped at 5 MB, secrets redacted from the body and headers. The client may not set its own `Authorization` header.
- Secrets are read from `DEFAULT_ENVIRONMENT` (`dev`) unless `environment` is passed. Keep one Infisical folder per service (`/notion`, `/github`, ...): `api_request` finds a secret by name in any folder, refuses to guess if the same name is in several (pass `path`), and `list_secrets` searches all folders by default. `add_secret` takes `path` to choose the folder.
- This is not a shell: it cannot run CLIs like `aws` or `gh`. For those, use `infisical run --env=dev -- <cmd>` in a session that has the Infisical CLI.

## Approval for destructive actions
These always need a human, enforced by the server (not by the model):
- `delete_secret`, and `update_secret` with a new value or name.
- `api_request` that is destructive: method `DELETE`; a GraphQL mutation whose field names contain delete/destroy/remove/archive/purge/trash (e.g. Linear `issueDelete`); or a JSON body that sets `archived`/`trashed`/`deleted`/`in_trash` to `true` (how Notion and GitHub archive).

Everything else (reads, creates, other writes, comment-only edits) runs automatically.
1. The first call returns `approval_required` with an `approve_url` and does nothing.
2. The user opens the link. The first time, it goes straight to Google sign-in (an account in `ALLOWED_EMAILS`); that leaves a 12-hour `HttpOnly` session cookie in their browser. After that, every approval link opens directly to a page showing the exact action with **Approve** and **Deny** buttons, so approving is one click. The page has a "Sign out of approvals" button. A model can't do this: it never has the cookie, and the confirm request needs both the cookie and a one-time nonce that was issued for that person and that approval.
3. The model repeats the identical call with `approval_id`. The approval is bound to the exact tool and arguments (a different URL, name or body is refused), works once, and expires after 15 minutes.

Approval records, sign-in sessions and one-time nonces live in a **Durable Object** (`ApprovalStore`), not Workers KV: KV is only eventually consistent, so an approval made in one region could still read as "pending" in another for up to a minute. A Durable Object reads its own writes everywhere, so a retry right after you click Approve sees it.

Limits: detection of non-`DELETE` destructive API calls is best effort (`src/destructive.ts`). It reads GraphQL field names (aliases can't hide them; string literals and comments are ignored) and archive-style flags, but a destructive operation that uses other wording or a persisted query id is not recognised. Method-override headers are refused so they can't disguise a `DELETE`.

## Deploy
Pushes to `main` deploy automatically via GitHub Actions (`.github/workflows/deploy.yml`; repo secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`). The steps below are the one-time setup and the manual route.
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
