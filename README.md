# infisical-mcp

Remote MCP server on Cloudflare Workers (free plan) for Infisical secrets, behind Google sign-in.

Tools: `list_environments`, `list_folders`, `list_secrets`, `get_secret`, `add_secret`, `update_secret`, `delete_secret` (needs `confirm: true`), `call_api`.

**Values never come back to the client.** List/get use `viewSecretValue=false` and responses are redacted. `add_secret`/`update_secret` do pass the new value through the MCP client once.

## Making API calls: `call_api`
Connect this MCP to any Claude session and it can call any HTTPS API with a stored token without ever seeing the token. The model passes the secret *name*; the Worker reads the value from Infisical, adds the auth, calls the API and returns only the response (the token is redacted from it).

```
call_api { url: "https://api.notion.com/v1/users/me", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" } }
call_api { url: "https://api.github.com/user", secret: "GH_TOKEN" }
call_api { url: "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", auth_type: "aws_sigv4", aws_service: "sts", aws_region: "us-east-1" }
```
`auth_type`: `bearer` (default), `header` (`header_name`, `header_prefix`), `basic` (`secret` = `user:pass`, or `username` + secret as password), `query` (`query_param`), `aws_sigv4` (uses the secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`).

**File uploads.** `multipart` sends a `multipart/form-data` form with files; `body_base64` sends raw bytes. Both take base64 data, up to 5 MB decoded per request, and cannot be combined with `body`. Example, uploading an image to a Notion row (the same two calls the Notion docs describe):
```
1. call_api { url: "https://api.notion.com/v1/file_uploads", method: "POST", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, body: { filename: "card.png", content_type: "image/png" } }          -> id
2. call_api { url: "https://api.notion.com/v1/file_uploads/<id>/send", method: "POST", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, multipart: { files: [{ filename: "card.png", content_type: "image/png", data_base64: "<...>" }] } }
3. call_api { url: "https://api.notion.com/v1/pages/<page>", method: "PATCH", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, body: { properties: { Image: { files: [{ name: "card.png", type: "file_upload", file_upload: { id: "<id>" } }] } } } }
```
S3: `PUT https://<bucket>.s3.<region>.amazonaws.com/<key>` with `auth_type: aws_sigv4`, `aws_service: s3` and `body_base64`.

**Safety rules**
- A secret can only be sent to hosts listed for it in the `API_HOSTS` var in `wrangler.jsonc` (deny by default; `*.example.com` matches any subdomain depth). Only the Worker owner can change it, by redeploying. To add a service: store its token (`add_secret`), add `"MY_TOKEN": ["api.example.com"]` to `API_HOSTS`, `npx wrangler deploy`.
- HTTPS only, default port only, redirects are not followed, 25 s timeout, response body capped at 60 KB, uploads capped at 5 MB, secrets redacted from the body and headers. The client may not set its own `Authorization` header.
- Secrets are read from `DEFAULT_ENVIRONMENT` (`dev`) unless `environment`/`path` is passed.
- This is not a shell: it cannot run CLIs like `aws` or `gh`. For those, use `infisical run --env=dev -- <cmd>` in a session that has the Infisical CLI.

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
