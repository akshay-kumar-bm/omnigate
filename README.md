# Omnigate

**Omnigate**: one MCP server instead of many. *Omni*: every API, AWS and multi-step task through one server. *Gate*: credentials stay behind it, every action is checked, and risky ones wait for your approval.
(Repo `universal-api-mcp`; the Cloudflare Worker is still named `infisical-mcp`, so its URL and the Google redirect URI are unchanged.)

One MCP server that lets Claude call **any HTTPS API or integration** (GitHub, Jira, Notion, Stripe, Slack, Google, ...) with credentials kept in Infisical, so the model never sees a token. Runs on Cloudflare Workers (free plan) behind Google sign-in.

Six tools: **`api_request`** (one call), **`run_code`** (multi-step work as JavaScript on the server), **`open_gateway`** (curl, SDKs and the real `aws` CLI from an agent's shell, through the server), `list_secrets` (which credentials exist and where each may be sent), `get_upload_url` and `issue_temp_token` (below). Design and threat model: [docs/design-credential-broker.md](docs/design-credential-broker.md). The server cannot create, change or delete secrets: the owner manages them in the Infisical dashboard. The tool list is kept short on purpose, so small models spend fewer tokens on it.

**Values never come back to the client.** `list_secrets` uses `viewSecretValue=false` and returns only name, folder, approved hosts and any note.

## Making API calls: `api_request`
Connect this MCP to any Claude session and it can call any HTTPS API or integration with a stored token without ever seeing the token. To connect a new integration: add its token in Infisical with a `hosts:` comment line (below). No redeploy needed. The model passes the secret *name*; the Worker reads the value from Infisical, adds the auth, calls the API and returns only the response (the token is redacted from it).

```
api_request { url: "https://api.notion.com/v1/users/me", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" } }
api_request { url: "https://api.github.com/user", secret: "GH_TOKEN" }
api_request { url: "https://gmail.googleapis.com/gmail/v1/users/me/messages", auth_type: "oauth2_refresh", secret: "GOOGLE_OAUTH" }
```
`auth_type`: `bearer` (default), `header` (`header_name`, `header_prefix`), `basic` (`secret` = `user:pass`, or `username` + secret as password), `query` (`query_param`), `oauth2_refresh` (below).

**OAuth APIs (Google, Microsoft, ...): `oauth2_refresh`.** These need a short-lived access token instead of a fixed key. Store one secret whose value is JSON, and the Worker trades the refresh token for an access token (cached until a minute before it expires) and sends it as `Bearer`:
```
name:    GOOGLE_OAUTH            (folder /google)
value:   {"client_id":"...","client_secret":"...","refresh_token":"...","token_url":"https://oauth2.googleapis.com/token"}
comment: hosts: *.googleapis.com
```
`token_url`'s host must also be in the `hosts:` line (for Microsoft: `hosts: graph.microsoft.com, login.microsoftonline.com`), so the refresh token only goes where you allowed. Optional `scope` is sent with the refresh (Microsoft wants it). Providers that invalidate the old refresh token on every refresh are not supported, because this server never writes secrets.
Google one-time setup: Google Cloud Console → enable the APIs (Gmail, Drive, Calendar, ...) → OAuth consent screen, publishing status **In production** (unverified is fine for your own account; in Testing mode Google expires refresh tokens after 7 days) → Clients → new OAuth client of type **Web application** (not the Worker's sign-in client) with the redirect URI `https://developers.google.com/oauthplayground` → in [OAuth Playground](https://developers.google.com/oauthplayground), gear icon → "Use your own OAuth credentials", enter the scopes you want (space-separated), authorize, then "Exchange authorization code for tokens" → put the refresh token in the JSON and paste it into Infisical. One token covers every API whose scope you granted; adding a scope later means a new refresh token.

**AWS: `aws`.** Store one secret per AWS identity whose value is JSON; the Worker signs every request (SigV4) and the key never leaves it:
```
name:    AWS_ADMIN               (folder /aws)
value:   {"access_key_id":"AKIA...","secret_access_key":"...","region":"ap-south-1","role_arn":"arn:aws:iam::123456789012:role/agent"}
comment: hosts: sts.ap-south-1.amazonaws.com, *.ap-south-1.amazonaws.com
         approve: writes
         allow: aws dynamodb:PutItem
```
- `role_arn` is optional but recommended: the stored keys are then only used for `sts:AssumeRole`, and requests are signed with 15-minute role credentials, so the role's IAM policy caps what any request can do. Optional `external_id`, `session_seconds`, `session_token`.
- `*.amazonaws.com` is refused as a wildcard (anyone can create an S3 bucket under it); name hosts per region as above, plus `iam.amazonaws.com` if you use IAM.
- AWS approvals are decided by the **action**, not the HTTP method (most AWS reads are POSTs): `Describe*`/`Get*`/`List*`/`Query`/`Scan`/S3 `GET` are reads; `Delete*`, `Terminate*`, `Stop*`, `Remove*`, `Revoke*`, ..., every IAM/Organizations/KMS change, policy changes, `ssm:SendCommand`/`StartSession` and `iam:CreateAccessKey` always need approval; anything else is a write (needs approval with `approve: writes` unless an `allow: aws service:Action` line covers it; `*` works inside the action, e.g. `allow: aws s3:Put*`). See `src/aws.ts`.
- Reads that return secrets (`secretsmanager:GetSecretValue`, SSM `SecureString` parameters, `sts:AssumeRole`, `kms:Decrypt`, `ecr:GetAuthorizationToken`, ...) run, but the secret fields go into the **session vault** and the response shows `vault:<name>` instead.
- `api_request` with an AWS secret: pass the endpoint URL (`https://dynamodb.ap-south-1.amazonaws.com/`), headers and body as the API expects; `aws_service`/`aws_region` only if the host doesn't make them clear. For several calls use `run_code`'s `aws.call`.

**Session vault (`capture`).** Values a call returns that the model must not see, such as an API key an admin call just created, can be kept server-side: `api_request { ..., capture: { newkey: "$.key" } }` stores the value for 60 minutes (`capture_minutes`, max 24 h) and the response shows `vault:newkey`. Later calls use `secret: "vault:newkey"` or `{{vault:newkey}}` in a header, URL or body; the server substitutes it right before sending and redacts it. A vault value may only go to the hosts of the secret that produced it; sending it anywhere else needs an approval naming that host.

**`approve: all`** (for production secrets): every call with the secret, reads included, needs approval.

**File uploads.** `multipart` sends a `multipart/form-data` form with files; `body_base64` sends raw bytes. Both take base64 data, up to 5 MB decoded per request, and cannot be combined with `body`. Example, uploading an image to a Notion row (the same two calls the Notion docs describe):
```
1. api_request { url: "https://api.notion.com/v1/file_uploads", method: "POST", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, body: { filename: "card.png", content_type: "image/png" } }          -> id
2. api_request { url: "https://api.notion.com/v1/file_uploads/<id>/send", method: "POST", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, multipart: { files: [{ filename: "card.png", content_type: "image/png", data_base64: "<...>" }] } }
3. api_request { url: "https://api.notion.com/v1/pages/<page>", method: "PATCH", secret: "NOTION_TOKEN", headers: { "Notion-Version": "2022-06-28" }, body: { properties: { Image: { files: [{ name: "card.png", type: "file_upload", file_upload: { id: "<id>" } }] } } } }
```

**Safety rules**
- A secret can only be sent to the hosts in **its own comment**, a line like `hosts: api.example.com, *.example.com`. There is no built-in list and no config var: no `hosts:` line means the secret is never sent anywhere (fine for IDs and config).
  - Only the owner writes that line, in the Infisical dashboard; no tool can create or edit a secret, so a tricked model can't point a token at another site. It shows as `hosts` in `list_secrets`.
  - Hosts must be bare hostnames (no scheme, path, port, IP or internal domain). Wildcards need two labels (`*.example.com`, matches any subdomain depth, never the bare domain) and are refused on shared-hosting domains such as `*.workers.dev` or `*.github.io`.
  - To connect a new service: add the token in Infisical, in its own folder (e.g. `/linear`), with the comment `hosts: api.linear.app`. No redeploy.
- Secret references (`${OTHER}`) are not expanded when `api_request` reads a value, so a secret can't be used to leak another secret.
- HTTPS only, default port only, redirects are not followed, 3-minute timeout, response body capped at 60 KB, uploads capped at 5 MB, secrets redacted from the body and headers. The client may not set its own `Authorization` header.
- Secrets are read from `DEFAULT_ENVIRONMENT` (`dev`) unless `environment` is passed. Keep one Infisical folder per service (`/notion`, `/github`, ...): `api_request` finds a secret by name in any folder, refuses to guess if the same name is in several (pass `path`), and `list_secrets` searches all folders by default.
- `api_request` and `run_code` are not a shell. For CLIs and SDKs on the agent's own machine use `open_gateway` (below); only as a last resort `infisical run --env=dev -- <cmd>` with a token from `issue_temp_token`.
  - With a token from `issue_temp_token`: `infisical run --token="$INFISICAL_TOKEN" --domain=https://us.infisical.com --projectId=<id> --env=dev --path=/github -- gh api user`. Use the real command after `--`, not another `infisical run`.
  - To clone with the injected token use `git` (e.g. `-c http.extraheader=...`), not `gh repo clone`: that uses GraphQL, which Claude Code sessions can't call.

## Multi-step work: `run_code`
The assistant writes JavaScript (the body of an async function) and the server runs it in an isolated sandbox with no network and no secrets: on the **free plan** in **QuickJS** (a small JavaScript engine compiled to WebAssembly, inside the Worker; `src/quick-run.ts`), on the paid plan in a fresh **Cloudflare Dynamic Worker** per run. The engine is picked automatically: the `LOADER` binding present means Dynamic Workers. The only way out is a set of helpers that run back in this Worker through the same checks as `api_request` (hosts, approvals, redaction, vault):
```js
// run_code { purpose: "check user 1 and the app log", secrets: ["AWS_ADMIN", "GH_TOKEN"], code: `...` }
const [item, repos] = await Promise.all([
  aws.call("AWS_ADMIN", { service: "dynamodb", action: "GetItem", params: { TableName: "users", Key: { id: { S: "1" } } } }),
  api.get("GH_TOKEN", "https://api.github.com/user/repos"),
]);
const obj = await aws.request("AWS_ADMIN", { service: "s3", method: "GET", path: "/my-bucket/config.json" });
const cmd = await aws.call("AWS_ADMIN", { service: "ssm", action: "SendCommand",      // asks for approval
  params: { InstanceIds: ["i-0abc"], DocumentName: "AWS-RunShellScript", Parameters: { commands: ["tail -n 200 /var/log/app.log"] } } });
await sleep(3000);
const out = await aws.call("AWS_ADMIN", { service: "ssm", action: "GetCommandInvocation", params: { CommandId: cmd.body.Command.CommandId, InstanceId: "i-0abc" } });
return { user: item.body.Item, repos: repos.body.length, config: obj.body, log: out.body.StandardOutputContent };
```
- Helpers: `api.get/post/put/patch/delete/request` (same arguments as `api_request`), `aws.call` (JSON and query AWS APIs; XML is parsed), `aws.request` (REST AWS APIs such as S3, path-style), `vault.list/delete`, `sleep`, `input`, `console.log`. Only the return value and logs come back (100 KB), so filter big data in code.
- **Approvals pause the run.** A call that needs approval stops the run and returns `approval_required`; after the user approves, the assistant repeats `run_code` with the same code plus `approval_id`. Finished calls are replayed from a journal (Durable Object, 1 h), not repeated, and the approved call goes out. Changed code or arguments are refused.
- `secrets` lists what the code may use. Limits: 300 calls per run, 6 in flight, 120 s wall time by default (max 600).
- **Free plan request budget.** Cloudflare allows 50 outbound requests per invocation on the free plan. Within a run each secret is read from Infisical once (not per call), so a call costs about one outbound request, and a segment makes up to 35 live calls (`RUN_CODE_CALL_BUDGET`). The server then **continues by itself**: each segment runs as a fresh invocation of the Worker (the `RunSegment` entrypoint via `ctx.exports`) and resumes the same run from its journal, up to 8 segments (~280 calls) or ~50 s per tool call. Only after that does the tool return a **checkpoint** (`checkpoint: true`, `run_id`); the assistant then calls `run_code` with ONLY `resume_run_id` (never resending code, purpose or input) until `ok: true`. Finished calls are replayed, never repeated. If the platform limit is hit anyway, that also becomes a checkpoint.
- **Big responses.** Inside `run_code`, a response over 60 KB (or `max_bytes`, up to 500 KB) comes back with `truncated: true`, `original_bytes`/`returned_bytes`, `body: null` plus `body_text` when it was JSON (never a cut-off string that won't parse), a `sample` of the full response's shape (keys, types, array lengths, first item; ~2 KB, redacted) and a hint; a log line says what was cut. Pass `pick: ["$.results[*].id", "$.has_more"]` to get only those fields, in their original nesting. A return value over 100 KB comes back as `truncated: true` with a `sample` instead of failing. (`api_request` itself is unchanged.)
- **Resume with ids only.** The server keeps each run's code, secrets, purpose and input for 1 hour, so continuing after an approval, a checkpoint or a failure is just `run_code({resume_run_id, approval_id?})`. Code sent along must match the stored copy; approvals stay bound to the stored program and the exact call.
- **Failures keep finished work.** A failed run returns `completed_calls` and `run_id`; after fixing the cause (e.g. renewing an expired key), resuming retries only the calls that got an error status (only after a failed run; continuing from a checkpoint replays them).
- **Free plan (QuickJS):** Cloudflare gives a free Worker about 10 ms of CPU per request, so code should orchestrate calls and filter results, not compute heavily; a runaway loop is stopped after a fixed number of steps (`RUN_CODE_MAX_STEPS` var, default 200, about 8 ms) with a clear error. Waiting for APIs costs no CPU. No `fetch`, `setTimeout` or Node APIs inside; use the helpers.
- **Dynamic Workers:** uncomment the `LOADER` Worker Loader binding in `wrangler.jsonc` and deploy; same helpers, real V8 (much faster than QuickJS within the same CPU limit). Cloudflare's pricing page lists them for Workers Paid; if they turn out not to run on your plan, `run_code` falls back to QuickJS by itself (calls that already ran are replayed, not repeated) and the result says `engine`. If Cloudflare refuses the deploy because of the binding, the previous version keeps running: comment the line out again. Optional var `RUN_CODE_CPU_MS` sets a lower CPU limit per run.

## Agents with a shell: `open_gateway`
For Claude Code and cloud sessions that want curl, an SDK or the real **`aws` CLI**, with nothing to install and no real credential in the sandbox. `open_gateway { secrets: ["AWS_ADMIN", "GH_TOKEN"], minutes: 30, purpose: "..." }` always needs approval (with a tick box) and returns a **gateway token** plus lines to run:
```bash
export GATEWAY_TOKEN='gwt_...'
curl -sS -H "Authorization: Bearer $GATEWAY_TOKEN" https://infisical-mcp.shipengine-ai.workers.dev/gw/GH_TOKEN/api.github.com/user
export AWS_ACCESS_KEY_ID=GW... AWS_SECRET_ACCESS_KEY=gateway-dummy-key AWS_SESSION_TOKEN="$GATEWAY_TOKEN"
export AWS_ENDPOINT_URL=https://infisical-mcp.shipengine-ai.workers.dev AWS_REGION=ap-south-1 AWS_DEFAULT_REGION=ap-south-1
aws configure set default.s3.addressing_style path
aws dynamodb get-item --table-name users --key '{"id":{"S":"1"}}'
```
- HTTP: `https://<worker>/gw/<SECRET>/<api-host>/<path>`, gateway token where the API key would go (`Authorization: Bearer`/`Basic`, `x-api-key` or `x-gateway-token`); other auth styles via `x-gateway-auth: header|query|basic` and `x-gateway-header-name` etc.
- AWS: the CLI signs with a dummy key; the Worker checks the gateway token (sent as `X-Amz-Security-Token`), takes service and region from the signature, maps them to the real endpoint and signs again with the real (or AssumeRole) credentials. Works with the AWS CLI, boto3 and the other SDKs. Newer CLIs' chunked S3 uploads are decoded.
- Same policy as `api_request`. A request that needs approval fails with a message containing the link; after the user approves, **re-running the identical command** goes through (the approval is bound to the session and the request, once, 15 minutes).
- The token is a gateway credential: only for this server, only the listed secrets, at most 60 minutes. Cloud sessions need the Worker's host in their environment's allowed hosts.
- Not through the gateway: commands that sign locally (`aws s3 presign`, `aws eks get-token`, `aws rds generate-db-auth-token`) and interactive `aws ssm start-session`. Read logs with `ssm send-command` (with approval) instead of SSH.

## Approval for destructive actions
These always need a human, enforced by the server (not by the model):
- `api_request` that is destructive: method `DELETE`; a GraphQL mutation whose field names contain delete/destroy/remove/archive/purge/trash (e.g. Linear `issueDelete`); a JSON body that sets `archived`/`trashed`/`deleted`/`in_trash` to `true` (how Notion and GitHub archive); a URL whose last part is a trash/delete action (`/trash`, `/delete`, `/batchDelete`, `/emptyTrash`, `:delete`, e.g. Gmail `POST .../messages/{id}/trash`); or Gmail send (`.../messages/send`, `.../drafts/send`), which can't be undone.

Everything else (reads, creates, other writes) runs automatically, unless the secret is in strict mode (next section).

**Strict mode: approve every write (`approve: writes`).** Pattern detection can never list every way an API can lose data (a Docs `batchUpdate` delete, a Gmail `TRASH` label, a filter, sharing a Drive file, clearing a sheet, a batch request with a DELETE inside). For a powerful credential, turn the rule around in the secret's own comment, which only the owner writes:
```
hosts: *.googleapis.com
approve: writes
allow: POST gmail.googleapis.com/gmail/v1/users/me/drafts
allow: POST sheets.googleapis.com/v4/spreadsheets/<sheet id>/values/*:append
```
- `approve: writes`: every `POST`/`PUT`/`PATCH`/`DELETE` with this secret needs approval, whatever the URL or body. Reads (`GET`/`HEAD`) don't. Any `approve:` line turns it on, so a typo fails closed.
- `allow: METHOD host/path`: the only writes that run without approval. `METHOD` is `POST`, `PUT` or `PATCH`; the host is exact (no wildcards); the whole path must match, and `*` matches within one path segment only, so `values/*:append` covers append but not `:clear`, another sheet, or a batch endpoint. Query strings are not checked, so think about them (e.g. Calendar `sendUpdates=all` emails attendees). A path with an encoded `/` never matches. Invalid lines are ignored. An allow line never waives the approval for `DELETE` or the destructive patterns above.
- `list_secrets` shows `approval: "writes"` and the `allow` list, so the model knows in advance and can prefer an allowed action (draft instead of send).

**What the approval page shows.** A plain-language summary line first (e.g. "Create Google Sheet "Email Summaries" with 31 rows × 7 columns", "Append 3 rows × 2 columns to Sheet1!A1", "Create Notion page "Weekly report" in database …", or method + host + path with the number of items), a preview table of the first 10 records when the body holds a list (Sheets `rowData`/`values`, or any array of objects), then the method, host and decoded path, the query and why approval is needed, and the full body (compact, up to 200 KB) in a collapsed section. The page has no script. The model is told the same summary line, not the body. For Gmail send the base64 message is decoded into From / To / Cc / **Bcc** / **Reply-To** / Subject / the first lines / attachment names (Bcc, Reply-To and attachments are highlighted, since they are how mail is quietly copied or redirected). `drafts/send` carries only a draft id, so the server reads that draft's headers first and shows them.

**Recommended Google setup** (defence in depth: Google refuses what the scope doesn't allow, the server asks for the rest):
- Scopes: `gmail.modify` instead of `https://mail.google.com/` (no permanent delete, no filters or forwarding), `calendar.events` instead of `calendar` (no deleting or re-sharing calendars), plus `drive`, `documents`, `spreadsheets`.
- The secret comment above: drafts and appending to one sheet run unattended; sending, trashing, labels, edits, sharing and invites wait for a click.
- Scheduled agents should read and draft; you send.
- Not covered: an agent that reads your mail and leaks it through its own shell (`curl` in Claude Code). Run mail automations without a shell or with network access restricted.

1. The first call returns `approval_required` with an `approve_url` and does nothing.
2. The user opens the link. The first time, it goes straight to Google sign-in (an account in `ALLOWED_EMAILS`); that leaves a 12-hour `HttpOnly` session cookie in their browser. After that, every approval link opens directly to a page showing the exact action with **Approve** and **Deny** buttons, so approving is one click. The page has a "Sign out of approvals" button. A model can't do this: it never has the cookie, and the confirm request needs both the cookie and a one-time nonce that was issued for that person and that approval.
3. The model repeats the identical call with `approval_id`. The approval is bound to the exact tool and arguments (a different URL, name or body is refused), works once, and expires after 15 minutes.

Approval records, sign-in sessions and one-time nonces live in a **Durable Object** (`ApprovalStore`), not Workers KV: KV is only eventually consistent, so an approval made in one region could still read as "pending" in another for up to a minute. A Durable Object reads its own writes everywhere, so a retry right after you click Approve sees it.

Limits: detection of non-`DELETE` destructive API calls is best effort (`src/destructive.ts`). It reads GraphQL field names (aliases can't hide them; string literals and comments are ignored) and archive-style flags, but a destructive operation that uses other wording or a persisted query id is not recognised. Method-override headers are refused so they can't disguise a `DELETE`.

## Big files (`get_upload_url`)
The assistant asks for an upload URL, runs one `curl -T <file> <url>` from its own machine (the file never passes through the chat), and gets a temporary download URL to give to other API calls. No approval step. The upload URL lasts 5 minutes and signs `If-None-Match: *`, so R2 accepts only the first write; the download URL lasts 1 hour; a bucket lifecycle rule deletes objects under `tmp/` after 1 day. Until R2 is configured the tool returns the setup steps:
```
npx wrangler r2 bucket create <bucket>
npx wrangler r2 bucket lifecycle add <bucket> --name expire-tmp --prefix tmp/ --expire-days 1
# R2 > Manage API tokens > Object Read & Write on that bucket, then:
npx wrangler secret put R2_ACCESS_KEY_ID
npx wrangler secret put R2_SECRET_ACCESS_KEY
# and add R2_ACCOUNT_ID and R2_BUCKET as vars in wrangler.jsonc
```
The uploading machine must be allowed to reach `<account id>.r2.cloudflarestorage.com`.

To send the stored file somewhere, pass its download URL to `api_request` as `body_source` (raw body) or as a multipart file's `source` (e.g. Notion `POST /v1/file_uploads/{id}/send`). The Worker reads it from R2 itself, so the bytes never pass through the chat (max 40 MB). Only files stored by `get_upload_url` can be read this way.

The other direction works too: pass `save_response: true` to `api_request` and a successful response body is written to the same bucket and returned as `saved.download_url` (1 hour, deleted after a day) instead of the body. Use it for binary output, e.g. text-to-speech in one call:
```json
{ "url": "https://api.elevenlabs.io/v1/text-to-speech/<voice id>", "method": "POST", "auth_type": "header", "header_name": "xi-api-key",
  "secret": "ELEVENLABS_API_KEY", "body": { "text": "Hello", "model_id": "eleven_multilingual_v2" }, "save_response": true }
```
The file is named from the response's `Content-Disposition`, else `response.<ext>` from its `Content-Type` (e.g. `response.mp3`).
Max 40 MB. Error statuses come back as text and are not saved. A response that contains the secret itself is refused rather than stored (binary can't be redacted). Storage is checked before the call, so a paid API is not charged for output that can't be kept. The saved file can be forwarded with `body_source`.

## Temporary tokens for CLIs (`issue_temp_token`)
For tools that need credentials in their own environment (the AWS CLI, terraform), `issue_temp_token` gives the assistant a short-lived Infisical token to use with `infisical run -- <command>`. **Every request needs a person**: the approval page shows the purpose, project, folder and the token's lifetime, and the approver must tick a "give token" box (enforced on the server). The token comes from a separate limited "agent" identity (Worker secrets `AGENT_INFISICAL_CLIENT_ID` / `AGENT_INFISICAL_CLIENT_SECRET`), never the server's own, and the server refuses to hand out one that lives longer than 1 hour. Not set up yet? The tool says so and returns the steps. Full guide (agent identity, AWS CLI, running the Agent Proxy server): [docs/agent-access.md](docs/agent-access.md).

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
