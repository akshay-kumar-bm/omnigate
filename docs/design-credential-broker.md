# Design: credential broker, `run_code` and the agent gateway

Status: **steps 1-5 implemented** in this branch: broker core, AWS adapter, session vault, `run_code` and the gateway
(sections 5-8 and 10; the AWS, vault, run_code and gateway parts). Not yet built: the new OAuth adapters (client
credentials, Google service account, GitHub App), databases, the audit log page and the `/sessions` revoke page.
Owner decisions are marked *(decided)*. Defaults chosen without an explicit answer: `ssm:SendCommand` always needs
approval (a safe-command allow list can come later).

## 1. Problem

Today the server does one authenticated HTTPS call per tool call (`api_request`). That leaves three gaps:

1. **AWS.** SigV4 was removed. The only path is `issue_temp_token` + `infisical run -- aws ...`, which puts a real
   Infisical token (and through it the AWS keys) inside the agent's sandbox.
2. **Created credentials.** An admin call that creates a key/password/client secret returns it straight to the model
   (only the secret *used* for the call is redacted), and there is no way to use it in a later call without the model
   seeing it.
3. **One step at a time.** Sequential, parallel, nested and conditional work needs a model round trip per call, and
   every intermediate value (including sensitive ones) passes through the chat.

## 2. Goals and non-goals

Goals
- Any task you could do with an API, an SDK or the **AWS CLI**, from **claude.ai chat**, **Claude Code** and
  **Claude Code cloud sessions** *(decided: these are the main clients)*.
- Credential types in use *(decided)*: **GitHub, Google, generic OAuth, AWS**; plus **databases** *(decided)*.
- Full control flow: sequential, parallel, nested, loops, conditions, retries.
- The model and the agent's sandbox **never hold a real credential**, including credentials created during a task.
- Keep it easy for agents: few tools, ordinary code, copy-paste examples.
- Keep every current guarantee: owner-only `hosts:` binding, approvals that cannot be bypassed, redaction, no redirects.

Non-goals
- No tool that returns secret values. No tool that creates/edits Infisical secrets (owner keeps doing that).
- No SSH/shell on remote servers *(decided: HTTPS + databases only)*.
- Saving created credentials into Infisical is out *(decided: session vault only)*.

## 3. What the research says (summary)

- Agents do better writing **code that calls tools** than calling tools one by one: control flow runs in code, large
  results are filtered before the model sees them, and tool definitions load on demand
  ([Anthropic: code execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp);
  [programmatic tool calling](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling);
  Cloudflare "Code Mode").
- **Never put the secret in the sandbox**, not even as an env var: anything the agent runs can read it. The 2026
  pattern is a **credential broker**: the sandbox holds a placeholder and a proxy outside it injects the real
  credential only for approved destinations (Claude Code sandbox credential masking, Cloudflare Dynamic Worker egress
  gateways, [Infisical Agent Vault](https://infisical.com/blog/credential-brokering-for-ai-agents.md),
  [scoped credentials via proxy](https://agentpatterns.ai/security/scoped-credentials-proxy/)).
- A proxy controls *where* a request goes, not *what* it does
  ([StackOne](https://www.stackone.com/blog/ai-agent-sandbox-api-keys/)): an update and a delete carry the same
  credential. So method/path/action policy, approvals and an audit log still matter.

## 4. Architecture

One **broker core** in the Worker, three ways in:

```
                 ┌──────────────────── Broker core (this Worker) ─────────────────────┐
 api_request ───►│ resolve secret (Infisical) · hosts: binding · approve:/allow:        │──► HTTPS APIs
 run_code ──────►│ auth adapters (bearer … oauth2 … google SA … github app … aws sigv4) │──► AWS
 gateway (HTTP) ►│ session vault · redaction · destructive/strict approvals · audit log │──► Postgres / MySQL
                 └──────────────────────────────────────────────────────────────────────┘
```

| Client | Has its own sandbox? | Main way in |
|---|---|---|
| claude.ai chat / mobile | no | `run_code` (code runs on Cloudflare), `api_request` |
| Claude Code (laptop) | yes (shell) | **gateway** (curl, SDKs, `aws` CLI), `run_code` for quick jobs |
| Claude Code cloud sessions | yes (shell, egress allowlist) | **gateway**; the Worker host must be in the environment's allowed hosts |
| small models | no | `api_request` |

All three entry points call the same `brokerCall()` function, so policy is enforced in exactly one place.

### Tools after the change (6)

| Tool | Status | Purpose |
|---|---|---|
| `list_secrets` | changed | adds each secret's auth type and a one-line "how to use" |
| `api_request` | changed | gains new auth types, `capture` (vault) and `vault:` references |
| `run_code` | **new** | run JavaScript with `api`, `aws`, `db`, `vault` objects |
| `open_gateway` | **new** | (approval) start a short-lived, scoped gateway session for an agent with a shell |
| `get_upload_url` | same | large files |
| `issue_temp_token` | kept, last resort | only for tools the gateway cannot serve (see 6.5) |

## 5. Credential adapters

Each Infisical secret declares its type by its value shape or a `type:` comment line (owner-written, like `hosts:`).
Adapter output is always "a signed/authorized request"; values never leave the broker.

| Adapter | Secret value | Used for |
|---|---|---|
| `bearer`, `header`, `basic`, `query` | token string | most APIs (exists) |
| `oauth2_refresh` | JSON `{client_id, client_secret?, refresh_token, token_url, scope?}` | Google user APIs, Microsoft, … (exists) |
| `oauth2_client_credentials` **new** | JSON `{client_id, client_secret, token_url, scope?, audience?}` | machine-to-machine OAuth |
| `google_service_account` **new** | the service-account JSON key | Google Cloud / Workspace (JWT → token, optional `subject` for domain-wide delegation) |
| `github_app` **new** | JSON `{app_id, private_key, installation_id}` | GitHub App installation tokens (narrower than a PAT) |
| `aws` **new** | JSON `{access_key_id, secret_access_key, region?, role_arn?, external_id?, session_seconds?}` | SigV4 for every AWS service (section 6) |
| `db` **new** | connection URL | Postgres / MySQL (section 9) |

Tokens minted by an adapter (OAuth, JWT, STS) are cached in memory until shortly before expiry and are redacted like
the base secret. Token and STS endpoints must be in the secret's `hosts:` line.

## 6. AWS: yes, your AWS credentials work, for everything the CLI does

Your access key ID + secret access key stay in Infisical (e.g. `/aws/AWS_ADMIN`, `hosts: *.amazonaws.com`).
The Worker uses them to sign, the agent never receives them.

### 6.1 Recommended: AssumeRole per session
Put `role_arn` in the secret. The Worker calls STS `AssumeRole` with your keys, gets 15-60 min credentials for that
role, signs with those and drops them. Then even a mistake is limited to the role's IAM policy, and your base IAM
user only needs `sts:AssumeRole`. Without `role_arn` the Worker signs with the stored keys directly (simpler, wider).
You can have several secrets (e.g. `AWS_READONLY`, `AWS_DEPLOY`, `AWS_ADMIN` with `approve: all`).

### 6.2 Three ways to use it
1. **The real `aws` CLI through the gateway** (Claude Code, cloud sessions):
   ```bash
   # values come from open_gateway; they are gateway credentials, not AWS keys
   export AWS_ACCESS_KEY_ID=<gateway key id> AWS_SECRET_ACCESS_KEY=<gateway session secret>
   export AWS_ENDPOINT_URL=https://infisical-mcp.shipengine-ai.workers.dev/gw/aws/AWS_ADMIN
   aws configure set default.s3.addressing_style path
   aws sts get-caller-identity
   aws ec2 describe-instances --region ap-south-1
   aws s3 cp ./build s3://my-bucket/ --recursive
   ```
   How it works: the CLI signs each request with the gateway session secret. The Worker **verifies that signature**
   (so only the holder of the session can use it), reads `service` and `region` from the SigV4 credential scope,
   maps them to the real endpoint (`{service}.{region}.amazonaws.com`, with a small exceptions table for S3, IAM,
   STS, CloudFront, Route 53 and other global or oddly-named services), checks policy, **re-signs** with the real
   (STS) credentials and forwards. Responses stream back. `AWS_ENDPOINT_URL` (global, or per service
   `AWS_ENDPOINT_URL_<SERVICE>`) is standard in AWS CLI v2 and the SDKs, so boto3, the JS SDK, terraform's AWS
   provider and CDK work the same way.
2. **`run_code`:** `await aws.call("AWS_ADMIN", {service: "ec2", region: "ap-south-1", action: "DescribeInstances"})`
   or `aws.request({...})` for REST-style services (S3, Lambda, API Gateway).
3. **`api_request`** with `auth_type: "aws"` (auto-detected from the secret JSON) for a single signed call.

### 6.3 AWS approvals
The Worker knows the action of every AWS request (`X-Amz-Target`, `Action=` in query/form, or method + path for REST
services). Rules, fail closed:
- `Describe*`, `Get*`, `List*`, `Head*` (and S3 GET/HEAD): no approval, unless the secret has `approve: all`.
- Other actions are writes: follow the secret's `approve:` / `allow:` lines (allow lines can name actions, e.g.
  `allow: aws s3:PutObject my-bucket/*`).
- **Always approval:** `Delete*`, `Terminate*`, `Remove*`, `Detach*`, `Revoke*`, `Deregister*`, `Disable*`,
  `Put*Policy`, `Attach*Policy`, `CreateAccessKey`, `UpdateAssumeRolePolicy`, `StopInstances`, S3 `DELETE` and
  `PutBucketPolicy`, and anything in IAM/Organizations/KMS that is not a read.
- **Secret-bearing reads** (`secretsmanager:GetSecretValue`, `ssm:GetParameter(s)` with decryption,
  `iam:CreateAccessKey`, `sts:AssumeRole/GetSessionToken`): the secret fields are moved into the **vault** and the
  response shows a handle instead (section 7).
- The approval page shows service, region, action, resource ARNs/names and the parameters.

### 6.4 Approvals in the gateway without custom headers
The CLI cannot add an approval header, so approvals are bound to the **gateway session**: a request needing approval
gets `428` with an AWS-style error whose message contains the approval link; once approved, the *identical* request
(same action + parameters hash) succeeds once within 15 minutes when the agent simply re-runs the command.

### 6.5 Known AWS limits (and fallbacks)
- Things the CLI computes **locally** with the secret key cannot be brokered: `aws s3 presign`,
  `aws eks get-token`, `aws rds generate-db-auth-token`. Fallback: broker helpers that do the same server-side
  (`aws.presign(...)` returns a URL), or `issue_temp_token` with approval. `aws ecr get-login-password` works (it is
  an API call), but its result is a 12 h registry password the agent then holds, so it needs approval.
- Worker request body limit (100 MB on paid plans): `aws s3 cp` already uploads large files in 8 MB multipart chunks,
  so big uploads work; a single non-multipart PUT over the limit does not.
- SSO / `aws configure sso` profiles are not used; the broker is the identity.
- To verify during build: the endpoint map for every service you use, S3 path-style through a custom endpoint, and
  streaming of large `GetObject` responses.

## 7. Session vault *(decided)*

For values the model must not see but later steps need (newly created API keys, passwords, OAuth client secrets,
AWS keys from `CreateAccessKey`, values from Secrets Manager).

- `capture: {new_key: "$.body.api_key"}` on any call (or automatic, for known secret-bearing responses) stores the
  value in a Durable Object keyed by the signed-in user, TTL 1 h by default, 24 h max. The response shows
  `"vault:new_key"` in its place, and the value is redacted from every later output.
- Later calls reference it anywhere a secret or value is accepted: `secret: "vault:new_key"`, or `{{vault:new_key}}`
  inside a header, URL or body. Substitution happens only in the broker, right before sending.
- **Where a vault value may be sent:** by default only to the hosts of the secret that created it. Sending it to any
  other host needs an approval that names the host (stops "create a key, then post it to evil.com").
- No tool returns a vault value. Values expire; `vault.delete(name)` ends one early.

## 8. `run_code`

### 8.1 What the agent writes
```js
// tool input: { code: "...", secrets: ["GITHUB_TOKEN", "AWS_ADMIN"], timeout_s: 120 }
const repo = await api.post("GITHUB_TOKEN", "https://api.github.com/user/repos", {name: "demo"});
const [issues, pulls] = await Promise.all([
  api.get("GITHUB_TOKEN", `${repo.body.url}/issues`),
  api.get("GITHUB_TOKEN", `${repo.body.url}/pulls`),
]);
for (const r of ["ap-south-1", "us-east-1"]) {
  const out = await aws.call("AWS_READONLY", {service: "ec2", region: r, action: "DescribeInstances"});
  console.log(r, out.body.Reservations.length);
}
const key = await api.post("ADMIN_TOKEN", "https://admin.example.com/keys", {}, {capture: {k: "$.body.key"}});
await api.get("vault:k", "https://admin.example.com/whoami");
const rows = await db.query("APP_DB", "select count(*) from users where plan = $1", ["pro"]);
return {repo: repo.body.full_name, issues: issues.body.length, pros: rows[0].count};
```
Plain JavaScript gives sequential, parallel, nested, loops, conditions, try/catch and retries. Only `return` and
`console.log` output reach the model (redacted, capped in size), so large data is filtered in code.

### 8.2 Sandbox
- A **Cloudflare Dynamic Worker** (Worker Loader binding) per run: no `fetch` to the internet (`globalOutbound: null`),
  no env vars, no bindings except stubs for `api`, `aws`, `db`, `vault`. Each stub method runs back in the main Worker
  through `brokerCall()`, so the code never sees a credential and cannot skip a check
  (capability model: no stub, no access).
- `secrets` in the input lists which secrets this run may use (shown on any approval page); others are refused.
- Limits: CPU and wall time (default 2 min, max 10), max 200 broker calls, max 20 in flight, max output 100 KB.

### 8.3 Approvals inside code (pause and replay)
When a call needs approval the run stops and returns `approval_required` with the link and the exact pending call.
Every finished broker call was recorded in a run journal (Durable Object). The agent repeats `run_code` with the same
code and the `approval_id`; the code re-runs from the start, **recorded calls return their recorded result instead of
hitting the network** (matched by call arguments + occurrence), and the approved call goes out. So nothing runs twice.
If the code takes a different path on replay (e.g. uses `Date.now()` in a request), the run stops with a clear error.
Optional `approve_upfront: true`: a dry run lists every write the code reaches and asks for one approval of the list;
only works when writes do not depend on earlier write results.

## 9. Databases *(decided)*

- `db.query(secret, sql, params)` in `run_code`, and an `api_request`-style single query.
- Postgres via TCP sockets (`cloudflare:sockets`) or Hyperdrive; MySQL via TCP. Database host must be in `hosts:`.
- Default: every query runs in a `READ ONLY` transaction. A statement that writes (or any statement, with
  `approve: all`) needs approval showing the SQL and parameters. `DROP`, `TRUNCATE`, `DELETE`/`UPDATE` without
  `WHERE`, `ALTER`, `GRANT` always need approval. Row cap per result (default 1000).

## 10. Gateway sessions (`open_gateway`)

- The agent calls `open_gateway({secrets: ["GITHUB_TOKEN", "AWS_ADMIN"], minutes: 60, purpose: "..."})`.
  **Always needs approval** (like `issue_temp_token`), showing the secrets, their hosts, lifetime and purpose.
- Returns a gateway session: an id + session secret, plus ready-to-paste env lines per secret. These are broker
  credentials: usable only against this Worker, only for the listed secrets, until expiry; revocable from an
  `/sessions` page. They are not API keys and not Infisical tokens.
- HTTP APIs: `https://<worker>/gw/<SECRET_NAME>/<upstream-host>/<path>` with the session secret as the placeholder
  token (e.g. `GITHUB_TOKEN=<session secret>`, base URL `https://<worker>/gw/GITHUB_TOKEN/api.github.com`). The Worker
  checks the session, swaps in the real credential, applies all policy, forwards, redacts the response.
  Works with curl, Python `requests`/`httpx`, and SDKs that take a base URL (GitHub Octokit, Google API clients with a
  custom endpoint, Stripe, OpenAI, Notion, ...).
- AWS: section 6.2.
- Cloud sessions: their egress allowlist must include `infisical-mcp.shipengine-ai.workers.dev` (one-time environment
  setting).
- To verify: `gh` CLI (it only takes a custom *host*, not a path) and `gcloud` (custom endpoints per service); if they
  do not fit, use curl/SDKs through the gateway or `issue_temp_token`.

## 11. Production

- Separate secret names for prod (`AWS_PROD_ADMIN`, `PROD_DB`), each with its own `hosts:` line.
- New `approve: all`: every call with that secret, reads included, needs approval. Recommended for prod.
- Gateway sessions that include a prod secret show a red banner and are capped at 30 minutes.

## 12. Audit log

Every broker call (all three entry points) is logged: time, user, entry point, secret name, method/action, host,
path, status, approval id, run/session id. Never values or bodies. Stored in the Durable Object (or Workers Analytics
Engine), 30 days, viewable at `/audit` behind the same Google sign-in.

## 13. Threat model (short)

| Threat | Control |
|---|---|
| Model/sandbox exfiltrates a credential | never in the sandbox or model context; redaction of all outputs |
| Prompt injection makes the agent do harmful writes | approvals for destructive/strict/prod calls; approval shows exact action |
| Agent sends a created key to another host | vault values bound to the creator's hosts; widening needs approval |
| Stolen gateway session | scoped to named secrets, short TTL, revocable, AWS signatures verified, audit log |
| Runaway code | CPU/time/call/concurrency caps; no internet access from the sandbox |
| Replay changes behaviour after approval | journal match on exact arguments; approval bound to exact call hash |

## 14. Build plan (one draft PR each; merging deploys)

1. **This design doc.**
2. **Broker core refactor + AWS adapter** (`auth_type: aws`, AssumeRole, action classification, approvals) in
   `api_request`. Test with `aws sts get-caller-identity` equivalents.
3. **Session vault** + `capture` + auto-capture for secret-bearing responses.
4. **Gateway** (`open_gateway`, HTTP + AWS re-signing). Test the real `aws` CLI from a cloud session.
5. **`run_code`** with pause/replay.
6. **New OAuth adapters** (client credentials, Google service account, GitHub App).
7. **Databases.**
8. **Audit log page**, `approve: all`, prod banner.

## 15. Open points to confirm

- Dynamic Worker Loader availability and limits on the account's plan (Cloudflare docs could not be fetched from the
  session that wrote this; verify before step 5). Fallback if unavailable: a JSON step plan with the same broker.
- The exact AWS services you use most (to test their endpoint mapping first).
- Whether `issue_temp_token` can be retired once the gateway covers your CLIs.
