# Temporary access for CLIs (AWS CLI, terraform) and the Agent Proxy

Most API calls go through `api_request`, where the server adds the credential and the assistant never sees it. Some tools cannot work that way because they need credentials in their own environment (the AWS CLI, terraform). For those there is `issue_temp_token`: it gives the assistant a **short-lived Infisical token** so it can run `infisical run -- <command>`. This file is also returned by the `access_guide` tool.

## What you get, and the rules
- **Always approved by a person.** Every `issue_temp_token` call returns an approval link first. The approver signs in with Google, sees the purpose, the project, the folder and the token's lifetime, and must **tick a box** ("Yes, give the assistant a temporary Infisical token...") before **Give token** works. The box is enforced on the server. Each approval is for that exact request, works once and expires after 15 minutes.
- **A limited identity, not the server's own.** The token comes from a separate "agent" machine identity (Worker secrets `AGENT_INFISICAL_CLIENT_ID` / `AGENT_INFISICAL_CLIENT_SECRET`). The server's own identity can create and delete secrets, so it is never used for tokens. If the agent identity is not set up, the tool returns the setup steps and issues nothing.
- **Short-lived, enforced.** The token's lifetime is the agent identity's Access Token TTL in Infisical. The server logs in first to learn it, shows it on the approval page, and **refuses** to hand out a token that lives longer than 1 hour (optional Worker variable `AGENT_TOKEN_MAX_SECONDS` changes the cap). Infisical's default TTL is much longer, so set it.
- **What the token can read is decided in Infisical,** by the agent identity's role, not by the folder the assistant names in the request. Give it the least: read-only, one environment, one folder.
- The assistant is told to treat the token as a secret: never print it, write it to a file, commit it or send it anywhere.

## Overview

```text
How the pieces fit
- api_request: the assistant calls HTTPS APIs; this server adds the credential. No setup beyond storing the token with hosts.
- issue_temp_token: for real CLIs (aws, terraform, gh) that need credentials in their environment. The owner approves each request and ticks a box; the assistant gets a short-lived Infisical token for a limited agent identity and uses "infisical run".
- Agent Proxy: for bearer-token/API-key APIs when the assistant runs on a machine you control and should never hold the credential at all.
Topics: agent_identity, proxy, aws.
```

## 1. Create the limited agent identity

```text
Create the limited "agent" identity (one time, in the Infisical dashboard, by the owner)
1. Machine Identities -> create one named e.g. "assistant-agent" with Universal Auth.
2. Set Access Token TTL and Max TTL short: 900-3600 seconds. That is how long a token this server hands out lives, and the server REFUSES to hand out any token that lives longer than 1 hour (Infisical's default is much longer). Optionally set "Access Token Max Number of Uses".
3. Add the identity to the project with a custom role that can only do what the assistant needs, for example: read secrets in environment dev, folder /aws only. Do not give it create, edit or delete.
4. Create a client secret for it, then store both values as Worker secrets (the server's own identity is NOT used for tokens):
     echo -n '<client-id>'     | npx wrangler secret put AGENT_INFISICAL_CLIENT_ID
     echo -n '<client-secret>' | npx wrangler secret put AGENT_INFISICAL_CLIENT_SECRET
   (pipe the bare value in: no "NAME=" prefix, no spaces)
Every token request then needs the owner's approval with the "give token" box ticked.
```

## 2. Run the AWS CLI

```text
Running the AWS CLI with Infisical secrets
Do NOT route the AWS CLI through the Agent Proxy. The docs describe header rewrites and placeholder substitution only, and the AWS CLI signs each request (SigV4) with the secret key on the client, so a placeholder key produces a signature the proxy cannot fix. This is my reading of the docs, not something I tested.
Use a temporary token with "infisical run" instead (this is how it was tested here):
1. Store the AWS credentials in a folder, e.g. /aws in dev: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION (and AWS_SESSION_TOKEN if you use temporary ones). Use an IAM user or role with the least rights that work.
2. Ask the assistant for a token (issue_temp_token, use=aws_cli); you approve with the box ticked.
3. Run, with the token it returns:
     export INFISICAL_TOKEN='<token>'
     infisical run --token="$INFISICAL_TOKEN" --domain=<infisical-host> --projectId=<project-id> --env=dev --path=/aws -- aws sts get-caller-identity
   "infisical run" puts the secrets into that one aws process only. Try "aws sts get-caller-identity" first, then your real command.
Even better: an Infisical AWS IAM dynamic secret ("Temporary Credentials" mode, up to 12 hours) hands out short-lived AWS credentials instead of a stored key. Docs: https://infisical.com/docs/documentation/platform/dynamic-secrets/aws-iam (not tested here).
```

## 3. Run the Agent Proxy server (for bearer-token and API-key APIs)

```text
Agent Proxy (placeholders and credential injection for bearer-token and API-key APIs such as GitHub, Notion, Linear)
The proxy sits between the assistant's HTTP client and the API and swaps the real credential in, so the assistant never holds it.
A. Proxy identity (runs the proxy): Universal Auth machine identity with "Read Value" and "Describe Secret" on the secrets the services use, and "Report Usage" on Proxied Services.
B. Agent identity (what the assistant uses): only the "Proxy" permission on Proxied Services for its environment/folder. It cannot read secret values.
C. Run the proxy on its own host, on a private network, port 17322 (not the public internet):
     export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=<proxy-client-id>
     export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=<proxy-client-secret>
     infisical secrets agent-proxy start
   or with Docker:
     docker run -p 17322:17322 -e INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=<id> -e INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=<secret> infisical/cli:latest secrets agent-proxy start
D. In Infisical, in the folder (e.g. /github) add a Proxied Service: host pattern api.github.com, header rewrite Authorization with prefix Bearer, secret GITHUB_TOKEN.
E. On the machine that runs the assistant, launch the work behind the proxy (the agent identity logs in with its own client id/secret):
     export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID=<agent-client-id>
     export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=<agent-client-secret>
     infisical secrets agent-proxy connect --proxy=<proxy-host>:17322 --projectId=<project-id> --env=dev --path=/github -- curl -s https://api.github.com/user
   Single machine, no separate host: "infisical secrets agent-proxy run -- <command>".
Docs: https://infisical.com/docs/documentation/platform/agent-proxy/standalone-agent-proxy
```

## What was tested here
`infisical run --token ...` injecting secrets into one command, the approval flow with the tick box, the lifetime cap, and that an issued token works against the Infisical API. Not tested here: a real AWS account, the AWS dynamic secret, and a running Agent Proxy host. Those steps follow Infisical's documentation.
