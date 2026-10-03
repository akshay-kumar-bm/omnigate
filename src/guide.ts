// Setup and usage guides returned by the issue_temp_token and access_guide tools. Kept in step with docs/agent-access.md.
export type Topic = "overview" | "agent_identity" | "proxy" | "aws";

const AGENT_IDENTITY = `Create the limited "agent" identity (one time, in the Infisical dashboard, by the owner)
1. Machine Identities -> create one named e.g. "assistant-agent" with Universal Auth.
2. Set Access Token TTL and Max TTL short: 900-3600 seconds. That is how long a token this server hands out lives, and the server REFUSES to hand out any token that lives longer than 1 hour (Infisical's default is much longer). Optionally set "Access Token Max Number of Uses".
3. Add the identity to the project with a custom role that can only do what the assistant needs, for example: read secrets in environment dev, folder /aws only. Do not give it create, edit or delete.
4. Create a client secret for it, then store both values as Worker secrets (the server's own identity is NOT used for tokens):
     echo -n '<client-id>'     | npx wrangler secret put AGENT_INFISICAL_CLIENT_ID
     echo -n '<client-secret>' | npx wrangler secret put AGENT_INFISICAL_CLIENT_SECRET
   (pipe the bare value in: no "NAME=" prefix, no spaces)
Every token request then needs the owner's approval with the "give token" box ticked.`;

const PROXY = `Agent Proxy (placeholders and credential injection for bearer-token and API-key APIs such as GitHub, Notion, Linear)
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
Docs: https://infisical.com/docs/documentation/platform/agent-proxy/standalone-agent-proxy`;

const AWS = `Running the AWS CLI with Infisical secrets
Do NOT route the AWS CLI through the Agent Proxy. The docs describe header rewrites and placeholder substitution only, and the AWS CLI signs each request (SigV4) with the secret key on the client, so a placeholder key produces a signature the proxy cannot fix. This is my reading of the docs, not something I tested.
Use a temporary token with "infisical run" instead (this is how it was tested here):
1. Store the AWS credentials in a folder, e.g. /aws in dev: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION (and AWS_SESSION_TOKEN if you use temporary ones). Use an IAM user or role with the least rights that work.
2. Ask the assistant for a token (issue_temp_token, use=aws_cli); you approve with the box ticked.
3. Run, with the token it returns:
     export INFISICAL_TOKEN='<token>'
     infisical run --token="$INFISICAL_TOKEN" --domain=<infisical-host> --projectId=<project-id> --env=dev --path=/aws -- aws sts get-caller-identity
   "infisical run" puts the secrets into that one aws process only. Try "aws sts get-caller-identity" first, then your real command.
Even better: an Infisical AWS IAM dynamic secret ("Temporary Credentials" mode, up to 12 hours) hands out short-lived AWS credentials instead of a stored key. Docs: https://infisical.com/docs/documentation/platform/dynamic-secrets/aws-iam (not tested here).`;

const OVERVIEW = `How the pieces fit
- api_request: the assistant calls HTTPS APIs; this server adds the credential. No setup beyond storing the token with hosts.
- issue_temp_token: for real CLIs (aws, terraform, gh) that need credentials in their environment. The owner approves each request and ticks a box; the assistant gets a short-lived Infisical token for a limited agent identity and uses "infisical run".
- Agent Proxy: for bearer-token/API-key APIs when the assistant runs on a machine you control and should never hold the credential at all.
Topics: agent_identity, proxy, aws.`;

const TOPICS: Record<Topic, string> = { overview: OVERVIEW, agent_identity: AGENT_IDENTITY, proxy: PROXY, aws: AWS };
export const guide = (topic: Topic = "overview") => TOPICS[topic];
export const fullGuide = () => [OVERVIEW, AGENT_IDENTITY, AWS, PROXY].join("\n\n");

// Commands for a freshly issued token. The token itself is returned in its own field and referenced as $INFISICAL_TOKEN.
export function usage(a: { use: "aws_cli" | "infisical_run" | "rest_api"; host: string; projectId: string; environment: string; path: string }): string {
  const run = `infisical run --token="$INFISICAL_TOKEN" --domain=${a.host} --projectId=${a.projectId} --env=${a.environment} --path=${a.path} --`;
  const head = `export INFISICAL_TOKEN='<the token above>'   # do not print it or paste it anywhere else`;
  if (a.use === "aws_cli") {
    return `${head}\n${run} aws sts get-caller-identity   # then your real aws command\nThe folder ${a.path} needs AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_DEFAULT_REGION. Install the CLI if needed: npm install -g @infisical/cli`;
  }
  if (a.use === "infisical_run") {
    return `${head}\n${run} <your command>   # secrets from ${a.environment}${a.path} are injected as environment variables for that command only`;
  }
  return `curl -s -H "Authorization: Bearer $INFISICAL_TOKEN" "${a.host}/api/v4/secrets?projectId=${a.projectId}&environment=${a.environment}&secretPath=${a.path}"   # lists what the agent identity may read`;
}
