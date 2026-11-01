// Text returned by issue_temp_token: setup steps when no agent identity exists, and usage steps for a new token.
// The full guide (Agent Proxy, AWS CLI) lives in docs/agent-access.md.
export const AGENT_IDENTITY_SETUP = `Create the limited "agent" identity (one time, in the Infisical dashboard, by the owner)
1. Machine Identities -> create one named e.g. "assistant-agent" with Universal Auth.
2. Set Access Token TTL and Max TTL short: 900-3600 seconds. That is how long a token this server hands out lives, and the server REFUSES to hand out any token that lives longer than 1 hour (Infisical's default is much longer). Optionally set "Access Token Max Number of Uses".
3. Add the identity to the project with a custom role that can only do what the assistant needs, for example: read secrets in environment dev, folder /aws only. Do not give it create, edit or delete.
4. Create a client secret for it, then store both values as Worker secrets (the server's own identity is NOT used for tokens):
     echo -n '<client-id>'     | npx wrangler secret put AGENT_INFISICAL_CLIENT_ID
     echo -n '<client-secret>' | npx wrangler secret put AGENT_INFISICAL_CLIENT_SECRET
   (pipe the bare value in: no "NAME=" prefix, no spaces)
Every token request then needs the owner's approval with the "give token" box ticked.`;

// Steps for a freshly issued token. Generic on purpose: the same text for any CLI and any use.
export function usage(a: { host: string; projectId: string; environment: string }): string {
  return `1. Install the CLI once: npm install -g @infisical/cli
2. Set the token once as a global environment variable (never print it): echo "export INFISICAL_TOKEN='<the token above>'" >> ~/.bashrc && export INFISICAL_TOKEN='<the token above>'
   Later commands pick it up; do not ask for a new token each time. It stops working when it expires.
3. Run any command with the secrets of a folder injected into it (the CLI reads INFISICAL_TOKEN):
   infisical run --silent --domain=${a.host} --projectId=${a.projectId} --env=${a.environment} --path=<folder, e.g. /github> -- <command>
   A command that uses $VARS must be wrapped: sh -c '<command using $VARS>'`;
}
