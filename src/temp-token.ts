// Mints a short-lived Infisical access token for a dedicated, least-privilege "agent" machine identity.
// It deliberately does NOT use the server's own identity (INFISICAL_CLIENT_ID), which can create and delete secrets:
// a token handed to an assistant should carry only what the agent identity was given in Infisical (for example read
// access to one folder). Its lifetime is the identity's "Access Token TTL" setting in Infisical, not chosen here.
export interface AgentTokenEnv {
  INFISICAL_HOST: string;
  AGENT_INFISICAL_CLIENT_ID?: string;
  AGENT_INFISICAL_CLIENT_SECRET?: string;
}

export const agentConfigured = (env: AgentTokenEnv) => !!(env.AGENT_INFISICAL_CLIENT_ID && env.AGENT_INFISICAL_CLIENT_SECRET);

export async function mintAgentToken(env: AgentTokenEnv): Promise<{ accessToken: string; expiresIn: number; tokenType: string }> {
  if (!agentConfigured(env)) throw new Error("The agent identity is not configured");
  const r = await fetch(`${env.INFISICAL_HOST}/api/v1/auth/universal-auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ clientId: env.AGENT_INFISICAL_CLIENT_ID, clientSecret: env.AGENT_INFISICAL_CLIENT_SECRET }),
  });
  // Never echo the response body or the credentials: only the status.
  if (!r.ok) throw new Error(`Infisical login for the agent identity failed (${r.status}). Check AGENT_INFISICAL_CLIENT_ID/SECRET.`);
  const j = (await r.json()) as { accessToken?: string; expiresIn?: number; tokenType?: string };
  if (!j.accessToken) throw new Error("Infisical returned no access token");
  return { accessToken: j.accessToken, expiresIn: j.expiresIn ?? 0, tokenType: j.tokenType ?? "Bearer" };
}
