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

export interface AccessSummary {
  folders: { path: string; count: number }[];
  total: number;
  canWrite: boolean | null; // null = could not tell
}

// Measures what a freshly minted token can really do, so the person approving sees facts instead of a generic warning.
// Reading is listed with values hidden. Writing is probed by deleting a secret that does not exist: Infisical answers
// 403 if the identity may not delete and 404 if it may, and nothing is ever deleted or changed.
export async function probeAccess(env: { INFISICAL_HOST: string }, token: string, projectId: string, environment: string): Promise<AccessSummary> {
  const h = { authorization: `Bearer ${token}` };
  const q = new URLSearchParams({ projectId, environment, secretPath: "/", recursive: "true", viewSecretValue: "false", expandSecretReferences: "false", includeImports: "false" });
  const r = await fetch(`${env.INFISICAL_HOST}/api/v4/secrets?${q}`, { headers: h });
  const secrets: { secretPath?: string }[] = r.ok ? ((await r.json()) as any).secrets ?? [] : [];
  const byPath = new Map<string, number>();
  for (const x of secrets) byPath.set(x.secretPath ?? "/", (byPath.get(x.secretPath ?? "/") ?? 0) + 1);
  const folders = [...byPath].map(([path, count]) => ({ path, count })).sort((a, b) => a.path.localeCompare(b.path));
  let canWrite: boolean | null = r.ok ? false : null;
  for (const path of ["/", ...folders.map((f) => f.path)].slice(0, 12)) {
    const d = await fetch(`${env.INFISICAL_HOST}/api/v4/secrets/ZZ_ACCESS_PROBE_${crypto.randomUUID().slice(0, 8)}`, {
      method: "DELETE", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify({ projectId, environment, secretPath: path, type: "shared" }),
    });
    if (d.status === 404) { canWrite = true; break; } // allowed to delete, there was just nothing by that name
    if (d.status !== 403 && d.status !== 400) canWrite = canWrite === false ? null : canWrite;
  }
  return { folders, total: secrets.length, canWrite };
}
