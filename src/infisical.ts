// Thin Infisical REST client (Universal Auth machine identity).
// Endpoints: v4 secrets (list/get/create/update/delete), v2 folders, project lookup for environments.
export interface InfisicalEnv {
  INFISICAL_HOST: string;
  INFISICAL_CLIENT_ID: string;
  INFISICAL_CLIENT_SECRET: string;
}

let cached: { token: string; exp: number } | null = null;

async function getToken(env: InfisicalEnv): Promise<string> {
  if (cached && cached.exp > Date.now() + 30_000) return cached.token;
  const r = await fetch(`${env.INFISICAL_HOST}/api/v1/auth/universal-auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ clientId: env.INFISICAL_CLIENT_ID, clientSecret: env.INFISICAL_CLIENT_SECRET }),
  });
  if (!r.ok) throw new Error(`Infisical login failed (${r.status})`);
  const j = (await r.json()) as { accessToken: string; expiresIn: number };
  cached = { token: j.accessToken, exp: Date.now() + j.expiresIn * 1000 };
  return j.accessToken;
}

async function call(env: InfisicalEnv, method: string, path: string, opts: { query?: Record<string, string>; body?: unknown } = {}) {
  const url = new URL(env.INFISICAL_HOST + path);
  for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, v);
  const r = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${await getToken(env)}`,
      ...(opts.body ? { "content-type": "application/json" } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await r.text();
  let data: any;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!r.ok) throw new Error(`Infisical ${method} ${path} -> ${r.status}: ${data?.message ?? text.slice(0, 200)}`);
  return data;
}

// Strip anything that could carry the real value.
export function redact(s: any) {
  if (!s) return s;
  const { secretValue, ...rest } = s;
  return {
    name: rest.secretKey,
    environment: rest.environment,
    path: rest.secretPath,
    version: rest.version,
    type: rest.type,
    comment: rest.secretComment,
    tags: (rest.tags ?? []).map((t: any) => t.slug),
    createdAt: rest.createdAt,
    updatedAt: rest.updatedAt,
    valueHidden: true,
  };
}

export const infisical = {
  listSecrets: (env: InfisicalEnv, q: { projectId: string; environment: string; secretPath: string; recursive: boolean }) =>
    call(env, "GET", "/api/v4/secrets", {
      query: { ...q, recursive: String(q.recursive), viewSecretValue: "false", expandSecretReferences: "false", includeImports: "false" },
    }),
  getSecret: (env: InfisicalEnv, name: string, q: { projectId: string; environment: string; secretPath: string }) =>
    call(env, "GET", `/api/v4/secrets/${encodeURIComponent(name)}`, {
      query: { ...q, type: "shared", viewSecretValue: "false", expandSecretReferences: "false", includeImports: "false" },
    }),
  // Server-side use only (api_request). The value must never be returned to the MCP client.
  getSecretValue: async (env: InfisicalEnv, name: string, q: { projectId: string; environment: string; secretPath: string }): Promise<{ value: string; comment: string }> => {
    // expandSecretReferences=false: a secret whose value is "${OTHER}" must not resolve to another secret's value.
    const r = await call(env, "GET", `/api/v4/secrets/${encodeURIComponent(name)}`, {
      query: { ...q, type: "shared", viewSecretValue: "true", expandSecretReferences: "false", includeImports: "true" },
    });
    const v = r?.secret?.secretValue;
    if (typeof v !== "string" || v === "") throw new Error(`Secret ${name} has no readable value`);
    return { value: v, comment: String(r.secret.secretComment ?? "") };
  },
  // Folders of every secret with this exact name (value never requested). Used when a caller omits the path.
  findSecretPaths: async (env: InfisicalEnv, name: string, q: { projectId: string; environment: string }): Promise<string[]> => {
    const r = await call(env, "GET", "/api/v4/secrets", {
      query: { ...q, secretPath: "/", recursive: "true", viewSecretValue: "false", expandSecretReferences: "false", includeImports: "false" },
    });
    return (r.secrets ?? []).filter((x: any) => x.secretKey === name).map((x: any) => String(x.secretPath ?? "/"));
  },
  createSecret: (env: InfisicalEnv, name: string, body: Record<string, unknown>) =>
    call(env, "POST", `/api/v4/secrets/${encodeURIComponent(name)}`, { body: { type: "shared", ...body } }),
  updateSecret: (env: InfisicalEnv, name: string, body: Record<string, unknown>) =>
    call(env, "PATCH", `/api/v4/secrets/${encodeURIComponent(name)}`, { body: { type: "shared", ...body } }),
  deleteSecret: (env: InfisicalEnv, name: string, body: Record<string, unknown>) =>
    call(env, "DELETE", `/api/v4/secrets/${encodeURIComponent(name)}`, { body: { type: "shared", ...body } }),
  listFolders: (env: InfisicalEnv, q: { projectId: string; environment: string; path: string; recursive: boolean }) =>
    call(env, "GET", "/api/v2/folders", { query: { ...q, recursive: String(q.recursive) } }),
  async listEnvironments(env: InfisicalEnv, projectId: string) {
    // Project object carries its environments; try the current path then the legacy one.
    for (const p of [`/api/v1/projects/${projectId}`, `/api/v1/workspace/${projectId}`]) {
      try {
        const j = await call(env, "GET", p);
        const envs = j.environments ?? j.project?.environments ?? j.workspace?.environments;
        if (envs) return envs.map((e: any) => ({ name: e.name, slug: e.slug }));
      } catch { /* try next */ }
    }
    throw new Error("Could not read environments from Infisical project");
  },
};
