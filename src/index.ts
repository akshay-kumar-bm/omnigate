import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { GoogleHandler } from "./google-handler";
import { infisical, redact } from "./infisical";

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: any;
  // vars
  INFISICAL_HOST: string;
  INFISICAL_PROJECT_ID: string;
  DEFAULT_ENVIRONMENT: string;
  ALLOWED_EMAILS: string;
  PLACEHOLDER_PREFIX: string;
  PUBLIC_URL: string;
  // secrets
  INFISICAL_CLIENT_ID: string;
  INFISICAL_CLIENT_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
}

const ok = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: String((e as Error).message ?? e) }] });

const secretName = z.string().min(1).regex(/^[A-Za-z0-9_.\-]+$/, "letters, digits, _ . - only");

function createServer(env: Env) {
  const server = new McpServer({ name: "infisical-secrets", version: "0.1.0" });
  {
    const base = (a: { environment?: string; path?: string }) => ({
      projectId: env.INFISICAL_PROJECT_ID,
      environment: a.environment ?? env.DEFAULT_ENVIRONMENT,
      secretPath: a.path ?? "/",
    });
    const loc = {
      environment: z.string().optional().describe("Environment slug (default from config, e.g. dev)"),
      path: z.string().optional().describe("Folder path, default /"),
    };
    // The real value never leaves Infisical. Agents send this placeholder; an Infisical
    // Agent Proxy (proxied service) swaps it for the real credential on outbound requests.
    const placeholder = (name: string, b: ReturnType<typeof base>) =>
      `${env.PLACEHOLDER_PREFIX}:${b.environment}:${b.secretPath === "/" ? "" : b.secretPath.replace(/^\//, "") + ":"}${name}`;

    server.registerTool("list_environments", { description: "List environments of the configured Infisical project.", inputSchema: z.object({}) }, async () => {
      try { return ok(await infisical.listEnvironments(env, env.INFISICAL_PROJECT_ID)); } catch (e) { return fail(e); }
    });

    server.registerTool(
      "list_folders",
      { description: "List folders under a path in an environment.", inputSchema: z.object({ ...loc, recursive: z.boolean().default(false) }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.listFolders(env, { projectId: b.projectId, environment: b.environment, path: b.secretPath, recursive: a.recursive });
          return ok((r.folders ?? []).map((f: any) => ({ name: f.name, path: f.relativePath ?? f.name })));
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "list_secrets",
      { description: "List secret names and metadata. Values are never returned.", inputSchema: z.object({ ...loc, recursive: z.boolean().default(false) }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.listSecrets(env, { ...b, recursive: a.recursive });
          return ok((r.secrets ?? []).map(redact));
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "get_secret",
      { description: "Get a secret's metadata and an Agent Proxy placeholder. The raw value is never returned; use the placeholder in requests routed through Infisical Agent Proxy.", inputSchema: z.object({ name: secretName, ...loc }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.getSecret(env, a.name, b);
          return ok({ ...redact(r.secret), placeholder: placeholder(a.name, b) });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "add_secret",
      { description: "Create a new secret. The value is written to Infisical and not echoed back.", inputSchema: z.object({ name: secretName, value: z.string().min(1), comment: z.string().optional(), ...loc }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.createSecret(env, a.name, { ...b, secretValue: a.value, secretComment: a.comment ?? "" });
          return ok({ created: true, ...redact(r.secret), placeholder: placeholder(a.name, b) });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "update_secret",
      { description: "Update a secret's value, comment, or name. The value is not echoed back.", inputSchema: z.object({
        name: secretName, value: z.string().min(1).optional(), comment: z.string().optional(),
        new_name: secretName.optional(), ...loc,
      }) },
      async (a) => {
        try {
          if (a.value === undefined && a.comment === undefined && a.new_name === undefined) throw new Error("Nothing to update");
          const b = base(a);
          const body: Record<string, unknown> = { ...b };
          if (a.value !== undefined) body.secretValue = a.value;
          if (a.comment !== undefined) body.secretComment = a.comment;
          if (a.new_name !== undefined) body.newSecretName = a.new_name;
          const r = await infisical.updateSecret(env, a.name, body);
          return ok({ updated: true, ...redact(r.secret) });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "delete_secret",
      { description: "Permanently delete a secret. Requires confirm=true.", inputSchema: z.object({ name: secretName, confirm: z.literal(true).describe("Must be true"), ...loc }) },
      async (a) => {
        try {
          const b = base(a);
          await infisical.deleteSecret(env, a.name, b);
          return ok({ deleted: a.name, environment: b.environment, path: b.secretPath });
        } catch (e) { return fail(e); }
      },
    );
  }
  return server;
}

let provider: OAuthProvider<Env> | undefined;
export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Built lazily because the RFC 9728 resource URL comes from config (PUBLIC_URL).
    provider ??= new OAuthProvider<Env>({
      apiRoute: "/mcp",
      apiHandler: { fetch: (req: Request, e: Env, c: ExecutionContext) => createMcpHandler(() => createServer(e))(req, e, c) } as any,
      defaultHandler: GoogleHandler as any,
      authorizeEndpoint: "/authorize",
      tokenEndpoint: "/token",
      clientRegistrationEndpoint: "/register",
      scopesSupported: ["mcp:read", "mcp:write"],
      requiredScopes: ["mcp:read"],
      resourceMetadata: { resource: `${env.PUBLIC_URL}/mcp`, authorization_servers: [env.PUBLIC_URL] },
    } as any);
    return provider.fetch(request, env, ctx);
  },
};
