import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";
import { GoogleHandler } from "./google-handler";
import { infisical, redact } from "./infisical";
import { callApi } from "./api-call";

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: any;
  // vars
  INFISICAL_HOST: string;
  INFISICAL_PROJECT_ID: string;
  DEFAULT_ENVIRONMENT: string;
  ALLOWED_EMAILS: string;
  API_HOSTS: string;
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
      { description: "Get a secret's metadata. The raw value is never returned; to use a secret in an API request, call call_api with its name.", inputSchema: z.object({ name: secretName, ...loc }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.getSecret(env, a.name, b);
          return ok(redact(r.secret));
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "call_api",
      {
        description:
          "Make an authenticated HTTPS API call using a stored secret without ever seeing it. Pass the secret NAME; the server reads the token, adds the auth, calls the API and returns the response. " +
          "A secret can only be sent to hosts listed for it in the server's API_HOSTS config (otherwise the call is refused). Redirects are not followed. " +
          "auth_type: bearer (default; Authorization: Bearer <secret>), header (header_name + optional header_prefix), basic (secret = 'user:pass', or username + secret as password), query (query_param), " +
          "file uploads: body_base64 (raw bytes) or multipart (form with files), up to 5 MB; aws_sigv4 (signs with secrets AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / optional AWS_SESSION_TOKEN; needs aws_service and aws_region). Do not send your own Authorization header.",
        inputSchema: z.object({
          url: z.string().url().describe("Full https:// URL"),
          method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
          headers: z.record(z.string(), z.string()).optional().describe("Extra request headers (e.g. Notion-Version, Accept)"),
          query: z.record(z.string(), z.string()).optional().describe("Query string params"),
          body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional().describe("Request body; objects/arrays are sent as JSON"),
          body_base64: z.string().optional().describe("Raw binary request body as base64 (max 5 MB decoded), e.g. PUT an object to S3. Set Content-Type in headers. Use instead of body."),
          multipart: z.object({
            fields: z.record(z.string(), z.string()).optional().describe("Plain form fields, sent before the files"),
            files: z.array(z.object({
              field: z.string().default("file").describe("Form field name, default 'file'"),
              filename: z.string(),
              content_type: z.string().optional().describe("e.g. image/png"),
              data_base64: z.string().describe("File bytes as base64"),
            })).min(1),
          }).optional().describe("multipart/form-data upload (max 5 MB total decoded), e.g. Notion /v1/file_uploads/{id}/send. Use instead of body. Not for aws_sigv4."),
          auth_type: z.enum(["bearer", "header", "basic", "query", "aws_sigv4"]).default("bearer"),
          secret: secretName.optional().describe("Name of the secret holding the token / API key (not needed for aws_sigv4)"),
          header_name: z.string().optional(),
          header_prefix: z.string().optional(),
          query_param: z.string().optional(),
          username: z.string().optional(),
          aws_service: z.string().optional().describe("e.g. s3, sts, ec2"),
          aws_region: z.string().optional().describe("e.g. us-east-1"),
          aws_access_key_secret: secretName.optional().describe("default AWS_ACCESS_KEY_ID"),
          aws_secret_key_secret: secretName.optional().describe("default AWS_SECRET_ACCESS_KEY"),
          aws_session_token_secret: secretName.optional().describe("default AWS_SESSION_TOKEN"),
          ...loc,
        }),
      },
      async (a) => {
        try { return ok(await callApi(env, a)); } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "add_secret",
      { description: "Create a new secret. The value is written to Infisical and not echoed back.", inputSchema: z.object({ name: secretName, value: z.string().min(1), comment: z.string().optional(), ...loc }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.createSecret(env, a.name, { ...b, secretValue: a.value, secretComment: a.comment ?? "" });
          return ok({ created: true, ...redact(r.secret) });
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
