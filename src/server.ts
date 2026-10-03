import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { infisical, redact } from "./infisical";
import { approvedHosts, callApi } from "./api-call";
import { buildComment, commentHosts } from "./hosts";

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: any;
  // vars
  INFISICAL_HOST: string;
  INFISICAL_PROJECT_ID: string;
  DEFAULT_ENVIRONMENT: string;
  ALLOWED_EMAILS: string;
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

const INSTRUCTIONS = [
  "Universal API: make authenticated calls to any HTTPS API or integration (GitHub, Jira, Notion, Stripe, Slack, AWS, ...) without ever seeing the credentials.",
  "Use api_request for the call itself: pass the secret NAME plus the URL, method and body; the server adds the token and returns the response with the token redacted.",
  "Use list_secrets to see which credentials exist (names, approved hosts; never values) and add_secret to store a new one. A secret can only be sent to the hosts in its own comment (a 'hosts: ...' line, shown as approved_hosts). When you store a token with add_secret you MUST pass hosts, the API's hostnames, e.g. [\"api.linear.app\"] or [\"*.atlassian.net\"] (no scheme or path); look up the service's API host if you are unsure. Hosts are fixed when the secret is created and cannot be changed through this server, so get them right the first time; only the owner can change them later. If api_request says a host is not allowed, tell the user.",
  "Secrets are organised in one folder per service (e.g. /notion/NOTION_TOKEN). api_request finds a secret by name in any folder; pass path only if the same name exists in several. When you add a token, put it in its own folder with path (e.g. /linear).",
  "Never ask the user to paste a token into the chat if it can be stored with add_secret, and never try to read secret values back.",
].join("\n");

export function createServer(env: Env) {
  const server = new McpServer(
    {
      name: "universal-api",
      title: "Universal API",
      version: "0.2.0",
      description: "Call any HTTPS API or integration (GitHub, Jira, Notion, Stripe, Slack, AWS, ...) with credentials kept in a vault. You never see the tokens.",
    },
    { instructions: INSTRUCTIONS },
  );
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
    server.registerTool(
      "api_request",
      {
        description:
          "Make an authenticated HTTPS request to ANY API or integration (GitHub, Jira, Notion, Stripe, Slack, AWS, ...) using a credential stored in this server, without ever seeing it. Use this whenever you need to call a third-party API on the user's behalf. " +
          "Pass the secret NAME (see list_secrets); the server reads the token, adds the auth, calls the API and returns the response with the token redacted. " +
          "A secret can only be sent to the hosts in its own comment (the hosts given to add_secret; see approved_hosts in list_secrets), otherwise the call is refused and the error lists the approved hosts. Redirects are not followed. " +
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
          path: z.string().optional().describe("Folder of the secret, e.g. /notion. If omitted, the secret is found by name in any folder (an error if the name exists in several)."),
        }),
      },
      async (a) => {
        try { return ok(await callApi(env, a)); } catch (e) { return fail(e); }
      },
    );

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
      { description: "List the credentials available to api_request: names, folders, comments and the hosts each may be sent to. Values are never returned. Searches all folders by default.", inputSchema: z.object({ ...loc, recursive: z.boolean().default(true) }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.listSecrets(env, { ...b, recursive: a.recursive });
          return ok((r.secrets ?? []).map((x: any) => ({ ...redact(x), approved_hosts: approvedHosts(x.secretComment) })));
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "get_secret",
      { description: "Get a secret's metadata. The raw value is never returned; to use a secret in an API request, call api_request with its name.", inputSchema: z.object({ name: secretName, ...loc }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.getSecret(env, a.name, b);
          return ok({ ...redact(r.secret), approved_hosts: approvedHosts(r.secret?.secretComment) });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "add_secret",
      {
        description:
          "Store a new credential (e.g. a Jira or Stripe token) so api_request can use it. The value is written to Infisical and not echoed back. " +
          "hosts = the only hostnames api_request may send this secret to, e.g. [\"api.linear.app\"] or [\"*.atlassian.net\"] (no scheme, path or port). Required for any token you want to use with api_request. They are saved in the secret's comment as 'hosts: ...' and cannot be changed through this server later, so double-check them. " +
          "Omit hosts only for values that are never sent anywhere (IDs, config). comment = a free-text note.",
        inputSchema: z.object({ name: secretName, value: z.string().min(1), hosts: z.array(z.string()).max(10).optional(), comment: z.string().optional(), ...loc }),
      },
      async (a) => {
        try {
          const b = base(a);
          const note = buildComment(a.hosts, a.comment); // validates hosts; drops any 'hosts:' line typed into the note
          const r = await infisical.createSecret(env, a.name, { ...b, secretValue: a.value, secretComment: note });
          const hosts = approvedHosts(note);
          return ok({
            created: true, ...redact(r.secret), approved_hosts: hosts,
            ...(hosts.length ? {} : { note: "No hosts are approved for this secret, so api_request will refuse to send it anywhere. Fine for IDs; for a token, delete it and add it again with hosts, or ask the owner to set the comment in Infisical." }),
          });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "update_secret",
      { description: "Update a secret's value, comment (free-text note), or name. The value is not echoed back. The approved hosts (the 'hosts:' line in the comment) are kept as they are and cannot be changed here.", inputSchema: z.object({
        name: secretName, value: z.string().min(1).optional(), comment: z.string().optional(),
        new_name: secretName.optional(), ...loc,
      }) },
      async (a) => {
        try {
          if (a.value === undefined && a.comment === undefined && a.new_name === undefined) throw new Error("Nothing to update");
          const b = base(a);
          // Always send the comment back: Infisical clears it when omitted, which would also drop the approved hosts.
          const existing = (await infisical.getSecret(env, a.name, b)).secret?.secretComment ?? "";
          const body: Record<string, unknown> = { ...b, secretComment: a.comment !== undefined ? buildComment(commentHosts(existing), a.comment) : existing };
          if (a.value !== undefined) body.secretValue = a.value;
          if (a.new_name !== undefined) body.newSecretName = a.new_name;
          const r = await infisical.updateSecret(env, a.name, body);
          return ok({ updated: true, ...redact(r.secret), approved_hosts: approvedHosts(r.secret?.secretComment) });
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
