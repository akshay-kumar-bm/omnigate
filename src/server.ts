import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { infisical, redact } from "./infisical";
import { approvedHosts, callApi } from "./api-call";
import { checkApproval, requestApproval, type ApprovalSpec } from "./approvals";
import { agentConfigured, mintAgentToken, probeAccess, type AccessSummary } from "./temp-token";
import { fullGuide, guide, usage, type Topic, type Use } from "./guide";
import { destructiveReason } from "./destructive";
import { buildComment, commentHosts } from "./hosts";

export interface Env {
  OAUTH_KV: KVNamespace;
  APPROVAL_STORE?: DurableObjectNamespace<import("./approval-store").ApprovalStore>; // absent only in local tests
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
  AGENT_INFISICAL_CLIENT_ID?: string; // optional: limited identity used only by issue_temp_token
  AGENT_INFISICAL_CLIENT_SECRET?: string;
  AGENT_TOKEN_MAX_SECONDS?: string; // optional cap on token lifetime, default 3600
  AGENT_REQUIRE_READ_ONLY?: string; // "true" = refuse to issue a token if the agent identity can change or delete secrets
}

const ok = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: String((e as Error).message ?? e) }] });

const secretName = z.string().min(1).regex(/^[A-Za-z0-9_.\-]+$/, "letters, digits, _ . - only");

const INSTRUCTIONS = [
  "Universal API: make authenticated calls to any HTTPS API or integration (GitHub, Jira, Notion, Stripe, Slack, AWS, ...) without ever seeing the credentials.",
  "Use api_request for the call itself: pass the secret NAME plus the URL, method and body; the server adds the token and returns the response with the token redacted.",
  "Use list_secrets to see which credentials exist (names, approved hosts; never values) and add_secret to store a new one. A secret can only be sent to the hosts in its own comment (a 'hosts: ...' line, shown as approved_hosts). When you store a token with add_secret you MUST pass hosts, the API's hostnames, e.g. [\"api.linear.app\"] or [\"*.atlassian.net\"] (no scheme or path); look up the service's API host if you are unsure. Hosts are fixed when the secret is created and cannot be changed through this server, so get them right the first time; only the owner can change them later. If api_request says a host is not allowed, tell the user.",
  "Secrets are organised in one folder per service (e.g. /notion/NOTION_TOKEN). api_request finds a secret by name in any folder; pass path only if the same name exists in several. When you add a token, put it in its own folder with path (e.g. /linear).",
  "Destructive actions always need the user's approval, enforced by the server: delete_secret, update_secret with a new value or name, and api_request for DELETE requests, GraphQL delete/archive-style mutations and bodies that set archived/trashed/deleted to true. The first call returns approval_required with a link; give the link to the user, wait until they say they approved it, then repeat the identical call with approval_id. An approval works once, for that exact action, for 15 minutes. Never try to work around it.",
  "For real CLIs that need credentials in their environment (aws, terraform), use issue_temp_token. It ALWAYS needs the user's approval, with a \"give token\" checkbox they must tick: the first call returns approval_required + a link; after they approve, repeat the identical call to receive a short-lived Infisical token and commands (infisical run). Treat that token as a secret: never print it, write it to a file, commit it or send it anywhere. access_guide explains setup (agent identity, Agent Proxy, AWS CLI) and needs no approval.",
  "Never ask the user to paste a token into the chat if it can be stored with add_secret, and never try to read secret values back.",
].join("\n");

const MAX_TOKEN_SECONDS_DEFAULT = 3600;
const duration = (sec: number) =>
  sec % 86400 === 0 ? `${sec / 86400} day${sec === 86400 ? "" : "s"}` : sec % 3600 === 0 ? `${sec / 3600} hour${sec === 3600 ? "" : "s"}` : sec >= 3600 ? `${(sec / 3600).toFixed(1)} hours` : `${Math.round(sec / 60)} minutes`;

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
    // Risky actions: the first call returns a link for the human; the repeat call carries approval_id.
    const gate = async (tool: string, args: Record<string, unknown>, spec: ApprovalSpec) => {
      const approvalId = typeof args.approval_id === "string" ? args.approval_id : undefined;
      if (approvalId) {
        const c = await checkApproval(env, approvalId, tool, args);
        return c.ok ? null : fail(new Error(c.reason));
      }
      const r = await requestApproval(env, tool, args, spec);
      return ok({
        approval_required: true, approval_id: r.id, approve_url: r.url, expires_in_minutes: r.expiresInMinutes,
        action: [spec.title, ...spec.rows.map(([k, v]) => `${k}: ${v}`)],
        next_step: `Tell the user to open approve_url, sign in with Google if asked, review the details${spec.ack ? ", tick the confirmation box" : ""} and press ${spec.ack ? "Give token" : "Approve"}. After they confirm, call ${tool} again with exactly the same arguments plus approval_id. Do not repeat the call before they confirm.`,
      });
    };
    const approvalField = { approval_id: z.string().optional().describe("From an earlier approval_required response, after the user approved it") };
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
          "file uploads: body_base64 (raw bytes) or multipart (form with files), up to 5 MB; aws_sigv4 (signs with secrets AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / optional AWS_SESSION_TOKEN; needs aws_service and aws_region). Do not send your own Authorization header. Destructive requests always need the user's approval: method DELETE, GraphQL mutations whose names contain delete/destroy/remove/archive/purge/trash, and bodies that set archived/trashed/deleted to true. The first call returns an approval link, and you repeat the call with approval_id once they approve.",
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
          ...approvalField,
          path: z.string().optional().describe("Folder of the secret, e.g. /notion. If omitted, the secret is found by name in any folder (an error if the name exists in several)."),
        }),
      },
      async (a) => {
        try {
          const why = destructiveReason(a.method, a.body);
          if (why) {
            const preview = typeof a.body === "string" ? a.body : a.body !== undefined ? JSON.stringify(a.body) : "";
            const held = await gate("api_request", a, {
              title: "Send a destructive request", risk: "danger",
              rows: [
                ["Request", `${a.method} ${a.url}`], ["Why flagged", why], ["Credential", `${a.secret ?? "AWS keys"} (${a.auth_type})`],
                ...(a.query ? [["Query", JSON.stringify(a.query)] as [string, string]] : []),
                ...(preview ? [["Body", `${preview.slice(0, 400)}${preview.length > 400 ? "..." : ""}`] as [string, string]] : []),
              ],
            });
            if (held) return held;
          }
          return ok(await callApi(env, a));
        } catch (e) { return fail(e); }
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
      { description: "Update a secret's value, comment (free-text note), or name. The value is not echoed back. The approved hosts (the 'hosts:' line in the comment) are kept as they are and cannot be changed here. Changing the value or the name overwrites the secret and needs the user's approval: the first call returns an approval link, and you repeat the call with approval_id once they approve. Changing only the comment needs no approval.", inputSchema: z.object({
        name: secretName, value: z.string().min(1).optional(), comment: z.string().optional(),
        new_name: secretName.optional(), ...loc, ...approvalField,
      }) },
      async (a) => {
        try {
          if (a.value === undefined && a.comment === undefined && a.new_name === undefined) throw new Error("Nothing to update");
          const b = base(a);
          if (a.value !== undefined || a.new_name !== undefined) {
            const held = await gate("update_secret", a, {
              title: a.value !== undefined ? "Overwrite a secret" : "Rename a secret", risk: "danger",
              rows: [
                ["Secret", a.name], ["Environment", b.environment], ["Folder", b.secretPath],
                ...(a.value !== undefined ? [["Change", "Replace the value. The old one cannot be recovered through this server."] as [string, string]] : []),
                ...(a.new_name !== undefined ? [["Rename to", a.new_name] as [string, string]] : []),
              ],
            });
            if (held) return held;
          }
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
      { description: "Permanently delete a secret. Always needs the user's approval: the first call returns an approval link for the user, and you repeat the call with approval_id once they approve.", inputSchema: z.object({ name: secretName, confirm: z.literal(true).describe("Must be true"), ...loc, ...approvalField }) },
      async (a) => {
        try {
          const b = base(a);
          const held = await gate("delete_secret", a, { title: "Delete a secret", risk: "danger", rows: [["Secret", a.name], ["Environment", b.environment], ["Folder", b.secretPath], ["Effect", "Permanent. It cannot be undone through this server."]] });
          if (held) return held;
          await infisical.deleteSecret(env, a.name, b);
          return ok({ deleted: a.name, environment: b.environment, path: b.secretPath });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "issue_temp_token",
      {
        description:
          "Get a short-lived Infisical access token so a CLI such as aws or terraform can read secrets (via `infisical run`). ALWAYS needs the user's approval with a 'give token' checkbox they must tick: the first call returns approval_required and a link; after they approve, repeat the identical call to receive the token and the commands to use it. " +
          "The token belongs to a limited 'agent' identity configured by the owner (not this server's own identity) and expires on its own. Treat it as a secret: never print it, store it or send it anywhere. If the agent identity is not set up yet, this returns the setup steps instead. " +
          "use: git_clone (clone private repos with the stored GITHUB_TOKEN), github_cli (gh), aws_cli, infisical_run (any other command), rest_api (call the Infisical API). The response has the exact `infisical run` command to run, with the secrets of `path` injected into that one command.",
        inputSchema: z.object({
          purpose: z.string().min(5).max(200).describe("Why you need the token, in a sentence. The user sees this."),
          use: z.enum(["aws_cli", "git_clone", "github_cli", "infisical_run", "rest_api"]).default("aws_cli"),
          environment: z.string().optional().describe("Environment you will read (default from config, e.g. dev)"),
          path: z.string().optional().describe("Folder holding the secrets the command needs, e.g. /github or /aws. Default: /github for git_clone and github_cli, /aws for aws_cli, otherwise /."),
          command: z.string().max(300).optional().describe("The command you plan to run (shown to the user and put into the returned commands). The approval is for the token, not for this command."),
          ...approvalField,
        }),
      },
      async (a) => {
        try {
          if (!agentConfigured(env)) {
            return ok({
              configured: false,
              message: "No agent identity is set up, so no token can be issued. The owner needs to create one first; the steps are below.",
              how_to_set_up: guide("agent_identity"),
            });
          }
          const environment = a.environment ?? env.DEFAULT_ENVIRONMENT;
          const path = a.path ?? ({ aws_cli: "/aws", git_clone: "/github", github_cli: "/github" } as Record<string, string>)[a.use] ?? "/";
          // A token handed to an assistant must be short-lived. Its lifetime is set on the agent identity in Infisical, so log in
          // once up front (the probe token is thrown away, never shown) to learn it, refuse if it is too long, and show it to the human.
          const maxSeconds = Number(env.AGENT_TOKEN_MAX_SECONDS) > 0 ? Number(env.AGENT_TOKEN_MAX_SECONDS) : MAX_TOKEN_SECONDS_DEFAULT;
          const tooLong = (sec: number) => ({
            issued: false,
            reason: `The agent identity issues tokens that live ${duration(sec)}, longer than the ${duration(maxSeconds)} allowed for a token handed to an assistant. No token was issued. The owner should set the identity's Access Token TTL and Max TTL in Infisical to ${duration(maxSeconds)} or less.`,
          });
          let lifetime = "Checked when you approve";
          let access: AccessSummary | undefined;
          if (typeof a.approval_id !== "string") {
            const probe = await mintAgentToken(env);
            if (!(probe.expiresIn > 0) || probe.expiresIn > maxSeconds) return ok(tooLong(probe.expiresIn));
            lifetime = `${duration(probe.expiresIn)}, then it stops working`;
            access = await probeAccess(env, probe.accessToken, env.INFISICAL_PROJECT_ID, environment); // measured now, shown to the approver
            if (access.canWrite && env.AGENT_REQUIRE_READ_ONLY === "true") {
              return ok({ issued: false, reason: "The agent identity can change or delete secrets, and this server is set to hand out read-only tokens only (AGENT_REQUIRE_READ_ONLY). No token was issued. The owner should give the identity a read-only role in Infisical." });
            }
          }
          const useLabel = { aws_cli: "Running the AWS CLI", git_clone: "Cloning repositories with git", github_cli: "Running the GitHub CLI", infisical_run: "Running a command with `infisical run`", rest_api: "Calling the Infisical API" }[a.use];
          const held = await gate("issue_temp_token", a, {
            title: "Give the assistant a temporary Infisical token",
            risk: "token",
            rows: [
              ["Purpose", a.purpose], ["Will be used for", useLabel], ...(a.command ? [["Command", a.command] as [string, string]] : []), ["Project", env.INFISICAL_PROJECT_ID], ["Environment", environment], ["Folder", path],
              ["Identity", `agent identity (client id ending ${String(env.AGENT_INFISICAL_CLIENT_ID).slice(-6)})`],
              ["Lifetime", lifetime],
              ...(access
                ? ([
                    ["Can read", access.total === 0 ? "Nothing in this environment" : `${access.total} secret${access.total === 1 ? "" : "s"} in ${access.folders.length} folder${access.folders.length === 1 ? "" : "s"} of ${environment}: ${access.folders.map((f) => `${f.path} (${f.count})`).join(", ")}`],
                    access.canWrite
                      ? ["Can change or delete", "YES (tested). With this token the assistant could overwrite or delete these secrets without asking you again.", "warn"]
                      : ["Can change or delete", access.canWrite === false ? "No (tested): read-only" : "Could not be tested"],
                    ["Note", `The folder above only selects which secrets \`infisical run\` puts into the command. The token itself can use everything listed under "Can read".`],
                  ] as ApprovalSpec["rows"])
                : []),
            ],
            ack: "Yes, give the assistant a temporary Infisical token. I understand it can read whatever the agent identity is allowed to read until it expires.",
          });
          if (held) return held;
          const t = await mintAgentToken(env);
          if (!(t.expiresIn > 0) || t.expiresIn > maxSeconds) return ok(tooLong(t.expiresIn)); // the identity changed since the preview; hand nothing out
          return ok({
            token: t.accessToken,
            expires_in_human: duration(t.expiresIn),
            token_type: t.tokenType,
            expires_in_seconds: t.expiresIn,
            expires_at: new Date(Date.now() + t.expiresIn * 1000).toISOString(),
            infisical_host: env.INFISICAL_HOST,
            project_id: env.INFISICAL_PROJECT_ID,
            environment,
            path,
            how_to_use: usage({ use: a.use as Use, host: env.INFISICAL_HOST, projectId: env.INFISICAL_PROJECT_ID, environment, path, command: a.command }),
            reminder: "Secret. Save it once to ~/.infisical-token (mode 600) and reuse it until it expires; do not print it, and do not request a new one per command. Delete the file when done.",
          });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "access_guide",
      {
        description: "Explains how to set up and use temporary access for CLIs: the limited agent identity, running the Infisical Agent Proxy server, and running the AWS CLI. Returns text only (no secrets); needs no approval.",
        inputSchema: z.object({ topic: z.enum(["overview", "agent_identity", "proxy", "aws", "all"]).default("overview") }),
      },
      async (a) => ({ content: [{ type: "text" as const, text: a.topic === "all" ? fullGuide() : guide(a.topic as Topic) }] }),
    );
  }
  return server;
}
