import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { infisical } from "./infisical";
import { approvedHosts, callApi, writeApprovalReason } from "./api-call";
import { describeRequest, draftHeaderRows, gmailDraftSendId, type Row } from "./preview";
import { checkApproval, requestApproval, type ApprovalSpec } from "./approvals";
import { agentConfigured, mintAgentToken, probeAccess, type AccessSummary } from "./temp-token";
import { AGENT_IDENTITY_SETUP, usage } from "./guide";
import { destructiveReason } from "./destructive";
import { commentPolicy, stripHostsLines } from "./hosts";
import { createUpload, SETUP as UPLOAD_SETUP, uploadsConfigured, type UploadEnv } from "./uploads";

export interface Env extends UploadEnv {
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
  AGENT_PROJECT_ID?: string; // project the agent identity reads (a separate, small project); defaults to INFISICAL_PROJECT_ID
  AGENT_INFISICAL_CLIENT_ID?: string; // optional: limited identity used only by issue_temp_token
  AGENT_INFISICAL_CLIENT_SECRET?: string;
  AGENT_TOKEN_MAX_SECONDS?: string; // optional cap on token lifetime, default 3600
  AGENT_REQUIRE_READ_ONLY?: string; // "true" = refuse to issue a token if the agent identity can change or delete secrets
}

const ok = (data: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(data) }] }); // compact: indentation costs tokens

// What the model needs about a secret: where it is and where it may be sent. Built field by field, so the value can never leak;
// timestamps, version, type, empty tags and the raw comment (its hosts line repeats `hosts`) are left out to save tokens.
const brief = (s: any) => {
  const note = stripHostsLines(String(s?.secretComment ?? ""));
  const policy = commentPolicy(s?.secretComment);
  return {
    name: s?.secretKey, path: s?.secretPath, hosts: approvedHosts(s?.secretComment),
    ...(policy.approveWrites ? { approval: "writes", ...(policy.allow.length ? { allow: policy.allow.map((r) => r.text) } : {}) } : {}),
    ...(note ? { note } : {}),
  };
};
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: String((e as Error).message ?? e) }] });

const secretName = z.string().min(1).regex(/^[A-Za-z0-9_.\-]+$/, "letters, digits, _ . - only");

const INSTRUCTIONS = [
  "Universal API: make authenticated calls to any HTTPS API or integration (GitHub, Jira, Notion, Stripe, Slack, Google, ...) without ever seeing the credentials.",
  "Use api_request for the call itself: pass the secret NAME plus the URL, method and body; the server adds the token and returns the response with the token redacted.",
  "Use list_secrets to see which credentials exist (name, folder, hosts; never values). A secret can only be sent to its listed hosts. The owner adds and edits secrets in Infisical; this server cannot. If a credential is missing or api_request says a host is not allowed, tell the user.",
  "Secrets are organised in one folder per service (e.g. /notion/NOTION_TOKEN). api_request finds a secret by name in any folder; pass path only if the same name exists in several.",
  "Destructive api_request calls always need the user's approval, enforced by the server: DELETE requests, GraphQL delete/archive-style mutations, bodies that set archived/trashed/deleted to true, trash/delete-style URLs and Gmail send, plus every write with a secret marked approval: \"writes\" (except its allow list). Prefer actions that need no approval (e.g. create a Gmail draft rather than send). The first call returns approval_required with a link; give the link to the user, wait until they say they approved it, then repeat the identical call with approval_id. An approval works once, for that exact action, for 15 minutes. Never try to work around it.",
  "For real CLIs that need credentials in their environment (aws, terraform), use issue_temp_token. It ALWAYS needs the user's approval, with a \"give token\" checkbox they must tick: the first call returns approval_required + a link; after they approve, repeat the identical call to receive a short-lived Infisical token and commands (infisical run). Treat that token as a secret: never print it, write it to a file, commit it or send it anywhere.",
  "For files too big to pass through the chat (or any file on disk), use get_upload_url: it needs no approval and returns a one-time upload URL (run the given curl with the file path) and a temporary download URL you can hand to other API calls. For the reverse (an API returns audio, an image or a file), call api_request with save_response=true to get a download URL instead of the bytes.",
  "Never ask the user to paste a token into the chat, and never try to read secret values back.",
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
      description: "Call any HTTPS API or integration (GitHub, Jira, Notion, Stripe, Slack, Google, ...) with credentials kept in a vault. You never see the tokens.",
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
    // `spec` may be a function, so details that cost a call (e.g. reading a Gmail draft) are only built for the first call.
    const gate = async (tool: string, args: Record<string, unknown>, specOrFn: ApprovalSpec | (() => Promise<ApprovalSpec>)) => {
      const approvalId = typeof args.approval_id === "string" ? args.approval_id : undefined;
      if (approvalId) {
        const c = await checkApproval(env, approvalId, tool, args);
        return c.ok ? null : fail(new Error(c.reason));
      }
      const spec = typeof specOrFn === "function" ? await specOrFn() : specOrFn;
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
          "Make an authenticated HTTPS request to ANY API or integration (GitHub, Jira, Notion, Stripe, Slack, Google, ...) using a credential stored in this server, without ever seeing it. Use this whenever you need to call a third-party API on the user's behalf. " +
          "Pass the secret NAME (see list_secrets); the server reads the token, adds the auth, calls the API and returns the response with the token redacted. " +
          "A secret can only be sent to the hosts in its own comment (see hosts in list_secrets), otherwise the call is refused and the error lists the approved hosts. Redirects are not followed. The server waits up to 3 minutes for the API to respond. " +
          "auth_type: bearer (default; Authorization: Bearer <secret>), header (header_name + optional header_prefix), basic (secret = 'user:pass', or username + secret as password), query (query_param), " +
          "file uploads: body_base64 (raw bytes) or multipart (form with files), up to 5 MB, or for bigger files first call get_upload_url, upload with curl, then pass the download URL as body_source or as a multipart file's source (up to 40 MB; the server reads it, nothing passes through the chat); " +
          "binary or large responses (generated audio, images, PDFs, exports): set save_response=true and the server stores a successful response in temporary storage and returns a download URL instead of the body (up to 40 MB, link valid 1 h, deleted after a day); " +
          "oauth2_refresh (for Google, Microsoft and other OAuth APIs: the secret holds a refresh token; the server gets a short-lived access token and sends it as Bearer). Do not send your own Authorization header. Destructive requests always need the user's approval: method DELETE, GraphQL mutations whose names contain delete/destroy/remove/archive/purge/trash, bodies that set archived/trashed/deleted to true, URLs ending in /trash, /delete, /batchDelete or /emptyTrash, and Gmail send. A secret whose list_secrets entry has approval: \"writes\" needs approval for EVERY write (POST/PUT/PATCH/DELETE) except the ones in its allow list; reads never do. The first call returns an approval link, and you repeat the call with approval_id once they approve.",
        inputSchema: z.object({
          url: z.string().url().describe("Full https:// URL"),
          method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
          headers: z.record(z.string(), z.string()).optional().describe("Extra request headers (e.g. Notion-Version, Accept)"),
          query: z.record(z.string(), z.string()).optional().describe("Query string params"),
          body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional().describe("Request body; objects/arrays are sent as JSON"),
          body_base64: z.string().optional().describe("Raw binary request body as base64 (max 5 MB decoded), e.g. PUT an object to S3. Set Content-Type in headers. Use instead of body."),
          body_source: z.string().optional().describe("Send a file stored with get_upload_url as the raw request body: pass its download URL (or key). The server reads it and forwards it, so the bytes never pass through the chat (max 40 MB). Use instead of body_base64."),
          multipart: z.object({
            fields: z.record(z.string(), z.string()).optional().describe("Plain form fields, sent before the files"),
            files: z.array(z.object({
              field: z.string().default("file").describe("Form field name, default 'file'"),
              filename: z.string().optional().describe("File name; required with data_base64, defaults to the stored name with source"),
              content_type: z.string().optional().describe("e.g. image/png; defaults to the stored file's type with source"),
              data_base64: z.string().optional().describe("File bytes as base64 (max 5 MB). Use this OR source."),
              source: z.string().optional().describe("Download URL (or key) of a file stored with get_upload_url; the server reads it itself (max 40 MB total). Use this OR data_base64."),
            })).min(1),
          }).optional().describe("multipart/form-data upload (max 5 MB total with data_base64, 40 MB with source), e.g. Notion /v1/file_uploads/{id}/send. Use instead of body."),
          auth_type: z.enum(["bearer", "header", "basic", "query", "oauth2_refresh"]).default("bearer"),
          secret: secretName.describe("Name of the secret holding the token / API key (for oauth2_refresh: the OAuth secret, e.g. GOOGLE_OAUTH)"),
          header_name: z.string().optional(),
          header_prefix: z.string().optional(),
          query_param: z.string().optional(),
          username: z.string().optional(),
          save_response: z.boolean().optional().describe("Store a successful (2xx) response body in temporary storage and return saved.download_url instead of the body. Use for binary output such as text-to-speech audio, images or file downloads. Error responses are returned as text as usual."),
          ...loc,
          ...approvalField,
          path: z.string().optional().describe("Folder of the secret, e.g. /notion. If omitted, the secret is found by name in any folder (an error if the name exists in several)."),
        }),
      },
      async (a) => {
        try {
          // Destructive patterns always need approval; with `approve: writes` in the secret's comment, so does every
          // other write that no `allow:` line covers.
          const destructive = destructiveReason(a.method, a.body, a.url);
          const why = destructive ?? (await writeApprovalReason(env, a));
          if (why) {
            const held = await gate("api_request", a, async () => {
              let draft: Row[] | undefined;
              const draftId = gmailDraftSendId(new URL(a.url), a.body);
              if (draftId) {
                // drafts/send only carries the draft id, so read the draft's recipients and subject to show them.
                const unreadable: Row = ["Draft", `could not read draft ${draftId}; check it in Gmail before approving`, "warn"];
                try {
                  const r: any = await callApi(env, {
                    secret: a.secret, auth_type: a.auth_type, environment: a.environment, path: a.path,
                    url: `https://gmail.googleapis.com/gmail/v1/users/me/drafts/${draftId}`, query: { format: "metadata" },
                  });
                  draft = r.ok ? draftHeaderRows(JSON.parse(r.body)) : [unreadable];
                } catch { draft = [unreadable]; }
              }
              const d = describeRequest(a, why, draft);
              return { title: destructive ? `${d.title} (destructive)` : d.title, risk: destructive ? "danger" : "write", rows: d.rows };
            });
            if (held) return held;
          }
          return ok(await callApi(env, a));
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "list_secrets",
      { description: "List the credentials available to api_request: name, folder (path), the hosts each may be sent to (empty = never sent, e.g. IDs), approval: \"writes\" if every write with it needs the user's approval (allow = the writes that don't) and any note. Values are never returned. Searches all folders by default.", inputSchema: z.object({ ...loc, recursive: z.boolean().default(true) }) },
      async (a) => {
        try {
          const b = base(a);
          const r = await infisical.listSecrets(env, { ...b, recursive: a.recursive });
          return ok({ environment: b.environment, secrets: (r.secrets ?? []).map(brief) });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "issue_temp_token",
      {
        description:
          "Get a short-lived Infisical access token so a CLI such as aws or terraform can read secrets (via `infisical run`). ALWAYS needs the user's approval with a 'give token' checkbox they must tick: the first call returns approval_required and a link; after they approve, repeat the identical call to receive the token and the commands to use it. " +
          "The token belongs to a limited 'agent' identity configured by the owner (not this server's own identity) and expires on its own. Treat it as a secret: never print it, store it or send it anywhere. If the agent identity is not set up yet, this returns the setup steps instead. " +
          "The response is the token plus short generic steps for using it with any CLI; it does not depend on what the CLI is.",
        inputSchema: z.object({
          purpose: z.string().min(5).max(200).describe("Why you need the token, in a sentence. The user sees this."),
          environment: z.string().optional().describe("Environment you will read (default from config, e.g. dev)"),
          ...approvalField,
        }),
      },
      async (a) => {
        try {
          if (!agentConfigured(env)) {
            return ok({
              configured: false,
              message: "No agent identity is set up, so no token can be issued. The owner needs to create one first; the steps are below.",
              how_to_set_up: AGENT_IDENTITY_SETUP,
            });
          }
          const environment = a.environment ?? env.DEFAULT_ENVIRONMENT;
          const projectId = env.AGENT_PROJECT_ID ?? env.INFISICAL_PROJECT_ID;
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
            access = await probeAccess(env, probe.accessToken, projectId, environment); // measured now, shown to the approver
            if (access.canWrite && env.AGENT_REQUIRE_READ_ONLY === "true") {
              return ok({ issued: false, reason: "The agent identity can change or delete secrets, and this server is set to hand out read-only tokens only (AGENT_REQUIRE_READ_ONLY). No token was issued. The owner should give the identity a read-only role in Infisical." });
            }
          }
          const held = await gate("issue_temp_token", a, {
            title: "Give the assistant a temporary Infisical token",
            risk: "token",
            rows: [
              ["Purpose", a.purpose], ["Project", projectId], ["Environment", environment],
              ["Identity", `agent identity (client id ending ${String(env.AGENT_INFISICAL_CLIENT_ID).slice(-6)})`],
              ["Lifetime", lifetime],
              ...(access
                ? ([
                    ["Can read", access.total === 0 ? "Nothing in this environment" : `${access.total} secret${access.total === 1 ? "" : "s"} in ${access.folders.length} folder${access.folders.length === 1 ? "" : "s"} of ${environment}: ${access.folders.map((f) => `${f.path} (${f.count})`).join(", ")}`],
                    access.canWrite
                      ? ["Can change or delete", "YES (tested). With this token the assistant could overwrite or delete these secrets without asking you again.", "warn"]
                      : ["Can change or delete", access.canWrite === false ? "No (tested): read-only" : "Could not be tested"],
                    ["Note", `The token can use everything listed under "Can read", whichever folder the assistant picks.`],
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
            project_id: projectId,
            environment,
            how_to_use: usage({ host: env.INFISICAL_HOST, projectId, environment }),
            reminder: "Secret. Set it once as the global INFISICAL_TOKEN (see how_to_use) and reuse it until it expires; do not print it, and do not request a new one per command.",
          });
        } catch (e) { return fail(e); }
      },
    );

    server.registerTool(
      "get_upload_url",
      {
        description:
          "Upload a file of any size (up to 5 GB) from the machine you run on to temporary storage, without the file passing through the chat, and get a download URL for other API calls (e.g. a file URL to hand to Notion, GitHub, an email API). " +
          "Returns a one-time upload URL (run the given curl PUT with the file path) and a download URL that expires on its own; uploaded files are deleted automatically after a day. No approval needed. Do not upload anything the user would not want copied to a temporary link.",
        inputSchema: z.object({
          filename: z.string().max(200).optional().describe("Name for the file, e.g. report.pdf. Used for the download name and to pick the file type."),
          content_type: z.string().max(100).optional().describe("File type, e.g. application/pdf. Optional: guessed from the file name."),
        }),
      },
      async (a) => {
        try {
          if (!uploadsConfigured(env)) return ok({ configured: false, message: "File upload storage is not set up yet, so no upload URL can be issued. The owner needs to set it up once.", how_to_set_up: UPLOAD_SETUP });
          return ok(await createUpload(env, a));
        } catch (e) { return fail(e); }
      },
    );
  }
  return server;
}
