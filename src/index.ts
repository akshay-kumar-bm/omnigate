import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { GoogleHandler } from "./google-handler";
import { handleGateway } from "./gateway";
import { createServer, type Env } from "./server";

export type { Env } from "./server";
export { ApprovalStore } from "./approval-store";
export { Broker } from "./broker-rpc"; // RPC entrypoint for run_code sandboxes (ctx.exports.Broker)

let provider: OAuthProvider<Env> | undefined;
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Gateway requests (/gw/... and aws CLI calls signed with a gateway key id) carry their own gateway token,
    // not an MCP OAuth token, so they are handled before the OAuth provider.
    const gw = await handleGateway(request, env);
    if (gw) return gw;
    // Built lazily because the RFC 9728 resource URL comes from config (PUBLIC_URL).
    provider ??= new OAuthProvider<Env>({
      apiRoute: "/mcp",
      apiHandler: { fetch: (req: Request, e: Env, c: ExecutionContext) => createMcpHandler(() => createServer(e, c))(req, e, c) } as any,
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
