import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { GoogleHandler } from "./google-handler";
import { createServer, type Env } from "./server";

export type { Env } from "./server";
export { ApprovalStore } from "./approval-store";

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
