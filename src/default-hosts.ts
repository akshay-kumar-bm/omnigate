// Built-in approved hosts for well-known services, keyed by the conventional secret name.
// A secret stored under one of these names can be sent to these hosts by api_request with no config.
// The API_HOSTS var in wrangler.jsonc adds names not listed here, or overrides an entry:
//   "STRIPE_API_KEY": []                      -> disable the built-in approval for that name
//   "MY_TOKEN": ["api.example.com"]           -> approve a service not listed here
//   "JIRA_AUTH": ["*.atlassian.net"]          -> "*." matches any subdomain depth, never the bare domain
// Anything not listed here or in API_HOSTS is refused.
const GITHUB = ["api.github.com", "uploads.github.com"];
const ATLASSIAN = ["*.atlassian.net", "api.atlassian.com"];
const AWS = ["*.amazonaws.com"];

export const DEFAULT_API_HOSTS: Record<string, string[]> = {
  NOTION_TOKEN: ["api.notion.com"],
  GITHUB_TOKEN: GITHUB,
  GH_TOKEN: GITHUB,
  LINEAR_API_TOKEN: ["api.linear.app"],
  LINEAR_API_KEY: ["api.linear.app"],
  JIRA_AUTH: ATLASSIAN,
  JIRA_API_TOKEN: ATLASSIAN,
  ATLASSIAN_API_TOKEN: ATLASSIAN,
  TAVILY_API_KEY: ["api.tavily.com"],
  FIRECRAWL_API_KEY: ["api.firecrawl.dev"],
  STRIPE_API_KEY: ["api.stripe.com", "files.stripe.com"],
  STRIPE_SECRET_KEY: ["api.stripe.com", "files.stripe.com"],
  SLACK_BOT_TOKEN: ["slack.com"],
  DISCORD_BOT_TOKEN: ["discord.com"],
  OPENAI_API_KEY: ["api.openai.com"],
  ANTHROPIC_API_KEY: ["api.anthropic.com"],
  SENDGRID_API_KEY: ["api.sendgrid.com"],
  CLOUDFLARE_API_TOKEN: ["api.cloudflare.com"],
  VERCEL_TOKEN: ["api.vercel.com"],
  HUBSPOT_ACCESS_TOKEN: ["api.hubapi.com"],
  AIRTABLE_API_KEY: ["api.airtable.com"],
  AIRTABLE_TOKEN: ["api.airtable.com"],
  AWS_ACCESS_KEY_ID: AWS,
  AWS_SECRET_ACCESS_KEY: AWS,
  AWS_SESSION_TOKEN: AWS,
};

// ---- Per-secret hosts stored in the secret's comment -------------------------------------------------
// A secret's comment may contain a line `hosts: api.example.com, *.example.com`. add_secret writes it from
// its `hosts` argument; update_secret keeps it unchanged and strips any `hosts:` line from new comment text,
// so hosts are fixed when the secret is created and the model cannot widen them later. The owner can edit
// the comment in the Infisical dashboard, or override per name with API_HOSTS.

// Domains where anyone can register a subdomain and read the requests it receives, so a wildcard on them
// would let an attacker-owned site collect tokens. Exact hosts on these are still allowed when named in full.
const SHARED_HOSTING = new Set([
  "workers.dev", "pages.dev", "github.io", "herokuapp.com", "vercel.app", "netlify.app", "ngrok.io", "ngrok.app",
  "ngrok-free.app", "trycloudflare.com", "onrender.com", "fly.dev", "railway.app", "web.app", "firebaseapp.com",
  "glitch.me", "repl.co", "replit.dev", "azurewebsites.net", "cloudfront.net", "amazonaws.com", "appspot.com", "run.app",
]);
const MULTI_PART_SUFFIX = new Set(["co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "com.mx", "com.sg"]);
const PRIVATE_TLD = new Set(["local", "internal", "localhost", "lan", "home", "corp", "test", "invalid", "example"]);
const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,}|xn--[a-z0-9-]+)$/;

export function validateHostPattern(raw: string): string {
  const p = raw.trim().toLowerCase();
  if (!HOST_RE.test(p)) throw new Error(`Invalid host "${raw}": use a bare hostname like api.example.com (no scheme, path, port or IP) or *.example.com`);
  if (PRIVATE_TLD.has(p.slice(p.lastIndexOf(".") + 1))) throw new Error(`Invalid host "${raw}": internal or reserved domain`);
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    if (base.split(".").length < 2 || MULTI_PART_SUFFIX.has(base) || SHARED_HOSTING.has(base)) {
      throw new Error(`Wildcard "${p}" is too broad (anyone can register a subdomain there); name the exact host instead`);
    }
  }
  return p;
}

const HOSTS_LINE = /^[ \t]*hosts[ \t]*:[ \t]*(.*)$/im;
const HOSTS_LINES = /^[ \t]*hosts[ \t]*:.*$/gim;

// Valid hosts from the comment's first `hosts:` line; invalid entries are ignored.
export function commentHosts(comment: string | undefined | null): string[] {
  const m = (comment ?? "").match(HOSTS_LINE);
  if (!m) return [];
  return m[1].split(/[,\s]+/).filter(Boolean).flatMap((x) => { try { return [validateHostPattern(x)]; } catch { return []; } });
}

export function stripHostsLines(comment: string): string {
  return comment.replace(HOSTS_LINES, "").replace(/\n{2,}/g, "\n").trim();
}

// Builds a comment from validated hosts plus free-text note (any `hosts:` line in the note is dropped).
export function buildComment(hosts: string[] | undefined, note: string | undefined): string {
  const valid = [...new Set((hosts ?? []).map(validateHostPattern))];
  return [valid.length ? `hosts: ${valid.join(", ")}` : "", stripHostsLines(note ?? "")].filter(Boolean).join("\n");
}
