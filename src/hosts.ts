// Approved hosts live in each secret's own comment, as a line `hosts: api.example.com, *.example.com`.
// Only the owner writes it, in the Infisical dashboard; this server has no tool that creates or edits secrets,
// so the model cannot widen them. There is no other source of approvals:
// a secret without a valid `hosts:` line is never sent anywhere.

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

