// Best-effort detection of destructive api_request calls that are not an HTTP DELETE, so they get human approval too.
// It cannot be perfect: it only recognises (1) GraphQL documents whose field names say delete/destroy/remove/archive/
// purge/trash (field names are literal text in the document, so aliases cannot hide them) and (2) JSON bodies that set
// archived/trashed/deleted/in_trash to true (how Notion, GitHub and others archive), (3) REST URLs whose last path
// segment is a trash/delete action (Gmail POST .../messages/{id}/trash, .../batchDelete, Google ...:batchDelete) and
// (4) Gmail send, which cannot be undone. Anything else is treated as normal.

const GRAPHQL_DESTRUCTIVE = /(delete|destroy|remove|archive|purge|trash)/i;
const PATH_DESTRUCTIVE = /[/:](trash|delete|batchdelete|emptytrash)$/i;
const FLAG_KEYS = new Set(["archived", "in_trash", "trashed", "deleted", "is_archived", "is_deleted"]);

// Drop string literals and comments so text such as {title: "Delete the cache"} is not mistaken for an operation.
function stripGraphqlNoise(q: string): string {
  return q.replace(/"""[\s\S]*?"""/g, '""').replace(/"(?:[^"\\\n]|\\.)*"/g, '""').replace(/#[^\n]*/g, "");
}

function flagged(v: unknown, depth = 0): string | null {
  if (depth > 6 || v === null || typeof v !== "object") return null;
  for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
    if (FLAG_KEYS.has(k.toLowerCase()) && val === true) return k;
    const inner = flagged(val, depth + 1);
    if (inner) return inner;
  }
  return null;
}

function graphqlText(body: unknown): string | null {
  const obj = typeof body === "string" ? safeJson(body) : body;
  if (obj && typeof obj === "object" && !Array.isArray(obj) && typeof (obj as any).query === "string") return (obj as any).query;
  if (Array.isArray(obj)) return obj.map((o) => (o && typeof (o as any).query === "string" ? (o as any).query : "")).join("\n") || null;
  if (typeof body === "string" && /\b(mutation|query)\b[\s({]/.test(body)) return body; // raw application/graphql body
  return null;
}
const safeJson = (s: string): unknown => { try { return JSON.parse(s); } catch { return undefined; } };

// Why this call needs approval, or null if it does not look destructive.
export function destructiveReason(method: string, body: unknown, url?: string): string | null {
  if (method === "DELETE") return "HTTP DELETE request";
  if (method === "GET" || method === "HEAD") return null;
  if (url) {
    let path = "", host = "";
    try { const u = new URL(url); path = u.pathname; host = u.hostname.toLowerCase(); } catch { /* callApi rejects it */ }
    try { path = decodeURIComponent(path); } catch { /* keep the raw path; an encoded name is still checked below */ }
    path = path.replace(/\/+$/, "");
    const m = path.match(PATH_DESTRUCTIVE);
    if (m) return `URL ends in a ${m[1]} action`;
    if ((host === "gmail.googleapis.com" || path.includes("/gmail/")) && /\/send$/i.test(path)) return "sends an email (Gmail send)";
  }
  if (body === undefined || body === null) return null;
  const gql = graphqlText(body);
  if (gql !== null) {
    const doc = stripGraphqlNoise(gql);
    if (/\bmutation\b/i.test(doc)) {
      const m = doc.match(new RegExp(`\\b\\w*${GRAPHQL_DESTRUCTIVE.source}\\w*`, "i"));
      if (m) return `GraphQL mutation that looks destructive (${m[0]})`;
    }
  }
  const obj = typeof body === "string" ? safeJson(body) : body;
  const key = flagged(obj);
  return key ? `request body sets "${key}": true` : null;
}
