// What the approval page shows for an api_request: the request in plain words, so the human can see what they approve.
// Gmail messages are decoded (the API takes them as base64url RFC 822), so a hidden Bcc or Reply-To is visible.
// Pure functions, no I/O: server.ts fetches an existing draft's headers itself and passes them in.

export type Row = [string, string] | [string, string, "warn"];

const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}...` : s);

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "").padEnd(Math.ceil(b64.replace(/\s+/g, "").length / 4) * 4, "="));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
const utf8 = (b: Uint8Array) => new TextDecoder().decode(b);

// RFC 2047 encoded words in headers, e.g. =?UTF-8?B?...?= or =?utf-8?Q?...?=
const decodeWords = (v: string) =>
  v.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, _cs, enc: string, txt: string) => {
    try {
      if (enc.toUpperCase() === "B") return utf8(b64ToBytes(txt));
      return utf8(Uint8Array.from(txt.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_x, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0)));
    } catch { return txt; }
  });

function splitMessage(text: string): { headers: Map<string, string>; body: string } {
  const norm = text.replace(/\r\n/g, "\n");
  const cut = norm.indexOf("\n\n");
  const head = cut < 0 ? norm : norm.slice(0, cut);
  const headers = new Map<string, string>();
  for (const line of head.replace(/\n[ \t]+/g, " ").split("\n")) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    headers.set(k, headers.has(k) ? `${headers.get(k)}, ${line.slice(i + 1).trim()}` : line.slice(i + 1).trim());
  }
  return { headers, body: cut < 0 ? "" : norm.slice(cut + 2) };
}

function decodePart(body: string, encoding: string | undefined): string {
  const e = (encoding ?? "").toLowerCase();
  try {
    if (e === "base64") return utf8(b64ToBytes(body));
    if (e === "quoted-printable") {
      return utf8(Uint8Array.from(body.replace(/=\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_x, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0)));
    }
  } catch { /* show as is */ }
  return body;
}

const htmlToText = (h: string) => h.replace(/<(style|script)[\s\S]*?<\/\1>/gi, "").replace(/<br\s*\/?>|<\/p>/gi, "\n").replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");

// First readable text of a (possibly multipart) message, plus attachment names.
function readBody(headers: Map<string, string>, body: string, depth = 0): { text: string; files: string[] } {
  const type = headers.get("content-type") ?? "text/plain";
  const boundary = type.match(/boundary="?([^";]+)"?/i)?.[1];
  if (/^multipart\//i.test(type) && boundary && depth < 5) {
    let text = "", html = "";
    const files: string[] = [];
    for (const raw of body.split(`--${boundary}`).slice(1)) {
      if (raw.startsWith("--")) break;
      const part = splitMessage(raw.replace(/^\n/, ""));
      const disp = part.headers.get("content-disposition") ?? "";
      const pt = part.headers.get("content-type") ?? "text/plain";
      const name = (disp.match(/filename\*?="?([^";]+)"?/i) ?? pt.match(/\bname="?([^";]+)"?/i))?.[1];
      if (/^attachment/i.test(disp) || (name && !/^multipart\//i.test(pt))) { files.push(name ? decodeWords(name) : "(unnamed)"); continue; }
      const inner = readBody(part.headers, part.body, depth + 1);
      files.push(...inner.files);
      if (!text && inner.text && !/html/i.test(pt)) text = inner.text;
      if (!html && inner.text && /html/i.test(pt)) html = inner.text;
    }
    return { text: text || html, files };
  }
  const decoded = decodePart(body, headers.get("content-transfer-encoding"));
  return { text: /html/i.test(type) ? htmlToText(decoded) : decoded, files: [] };
}

// Rows for an RFC 822 message (Gmail send / draft). Bcc and Reply-To are marked: they are how a message gets
// quietly copied or redirected to someone else.
export function emailRows(message: string): Row[] {
  const { headers, body } = splitMessage(message);
  const h = (k: string) => (headers.has(k) ? decodeWords(headers.get(k)!) : undefined);
  const { text, files } = readBody(headers, body);
  const rows: Row[] = [];
  for (const [k, label] of [["from", "From"], ["to", "To"], ["cc", "Cc"], ["bcc", "Bcc"], ["reply-to", "Reply-To"], ["subject", "Subject"]] as const) {
    const v = h(k);
    if (v === undefined) continue;
    rows.push(k === "bcc" || k === "reply-to" ? [label, v, "warn"] : [label, v]);
  }
  if (!headers.has("to") && !headers.has("cc") && !headers.has("bcc")) rows.push(["To", "(no recipients in the message)", "warn"]);
  const preview = text.replace(/\n{3,}/g, "\n\n").trim();
  rows.push(["Message", preview ? clip(preview, 800) : "(empty)"]);
  if (files.length) rows.push(["Attachments", files.join(", "), "warn"]);
  return rows;
}

// Gmail headers from a drafts.get?format=metadata response, for drafts/send (whose request only carries the draft id).
export function draftHeaderRows(meta: { message?: { snippet?: string; payload?: { headers?: { name: string; value: string }[] } } }): Row[] {
  const hs = meta.message?.payload?.headers ?? [];
  const msg = hs.map((x) => `${x.name}: ${x.value}`).join("\n") + `\n\n${meta.message?.snippet ?? ""}`;
  return emailRows(msg);
}

const isGmailSend = (u: URL) => (u.hostname === "gmail.googleapis.com" || u.pathname.includes("/gmail/")) && /\/send$/.test(u.pathname.replace(/\/+$/, ""));
export const gmailDraftSendId = (u: URL, body: unknown): string | null =>
  isGmailSend(u) && /\/drafts\/send$/.test(u.pathname.replace(/\/+$/, "")) && body && typeof body === "object" && typeof (body as any).id === "string" && /^[A-Za-z0-9_-]+$/.test((body as any).id) ? (body as any).id : null;

export interface RequestLike {
  method: string; url: string; secret: string; auth_type?: string;
  query?: Record<string, string>; body?: unknown; body_base64?: string; body_source?: string; multipart?: unknown; save_response?: boolean;
}

// Title and rows for the approval page. `draft` is the fetched draft for drafts/send (or an error to show).
// With omitBody, the body is left out of the rows (the approval page shows it in full in a collapsed section instead).
export function describeRequest(a: RequestLike, why: string, draft?: Row[], omitBody = false): { title: string; rows: Row[] } {
  const u = new URL(a.url);
  for (const [k, v] of Object.entries(a.query ?? {})) u.searchParams.set(k, v);
  let path = u.pathname;
  try { path = decodeURIComponent(path); } catch { /* keep encoded */ }
  const rows: Row[] = [
    ["Request", `${a.method} ${u.hostname}`],
    ["Path", path],
    ...(u.search ? [["Query", decodeURIComponent(u.search.slice(1)).replace(/&/g, "  &  ")] as Row] : []),
    ["Why asked", why],
    ["Credential", a.auth_type ? `${a.secret} (${a.auth_type})` : a.secret],
  ];
  if (isGmailSend(u)) {
    const raw = a.body && typeof a.body === "object" ? ((a.body as any).raw ?? (a.body as any).message?.raw) : undefined;
    let email: Row[] | undefined;
    try {
      if (typeof raw === "string") email = emailRows(utf8(b64ToBytes(raw)));
      else if (typeof a.body === "string" && /^[\w-]+:/m.test(a.body)) email = emailRows(a.body); // upload endpoint: raw RFC 822
    } catch { email = [["Message", "(could not decode the message; deny unless you are sure)", "warn"]]; }
    if (email) return { title: "Send an email", rows: [...rows, ...email] };
    if (draft) return { title: "Send a saved draft", rows: [...rows, ...draft] };
    if (a.body_base64 || a.body_source || a.multipart) return { title: "Send an email", rows: [...rows, ["Message", "(sent as an uploaded file, so it is not shown here; deny unless you are sure)", "warn"]] };
  }
  const body = typeof a.body === "string" ? a.body : a.body !== undefined ? JSON.stringify(a.body, null, 1) : "";
  if (body && !omitBody) rows.push(["Body", clip(body, 1500)]);
  if (a.body_base64) rows.push(["Body", `(binary, ${Math.round((a.body_base64.length * 3) / 4)} bytes)`]);
  if (a.body_source) rows.push(["Body", `(stored file ${a.body_source.split("?")[0].split("/").slice(-1)[0]})`]);
  if (a.multipart) rows.push(["Body", clip(JSON.stringify(a.multipart, (k, v) => (k === "data_base64" ? `(${String(v).length} chars of base64)` : v)), 800)]);
  return { title: a.method === "DELETE" ? "Delete something" : "Make a change", rows };
}

// ---- Plain-language summary, preview table and full body for the approval page ---------------------------------
// The page used to show the raw body as indented JSON cut off after ~1500 characters, so a 30-row sheet showed one row.
// Now: one summary line at the top (action, target, size), a preview table of the first rows when the body holds a list,
// and the full body (compact, up to 200 KB) in a collapsed <details> section. Pure; the page stays script-free.

export interface PreviewTable { caption: string; columns: string[]; rows: string[][] }
export interface RequestSummary { summary: string; table?: PreviewTable; body?: string; bodyBytes?: number }

const MAX_FULL_BODY = 200_000;
const TABLE_ROWS = 10;
const TABLE_COLS = 8;
const CELL = 40;

const cellText = (v: unknown): string => {
  if (v === null || v === undefined) return "";
  const s = typeof v === "string" ? v : typeof v === "object" ? JSON.stringify(v) : String(v);
  return clip(s.replace(/\s+/g, " "), CELL);
};
const kbText = (n: number) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`);
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
const colName = (i: number) => { let s = ""; for (let n = i + 1; n > 0; n = Math.floor((n - 1) / 26)) s = String.fromCharCode(65 + ((n - 1) % 26)) + s; return s; };

const parseMaybe = (b: unknown): unknown => {
  if (typeof b !== "string") return b;
  const t = b.trimStart();
  if (t.startsWith("{") || t.startsWith("[")) { try { return JSON.parse(b); } catch { /* not JSON */ } }
  return b;
};

// Sheets cell -> text: userEnteredValue / effectiveValue {stringValue|numberValue|boolValue|formulaValue}
const sheetCell = (c: any): string => {
  const v = c?.userEnteredValue ?? c?.effectiveValue ?? c;
  if (v && typeof v === "object") return cellText(v.stringValue ?? v.numberValue ?? v.boolValue ?? v.formulaValue ?? "");
  return cellText(v);
};

function gridTable(rows: unknown[][], caption: string): PreviewTable {
  const width = Math.min(TABLE_COLS, Math.max(0, ...rows.map((r) => r.length)));
  return { caption, columns: Array.from({ length: width }, (_, i) => colName(i)), rows: rows.slice(0, TABLE_ROWS).map((r) => Array.from({ length: width }, (_, i) => cellText(r[i]))) };
}

function objectTable(items: Record<string, unknown>[], caption: string): PreviewTable {
  const cols: string[] = [];
  for (const it of items.slice(0, TABLE_ROWS)) for (const k of Object.keys(it)) if (!cols.includes(k) && cols.length < TABLE_COLS) cols.push(k);
  return { caption, columns: cols, rows: items.slice(0, TABLE_ROWS).map((it) => cols.map((c) => cellText(it[c]))) };
}

// The biggest list in the body: an array of objects or an array of arrays (rows), searched a few levels deep.
function findList(v: unknown, path = "", depth = 0): { path: string; list: unknown[] } | null {
  if (depth > 4 || v === null || typeof v !== "object") return null;
  let best: { path: string; list: unknown[] } | null = null;
  if (Array.isArray(v)) {
    if (v.length >= 2 && v.every((x) => (x && typeof x === "object") || Array.isArray(x))) best = { path, list: v };
    return best;
  }
  for (const [k, x] of Object.entries(v)) {
    const f = findList(x, path ? `${path}.${k}` : k, depth + 1);
    if (f && (!best || f.list.length > best.list.length)) best = f;
  }
  return best;
}

function listTable(list: unknown[], what: string): PreviewTable {
  const caption = list.length > TABLE_ROWS ? `First ${TABLE_ROWS} of ${list.length} ${what}` : plural(list.length, what.replace(/s$/, ""));
  return list.every(Array.isArray) ? gridTable(list as unknown[][], caption) : objectTable(list.filter((x) => x && typeof x === "object" && !Array.isArray(x)) as Record<string, unknown>[], caption);
}

const notionTitle = (props: unknown): string | undefined => {
  if (!props || typeof props !== "object") return undefined;
  for (const p of Object.values(props as Record<string, any>)) {
    const t = p?.title;
    if (Array.isArray(t)) return t.map((x: any) => x?.plain_text ?? x?.text?.content ?? "").join("").slice(0, 80) || undefined;
  }
  return undefined;
};

export function summarizeRequest(a: { method: string; url: string; query?: Record<string, string>; body?: unknown; body_base64?: string; body_source?: string; multipart?: unknown }): RequestSummary {
  const u = new URL(a.url);
  for (const [k, v] of Object.entries(a.query ?? {})) u.searchParams.set(k, v);
  const method = a.method.toUpperCase();
  let path = u.pathname;
  try { path = decodeURIComponent(path); } catch { /* keep */ }
  const raw = a.body === undefined || a.body === null ? undefined : typeof a.body === "string" ? a.body : JSON.stringify(a.body);
  const bodyBytes = raw === undefined ? 0 : new TextEncoder().encode(raw).length;
  const body = raw === undefined ? undefined : raw.length > MAX_FULL_BODY ? `${raw.slice(0, MAX_FULL_BODY)}\n… (first 200 KB of ${kbText(bodyBytes)})` : raw;
  const v = parseMaybe(a.body);
  const size = bodyBytes ? `, ${kbText(bodyBytes)}` : "";
  const target = `${method} ${u.hostname}${path.length > 70 ? `${path.slice(0, 70)}…` : path}`;
  const out = (summary: string, table?: PreviewTable): RequestSummary => ({ summary, ...(table ? { table } : {}), ...(body !== undefined ? { body, bodyBytes } : {}) });

  if (a.body_base64 || a.body_source || a.multipart) return out(`${target} (uploads a file)`);
  const b = v as any;

  if (u.hostname === "sheets.googleapis.com") {
    const id = path.match(/\/spreadsheets\/([^/:]+)/)?.[1];
    const short = id ? `${id.slice(0, 10)}…` : "";
    if (method === "POST" && /^\/v4\/spreadsheets\/?$/.test(path) && b && typeof b === "object") {
      const sheets: any[] = Array.isArray(b.sheets) ? b.sheets : [];
      const rowData: any[] = sheets[0]?.data?.[0]?.rowData ?? [];
      const grid = rowData.map((r) => (Array.isArray(r?.values) ? r.values.map(sheetCell) : []));
      const cols = Math.max(0, ...grid.map((r) => r.length));
      const title = b.properties?.title ? `"${clip(String(b.properties.title), 80)}"` : "(untitled)";
      return out(`Create Google Sheet ${title}${grid.length ? ` with ${plural(grid.length, "row")} × ${plural(cols, "column")}` : ""}${sheets.length > 1 ? ` in ${sheets.length} tabs` : ""}`,
        grid.length ? gridTable(grid, grid.length > TABLE_ROWS ? `First ${TABLE_ROWS} of ${grid.length} rows` : plural(grid.length, "row")) : undefined);
    }
    const valuesOf = (x: any): unknown[][] | undefined => (Array.isArray(x?.values) && x.values.every(Array.isArray) ? x.values : undefined);
    const m = path.match(/\/values\/([^:]+)(?::(append|clear))?$/);
    if (m && valuesOf(b)) {
      const rows = valuesOf(b)!;
      const cols = Math.max(0, ...rows.map((r) => r.length));
      const verb = m[2] === "append" ? "Append" : "Write";
      return out(`${verb} ${plural(rows.length, "row")} × ${plural(cols, "column")} ${m[2] === "append" ? "to" : "into"} ${m[1]} in spreadsheet ${short}`, gridTable(rows, rows.length > TABLE_ROWS ? `First ${TABLE_ROWS} of ${rows.length} rows` : plural(rows.length, "row")));
    }
    if (/:batchUpdate$/.test(path) && Array.isArray(b?.requests)) {
      const kinds = [...new Set(b.requests.map((r: object) => Object.keys(r ?? {})[0]).filter(Boolean))].slice(0, 6);
      return out(`Update spreadsheet ${short}: ${plural(b.requests.length, "change")} (${kinds.join(", ")})`);
    }
    if (/values:batchUpdate$/.test(path) && Array.isArray(b?.data)) {
      const n = b.data.reduce((t: number, d: any) => t + (Array.isArray(d?.values) ? d.values.length : 0), 0);
      const first = b.data.find((d: any) => valuesOf(d));
      return out(`Write ${plural(n, "row")} into ${plural(b.data.length, "range")} of spreadsheet ${short}`, first ? gridTable(first.values, `${first.range ?? "first range"}`) : undefined);
    }
  }

  if (u.hostname === "api.notion.com" && b && typeof b === "object") {
    const title = notionTitle(b.properties);
    const kids = Array.isArray(b.children) ? `, ${plural(b.children.length, "block")}` : "";
    if (method === "POST" && /^\/v1\/pages\/?$/.test(path)) {
      const where = b.parent?.database_id ? ` in database ${b.parent.database_id}` : b.parent?.page_id ? ` under page ${b.parent.page_id}` : "";
      return out(`Create Notion page${title ? ` "${title}"` : ""}${where}${kids}`);
    }
    const pm = path.match(/^\/v1\/pages\/([^/]+)$/);
    if (method === "PATCH" && pm) {
      const props = b.properties ? Object.keys(b.properties).slice(0, 6).join(", ") : "";
      return out(`Update Notion page ${pm[1]}${props ? ` (properties: ${props})` : ""}`);
    }
    const bm = path.match(/^\/v1\/blocks\/([^/]+)\/children$/);
    if (bm && Array.isArray(b.children)) return out(`Add ${plural(b.children.length, "block")} to Notion page/block ${bm[1]}`);
  }

  const list = v && typeof v === "object" ? findList(v) : null;
  if (list) {
    const where = list.path ? ` in "${list.path}"` : "";
    return out(`${target} (${plural(list.list.length, "item")}${where}${size})`, listTable(list.list, list.list.every(Array.isArray) ? "rows" : "items"));
  }
  return out(`${target}${bodyBytes ? ` (${kbText(bodyBytes)} body)` : ""}`);
}
