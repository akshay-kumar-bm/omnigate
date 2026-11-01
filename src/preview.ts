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
  method: string; url: string; secret: string; auth_type: string;
  query?: Record<string, string>; body?: unknown; body_base64?: string; body_source?: string; multipart?: unknown; save_response?: boolean;
}

// Title and rows for the approval page. `draft` is the fetched draft for drafts/send (or an error to show).
export function describeRequest(a: RequestLike, why: string, draft?: Row[]): { title: string; rows: Row[] } {
  const u = new URL(a.url);
  for (const [k, v] of Object.entries(a.query ?? {})) u.searchParams.set(k, v);
  let path = u.pathname;
  try { path = decodeURIComponent(path); } catch { /* keep encoded */ }
  const rows: Row[] = [
    ["Request", `${a.method} ${u.hostname}`],
    ["Path", path],
    ...(u.search ? [["Query", decodeURIComponent(u.search.slice(1)).replace(/&/g, "  &  ")] as Row] : []),
    ["Why asked", why],
    ["Credential", `${a.secret} (${a.auth_type})`],
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
  if (body) rows.push(["Body", clip(body, 1500)]);
  if (a.body_base64) rows.push(["Body", `(binary, ${Math.round((a.body_base64.length * 3) / 4)} bytes)`]);
  if (a.body_source) rows.push(["Body", `(stored file ${a.body_source.split("?")[0].split("/").slice(-1)[0]})`]);
  if (a.multipart) rows.push(["Body", clip(JSON.stringify(a.multipart, (k, v) => (k === "data_base64" ? `(${String(v).length} chars of base64)` : v)), 800)]);
  return { title: a.method === "DELETE" ? "Delete something" : "Make a change", rows };
}
