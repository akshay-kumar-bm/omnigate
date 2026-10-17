// get_upload_url: lets the assistant move a file of any size out of its sandbox into an R2 bucket without the file
// passing through the model. The Worker presigns two URLs (it never sees the file): a PUT the assistant uses once with
// curl, and a GET that other API calls can use as a "file URL". No approval step by design; the damage is bounded by:
//  - the PUT URL lives a few minutes and is bound to one random key,
//  - it signs `If-None-Match: *`, so R2 accepts only the first write to that key (single use),
//  - the GET URL expires on its own, and a bucket lifecycle rule deletes the objects after a day.
import { AwsClient } from "aws4fetch";

export interface UploadEnv {
  R2_ACCOUNT_ID?: string;
  R2_BUCKET?: string;
  R2_ACCESS_KEY_ID?: string;
  R2_SECRET_ACCESS_KEY?: string;
  UPLOAD_PUT_SECONDS?: string; // default 300
  UPLOAD_GET_SECONDS?: string; // default 3600
}

export const UPLOAD_PREFIX = "tmp/";
const PUT_DEFAULT = 300;
const GET_DEFAULT = 3600;
const GET_MAX = 86_400;

// Notion and other APIs check the file type, and R2 serves back whatever Content-Type the upload sent. The Content-Type header is
// not signed (the signing library skips it), so this is a convenience for the curl command, not a security control.
const MIME: Record<string, string> = {
  pdf: "application/pdf", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
  txt: "text/plain", md: "text/markdown", csv: "text/csv", json: "application/json", html: "text/html", zip: "application/zip",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation", mp3: "audio/mpeg", mp4: "video/mp4", mov: "video/quicktime",
};
export function contentTypeFor(filename: string, given?: string): string {
  if (given && /^[A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+$/.test(given)) return given;
  return MIME[filename.split(".").pop()?.toLowerCase() ?? ""] ?? "application/octet-stream";
}

export const uploadsConfigured = (e: UploadEnv) => !!(e.R2_ACCOUNT_ID && e.R2_BUCKET && e.R2_ACCESS_KEY_ID && e.R2_SECRET_ACCESS_KEY);

export const SETUP = `One-time setup for get_upload_url (Cloudflare R2):
1. Create a PRIVATE bucket:  npx wrangler r2 bucket create <bucket>
2. Delete uploads automatically (R2 expires by whole days, so 1 day is the shortest):
   npx wrangler r2 bucket lifecycle add <bucket> --name expire-tmp --prefix ${UPLOAD_PREFIX} --expire-days 1
3. Create S3 credentials: Cloudflare dashboard > R2 > Manage R2 API Tokens > Create API token, permission "Object Read & Write", limited to that bucket. Copy the Access Key ID and Secret Access Key.
   (An "Admin Read & Write" token also lets this tool confirm that the delete rule exists; Object Read & Write is enough to work.)
4. Give them to the Worker (pipe the bare value in, no NAME= prefix):
   npx wrangler secret put R2_ACCESS_KEY_ID
   npx wrangler secret put R2_SECRET_ACCESS_KEY
   and set R2_ACCOUNT_ID and R2_BUCKET as vars in wrangler.jsonc.
5. The machine that uploads must be allowed to reach <account id>.r2.cloudflarestorage.com (Claude Code cloud: environment network allowlist).`;

const seconds = (v: string | undefined, dflt: number, max: number) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 1 ? Math.min(Math.floor(n), max) : dflt;
};

// "../../x y.png" -> "x_y.png": a single safe path segment.
export function safeName(name: string | undefined): string {
  const base = (name ?? "file").split(/[\\/]/).pop() ?? "file";
  const clean = base.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^\.+/, "").slice(0, 120);
  return clean || "file";
}

function client(e: UploadEnv) {
  return new AwsClient({ accessKeyId: e.R2_ACCESS_KEY_ID!, secretAccessKey: e.R2_SECRET_ACCESS_KEY!, service: "s3", region: "auto" });
}
const objectUrl = (e: UploadEnv, key: string) => `https://${e.R2_BUCKET}.${e.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${key.split("/").map(encodeURIComponent).join("/")}`;

async function presign(e: UploadEnv, method: "PUT" | "GET", key: string, expires: number, headers?: Record<string, string>) {
  const u = new URL(objectUrl(e, key));
  u.searchParams.set("X-Amz-Expires", String(expires));
  const signed = await client(e).sign(u.toString(), { method, headers, aws: { signQuery: true } });
  return signed.url;
}

// Is a delete rule for the upload prefix in place? Needs a token that may read bucket settings; "unknown" otherwise.
let lifecycleCache: { at: number; value: string } | null = null;
export async function autoDeleteStatus(e: UploadEnv): Promise<string> {
  if (lifecycleCache && Date.now() - lifecycleCache.at < 10 * 60_000) return lifecycleCache.value;
  let value = "unknown (this token cannot read the bucket's lifecycle rules; check the rule exists)";
  try {
    const r = await client(e).fetch(`https://${e.R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${e.R2_BUCKET}?lifecycle`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) {
      const xml = await r.text();
      const rule = [...xml.matchAll(/<Rule>([\s\S]*?)<\/Rule>/g)].map((m) => m[1]).find((x) => /<Status>Enabled<\/Status>/.test(x) && x.includes(`<Prefix>${UPLOAD_PREFIX}</Prefix>`) && /<Days>\d+<\/Days>/.test(x));
      const days = rule?.match(/<Days>(\d+)<\/Days>/)?.[1];
      value = days ? `yes: objects under ${UPLOAD_PREFIX} are deleted ${days} day${days === "1" ? "" : "s"} after upload` : `NO RULE FOUND for ${UPLOAD_PREFIX}: uploads are kept until deleted. Run the lifecycle command from the setup steps.`;
    }
  } catch { /* keep "unknown" */ }
  lifecycleCache = { at: Date.now(), value };
  return value;
}

export async function createUpload(e: UploadEnv, a: { filename?: string; content_type?: string }) {
  const putSeconds = seconds(e.UPLOAD_PUT_SECONDS, PUT_DEFAULT, 3600);
  const getSeconds = seconds(e.UPLOAD_GET_SECONDS, GET_DEFAULT, GET_MAX);
  const key = `${UPLOAD_PREFIX}${crypto.randomUUID()}/${safeName(a.filename)}`;
  const putHeaders = { "if-none-match": "*" };
  const contentType = contentTypeFor(safeName(a.filename), a.content_type);
  const [putUrl, getUrl, autoDelete] = await Promise.all([presign(e, "PUT", key, putSeconds, putHeaders), presign(e, "GET", key, getSeconds), autoDeleteStatus(e)]);
  return {
    upload: {
      method: "PUT",
      url: putUrl,
      required_headers: ["If-None-Match: *", `Content-Type: ${contentType}`],
      expires_in_seconds: putSeconds,
      single_use: "R2 accepts only the first write to this key.",
      curl: `curl --fail -sS -X PUT -H 'If-None-Match: *' -H 'Content-Type: ${contentType}' -T '<path to the file>' '${putUrl}'`,
    },
    download: { url: getUrl, expires_in_seconds: getSeconds, note: "Pass this as the file URL to other API calls. Anyone with the link can read the file until it expires." },
    content_type: contentType,
    key,
    auto_delete: autoDelete,
  };
}

// Read a file that get_upload_url stored, so api_request can send it to another API without the bytes passing through the chat.
// Only objects this feature created are readable: the reference must be a key (or the download URL) under tmp/<uuid>/<name> in our
// own bucket. Any other URL is refused, so this cannot be used to make the Worker fetch arbitrary addresses. The Worker signs its own
// request, so the link's expiry does not matter.
export const MAX_STORED_BYTES = 25 * 1024 * 1024; // the bytes are held in memory (and copied into a form), so keep this well under the Worker's 128 MB
const KEY_RE = /^tmp\/[0-9a-f-]{36}\/[A-Za-z0-9._-]{1,120}$/;

export function storedKey(e: UploadEnv, ref: string): string {
  let key = ref.trim();
  if (/^https?:\/\//i.test(key)) {
    const u = new URL(key);
    if (u.protocol !== "https:" || u.host !== `${e.R2_BUCKET}.${e.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`) throw new Error("source must be the download URL (or key) returned by get_upload_url");
    key = decodeURIComponent(u.pathname.slice(1));
  }
  if (!KEY_RE.test(key)) throw new Error("source must be the download URL (or key) returned by get_upload_url");
  return key;
}

export async function fetchStored(e: UploadEnv, ref: string): Promise<{ bytes: Uint8Array; contentType: string; name: string }> {
  if (!uploadsConfigured(e)) throw new Error("File storage is not set up on this server, so source cannot be used");
  const key = storedKey(e, ref);
  const r = await client(e).fetch(objectUrl(e, key), { signal: AbortSignal.timeout(25_000) });
  if (r.status === 404) throw new Error("The stored file was not found. It may not have been uploaded yet (run the curl first), or it was deleted after a day");
  if (!r.ok) throw new Error(`Could not read the stored file (status ${r.status})`);
  const declared = Number(r.headers.get("content-length") ?? 0);
  if (declared > MAX_STORED_BYTES) throw new Error(`Stored file is too large to forward (max ${MAX_STORED_BYTES / 1024 / 1024} MB)`);
  const bytes = new Uint8Array(await r.arrayBuffer());
  if (bytes.length > MAX_STORED_BYTES) throw new Error(`Stored file is too large to forward (max ${MAX_STORED_BYTES / 1024 / 1024} MB)`);
  return { bytes, contentType: r.headers.get("content-type") ?? "application/octet-stream", name: key.split("/").pop()! };
}
