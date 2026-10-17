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

export async function createUpload(e: UploadEnv, a: { filename?: string }) {
  const putSeconds = seconds(e.UPLOAD_PUT_SECONDS, PUT_DEFAULT, 3600);
  const getSeconds = seconds(e.UPLOAD_GET_SECONDS, GET_DEFAULT, GET_MAX);
  const key = `${UPLOAD_PREFIX}${crypto.randomUUID()}/${safeName(a.filename)}`;
  const putHeaders = { "if-none-match": "*" };
  const [putUrl, getUrl, autoDelete] = await Promise.all([presign(e, "PUT", key, putSeconds, putHeaders), presign(e, "GET", key, getSeconds), autoDeleteStatus(e)]);
  return {
    upload: {
      method: "PUT",
      url: putUrl,
      required_header: "If-None-Match: *",
      expires_in_seconds: putSeconds,
      single_use: "R2 accepts only the first write to this key.",
      curl: `curl --fail -sS -X PUT -H 'If-None-Match: *' -T '<path to the file>' '${putUrl}'`,
    },
    download: { url: getUrl, expires_in_seconds: getSeconds, note: "Pass this as the file URL to other API calls. Anyone with the link can read the file until it expires." },
    key,
    auto_delete: autoDelete,
  };
}
