// AWS support for the broker: credentials (optionally via STS AssumeRole), endpoints, building calls for the JSON and
// query protocols, and classifying every AWS request by its action so approvals can be decided per action
// (POST is a read for most AWS APIs, so the HTTP method alone says nothing).
// No Cloudflare-only imports: runs under Node for tests.
import { AwsClient } from "aws4fetch";

// ---- Credentials -------------------------------------------------------------------------------------------
// The owner stores one Infisical secret per AWS identity, as JSON:
//   {"access_key_id": "...", "secret_access_key": "...", "region": "ap-south-1",            // required, region optional
//    "session_token": "...", "role_arn": "arn:aws:iam::123:role/agent", "external_id": "...", "session_seconds": 900}
// With role_arn the stored keys are only used to call sts:AssumeRole; requests are signed with the short-lived role
// credentials, so the role's IAM policy limits what any request can do.
export interface AwsSecret {
  accessKeyId: string; secretAccessKey: string; sessionToken?: string; region?: string;
  roleArn?: string; externalId?: string; sessionSeconds?: number;
}

const pick = (o: Record<string, unknown>, ...keys: string[]) => {
  for (const k of keys) if (typeof o[k] === "string" && o[k]) return o[k] as string;
  return undefined;
};

export function parseAwsSecret(value: string): AwsSecret | null {
  if (!value.trimStart().startsWith("{")) return null;
  let o: Record<string, unknown>;
  try { o = JSON.parse(value); } catch { return null; }
  if (!o || typeof o !== "object") return null;
  const accessKeyId = pick(o, "access_key_id", "aws_access_key_id", "AWS_ACCESS_KEY_ID", "AccessKeyId");
  const secretAccessKey = pick(o, "secret_access_key", "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY", "SecretAccessKey");
  if (!accessKeyId || !secretAccessKey) return null;
  const seconds = Number(o.session_seconds);
  return {
    accessKeyId, secretAccessKey,
    sessionToken: pick(o, "session_token", "aws_session_token", "AWS_SESSION_TOKEN", "SessionToken"),
    region: pick(o, "region", "aws_region", "AWS_REGION", "AWS_DEFAULT_REGION"),
    roleArn: pick(o, "role_arn", "RoleArn"), externalId: pick(o, "external_id", "ExternalId"),
    sessionSeconds: Number.isFinite(seconds) && seconds >= 900 && seconds <= 43200 ? seconds : undefined,
  };
}
export const isAwsSecret = (value: string) => parseAwsSecret(value) !== null;

const roleCache = new Map<string, { creds: AwsSecret; expires: number }>();

const xmlTag = (xml: string, tag: string) => xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1];

// Credentials to sign with. `allowHost` decides whether the STS host may receive the stored keys' signature
// (the owner's hosts line must include it). Every secret part is pushed to `used` for redaction.
export async function awsCredentials(name: string, s: AwsSecret, allowHost: (host: string) => boolean, used: string[]): Promise<AwsSecret> {
  used.push(s.secretAccessKey);
  if (s.sessionToken) used.push(s.sessionToken);
  if (!s.roleArn) return s;
  const region = s.region ?? "us-east-1";
  const host = `sts.${region}.amazonaws.com`;
  if (!allowHost(host)) throw new Error(`${name} has role_arn, so the server must call ${host}; add it to the secret's hosts line in Infisical`);
  const key = `${s.accessKeyId}|${s.roleArn}|${s.externalId ?? ""}`;
  const hit = roleCache.get(key);
  if (hit && hit.expires > Date.now()) { used.push(hit.creds.secretAccessKey, hit.creds.sessionToken!); return hit.creds; }
  const form = new URLSearchParams({
    Action: "AssumeRole", Version: "2011-06-15", RoleArn: s.roleArn,
    RoleSessionName: "universal-api-broker", DurationSeconds: String(s.sessionSeconds ?? 900),
  });
  if (s.externalId) form.set("ExternalId", s.externalId);
  const client = new AwsClient({ accessKeyId: s.accessKeyId, secretAccessKey: s.secretAccessKey, sessionToken: s.sessionToken, service: "sts", region, retries: 0 });
  const res = await client.fetch(`https://${host}/`, {
    method: "POST", redirect: "manual", signal: AbortSignal.timeout(30_000),
    headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString(),
  });
  const xml = await res.text();
  const creds: AwsSecret = {
    accessKeyId: xmlTag(xml, "AccessKeyId") ?? "", secretAccessKey: xmlTag(xml, "SecretAccessKey") ?? "",
    sessionToken: xmlTag(xml, "SessionToken") ?? "", region: s.region,
  };
  if (creds.secretAccessKey) used.push(creds.secretAccessKey);
  if (creds.sessionToken) used.push(creds.sessionToken);
  if (!res.ok || !creds.accessKeyId || !creds.secretAccessKey) {
    const why = xmlTag(xml, "Message") ?? `HTTP ${res.status}`;
    throw new Error(`AssumeRole for ${name} failed: ${why.slice(0, 300)}`);
  }
  const exp = Date.parse(xmlTag(xml, "Expiration") ?? "") || Date.now() + 900_000;
  if (roleCache.size > 50) roleCache.clear();
  roleCache.set(key, { creds, expires: exp - 120_000 });
  return creds;
}

// ---- Endpoints ---------------------------------------------------------------------------------------------
const GLOBAL: Record<string, string> = {
  iam: "iam.amazonaws.com", cloudfront: "cloudfront.amazonaws.com", route53: "route53.amazonaws.com",
  organizations: "organizations.us-east-1.amazonaws.com", ce: "ce.us-east-1.amazonaws.com",
};
const PREFIX: Record<string, string> = { ses: "email", ecr: "api.ecr" };

// Real endpoint for a signing service name + region. `path` disambiguates services that share a signing name.
export function endpointFor(service: string, region: string, path = "/"): string {
  if (!/^[a-z0-9-]{2,40}$/.test(service) || !/^[a-z]{2}(-[a-z]+)+-\d$/.test(region)) throw new Error(`Unknown AWS service or region: ${service} / ${region}`);
  if (GLOBAL[service]) return GLOBAL[service];
  if (service === "bedrock" && /^\/(model|async-invoke)\b/.test(path)) return `bedrock-runtime.${region}.amazonaws.com`;
  if (service === "execute-api") throw new Error("API Gateway invoke URLs are per API; call the API's own URL with api_request instead");
  return `${PREFIX[service] ?? service}.${region}.amazonaws.com`;
}

export const isAwsHost = (host: string) => /(^|\.)amazonaws\.com$/i.test(host);

// Signing service and region from an AWS hostname (best effort; callers may pass them explicitly).
export function serviceFromHost(host: string): { service?: string; region?: string } {
  const labels = host.toLowerCase().split(".");
  const i = labels.lastIndexOf("amazonaws");
  if (i < 1) return {};
  const parts = labels.slice(0, i);
  const region = parts.find((p) => /^[a-z]{2}(-[a-z]+)+-\d$/.test(p));
  if (parts.some((p) => p === "s3" || p.startsWith("s3-"))) return { service: "s3", region: region ?? "us-east-1" };
  for (const [svc, h] of Object.entries(GLOBAL)) if (h === host.toLowerCase()) return { service: svc, region: "us-east-1" };
  if (parts[0] === "email") return { service: "ses", region };
  if (parts[0] === "api" && parts[1] === "ecr") return { service: "ecr", region };
  if (parts[0] === "bedrock-runtime") return { service: "bedrock", region };
  return { service: parts[0], region };
}

// ---- Building calls ----------------------------------------------------------------------------------------
// JSON-protocol services: X-Amz-Target prefix and JSON version.
const JSON_TARGETS: Record<string, [string, string]> = {
  dynamodb: ["DynamoDB_20120810", "1.0"], ssm: ["AmazonSSM", "1.1"], logs: ["Logs_20140328", "1.1"],
  secretsmanager: ["secretsmanager", "1.1"], kms: ["TrentService", "1.1"], ecs: ["AmazonEC2ContainerServiceV20141113", "1.1"],
  ecr: ["AmazonEC2ContainerRegistry_V20150921", "1.1"], events: ["AWSEvents", "1.1"], states: ["AWSStepFunctions", "1.0"],
  sqs: ["AmazonSQS", "1.0"], "cognito-idp": ["AWSCognitoIdentityProviderService", "1.1"], kinesis: ["Kinesis_20131202", "1.1"],
  firehose: ["Firehose_20150804", "1.1"], codebuild: ["CodeBuild_20161006", "1.1"], codepipeline: ["CodePipeline_20150709", "1.1"],
  ce: ["AWSInsightsIndexService", "1.1"], glue: ["AWSGlue", "1.1"], athena: ["AmazonAthena", "1.1"], acm: ["CertificateManager", "1.1"],
  cloudtrail: ["CloudTrail_20131101", "1.1"], "ec2-instance-connect": ["AWSEC2InstanceConnectService", "1.1"],
};
// Query-protocol services (form body, XML response) and their API version.
const QUERY_VERSIONS: Record<string, string> = {
  ec2: "2016-11-15", iam: "2010-05-08", sts: "2011-06-15", sns: "2010-03-31", cloudformation: "2010-05-15", rds: "2014-10-31",
  autoscaling: "2011-01-01", elasticloadbalancing: "2015-12-01", monitoring: "2010-08-01", elasticache: "2015-02-02", ses: "2010-12-01",
};

export interface AwsCallSpec {
  service: string; region?: string; action: string; params?: Record<string, unknown>;
  target?: string; json_version?: string; version?: string; // for services not in the tables above
}

function flattenQuery(prefix: string, v: unknown, out: URLSearchParams) {
  if (Array.isArray(v)) v.forEach((x, i) => flattenQuery(`${prefix}.${i + 1}`, x, out));
  else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) flattenQuery(prefix ? `${prefix}.${k}` : k, x, out);
  else if (v !== undefined && v !== null) out.set(prefix, String(v));
}

// A JSON- or query-protocol call as plain request parts. REST services (S3, Lambda, ...) use aws.request instead.
export function buildAwsCall(c: AwsCallSpec, defaultRegion?: string) {
  const region = c.region ?? defaultRegion ?? "us-east-1";
  if (!/^[A-Za-z0-9]{2,80}$/.test(c.action)) throw new Error(`Invalid AWS action ${c.action}`);
  const url = `https://${endpointFor(c.service, region)}/`;
  const t = c.target ? [c.target, c.json_version ?? "1.1"] : JSON_TARGETS[c.service];
  if (t) {
    return { url, method: "POST", region, headers: { "x-amz-target": `${t[0]}.${c.action}`, "content-type": `application/x-amz-json-${t[1]}` }, body: JSON.stringify(c.params ?? {}), protocol: "json" as const };
  }
  const version = c.version ?? QUERY_VERSIONS[c.service];
  if (!version) throw new Error(`Unknown protocol for AWS service ${c.service}: pass target (JSON APIs) or version (query APIs), or use aws.request for REST APIs such as s3 and lambda`);
  const form = new URLSearchParams({ Action: c.action, Version: version });
  flattenQuery("", c.params ?? {}, form);
  return { url, method: "POST", region, headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" }, body: form.toString(), protocol: "query" as const };
}

// Minimal XML -> object for query-protocol responses (EC2, IAM, STS, ...). Repeated tags become arrays;
// <item>/<member> lists become arrays. Attributes are dropped. Good enough to read AWS responses in code.
export function xmlToJson(xml: string): unknown {
  const re = /<(\/?)([A-Za-z_][\w.:-]*)[^>]*?(\/?)>|([^<]+)/g;
  const lists = new WeakSet<unknown[]>(); // arrays made from repeated tags (vs. values that are arrays already)
  const unesc = (s: string) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
  const add = (parent: Record<string, unknown>, name: string, val: unknown) => {
    const cur = parent[name];
    if (cur === undefined) parent[name] = val;
    else if (Array.isArray(cur) && lists.has(cur)) cur.push(val);
    else { const arr = [cur, val]; lists.add(arr); parent[name] = arr; }
  };
  const root: Record<string, unknown> = {};
  const stack: { obj: Record<string, unknown>; text: string }[] = [{ obj: root, text: "" }];
  for (const m of xml.replace(/<\?[^>]*\?>/g, "").replace(/<!--[\s\S]*?-->/g, "").matchAll(re)) {
    if (m[4] !== undefined) { stack[stack.length - 1].text += m[4]; continue; }
    const [, close, name, self] = m;
    if (self) { add(stack[stack.length - 1].obj, name, ""); continue; }
    if (!close) { stack.push({ obj: {}, text: "" }); continue; }
    const top = stack.pop();
    if (!top || stack.length === 0) break;
    const keys = Object.keys(top.obj);
    let val: unknown = keys.length ? top.obj : unesc(top.text.trim());
    if (keys.length === 1 && (keys[0] === "item" || keys[0] === "member")) { const v = top.obj[keys[0]]; val = Array.isArray(v) && lists.has(v) ? v : [v]; }
    add(stack[stack.length - 1].obj, name, val);
  }
  return root;
}

// ---- Classifying requests ----------------------------------------------------------------------------------
export type AwsKind = "read" | "secret" | "write" | "destructive";
export interface AwsInfo { service: string; region?: string; action: string; kind: AwsKind; reason: string }

const READ = /^(Describe|Get|List|Head|Query|Scan|BatchGet|Select|Search|Lookup|Filter|Simulate|Estimate|Validate|Check|Preview|View|StartQuery|TestConnection)/;
const DESTRUCTIVE = /^(Delete|Terminate|Remove|Detach|Revoke|Deregister|Disable|Purge|Stop|Reboot|Reset|Abort|Disassociate|Untag|Cancel)/;
const ALWAYS_ASK = new Set([
  "ssm:SendCommand", "ssm:StartSession", "ssm:StartAutomationExecution", "ec2-instance-connect:SendSSHPublicKey", "ec2-instance-connect:SendSerialConsoleSSHPublicKey",
  "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:UpdateAssumeRolePolicy", "lambda:UpdateFunctionCode",
  "ec2:ModifyInstanceAttribute", "ec2:AuthorizeSecurityGroupIngress", "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl",
  "s3:PutPublicAccessBlock", "s3:DeletePublicAccessBlock", "s3:PutBucketLifecycleConfiguration", "kms:ScheduleKeyDeletion",
]);
// Reads that return credentials or secret values. They run without approval, but the secret fields of the response
// are moved into the session vault and the caller only sees a handle (see SECRET_FIELDS).
const SECRET_READS = new Set([
  "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
  "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:GetSessionToken", "sts:GetFederationToken", "kms:Decrypt", "kms:GenerateDataKey",
  "ecr:GetAuthorizationToken", "ec2:GetPasswordData",
]);
// Response fields that hold secret values, per action ("*" = any action of a SECRET_READS kind).
export const SECRET_FIELDS = ["SecretString", "SecretBinary", "SecretAccessKey", "SessionToken", "Plaintext", "authorizationToken", "PasswordData", "Password"];
// ssm parameters are only secret when SecureString; handled by the capture code (Type next to Value).
export const SSM_VALUE_ACTIONS = new Set(["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]);
// IAM, Organizations and KMS changes are always treated as destructive (they change who can do what).
const SENSITIVE_SERVICES = new Set(["iam", "organizations", "kms", "sso-admin", "identitystore"]);

function s3Action(method: string, url: URL, headers: Headers): string {
  const q = url.searchParams;
  const parts = url.pathname.split("/").filter(Boolean);
  // path-style: /bucket/key...; virtual-hosted: key only
  const virtual = !/^s3[.-]/.test(url.hostname);
  const hasKey = virtual ? parts.length >= 1 : parts.length >= 2;
  const sub = ["policy", "acl", "lifecycle", "cors", "tagging", "versioning", "website", "encryption", "publicAccessBlock", "replication", "notification", "ownershipControls", "logging"].find((s) => q.has(s));
  const sub2 = sub ? sub[0].toUpperCase() + sub.slice(1) : "";
  if (method === "GET" || method === "HEAD") {
    if (!hasKey) return sub ? `GetBucket${sub2}` : parts.length === 0 && !virtual ? "ListBuckets" : q.has("uploads") ? "ListMultipartUploads" : "ListObjectsV2";
    return method === "HEAD" ? "HeadObject" : q.has("uploadId") ? "ListParts" : sub ? `GetObject${sub2}` : "GetObject";
  }
  if (method === "DELETE") return hasKey ? (q.has("uploadId") ? "AbortMultipartUpload" : sub ? `DeleteObject${sub2}` : "DeleteObject") : sub ? `DeleteBucket${sub2}` : "DeleteBucket";
  if (method === "POST") {
    if (q.has("delete")) return "DeleteObjects";
    if (q.has("uploads")) return "CreateMultipartUpload";
    if (q.has("uploadId")) return "CompleteMultipartUpload";
    if (q.has("restore")) return "RestoreObject";
    if (q.has("select")) return "SelectObjectContent";
    return "PostObject";
  }
  if (method === "PUT") {
    if (!hasKey) return sub ? (sub === "acl" ? "PutBucketAcl" : sub === "policy" ? "PutBucketPolicy" : sub === "publicAccessBlock" ? "PutPublicAccessBlock" : sub === "lifecycle" ? "PutBucketLifecycleConfiguration" : `PutBucket${sub2}`) : "CreateBucket";
    if (q.has("partNumber")) return headers.has("x-amz-copy-source") ? "UploadPartCopy" : "UploadPart";
    if (sub) return sub === "acl" ? "PutObjectAcl" : `PutObject${sub2}`;
    return headers.has("x-amz-copy-source") ? "CopyObject" : "PutObject";
  }
  return `${method} ${url.pathname}`;
}

function actionOf(service: string, method: string, url: URL, headers: Headers, bodyText: string): string {
  const target = headers.get("x-amz-target");
  if (target) return target.slice(target.lastIndexOf(".") + 1);
  const q = url.searchParams.get("Action");
  if (q) return q;
  const ct = headers.get("content-type") ?? "";
  if (bodyText && (ct.includes("x-www-form-urlencoded") || /^Action=/.test(bodyText))) {
    const a = new URLSearchParams(bodyText).get("Action");
    if (a) return a;
  }
  if (service === "s3") return s3Action(method, url, headers);
  return `${method} ${url.pathname}`; // REST services without an action name: decided by method below
}

// What this AWS request does and whether it needs approval. Unknown actions count as writes (fail closed).
export function classifyAws(r: { service?: string; region?: string; method: string; url: URL; headers: Headers; bodyText: string }): AwsInfo {
  const guess = serviceFromHost(r.url.hostname);
  const service = r.service ?? guess.service ?? "unknown";
  const region = r.region ?? guess.region;
  const method = r.method.toUpperCase();
  const action = actionOf(service, method, r.url, r.headers, r.bodyText);
  const full = `${service}:${action}`;
  const info = (kind: AwsKind, reason: string): AwsInfo => ({ service, region, action, kind, reason });
  const rest = action.includes(" "); // REST call with no action name

  if (ALWAYS_ASK.has(full)) return info("destructive", `AWS ${full} always needs approval (it can run commands, grant access or expose data)`);
  if (SECRET_READS.has(full)) return info("secret", `AWS ${full} returns secret values; they are kept in the session vault`);
  if (rest) {
    if (method === "GET" || method === "HEAD") return info("read", `AWS ${service} ${method}`);
    if (method === "DELETE") return info("destructive", `AWS ${service} DELETE ${r.url.pathname}`);
    return info("write", `AWS ${service} ${method} ${r.url.pathname}`);
  }
  if (service === "dynamodb") {
    if (action === "ExecuteStatement" || action === "BatchExecuteStatement" || action === "ExecuteTransaction") {
      const sql = r.bodyText.match(/"Statement"\s*:\s*"([^"]*)/i)?.[1]?.trim().toUpperCase() ?? "";
      if (/^SELECT\b/.test(sql) && action === "ExecuteStatement") return info("read", "DynamoDB PartiQL SELECT");
      if (/\bDELETE\b/.test(r.bodyText.toUpperCase())) return info("destructive", "DynamoDB PartiQL statement that deletes items");
      return info("write", `DynamoDB ${action}`);
    }
    if ((action === "BatchWriteItem" && r.bodyText.includes("DeleteRequest")) || (action === "TransactWriteItems" && /"Delete"\s*:/.test(r.bodyText))) {
      return info("destructive", `DynamoDB ${action} that deletes items`);
    }
  }
  if (READ.test(action)) return info("read", `AWS ${full}`);
  if (DESTRUCTIVE.test(action)) return info("destructive", `AWS ${full} deletes, stops or removes something`);
  if (SENSITIVE_SERVICES.has(service)) return info("destructive", `AWS ${full} changes permissions or keys`);
  if (/Policy$/.test(action) && /^(Put|Attach|Set|Update|Create)/.test(action)) return info("destructive", `AWS ${full} changes an access policy`);
  return info("write", `AWS ${full}`);
}

// ---- aws-chunked bodies (S3 uploads from newer CLIs) ----------------------------------------------------------
// Body is "<hex-size>[;chunk-signature=...]\r\n<data>\r\n ... 0\r\n<trailer headers>\r\n\r\n". Returns the plain
// bytes and any trailing checksum headers so the request can be re-signed as an ordinary upload.
export function decodeAwsChunked(buf: Uint8Array): { body: Uint8Array; trailers: Record<string, string> } {
  const out: Uint8Array[] = [];
  let pos = 0, total = 0;
  const dec = new TextDecoder();
  const line = () => {
    for (let i = pos; i < buf.length - 1; i++) if (buf[i] === 13 && buf[i + 1] === 10) { const s = dec.decode(buf.subarray(pos, i)); pos = i + 2; return s; }
    throw new Error("Malformed aws-chunked body");
  };
  for (;;) {
    const size = parseInt(line().split(";")[0], 16);
    if (!Number.isFinite(size) || size < 0) throw new Error("Malformed aws-chunked body");
    if (size === 0) break;
    out.push(buf.subarray(pos, pos + size)); total += size; pos += size + 2;
  }
  const trailers: Record<string, string> = {};
  while (pos < buf.length) {
    const l = line();
    if (!l) break;
    const i = l.indexOf(":");
    if (i > 0) { const k = l.slice(0, i).trim().toLowerCase(); if (k.startsWith("x-amz-checksum-")) trailers[k] = l.slice(i + 1).trim(); }
  }
  const body = new Uint8Array(total);
  let at = 0;
  for (const c of out) { body.set(c, at); at += c.length; }
  return { body, trailers };
}
