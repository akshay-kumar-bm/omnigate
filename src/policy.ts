// Which calls need a human, and what the approval page shows. One place for every way in (api_request, run_code,
// the gateway), so the rules cannot drift apart:
//  - destructive patterns (destructive.ts) and, for AWS, destructive or always-ask actions (aws.ts);
//  - vault values sent to a host they are not bound to;
//  - `approve: all` on the secret (every call), or `approve: writes` (every write no `allow:` line covers).
// For AWS, "write" is decided by the action (most AWS reads are POSTs), not by the HTTP method.
import { classifyAws, isAwsHost, type AwsInfo } from "./aws";
import { resolveSecret, vaultHostProblems, type ApiCallArgs, type ApiCallEnv } from "./api-call";
import { destructiveReason } from "./destructive";
import { awsActionAllowed, commentPolicy, writeAllowed } from "./hosts";
import { describeRequest, summarizeRequest, type Row } from "./preview";
import type { ApprovalSpec } from "./approvals";

export interface Need { why: string; destructive: boolean; aws?: AwsInfo }

const bodyText = (a: ApiCallArgs) => (typeof a.body === "string" ? a.body : a.body !== undefined && a.body !== null ? JSON.stringify(a.body) : "");

export function awsInfo(a: ApiCallArgs, headers?: Headers): AwsInfo | undefined {
  let url: URL;
  try { url = new URL(a.url); } catch { return undefined; }
  for (const [k, v] of Object.entries(a.query ?? {})) url.searchParams.set(k, v);
  if (!isAwsHost(url.hostname) && a.auth_type !== "aws") return undefined;
  return classifyAws({ service: a.aws_service, region: a.aws_region, method: (a.method ?? "GET").toUpperCase(), url, headers: headers ?? new Headers(a.headers ?? {}), bodyText: bodyText(a) });
}

export async function approvalNeed(env: ApiCallEnv, a: ApiCallArgs, headers?: Headers): Promise<Need | null> {
  const method = (a.method ?? "GET").toUpperCase();
  const aws = awsInfo(a, headers);
  if (aws) {
    if (aws.kind === "destructive") return { why: aws.reason, destructive: true, aws };
  } else {
    const d = destructiveReason(method, a.body, a.url);
    if (d) return { why: d, destructive: true };
  }
  const stray = await vaultHostProblems(env, a);
  if (stray.length) return { why: `sends ${stray.join(", ")} to a host it was not created for`, destructive: true, aws };
  if (!a.secret) return null;
  const policy = commentPolicy((await resolveSecret(env, a.secret, a)).comment);
  if (policy.approveAll) return { why: `every call with ${a.secret} needs approval (approve: all)`, destructive: false, aws };
  const isWrite = aws ? aws.kind === "write" : method !== "GET" && method !== "HEAD";
  if (!isWrite || !policy.approveWrites) return null;
  if (aws ? awsActionAllowed(policy, aws.service, aws.action) : writeAllowed(policy, method, new URL(a.url))) return null;
  const what = aws ? `${aws.service}:${aws.action}` : `${method} ${new URL(a.url).hostname}${new URL(a.url).pathname}`;
  return { why: `every write with ${a.secret} needs approval (approve: writes), and no allow line matches ${what}`, destructive: false, aws };
}

// The approval page for a call. `extra` rows go first (e.g. which run_code program or gateway session asked).
export function approvalSpec(a: ApiCallArgs, need: Need, extra: Row[] = [], draft?: Row[]): ApprovalSpec {
  const req = { ...a, method: (a.method ?? "GET").toUpperCase(), secret: a.secret ?? "" };
  const d = describeRequest(req, need.why, draft, true);
  const sm = summarizeRequest(req);
  const awsWhere = need.aws ? `${need.aws.service}:${need.aws.action}${need.aws.region ? ` in ${need.aws.region}` : ""}` : "";
  const awsRows: Row[] = need.aws ? [["AWS action", awsWhere]] : [];
  const title = need.aws ? `AWS ${need.aws.service}:${need.aws.action}` : d.title;
  // Gmail send: the decoded message is in the rows; say who it goes to in the headline.
  const to = d.rows.find((r) => r[0] === "To")?.[1], subject = d.rows.find((r) => r[0] === "Subject")?.[1];
  const headline = to ? `Send an email to ${to}${subject ? `: "${subject}"` : ""}` : need.aws ? `AWS ${awsWhere}${sm.table ? ` (${sm.table.caption.toLowerCase()})` : ""}` : sm.summary;
  return {
    title: need.destructive ? `${title} (destructive)` : title, risk: need.destructive ? "danger" : "write", rows: [...extra, ...awsRows, ...d.rows],
    headline, table: sm.table, body: sm.body, bodyBytes: sm.bodyBytes,
  };
}
