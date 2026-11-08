// run_code: the assistant's JavaScript runs in a fresh Cloudflare Dynamic Worker (Worker Loader) with no network
// (globalOutbound: null), no secrets and no bindings except BROKER, an RPC stub whose every method runs back in this
// Worker (broker-rpc.ts -> brokerOp below). So code can do sequential, parallel, nested and conditional work with
// ordinary JavaScript, but every request still goes through the same checks as api_request: host binding, approvals
// (policy.ts), redaction and the vault. The code never holds a credential.
//
// Approvals inside code: a call that needs a human pauses the run and returns approval_required. Every finished call
// is recorded in a journal (keyed by its sequence number and a fingerprint of its arguments). The assistant repeats
// run_code with the same code + approval_id: the code runs again from the start, recorded calls return their recorded
// result instead of running again, and the approved call goes out. Nothing runs twice. If the code takes a different
// path on replay (different arguments at the same step), the run stops with an error.
//
// No Cloudflare-only imports here (the entrypoint class is in broker-rpc.ts), so this file runs under Node for tests.
import { z } from "zod";
import { apiRequestSchema } from "./api-schema";
import { callApi, resolveSecret, type ApiCallArgs, type ApiCallEnv } from "./api-call";
import { buildAwsCall, endpointFor, parseAwsSecret, xmlToJson } from "./aws";
import { checkApproval, fingerprint, requestApproval, store } from "./approvals";
import { approvalNeed, approvalSpec } from "./policy";
import { isVaultName, vaultDelete, vaultList } from "./vault";
import type { Env } from "./server";

export const MAX_CALLS = 300;
const JOURNAL_TTL = 60 * 60;
const MAX_CODE = 100_000;
const MAX_OUTPUT = 100_000;

export interface RunProps { runId: string; codeHash: string; secrets: string[]; purpose: string; resume?: { approvalId: string; seq: number } }

const awsCallOp = z.object({
  kind: z.literal("aws"), secret: z.string().min(1), service: z.string().regex(/^[a-z0-9-]{2,40}$/), region: z.string().optional(),
  action: z.string().regex(/^[A-Za-z0-9]{2,80}$/), params: z.record(z.string(), z.unknown()).optional(),
  target: z.string().optional(), json_version: z.string().optional(), version: z.string().optional(),
  capture: z.record(z.string(), z.string()).optional(), capture_minutes: z.number().int().min(1).max(1440).optional(),
});
const awsRequestOp = z.object({
  kind: z.literal("aws_request"), secret: z.string().min(1), service: z.string().regex(/^[a-z0-9-]{2,40}$/), region: z.string().optional(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"), path: z.string().default("/"), host: z.string().optional(),
  query: z.record(z.string(), z.string()).optional(), headers: z.record(z.string(), z.string()).optional(),
  body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional(), body_base64: z.string().optional(),
  body_source: z.string().optional(), save_response: z.boolean().optional(),
  capture: z.record(z.string(), z.string()).optional(), capture_minutes: z.number().int().min(1).max(1440).optional(),
});
const opSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("api"), args: apiRequestSchema }),
  awsCallOp, awsRequestOp,
  z.object({ kind: z.literal("vault_list") }),
  z.object({ kind: z.literal("vault_delete"), name: z.string().regex(/^(vault:)?[A-Za-z0-9_-]{1,64}$/) }),
]);
export type Op = z.input<typeof opSchema>;

const hex = async (s: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");

async function defaultRegion(env: ApiCallEnv, secret: string): Promise<string | undefined> {
  try { return parseAwsSecret((await resolveSecret(env, secret, {})).value)?.region; } catch { return undefined; }
}

// Turn a sandbox op into api_request arguments (validated, so the sandbox cannot set server-only fields).
async function toArgs(env: ApiCallEnv, raw: unknown): Promise<{ a: ApiCallArgs; protocol?: "json" | "query" } | { vault: "list" | "delete"; name?: string }> {
  const op = opSchema.parse(raw);
  if (op.kind === "vault_list") return { vault: "list" };
  if (op.kind === "vault_delete") return { vault: "delete", name: op.name.replace(/^vault:/, "") };
  if (op.kind === "api") return { a: op.args as ApiCallArgs };
  const region = op.region ?? (await defaultRegion(env, op.secret)) ?? "us-east-1";
  if (op.kind === "aws") {
    const c = buildAwsCall({ ...op, region });
    return {
      protocol: c.protocol,
      a: { url: c.url, method: c.method, headers: c.headers as Record<string, string>, body: c.body, secret: op.secret, auth_type: "aws", aws_service: op.service, aws_region: region, capture: op.capture, capture_minutes: op.capture_minutes },
    };
  }
  const path = op.path.startsWith("/") ? op.path : `/${op.path}`;
  const host = op.host ?? endpointFor(op.service, region, path);
  return {
    a: {
      url: `https://${host}${path}`, method: op.method, query: op.query, headers: op.headers, body: op.body, body_base64: op.body_base64,
      body_source: op.body_source, save_response: op.save_response, secret: op.secret, auth_type: "aws", aws_service: op.service, aws_region: region,
      capture: op.capture, capture_minutes: op.capture_minutes,
    },
  };
}

// Parse a response body for code: JSON as an object, AWS query-protocol XML as an object, anything else as text.
function shape(r: any, protocol?: "json" | "query") {
  if (!r || typeof r.body !== "string") return r;
  const t = r.body.trimStart();
  let body: unknown = r.body;
  if (protocol === "query" || (t.startsWith("<") && /xml/.test(r.headers?.["content-type"] ?? ""))) body = xmlToJson(r.body);
  else if (t.startsWith("{") || t.startsWith("[")) { try { body = JSON.parse(r.body); } catch { /* keep text */ } }
  return { ...r, body };
}

const pausedKey = (runId: string) => `run:${runId}:paused`;

// One call from the sandbox. Runs in this Worker (via broker-rpc.ts), never in the sandbox.
export async function brokerOp(env: Env, props: RunProps, seq: number, raw: unknown): Promise<unknown> {
  if (!Number.isInteger(seq) || seq < 0 || seq >= MAX_CALLS) throw new Error(`A run may make at most ${MAX_CALLS} calls`);
  const s = store(env);
  if (await s.get(pausedKey(props.runId))) throw new Error("APPROVAL_REQUIRED: this run is paused for an approval; no more calls run until it is resumed");
  const t = await toArgs(env, raw);
  if ("vault" in t) return t.vault === "list" ? vaultList(env) : { deleted: await vaultDelete(env, t.name!) };
  const a = t.a;
  if (!a.secret || (!props.secrets.includes(a.secret) && !isVaultName(a.secret))) {
    throw new Error(`Secret ${a.secret} is not in this run's secrets list (${props.secrets.join(", ")}); add it to run_code's secrets`);
  }
  const fp = await fingerprint("run_code.call", a as unknown as Record<string, unknown>);
  const jKey = `run:${props.runId}:c:${seq}`;
  const recorded = await s.get(jKey);
  if (recorded) {
    const j = JSON.parse(recorded) as { fp: string; result: unknown };
    if (j.fp !== fp) throw new Error(`Replay mismatch at call #${seq}: the code made a different call than in the first run (e.g. it used the time or a random value). Run it again without approval_id.`);
    return j.result;
  }
  let vaultOk = false;
  const need = await approvalNeed(env, a);
  if (need) {
    const approvalArgs = { code_hash: props.codeHash, seq, call: a };
    if (props.resume && props.resume.seq === seq) {
      const c = await checkApproval(env, props.resume.approvalId, "run_code", approvalArgs);
      if (!c.ok) {
        // Not approved yet: pause again on the same approval so the caller gets the link back.
        const rp = await s.get(`runpause:${props.resume.approvalId}`);
        if (rp && /Not approved yet/.test(c.reason)) await s.put(pausedKey(props.runId), JSON.stringify(JSON.parse(rp).pause), JOURNAL_TTL);
        throw new Error(`APPROVAL_REQUIRED: ${c.reason}`);
      }
      vaultOk = true;
    } else {
      const spec = approvalSpec(a, need, [["Asked by", `run_code (${props.purpose})`], ["Step", `call #${seq + 1} of the program`]]);
      const r = await requestApproval(env, "run_code", approvalArgs, spec);
      const pause = { approval_id: r.id, approve_url: r.url, expires_in_minutes: r.expiresInMinutes, seq, action: [spec.title, ...spec.rows.map(([k, v]) => `${k}: ${v}`)] };
      await s.put(pausedKey(props.runId), JSON.stringify(pause), JOURNAL_TTL);
      await s.put(`runpause:${r.id}`, JSON.stringify({ runId: props.runId, seq, pause }), JOURNAL_TTL);
      throw new Error(`APPROVAL_REQUIRED: ${r.url}`);
    }
  }
  const result = shape(await callApi(env, { ...a, _vault_ok: vaultOk }), t.protocol);
  await s.put(jKey, JSON.stringify({ fp, result }), JOURNAL_TTL);
  return result;
}

// The sandbox's main module. `user.js` holds the assistant's code as the body of an async function.
const SHIM = `
import user from "./user.js";
class ApprovalPause extends Error {}
export default {
  async fetch(request, env) {
    const { input } = await request.json();
    const logs = []; let logBytes = 0;
    const fmt = (v) => { if (typeof v === "string") return v; try { return JSON.stringify(v); } catch { return String(v); } };
    const log = (...a) => { const l = a.map(fmt).join(" "); if (logBytes < 20000) { logs.push(l.slice(0, 4000)); logBytes += l.length; } };
    let seq = 0, active = 0; const waiting = [];
    const call = async (op) => {
      const n = seq++; // numbered when called, so Promise.all keeps a stable order on replay
      while (active >= 20) await new Promise((r) => waiting.push(r));
      active++;
      try { return await env.BROKER.call(n, op); }
      catch (e) { const m = String((e && e.message) || e); if (m.startsWith("APPROVAL_REQUIRED")) throw new ApprovalPause(m); throw new Error(m); }
      finally { active--; const w = waiting.shift(); if (w) w(); }
    };
    const method = (m) => (secret, url, a, b) => call({ kind: "api", args: { ...(m === "GET" || m === "DELETE" || m === "HEAD" ? a : b), secret, url, method: m, ...(m === "GET" || m === "DELETE" || m === "HEAD" ? {} : a === undefined ? {} : { body: a }) } });
    const api = { request: (args) => call({ kind: "api", args }), get: method("GET"), head: method("HEAD"), delete: method("DELETE"), post: method("POST"), put: method("PUT"), patch: method("PATCH") };
    const aws = { call: (secret, spec) => call({ ...spec, kind: "aws", secret }), request: (secret, spec) => call({ ...spec, kind: "aws_request", secret }) };
    const vault = { list: () => call({ kind: "vault_list" }), delete: (name) => call({ kind: "vault_delete", name }) };
    const sleep = (ms) => new Promise((r) => setTimeout(r, Math.max(0, Math.min(Number(ms) || 0, 60000))));
    const out = (o) => { try { return new Response(JSON.stringify(o), { headers: { "content-type": "application/json" } }); } catch (e) { return new Response(JSON.stringify({ ok: false, error: "The result could not be turned into JSON: " + e, logs })); } };
    try {
      const result = await user({ api, aws, vault, input, sleep, console: { log, info: log, warn: log, error: log, debug: log } });
      return out({ ok: true, result: result === undefined ? null : result, logs });
    } catch (e) {
      return out({ ok: false, paused: e instanceof ApprovalPause, error: String((e && e.stack) || e).slice(0, 4000), logs });
    }
  },
};
`;

export const runCodeInput = {
  code: z.string().min(1).max(MAX_CODE).describe("JavaScript: the BODY of an async function (use await and return). In scope: api, aws, vault, input, sleep, console. See the tool description for the helpers."),
  secrets: z.array(z.string().regex(/^[A-Za-z0-9_.\-]+$/)).min(1).max(20).describe("Names of the secrets this code may use (vault handles are always allowed). The user sees them on any approval page."),
  purpose: z.string().min(3).max(200).describe("What the code does, in a sentence. Shown on approval pages."),
  input: z.unknown().optional().describe("Optional JSON value passed to the code as `input`"),
  timeout_seconds: z.number().int().min(5).max(600).default(120).describe("Wall-clock limit (default 120, max 600)"),
  approval_id: z.string().optional().describe("From an earlier approval_required response of this same code, after the user approved it"),
};

export async function runCode(env: Env, ctx: ExecutionContext | undefined, a: { code: string; secrets: string[]; purpose: string; input?: unknown; timeout_seconds?: number; approval_id?: string }) {
  const loader = (env as any).LOADER as WorkerLoader | undefined;
  const entry = (ctx as any)?.exports?.Broker as ((o: { props: RunProps }) => Fetcher) | undefined;
  if (!loader || !entry) {
    return { configured: false, message: "run_code needs the Worker Loader binding (LOADER in wrangler.jsonc) and the Broker entrypoint. It is not available on this deployment; use api_request instead." };
  }
  const secrets = [...new Set(a.secrets)].sort();
  const codeHash = await hex(`${a.code}\n${secrets.join(",")}\n${JSON.stringify(a.input ?? null)}`);
  const s = store(env);
  let runId: string;
  let resume: RunProps["resume"];
  if (a.approval_id) {
    const raw = await s.get(`runpause:${a.approval_id}`);
    if (!raw) throw new Error("That approval_id does not belong to a paused run, or the run expired (1 hour). Run the code again without approval_id.");
    const p = JSON.parse(raw) as { runId: string; seq: number };
    const meta = await s.get(`run:${p.runId}:meta`);
    if (!meta || JSON.parse(meta).codeHash !== codeHash) throw new Error("That approval was given for a different program (code, secrets or input changed). Run the code again without approval_id.");
    await s.delete(pausedKey(p.runId));
    runId = p.runId;
    resume = { approvalId: a.approval_id, seq: p.seq };
  } else {
    runId = crypto.randomUUID();
    await s.put(`run:${runId}:meta`, JSON.stringify({ codeHash }), JOURNAL_TTL);
  }
  const props: RunProps = { runId, codeHash, secrets, purpose: a.purpose, resume };
  const worker = loader.load({
    compatibilityDate: "2026-09-01",
    mainModule: "main.js",
    modules: { "main.js": SHIM, "user.js": `export default async function ({ api, aws, vault, input, sleep, console }) {\n${a.code}\n}\n` },
    env: { BROKER: entry({ props }) },
    globalOutbound: null, // no network at all: only the BROKER stub
    limits: { cpuMs: 30_000 },
  });
  const timeout = (a.timeout_seconds ?? 120) * 1000;
  let res: Response;
  try {
    res = await worker.getEntrypoint().fetch("https://run/", { method: "POST", body: JSON.stringify({ input: a.input ?? null }), signal: AbortSignal.timeout(timeout) });
  } catch (e) {
    const m = String((e as Error)?.message ?? e);
    return { ok: false, error: /timeout|abort/i.test(m) ? `The code did not finish within ${timeout / 1000} s` : `The code could not run: ${m.slice(0, 2000)}` };
  }
  const out = (await res.json().catch(async () => ({ ok: false, error: (await res.text()).slice(0, 2000) }))) as { ok: boolean; result?: unknown; error?: string; logs?: string[] };
  const paused = await s.get(pausedKey(runId));
  if (paused) {
    const p = JSON.parse(paused);
    return {
      approval_required: true, approval_id: p.approval_id, approve_url: p.approve_url, expires_in_minutes: p.expires_in_minutes, action: p.action,
      logs: out.logs,
      next_step: "Tell the user to open approve_url, sign in with Google if asked, review the step and press Approve. After they confirm, call run_code again with exactly the same code, secrets, purpose and input plus approval_id. Steps that already ran are not repeated.",
    };
  }
  const text = JSON.stringify(out.result ?? null);
  return {
    ok: out.ok,
    ...(out.ok ? { result: text.length > MAX_OUTPUT ? `${text.slice(0, MAX_OUTPUT)}... (truncated; return less data)` : out.result } : { error: out.error }),
    ...(out.logs?.length ? { logs: out.logs } : {}),
  };
}

export const RUN_CODE_DESCRIPTION =
  "Run JavaScript on the server to do multi-step work with the stored credentials: sequential, parallel (Promise.all), nested, loops, conditions, retries. " +
  "Your code is the BODY of an async function: use await, and `return` the result (only the return value and console.log output come back, so filter big data in code). It runs in an isolated sandbox with no network except these helpers, and it never sees a credential: " +
  "api.get(secret, url, opts?), api.post(secret, url, body, opts?), api.put/patch(...same), api.delete(secret, url, opts?), api.request({...same arguments as api_request}) -> {status, ok, body (parsed JSON when possible), headers, vault?}; " +
  "aws.call(secret, {service, region?, action, params?}) for JSON/query AWS APIs, e.g. aws.call('AWS_ADMIN', {service: 'dynamodb', action: 'GetItem', params: {TableName: 't', Key: {id: {S: '1'}}}}), aws.call(s, {service: 'ec2', action: 'DescribeInstances'}), aws.call(s, {service: 'ssm', action: 'SendCommand', params: {...}}) (XML responses are parsed to objects); " +
  "aws.request(secret, {service, region?, method, path, query?, headers?, body?}) for REST AWS APIs such as s3 (path-style: path '/bucket/key') and lambda; " +
  "vault.list(), vault.delete(name); sleep(ms); input (your input value). Any opts may include capture: {name: '$.json.path'} to keep a value (e.g. a new API key) server-side as vault:<name>, usable later as secret or {{vault:name}}. " +
  "List every secret the code uses in `secrets`. The same checks as api_request apply to every call (hosts, redaction, approvals). If a call needs the user's approval, the run stops and returns approval_required with a link; after they approve, call run_code again with the same code, secrets, purpose and input plus approval_id: finished steps are replayed from a record, not repeated. " +
  "So keep the code deterministic (do not put Date.now() or random values into requests). Limits: 300 calls, 20 in flight, 30 s CPU, timeout_seconds wall time, 100 KB result.";
