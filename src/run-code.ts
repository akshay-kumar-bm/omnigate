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
import { callApi, resolveSecret, withSecretCache, type ApiCallArgs, type ApiCallEnv } from "./api-call";
import { buildAwsCall, endpointFor, parseAwsSecret, xmlToJson } from "./aws";
import { checkApproval, fingerprint, requestApproval, store } from "./approvals";
import { approvalNeed, approvalSpec } from "./policy";
import { isVaultName, vaultDelete, vaultList } from "./vault";
import type { Env } from "./server";
import type { QuickJSWASMModule } from "quickjs-emscripten-core";
import { runInQuickJS } from "./quick-run";

export const MAX_CALLS = 300;
const JOURNAL_TTL = 60 * 60;
const MAX_CODE = 100_000;
const MAX_OUTPUT = 100_000;

export interface RunProps { runId: string; codeHash: string; secrets: string[]; purpose: string; resume?: { approvalId: string; seq: number }; retryFailed?: boolean }

// Per-request state of a QuickJS run (same request as the calls, so it can count them). On the free plan a request may
// make 50 outbound requests in total; the run stops at a checkpoint before that, and resume_run_id continues it in a
// new request with a fresh budget (finished calls are replayed from the journal, which costs no outbound request).
export interface RunState { liveLeft: number; checkpoint?: string; calls: { step: number; call: string; status: number | string; replayed?: boolean }[] }
const CHECKPOINT = "CHECKPOINT";
const LIMIT_ERROR = /too many subrequests|subrequest limit/i;
const describeCall = (a: ApiCallArgs) => {
  const t = a.headers?.["x-amz-target"]?.split(".").pop() ?? (typeof a.body === "string" ? a.body.match(/^Action=(\w+)/)?.[1] : undefined);
  try { const u = new URL(a.url); return `${(a.method ?? "GET").toUpperCase()} ${u.hostname}${u.pathname.slice(0, 60)}${t ? ` ${t}` : ""}`; } catch { return a.url.slice(0, 80); }
};

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
export async function brokerOp(env: Env, props: RunProps, seq: number, raw: unknown, state?: RunState): Promise<unknown> {
  if (!Number.isInteger(seq) || seq < 0 || seq >= MAX_CALLS) throw new Error(`A run may make at most ${MAX_CALLS} calls`);
  if (state?.checkpoint) throw new Error(`${CHECKPOINT}: ${state.checkpoint}`);
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
  const j0 = recorded ? (JSON.parse(recorded) as { fp: string; result: unknown }) : null;
  // resume_run_id retries calls that failed last time (e.g. after the owner renewed an expired key) instead of replaying them.
  const retry = !!j0 && props.retryFailed === true && j0.fp === fp && (j0.result as { ok?: boolean })?.ok === false;
  if (j0 && !retry) {
    const j = j0;
    if (j.fp !== fp) throw new Error(`Replay mismatch at call #${seq}: the code made a different call than in the first run (e.g. it used the time or a random value). Run it again without approval_id or resume_run_id.`);
    state?.calls.push({ step: seq, call: describeCall(a), status: (j.result as { status?: number })?.status ?? "ok", replayed: true });
    return j.result;
  }
  if (state && state.liveLeft <= 0) {
    state.checkpoint = "this request's budget of outbound calls is used up";
    throw new Error(`${CHECKPOINT}: ${state.checkpoint}`);
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
  if (state) state.liveLeft--;
  let result: any;
  try {
    result = shape(await callApi(env, { ...a, _vault_ok: vaultOk }), t.protocol);
  } catch (e) {
    const m = String((e as Error)?.message ?? e);
    if (state && LIMIT_ERROR.test(m)) { state.checkpoint = "Cloudflare's per-request limit on outbound requests was reached"; throw new Error(`${CHECKPOINT}: ${state.checkpoint}`); }
    state?.calls.push({ step: seq, call: describeCall(a), status: `error: ${m.slice(0, 120)}` });
    throw e;
  }
  await s.put(jKey, JSON.stringify({ fp, result }), JOURNAL_TTL);
  state?.calls.push({ step: seq, call: describeCall(a), status: result?.status ?? "ok" });
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
      while (active >= 6) await new Promise((r) => waiting.push(r));
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
  resume_run_id: z.string().uuid().optional().describe("From an earlier checkpoint (or failed run) of this same code: continue it. Calls that finished are replayed from a record, not repeated."),
};

export async function runCode(
  env: Env, ctx: ExecutionContext | undefined,
  a: { code: string; secrets: string[]; purpose: string; input?: unknown; timeout_seconds?: number; approval_id?: string; resume_run_id?: string },
  opts: { quickjs?: () => Promise<QuickJSWASMModule> } = {},
) {
  // Paid plan: a Dynamic Worker per run. Free plan (no LOADER binding): QuickJS inside this Worker (quick-run.ts).
  const loader = (env as any).LOADER as WorkerLoader | undefined;
  const entry = (ctx as any)?.exports?.Broker as ((o: { props: RunProps }) => Fetcher) | undefined;
  const secrets = [...new Set(a.secrets)].sort();
  const codeHash = await hex(`${a.code}\n${secrets.join(",")}\n${JSON.stringify(a.input ?? null)}`);
  const s = store(env);
  let runId: string;
  let resume: RunProps["resume"];
  let retryFailed = false;
  if (a.approval_id) {
    const raw = await s.get(`runpause:${a.approval_id}`);
    if (!raw) throw new Error("That approval_id does not belong to a paused run, or the run expired (1 hour). Run the code again without approval_id.");
    const p = JSON.parse(raw) as { runId: string; seq: number };
    const meta = await s.get(`run:${p.runId}:meta`);
    if (!meta || JSON.parse(meta).codeHash !== codeHash) throw new Error("That approval was given for a different program (code, secrets or input changed). Run the code again without approval_id.");
    await s.delete(pausedKey(p.runId));
    runId = p.runId;
    resume = { approvalId: a.approval_id, seq: p.seq };
  } else if (a.resume_run_id) {
    const meta = await s.get(`run:${a.resume_run_id}:meta`);
    if (!meta) throw new Error("That run_id is unknown or expired (runs are kept 1 hour). Run the code again without resume_run_id.");
    if (JSON.parse(meta).codeHash !== codeHash) throw new Error("resume_run_id belongs to a different program (code, secrets or input changed). Pass exactly the same code, secrets and input, or run again without resume_run_id.");
    if (await s.get(pausedKey(a.resume_run_id))) throw new Error("That run is waiting for an approval: resume it with approval_id once the user has approved.");
    runId = a.resume_run_id;
    retryFailed = true;
  } else {
    runId = crypto.randomUUID();
    await s.put(`run:${runId}:meta`, JSON.stringify({ codeHash }), JOURNAL_TTL);
  }
  const props: RunProps = { runId, codeHash, secrets, purpose: a.purpose, resume, retryFailed };
  const timeout = (a.timeout_seconds ?? 120) * 1000;
  let out: { ok: boolean; result?: unknown; error?: string; logs?: string[] } = { ok: false, error: "not run" };
  let engine = "quickjs";
  if (loader && entry) {
    const cpuMs = Number((env as any).RUN_CODE_CPU_MS) > 0 ? Number((env as any).RUN_CODE_CPU_MS) : undefined;
    out = await runInDynamicWorker(loader, entry, props, a, timeout, cpuMs);
    engine = "dynamic-worker";
    // The sandbox itself could not start (e.g. Dynamic Workers not available on this plan): run the same code in QuickJS.
    // Calls the first attempt finished are in the journal, so the fallback replays them instead of repeating them.
    if ((out as { infra?: boolean }).infra && !(await s.get(pausedKey(runId)))) {
      console.log(JSON.stringify({ run_code: { fallback: "quickjs", reason: String(out.error).slice(0, 200) } }));
      engine = "quickjs";
    }
  }
  if (engine === "quickjs") {
    const QuickJS = await (opts.quickjs ?? (async () => (await import("./quickjs-wasm")).loadQuickJS()))();
    const maxSteps = Number((env as any).RUN_CODE_MAX_STEPS) > 0 ? Number((env as any).RUN_CODE_MAX_STEPS) : 200; // ~25 interrupt checks per ms of interpreting: about 8 ms, under the free plan's 10 ms CPU
    const budget = Number((env as any).RUN_CODE_CALL_BUDGET) > 0 ? Number((env as any).RUN_CODE_CALL_BUDGET) : 35; // of 50 per request on the free plan; the rest covers Infisical and token refreshes
    const state: RunState = { liveLeft: budget, calls: [] };
    const runEnv = withSecretCache(env); // each secret is read once per request, not once per call
    out = await runInQuickJS(QuickJS, { code: a.code, input: a.input, timeoutMs: timeout, maxSteps, call: (seq, op) => brokerOp(runEnv, props, seq, op, state) });
    if (state.checkpoint && !(await s.get(pausedKey(runId)))) {
      const done = state.calls.filter((c) => typeof c.status === "number").length;
      return {
        ok: false, checkpoint: true, run_id: runId, engine,
        reason: `${state.checkpoint}; ${done} call${done === 1 ? "" : "s"} finished so far (kept).`,
        ...(out.logs?.length ? { logs: out.logs } : {}),
        next_step: `Call run_code again with exactly the same code, secrets, purpose and input plus resume_run_id: "${runId}". Finished calls are replayed from a record (not repeated, no cost) and the run continues with a fresh budget. Repeat until it returns ok. To need fewer resumes, batch work into fewer calls (e.g. one AI request for many items).`,
      };
    }
    if (!out.ok && state.calls.length) {
      return { ...(await finish(s, runId, out)), engine, run_id: runId, completed_calls: state.calls.slice(-50),
        hint: `Calls that finished are kept for 1 hour: after fixing the cause, call run_code again with the same code, secrets, purpose and input plus resume_run_id: "${runId}" to continue without repeating them.` };
    }
  }
  return { ...(await finish(s, runId, out)), engine };
}

async function runInDynamicWorker(
  loader: WorkerLoader, entry: (o: { props: RunProps }) => Fetcher, props: RunProps,
  a: { code: string; input?: unknown }, timeout: number, cpuMs?: number,
): Promise<{ ok: boolean; result?: unknown; error?: string; logs?: string[]; infra?: boolean }> {
  let worker: WorkerStub;
  try {
    worker = loader.load({
    compatibilityDate: "2026-09-01",
    mainModule: "main.js",
    modules: { "main.js": SHIM, "user.js": `export default async function ({ api, aws, vault, input, sleep, console }) {\n${a.code}\n}\n` },
    env: { BROKER: entry({ props }) },
    globalOutbound: null, // no network at all: only the BROKER stub
    ...(cpuMs ? { limits: { cpuMs } } : {}), // default: the plan's own limit
    });
  } catch (e) {
    return { ok: false, infra: true, error: `Dynamic Worker could not be created: ${String((e as Error)?.message ?? e).slice(0, 500)}` };
  }
  let res: Response;
  try {
    res = await worker.getEntrypoint().fetch("https://run/", { method: "POST", body: JSON.stringify({ input: a.input ?? null }), signal: AbortSignal.timeout(timeout) });
  } catch (e) {
    const m = String((e as Error)?.message ?? e);
    if (/timeout|abort/i.test(m)) return { ok: false, error: `The code did not finish within ${timeout / 1000} s` };
    if (/cpu|exceeded/i.test(m)) return { ok: false, error: `The code used too much CPU: ${m.slice(0, 300)}` };
    return { ok: false, infra: true, error: `The code could not run: ${m.slice(0, 2000)}` };
  }
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { ok: false, infra: true, error: text.slice(0, 2000) }; }
}

async function finish(s: ReturnType<typeof store>, runId: string, out: { ok: boolean; result?: unknown; error?: string; logs?: string[] }) {
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
  "So keep the code deterministic (do not put Date.now() or random values into requests). " +
  "LIMITS on this server (Cloudflare free plan): about 35 API calls per run_code call (the platform allows 50 outbound requests per request; replayed calls are free), 6 in flight at once, ~10 ms of CPU for your own code (orchestrate and filter; no heavy loops), timeout_seconds wall time, 100 KB result, 300 calls per run in total. " +
  "Plan for it: batch work into few calls (e.g. send many items in ONE AI request, use list/batch endpoints) rather than one call per item. If a run reaches the per-request budget it stops at a checkpoint and returns checkpoint: true with run_id; call run_code again with the same code, secrets, purpose and input plus resume_run_id to continue (finished calls are not repeated); repeat until ok. A failed run returns completed_calls and run_id, so after fixing the cause you can resume the same way (calls that got an error status are retried, successful ones are not). console.log progress if you want it back even on failure. " +
  "Modern syntax works, but there is no fetch, setTimeout or Node API inside: use the helpers.";
