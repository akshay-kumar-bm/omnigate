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
import { actionLines, checkApproval, fingerprint, requestApproval, store } from "./approvals";
import { approvalNeed, approvalSpec } from "./policy";
import { isVaultName, vaultDelete, vaultList } from "./vault";
import type { Env } from "./server";
import type { QuickJSWASMModule } from "quickjs-emscripten-core";
import { runInQuickJS } from "./quick-run";
import { pick, sampleOf, utf8Length } from "./shape";

export const MAX_CALLS = 300;
const JOURNAL_TTL = 60 * 60;
const MAX_CODE = 100_000;
const MAX_OUTPUT = 100_000;

export interface RunProps { runId: string; codeHash: string; secrets: string[]; purpose: string; resume?: { approvalId: string; seq: number }; retryFailed?: boolean }

// Per-request state of a QuickJS run (same request as the calls, so it can count them). On the free plan a request may
// make 50 outbound requests in total; the run stops at a checkpoint before that, and resume_run_id continues it in a
// new request with a fresh budget (finished calls are replayed from the journal, which costs no outbound request).
export interface RunState { liveLeft: number; checkpoint?: string; calls: { step: number; call: string; status: number | string; replayed?: boolean }[]; notes: string[] }
const CHECKPOINT = "CHECKPOINT";
const LIMIT_ERROR = /too many subrequests|subrequest limit/i;
const describeCall = (a: ApiCallArgs) => {
  const t = a.headers?.["x-amz-target"]?.split(".").pop() ?? (typeof a.body === "string" ? a.body.match(/^Action=(\w+)/)?.[1] : undefined);
  try { const u = new URL(a.url); return `${(a.method ?? "GET").toUpperCase()} ${u.hostname}${u.pathname.slice(0, 60)}${t ? ` ${t}` : ""}`; } catch { return a.url.slice(0, 80); }
};

// Per-call size options for code (not part of api_request): max_bytes caps the response, pick keeps only some fields.
const limitFields = {
  max_bytes: z.number().int().min(1000).max(500_000).optional(),
  pick: z.array(z.string().min(1).max(300)).min(1).max(30).optional(),
};
const awsCallOp = z.object({
  kind: z.literal("aws"), secret: z.string().min(1), service: z.string().regex(/^[a-z0-9-]{2,40}$/), region: z.string().optional(),
  action: z.string().regex(/^[A-Za-z0-9]{2,80}$/), params: z.record(z.string(), z.unknown()).optional(),
  target: z.string().optional(), json_version: z.string().optional(), version: z.string().optional(),
  capture: z.record(z.string(), z.string()).optional(), capture_minutes: z.number().int().min(1).max(1440).optional(),
  ...limitFields,
});
const awsRequestOp = z.object({
  kind: z.literal("aws_request"), secret: z.string().min(1), service: z.string().regex(/^[a-z0-9-]{2,40}$/), region: z.string().optional(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"), path: z.string().default("/"), host: z.string().optional(),
  query: z.record(z.string(), z.string()).optional(), headers: z.record(z.string(), z.string()).optional(),
  body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional(), body_base64: z.string().optional(),
  body_source: z.string().optional(), save_response: z.boolean().optional(),
  capture: z.record(z.string(), z.string()).optional(), capture_minutes: z.number().int().min(1).max(1440).optional(),
  ...limitFields,
});
const opSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("api"), args: apiRequestSchema.extend(limitFields) }),
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
interface Limits { max_bytes?: number; pick?: string[] }
async function toArgs(env: ApiCallEnv, raw: unknown): Promise<{ a: ApiCallArgs; protocol?: "json" | "query"; limits: Limits } | { vault: "list" | "delete"; name?: string }> {
  const op = opSchema.parse(raw);
  if (op.kind === "vault_list") return { vault: "list" };
  if (op.kind === "vault_delete") return { vault: "delete", name: op.name.replace(/^vault:/, "") };
  if (op.kind === "api") { const { max_bytes, pick, ...args } = op.args; return { a: args as ApiCallArgs, limits: { max_bytes, pick } }; }
  const limits: Limits = { max_bytes: op.max_bytes, pick: op.pick };
  const region = op.region ?? (await defaultRegion(env, op.secret)) ?? "us-east-1";
  if (op.kind === "aws") {
    const c = buildAwsCall({ ...op, region });
    return {
      protocol: c.protocol, limits,
      a: { url: c.url, method: c.method, headers: c.headers as Record<string, string>, body: c.body, secret: op.secret, auth_type: "aws", aws_service: op.service, aws_region: region, capture: op.capture, capture_minutes: op.capture_minutes },
    };
  }
  const path = op.path.startsWith("/") ? op.path : `/${op.path}`;
  const host = op.host ?? endpointFor(op.service, region, path);
  return {
    limits,
    a: {
      url: `https://${host}${path}`, method: op.method, query: op.query, headers: op.headers, body: op.body, body_base64: op.body_base64,
      body_source: op.body_source, save_response: op.save_response, secret: op.secret, auth_type: "aws", aws_service: op.service, aws_region: region,
      capture: op.capture, capture_minutes: op.capture_minutes,
    },
  };
}

// Parse a response body for code: JSON as an object, AWS query-protocol XML as an object, else undefined.
function parseBody(text: string, protocol: "json" | "query" | undefined, contentType: string): unknown {
  const t = text.trimStart();
  if (protocol === "query" || (t.startsWith("<") && /xml/.test(contentType))) return xmlToJson(text);
  if (t.startsWith("{") || t.startsWith("[")) { try { return JSON.parse(text); } catch { return undefined; } }
  return undefined;
}

const DEFAULT_MAX_BYTES = 60_000;
const TRUNCATION_HINT = "use pick or a smaller page_size; see sample for the shape";
const kb = (n: number) => Math.round(n / 102.4) / 10;
const sliceBytes = (s: string, n: number) => new TextDecoder().decode(new TextEncoder().encode(s).subarray(0, n));

// What code receives for a response. Small: parsed body. Too big: never a cut-off string that looks like JSON but does not
// parse; instead truncated: true, sizes, body: null + body_text (when it was JSON), a sample of the full response's shape,
// and a hint. `pick` keeps only the requested fields (measured after picking). The body was redacted by callApi.
function limitResult(r: any, url: string, protocol: "json" | "query" | undefined, lim: Limits, state?: RunState) {
  if (!r || typeof r.body !== "string") return r;
  const { body: text, truncated: _t, ...rest } = r;
  const ct = String(r.headers?.["content-type"] ?? "");
  const parsed = parseBody(text, protocol, ct);
  const total = utf8Length(text);
  let value: unknown = parsed ?? text;
  let outText = text, outBytes = total;
  if (lim.pick) {
    if (parsed === undefined) return { ...rest, truncated: false, body: null, body_text: sliceBytes(text, 2000), pick_error: "pick needs a JSON (or AWS XML) response; this one is not" };
    value = pick(parsed, lim.pick);
    outText = JSON.stringify(value);
    outBytes = utf8Length(outText);
  }
  const limit = lim.max_bytes ?? DEFAULT_MAX_BYTES;
  if (outBytes <= limit) return { ...rest, truncated: false, body: value, ...(lim.pick ? { picked: true, original_bytes: total } : {}) };
  const cut = sliceBytes(outText, limit);
  let where = url;
  try { const u = new URL(url); where = `${u.hostname}${u.pathname}`; } catch { /* keep as is */ }
  const note = `response from ${where} truncated at ${kb(limit)} KB (original ${kb(outBytes)} KB)`;
  state?.notes.push(note);
  const structured = parsed !== undefined;
  return {
    ...rest, truncated: true, original_bytes: outBytes, returned_bytes: utf8Length(cut),
    body: structured ? null : cut, ...(structured ? { body_text: cut, sample: sampleOf(value) } : {}),
    note, hint: TRUNCATION_HINT,
  };
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
  const fp = await fingerprint("run_code.call", { ...a, ...t.limits } as unknown as Record<string, unknown>);
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
      const pause = { approval_id: r.id, approve_url: r.url, expires_in_minutes: r.expiresInMinutes, seq, action: actionLines(spec) };
      await s.put(pausedKey(props.runId), JSON.stringify(pause), JOURNAL_TTL);
      await s.put(`runpause:${r.id}`, JSON.stringify({ runId: props.runId, seq, pause }), JOURNAL_TTL);
      throw new Error(`APPROVAL_REQUIRED: ${r.url}`);
    }
  }
  if (state) state.liveLeft--;
  let result: any;
  try {
    result = limitResult(await callApi(env, { ...a, _vault_ok: vaultOk, _full_body: true }), a.url, t.protocol, t.limits, state);
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
  code: z.string().min(1).max(MAX_CODE).optional().describe("JavaScript: the BODY of an async function (use await and return). In scope: api, aws, vault, input, sleep, console. Required for a new run. When resuming, do NOT send it: pass only resume_run_id (and approval_id)."),
  secrets: z.array(z.string().regex(/^[A-Za-z0-9_.\-]+$/)).min(1).max(20).optional().describe("Names of the secrets this code may use (vault handles are always allowed). The user sees them on any approval page. Required for a new run."),
  purpose: z.string().min(3).max(200).optional().describe("What the code does, in a sentence. Shown on approval pages. Required for a new run."),
  input: z.unknown().optional().describe("Optional JSON value passed to the code as `input`"),
  timeout_seconds: z.number().int().min(5).max(600).optional().describe("Wall-clock limit (default 120, max 600)"),
  resume_run_id: z.string().uuid().optional().describe("run_id from an earlier checkpoint, approval_required or failed run. To continue, send ONLY this (plus approval_id after the user approved); never resend code, secrets, purpose or input. Finished calls are replayed, not repeated."),
  approval_id: z.string().optional().describe("From an approval_required response, after the user approved it (with resume_run_id)"),
};

// What a run executes. Kept server-side with the run, so resuming needs only run_id (+ approval_id).
interface Program { code: string; secrets: string[]; purpose: string; input?: unknown; timeout_seconds?: number }
const programHash = (p: { code: string; secrets: string[]; input?: unknown }) => hex(`${p.code}\n${[...new Set(p.secrets)].sort().join(",")}\n${JSON.stringify(p.input ?? null)}`);
const resumeCall = (runId: string, approvalId?: string) => `run_code({resume_run_id: "${runId}"${approvalId ? `, approval_id: "${approvalId}"` : ""}})`;

export type RunArgs = { code?: string; secrets?: string[]; purpose?: string; input?: unknown; timeout_seconds?: number; approval_id?: string; resume_run_id?: string };
export const MAX_AUTO_SEGMENTS = 8;
const AUTO_WALL_MS = 50_000;

// run_code as the tool sees it. On the free plan one request may make only 50 outbound requests, so a long run stops at a
// checkpoint. Rather than making the assistant call again and again, the server continues by itself: each segment runs
// as a fresh invocation of this Worker (the RunSegment entrypoint, ctx.exports), which gets its own per-invocation
// limits, and resumes the same run from its journal (finished calls are replayed, not repeated). It stops at ok, an
// approval, an error, no progress, MAX_AUTO_SEGMENTS segments or ~50 s; then the assistant resumes with resume_run_id.
export async function runCode(env: Env, ctx: ExecutionContext | undefined, a: RunArgs, opts: { quickjs?: () => Promise<QuickJSWASMModule>; segment?: boolean } = {}) {
  const seg = (ctx as any)?.exports?.RunSegment as { run(a: RunArgs): Promise<any> } | undefined; // loopback stub: each call is a new invocation
  if (opts.segment || !seg) return runOnce(env, ctx, a, opts);
  const started = Date.now();
  let r: any = await seg.run(a);
  let segments = 1;
  while (r?.checkpoint && r.run_id && segments < MAX_AUTO_SEGMENTS && Date.now() - started < AUTO_WALL_MS) {
    const before = r.finished_calls ?? 0;
    const next: any = await seg.run({ resume_run_id: r.run_id });
    segments++;
    const progressed = (next?.finished_calls ?? Infinity) > before || !next?.checkpoint;
    r = next;
    if (!progressed) break; // a segment made no progress: hand back to the assistant instead of looping
  }
  return segments > 1 ? { ...r, segments } : r;
}

async function runOnce(env: Env, ctx: ExecutionContext | undefined, a: RunArgs, opts: { quickjs?: () => Promise<QuickJSWASMModule> } = {}) {
  // Paid plan: a Dynamic Worker per run. Free plan (no LOADER binding): QuickJS inside this Worker (quick-run.ts).
  const loader = (env as any).LOADER as WorkerLoader | undefined;
  const entry = (ctx as any)?.exports?.Broker as ((o: { props: RunProps }) => Fetcher) | undefined;
  const s = store(env);
  let runId: string | undefined;
  let resume: RunProps["resume"];
  let retryFailed = false;
  if (a.approval_id) {
    const raw = await s.get(`runpause:${a.approval_id}`);
    if (!raw) throw new Error("That approval_id does not belong to a paused run, or the run expired (1 hour). Run the code again as a new run.");
    const p = JSON.parse(raw) as { runId: string; seq: number };
    if (a.resume_run_id && a.resume_run_id !== p.runId) throw new Error("That approval_id belongs to a different run_id.");
    runId = p.runId;
    resume = { approvalId: a.approval_id, seq: p.seq };
  } else if (a.resume_run_id) {
    runId = a.resume_run_id;
    // Retry calls that got an error status only when resuming a run that FAILED (the cause may be fixed now, e.g. a
    // renewed key). Continuing from a checkpoint replays them like every other finished call.
    retryFailed = (await s.get(`run:${runId}:last`)) === "failed";
  }

  let program: Program;
  let codeHash: string;
  if (runId) {
    const [meta, src] = await Promise.all([s.get(`run:${runId}:meta`), s.get(`run:${runId}:src`)]);
    if (!meta || !src) throw new Error("That run is unknown or expired (runs are kept 1 hour). Start it again as a new run.");
    codeHash = JSON.parse(meta).codeHash;
    program = JSON.parse(src) as Program;
    // Code sent along with a resume must be exactly the stored program (the approval is bound to it).
    if (a.code !== undefined && (await programHash({ code: a.code, secrets: a.secrets ?? program.secrets, input: a.input === undefined ? program.input : a.input })) !== codeHash) {
      throw new Error("The code, secrets or input differ from the run being resumed. Resume with just resume_run_id (and approval_id), or start a new run.");
    }
    if (!resume && (await s.get(pausedKey(runId)))) throw new Error(`That run is waiting for an approval: once the user approved, call ${resumeCall(runId, "<approval_id>")}.`);
    if (resume) await s.delete(pausedKey(runId));
  } else {
    if (!a.code || !a.secrets?.length || !a.purpose) throw new Error("A new run needs code, secrets and purpose (or pass resume_run_id to continue an earlier run).");
    program = { code: a.code, secrets: [...new Set(a.secrets)].sort(), purpose: a.purpose, input: a.input, timeout_seconds: a.timeout_seconds };
    codeHash = await programHash(program);
    runId = crypto.randomUUID();
    await s.put(`run:${runId}:meta`, JSON.stringify({ codeHash }), JOURNAL_TTL);
    await s.put(`run:${runId}:src`, JSON.stringify(program), JOURNAL_TTL);
  }
  const props: RunProps = { runId, codeHash, secrets: program.secrets, purpose: program.purpose, resume, retryFailed };
  const timeout = (a.timeout_seconds ?? program.timeout_seconds ?? 120) * 1000;
  let out: { ok: boolean; result?: unknown; error?: string; logs?: string[] } = { ok: false, error: "not run" };
  let engine = "quickjs";
  if (loader && entry) {
    const cpuMs = Number((env as any).RUN_CODE_CPU_MS) > 0 ? Number((env as any).RUN_CODE_CPU_MS) : undefined;
    out = await runInDynamicWorker(loader, entry, props, program, timeout, cpuMs);
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
    const state: RunState = { liveLeft: budget, calls: [], notes: [] };
    const runEnv = withSecretCache(env); // each secret is read once per request, not once per call
    out = await runInQuickJS(QuickJS, { code: program.code, input: program.input, timeoutMs: timeout, maxSteps, call: (seq, op) => brokerOp(runEnv, props, seq, op, state) });
    if (state.notes.length) out.logs = [...(out.logs ?? []), ...state.notes];
    const outcome = state.checkpoint ? "checkpoint" : out.ok ? "ok" : "failed";
    await s.put(`run:${runId}:last`, outcome, JOURNAL_TTL);
    if (state.checkpoint && !(await s.get(pausedKey(runId)))) {
      const done = state.calls.filter((c) => typeof c.status === "number").length;
      return {
        ok: false, checkpoint: true, run_id: runId, engine, finished_calls: done,
        reason: `${state.checkpoint}; ${done} call${done === 1 ? "" : "s"} finished so far (kept).`,
        ...(out.logs?.length ? { logs: out.logs } : {}),
        next_step: `Call ${resumeCall(runId)} with ONLY resume_run_id (do not resend code, purpose or input; the server kept them). Finished calls are replayed, not repeated. Repeat until ok: true. Batch work into fewer calls to need fewer resumes.`,
      };
    }
    if (!out.ok && state.calls.length) {
      return { ...(await finish(s, runId, out)), engine, completed_calls: state.calls.slice(-50),
        next_step: `After fixing the cause, call ${resumeCall(runId)} with ONLY resume_run_id (do not resend code): finished calls are not repeated, failed ones are retried. Kept 1 hour.` };
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
      approval_required: true, run_id: runId, approval_id: p.approval_id, approve_url: p.approve_url, expires_in_minutes: p.expires_in_minutes, action: p.action,
      logs: out.logs,
      next_step: `Tell the user to open approve_url and press Approve. After they confirm, call ${resumeCall(runId, p.approval_id)} with ONLY resume_run_id and approval_id (do not resend code, purpose or input). Steps that already ran are not repeated.`,
    };
  }
  const base = { ok: out.ok, run_id: runId, ...(out.logs?.length ? { logs: out.logs } : {}) };
  if (!out.ok) return { ...base, error: out.error };
  const text = JSON.stringify(out.result ?? null);
  const bytes = utf8Length(text);
  if (bytes > MAX_OUTPUT) {
    // Too big to return: say so, and show its shape so the next run can return just what is needed.
    return { ...base, truncated: true, original_bytes: bytes, limit_bytes: MAX_OUTPUT, result: null, sample: sampleOf(out.result),
      hint: "The return value is too big: return only the fields you need (filter or map in code, or use pick on calls); see sample for the shape." };
  }
  return { ...base, result: out.result };
}

export const RUN_CODE_DESCRIPTION =
  "Run JavaScript on the server to do multi-step work with the stored credentials: sequential, parallel (Promise.all), nested, loops, conditions, retries. " +
  "Your code is the BODY of an async function: use await, and `return` the result (only the return value and console.log output come back, so filter big data in code). It runs in an isolated sandbox with no network except these helpers, and it never sees a credential: " +
  "api.get(secret, url, opts?), api.post(secret, url, body, opts?), api.put/patch(...same), api.delete(secret, url, opts?), api.request({...same arguments as api_request}) -> {status, ok, body (parsed JSON when possible), headers, vault?}; " +
  "aws.call(secret, {service, region?, action, params?}) for JSON/query AWS APIs, e.g. aws.call('AWS_ADMIN', {service: 'dynamodb', action: 'GetItem', params: {TableName: 't', Key: {id: {S: '1'}}}}), aws.call(s, {service: 'ec2', action: 'DescribeInstances'}), aws.call(s, {service: 'ssm', action: 'SendCommand', params: {...}}) (XML responses are parsed to objects); " +
  "aws.request(secret, {service, region?, method, path, query?, headers?, body?}) for REST AWS APIs such as s3 (path-style: path '/bucket/key') and lambda; " +
  "vault.list(), vault.delete(name); sleep(ms); input (your input value). Any opts may include capture: {name: '$.json.path'} to keep a value (e.g. a new API key) server-side as vault:<name>, usable later as secret or {{vault:name}}. " +
  "RESPONSE SIZE: a response body over 60 KB (or opts.max_bytes, up to 500000) comes back with truncated: true, original_bytes, body: null, body_text (the cut-off text), sample (the shape of the full response: keys, types, array lengths, first item) and a hint. Always check r.truncated before using r.body. " +
  "To fetch less, pass opts.pick: JSON paths such as ['$.results[*].id', '$.results[*].properties.Name', '$.has_more'] and only those fields come back, in their original nesting; or use the API's own page_size/limit. " +
  "List every secret the code uses in `secrets`. The same checks as api_request apply to every call (hosts, redaction, approvals). If a call needs the user's approval, the run stops and returns approval_required with run_id and a link; after they approve, call run_code with ONLY {resume_run_id, approval_id}. Do NOT resend code, purpose or input: the server kept the original code, and finished steps are replayed from a record, not repeated. " +
  "So keep the code deterministic (do not put Date.now() or random values into requests). " +
  "LIMITS on this server (Cloudflare free plan): about 35 API calls per run_code call (the platform allows 50 outbound requests per request; replayed calls are free), 6 in flight at once, ~10 ms of CPU for your own code (orchestrate and filter; no heavy loops), timeout_seconds wall time, 100 KB return value (bigger returns truncated: true with a sample), 300 calls per run in total. " +
  "Plan for it: batch work into few calls (e.g. send many items in ONE AI request, use list/batch endpoints) rather than one call per item. Long runs: the server continues past the per-request budget by itself (up to 8 segments, ~280 calls, ~50 s per tool call). If it still returns checkpoint: true, call run_code with ONLY {resume_run_id} (no code, purpose or input) and repeat until ok: true. A failed run returns completed_calls and run_id; after fixing the cause run_code with ONLY {resume_run_id} continues (calls that got an error status are retried, successful ones are not). " +
  "Modern syntax works, but there is no fetch, setTimeout or Node API inside: use the helpers.";
