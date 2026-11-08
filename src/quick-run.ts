// run_code on the Workers FREE plan: the assistant's JavaScript runs in QuickJS (a small JavaScript engine compiled to
// WebAssembly) inside this Worker, instead of in a Dynamic Worker (which needs the paid plan). The guest has no fetch,
// no timers, no network and no access to the host: its only ways out are three host functions defined here
// (__call -> brokerOp with every check of api_request, __log, __sleep). Memory is capped, and execution is cut off after
// a fixed number of interrupt checks (time does not advance inside a Worker while code runs, so a clock is no use).
// Free Workers get 10 ms of CPU per request: fine for orchestration code (calls, filtering, small loops), not for
// heavy computation. No Cloudflare-only imports: runs under Node for tests (the Worker passes the WebAssembly module in).
import type { QuickJSHandle, QuickJSWASMModule } from "quickjs-emscripten-core";

export interface QuickRunResult { ok: boolean; result?: unknown; error?: string; logs: string[] }

// Same helpers as the Dynamic Worker shim (run-code.ts), written for QuickJS: ops go out as JSON strings.
const PRELUDE = `
globalThis.__start = async function (input) {
  const fmt = (v) => { if (typeof v === "string") return v; try { return JSON.stringify(v); } catch (e) { return String(v); } };
  const log = (...a) => __log(a.map(fmt).join(" "));
  let seq = 0, active = 0; const waiting = [];
  const call = async (op) => {
    const n = seq++; // numbered when called, so Promise.all keeps a stable order on replay
    while (active >= 20) await new Promise((r) => waiting.push(r));
    active++;
    try { return JSON.parse(await __call(n, JSON.stringify(op))); }
    finally { active--; const w = waiting.shift(); if (w) w(); }
  };
  const noBody = (m) => m === "GET" || m === "DELETE" || m === "HEAD";
  const method = (m) => (secret, url, a, b) => call({ kind: "api", args: Object.assign({}, noBody(m) ? a : b, { secret, url, method: m }, noBody(m) || a === undefined ? {} : { body: a }) });
  const api = { request: (args) => call({ kind: "api", args }), get: method("GET"), head: method("HEAD"), delete: method("DELETE"), post: method("POST"), put: method("PUT"), patch: method("PATCH") };
  const aws = { call: (secret, spec) => call(Object.assign({}, spec, { kind: "aws", secret })), request: (secret, spec) => call(Object.assign({}, spec, { kind: "aws_request", secret })) };
  const vault = { list: () => call({ kind: "vault_list" }), delete: (name) => call({ kind: "vault_delete", name }) };
  const sleep = (ms) => __sleep(Math.max(0, Math.min(Number(ms) || 0, 60000)));
  const result = await __user({ api, aws, vault, input, sleep, console: { log, info: log, warn: log, error: log, debug: log } });
  return JSON.stringify(result === undefined ? null : result);
};
`;

export async function runInQuickJS(
  QuickJS: QuickJSWASMModule,
  o: { code: string; input: unknown; timeoutMs: number; maxSteps: number; call: (seq: number, op: unknown) => Promise<unknown> },
): Promise<QuickRunResult> {
  const logs: string[] = [];
  let logBytes = 0;
  const rt = QuickJS.newRuntime();
  rt.setMemoryLimit(64 * 1024 * 1024);
  rt.setMaxStackSize(1024 * 1024);
  let steps = 0;
  rt.setInterruptHandler(() => ++steps > o.maxSteps);
  const vm = rt.newContext();
  let dead = false;
  const drain = () => { if (!dead) { const r = rt.executePendingJobs(); if (r.error) r.error.dispose(); } };
  const def = (name: string, fn: (...args: QuickJSHandle[]) => QuickJSHandle | undefined) => {
    const h = vm.newFunction(name, fn);
    vm.setProp(vm.global, name, h);
    h.dispose();
  };
  // A host promise whose result is handed to the guest when it settles.
  const hostPromise = (work: Promise<string | undefined>) => {
    const d = vm.newPromise();
    work.then(
      (v) => { if (dead) return; if (v === undefined) d.resolve(); else { const h = vm.newString(v); d.resolve(h); h.dispose(); } },
      (e) => { if (dead) return; const h = vm.newError(String((e as Error)?.message ?? e)); d.reject(h); h.dispose(); },
    );
    d.settled.then(drain);
    return d.handle;
  };
  def("__call", (seqH, opH) => {
    const seq = vm.getNumber(seqH);
    const op = vm.getString(opH);
    return hostPromise((async () => JSON.stringify(await o.call(seq, JSON.parse(op))))());
  });
  def("__log", (h) => {
    const l = vm.getString(h);
    if (logBytes < 20_000) { logs.push(l.slice(0, 4000)); logBytes += l.length; }
    return undefined;
  });
  def("__sleep", (h) => hostPromise(new Promise((r) => setTimeout(() => r(undefined), vm.getNumber(h)))));

  const fail = (error: string): QuickRunResult => ({ ok: false, error, logs });
  try {
    const setup = vm.evalCode(`${PRELUDE}\nglobalThis.__user = async function ({ api, aws, vault, input, sleep, console }) {\n${o.code}\n};`, "run_code.js");
    if (setup.error) { const e = vm.dump(setup.error); setup.error.dispose(); return fail(`The code could not be compiled: ${fmtErr(e)}`); }
    setup.value.dispose();
    const started = vm.evalCode(`__start(${JSON.stringify(o.input ?? null)})`);
    if (started.error) { const e = vm.dump(started.error); started.error.dispose(); return fail(fmtErr(e)); }
    const native = vm.resolvePromise(started.value);
    started.value.dispose();
    drain();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      native,
      new Promise<"timeout">((r) => { timer = setTimeout(() => r("timeout"), o.timeoutMs); }),
    ]);
    if (timer !== undefined) clearTimeout(timer);
    if (outcome === "timeout") return fail(`The code did not finish within ${o.timeoutMs / 1000} s`);
    if (outcome.error) {
      const e = vm.dump(outcome.error); outcome.error.dispose();
      return fail(steps > o.maxSteps ? "The code used too much computation and was stopped (the free Workers plan allows about 10 ms of CPU per request; move heavy work out of the loop or filter less data)" : fmtErr(e));
    }
    const text = vm.getString(outcome.value);
    outcome.value.dispose();
    return { ok: true, result: JSON.parse(text), logs };
  } catch (e) {
    return fail(String((e as Error)?.message ?? e));
  } finally {
    dead = true;
    try { vm.dispose(); } catch { /* handles still held by pending host promises; the runtime goes with the request */ }
    try { rt.dispose(); } catch { /* same */ }
  }
}

function fmtErr(e: unknown): string {
  if (e && typeof e === "object") {
    const x = e as { name?: string; message?: string; stack?: string };
    return `${x.name ?? "Error"}: ${x.message ?? ""}${x.stack ? `\n${String(x.stack).slice(0, 1500)}` : ""}`;
  }
  return String(e);
}
