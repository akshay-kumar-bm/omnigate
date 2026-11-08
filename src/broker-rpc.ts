// The RPC entrypoint a run_code sandbox calls. The sandbox only receives a stub (ctx.exports.Broker({props})), so it
// can call `call()` but never sees env, secrets or props; props (run id, allowed secrets, approval being resumed) are
// fixed by run-code.ts when the sandbox is created. Kept apart from run-code.ts because it imports cloudflare:workers.
import { WorkerEntrypoint } from "cloudflare:workers";
import { brokerOp, type RunProps } from "./run-code";
import type { Env } from "./server";

export class Broker extends WorkerEntrypoint<Env, RunProps> {
  async call(seq: number, op: unknown): Promise<unknown> {
    return brokerOp(this.env, this.ctx.props, seq, op);
  }
}
