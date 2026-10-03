import { DurableObject } from "cloudflare:workers";
import { StoreCore } from "./store-core";

const SWEEP_MS = 6 * 60 * 60 * 1000;

// One global instance (idFromName("global")) holds approvals, sign-in sessions, nonces and OAuth state.
export class ApprovalStore extends DurableObject {
  private core = new StoreCore(this.ctx.storage as any);

  get(key: string) { return this.core.get(key); }
  async put(key: string, value: string, ttlSeconds: number) {
    await this.core.put(key, value, ttlSeconds);
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_MS);
  }
  delete(key: string) { return this.core.delete(key); }

  async alarm() {
    if ((await this.core.sweep()) > 0) await this.ctx.storage.setAlarm(Date.now() + SWEEP_MS);
  }
}
