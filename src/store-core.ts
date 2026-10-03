// Tiny key-value store with expiry, used by the approval flow. Kept free of Cloudflare imports so it can be tested
// under Node; ApprovalStore (approval-store.ts) runs it inside a Durable Object, which is strongly consistent:
// a write is visible to every later read anywhere, unlike Workers KV (visible elsewhere only after up to a minute).
export interface RawStorage {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<unknown>;
  list<T>(): Promise<Map<string, T>>;
}
interface Entry { v: string; x: number }

export class StoreCore {
  constructor(private s: RawStorage, private now: () => number = Date.now) {}

  async get(key: string): Promise<string | null> {
    const e = await this.s.get<Entry>(key);
    if (!e) return null;
    if (e.x <= this.now()) { await this.s.delete(key); return null; }
    return e.v;
  }
  async put(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.s.put(key, { v: value, x: this.now() + ttlSeconds * 1000 } satisfies Entry);
  }
  async delete(key: string): Promise<void> { await this.s.delete(key); }

  // Drops expired entries; returns how many entries remain.
  async sweep(): Promise<number> {
    let left = 0;
    for (const [k, e] of await this.s.list<Entry>()) {
      if (e.x <= this.now()) await this.s.delete(k); else left++;
    }
    return left;
  }
}
