// Session vault: values the model must not see but later calls need (an API key an admin call just created, a
// password from Secrets Manager, AWS keys from CreateAccessKey). They are kept server-side for a limited time and
// the caller only ever sees a handle "vault:<name>". A handle can be used as an api_request secret or inside a header,
// URL or body as {{vault:<name>}}; the server substitutes the value right before sending and redacts it everywhere.
// A vault value may only be sent to the hosts of the secret that produced it (plus hosts a human approved for it),
// so "create a key, then post it to some other site" needs an approval naming that site.
import { store, type Store } from "./approvals";
import { commentHosts } from "./hosts";

export interface VaultRecord {
  value: string;
  source: string;        // secret whose call produced it
  comment: string;       // that secret's comment: its hosts/approve/allow lines apply to the vault value too
  extra_hosts: string[]; // hosts a human approved for this value
  expires: number;
}

const NAME = /^[A-Za-z0-9_-]{1,64}$/;
export const REF = /\{\{vault:([A-Za-z0-9_-]{1,64})\}\}/g;
export const DEFAULT_TTL = 60 * 60;
export const MAX_TTL = 24 * 60 * 60;

type VaultEnv = Parameters<typeof store>[0];

const key = (name: string) => `vault:${name}`;
const INDEX = "vault-index";

async function index(s: Store): Promise<Record<string, number>> {
  const raw = await s.get(INDEX);
  const all: Record<string, number> = raw ? JSON.parse(raw) : {};
  const now = Date.now();
  for (const [k, x] of Object.entries(all)) if (x <= now) delete all[k];
  return all;
}

export const isVaultName = (s: string) => s.startsWith("vault:") && NAME.test(s.slice(6));
export const vaultHosts = (r: VaultRecord) => [...new Set([...commentHosts(r.comment), ...r.extra_hosts])];

export async function vaultGet(env: VaultEnv, name: string): Promise<VaultRecord | null> {
  if (!NAME.test(name)) return null;
  const raw = await store(env).get(key(name));
  return raw ? (JSON.parse(raw) as VaultRecord) : null;
}

export async function vaultPut(env: VaultEnv, name: string, r: Omit<VaultRecord, "expires">, ttlSeconds = DEFAULT_TTL): Promise<string> {
  if (!NAME.test(name)) throw new Error(`Invalid vault name ${name}: letters, digits, _ and - only, up to 64`);
  const ttl = Math.min(Math.max(60, ttlSeconds), MAX_TTL);
  const s = store(env);
  const rec: VaultRecord = { ...r, expires: Date.now() + ttl * 1000 };
  await s.put(key(name), JSON.stringify(rec), ttl);
  const idx = await index(s);
  idx[name] = rec.expires;
  await s.put(INDEX, JSON.stringify(idx), MAX_TTL);
  return `vault:${name}`;
}

export async function vaultAllowHost(env: VaultEnv, name: string, host: string): Promise<void> {
  const r = await vaultGet(env, name);
  if (!r || r.extra_hosts.includes(host)) return;
  r.extra_hosts.push(host);
  await store(env).put(key(name), JSON.stringify(r), Math.max(60, Math.round((r.expires - Date.now()) / 1000)));
}

export async function vaultDelete(env: VaultEnv, name: string): Promise<boolean> {
  const s = store(env);
  const had = !!(await vaultGet(env, name));
  await s.delete(key(name));
  const idx = await index(s);
  delete idx[name];
  await s.put(INDEX, JSON.stringify(idx), MAX_TTL);
  return had;
}

// Names, sources and expiry only; never values.
export async function vaultList(env: VaultEnv) {
  const s = store(env);
  const out: { handle: string; source: string; hosts: string[]; expires_at: string }[] = [];
  for (const name of Object.keys(await index(s))) {
    const r = await vaultGet(env, name);
    if (r) out.push({ handle: `vault:${name}`, source: r.source, hosts: vaultHosts(r), expires_at: new Date(r.expires).toISOString() });
  }
  return out;
}

// Names referenced as {{vault:x}} anywhere in a JSON-able value.
export function vaultRefs(...parts: unknown[]): string[] {
  const names = new Set<string>();
  for (const p of parts) {
    if (p === undefined || p === null) continue;
    const text = typeof p === "string" ? p : JSON.stringify(p);
    for (const m of text.matchAll(REF)) names.add(m[1]);
  }
  return [...names];
}

export function substitute(text: string, values: Map<string, string>): string {
  return text.replace(REF, (_m, n: string) => values.get(n) ?? _m);
}

// Deep substitute in a JSON value (strings only; keys untouched).
export function substituteDeep(v: unknown, values: Map<string, string>): unknown {
  if (typeof v === "string") return substitute(v, values);
  if (Array.isArray(v)) return v.map((x) => substituteDeep(x, values));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, substituteDeep(x, values)]));
  return v;
}

// `$.a.b[0].c` or `a.b.0.c`
export function getPath(obj: unknown, path: string): unknown {
  const parts = path.replace(/^\$\.?/, "").replace(/\[(\d+)\]/g, ".$1").split(".").filter(Boolean);
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

export const randomSuffix = () => Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) => b.toString(16).padStart(2, "0")).join("");
