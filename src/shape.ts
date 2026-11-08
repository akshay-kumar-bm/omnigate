// Helpers for run_code results that are too big: a short "sample" that shows the shape of a value (keys, types, array
// lengths, the first item), and `pick`, a small JSONPath subset that keeps only the fields the caller asks for.
// Pure functions, no I/O.

const MAX_STRING = 80;
const MAX_SAMPLE = 2048;

const clipStr = (s: string) => JSON.stringify(s.length > MAX_STRING ? `${s.slice(0, MAX_STRING)}…` : s);
const keyText = (k: string) => (/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k));

function describe(v: unknown, depth: number, maxKeys: number): string {
  if (v === null || v === undefined) return String(v);
  if (typeof v === "string") return clipStr(v);
  if (typeof v !== "object") return String(v);
  if (depth <= 0) return Array.isArray(v) ? `[${v.length} items]` : "{…}";
  if (Array.isArray(v)) {
    if (v.length === 0) return "[]";
    return `[${v.length} item${v.length === 1 ? "" : "s"}] → first: ${describe(v[0], depth - 1, maxKeys)}`;
  }
  const entries = Object.entries(v as Record<string, unknown>);
  const shown = entries.slice(0, maxKeys).map(([k, x]) => `${keyText(k)}:${describe(x, depth - 1, maxKeys)}`);
  if (entries.length > maxKeys) shown.push(`…+${entries.length - maxKeys} keys`);
  return `{${shown.join(", ")}}`;
}

// The shape of a value in at most ~2 KB: shallower and with fewer keys until it fits.
export function sampleOf(v: unknown, max = MAX_SAMPLE): string {
  for (const [depth, keys] of [[6, 30], [5, 20], [4, 15], [3, 10], [2, 8], [1, 8]] as const) {
    const s = describe(v, depth, keys);
    if (s.length <= max) return s;
  }
  return `${describe(v, 1, 8).slice(0, max - 1)}…`;
}

// ---- pick: "$.results[*].id", "$.results[*].properties.title", "$.has_more", "$.data[0].name", "$['odd key']" ----
type Seg = string | number | "*";

export function parsePath(p: string): Seg[] {
  const src = p.trim();
  if (!src.startsWith("$")) throw new Error(`pick path must start with $: ${p}`);
  const segs: Seg[] = [];
  const re = /\.([A-Za-z_$][\w$-]*)|\.\*|\[(\d+)\]|\[\*\]|\[['"]([^'"]+)['"]\]/y;
  let i = 1;
  while (i < src.length) {
    re.lastIndex = i;
    const m = re.exec(src);
    if (!m) throw new Error(`Unsupported pick path ${p}: use $.key, $.list[*].key, $.list[0], $['key']`);
    segs.push(m[1] ?? m[3] ?? (m[2] !== undefined ? Number(m[2]) : "*"));
    i = re.lastIndex;
  }
  return segs;
}

function project(v: unknown, segs: Seg[], i = 0): unknown {
  if (i === segs.length) return v;
  const s = segs[i];
  if (v === null || typeof v !== "object") return undefined;
  if (s === "*") {
    if (Array.isArray(v)) return v.map((x) => project(x, segs, i + 1));
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, project(x, segs, i + 1)]));
  }
  if (typeof s === "number") {
    if (!Array.isArray(v) || s >= v.length) return undefined;
    const out: unknown[] = [];
    out[s] = project(v[s], segs, i + 1);
    return out;
  }
  if (!(s in (v as Record<string, unknown>))) return undefined;
  return { [s]: project((v as Record<string, unknown>)[s], segs, i + 1) };
}

function merge(a: unknown, b: unknown): unknown {
  if (a === undefined) return b;
  if (b === undefined) return a;
  if (Array.isArray(a) && Array.isArray(b)) return Array.from({ length: Math.max(a.length, b.length) }, (_, i) => merge(a[i], b[i]));
  if (a && b && typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
    const out: Record<string, unknown> = { ...(a as Record<string, unknown>) };
    for (const [k, x] of Object.entries(b)) out[k] = merge(out[k], x);
    return out;
  }
  return b;
}

// Keep only the picked fields, in their original nesting (so r.body.results.map(x => x.id) still works).
export function pick(v: unknown, paths: string[]): unknown {
  let out: unknown = undefined;
  for (const p of paths) out = merge(out, project(v, parsePath(p)));
  return out ?? null;
}

export const utf8Length = (s: string) => new TextEncoder().encode(s).length;
