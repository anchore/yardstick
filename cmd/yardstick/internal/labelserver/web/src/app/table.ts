// table.ts is the data table's logic: sort, filter, group and count. Pure: tableview.ts draws it.

export type Cell = string | number | null | undefined;
export type Dir = "asc" | "desc";
export interface Sort { key: string; dir: Dir }

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

// compare orders two cells: numbers numerically, text naturally (CVE-2019-9 before CVE-2019-10),
// and empty cells last whichever way the sort goes
export function compare(a: Cell, b: Cell, dir: Dir = "asc"): number {
  const ea = a == null || a === "", eb = b == null || b === "";
  if (ea || eb) return ea === eb ? 0 : ea ? 1 : -1;
  const c = typeof a === "number" && typeof b === "number" ? a - b : collator.compare(String(a), String(b));
  return dir === "asc" ? c : -c;
}

// sortRows is a sorted copy, stable, by the cell value(row) gives
export function sortRows<T>(rows: readonly T[], value: (row: T) => Cell, dir: Dir = "asc"): T[] {
  return rows.map((r, i) => [r, i] as const)
    .sort(([a, i], [b, j]) => compare(value(a), value(b), dir) || i - j)
    .map(([r]) => r);
}

// filterRows keeps the rows whose text(row) has every word of q, ignoring case
export function filterRows<T>(rows: readonly T[], q: string, text: (row: T) => string): T[] {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [...rows];
  return rows.filter((r) => {
    const t = text(r).toLowerCase();
    return words.every((w) => t.includes(w));
  });
}

export interface Group<T> { key: string; rows: T[] }

// groupRows splits rows by key(row), groups in the order their first row appears
export function groupRows<T>(rows: readonly T[], key: (row: T) => string): Group<T>[] {
  const by = new Map<string, T[]>();
  for (const r of rows) {
    const k = key(r);
    let g = by.get(k);
    if (!g) by.set(k, (g = []));
    g.push(r);
  }
  return [...by].map(([k, rs]) => ({ key: k, rows: rs }));
}

// countBy is how many rows have each key, for filter chips' counts
export function countBy<T>(rows: readonly T[], key: (row: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of rows) {
    const k = key(r);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

// nextSort is the sort after clicking a column's header: a new column sorts ascending, the same
// column flips
export function nextSort(cur: Sort | null, key: string): Sort {
  return cur?.key === key ? { key, dir: cur.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" };
}
