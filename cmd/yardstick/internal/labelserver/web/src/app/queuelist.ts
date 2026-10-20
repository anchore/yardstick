// queuelist.ts is the queue's logic: which queue n enters from a screen and where Exit goes back
// to, the gate an entry is labeled in, the order a scope walks, and the row Save and next goes to.
// Pure: queue.ts fetches and draws.
import type { QueueEntry, QueueGate } from "../gen/wire";
import type { Item } from "./neighbors";
import type { Route } from "./route";

export type QueueRoute = Extract<Route, { level: "queue" }>;

// DoneRow is a row labeled since the queue started, and the gate it was labeled in
export interface DoneRow { row: string; gate: string }

// queueFor is the queue n (and "Label next") enters from a screen: an image filter's image; a gate,
// check or finding's gate first (a check's own open rows before that), continuing across gates;
// anywhere else every gate
export function queueFor(r: Route): QueueRoute {
  if (r.level === "queue") return { level: "queue", scope: r.scope, check: r.check, low: r.low, filters: {} };
  if (r.level === "research") return r.scope ? { level: "queue", scope: r.scope, filters: {} } : { level: "queue", filters: {} };
  if (r.level !== "gate" && r.level !== "check" && r.level !== "finding") return { level: "queue", filters: {} };
  if (r.filters.image) return { level: "queue", scope: `image:${r.filters.image}`, filters: {} };
  const check = r.level === "check" ? r.check : r.level === "finding" ? r.check ?? undefined : undefined;
  return { level: "queue", scope: `gate:${r.gate}`, ...(check && { check }), filters: {} };
}

// researchFor is the research page r opens from a screen, scoped the way n is: a check's rows bearing
// on it (in its gate, whatever the image filter), an image filter's image, a gate; anywhere else
// every gate
export function researchFor(r: Route): Extract<Route, { level: "research" }> {
  if (r.level === "check") return { level: "research", scope: `gate:${r.gate}`, check: r.check, filters: {} };
  const scope = queueFor(r).scope;
  return scope ? { level: "research", scope, filters: {} } : { level: "research", filters: {} };
}

// scopeGate is the gate a gate scope names, or null for all and for an image
export const scopeGate = (scope: string | undefined) => (scope?.startsWith("gate:") ? scope.slice(5) : null);

// exitRoute is where Exit (and Esc) leaves a queue for: the check or gate it was entered from, else
// the gates screen
export function exitRoute(q: QueueRoute): Route {
  const gate = scopeGate(q.scope);
  if (gate && q.check) return { level: "check", gate, check: q.check, filters: {} };
  if (gate) return { level: "gate", gate, tab: "checks", filters: {} };
  return { level: "gates", tab: "gates", filters: {} };
}

// entryGate is the gate an entry is labeled in: the scope's gate when the entry is in it, else the
// closest to done of its gates that is not settled yet, else the closest to done
export function entryGate(e: QueueEntry, gates: QueueGate[], scope?: string): string {
  const named = scopeGate(scope);
  if (named && e.in.some((a) => a.gate === named)) return named;
  const g = (name: string) => gates.find((x) => x.name === name);
  const rank = (name: string) => [g(name)?.settled ? 1 : 0, g(name)?.rows ?? Infinity];
  return [...e.in].sort((a, b) => {
    const [x, y] = [rank(a.gate), rank(b.gate)];
    return x[0] - y[0] || x[1] - y[1];
  })[0]?.gate ?? "";
}

// ordered is the queue a scope walks: first the rows named (a check's open rows), then each list in
// turn (the scope's queue, then every gate's for a gate scope), each row once
export function ordered(first: string[], ...lists: QueueEntry[][]): QueueEntry[] {
  const by = new Map<string, QueueEntry>();
  for (const l of lists) for (const e of l) if (!by.has(e.row)) by.set(e.row, e);
  const out = first.flatMap((id) => (by.has(id) ? [by.get(id)!] : []));
  for (const e of by.values()) if (!first.includes(e.row)) out.push(e);
  return out;
}

// pickNext is the row Save and next goes to: the first in queue order not just written and not
// passed over with Skip, else the first passed over (the queue comes back round to them)
export function pickNext(entries: QueueEntry[], written: string[], skipped: string[]): string | undefined {
  const left = entries.filter((e) => !written.includes(e.row));
  return (left.find((e) => !skipped.includes(e.row)) ?? left[0])?.row;
}

// walk is the queue as j and k step through it: the rows labeled since it started, then the open
// ones in queue order. With the cog's "skip labeled rows" on, neighbors.position steps over the done ones.
export function walk(entries: QueueEntry[], done: DoneRow[]): Item[] {
  const open = new Set(entries.map((e) => e.row));
  return [...done.filter((d) => !open.has(d.row)).map((d) => ({ id: d.row, open: false })), ...entries.map((e) => ({ id: e.row, open: true }))];
}

// newlyDone are the rows of the last snapshot the fresh queue no longer has: labeled since, here or
// anywhere else
export function newlyDone(seen: DoneRow[], entries: QueueEntry[], done: DoneRow[]): DoneRow[] {
  const open = new Set(entries.map((e) => e.row)), had = new Set(done.map((d) => d.row));
  return seen.filter((s) => !open.has(s.row) && !had.has(s.row));
}
