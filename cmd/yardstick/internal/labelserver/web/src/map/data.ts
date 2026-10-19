// data.ts reads the gate's /state into what the map draws: the rows in scope, their label tallies,
// the groups one action settles, ranked by what their labels do for the gate, and the rows a card
// spec opens. Pure: every function takes the state it reads.
import type { CheckResult, State, StateCause, claimsv1 } from "../gen/wire";
import { endsGate, regressionRisk } from "../shared/gate";
import { bears, decisive, type Dir, direction, hinted, isOpen, isResearched, researchLevel, type Row, srcPkg } from "../shared/rows";
import { dirTitle, marks, plural, whyTitle } from "../shared/words";
import type { CardsSpec } from "./url";

// Item is a row in scope, with its subject index and direction
export interface Item { r: Row; si: number; dir: Dir }
export interface Cards { title: string; ids: Set<string> }
export interface Group { key: string; tier: number; cause: StateCause | undefined; dir: Dir; pkg: string; rows: Item[] }

export function groupBy<T>(list: T[], keyOf: (it: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of list) { const k = keyOf(it); let l = m.get(k); if (!l) m.set(k, (l = [])); l.push(it); }
  return m;
}

function rowsWhere(st: State, si: number | null, keep: (d: Dir) => boolean): Item[] {
  const out: Item[] = [];
  st.subjects.forEach((s, i) => {
    if (si != null && i !== si) return;
    for (const r of s.rows) { const d = direction(r); if (keep(d)) out.push({ r, si: i, dir: d }); }
  });
  return out;
}
// diffRows are the differing rows in scope (si, or every image when null)
export const diffRows = (st: State, si: number | null) => rowsWhere(st, si, (d) => d === "added" || d === "dropped");
// allRows is every row in scope, with its subject and direction (both-sided rows included: open
// ones bear on the F1 check too)
export const allRows = (st: State, si: number | null) => rowsWhere(st, si, (d) => d !== "neither");

export type Tally = ReturnType<typeof tally>;
// tally counts a set of rows by label state
export function tally(list: Item[]) {
  const t = { n: list.length, tp: 0, fp: 0, unclear: 0, open: 0, hinted: 0, triaged: 0, researched: 0, decisive: 0, bears: 0 };
  for (const { r } of list) {
    if (r.verdict === "tp") t.tp++;
    else if (r.verdict === "fp") t.fp++;
    else if (r.verdict === "unclear") t.unclear++;
    else t.open++;
    if (hinted(r)) t.hinted++;
    if (isResearched(r)) t.researched++;
    else if (researchLevel(r) === "triaged") t.triaged++;
    if (isOpen(r) && decisive(r)) t.decisive++;
    else if (isOpen(r) && bears(r)) t.bears++;
  }
  return t;
}

export const whyKey = (w: Row["why"]) => (w ? `${w.key}|${w.from || ""}|${w.to || ""}` : "none");

// reasonTitle is a reason node's title: the agent's explanation when every row under it shares one
// (an explanation never changes a verdict, it only says why the setups differ), else the computed
// reason
export function reasonTitle(st: State, list: Item[], dir: string) {
  const id = list[0]?.r.explanation;
  const ex = id && list.every((x) => x.r.explanation === id) && (st.explanations || []).find((e) => e.id === id);
  return ex ? `✎ ${ex.title}` : whyTitle(list[0]?.r.why, dir);
}
export function subjectName(st: State, si: number) {
  const s = st.scans.subjects?.[si];
  return s?.name || s?.slug || `subject ${si + 1}`;
}

// unchanged: a passing gate whose scans don't differ in any image. Its checks compare nothing to
// nothing, so it gets one plain headline instead of a board of zeroes. Returns the matches both
// sides report and the image count, else null.
export function unchanged(st: State) {
  if (st.gate?.result?.outcome !== "pass" || diffRows(st, null).length) return null;
  return { shared: allRows(st, null).length, images: st.subjects.length };
}

// ---------- the gate board's ranking ----------

const hintRank: Record<string, number> = { high: 0, medium: 0.3, low: 0.6 };

// tier ranks an open row by what its label does for the gate: 0 ends the gate now, 1 a dropped
// finding (one TP is a regression: fails noNewFalseNegatives outright), 2 agent-suggested (high
// confidence first; one accept can label many), 3 the rest; findings both sides report come last
// within a tier, since only the F1 check feels them.
export function tier(st: State, r: Row, dir: Dir) {
  const res = st.gate?.result;
  if (!isOpen(r)) return 9;
  if (endsGate(res?.outcome, r)) return 0;
  // a dropped finding is a regression risk while a check that counts false negatives is open (the
  // check says what it counts); one the agent already reads as FP is a cleanup to accept
  let t = regressionRisk(res?.checks || [], dir) && !(hinted(r) && r.hint.verdict === "fp") ? 1 : hinted(r) ? 2 + (hintRank[r.hint.confidence ?? ""] ?? 0.6) : 3;
  if (dir === "both") t += 0.05;
  return t;
}
export const tierNames: Record<number, string> = { 0: "a label here ends the gate now", 1: "− dropped: a TP here is a regression", 2: "✦ agent hint: one accept can label many", 3: "the rest" };
export const tierOf = (t: number) => Math.min(3, Math.floor(t));

// failingClaims are the rows whose existing claims a failed check counts against it: the check
// names them (failsOn); a check that doesn't has none to show.
export function failingClaims(st: State, si: number | null, c: CheckResult) {
  const ids = new Set(c.failsOn || []);
  return ids.size ? allRows(st, si).filter((x) => ids.has(x.r.id)) : [];
}

// bearing lists the open rows whose label narrows a check
export const bearing = (st: State, si: number | null, c: CheckResult) =>
  allRows(st, si).filter((x) => x.r.gate && isOpen(x.r) && ((x.r.gate.bears || []).includes(c.name) || (x.r.gate.couldFlip || []).includes(c.name)));

// groups folds a check's bearing rows into the things one action settles: a same-reasoning group
// (one accept labels every pending member) or a source package in one direction, by tier.
export function groups(st: State, rows: Item[]): Group[] {
  const causes = new Map(st.causes.map((c) => [c.id, c]));
  const byKey = new Map<string, Group>();
  for (const x of rows) {
    const cause = (x.r.causes || []).map((id) => causes.get(id)).find((c) => c && c.pending?.includes(x.r.id));
    const t = tier(st, x.r, x.dir);
    const key = cause ? `c|${cause.id}` : `p|${tierOf(t)}|${x.dir}|${srcPkg(x.r)}`;
    let g = byKey.get(key);
    if (!g) byKey.set(key, (g = { key, tier: t, cause, dir: x.dir, pkg: srcPkg(x.r), rows: [] }));
    g.rows.push(x);
    g.tier = Math.min(g.tier, t);
  }
  return [...byKey.values()].sort((a, b) => (tierOf(a.tier) - tierOf(b.tier)) || (b.rows.length - a.rows.length) || (a.tier - b.tier) || a.pkg.localeCompare(b.pkg));
}

// ---------- cards: the rows a spec opens on the tile ----------

type GroupSpec = Extract<CardsSpec, { kind: "cause" | "tier" }>;
export const specOfGroup = (c: CheckResult, g: Group): GroupSpec =>
  (g.cause ? { kind: "cause", check: c.name, cause: g.cause.id } : { kind: "tier", check: c.name, tier: tierOf(g.tier), dir: g.dir, pkg: g.pkg });
const isGroup = (s: GroupSpec, g: Group) => (s.kind === "cause" ? g.cause?.id === s.cause : !g.cause && tierOf(g.tier) === s.tier && g.dir === s.dir && g.pkg === s.pkg);
const checkOf = (st: State, name: string) => st.gate?.result?.checks.find((k) => k.name === name);

// cardsFor turns the URL's card spec into the rows to show, from the current state
export function cardsFor(st: State, si: number | null, s: CardsSpec | null): Cards | null {
  if (!s) return null;
  if (s.kind === "delta") {
    const rows = diffRows(st, si).filter((x) => x.dir === s.dir && whyKey(x.r.why) === s.why && (s.pkg == null || srcPkg(x.r) === s.pkg));
    return { title: `${dirTitle[s.dir] || s.dir} › ${reasonTitle(st, rows, s.dir)}${s.pkg ? ` › ${s.pkg}` : ""}`, ids: new Set(rows.map((x) => x.r.id)) };
  }
  const c = checkOf(st, s.check);
  if (!c) return null;
  if (s.kind === "fails") {
    let rows = failingClaims(st, si, c);
    if (s.vuln) rows = rows.filter((x) => x.r.vulnerability === s.vuln && srcPkg(x.r) === s.pkg);
    return { title: s.vuln ? `${c.name} fails on ${s.vuln} · ${s.pkg}` : `${c.name}: the ${plural(rows.length, "claim")} it fails on`, ids: new Set(rows.map((x) => x.r.id)) };
  }
  const g = groups(st, bearing(st, si, c)).find((x) => isGroup(s, x));
  if (!g) return null;
  return { title: `${c.name} › ${g.cause ? `✦ ${g.cause.title}` : `${marks[g.dir]} ${g.pkg}`}`, ids: new Set(g.rows.map((x) => x.r.id)) };
}

// groupRows is the open group's rows in the group's order: by tier, open first, then package and id
export function groupRows(st: State, si: number | null, cards: Cards) {
  return allRows(st, si).filter((x) => cards.ids.has(x.r.id))
    .sort((a, b) => (tier(st, a.r, a.dir) - tier(st, b.r, b.dir)) || (Number(isOpen(b.r)) - Number(isOpen(a.r))) || srcPkg(a.r).localeCompare(srcPkg(b.r)) || a.r.vulnerability.localeCompare(b.r.vulnerability));
}

// nextGroup is the next group of the same check with something open, after the one shown
export function nextGroup(st: State, si: number | null, s: CardsSpec | null) {
  if (!s || (s.kind !== "cause" && s.kind !== "tier")) return null;
  const c = checkOf(st, s.check);
  if (!c) return null;
  const gs = groups(st, bearing(st, si, c)), i = gs.findIndex((g) => isGroup(s, g));
  const ring = [...gs.slice(i + 1), ...gs.slice(0, Math.max(0, i))];
  const g = ring.find((x) => x.rows.some((y) => isOpen(y.r)));
  return g ? { g, c } : null;
}

// hintLabels is what accepting the pending agent hints on these rows would write
export function hintLabels(rows: Row[]) {
  const out: Record<string, claimsv1.Verdict> = {};
  for (const r of rows) if (hinted(r)) out[r.id] = r.hint.verdict;
  return out;
}
export function causeLabels(cause: StateCause, ids: string[]) {
  const out: Record<string, claimsv1.Verdict> = {};
  for (const id of ids) if (cause.pending.includes(id)) out[id] = cause.verdict;
  return out;
}
