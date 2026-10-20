// scandata.ts reads the gate's /state into what the scan map draws: the changed rows in scope, their
// label tallies, and each reason's title. Pure: every function takes the state it reads.
import type { State } from "../gen/wire";
import { type Dir, direction, hinted, type Row } from "../shared/rows";
import { whyTitle } from "../shared/words";

// Item is a row in scope, with its subject index and direction
export interface Item { r: Row; si: number; dir: Dir }

export function groupBy<T>(list: T[], keyOf: (it: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of list) { const k = keyOf(it); let l = m.get(k); if (!l) m.set(k, (l = [])); l.push(it); }
  return m;
}

// diffRows are the rows only one setup reports, in image si or every image when null
export function diffRows(st: State, si: number | null): Item[] {
  const out: Item[] = [];
  st.subjects.forEach((s, i) => {
    if (si != null && i !== si) return;
    for (const r of s.rows) { const d = direction(r); if (d === "added" || d === "dropped") out.push({ r, si: i, dir: d }); }
  });
  return out;
}

// tally counts a set of rows by label state; open is unlabeled, and hinted the open ones with a hint
export function tally(list: Item[]) {
  const t = { n: list.length, tp: 0, fp: 0, unclear: 0, open: 0, hinted: 0 };
  for (const { r } of list) {
    if (r.verdict === "tp") t.tp++;
    else if (r.verdict === "fp") t.fp++;
    else if (r.verdict === "unclear") t.unclear++;
    else t.open++;
    if (hinted(r)) t.hinted++;
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
