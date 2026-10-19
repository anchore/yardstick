// gate.ts is the gate's math: what one label does to the outcome, and where a check's worst-to-best
// range and threshold land on its bar. Pure: no DOM, no page state.
import type { CheckResult, GateStatus, analysis } from "../gen/wire";
import type { Dir, Row } from "./rows";
import { fmt } from "./words";

// endsGate: one label on this row would change the gate's outcome now
export const endsGate = (outcome: analysis.State | undefined, r: Row) => !!r.gate && !!outcome && (r.gate.ifTP?.outcome !== outcome || r.gate.ifFP?.outcome !== outcome);

// regressionRisk: a dropped row while a check counting false negatives is open (one TP fails it)
export const regressionRisk = (checks: CheckResult[], dir: Dir) => dir === "dropped" && checks.some((c) => c.counts === "fn" && c.state === "undecided");

// noResult says why a gate has no result, which makes it undecided: it changed since it was
// scanned, so it needs re-scanning (with the command in note)
export const noResult = (g: GateStatus | undefined) => (g?.rerun ? "undecided · re-scan needed" : "undecided");

// the bar's frame: viewBox width and height, left and right margins, and the range's top
export const bar = { W: 260, H: 40, L: 4, R: 4, Y: 18 };

export interface BarLayout {
  range: { x: number; width: number };  // worst to best
  ghost: { x: number; width: number } | null;  // where the range would be under a preview
  thrX: number;
  rangeText: string;  // over the range, in drawn order: "worst 14 … 2 best" or "best 2 … 14 worst"
  rangeTextX: number;
  thrText: string;  // under the threshold line: what it is and which side passes
  thrTextX: number;
  flips: boolean;  // the preview changes the check's state
}

// barLayout places a check on its bar: the range from the worst case for the candidate to the
// best (until the open deltas are labeled) and the threshold, scaled to fit with some padding.
// With ghost (the check under a previewed accept), a moved range is drawn too.
export function barLayout(c: CheckResult, ghost?: CheckResult): BarLayout {
  const worst = c.value.worst, best = c.value.best, thr = c.threshold;
  const moved = !!ghost && (ghost.value.worst !== worst || ghost.value.best !== best);
  // the passing side is the check's direction (atLeast: right); without one, where "best" lies
  const passRight = c.direction ? c.direction === "atLeast" : best >= worst;
  const vals = [worst, best, thr, ...(moved && ghost ? [ghost.value.worst, ghost.value.best] : [])];
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const pad = (hi - lo || Math.max(Math.abs(thr), 1) * 0.5) * 0.3, min = lo - pad, max = hi + pad;
  const { W, L, R } = bar;
  const x = (v: number) => L + ((v - min) / (max - min)) * (W - L - R);
  const a = x(Math.min(worst, best)), b = x(Math.max(worst, best));
  const t = x(thr);
  // a label centered at x, kept inside the bar (cw: about a character's width at its size)
  const centered = (text: string, at: number, cw: number) => Math.max(L + (text.length * cw) / 2, Math.min(W - R - (text.length * cw) / 2, at));
  const worstLeft = x(worst) <= x(best);
  const ends: [string, number][] = worstLeft ? [["worst", worst], ["best", best]] : [["best", best], ["worst", worst]];
  const rangeText = worst === best ? `${fmt(worst)} (no unlabeled delta moves it)` : `${ends[0][0]} ${fmt(ends[0][1])} … ${fmt(ends[1][1])} ${ends[1][0]}`;
  const thrText = `threshold: pass if ${passRight ? "≥" : "≤"} ${fmt(thr)}`;
  let g: BarLayout["ghost"] = null;
  if (moved && ghost) {
    const ga = x(Math.min(ghost.value.worst, ghost.value.best)), gb = x(Math.max(ghost.value.worst, ghost.value.best));
    g = { x: ga, width: Math.max(3, gb - ga) };
  }
  return {
    range: { x: a, width: Math.max(3, b - a) },
    ghost: g,
    thrX: t,
    rangeText,
    rangeTextX: centered(rangeText, (a + b) / 2, 6),
    thrText,
    thrTextX: centered(thrText, t, 5.2),
    flips: moved && !!ghost && ghost.state !== c.state,
  };
}
