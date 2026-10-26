// rows.ts reads one /state row: which side reported it, its package, whether it is still open, and
// how far an agent has looked at it. Pure: no DOM, no page state.
import type { Direction, HintSummary, RowVerdict, StateRow } from "../gen/wire";

export type Row = StateRow;
export function direction(r: Row): Direction {
  if (r.inCandidate && !r.inReference) return "added";
  if (!r.inCandidate && r.inReference) return "dropped";
  return r.inCandidate ? "both" : "neither";
}
// decoded is a purl or version as people read it, percent escapes undone (+, not %2B); a malformed
// escape leaves it as it is
export function decoded(s: string) {
  try { return decodeURIComponent(s); } catch { return s; }
}
export function pkgOf(ref: string | undefined) {
  const m = (ref || "").match(/^pkg:([^/]+)\/(?:.*\/)?([^@?#]+)(?:@([^?#]+))?/);
  return { type: m?.[1] || "", name: decoded(m?.[2] || ref || ""), version: decoded(m?.[3] || "") };
}
export const detail = (r: Row) => r.candidate || r.reference;
export const otherRecords = (r: Row) => (direction(r) === "added" ? r.referenceRecords : r.candidateRecords) || [];
// Outcome is what a changed row says about the candidate: fixed or new, FN or FP, from its label and
// which side reports it. An open row has no outcome yet, so it names the risk labeling settles: a
// match only the candidate reports might be a new FP, one only the reference reports a new FN.
export type OutcomeKind = "good" | "bad" | "open";
export interface Outcome { kind: OutcomeKind; text: string }
export function outcome(dir: string, verdict: string | undefined): Outcome | null {
  if (dir !== "added" && dir !== "dropped") return null;
  const added = dir === "added";
  if (verdict === "tp") return added ? { kind: "good", text: "fixed FN" } : { kind: "bad", text: "new FN" };
  if (verdict === "fp") return added ? { kind: "bad", text: "new FP" } : { kind: "good", text: "fixed FP" };
  return { kind: "open", text: added ? "new FP?" : "new FN?" };
}
// outcomeRank sorts regressions first, then fixes, then open rows, then rows with no outcome
export const outcomeRank = (o: Outcome | null) => (o ? ["bad", "good", "open"].indexOf(o.kind) : 3);
// open is a verdict that leaves a match open: unlabeled, or unclear (UI-RULES: open means both)
export const open = (v: RowVerdict) => v === "unlabeled" || v === "unclear";
export const isOpen = (r: Row) => open(r.verdict);
export const hinted = (r: Row): r is Row & { hint: HintSummary } => r.hint?.status === "pending" && isOpen(r);
export const srcPkg = (r: Row) => r.sourcePackage || pkgOf(r.package.ref).name;

// isResearched is the one place that decides whether a match counts as researched: the server's
// row.researched, true when research-vuln output exists for it, however it was started (label UI,
// `delta research`, a hand-run session): a research-vuln hint or a finished research job, with or
// without a hint. A triage-deltas hint alone is the middle level (Will, 2026-10-13).
export const isResearched = (r: Row) => !!r.researched;
