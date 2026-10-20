// rows.ts reads one /state row: which side reported it, its package, whether it is still open, and
// how far an agent has looked at it. Pure: no DOM, no page state.
import type { HintSummary, StateRow } from "../gen/wire";

export type Row = StateRow;
export type Dir = "added" | "dropped" | "both" | "neither";

export function direction(r: Row): Dir {
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
export const isOpen = (r: Row) => r.verdict === "unlabeled" || r.verdict === "unclear";
export const hinted = (r: Row): r is Row & { hint: HintSummary } => r.hint?.status === "pending" && isOpen(r);
export const decisive = (r: Row) => !!r.gate?.couldFlip?.length;
export const bears = (r: Row) => !!r.gate?.bears?.length;
export const srcPkg = (r: Row) => r.sourcePackage || pkgOf(r.package.ref).name;
export const matchName = (r: Row) => `${r.vulnerability} ${pkgOf(r.package.ref).name}`;

// isResearched is the one place that decides whether a match counts as researched: the server's
// row.researched, true when research-vuln output exists for it, however it was started (label UI,
// `delta research`, a hand-run session): a research-vuln hint or a finished research job, with or
// without a hint. A triage-deltas hint alone is the middle level (Will, 2026-10-13).
export const isResearched = (r: Row) => !!r.researched;

// researchLevel is "" (no agent hint, no research-vuln output), "triaged" (a triage-deltas hint, no
// research-vuln output) or "researched". The tile shows only "researched": next to the hint chip
// "triaged" is redundant; Map's lists, which hide the hints, show both.
export const researchLevel = (r: Row) => (isResearched(r) ? "researched" : r.researchLevel || "");
