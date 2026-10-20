// words.ts is how the pages say things: label glyphs, directions, counts and numbers, and a
// row's computed reason in words. Pure: no DOM, no page state.
import type { Vocabulary, report } from "../gen/wire";

export interface LabelWords { glyph: string; word: string; long: string }
export const labels: Record<string, LabelWords> = {
  tp: { glyph: "●", word: "TP", long: "real match" },
  fp: { glyph: "○", word: "FP", long: "false match" },
  unclear: { glyph: "◐", word: "unclear", long: "unclear" },
  unlabeled: { glyph: "◌", word: "unlabeled", long: "unlabeled" },
};
export const dots: Record<string, string> = { high: "•••", medium: "••◦", low: "•◦◦" };
export const dirWords: Record<string, string> = { added: "the candidate added this", dropped: "the candidate dropped this", both: "both sides found this", neither: "neither side found this" };
export const sideWords: Record<string, string> = { added: "only in candidate", dropped: "only in reference", both: "in both scans", neither: "in neither scan" };

export const plural = (n: number, w: string, many = `${w}s`) => `${n} ${n === 1 ? w : many}`;
export const fmt = (x: number) => (Number.isInteger(x) ? String(x) : Math.abs(x) < 10 ? x.toFixed(3) : x.toFixed(1));
export const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, Math.max(1, Math.floor(n) - 1))}…` : s);

// whyTitle is a computed reason as a map node's title
export function whyTitle(w: report.Reason | undefined, dir: string): string {
  if (!w) return "no computed reason";
  const other = dir === "added" ? "reference" : "candidate";
  switch (w.key) {
    case "record/rejected-in-candidate": return "rejected in the candidate's DB";
    case "record/rejected-in-reference": return "rejected in the reference DB";
    case "record/absent-in-reference": return `new record${w.to ? ` in ${w.to}` : ""}`;
    case "record/absent-in-candidate": return `record gone${w.from ? ` from ${w.from}` : ""}`;
    case "package/absent-in-reference": return "vulnerability known, package newly affected";
    case "package/absent-in-candidate": return "vulnerability known, package no longer affected";
    case "namespace/changed": return `namespace ${w.from} → ${w.to}`;
    case "fix-state/changed": return `fix state ${w.from} → ${w.to}`;
    case "constraint/changed": return "version constraint changed";
    case "record/same-but-unmatched": return `same record in the ${other} DB, no match`;
    case "match-type/cpe-only": return "matched by CPE only";
    case "matcher/changed": return "matcher changed";
    case "unexplained": return "unexplained";
    default: return w.key;
  }
}

// whyText is a computed reason as the tile's sentence
export function whyText(w: report.Reason | undefined, dir: string): string {
  if (!w) return "";
  const other = dir === "added" ? "reference" : "candidate";
  switch (w.key) {
    case "record/rejected-in-candidate": return "the candidate's DB marks this vulnerability rejected";
    case "record/rejected-in-reference": return "the reference DB marks this vulnerability rejected";
    case "record/absent-in-reference": return `the reference DB has no record of this vulnerability under any alias${w.to ? `; the candidate's has one in ${w.to}` : ""}`;
    case "record/absent-in-candidate": return `the candidate's DB has no record of this vulnerability under any alias${w.from ? `; the reference's had one in ${w.from}` : ""}`;
    case "package/absent-in-reference": return "the reference DB knows the vulnerability but has no record for this package or its source package";
    case "package/absent-in-candidate": return "the candidate's DB knows the vulnerability but has no record for this package or its source package";
    case "namespace/changed": return `the other DB's record is in another namespace: ${w.from} → ${w.to}`;
    case "fix-state/changed": return `the fix state changed: ${w.from} → ${w.to}`;
    case "constraint/changed": return "the version constraint changed between the two DBs";
    case "record/same-but-unmatched": return `the ${other} DB has the same record and its grype still didn't match: a matcher or config difference`;
    case "match-type/cpe-only": return "the reporting side matched by CPE only";
    case "matcher/changed": return "the matcher changed";
    case "unexplained": return "unexplained by the data on the match";
    default: return w.key;
  }
}

// justWords is a justification's description from the claims vocabulary, else the value itself
export const justWords = (state: { vocabulary?: Vocabulary } | undefined, verdict: string | undefined, j: string | undefined) =>
  (j ? state?.vocabulary?.justifications?.[verdict ?? ""]?.[j] || j : "");
// ruleWords turns a rule id into words: "sbom/code-not-in-binary" → "sbom: code not in binary"
export const ruleWords = (rule: string | undefined) => (rule ? rule.replace("/", ": ").replace(/-/g, " ") : "");

// columnHelp is what each table column means, shown behind the "?" by its header. A line per
// value where the column has a fixed set of them.
export const columnHelp = {
  label: "The verdict on file for this match.\nTP: a real match, the package is affected\nFP: a false match\nunclear: looked at, can't tell; still open\nunlabeled: nobody has labeled it yet",
  outcome: "What the label makes this match for the candidate, from which scan reports it (hover a pill for the side).\nfixed FN: a TP only the candidate reports\nfixed FP: an FP only the reference reports\nnew FP: an FP only the candidate reports\nnew FN: a TP only the reference reports\nnew FP? / new FN?: still open, the risk a label settles",
  hint: "An agent's proposed label and its confidence (high, medium, low). Not on file until someone accepts it, on the finding or with Accept hints on selected rows.\nWith no hint, where research stands:\nResearch: an agent can look into this open match and leave a hint\nqueued / researching: a research job is waiting or running on it\nresearched, no hint: research finished without proposing a label\nfailed: the job failed; retry starts it again",
  crossHint: "An agent's proposed label and its confidence (high, medium, low). Not on file until someone accepts it.\npackage hint: an agent's finding about the whole package, covering this match and others like it\nWith no hint, where research stands:\nResearch: an agent can look into this open match and leave a hint\nqueued / researching: a research job is waiting or running on it\nresearched, no hint: research finished without proposing a label\nfailed: the job failed; retry starts it again",
  effect: "What a label on this match does to the check. On a gate's Findings tab, its strongest effect over every check.\ndecides: the check fails on this label\ncould move: open, and a TP or FP label alone changes the check's result\ncounted: the check counts it, but it doesn't change the result alone\n–: no check counts it",
  crossEffect: "What a label on this match does across gates.\ncould move in N gates: a TP or FP label alone changes a check's result in that many gates\nbears on N gates: the label narrows where a check can land in that many gates, without changing a result alone",
  gates: "Every gate whose scans report this match; one label counts in all of them. The open question (new FP? or new FN?) shows once when every gate sees the same side, else on each gate's chip.",
  image: "The image the label applies to. global means every image with this package and vulnerability.",
  reason: "Why the verdict holds, from the claims vocabulary's justifications. A muted not-recorded means the label carries none, as most ported labels do.",
  source: "The claims source the label was read from: a repository at a ref, or a local directory. Hover a cell for the full locator.",
  note: "The label's notes. An accepted hint brings its agent's note along.",
  findings: "The findings this label sits on, a chip per gate (#2 when the package is in two places in one gate). none means no gate scans the match it labels.",
};
