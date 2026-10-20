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
