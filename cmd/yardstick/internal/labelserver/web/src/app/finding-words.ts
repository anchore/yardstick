// finding-words.ts is what the finding page says and decides from its data: the effect in the title
// row, the direction, a claims source's short name, the tools a label was seen with, the reasons a
// verdict offers, and which parts the label panel shows. Pure: no DOM, no page state.
import type { CheckResult, StateCause, StateRow, Vocabulary, claimsv1 } from "../gen/wire";
import { hinted, isOpen } from "../shared/rows";

export interface Effect { kind: "decides" | "could-move"; text: string }

// effect is the title row's line on what this finding's label does. On a check route the check's
// own findings list says (decides, could-move or counted); off it, the gate's result does: checks
// failing on a labeled row, and checks a label on an open row could flip.
export function effect(o: { check: string | null; checkEffect?: string; row: StateRow; checks: CheckResult[] }): Effect | null {
  if (o.check && o.checkEffect) {
    if (o.checkEffect === "decides") return { kind: "decides", text: `this label decides ${o.check}` };
    if (o.checkEffect === "could-move") return { kind: "could-move", text: `labeling this can flip ${o.check}` };
    return null;
  }
  const decides = o.checks.filter((c) => c.failsOn?.includes(o.row.id)).map((c) => c.name);
  if (decides.length && !isOpen(o.row)) return { kind: "decides", text: `this label decides ${decides.join(", ")}` };
  const flips = o.row.gate?.couldFlip ?? [];
  if (flips.length) return { kind: "could-move", text: `labeling this can flip ${flips.join(", ")}` };
  return null;
}

export type Dir = "added" | "dropped" | "both" | "neither";

export const directionWords: Record<Dir, string> = { added: "+ added by candidate", dropped: "− dropped by candidate", both: "= in both scans", neither: "in neither scan" };

// meaning is what a TP and an FP label say about the candidate, by direction (the glossary's
// fixed / introduced table); a match both or neither scan reports has none
export const meaning: Partial<Record<Dir, string>> = {
  added: "TP: the candidate fixed a false negative. FP: it introduced a false positive.",
  dropped: "TP: the candidate introduced a false negative. FP: it fixed a false positive.",
};

// shortSource is a claims source as people say it: the corpus's last path segment and its ref,
// e.g. "github.com/anchore/match-claims@main" → "match-claims@main", "/ws/claims" → "claims".
// The server also appends ": <verdict>" to the sources it lists; that goes.
// ponytail: an ssh locator (git@host:org/repo) reads as "git@…"; nothing serves one yet
export function shortSource(s: string): string {
  const [loc, ...ref] = s.replace(/: (tp|fp|unclear)$/, "").replace(/^[a-z+]+:\/\//, "").split("@");
  const base = loc.replace(/\/+$/, "").split("/").pop()!.replace(/\.git$/, "");
  return ref.length ? `${base}@${ref.join("@")}` : base;
}

// seenWith is the tools a label was written against, e.g. "grype v0.116.1, syft v1.14.0"; the
// grype DB's version is a checksum, so it's left out
export const seenWith = (l: claimsv1.Label | undefined) =>
  (l?.seenIn?.tools ?? []).filter((t) => t.name !== "grype-db").map((t) => `${t.name} ${t.version}`).join(", ");

// reasons is the reason picker's options for a verdict, from the vocabulary, sorted; a reason on
// file that the vocabulary lacks (not-recorded, from a port) is kept so a relabel can keep it
export function reasons(v: Vocabulary | undefined, verdict: string, current?: string): [string, string][] {
  const out = Object.entries(v?.justifications?.[verdict] ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (current && !out.some(([j]) => j === current)) out.unshift([current, current]);
  return out;
}

// muted says a reason is the default nobody chose, which most ported labels carry
export const mutedReason = (j: string | undefined) => !j || j === "not-recorded";

// pendingCause is the agent cause listing this row as a pending member, if any
export const pendingCause = (causes: StateCause[] | undefined, row: string) => (causes ?? []).find((c) => c.pending.includes(row));

export interface Panel {
  onFile: boolean;           // a label is on file: show it, and offer a relabel
  hint: boolean;             // the row's own agent hint is pending: its card and Accept
  cause: StateCause | null;  // an agent cause the row is pending in: its card and accept for all
  heading: string;           // the line over TP / FP / Unclear
}

// panel is which parts the label panel shows. Unclear is on file and still open, so an unclear
// row can show its label and a pending hint both.
export function panel(row: StateRow, causes: StateCause[] | undefined): Panel {
  const onFile = row.verdict !== "unlabeled", hint = hinted(row);
  const cause = isOpen(row) ? pendingCause(causes, row.id) ?? null : null;
  return { onFile, hint, cause, heading: onFile ? "Relabel" : hint || cause ? "Or label it yourself" : "Label" };
}
