// labelpanel.ts is the finding page's label panel, the one bordered card on the page (UI-RULES 6):
// the label on file, the agent's hint and cause each in their own card with their own Accept
// (UI-RULES: a hint never looks like a choice already made), then TP / FP / Unclear, the reason, a
// note, Save and Skip, the "go to the next match" switch, and research.
import type { StateCause, claimsv1 } from "../gen/wire";
import { provenance, researchLine } from "../shared/agent";
import { el } from "../shared/dom";
import { direction, isResearched } from "../shared/rows";
import { dots, justWords, labels, ruleWords } from "../shared/words";
import type { FindingData } from "./finding-data";
import { meaning, mutedReason, panel, reasons, seenWith, shortSource } from "./finding-words";
import { kbd, verdict, type Verdict } from "./ui";

// Draft is the form as typed, kept across a repaint (research polling redraws the page)
export interface Draft { verdict?: string; reason?: string; note: string }

export interface PanelActions {
  save: () => void;
  accept: () => void;               // the row's own hint, else this row of its cause
  acceptAll: (c: StateCause) => void;
  skip: () => void;
  research: () => void;
  advance: (on: boolean) => void;
}

export interface LabelPanel {
  el: HTMLElement;
  pick: (v: string) => void;        // t, f and u
  focusReason: () => void;
}

const words: Record<string, string> = { tp: "TP", fp: "FP", unclear: "Unclear" };
const date = (s: string | undefined) => (s ? new Date(s).toLocaleDateString() : "");
const reasonText = (d: FindingData, v: string, j: string | undefined) =>
  el("span", { class: `reason${mutedReason(j) ? " muted" : ""}`, "data-testid": "reason" }, j ? justWords(d.state, v, j) : "no reason");

export function labelPanel(d: FindingData, draft: Draft, advance: boolean, on: PanelActions): LabelPanel {
  const { row, detail, state } = d;
  const p = panel(row, state.causes);
  const lv = detail.label, l = lv?.label;
  if (p.onFile && !draft.verdict && l) Object.assign(draft, { verdict: l.verdict, reason: l.justification });

  // ---------- what's there already: the label on file, the hint, the cause ----------

  const onFile = p.onFile && l && el("section", { class: "onfile", "data-testid": "label-on-file", "data-verdict": l.verdict },
    el("h2", {}, "Label on file"),
    el("div", { class: "line" }, verdict(l.verdict as Verdict), reasonText(d, l.verdict, l.justification)),
    el("div", { class: "help" }, `${l.author || "?"} · ${date(l.lastUpdated)}`),
    lv.sources?.length ? el("div", { class: "help", title: lv.sources.join("\n"), "data-testid": "label-source" }, lv.sources.map(shortSource).join(", "), lv.global ? " · global" : "") : null,
    seenWith(l) ? el("div", { class: "help" }, `seen with ${seenWith(l)}`) : null);

  const h = p.hint ? row.hint! : null, full = detail.hint;
  const facts = (full?.proposal.evidence ?? []).flatMap((e) => e.facts ?? []);
  const factLink = (f: claimsv1.Fact) => (/^https?:\/\//.test(f.url ?? "") ? el("a", { href: f.url, target: "_blank", rel: "noopener noreferrer" }, f.source) : f.source);
  const hintCard = h && el("section", { class: "hintcard", "data-testid": "hint-card", "data-status": h.status, "data-verdict": h.verdict, "data-confidence": h.confidence ?? "" },
    el("div", { class: "top" }, el("span", { class: "hint" }, "Agent hint"), verdict(h.verdict as Verdict), el("span", { class: "help", "data-testid": "hint-confidence" }, `${h.confidence ?? ""} ${dots[h.confidence ?? ""] ?? ""}`)),
    el("p", { "data-testid": "hint-reason" }, h.title || justWords(state, h.verdict, h.justification) || ruleWords(h.rule) || full?.proposal.note || ""),
    (!!full?.proposal.note || facts.length > 0 || !!full?.policy.rule) && el("details", { class: "facts", "data-testid": "hint-facts" },
      el("summary", {}, [full?.proposal.note && "the note", facts.length > 0 && `${facts.length} ${facts.length === 1 ? "fact" : "facts"}`, full?.policy.rule && "the rule"].filter(Boolean).join(", ").replace(/^./, (c) => c.toUpperCase())),
      full?.proposal.note && el("p", { "data-testid": "hint-note" }, full.proposal.note),
      facts.length > 0 && el("ul", {}, facts.map((f) => el("li", {}, el("span", { class: "src" }, factLink(f)), " ", el("code", {}, f.field), " ", f.value))),
      full?.policy.rule && el("p", { class: "help" }, `rule: ${full.policy.rule.basis || ruleWords(full.policy.rule.rule)}${full.policy.rule.decision ? ` · policy ${full.policy.rule.decision}` : ""}${full.policy.problems?.length ? ` · ⚠ ${full.policy.problems.join("; ")}` : ""}`)),
    el("div", { class: "by", title: [h.model && `model ${h.model}`, h.researchJob && `research job ${h.researchJob}`].filter(Boolean).join(" · ") },
      provenance(h).replace(/^✦ /, ""), h.written ? ` · ${date(h.written)}` : "", isResearched(row) ? el("span", { class: "researched", "data-testid": "researched-mark" }, " · ✦ researched") : null),
    el("button", { type: "button", class: "btn", "data-testid": "accept-hint", onclick: on.accept }, "Accept hint ", kbd("a")));

  const c = p.cause;
  const causeCard = c && el("section", { class: "hintcard", "data-testid": "cause-card", "data-count": c.pending.length, "data-verdict": c.verdict },
    el("div", { class: "top" }, el("span", { class: "hint" }, "Package hint"), verdict(c.verdict as Verdict), c.confidence && el("span", { class: "help" }, `${c.confidence} ${dots[c.confidence] ?? ""}`)),
    el("p", {}, c.title),
    el("div", { class: "by" }, `${c.author.skill || c.author.name || "an agent"} · on ${c.sourcePackage} · ${c.pending.length} unlabeled ${c.pending.length === 1 ? "match" : "matches"}`),
    el("div", { class: "acts" },
      el("button", { type: "button", class: "btn", "data-variant": h ? "outline" : null, "data-testid": "accept-all", "data-count": c.pending.length, onclick: () => on.acceptAll(c) }, `Accept for all ${c.pending.length} `, kbd("A")),
      !h && el("button", { type: "button", class: "btn", "data-variant": "outline", "data-testid": "accept-hint", onclick: on.accept }, "This one ", kbd("a"))));

  // ---------- the form ----------

  const segs = (["tp", "fp", "unclear"] as const).map((v, i) => el("button", {
    type: "button", class: v, "aria-pressed": String(draft.verdict === v), "data-testid": "verdict-button", "data-verdict": v, title: labels[v].long,
    onclick: () => pick(v),
  }, words[v], el("small", {}, "tfu"[i])));
  const reason = el("select", { class: "select", id: "reason", "data-testid": "reason-picker", onchange: () => { draft.reason = reason.value || undefined; } });
  const note = el("input", { class: "input", id: "note", type: "text", "data-testid": "note-input", value: draft.note, placeholder: p.onFile ? "Why it changed (a newer label wins)" : "Optional",
    oninput: () => { draft.note = note.value; },
    onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); note.blur(); on.save(); } } });
  // one primary button per screen (UI-RULES 7): Save when no agent card holds Accept
  const save = el("button", { type: "button", class: "btn", "data-variant": h || c ? "outline" : null, "data-testid": "save-label", onclick: on.save }, advance ? "Save and next" : "Save");

  function fillReasons() {
    const v = draft.verdict;
    const opts = v ? reasons(state.vocabulary, v, p.onFile && l?.verdict === v ? l.justification : undefined) : [];
    if (draft.reason && !opts.some(([j]) => j === draft.reason)) draft.reason = undefined;
    reason.replaceChildren(
      el("option", { value: "" }, !v ? "Pick TP, FP or Unclear first" : v === "tp" ? "No reason (optional for TP)" : "Choose a reason…"),
      ...opts.map(([j, desc]) => el("option", { value: j, selected: j === draft.reason, title: j, "data-testid": "reason-option" }, desc)));
    reason.disabled = !v || opts.length === 0;
  }
  function pick(v: string) {
    draft.verdict = v;
    for (const b of segs) b.setAttribute("aria-pressed", String(b.dataset.verdict === v));
    fillReasons();
  }
  fillReasons();

  const dir = direction(row);
  const off = state.research && !state.research.available ? state.research : null;
  const line = researchLine(row);
  const root = el("aside", { class: "lpanel", "data-testid": "label-panel", "data-row": row.id, "data-verdict": row.verdict },
    onFile, hintCard, causeCard,
    el("h2", { class: p.onFile || h || c ? "rule" : null }, p.heading),
    el("div", { class: "segv", role: "group", "aria-label": "Verdict" }, segs),
    meaning[dir] && el("p", { class: "help", "data-testid": "label-meaning" }, meaning[dir]),
    el("label", { class: "field" }, "Reason", reason),
    el("label", { class: "field" }, "Note", note),
    el("div", { class: "acts" }, save, el("button", { type: "button", class: "btn", "data-variant": "outline", "data-testid": "skip-button", onclick: on.skip }, "Skip ", kbd("j"))),
    el("label", { class: "advance", "data-testid": "advance-toggle", title: "kept in this browser" },
      el("input", { type: "checkbox", "data-testid": "advance-checkbox", checked: advance, onchange: (e: Event) => {
        const t = e.target as HTMLInputElement;
        on.advance(t.checked);
        save.textContent = t.checked ? "Save and next" : "Save";
        t.blur();
      } }), " after labeling, go to the next match"),
    el("div", { class: "research", "data-testid": "research-foot" },
      line ? el("span", { "data-testid": "research-status", "data-state": row.research?.status }, line) : null,
      el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", "data-testid": "research-button", "data-researched": isResearched(row), disabled: !!off, onclick: on.research,
        title: off ? `research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}` : "an agent researches this match and leaves a hint" },
      isResearched(row) ? "Research again " : "Research ", kbd("R"))));

  return { el: root, pick, focusReason: () => { if (!reason.disabled) reason.focus(); } };
}

