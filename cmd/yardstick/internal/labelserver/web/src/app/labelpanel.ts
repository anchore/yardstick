// labelpanel.ts is the finding page's label panel, the one bordered card on the page (UI-RULES 6):
// the label on file, the agent's hint and cause each in their own card with their own Accept
// (UI-RULES: a hint never looks like a choice already made), then TP / FP / Unclear, the reason, a
// note, Save and Skip, and research. Whether Save goes on to the next match is a setting in the cog.
import type { Basis } from "../gen/research";
import type { StateCause, claimsv1 } from "../gen/wire";
import { doing, inFlight, jobHref, provenance, researchLine } from "../shared/agent";
import { html, nothing, render } from "lit-html";
import { el, fill, nodes, type Child } from "../shared/dom";
import { direction, isResearched, outcome, pkgOf } from "../shared/rows";
import { dots, justWords, labels, ruleWords } from "../shared/words";
import type { FindingData } from "./finding-data";
import { mutedReason, panel, reasons, seenWith, shortSource } from "./finding-words";
import { about, liveLog, money } from "./researchwords";
import { tick } from "./researchtable";
import type { GateLines } from "./queuewords";
import { kbd, verdict } from "./ui";

// Draft is the form as typed, kept across a repaint (research polling redraws the page)
export interface Draft { verdict?: claimsv1.Verdict; reason?: string; note: string }

export interface PanelActions {
  save: () => void;
  accept: () => void;               // the row's own hint, else this row of its cause
  acceptAll: (c: StateCause) => void;
  skip: () => void;
  research: () => void;
  cancelResearch: () => void;
}

export interface LabelPanel {
  el: HTMLElement;
  pick: (v: claimsv1.Verdict) => void; // t, f and u
  focusReason: () => void;
  advance: (on: boolean) => void;   // the cog's "go to the next match" changed: Save's words follow
  update: (d: FindingData, outcomes?: GateLines) => void;
}

const words: Record<string, string> = { tp: "TP", fp: "FP", unclear: "Unclear" };
const date = (s: string | undefined) => (s ? new Date(s).toLocaleDateString() : "");
const reasonText = (d: FindingData, v: claimsv1.Verdict, j: string | undefined) =>
  el("span", { class: `reason${mutedReason(j) ? " muted" : ""}`, "data-testid": "reason" }, j ? justWords(d.state, v, j) : "no reason");

// labelPanel builds the panel once for a row; update shows the row read again (after a write that
// stays, or while research runs) and keeps the form as it is, focus and caret included. outcomes,
// in the queue, says what each verdict does to the row's gates.
export function labelPanel(d0: FindingData, draft: Draft, advance: boolean, on: PanelActions, outcomes0?: GateLines): LabelPanel {
  let d = d0;

  // ---------- the form, built once ----------

  const segs = (["tp", "fp", "unclear"] as const).map((v, i) => el("button", {
    type: "button", class: v, "data-testid": "verdict-button", "data-verdict": v, title: labels[v].long,
    onclick: () => pick(v),
  }, words[v], kbd("tfu"[i])));
  const reason = el("select", { class: "select", id: "reason", "data-testid": "reason-picker", onchange: () => { draft.reason = reason.value || undefined; } });
  const note = el("input", { class: "input", id: "note", type: "text", "data-testid": "note-input", value: draft.note,
    oninput: () => { draft.note = note.value; },
    onkeydown: (e) => { if (e.key === "Enter") { e.preventDefault(); note.blur(); on.save(); } } });
  // one primary button per screen (UI-RULES 7): Save when no agent card holds Accept
  const save = el("button", { type: "button", class: "btn", "data-testid": "save-label", onclick: on.save }, advance ? "Save and next" : "Save");
  const skip = el("button", { type: "button", class: "btn", "data-variant": "outline", "data-testid": "skip-button", onclick: on.skip }, "Skip ", kbd("j"));
  const research = el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", "data-testid": "research-button", onclick: on.research });
  const root = el("aside", { class: "lpanel", "data-testid": "label-panel" });

  function fillReasons() {
    const v = draft.verdict, l = d.detail.label?.label;
    const opts = v ? reasons(d.state.vocabulary, v, panel(d.row, d.state.causes).onFile && l?.verdict === v ? l.justification : undefined) : [];
    if (draft.reason && !opts.some(([j]) => j === draft.reason)) draft.reason = undefined;
    reason.replaceChildren(
      el("option", { value: "" }, !v ? "Pick TP, FP or Unclear first" : v === "tp" ? "No reason (optional for TP)" : "Choose a reason…"),
      ...opts.map(([j, desc]) => el("option", { value: j, selected: j === draft.reason, title: j, "data-testid": "reason-option" }, desc)));
    reason.disabled = !v || opts.length === 0;
  }
  function pick(v: claimsv1.Verdict) {
    draft.verdict = v;
    for (const b of segs) b.setAttribute("aria-pressed", String(b.dataset.verdict === v));
    fillReasons();
  }

  // ---------- what's there already, drawn on every update: the label on file, the hint, the cause ----------

  function update(next: FindingData, outcomes?: GateLines) {
    d = next;
    const { row, detail, state } = d;
    const p = panel(row, state.causes);
    const lv = detail.label, l = lv?.label;
    if (p.onFile && !draft.verdict && l) Object.assign(draft, { verdict: l.verdict, reason: l.justification });

    const onFile = p.onFile && l && el("section", { class: "onfile", "data-testid": "label-on-file", "data-verdict": l.verdict },
      el("h2", {}, "Label on file"),
      el("div", { class: "line" }, verdict(l.verdict), reasonText(d, l.verdict, l.justification)),
      el("div", { class: "help" }, `${l.author || "?"} · ${date(l.lastUpdated)}`),
      lv.sources?.length ? el("div", { class: "help", title: lv.sources.join("\n"), "data-testid": "label-source" }, lv.sources.map(shortSource).join(", "), lv.global ? " · global" : "") : null,
      seenWith(l) ? el("div", { class: "help" }, `seen with ${seenWith(l)}`) : null);

    const h = p.hint ? row.hint! : null, full = detail.hint;
    const facts = (full?.proposal.evidence ?? []).flatMap((e) => e.facts ?? []);
    const factLink = (f: claimsv1.Fact) => (/^https?:\/\//.test(f.url ?? "") ? el("a", { href: f.url, target: "_blank", rel: "noopener noreferrer" }, f.source) : f.source);
    const hintCard = h && el("section", { class: "hintcard", "data-testid": "hint-card", "data-status": h.status, "data-verdict": h.verdict, "data-confidence": h.confidence ?? "" },
      el("div", { class: "top" }, el("span", { class: "hint" }, "Agent hint"), verdict(h.verdict), el("span", { class: "help", "data-testid": "hint-confidence" }, `${h.confidence ?? ""} ${dots[h.confidence ?? ""] ?? ""}`)),
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
      el("div", { class: "top" }, el("span", { class: "hint" }, "Package hint"), verdict(c.verdict), c.confidence && el("span", { class: "help" }, `${c.confidence} ${dots[c.confidence] ?? ""}`)),
      el("p", {}, c.title),
      el("div", { class: "by" }, `${c.author.skill || c.author.name || "an agent"} · on ${c.sourcePackage} · ${c.pending.length} unlabeled ${c.pending.length === 1 ? "match" : "matches"}`),
      el("div", { class: "acts" },
        el("button", { type: "button", class: "btn", "data-variant": h ? "outline" : null, "data-testid": "accept-all", "data-count": c.pending.length, onclick: () => on.acceptAll(c) }, `Accept for all ${c.pending.length} `, kbd("A")),
        !h && el("button", { type: "button", class: "btn", "data-variant": "outline", "data-testid": "accept-hint", onclick: on.accept }, "This one ", kbd("a"))));

    // the form keeps what's typed: only a value the draft changed (a save cleared it) is put back
    for (const b of segs) b.setAttribute("aria-pressed", String(draft.verdict === b.dataset.verdict));
    fillReasons();
    if (note.value !== draft.note) note.value = draft.note;
    note.placeholder = p.onFile ? "Why it changed (a newer label wins)" : "Optional";
    if (h || c) save.dataset.variant = "outline"; else delete save.dataset.variant;

    const off = state.research && !state.research.available ? state.research : null;
    const line = researchLine(row);
    const price = state.researchEstimate?.measured ? state.researchEstimate : null;
    research.dataset.researched = String(isResearched(row));
    research.disabled = !!off;
    research.title = off ? `research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}` : "an agent researches this match and leaves a hint";
    fill(research, isResearched(row) ? "Research again " : "Research ", price && el("span", { class: "costpill", "data-testid": "research-price" }, `~${money(price.mean)}`), " ", kbd("R"));

    root.dataset.row = row.id;
    root.dataset.verdict = row.verdict;
    // lit leaves the form's nodes where they are, since they are the same nodes each time
    render(html`${nodes(onFile, hintCard, causeCard)}<h2 class=${p.onFile || h || c ? "rule" : ""}>${p.heading}</h2><div class="segv" role="group" aria-label="Verdict">${segs}</div>${nodes(ifLines(direction(row), outcomes))}<label class="field">Reason${reason}</label><label class="field">Note${note}</label><div class="acts">${save}${skip}</div><div class="research" data-testid="research-foot">${nodes(line ? researchStatus(row, line, on.cancelResearch) : null)}${research}${off ? nothing : html`<span class="rnote quiet" data-testid="research-shares">${jobWords(d, price)}</span>`}</div>`, root);
  }

  update(d0, outcomes0);
  return { el: root, pick, update, focusReason: () => { if (!reason.disabled) reason.focus(); }, advance: (on) => { save.textContent = on ? "Save and next" : "Save"; } };
}


// researchStatus is the row's research line: while a job is queued or running, in the table cell's
// words and glyphs with the way to the job (and its log once it runs) and Cancel
function researchStatus(row: FindingData["row"], line: string, cancel: () => void) {
  const j = row.research!;
  if (!inFlight(j)) return el("span", { "data-testid": "research-status", "data-state": j.status }, line);
  const d = doing(j, { open: true, researched: false }), running = j.status === "running";
  if (running) tick();
  return el("span", { class: "rline" },
    el("span", { class: `rs ${running ? "run" : "q"}`, "data-testid": "research-status", "data-state": j.status }, `${d.word} `,
      el("small", running ? { "data-since": j.started } : {}, d.small), running && j.model && el("small", {}, ` · ${j.model[0].toUpperCase()}${j.model.slice(1)}`)),
    el("a", { class: "lk", href: jobHref(j.job), "data-testid": "research-job-link" }, "view job"),
    running && el("a", { class: "lk", href: `/api/research/${encodeURIComponent(j.job)}/log`, target: "_blank", rel: "noopener", title: liveLog }, "log"),
    j.cancellable && el("button", { type: "button", class: "lk", "data-testid": "research-cancel-row", onclick: cancel }, "cancel"));
}

// jobWords say what one research job on the row is: how long it takes, and the sibling packages
// that share it, so a click's reach is known before it is made
function jobWords(d: FindingData, price: Basis | null) {
  const shares = new Set(d.row.researchShares ?? []);
  const names = [...new Set(d.state.subjects.flatMap((s) => s.rows).filter((r) => shares.has(r.id)).map((r) => pkgOf(r.package.ref).name))];
  const time = price ? `, ${about(price.seconds)}` : "";
  return names.length ? `One job${time}, shared with ${names.join(", ")}.` : `One job${time}.`;
}

// ifLines is a line per verdict saying what it does, as quiet help text since the verdicts are the
// choice: what it makes the row (TP → new FN) and, in the queue, what it does to each gate
function ifLines(dir: string, gates: GateLines | undefined) {
  const side = dir === "added" || dir === "dropped", per = gates && "tp" in gates ? gates : null;
  if (!side && !gates) return null;
  return el("div", { class: "help if-label", "data-testid": "label-meaning" },
    (side || per) && (["tp", "fp"] as const).map((v) => el("div", { "data-testid": "verdict-outcome", "data-verdict": v },
      `${labels[v].word} → ${[side && outcome(dir, v)?.text, per?.[v]].filter(Boolean).join(" · ")}`)),
    gates && "none" in gates && el("div", {}, gates.none));
}
