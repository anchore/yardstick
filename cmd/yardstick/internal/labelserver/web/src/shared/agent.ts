// agent.ts is the tile's agent card: the agent hint on the row, open or already labeled, where it
// came from, and the row's research.
import type { HintSummary, StateCause } from "../gen/wire";
import { el } from "./dom";
import { isOpen, isResearched, type Row } from "./rows";
import type { TileCtx } from "./tile";
import { dots, justWords, labels, plural, ruleWords } from "./words";

const hintStatus: Record<string, string> = { accepted: "the label came from it", agrees: "the label agrees", disagrees: "⚠ the label disagrees" };

// provenance says where a hint came from: the skill, and who started the research that left it
const originWords: Record<string, string> = { "label-ui": "requested in the label UI", cli: "requested with yardstick", "research-job": "requester not recorded" };
export function provenance(h: HintSummary) {
  const skill = h.skill || "an agent";
  return `✦ ${skill}${h.origin && h.origin !== "skill-run" && originWords[h.origin] ? ` · ${originWords[h.origin]}` : ""}`;
}

// researchLine says where the row's newest research job is when the "✦ researched" mark doesn't
// already: running, failed, or done after the hint shown without leaving a new one
function researchLine(r: Row) {
  const j = r.research;
  if (!j) return "";
  if (j.status === "queued" || j.status === "running") return `⧗ research ${j.status}`;
  if (j.status === "cancelled") return "research cancelled";
  if (j.status !== "done") return `research ${j.status}${j.error ? `: ${j.error}` : ""}`;
  if (!r.hint) return "";
  const fresh = r.hint.written && j.started && new Date(r.hint.written) >= new Date(j.started);
  const when = j.finished ? ` ${new Date(j.finished).toLocaleDateString()}` : "";
  return fresh ? "" : `research${when} left no new agent hint; the one here is older`;
}

// agent is the agent hint for the row, open or already labeled, and the row's research. The
// verdict and confidence are the button that opens the hint's note, facts and rule (w).
export function agent(ctx: TileCtx, h: HintSummary | undefined, cause: StateCause | undefined) {
  const { r, on } = ctx, pending = h?.status === "pending" && isOpen(r);
  const line = researchLine(r);
  const off = ctx.state?.research && !ctx.state.research.available ? ctx.state.research : null;
  const foot = el("div", { class: "foot", "data-testid": "research-foot" }, line ? el("span", { "data-testid": "research-status", "data-state": r.research?.status }, line) : null, el("button", { class: "ghost", "data-testid": "research-button", "data-researched": isResearched(r), onclick: () => on.research([r.id]), disabled: !!off, title: off ? `research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}` : null }, isResearched(r) ? "research again" : "research"), el("kbd", {}, "R"));
  if (!h) {
    return el("div", { class: "agent none", "data-testid": "hint-card", "data-status": "none" }, isResearched(r) ? el("span", { class: "researched", "data-testid": "researched-mark" }, "✦ researched, no hint") : el("span", {}, "✦ no agent hint"), foot);
  }
  return el("div", { class: `agent${pending ? "" : " settled"}${ctx.why ? " open" : ""}`, "data-testid": "hint-card", "data-status": h.status, "data-verdict": h.verdict, "data-confidence": h.confidence ?? "", "data-open": !!ctx.why },
    el("h2", {}, "Agent hint"),
    el("div", { class: "head" },
      el("button", { class: "verdict", "data-testid": "hint-toggle", "aria-expanded": ctx.why ? "true" : "false", title: ctx.why ? "hide the note and facts (w)" : "show the note and facts (w)", onclick: () => on.toggleWhy() },
        el("span", { class: "star" }, "✦"), el("span", { class: `v-${h.verdict} big`, "data-testid": "hint-verdict", "aria-label": `${labels[h.verdict].word} hint` }, `${labels[h.verdict].glyph} ${labels[h.verdict].word}`),
        el("span", { class: "conf", "data-testid": "hint-confidence" }, `${h.confidence} ${dots[h.confidence ?? ""] || ""}`), el("span", { class: "caret" }, ctx.why ? "▾" : "▸")),
      el("span", { class: "reason", id: "hint-reason", "data-testid": "hint-reason", title: h.rule ? `rule ${h.rule}${h.decision ? ` · policy ${h.decision}` : ""}` : "" }, h.title || justWords(ctx.state, h.verdict, h.justification) || ruleWords(h.rule)),
      pending ? null : el("span", { class: `status ${h.status}`, "data-testid": "hint-status", "data-status": h.status }, hintStatus[h.status] || h.status)),
    el("div", { class: "from", title: [h.model ? `model ${h.model}` : "", h.researchJob ? `research job ${h.researchJob}` : ""].filter(Boolean).join(" · ") },
      el("span", { class: "skill", "data-testid": "hint-skill" }, provenance(h)),
      h.written ? el("span", {}, new Date(h.written).toLocaleDateString()) : null,
      isResearched(r) ? el("span", { class: "researched", "data-testid": "researched-mark" }, "✦ researched") : null),
    ctx.why ? el("div", { class: "note", id: "hint-note", "data-testid": "hint-note" }, "…") : null,
    ctx.why ? el("ul", { class: "facts", id: "hint-facts", "data-testid": "hint-facts" }) : null,
    ctx.why ? el("div", { class: "rule", id: "hint-rule", "data-testid": "hint-rule" }, h.rule ? `rule: ${ruleWords(h.rule)}${h.decision ? ` · policy ${h.decision}` : ""}` : "") : null,
    pending && cause ? el("div", { class: "group", "data-testid": "cause-offer", "data-count": cause.pending.length }, `✦ same reasoning on ${plural(cause.pending.length, "unlabeled match", "unlabeled matches")} (${cause.sourcePackage}): `, el("button", { class: "ghost", "data-testid": "accept-all", "data-count": cause.pending.length, "data-verdict": cause.verdict, onclick: () => on.acceptCause(cause) }, `accept all ${cause.pending.length} as ${labels[cause.verdict].glyph} ${labels[cause.verdict].word}`), " ", el("kbd", {}, "A")) : null,
    foot);
}
