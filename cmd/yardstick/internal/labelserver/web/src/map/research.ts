// research.ts is research on a selection of the gate's matches, and the "✦ researched" and
// "✦ triaged" marks for how far an agent has looked at a match.
//
// Two targeted selections, never "everything" (Will, 2026-10-13; docs/decisions.md, Agents 5): the
// server resolves them to unlabeled matches that research-vuln hasn't been run on, with no research
// queued or running; "with no agent hint" takes only those with no hint at all, "that could move a
// check" also takes the triaged ones. A dry run counts them for the control's text. A click starts
// research at once (the next researchBatch of them); the status stays, with cancel, while any of it
// runs.
import * as api from "../shared/api";
import { provenance } from "../shared/agent";
import { el, toast } from "../shared/dom";
import { isResearched, matchName, researchLevel, type Row } from "../shared/rows";
import { plural } from "../shared/words";
import { allRows, subjectName } from "./data";
import { load, render } from "./render";
import { gate, st, ui } from "./state";

const researchBatch = 20;
const selections = [
  { select: "could-move-check", words: "that could move a check" },
  { select: "no-hint", words: "with no agent hint" },
];
export const researchScope = () => (ui.si == null ? "" : st().scans.subjects?.[ui.si]?.slug || "");

// countForResearch asks the server, as a dry run, how many matches each selection takes in scope
export async function countForResearch() {
  if (!ui.state?.researchConcurrency) { ui.research = null; return; }
  const scope = researchScope(), counts: Record<string, number> = {};
  ui.research = { ...ui.research, scope, counts: ui.research?.scope === scope ? ui.research.counts : null };
  await Promise.all(selections.map(async ({ select }) => {
    try {
      const res = await api.research(gate(), { select, ...(scope ? { subject: scope } : {}), dryRun: true });
      counts[select] = res.matches;
    } catch { counts[select] = 0; } // e.g. a gate with no checks: nothing could move one
  }));
  if (researchScope() !== scope) return; // the scope changed meanwhile: its own count is coming
  ui.research = { ...ui.research, scope, counts };
  for (const n of document.querySelectorAll(".research-ctl")) n.replaceWith(researchControls());
}

// activeResearch is the matches in scope with research queued or running
export const activeResearch = () => allRows(st(), ui.si).filter((x) => ["queued", "running"].includes(x.r.research?.status ?? ""));

// researchOff is why research cannot start here (the yardstick plugin missing or at another
// version, or claude not on PATH), with the command to copy; null while it can
export const researchOff = () => (ui.state?.research && !ui.state.research.available ? ui.state.research : null);

export function researchControls() {
  const box = el("span", { class: "research-ctl", "data-testid": "research-controls" });
  const off = researchOff();
  if (off) {
    const command = off.command;
    box.append(el("span", { class: "research-off", "data-testid": "research-off", title: off.reason }, `⚠ research disabled: ${off.reason}`,
      command ? [" ", el("code", {}, command), " ", el("button", { class: "ghost", "data-testid": "research-copy", title: "copy the command", onclick: () => navigator.clipboard?.writeText(command).then(() => toast("copied"), () => toast(command)) }, "copy")] : null));
    return box;
  }
  const s = st();
  if (!s.researchConcurrency) return box;
  const active = activeResearch(), started = ui.research?.started;
  if (active.length) {
    const cancellable = active.filter((x) => x.r.research?.cancellable);
    box.append(el("span", { class: "researching", "data-testid": "research-running", "data-count": active.length, title: `${plural(new Set(active.map((x) => x.r.research?.job)).size, "research run")} queued or running, ${s.researchConcurrency} at a time; agent hints arrive as they finish` },
      `⧗ researching ${plural(active.length, "match", "matches")}`,
      cancellable.length ? [" ", el("button", { class: "ghost", "data-testid": "research-cancel", title: "cancel the research queued or running here", onclick: () => cancelResearch(cancellable.map((x) => x.r.id)) }, "✕ cancel")] : null));
  } else if (started) {
    box.append(el("span", { class: "researching done", "data-testid": "research-finished", "data-cancelled": !!started.cancelled, "data-count": started.matches, title: "agent hints are on the matches; this note stays until you dismiss it" },
      started.cancelled ? `research cancelled · ${plural(started.matches, "match", "matches")} asked for` : `✦ research finished on ${plural(started.matches, "match", "matches")}`,
      " ", el("button", { class: "ghost", "data-testid": "research-dismiss", title: "dismiss", onclick: () => { if (ui.research) ui.research.started = null; render(); } }, "✕")));
  }
  const counts = ui.research?.scope === researchScope() ? ui.research.counts : null;
  for (const { select, words } of selections) {
    const n = counts?.[select];
    if (n == null) continue;
    if (!n) { box.append(el("span", { class: "muted", "data-testid": "research-none", "data-select": select, title: "unlabeled matches that research-vuln hasn't been run on (researched ones are left out), with no research queued or running" }, `no match ${words} is left to research`)); continue; }
    const take = Math.min(n, researchBatch);
    box.append(el("button", { class: "ghost research", "data-testid": "research-select", "data-select": select, "data-count": n, "data-take": take, onclick: () => startResearch(select, take),
      title: `${take < n ? `the first ${take} of ${n}${select === "could-move-check" ? ", those that could flip a check first" : ""}` : `all ${n}`}${ui.si == null ? " in every image" : ` in ${subjectName(s, ui.si)}`}; unlabeled matches research-vuln hasn't been run on yet (already researched ones are left out). ${s.researchConcurrency} at a time; each costs tokens.` },
      `research ${take < n ? `${take} of ${n}` : n} ${n === 1 ? "match" : "matches"} ${words}`));
  }
  return box;
}

async function startResearch(select: string, limit: number) {
  const scope = researchScope();
  try {
    const res = await api.research(gate(), { select, limit, ...(scope ? { subject: scope } : {}) });
    ui.research = { scope: "", counts: null, ...ui.research, started: { matches: res.matches, jobs: res.jobs } };
  } catch (e) { return toast((e as Error).message, true); }
  await load();
}
async function cancelResearch(rows: string[]) {
  try {
    await api.cancelResearch(gate(), rows);
    if (ui.research?.started) ui.research.started.cancelled = true;
  } catch (e) { return toast((e as Error).message, true); }
  setTimeout(() => load(), 400); // let the jobs record it
}

// researchedText is a match's provenance, for a tooltip: which level, who had its say, who asked
function researchedText(r: Row) {
  const head = matchName(r);
  if (!r.hint) return `${head}: ✦ researched, no hint${r.researchedBy?.length ? ` (${r.researchedBy.join(", ")})` : ""}`;
  const h = r.hint, extra = [h.model, h.researchJob ? `research ${h.researchJob}` : ""].filter(Boolean).join(" · ");
  return `${head}: ${provenance(h)}${extra ? ` (${extra})` : ""}`;
}

// researchedMark is the neutral "✦ researched" / "✦ triaged" mark for a list of matches (one or
// many), or null when no agent has looked at any of them. Three levels (Will, 2026-10-13): none,
// triaged (a triage-deltas hint, no research-vuln output) and researched (research-vuln output
// exists, from any source); a match shows only its highest level.
export function researchedMark(rows: Row[]) {
  const done = rows.filter(isResearched), triaged = rows.filter((r) => !isResearched(r) && researchLevel(r) === "triaged");
  if (!done.length && !triaged.length) return null;
  const noHint = done.every((r) => !r.hint);
  const parts = [];
  if (done.length) parts.push(done.length < rows.length ? `✦ ${done.length} of ${rows.length} researched` : noHint ? "✦ researched, no hint" : "✦ researched");
  if (triaged.length) parts.push(triaged.length < rows.length ? `✦ ${triaged.length} of ${rows.length} triaged` : "✦ triaged");
  const shown = [...done, ...triaged];
  const title = shown.slice(0, 8).map(researchedText).join("\n") + (shown.length > 8 ? `\n… and ${shown.length - 8} more` : "");
  return el("span", { class: "researched", "data-testid": "researched-mark", "data-researched": done.length, "data-triaged": triaged.length, "data-total": rows.length, title }, parts.join(" · "));
}
