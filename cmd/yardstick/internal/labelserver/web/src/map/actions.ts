// actions.ts is what the map's buttons and keys do: write labels, accept agent hints, start research,
// and move between the cards of the open group.
import type { StateCause } from "../gen/wire";
import * as api from "../shared/api";
import { $, toast } from "../shared/dom";
import { bears, decisive, hinted, isOpen, type Row } from "../shared/rows";
import { autoAdvance } from "../shared/tile";
import { labels, plural } from "../shared/words";
import { replaceURL, select } from "./nav";
import { load } from "./render";
import { researchOff } from "./research";
import { gate, ui } from "./state";
import { renderTile } from "./tileview";

// label writes a verdict; FP and unclear need a justification from the vocabulary, picked on the
// tile (without one, the picker takes focus)
export async function label(verdict: string, rows: string[], justification = "") {
  if (!rows.length) return toast("no match selected");
  if (verdict !== "tp" && !justification) {
    $("#justification")?.focus();
    return toast(`${labels[verdict].word} needs a reason: pick one under the buttons`);
  }
  try {
    const res = await api.labels(gate(), { rows, verdict, justification, note: ui.note, scope: "subject" });
    const l = labels[verdict];
    await afterWrite(rows, `${l.glyph} ${l.word}${res.overridden?.length ? " · overrides the agent hint" : ""}`);
  } catch (e) {
    toast((e as Error).message, true);
  }
}
export async function acceptRows(ids: string[]) {
  const byId = new Map(ui.rows.map((x) => [x.r.id, x.r]));
  const rows = ids.filter((id) => { const r = byId.get(id); return !!r && hinted(r); });
  if (!rows.length) return toast("no agent hint to accept here");
  const v = byId.get(rows[0])?.hint?.verdict ?? "";
  try {
    const res = await api.accept(gate(), rows);
    await afterWrite(rows, `${labels[v].glyph} ${labels[v].word}, the ✦ agent hint accepted${res.written > 1 ? ` on ${plural(res.written, "match", "matches")}` : ""}`);
  } catch (e) {
    toast((e as Error).message, true);
  }
}
// acceptIds accepts the agent hints on rows of a board group
export async function acceptIds(rows: string[]) {
  if (!rows.length) return toast("no agent hint to accept there");
  try {
    const res = await api.accept(gate(), rows);
    const text = `✦ ${plural(res.written, "agent hint")} accepted as your labels`;
    if (ui.cards) await afterWrite(rows, text); else { toast(text); await load(); }
  } catch (e) { toast((e as Error).message, true); }
}
// acceptCause accepts a package hint for the given member rows
export async function acceptCause(cause: StateCause, ids: string[]) {
  const rows = ids.filter((id) => cause.pending.includes(id));
  if (!rows.length) return toast("no agent hint to accept in that group");
  try {
    const res = await api.acceptCause(gate(), cause.id, rows);
    const text = `${labels[cause.verdict].glyph} ${labels[cause.verdict].word}, the ✦ package hint accepted on ${plural(res.written ?? rows.length, "match", "matches")}`;
    if (ui.cards) await afterWrite(rows, text); else { toast(text); await load(); }
  } catch (e) { toast((e as Error).message, true); }
}
export async function research(rows: string[]) {
  const off = researchOff();
  if (off) return toast(`research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}`, true);
  try { await api.research(gate(), { rows }); toast("research started; what it finds arrives as an agent hint"); load(); } catch (e) { toast((e as Error).message, true); }
}

// afterWrite moves on to the next unlabeled match of the group (replacing the entry: the labeled
// one left the group, so back from its successor lands on the board, not on a dead stop), or stays
// on the labeled one when the reader turned the tile's "go to the next match" switch off. The
// tile's standing receipt bar says what happened, so there's no toast.
async function afterWrite(rows: string[], text: string) {
  const stay = !autoAdvance();
  ui.last = ui.selected;
  ui.note = ""; ui.why = false;
  const i = ui.rows.findIndex((x) => x.r.id === ui.selected);
  const todo = (x: { r: Row }) => !rows.includes(x.r.id) && (ui.cardsSpec?.kind === "fails" || isOpen(x.r));
  const next = ui.rows.slice(i + 1).find(todo) || ui.rows.slice(0, i).find(todo);
  ui.receipt = { text };
  ui.pin = stay ? ui.selected : null; // a labeled match leaves its group: keep it there to stay on it
  await load();
  if (!ui.cards) return;
  ui.selected = autoAdvance() ? (next?.r.id || null) : ui.selected;
  ui.evidence = false;
  replaceURL();
  renderTile();
}

export function moveCard(delta: 1 | -1) {
  if (!ui.cards || !ui.rows.length) return;
  const i = ui.rows.findIndex((x) => x.r.id === ui.selected);
  const j = Math.max(0, Math.min(ui.rows.length - 1, i + delta));
  if (j === i) return toast(delta > 0 ? "last one in this group" : "first one in this group");
  select(ui.rows[j].r.id, false);
}
export function nextDecisive() {
  if (!ui.cards) return toast("open a group first");
  const i = ui.rows.findIndex((x) => x.r.id === ui.selected);
  const ring = [...ui.rows.slice(i + 1), ...ui.rows.slice(0, i + 1)];
  const next = ring.find((x) => isOpen(x.r) && decisive(x.r)) || ring.find((x) => isOpen(x.r) && bears(x.r));
  if (!next) return toast("nothing here could change the verdict");
  select(next.r.id, false);
}
export const currentRow = () => ui.rows.find((x) => x.r.id === ui.selected) || null;
