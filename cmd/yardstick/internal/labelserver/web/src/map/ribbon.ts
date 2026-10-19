// ribbon.ts draws the gate: its outcome and a range bar per check, worst → best against the
// threshold, with a dashed ghost where a hovered accept would move the bar.
import type { CheckResult } from "../gen/wire";
import { el, fill, must, svg } from "../shared/dom";
import { bar, barLayout, noResult } from "../shared/gate";
import { fmt, plural } from "../shared/words";
import { diffRows, tally, unchanged } from "./data";
import { navigate } from "./nav";
import { st, ui } from "./state";

export function renderGate() {
  const s = st(), g = s.gate, box = must("#gate");
  const t = tally(diffRows(s, null));
  if (!g?.result) {
    fill(box, el("span", { class: "band band-undecided", "data-testid": "gate-outcome", "data-state": "undecided", title: g?.note || "" }, noResult(g)),
      g?.note ? el("span", { class: "muted" }, g.note) : null,
      el("span", { class: "summary", "data-testid": "gate-summary" }, `${plural(t.n, "delta")} · ${t.open} unlabeled · ${t.hinted} with an agent hint`));
    return;
  }
  const res = g.result, same = unchanged(s);
  if (same) {
    fill(box, el("span", { class: "band band-pass", "data-testid": "gate-outcome", "data-state": "pass" }, "✓ no differences"),
      el("span", { class: "summary", "data-testid": "gate-summary" }, `gate ${g.name} · both sides report the same ${plural(same.shared, "match", "matches")} in ${plural(same.images, "image")}: nothing to label`));
    return;
  }
  const onBoard = !ui.delta && !ui.cards;
  // The board and the delta map are two views of the gate: this switches between them. On a match
  // the breadcrumb is the one way back (Esc too), so the switch isn't offered there.
  const p = ui.preview;
  const count = (state: string) => res.checks.filter((c) => c.state === state).length;
  fill(box, 
    el("span", { class: `band band-${res.outcome}`, "data-testid": "gate-outcome", "data-state": res.outcome }, res.outcome),
    el("span", { class: "summary", "data-testid": "gate-summary" }, `gate ${g.name} · ${res.ci === res.outcome ? "" : `CI reads it as ${res.ci} · `}${plural(res.checks.length, "check")}: ${count("pass")} pass, ${count("fail")} fail, ${count("undecided")} undecided`),
    ui.cards ? null : el("button", { class: "ghost", "data-testid": "gate-view-toggle", "data-goes-to": onBoard ? "map" : "board", onclick: () => navigate({ delta: onBoard, zoom: null, cardsSpec: null, selected: null, evidence: false }) }, onBoard ? "scan delta map" : "gate board"),
    ...(onBoard ? [] : res.checks.map((c) => gateBar(c))),
    // while an accept is hovered, the last line says what the dashed ghosts are, in the same place,
    // so the ribbon keeps its height and the hovered control doesn't move
    p ? el("span", { class: "summary preview-note", "data-testid": "preview-note" }, p.result ? `dashed: where the bars would be if ${p.what} were accepted${p.result.outcome !== res.outcome ? ` · the gate would be ${p.result.outcome}` : ""}` : `working out where ${p.what} would move the bars…`)
      : el("span", { class: "summary", "data-testid": "gate-footer" }, res.outcome === "undecided" ? `◆ ${plural(t.decisive, "delta")} could change the verdict` : `${t.open} unlabeled of ${t.n}`),
  );
}

// gateBar draws one check: its name and state over a bar of where its value can still land (worst
// to best case for the candidate, until the open deltas are labeled) against the threshold line.
// Both marks say what they are on the bar itself. With ui.preview (hovering an accept control),
// a dashed ghost range shows where the bar would move if those agent hints were accepted.
export function gateBar(c: CheckResult, { head = true } = {}) {
  const ghost = ui.preview?.result?.checks.find((k) => k.name === c.name);
  const b = barLayout(c, ghost);
  const { W, H, L, R, Y } = bar;
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}` },
    svg("line", { x1: L, x2: W - R, y1: Y + 5, y2: Y + 5, class: "axis" }),
    svg("rect", { x: b.range.x, y: Y, width: b.range.width, height: 10, rx: 3, class: "range" },
      svg("title", {}, `${c.valueMeans}: ${fmt(c.value.worst)} in the worst case … ${fmt(c.value.best)} in the best case for the candidate. Labeling the open deltas narrows it.`)),
    b.ghost ? svg("rect", { x: b.ghost.x, y: Y - 3, width: b.ghost.width, height: 16, rx: 3, class: "ghost-range", "data-testid": "preview-range", "data-check": c.name }) : null,
    svg("line", { x1: b.thrX, x2: b.thrX, y1: Y - 5, y2: Y + 15, class: "thr" }, svg("title", {}, b.thrText)),
    svg("text", { x: b.thrTextX, y: H - 1, "text-anchor": "middle", class: "side" }, b.thrText),
    svg("text", { x: b.rangeTextX, y: Y - 7, "text-anchor": "middle" }, b.rangeText),
  );
  // a preview that changes the check's state says so: in the head, or (on a board panel, whose head
  // is elsewhere) after the range, so the panel doesn't grow under the hovered control
  const to = b.flips && ghost ? ghost.state : null;
  if (to && !head && s.lastChild) s.lastChild.textContent += `  → ${to}`;
  const state = to ? [el("span", { class: "st", "data-testid": "check-state" }, c.state), el("span", { class: `st to ${to}`, "data-testid": "preview-flip", "data-state": to }, ` → ${to}`)] : el("span", { class: "st", "data-testid": "check-state" }, c.state);
  return el("div", { class: `gcheck ${c.state}${b.ghost ? " previewing" : ""}`, title: c.description, "data-testid": head ? "check-bar" : "panel-bar", "data-check": c.name, "data-state": c.state, "data-worst": c.value.worst, "data-best": c.value.best, "data-threshold": c.threshold },
    head ? el("div", { class: "nm" }, c.name, " ", state) : null, s);
}
