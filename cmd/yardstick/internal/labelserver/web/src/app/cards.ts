// cards.ts is the queue's cards, drawn in place of the finding: the gate boundary (a gate's last
// open row in the queue is labeled), the stopping point (every gate is decided, rows remain) and
// the end (nothing open in scope). The words are queuewords.ts's.
import type { QueueEntry, QueueGate } from "../gen/wire";
import { el, type Child } from "../shared/dom";
import { pkgOf } from "../shared/rows";
import { kbd, status, type State } from "./ui";

// outcomeRow is one gate's outcome, and where it came from when that changed
const outcomeRow = (gate: string, after: string, before?: string, extra?: Child) =>
  el("div", { class: "r", "data-testid": "card-gate", "data-gate": gate, "data-state": after },
    before && before !== after && [status(before as State), el("span", { class: "arrow", "aria-hidden": "true" }, "→")],
    status(after as State), el("span", {}, gate), extra && el("small", {}, extra));

const button = (text: Child, testid: string, primary: boolean, act: string | (() => void)) => typeof act === "string"
  ? el("a", { class: "btn", "data-variant": primary ? null : "outline", href: act, "data-testid": testid }, text)
  : el("button", { type: "button", class: "btn", "data-variant": primary ? null : "outline", "data-testid": testid, onclick: act }, text);

const card = (kind: string, label: string, ...body: Child[]) =>
  el("section", { class: "qcard", "data-testid": "queue-card", "data-card": kind }, el("span", { class: "lbl" }, label), body);

export interface CardActions { go?: () => void; back: string; history?: string }

// boundaryCard follows a gate's last open row in the queue: its outcome then and now, and the next gate
export function boundaryCard(o: { label: string; gate: string; before?: string; after: string; next: string; foot: string } & CardActions) {
  return card("boundary", o.label,
    el("div", { class: "outc" }, outcomeRow(o.gate, o.after, o.before)),
    el("p", { class: "foot" }, o.foot),
    el("div", { class: "acts" }, button([`Continue to ${o.next} `, kbd("⏎")], "card-continue", true, o.go!), button(`Back to ${o.gate}`, "card-back", false, o.back)));
}

// stopCard is the stopping point: every gate's outcome, and the rows left, none of which changes one;
// research is the way to have an agent look at them first
export function stopCard(o: { gates: QueueGate[]; left: QueueEntry[]; foot: string; research?: Child } & CardActions) {
  return card("stop", "Stopping point",
    el("div", { class: "outc" }, o.gates.map((g) => outcomeRow(g.name, g.outcome))),
    el("p", { class: "foot" }, o.foot),
    el("ul", { class: "qleft", "data-testid": "card-left" }, o.left.map((e) => {
      const p = pkgOf(e.package.ref);
      return el("li", { "data-row": e.row }, el("b", {}, e.vulnerability), " ", el("span", { class: "mono" }, `${p.name} ${p.version}`), el("small", {}, ` · ${e.in.map((a) => a.gate).join(", ")} · changes no outcome`));
    })),
    el("div", { class: "acts" }, button(["Keep labeling ", kbd("⏎")], "card-continue", true, o.go!), o.research, button("Back to gates", "card-back", false, o.back)));
}

// endCard is the queue with nothing open: every gate's outcome and what this session wrote
export function endCard(o: { gates: QueueGate[]; foot: string } & CardActions) {
  return card("end", "Queue empty",
    el("div", { class: "outc" }, o.gates.map((g) => outcomeRow(g.name, g.outcome))),
    el("p", { class: "foot", "data-testid": "card-session" }, o.foot),
    el("div", { class: "acts" }, button("Back to gates", "card-back", true, o.back), o.history && button("See the labels", "card-history", false, o.history)));
}
