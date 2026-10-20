// ui.ts is the app's small components: status and verdict badges, the hint mark, image names, the
// meter and the verdict bar. Each is the word and the shape as well as the color (UI-RULES 8).
import { el, type Child } from "../shared/dom";
import { splitName, type Counts } from "./images";

export type State = "pass" | "fail" | "undecided";
export type Verdict = "tp" | "fp" | "unclear" | "unlabeled";

export const verdictWords: Record<Verdict, string> = { tp: "TP", fp: "FP", unclear: "unclear", unlabeled: "unlabeled" };

// status is a gate's or check's state: an outline badge with a colored dot
export const status = (s: State, large = false) =>
  el("span", { class: `badge status ${s}${large ? " lg" : ""}`, "data-variant": "outline", "data-testid": "status" }, s);

// verdict is a label's verdict: ● TP, ○ FP, ◖ unclear, or a dashed "unlabeled"
export const verdict = (v: Verdict) =>
  el("span", { class: `badge verdict ${v}`, "data-variant": "outline", "data-testid": "verdict" }, verdictWords[v]);

// hint is an agent's suggestion, ✦ in hint purple, e.g. "TP · medium"
export const hint = (text: string) => el("span", { class: "hint", "data-testid": "hint" }, text);

// couldMove marks a finding whose label can flip a check
export const couldMove = () => el("span", { class: "could-move" }, "could move");

export const kbd = (k: string) => el("kbd", { class: "kbd" }, k);

// step is a pager's k / j link: the arrow says which way, the key says how, dimmed when there is nowhere to go
export function step(href: string | undefined, way: "previous" | "next", testid: string) {
  const key = way === "previous" ? "k" : "j";
  const body = way === "previous" ? ["←", kbd(key)] : [kbd(key), "→"];
  return href
    ? el("a", { class: "step", href, "aria-label": way, title: `${way === "previous" ? "Previous" : "Next"} (${key})`, "data-testid": testid }, body)
    : el("span", { class: "step off", "aria-hidden": "true" }, body);
}

// imageName is an image's name that truncates its repository part and never its tag, with the full
// reference on hover
export function imageName(name: string, ref?: string) {
  const [b, tag] = splitName(name);
  return el("span", { class: "imname", title: ref || name }, el("span", { class: "b" }, b), tag && el("span", { class: "tag" }, tag));
}

// meterSpan places a check's value and limit on one track as fractions of its width: the larger
// of the two sits at 80%, so there is room past it, and a value below zero reads as none
export function meterSpan(value: number, limit: number): { fill: number; limit: number } {
  const v = Math.max(0, value), l = Math.max(0, limit), top = Math.max(v, l);
  if (top === 0) return { fill: 0, limit: 0 };
  return { fill: (v / top) * 0.8, limit: (l / top) * 0.8 };
}

const pct = (f: number) => `${(f * 100).toFixed(1)}%`;

// meter is one bar, one tick for the limit and one caption, e.g. "0.500 worse · limit 0"
export function meter(o: { value: number; limit: number; state: State; caption: Child }) {
  const s = meterSpan(o.value, o.limit);
  return el("div", { class: `meter ${o.state}`, "data-testid": "meter" },
    el("div", { class: "track" },
      el("div", { class: "fill", style: `width:${pct(s.fill)}` }),
      el("div", { class: "lim", style: `left:${pct(s.limit)}` })),
    el("div", { class: "cap" }, o.caption));
}

// segments are the verdict bar's parts in order; hinted and open split the unlabeled findings
const segments = (c: Counts) => [
  { cls: "tp", n: c.tp, word: "TP" },
  { cls: "fp", n: c.fp, word: "FP" },
  { cls: "unclear", n: c.unclear, word: "unclear" },
  { cls: "hinted", n: c.hinted, word: "unlabeled with a hint" },
  { cls: "open", n: Math.max(0, c.open - c.hinted), word: "unlabeled" },
];

// stackBar is the thin stacked bar of a set of findings by verdict
export const stackBar = (c: Counts) =>
  el("span", { class: "stack", "aria-hidden": "true" }, segments(c).filter((s) => s.n > 0).map((s) => el("i", { class: s.cls, style: `flex:${s.n}` })));

// verdictBar is the gate's whole verdict mix with its legend
export function verdictBar(c: Counts, noun = "changed matches") {
  return el("div", { class: "verbar", "data-testid": "verdict-bar" },
    stackBar(c),
    el("div", { class: "legend" },
      segments(c).map((s) => el("span", { class: s.cls }, `${s.word} ${s.n.toLocaleString()}`)),
      el("span", { class: "total" }, `· ${c.total.toLocaleString()} ${noun}`)));
}
