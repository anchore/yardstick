// banner.ts is the gates page's work banner: how much is open across gates, how much an agent has
// hinted, what accepting every hint would do to each gate (one preview per gate), and the two ways
// in: review the hints, or label what's left. Whichever fits is the screen's one primary button (the
// title row has none here). It also fills each gate row's hint column.
import type { GateList } from "../gen/wire";
import { el, fill } from "../shared/dom";
import { plural } from "../shared/words";
import { gateState } from "./data";
import { fetchHints, fetchQueue, preview } from "./hints";
import { aloneWords, hintedRows, hintsHref, inScope, previewLabels, waitWords, workNumbers, type OpenRow } from "./hintsdata";
import { openOf } from "./images";
import { gateRows, isOpen, sumTally } from "./listing";
import { kbd, status, type State as Status } from "./ui";

const needWords = (n: number) => `${n} ${n === 1 ? "needs" : "need"} you`;

export interface Work {
  el: HTMLElement;
  // cell is a gate row's hint column, filled once the hints are in
  cell(gate: string): HTMLElement;
}

export function workBanner(list: GateList): Work {
  const gates = list.gates.filter((g) => !g.error);
  const nums = { open: el("b", { "data-testid": "work-open" }, "–"), hinted: el("b", { "data-testid": "work-hinted" }, "–"), need: el("b", { "data-testid": "work-need" }, "–") };
  const big = (b: HTMLElement, word: string) => el("div", { class: "big" }, b, el("span", {}, word));
  const bar = el("div", { class: "workstack", "data-testid": "work-stack", "aria-hidden": "true" });
  const review = el("a", { class: "btn", href: hintsHref({}), "data-testid": "review-hints" }, "Review hints ", kbd("h"));
  const left = el("a", { class: "btn", "data-variant": "outline", href: "/ui/queue", "data-testid": "label-left" }, "Label what's left ", kbd("n"));
  const outcomes = el("div", { class: "outc" }, el("span", { class: "muted" }, "Previewing…"));
  const foot = el("p", { class: "foot", "data-testid": "work-foot" });
  const banner = el("section", { class: "work", "data-testid": "work-banner", "aria-label": "Open work" },
    el("div", {},
      el("span", { class: "caps" }, `Open work across ${plural(gates.length, "gate")}`),
      el("div", { class: "bigs" }, big(nums.open, "open findings"), big(nums.hinted, "have an agent hint"), big(nums.need, "need you")),
      bar,
      el("div", { class: "legend" }, el("span", { class: "hinted" }, "hinted, ready to review"), el("span", { class: "you" }, "no hint")),
      el("div", { class: "acts" }, review, left)),
    el("div", {}, el("span", { class: "caps" }, "If you accept every hint"), outcomes, foot));

  const cells = new Map(gates.map((g) => [g.id, el("div", { class: "lnum", "data-testid": "gate-work" })]));

  void (async () => {
    const [res, queue] = await Promise.all([fetchHints(), fetchQueue()]);
    const n = workNumbers(queue.entries), all = res.hints;
    fill(nums.open, n.open.toLocaleString());
    fill(nums.hinted, n.hinted.toLocaleString());
    fill(nums.need, n.needYou.toLocaleString());
    fill(bar, n.hinted > 0 && el("i", { class: "hinted", style: `flex:${n.hinted}` }), n.needYou > 0 && el("i", { class: "you", style: `flex:${n.needYou}` }));
    const { hints, low } = inScope(all, {});
    const hinted = hintedRows(all), labels = previewLabels(hints);
    fill(review, `Review ${plural(hints.length, "hint")} `, kbd("h"));
    // one primary button (UI-RULES 7): review while hints are pending, else label what's left
    if (!hints.length) { review.setAttribute("data-variant", "outline"); left.removeAttribute("data-variant"); }
    const after = new Map(await Promise.all(gates.map(async (g) => {
      const p = labels.get(g.id);
      return [g.id, (p ? (await preview(g.id, p)).outcome : g.gateOutcome ?? "undecided") as Status] as const;
    })));
    fill(outcomes, gates.map((g) => {
      const before = (g.gateOutcome ?? "undecided") as Status, a = after.get(g.id)!;
      return el("div", { class: "r", "data-testid": "work-outcome", "data-gate": g.id, "data-before": before, "data-after": a },
        status(before), el("span", { class: "arrow" }, "→"), status(a), el("b", {}, g.id));
    }));
    for (const g of gates) {
      const before = (g.gateOutcome ?? "undecided") as Status, open = openOf(sumTally(g.changes ?? [])), h = hinted.get(g.id)?.size ?? 0;
      const count = hints.filter((x) => x.gates.some((y) => y.gate === g.id)).length;
      fill(cells.get(g.id)!, `${h} hinted · ${needWords(Math.max(0, open - h))}`,
        el("small", {}, count ? `${plural(count, "hint")} · ${aloneWords(before, after.get(g.id)!)}` : "no hints"));
    }
    // what each gate hints don't pass still waits on: its open rows no hint labels
    const waits = await Promise.all(gates.filter((g) => after.get(g.id) !== "pass").map(async (g) => {
      const p = labels.get(g.id) ?? {};
      const rest: OpenRow[] = gateRows(await gateState(g.id)).filter((x) => x.row && isOpen(x) && !p[x.row])
        .map((x) => ({ gate: g.id, row: x.row!, vuln: x.vuln, pkg: x.pkg }));
      return rest.length ? waitWords(g.id, rest) : "";
    }));
    fill(foot, [...waits.filter(Boolean), low > 0 && `${plural(low, "low-confidence hint")} left out.`].filter(Boolean).join(" "));
  })().catch((e) => fill(outcomes, el("span", { class: "muted" }, `Couldn't preview the hints: ${(e as Error).message}`)));

  return { el: banner, cell: (gate) => cells.get(gate) ?? el("div", { class: "lnum" }) };
}
