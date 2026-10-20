// banner.ts is the gates page's work banner: how much is open across gates, how much an agent has
// hinted, what accepting every hint would do to each gate (one preview per gate, or with no hint
// pending, where each gate stands), and the ways in:
// review the hints (only while some are pending), research the open rows no agent has looked at, or
// label what's left. Whichever fits is the screen's one primary button (the title row has none here).
// While a research batch runs, the banner is its progress. It also fills each gate row's hint column.
//
// Labeling by hand never waits on research: "Label what's left" is here in every state. With no hint
// pending, h still opens hint review, which says there is nothing to review.
import type { GateList, ResearchBatch, ResearchGroup, ResearchQueueResponse } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill, toast } from "../shared/dom";
import { plural } from "../shared/words";
import { gateState } from "./data";
import { fetchHints, fetchQueue, preview } from "./hints";
import { aloneWords, hintedRows, hintsHref, inScope, previewLabels, waitWords, workNumbers, type OpenRow } from "./hintsdata";
import { openOf } from "./images";
import { formatRoute } from "./route";
import { gateRows, isOpen, sumTally } from "./listing";
import { active, batchWords, estimate, finishedWords, leadWords, money, summary } from "./researchwords";
import { kbd, status, verdict, type State as Status } from "./ui";

const needWords = (n: number) => `${n} ${n === 1 ? "needs" : "need"} you`;

// poll is how often a running batch's progress is read
const poll = 2000;

export interface Work {
  el: HTMLElement;
  // cell is a gate row's hint column, filled once the hints are in
  cell(gate: string): HTMLElement;
  // refresh reads the open work again after a write, over the numbers already shown
  refresh(list: GateList): void;
}

export function workBanner(list: GateList): Work {
  let gates = list.gates.filter((g) => !g.error);
  const nums = { open: el("b", { "data-testid": "work-open" }, "–"), hinted: el("b", { "data-testid": "work-hinted" }, "–"), need: el("b", { "data-testid": "work-need" }, "–") };
  const big = (b: HTMLElement, word: string) => el("div", { class: "big" }, b, el("span", {}, word));
  const caps = el("span", { class: "caps", "data-testid": "work-caps" }, `Open work across ${plural(gates.length, "gate")}`);
  const bigs = el("div", { class: "bigs" });
  const bar = el("div", { class: "workstack", "data-testid": "work-stack", "aria-hidden": "true" });
  const legend = el("div", { class: "legend", "data-testid": "work-legend" });
  const review = el("a", { class: "btn", href: hintsHref({}), "data-testid": "review-hints" }, "Review hints ", kbd("h"));
  const left = el("a", { class: "btn", "data-variant": "outline", href: "/ui/queue", "data-testid": "label-left" }, "Label what's left ", kbd("n"));
  const research = el("a", { class: "btn", "data-variant": "ghost", href: "/ui/research", hidden: true, "data-testid": "research-rows" });
  const cancel = el("button", { type: "button", class: "btn", "data-variant": "ghost", hidden: true, "data-testid": "research-cancel" });
  const acts = el("div", { class: "acts" }, review, left, research, cancel);
  const rcaps = el("span", { class: "caps", "data-testid": "work-rcaps" });
  const outcomes = el("div", { class: "outc" }, el("span", { class: "muted" }, "Loading…"));
  const foot = el("p", { class: "foot", "data-testid": "work-foot" });
  const banner = el("section", { class: "work", "data-testid": "work-banner", "aria-label": "Open work" },
    el("div", {}, caps, bigs, bar, legend, acts),
    el("div", {}, rcaps, outcomes, foot));
  const cells = new Map(gates.map((g) => [g.id, el("div", { class: "lnum", "data-testid": "gate-work" })]));

  // stack fills the bar, and the legend with only the segments the bar has
  const stack = (segs: [string, number, string][]) => {
    const on = segs.filter(([, n]) => n > 0);
    fill(bar, on.map(([c, n]) => el("i", { class: c, style: `flex:${n}` })));
    fill(legend, on.map(([c, , w]) => el("span", { class: c, "data-segment": c }, w)));
  };

  // primary makes b the banner's one primary button (UI-RULES 7); the others are outline, research ghost
  const primary = (b: HTMLElement) => {
    for (const x of [review, left]) if (x === b) x.removeAttribute("data-variant"); else x.setAttribute("data-variant", "outline");
    // research leads the row when it is the primary, as the mockup has it, else follows Label what's left
    if (research === b) { research.removeAttribute("data-variant"); acts.prepend(research); } else { research.setAttribute("data-variant", "ghost"); acts.insertBefore(research, cancel); }
  };

  // work is the open-work view: the numbers, the hinted / no hint bar, and research offered when
  // some open row has no hint, the primary only when no hint is pending and a row can change a gate
  function work(n: ReturnType<typeof workNumbers>, pending: number, plan: ResearchQueueResponse | null, last: ResearchBatch | null) {
    banner.dataset.research = last ? "finished" : "none";
    fill(caps, last ? finishedWords(last) : `Open work across ${plural(gates.length, "gate")}`);
    fill(bigs, big(nums.open, "open matches"), big(nums.hinted, "have an agent hint"), big(nums.need, "need you"));
    stack([["hinted", n.hinted, "hinted, ready to review"], ["you", n.needYou, "no hint"]]);
    cancel.hidden = true;
    review.hidden = !pending;
    const change = group(plan, "change"), offer = change?.jobs.length ? change : group(plan, "none");
    research.hidden = !offer?.jobs.length;
    const first = !pending && !!change?.jobs.length;
    primary(first ? research : pending ? review : left);
    if (!plan || !offer?.jobs.length) return false;
    const e = estimate(offer.jobs.length, plan.estimate.basis, plan.concurrency, offer.rows);
    research.dataset.rows = String(offer.rows);
    fill(research, `Research ${last ? `${offer.rows} more` : plural(offer.rows, "match", "matches")}… `,
      !first && e.basis.measured && [el("span", { class: "quiet" }, `~${money(e.mean)}`), " "], kbd("r"));
    if (!first) return false;
    // research leads: the other column prices it, since no hint is pending to preview; load fills
    // the foot with what the researched matches are
    banner.dataset.research = "offered";
    fill(rcaps, change!.rows === 1 ? "Research this match" : `Research these ${change!.rows} matches`);
    fill(outcomes,
      el("div", { class: "r" }, e.basis.measured
        ? [el("span", { class: "costpill", "data-testid": "research-price" }, `about ${money(e.mean)}`), el("span", { class: "quiet" }, `${money(e.low)} to ${money(e.high)}`)]
        : el("span", { class: "costpill", "data-testid": "research-price" }, "cost not measured")),
      el("div", { class: "r", "data-testid": "research-summary" }, summary(e)));
    return true;
  }

  // running is the banner as a batch's progress: jobs done, spent against the estimate, time left,
  // the hints it has left so far, and Cancel; Review and Label what's left stay
  function running(b: ResearchBatch, pending: number) {
    const w = batchWords(b), act = b.running + b.queued;
    banner.dataset.research = "running";
    fill(caps, `Researching · ${plural(b.total, "job")}`);
    fill(bigs, big(el("b", { "data-testid": "research-done" }, String(b.done)), w.done),
      big(el("b", { class: "cost", "data-testid": "research-spent" }, money(b.spent)), w.spent),
      big(el("b", { "data-testid": "research-left" }, w.left), w.leftWhy));
    stack([["done", b.total - act, "done"], ["running", b.running, "running"], ["queued", b.queued, "queued"]]);
    research.hidden = true;
    review.hidden = !pending;
    primary(pending ? review : left);
    cancel.hidden = false;
    fill(cancel, `Cancel ${plural(act, "job")}`);
    cancel.onclick = async () => {
      cancel.disabled = true;
      try {
        const res = await api.cancelBatch(b.id);
        toast(`${plural(res.cancelled.length, "research job")} cancelled; finished hints stay`);
      } catch (e) {
        toast((e as Error).message, true);
      }
      cancel.disabled = false;
      void load();
    };
    fill(rcaps, "So far");
    const so = (["fp", "tp", "unclear"] as const).filter((v) => b.hints[v] > 0);
    fill(outcomes, so.length
      ? so.map((v) => el("div", { class: "r", "data-testid": "research-so-far", "data-verdict": v }, verdict(v), el("span", {}, plural(b.hints[v], "hint")),
        v === "unclear" && el("span", { class: "quiet" }, "these still need you")))
      : el("span", { class: "muted" }, "No hints yet."));
    fill(foot, "Cancelling stops the queued jobs and the running ones. Finished hints stay. ", el("a", { href: "/ui/research/jobs", "data-testid": "work-jobs" }, "View jobs"));
  }

  // watch reads the batch until it is done, then draws the banner again with what it left; one
  // watch at a time, since a refresh loads the banner again while it runs
  let watching = false;
  function watch() {
    if (watching) return;
    watching = true;
    setTimeout(async () => {
      watching = false;
      if (!banner.isConnected) return;
      try {
        const [b, res] = await Promise.all([api.researchBatch(), fetchHints()]);
        if (!banner.isConnected) return;
        const pending = inScope(res.hints, {}).hints.length;
        fill(review, `Review ${plural(pending, "hint")} `, kbd("h"));
        if (active(b)) { running(b, pending); watch(); } else void load();
      } catch {
        watch();
      }
    }, poll);
  }

  async function load() {
    const [res, queue, plan, batch] = await Promise.all([fetchHints(), fetchQueue(),
      // research may be off here (no runner, or the plugin missing): the banner then never offers it
      api.researchQueue({ scope: "all", dryRun: true }).catch(() => null), api.researchBatch().catch(() => null)]);
    if (!banner.isConnected) return;
    const n = workNumbers(queue.entries), all = res.hints;
    fill(nums.open, n.open.toLocaleString());
    fill(nums.hinted, n.hinted.toLocaleString());
    fill(nums.need, n.needYou.toLocaleString());
    const { hints, low } = inScope(all, {});
    const hinted = hintedRows(all), labels = previewLabels(hints);
    fill(review, `Review ${plural(hints.length, "hint")} `, kbd("h"));
    const run = active(batch) ? batch : null;
    let priced = false;
    if (run) { running(run, hints.length); watch(); } else priced = work(n, hints.length, plan, batch);
    // with no hint pending there is nothing to preview: the column says where each gate stands
    if (!run && !priced) fill(rcaps, hints.length ? "If you accept every hint" : "Where each gate stands");
    const after = new Map(await Promise.all(gates.map(async (g) => {
      const p = labels.get(g.id);
      return [g.id, (p ? (await preview(g.id, p)).outcome : g.gateOutcome ?? "undecided") as Status] as const;
    })));
    const change = group(plan, "change");
    for (const g of gates) {
      const before = (g.gateOutcome ?? "undecided") as Status, open = openOf(sumTally(g.changes ?? [])), h = hinted.get(g.id)?.size ?? 0;
      const count = hints.filter((x) => x.gates.some((y) => y.gate === g.id)).length;
      // research priced per gate: the jobs that can change a gate, researched under this one
      const jobs = run || !plan ? 0 : change?.jobs.filter((j) => j.gate === g.id).length ?? 0, e = plan && estimate(jobs, plan.estimate.basis, plan.concurrency);
      fill(cells.get(g.id)!, `${h} hinted · ${needWords(Math.max(0, open - h))}`,
        el("small", {}, count ? `${plural(count, "hint")} · ${aloneWords(before, after.get(g.id)!)}` : "no hints"),
        // a link inside the row's link: the browser follows the innermost one
        jobs > 0 && e && el("a", { class: "costpill", href: formatRoute({ level: "research", scope: `gate:${g.id}`, filters: {} }), "data-testid": "gate-research" },
          e.basis.measured ? `research ~${money(e.mean)}` : `research: ${plural(jobs, "job")}`));
    }
    if (run) return;
    if (!priced) fill(outcomes, gates.map((g) => {
      const before = (g.gateOutcome ?? "undecided") as Status, a = after.get(g.id)!;
      return hints.length
        ? el("div", { class: "r", "data-testid": "work-outcome", "data-gate": g.id, "data-before": before, "data-after": a },
          status(before), el("span", { class: "arrow" }, "→"), status(a), el("b", {}, g.id))
        : el("div", { class: "r", "data-testid": "work-standing", "data-gate": g.id, "data-outcome": before }, status(before), el("b", {}, g.id));
    }));
    // research leading, the foot is one sentence on what it covers and why the rest don't count;
    // otherwise it is what each gate hints don't pass still waits on: its open rows no hint labels
    // (with no hint pending, what each gate not passing waits on now)
    const lead = priced ? leadWords(change!, group(plan, "none")?.rows) : "";
    const waits = priced ? [] : await Promise.all(gates.filter((g) => after.get(g.id) !== "pass").map(async (g) => {
      const p = labels.get(g.id) ?? {};
      const rest: OpenRow[] = gateRows(await gateState(g.id)).filter((x) => x.row && isOpen(x) && !p[x.row])
        .map((x) => ({ gate: g.id, row: x.row!, vuln: x.vuln, pkg: x.pkg }));
      return rest.length ? waitWords(g.id, rest, hints.length > 0) : "";
    }));
    fill(foot, [lead, ...waits.filter(Boolean), low > 0 && `${plural(low, "unclear hint")} left out.`].filter(Boolean).join(" "));
  }

  work({ open: 0, hinted: 0, needYou: 0 }, 1, null, null);

  const failed = (e: unknown) => fill(outcomes, el("span", { class: "muted" }, `Couldn't preview the hints: ${(e as Error).message}`));
  load().catch(failed);

  return {
    el: banner,
    cell: (gate) => cells.get(gate) ?? el("div", { class: "lnum" }),
    refresh(next) { gates = next.gates.filter((g) => !g.error); load().catch(failed); },
  };
}

const group = (p: ResearchQueueResponse | null, id: string): ResearchGroup | undefined => p?.groups.find((g) => g.group === id);
