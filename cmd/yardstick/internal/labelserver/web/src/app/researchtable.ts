// researchtable.ts is research where the rows are: the Agent hint cell's research states (the hint
// as before, researching, queued, failed with retry, researched with no hint, or a Research button
// with its price), the bulk bar's Research, and a table following its rows' jobs as they run.
// The words are shared/agent.ts's and researchwords.ts's; both findings tables and the gates
// screen's Unlabeled tab draw with it.
import type { Basis } from "../gen/research";
import type { ResearchSummary, State } from "../gen/wire";
import { doing, inFlight, jobHref, since, type Doing } from "../shared/agent";
import { el, toast, type Child } from "../shared/dom";
import { plural } from "../shared/words";
import { busy, kick, latest, onJobs } from "./activity";
import { bulkPlan, bulkWords, money, type BulkRow } from "./researchwords";

// Research is what a table needs to offer research: whether it can start here, what one job costs,
// and how many run at once
export interface Research { available: boolean; basis: Basis | null; concurrency: number }

export const researchOf = (st: State | undefined): Research =>
  ({ available: !!st?.researchConcurrency, basis: st?.researchEstimate ?? null, concurrency: st?.researchConcurrency ?? 0 });

// tick counts every running cell up once a second, between the reads that redraw the table
// ponytail: one page-wide interval that never stops; it only touches [data-since] cells
let ticking = false;
export function tick() {
  if (ticking) return;
  ticking = true;
  setInterval(() => { for (const n of document.querySelectorAll<HTMLElement>("[data-since]")) n.textContent = since(n.dataset.since); }, 1000);
}

// researchCell is the cell for a row with no hint showing (or a job in flight on one): d is what
// research is doing on it, start researches it (and retries a failed job)
export function researchCell(d: Doing, j: ResearchSummary | undefined, r: Research, start: (() => void) | null): Child {
  const small = (t: string | undefined, live = false) => t && el("small", live ? { "data-since": d.since } : {}, t);
  switch (d.kind) {
    case "running":
      tick();
      return el("a", { class: "rs run", href: jobHref(j!.job), title: d.title, "data-testid": "research-cell", "data-state": d.kind }, `${d.word} `, small(d.small, true));
    case "queued":
      return el("a", { class: "rs q", href: jobHref(j!.job), title: d.title, "data-testid": "research-cell", "data-state": d.kind }, `${d.word} `, small(d.small));
    case "failed":
      return el("span", { class: "rs fail", title: d.title, "data-testid": "research-cell", "data-state": d.kind }, `${d.word} `,
        r.available && start && el("button", { type: "button", class: "lk", "data-testid": "research-retry", onclick: start }, "retry"));
    case "notrecorded":
      return el("span", { class: "rs notrec", title: d.title, "data-testid": "research-cell", "data-state": d.kind }, d.word);
    case "nohint":
      return el("span", { class: "rs nohint", "data-testid": "research-cell", "data-state": d.kind }, d.word);
    case "offer":
      if (r.available && start) {
        return el("button", { type: "button", class: "rbtn", "data-testid": "research-cell", "data-state": d.kind, title: "an agent researches this match and leaves a hint", onclick: start },
          "Research", r.basis?.measured && [" ", el("span", { class: "c" }, `~${money(r.basis.mean)}`)]);
      }
  }
  return el("span", { class: "muted" }, "–");
}

// cellFor is a findings row's Agent hint cell: its hint unless a job is in flight on it, else research
export function cellFor(o: { hint: Child | null; research?: ResearchSummary; open: boolean; researched: boolean }, r: Research, start: (() => void) | null) {
  if (o.hint && !inFlight(o.research)) return o.hint;
  return researchCell(doing(o.research, { open: o.open, researched: o.researched }), o.research, r, start);
}

// bulkResearch is the bulk bar's Research and the line under it: N counts the selected rows research
// would take, priced by jobs; it is the bar's filled button whenever it takes any, and over
// bulkLimit jobs it opens the research page with those rows instead of starting. hinted is the
// selected rows Accept hints would take, which leads when research takes none.
export function bulkResearch(rows: BulkRow[], r: Research, act: { start: (ids: string[]) => Promise<boolean>; page: (ids: string[]) => void; clear: () => void }) {
  const p = bulkPlan(rows), w = bulkWords(p, r.basis, r.concurrency);
  const b = el("button", { type: "button", class: `btn${p.rows.length ? " go" : ""}`, "data-variant": "outline", "data-size": "sm", "data-testid": "bulk-research", disabled: !p.rows.length,
    "data-rows": p.rows.length, "data-jobs": p.jobs,
    onclick: async () => {
      if (w.over) return act.page(p.rows);
      b.disabled = true;
      if (await act.start(p.rows)) act.clear(); else b.disabled = false;
    } }, w.button, w.price && [" ", el("span", { class: "c" }, w.price)]);
  return { button: r.available ? b : null, why: r.available ? el("span", { class: "why", "data-testid": "bulk-research-why" }, w.why) : null, leads: r.available && p.rows.length > 0 };
}

// started is a start's toast, then the jobs read again so the top bar and the tables follow it
export function started(jobs: number, skipped = 0) {
  toast(jobs ? `✦ ${plural(jobs, "research job")} started${skipped ? `; ${skipped} already in flight` : ""}` : "nothing to research: a job is already on every one");
  void kick();
}

// follow redraws from fresh rows when the jobs change while any row on screen has a job in flight,
// or when nothing is in flight any more but the rows still say so (a job that finished before the
// screen saw it run), until signal aborts with the view
export function follow(signal: AbortSignal, anyInFlight: () => boolean, redraw: () => Promise<void>) {
  let seen = "";
  onJobs((j) => {
    if (signal.aborted) return false;
    const now = j.jobs.map((x) => `${x.id}:${x.status}:${x.position ?? ""}`).join(",");
    if (anyInFlight() && (now !== seen || !busy(j.summary))) void redraw().catch(() => undefined);
    seen = now;
  });
  // rows cached before their job finished still say it's in flight, and with nothing in flight the
  // top bar won't read the jobs again by itself: read them once, after the first draw
  setTimeout(() => { if (anyInFlight() && !busy(latest()?.summary)) void kick(); });
}
