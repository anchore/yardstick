// researchwords.ts is how the research page, the gates banner and the finding page say what research
// costs: money with tokens beside it, time, the basis an estimate comes from, a batch's progress,
// what a table selection's Research covers, the research page's rows, and the jobs page's rows.
// Pure: research.ts, banner.ts, labelpanel.ts, researchtable.ts and jobs.ts draw it.
import type { Availability, Basis } from "../gen/research";
import type { ResearchBatch, ResearchEstimate, ResearchGroup, ResearchJob, ResearchProgress, ResearchQueueResponse } from "../gen/wire";
import { clock, failedJob, ordinal, since, type Doing } from "../shared/agent";
import { cap, plural } from "../shared/words";
import type { Effect } from "./listing";

export const money = (x: number) => `$${x.toFixed(2)}`;
// liveLog is the hover on a running job's log link, which grows as the agent works
export const liveLog = "Live: the agent's work so far. Reload it for more.";

// tokens is a token count the way the estimate shows it: 6.5M, 99k, 400
export function tokens(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${Math.round(n / 1e3)}k`;
  return String(Math.round(n));
}

// about is a duration in rough words: about a minute, about 10 min, about 2.5 h
export function about(seconds: number): string {
  const m = Math.round(seconds / 60);
  if (m <= 1) return "about a minute";
  return m < 90 ? `about ${m} min` : `about ${(m / 60).toFixed(1)} h`;
}

export const modelWords = (m: string) => (m ? cap(m) : "the configured model");

// offWords is the gates page's notice when research can't run here: the tables then offer no
// research at all, so this is where a person learns why, and what to run (yardstick never runs it).
// A branch build's note (research on, with a reason) is said too. Null when there's nothing to say.
export function offWords(a: Availability | undefined): { title: string; body: string; command?: string } | null {
  if (!a?.reason) return null;
  if (a.available) return { title: "Which plugin research runs", body: cap(a.reason) + "." };
  return { title: "Research is off", body: `${cap(a.reason)}, so no table offers research.${a.command ? " To turn it on, run this, then restart claims serve:" : ""}`, command: a.command };
}

// estimate is what jobs on basis cost, as the server prices a selection (researchqueue.go): every
// figure times the jobs, and the time at concurrency jobs at once
export function estimate(jobs: number, basis: Basis, concurrency: number, rows = 0): ResearchEstimate {
  return {
    jobs, rows, basis, low: basis.min * jobs, mean: basis.mean * jobs, high: basis.max * jobs,
    tokensIn: basis.tokensIn * jobs, tokensOut: basis.tokensOut * jobs, seconds: basis.seconds * Math.ceil(jobs / Math.max(1, concurrency)),
  };
}

export interface EstimateWords { cost: string; range: string; tokens: string; time: string }

// estimateWords are the estimate panel's lines. Unmeasured, the job count is all that is known.
export function estimateWords(e: ResearchEstimate): EstimateWords {
  if (!e.jobs) return { cost: money(0), range: "", tokens: "none", time: "" };
  if (!e.basis.measured) return { cost: "not measured", range: plural(e.jobs, "job"), tokens: "unknown", time: "unknown" };
  return { cost: money(e.mean), range: `${money(e.low)} to ${money(e.high)}`, tokens: `~${tokens(e.tokensIn)} in · ~${tokens(e.tokensOut)} out`, time: about(e.seconds) };
}

// basisWords say where the per-job numbers come from
export function basisWords(b: Basis): string {
  const never = "Jobs write hints, never labels.";
  if (!b.measured) return `Nothing measured on ${modelWords(b.model)} in this workspace. ${never}`;
  const from = b.source === "workspace" ? `from ${plural(b.n, "finished job")} in this workspace` : `from ${plural(b.n, "job")} ${b.source ?? "measured"}`;
  return `Per job: ${money(b.min)} to ${money(b.max)}, mean ${money(b.mean)}, ${from} on ${modelWords(b.model)}. ${never}`;
}

// summary is one line of a plan: 21 jobs · about 10 min · about 6.5M tokens
export function summary(e: ResearchEstimate): string {
  if (!e.basis.measured) return `${plural(e.jobs, "job")} · cost not measured on ${modelWords(e.basis.model)}`;
  return `${plural(e.jobs, "job")} · ${about(e.seconds)} · about ${tokens(e.tokensIn + e.tokensOut)} tokens`;
}

// leadWords is the banner's foot while research leads: what the matches it offers are (change, the
// group that can change a gate), and that the rest with no hint (none of them) change nothing
export function leadWords(change: ResearchGroup, none = 0): string {
  const gates = new Set(change.jobs.map((j) => j.gate)).size;
  return `${plural(change.rows, "match", "matches")} across ${plural(gates, "gate")} can still change an outcome.${none ? ` The other ${none} ${none === 1 ? "changes" : "change"} none.` : ""}`;
}

export const active = (b: ResearchBatch | null | undefined): b is ResearchBatch => !!b && b.running + b.queued > 0;

export interface BatchWords { done: string; spent: string; left: string; leftWhy: string }

// batchWords are the banner's numbers while a batch runs
export function batchWords(b: ResearchBatch): BatchWords {
  const m = Math.max(1, Math.round(b.secondsLeft / 60));
  return {
    done: `of ${plural(b.total, "job")} done`,
    spent: b.estimate ? `spent of about ${money(b.estimate)}` : "spent, the rest not measured",
    left: b.secondsLeft ? `~${m} min` : "–",
    leftWhy: `left, ${b.running} running`,
  };
}

// finishedWords is the banner's line once the newest batch is over, with what it really cost
export function finishedWords(b: ResearchBatch): string {
  const stopped = b.cancelled > 0;
  return [stopped ? "Research stopped" : "Research finished", stopped ? `${b.done} of ${plural(b.total, "job")} done` : plural(b.total, "job"),
    money(b.spent), b.notRecorded > 0 && `${b.notRecorded} not recorded`, b.failed > 0 && `${b.failed} failed`].filter(Boolean).join(" · ");
}

// ---------- the research page's rows ----------

// RRow is one open match: its group is its job's, job its job's first row, siblings the other
// matches in that job
export interface RRow { id: string; vuln: string; pkg: string; version: string; image: string; slug: string; gate: string; effect: Effect; group: string; job: string; siblings: number }

// rowsOf are the plan's matches, one row each, in its order
export function rowsOf(p: ResearchQueueResponse): RRow[] {
  return p.groups.flatMap((g) => g.jobs.flatMap((j) => j.matches.map((m) => ({
    id: m.row, vuln: m.vulnerability, pkg: m.package.name, version: m.package.version ?? "", image: j.image, slug: j.imageSlug, gate: j.gate,
    effect: (m.effect === "none" ? "" : m.effect), group: g.group, job: j.rows[0], siblings: j.matches.length - 1,
  }))));
}

// rowText is what the search box matches a row against: CVE, package and image
export const rowText = (r: RRow) => `${r.vuln} ${r.pkg} ${r.version} ${r.image}`;
// jobsIn counts the jobs rows fall in
export const jobsIn = (rs: RRow[]) => new Set(rs.map((r) => r.job)).size;

// ---------- a table selection's Research ----------

// bulkLimit is the most jobs a table selection starts by itself; more go through the research
// page's estimate first
export const bulkLimit = 10;

// BulkRow is a selected row as the bulk bar's Research counts it: job keys the rows one job covers
// when the table has no sibling list (the Unlabeled tab)
export interface BulkRow { id: string; open: boolean; hinted: boolean; doing: Doing["kind"]; shares?: string[]; job?: string }

export interface BulkPlan { rows: string[]; jobs: number; shared: number; skip: { hinted: number; active: number; researched: number; labeled: number } }

// bulkPlan is what Research does with a selection: the open rows with no hint, no finished research
// and nothing in flight, and the jobs they make, a sibling package sharing its sibling's job
export function bulkPlan(rs: BulkRow[]): BulkPlan {
  const out: BulkPlan = { rows: [], jobs: 0, shared: 0, skip: { hinted: 0, active: 0, researched: 0, labeled: 0 } };
  const covered = new Set<string>();
  for (const r of rs) {
    if (r.doing === "running" || r.doing === "queued") out.skip.active++;
    else if (!r.open) out.skip.labeled++;
    else if (r.hinted) out.skip.hinted++;
    // research that recorded nothing is researched again: what stopped it may be fixed since
    else if (r.doing === "nohint") out.skip.researched++;
    else {
      out.rows.push(r.id);
      const k = r.job ?? r.id;
      if (covered.has(k)) { out.shared++; continue; }
      out.jobs++;
      covered.add(k);
      for (const s of r.shares ?? []) covered.add(s);
    }
  }
  return out;
}

export interface BulkWords { button: string; price: string; why: string; over: boolean }

// bulkWords are the bulk bar's Research button and the line under it: what was skipped and why,
// the jobs and how long they take
export function bulkWords(p: BulkPlan, basis: Basis | null | undefined, concurrency = 0): BulkWords {
  const s = p.skip;
  const skip = [s.hinted && `${s.hinted} with a hint`, s.active && `${s.active} already researching`, s.researched && `${s.researched} already researched`, s.labeled && `${s.labeled} labeled`].filter(Boolean).join(", ");
  if (!p.rows.length) return { button: "Research 0", price: "", why: `Nothing to research: ${skip || "no rows"}.`, over: false };
  const e = basis?.measured ? estimate(p.jobs, basis, concurrency || 1) : null, over = p.jobs > bulkLimit;
  const time = e && concurrency ? `, ${about(e.seconds)} at ${concurrency} at a time` : "";
  return {
    button: `Research ${p.rows.length}${over ? "…" : ""}`,
    price: e ? `· ~${money(e.mean)}` : "",
    why: `${skip ? `Research skips ${skip}. ` : ""}${plural(p.jobs, "job")}${p.shared ? `, ${p.shared} sharing a sibling's` : ""}${time}.${over ? ` More than ${bulkLimit}, so the research page shows the estimate first.` : ""}`,
    over,
  };
}

// ---------- the jobs page and the top bar ----------

// newHints counts the pending hints research jobs left: the ones nobody has accepted yet
export function newHints(jobs: Pick<ResearchJob, "hints">[], pending: { id: string }[]): number {
  const left = new Set(jobs.flatMap((j) => j.hints.map((h) => h.id)));
  return pending.filter((h) => left.has(h.id)).length;
}

// activityWords is the top bar's chip while research is in flight: "2 researching · 13 queued"
export const activityWords = (p: Pick<ResearchProgress, "running" | "queued">) =>
  [p.running && `${p.running} researching`, p.queued && `${p.queued} queued`].filter(Boolean).join(" · ");

export interface JobGroups { running: ResearchJob[]; queued: ResearchJob[]; finished: ResearchJob[] }

// jobGroups are the jobs page's three groups: running, queued in the order they will run, and
// finished newest first
export function jobGroups(jobs: ResearchJob[]): JobGroups {
  const at = (j: ResearchJob) => Date.parse(j.finished || j.started || j.queued) || 0;
  return {
    running: jobs.filter((j) => j.status === "running"),
    queued: jobs.filter((j) => j.status === "queued").sort((a, b) => (a.position || Infinity) - (b.position || Infinity) || a.queued.localeCompare(b.queued)),
    finished: jobs.filter((j) => j.status !== "running" && j.status !== "queued").sort((a, b) => at(b) - at(a)),
  };
}

// fromWords is where a job was started: the research page and its batch, a findings table and how
// many rows, a finding page
export function fromWords(j: ResearchJob): string {
  if (j.from === "research") return `research page${j.batch ? ` · batch ${j.batch.slice(0, 8)}` : ""}`;
  if (j.from === "table") return `matches table${j.rows.length > 1 ? ` · ${j.rows.length} rows` : ""}`;
  if (j.from === "finding") return "match page";
  return j.batch ? `batch ${j.batch.slice(0, 8)}` : "not recorded";
}

// stateWords is a job's state as its row leads with it: a queued job's place in line
export function stateWords(j: ResearchJob): string {
  if (j.status === "queued") return j.position ? ordinal(j.position) : "queued";
  if (j.status === "done") return "done";
  if (failedJob(j)) return "failed";
  return j.status;
}

// timeWords is how long a job ran (counting up while it runs), or for a queued one roughly how long
// until it finishes at the runner's concurrency
export function timeWords(j: ResearchJob, basis: Basis | null | undefined, concurrency: number, now = Date.now()): string {
  if (j.status === "running") return since(j.started, now);
  if (j.status === "queued") return basis?.measured && j.position ? `~${Math.max(1, Math.round((Math.ceil(j.position / Math.max(1, concurrency)) + 1) * basis.seconds / 60))} min` : "–";
  return j.started && j.finished ? clock(Date.parse(j.finished) - Date.parse(j.started)) : "–";
}

// costWords is what a job cost, or for a queued one what it likely will
export function costWords(j: ResearchJob, basis: Basis | null | undefined): string {
  if (j.usage) return money(j.usage.costUSD);
  return j.status === "queued" && basis?.measured ? `~${money(basis.mean)}` : "–";
}
