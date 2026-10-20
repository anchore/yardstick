// researchwords.ts is how the research page, the gates banner and the finding page say what research
// costs: money with tokens beside it, time, the basis an estimate comes from, and a batch's progress.
// Pure: research.ts, banner.ts and labelpanel.ts draw it.
import type { Basis } from "../gen/research";
import type { ResearchBatch, ResearchEstimate, ResearchGroup } from "../gen/wire";
import { plural } from "../shared/words";

export const money = (x: number) => `$${x.toFixed(2)}`;

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

export const modelWords = (m: string) => (m ? m[0].toUpperCase() + m.slice(1) : "the configured model");

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
    money(b.spent), b.failed > 0 && `${b.failed} failed`].filter(Boolean).join(" · ");
}
