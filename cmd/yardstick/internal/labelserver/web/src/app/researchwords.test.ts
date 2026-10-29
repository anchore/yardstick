import { describe, expect, test } from "bun:test";
import type { Basis } from "../gen/research";
import type { ResearchBatch, ResearchGroup, ResearchJob, ResearchQueueResponse } from "../gen/wire";
import { about, activityWords, basisWords, batchWords, bulkPlan, bulkWords, costWords, estimate, estimateWords, finishedWords, fromWords, jobGroups, offWords, jobsIn, leadWords, newHints, rowsOf, rowText, stateWords, summary, timeWords, tokens, type BulkRow } from "./researchwords";

// the built-in sonnet numbers (research/cost.go) and a model with no history
const sonnet: Basis = { model: "sonnet", measured: true, source: "measured 2026-10-19", n: 23, min: 0.18, mean: 0.23, max: 0.28, tokensIn: 310_000, tokensOut: 4_700, seconds: 55 };
const opus: Basis = { model: "opus", measured: false, n: 0, min: 0, mean: 0, max: 0, tokensIn: 0, tokensOut: 0, seconds: 0 };

describe("estimate words", () => {
  test("21 glibc jobs on sonnet read as the mockup does", () => {
    const e = estimate(21, sonnet, 2, 21);
    expect(estimateWords(e)).toEqual({ cost: "$4.83", range: "$3.78 to $5.88", tokens: "~6.5M in · ~99k out", time: "about 10 min" });
    expect(summary(e)).toBe("21 jobs · about 10 min · about 6.6M tokens");
  });
  test("a model with no measured jobs says so and shows only the job count", () => {
    const e = estimate(4, opus, 2);
    expect(estimateWords(e)).toEqual({ cost: "not measured", range: "4 jobs", tokens: "unknown", time: "unknown" });
    expect(summary(e)).toBe("4 jobs · cost not measured on Opus");
    expect(basisWords(opus)).toBe("Nothing measured on Opus in this workspace. Jobs write hints, never labels.");
  });
  test("no jobs costs nothing", () => {
    expect(estimateWords(estimate(0, sonnet, 2))).toEqual({ cost: "$0.00", range: "", tokens: "none", time: "" });
  });
  test("the basis names where its numbers come from", () => {
    expect(basisWords(sonnet)).toBe("Per job: $0.18 to $0.28, mean $0.23, from 23 jobs measured 2026-10-19 on Sonnet. Jobs write hints, never labels.");
    expect(basisWords({ ...sonnet, model: "haiku", source: "workspace", n: 3, min: 0.25, mean: 0.25, max: 0.25 }))
      .toBe("Per job: $0.25 to $0.25, mean $0.25, from 3 finished jobs in this workspace on Haiku. Jobs write hints, never labels.");
  });
  test("time runs at the concurrency, a part batch taking a whole slot", () => {
    expect(estimate(3, sonnet, 2).seconds).toBe(110);
    expect(about(40)).toBe("about a minute");
    expect(about(150 * 60)).toBe("about 2.5 h");
    expect(tokens(400)).toBe("400");
  });
});

const batch = (b: Partial<ResearchBatch>): ResearchBatch => ({
  id: "b1", started: "", model: "sonnet", total: 21, done: 0, running: 0, queued: 0, failed: 0, cancelled: 0, spent: 0, estimate: 0, secondsLeft: 0,
  hints: { tp: 0, fp: 0, unclear: 0 }, ...b,
});

describe("batch words", () => {
  test("a running batch counts what's done, what's spent against the estimate and the time left", () => {
    expect(batchWords(batch({ done: 12, running: 2, queued: 7, spent: 2.71, estimate: 4.83, secondsLeft: 240 })))
      .toEqual({ done: "of 21 jobs done", spent: "spent of about $4.83", left: "~4 min", leftWhy: "left, 2 running" });
    expect(batchWords(batch({ running: 1, model: "opus" })).spent).toBe("spent, the rest not measured");
  });
  test("a finished batch keeps its real total", () => {
    expect(finishedWords(batch({ done: 21, spent: 4.84 }))).toBe("Research finished · 21 jobs · $4.84");
    expect(finishedWords(batch({ done: 12, cancelled: 8, failed: 1, spent: 2.71 }))).toBe("Research stopped · 12 of 21 jobs done · $2.71 · 1 failed");
  });
});

describe("lead words", () => {
  const change = (rows: number, ...gates: string[]): ResearchGroup =>
    ({ group: "change", selected: true, rows, jobs: gates.map((gate) => ({ vulnerability: "CVE-1", package: { name: "p", version: "1" }, image: "i", imageSlug: "i", gate, rows: [], matches: [] })) });
  test("the banner's foot counts the matches and gates research covers, then the rest", () => {
    expect(leadWords(change(6, "deb-npm", "deb-npm", "deb-java", "deb-java"), 6)).toBe("6 matches across 2 gates can still change an outcome. The other 6 change none.");
    expect(leadWords(change(1, "deb-java"), 1)).toBe("1 match across 1 gate can still change an outcome. The other 1 changes none.");
    expect(leadWords(change(1, "deb-java"))).toBe("1 match across 1 gate can still change an outcome.");
  });
});

describe("a table selection's Research", () => {
  const r = (id: string, extra: Partial<BulkRow> = {}): BulkRow => ({ id, open: true, hinted: false, doing: "offer", ...extra });
  test("the mockup's three: one hinted, two open, priced by jobs", () => {
    const p = bulkPlan([r("h", { hinted: true }), r("a"), r("b")]);
    expect(p).toEqual({ rows: ["a", "b"], jobs: 2, shared: 0, skip: { hinted: 1, active: 0, researched: 0, labeled: 0 } });
    expect(bulkWords(p, { ...sonnet, mean: 0.25, seconds: 55 }, 2)).toEqual({ button: "Research 2", price: "· ~$0.50", why: "Research skips 1 with a hint. 2 jobs, about a minute at 2 at a time.", over: false });
  });
  test("siblings share a job, by their share list or a job key", () => {
    expect(bulkPlan([r("c1", { shares: ["c2"] }), r("c2", { shares: ["c1"] }), r("d")])).toMatchObject({ rows: ["c1", "c2", "d"], jobs: 2, shared: 1 });
    expect(bulkPlan([r("x", { job: "k" }), r("y", { job: "k" })])).toMatchObject({ jobs: 1, shared: 1 });
    expect(bulkWords(bulkPlan([r("c1", { shares: ["c2"] }), r("c2")]), opus).why).toBe("1 job, 1 sharing a sibling's.");
  });
  test("in flight, labeled and researched rows are skipped and named", () => {
    const p = bulkPlan([r("run", { doing: "running", hinted: true }), r("q", { doing: "queued" }), r("l", { open: false, doing: "none" }), r("n", { doing: "nohint" }), r("f", { doing: "failed" })]);
    expect(p).toEqual({ rows: ["f"], jobs: 1, shared: 0, skip: { hinted: 0, active: 2, researched: 1, labeled: 1 } });
    expect(bulkWords(bulkPlan([r("q", { doing: "queued" }), r("h", { hinted: true })]), sonnet, 2)).toEqual({ button: "Research 0", price: "", why: "Nothing to research: 1 with a hint, 1 already researching.", over: false });
  });
  test("over ten jobs it goes through the research page", () => {
    const w = bulkWords(bulkPlan(Array.from({ length: 11 }, (_, i) => r(`r${i}`))), sonnet, 2);
    expect(w.over).toBe(true);
    expect(w.button).toBe("Research 11…");
    expect(w.why).toEndWith("More than 10, so the research page shows the estimate first.");
  });
});

describe("the jobs page", () => {
  const job = (id: string, extra: Partial<ResearchJob> = {}): ResearchJob =>
    ({ id, rows: ["r1"], vulnerability: "CVE-1", package: "glibc", status: "done", command: "", dir: "", queued: "2026-10-20T10:00:00Z", hints: [], ...extra });
  test("groups running, queued in run order and finished newest first", () => {
    const g = jobGroups([job("q2", { status: "queued", position: 2 }), job("old", { finished: "2026-10-20T10:01:00Z" }), job("run", { status: "running" }),
      job("q1", { status: "queued", position: 1 }), job("new", { status: "failed", finished: "2026-10-20T10:05:00Z" })]);
    expect([g.running, g.queued, g.finished].map((x) => x.map((j) => j.id))).toEqual([["run"], ["q1", "q2"], ["new", "old"]]);
  });
  test("each row says where it started, its state, time and cost", () => {
    expect(fromWords(job("a", { from: "research", batch: "3f9a21c0deadbeef" }))).toBe("research page · batch 3f9a21c0");
    expect(fromWords(job("a", { from: "table", rows: ["x", "y"] }))).toBe("matches table · 2 rows");
    expect(fromWords(job("a", { from: "finding" }))).toBe("match page");
    expect(fromWords(job("a"))).toBe("not recorded");
    expect([stateWords(job("a", { status: "queued", position: 3 })), stateWords(job("a", { status: "timed-out" })), stateWords(job("a", { status: "cancelled" }))]).toEqual(["3rd", "failed", "cancelled"]);
    const now = Date.parse("2026-10-20T10:01:00Z");
    expect(timeWords(job("a", { status: "running", started: "2026-10-20T10:00:19Z" }), sonnet, 2, now)).toBe("0:41");
    expect(timeWords(job("a", { started: "2026-10-20T10:00:00Z", finished: "2026-10-20T10:00:58Z" }), sonnet, 2)).toBe("0:58");
    expect(timeWords(job("a", { status: "queued", position: 1 }), sonnet, 2)).toBe("~2 min");
    expect(timeWords(job("a", { status: "cancelled" }), sonnet, 2)).toBe("–");
    expect(costWords(job("a", { usage: { costUSD: 0.24, inputTokens: 0, cacheReadTokens: 0, cacheCreationTokens: 0, outputTokens: 0, turns: 0, durationMs: 0 } }), sonnet)).toBe("$0.24");
    expect([costWords(job("a", { status: "queued" }), sonnet), costWords(job("a", { status: "queued" }), opus), costWords(job("a", { status: "running" }), sonnet)]).toEqual(["~$0.23", "–", "–"]);
  });
  test("new hints are the pending ones jobs left", () => {
    const jobs = [job("a", { hints: [{ id: "h1", verdict: "fp" }, { id: "h2", verdict: "tp" }] }), job("b")];
    expect(newHints(jobs, [{ id: "h2" }, { id: "skill" }])).toBe(1);
  });
  test("the top bar's chip", () => {
    expect([activityWords({ running: 2, queued: 13 }), activityWords({ running: 1, queued: 0 }), activityWords({ running: 0, queued: 4 })]).toEqual(["2 researching · 13 queued", "1 researching", "4 queued"]);
  });
});

describe("the research page's rows", () => {
  const job = (rows: string[], effect = "decides") => ({ vulnerability: "CVE-2023-39323", package: { name: "stdlib", version: "1.16.9" }, image: "grype-quality-golang:d89207b", imageSlug: "grype-quality-golang-d89207b", gate: "grype-upgrade", rows,
    matches: rows.map((row, i) => ({ row, vulnerability: "CVE-2023-39323", package: { name: "stdlib", version: i ? "1.18.4" : "1.16.9" }, effect })) });
  const plan = { groups: [
    { group: "change", selected: true, rows: 1, jobs: [job(["a"], "could-move")] },
    { group: "none", selected: true, rows: 3, jobs: [job(["b", "c", "d"], "none")] },
  ] } as unknown as ResearchQueueResponse;
  test("one row per match, in the plan's order, each knowing its job and how many share it", () => {
    const rs = rowsOf(plan);
    expect(rs.map((r) => [r.id, r.group, r.job, r.siblings, r.effect])).toEqual([["a", "change", "a", 0, "could-move"], ["b", "none", "b", 2, ""], ["c", "none", "b", 2, ""], ["d", "none", "b", 2, ""]]);
    expect(rs[2].version).toBe("1.18.4");
    expect(jobsIn(rs)).toBe(2);
    expect(jobsIn(rs.slice(1, 3))).toBe(1);
  });
  test("the search matches CVE, package, version and image", () => {
    expect(rowText(rowsOf(plan)[0])).toBe("CVE-2023-39323 stdlib 1.16.9 grype-quality-golang:d89207b");
  });
});

describe("research off words", () => {
  test("says why research is off and what to run", () => {
    const w = offWords({ available: false, reason: "the yardstick plugin is version 0.16.0, but this yardstick is v0.17.0", command: "claude plugin update yardstick@yardstick" });
    expect(w?.title).toBe("Research is off");
    expect(w?.body).toBe("The yardstick plugin is version 0.16.0, but this yardstick is v0.17.0, so no table offers research. To turn it on, run this, then restart claims serve:");
    expect(w?.command).toBe("claude plugin update yardstick@yardstick");
  });
  test("a branch build's note is said, research still on", () => {
    expect(offWords({ available: true, reason: "this yardstick is v0.17.0-b, a build of 0.17.0" })?.title).toBe("Research runs the installed plugin");
  });
  test("nothing to say", () => {
    expect(offWords(undefined)).toBeNull();
    expect(offWords({ available: true })).toBeNull();
  });
});
