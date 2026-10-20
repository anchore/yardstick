import { describe, expect, test } from "bun:test";
import type { Basis } from "../gen/research";
import type { ResearchBatch, ResearchGroup } from "../gen/wire";
import { about, basisWords, batchWords, estimate, estimateWords, finishedWords, leadWords, summary, tokens } from "./researchwords";

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
    ({ group: "change", selected: true, rows, jobs: gates.map((gate) => ({ vulnerability: "CVE-1", package: { name: "p", version: "1" }, image: "i", gate, rows: [] })) });
  test("the banner's foot counts the matches and gates research covers, then the rest", () => {
    expect(leadWords(change(6, "deb-npm", "deb-npm", "deb-java", "deb-java"), 6)).toBe("6 matches across 2 gates can still change an outcome. The other 6 change none.");
    expect(leadWords(change(1, "deb-java"), 1)).toBe("1 match across 1 gate can still change an outcome. The other 1 changes none.");
    expect(leadWords(change(1, "deb-java"))).toBe("1 match across 1 gate can still change an outcome.");
  });
});
