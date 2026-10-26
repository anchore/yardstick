import { describe, expect, test } from "bun:test";
import type { ResearchSummary, StateRow } from "../gen/wire";
import { clock, doing, ordinal, researchLine } from "./agent";

const now = Date.parse("2026-10-20T10:01:00Z");
const job = (j: Partial<ResearchSummary>): ResearchSummary => ({ job: "j1", status: "queued", ...j });

describe("the table's research words", () => {
  test("ordinals and the stopwatch", () => {
    expect([1, 2, 3, 4, 11, 12, 13, 21, 22, 101, 111].map(ordinal)).toEqual(["1st", "2nd", "3rd", "4th", "11th", "12th", "13th", "21st", "22nd", "101st", "111th"]);
    expect([0, 41_000, 725_000, 3_729_000, -5].map(clock)).toEqual(["0:00", "0:41", "12:05", "1:02:09", "0:00"]);
  });
  test("running counts up from its start, queued says its place in line", () => {
    const open = { open: true, researched: false };
    expect(doing(job({ status: "running", started: "2026-10-20T10:00:19Z", batch: "3f9a21c0aa", model: "sonnet" }), open, now))
      .toEqual({ kind: "running", word: "researching", small: "0:41", since: "2026-10-20T10:00:19Z", title: "batch 3f9a21c0 · Sonnet" });
    expect(doing(job({ position: 1, queueLength: 13 }), open, now)).toMatchObject({ kind: "queued", word: "queued", small: "1st of 13" });
    expect(doing(job({}), open, now).small).toBe("");
  });
  test("a stopped job fails with its error, a finished one with nothing left says so, and an open row with none is offered", () => {
    const open = { open: true, researched: false };
    expect(doing(job({ status: "failed", error: "exit 1: no hint written" }), open)).toEqual({ kind: "failed", word: "failed", title: "exit 1: no hint written" });
    expect(doing(job({ status: "timed-out" }), open).kind).toBe("failed");
    expect(doing(job({ status: "done" }), open).kind).toBe("nohint");
    expect(doing(undefined, { open: true, researched: true }).word).toBe("researched, no hint");
    expect(doing(job({ status: "cancelled" }), open).kind).toBe("offer");
    expect(doing(undefined, open)).toEqual({ kind: "offer", word: "Research" });
    // a labeled row offers nothing, unless a job is still on it
    expect(doing(undefined, { open: false, researched: false }).kind).toBe("none");
    expect(doing(job({ status: "failed" }), { open: false, researched: false }).kind).toBe("none");
    expect(doing(job({ status: "queued" }), { open: false, researched: false }).kind).toBe("queued");
  });
  test("the finding page says it in the same words", () => {
    const row = (research: ResearchSummary) => ({ id: "r", research } as unknown as StateRow);
    expect(researchLine(row(job({ position: 3, queueLength: 13 })), now)).toBe("queued 3rd of 13");
    expect(researchLine(row(job({ status: "running", started: "2026-10-20T10:00:19Z", model: "sonnet" })), now)).toBe("researching 0:41 · Sonnet");
    expect(researchLine(row(job({ status: "cancelled" })), now)).toBe("research cancelled");
  });
});
