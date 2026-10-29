import { describe, expect, test } from "bun:test";
import type { ResearchDetail, ResearchSummary, StateRow } from "../gen/wire";
import { clock, doing, ordinal, researchLine, researchOutcome } from "./agent";

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
  test("research that recorded nothing says so, with why on hover, over an older run's done", () => {
    const open = { open: true, researched: true };
    const why = "the agent was refused 5 tool uses: Bash gh api repos/bminor/binutils-gdb/commits/ea1a0737";
    expect(doing(job({ status: "not-recorded", error: why }), open)).toEqual({ kind: "notrecorded", word: "researched, not recorded", title: why });
    expect(doing(job({ status: "done" }), open).word).toBe("researched, no hint");
    // the finding page's section says it in full, so the panel's line leaves it out
    expect(researchLine({ id: "r", research: job({ status: "not-recorded", error: why }) } as unknown as StateRow)).toBe("");
  });
});

describe("the finding page's research section", () => {
  const when = () => "Oct 28, 21:35";
  const ran = (j: Partial<ResearchSummary>) => job({ job: "c03045021a0f19a8", model: "sonnet", costUSD: 0.2724468, finished: "2026-10-28T21:36:17Z", ...j });
  const wrote = (p: Partial<NonNullable<NonNullable<ResearchDetail["output"]>["proposal"]>> | null): ResearchDetail => ({
    recordable: !!p, summary: "Verdict I would propose: tp, fix-newer, medium.",
    output: { dir: ".yardstick/research/CLEANSTART-2026-GU36052/binutils", files: ["proposal.json"], proposal: p ? { verdict: "tp", ...p } : undefined },
  });
  test("heads with when, on what and for how much", () => {
    expect(researchOutcome(ran({ status: "done" }), undefined, when)).toEqual({ kind: "recorded", head: "Researched Oct 28, 21:35 · Sonnet · $0.27", text: "Recorded as an agent hint." });
  });
  test("a conclusion it wrote but didn't record, and why", () => {
    const why = 'propose refused it: proposal 1: vulnerability CLEANSTART-2026-GU36052: namespace "CLEANSTART" is not in any claims source\'s vocabulary.yaml';
    expect(researchOutcome(ran({ status: "not-recorded", error: why }), wrote({ justification: "fix-newer", confidence: "high" }), when).text)
      .toBe(`Research concluded tp · fix-newer · high but it wasn't recorded: ${why}`);
  });
  test("nothing written: only the skeleton, or no file at all", () => {
    const why = "the agent was refused 5 tool uses: Write .yardstick/research/CLEANSTART-2026-GU36052/binutils/REPORT.md";
    for (const det of [wrote(null), undefined]) {
      expect(researchOutcome(ran({ status: "not-recorded", error: why }), det, when)).toMatchObject({ kind: "nothing", text: `Research ran but wrote no result: ${why}` });
    }
    expect(researchOutcome(ran({ status: "not-recorded" }), undefined, when).text).toBe("Research ran but wrote no result: nothing was recorded; the log says what happened");
  });
  test("running, failed and cancelled are the job's own", () => {
    expect(researchOutcome(ran({ status: "running", started: "2026-10-20T10:00:19Z", finished: undefined }), undefined, when, now))
      .toEqual({ kind: "running", head: "Researching · Sonnet · $0.27", text: "researching 0:41" });
    expect(researchOutcome(ran({ status: "failed", error: "exit status 1" }), undefined, when).text).toBe("Research failed: exit status 1");
    expect(researchOutcome(ran({ status: "timed-out" }), undefined, when).text).toBe("Research timed out.");
    expect(researchOutcome(ran({ status: "cancelled" }), undefined, when).kind).toBe("cancelled");
  });
});
