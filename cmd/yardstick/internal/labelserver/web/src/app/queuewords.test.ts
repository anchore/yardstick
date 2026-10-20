import { describe, expect, test } from "bun:test";
import type { CrossAppearance, QueueEntry, QueueGate } from "../gen/wire";
import { boundaryWords, dayKey, dayWords, outcomeLines, progress, sessionLabels, sessionWords, whyNext } from "./queuewords";

// entries and gates as the seed's GET /api/queue gives them (SCENARIO.md)
const gate = (name: string, outcome: string, rows: number, settled = false) => ({ name, outcome, rows, settled, open: rows, compared: "", images: 2 }) as QueueGate;
const entry = (row: string, effect: string, ...ins: CrossAppearance[]) =>
  ({ row, effect, key: row, vulnerability: "CVE", package: { ref: "pkg:deb/debian/tar" }, sourcePackage: "tar", image: "deb", in: ins, bears: 0, flips: 0 }) as QueueEntry;
const at = (g: string, outcome: string, tp?: string, fp?: string, extra: Partial<CrossAppearance["effect"]> = {}): CrossAppearance =>
  ({ gate: g, row: "r", dir: "dropped", outcome, ...(tp && { effect: { ifTP: { outcome: tp }, ifFP: { outcome: fp! }, bears: ["unjudgedChangesAtMost"], ...extra } }) });

// tar CVE-2026-18508 once every hint is accepted: deb-java's last open row
const lastTar = entry("e3bfd3b0b0c30ee6", "decides", at("deb-java", "undecided", "fail", "pass", { ifTP: { outcome: "fail", fails: ["noNewFalseNegatives"] } }));

describe("whyNext", () => {
  test("a gate's only open row, which decides it", () => {
    expect(whyNext(lastTar, "deb-java", [gate("deb-java", "undecided", 1)]))
      .toBe("deb-java is undecided and this is its only open row. A label here decides it: FP passes it; TP fails noNewFalseNegatives.");
  });
  test("a row either label decides the same way", () => {
    const gzip = entry("5e50fe5b2007001a", "decides", at("deb-npm", "undecided", "pass", "pass"));
    expect(whyNext(gzip, "deb-npm", [gate("deb-npm", "undecided", 3)])).toBe("deb-npm is undecided, with 3 open rows. A label here decides it: either label passes it.");
  });
  test("a row whose label leaves one way unmoved", () => {
    const jfh = entry("e1af7851f0e60bb4", "decides", at("deb-java", "fail", "undecided", "fail"));
    expect(whyNext(jfh, "deb-java", [gate("deb-java", "fail", 10)])).toBe("deb-java fails, with 10 open rows. A label here decides it: FP leaves it failing; TP leaves it undecided.");
  });
  test("a row that only counts toward a check", () => {
    const ul = entry("9f5eb52729c83cc1", "counted", at("deb-java", "fail", "fail", "fail"));
    expect(whyNext(ul, "deb-java", [gate("deb-java", "fail", 6)])).toBe("deb-java fails, with 6 open rows. No label here changes an outcome on its own, but it counts toward unjudgedChangesAtMost.");
  });
  test("a row that changes nothing says so plainly", () => {
    const babel = entry("24160b879ac36bf5", "none", at("deb-npm", "pass"));
    expect(whyNext(babel, "deb-npm", [gate("deb-npm", "pass", 1, true)])).toBe("deb-npm passes and this is its only open row. No label here changes any gate's outcome: its gate is decided either way.");
  });
  test("a row in two gates names the one it decides", () => {
    const tar = entry("0fe9fc814bcd060a", "decides", at("deb-npm", "undecided", "pass", "pass"), at("deb-java", "fail", "fail", "fail"));
    expect(whyNext(tar, "deb-java", [gate("deb-npm", "undecided", 3), gate("deb-java", "fail", 10)])).toBe("deb-java fails, with 10 open rows. A label here decides deb-npm: either label passes it.");
  });
});

describe("outcomeLines", () => {
  test("say what FP and TP do to each gate", () => {
    expect(outcomeLines(lastTar)).toBe("FP: deb-java passes. TP: deb-java fails noNewFalseNegatives.");
    const tar = entry("0fe9fc814bcd060a", "decides", at("deb-npm", "undecided", "pass", "pass"), at("deb-java", "fail", "fail", "fail"));
    expect(outcomeLines(tar)).toBe("FP: deb-npm passes, deb-java still fails. TP: deb-npm passes, deb-java still fails.");
  });
  test("say plainly when nothing moves", () => {
    expect(outcomeLines(entry("24160b879ac36bf5", "none", at("deb-npm", "pass")))).toBe("No label here changes a gate's outcome.");
  });
});

describe("progress", () => {
  test("counts done of the whole, and what's left", () => {
    expect(progress(8, 2)).toEqual({ text: "8 of 10 done · 2 left", frac: 0.8 });
    expect(progress(0, 12).text).toBe("0 of 12 done · 12 left");
    expect(progress(0, 0).frac).toBe(1);
  });
});

describe("cards", () => {
  test("the boundary card says the gate's outcome and what's next", () => {
    const w = boundaryWords({ gate: "deb-npm", before: "undecided", after: "pass", left: 2, settled: true, next: "deb-java", nextRows: 9, nextSettled: false });
    expect(w.headline).toBe("deb-npm passes");
    expect(w.foot).toBe("Next in the queue: deb-java, 9 open rows. The 2 rows left in deb-npm change nothing, so they come last.");
    expect(boundaryWords({ gate: "deb-java", after: "fail", left: 1, settled: false, next: "deb-npm", nextRows: 1, nextSettled: true }).foot)
      .toBe("Next in the queue: deb-npm, 1 open row. None of its rows changes deb-npm's outcome. 1 row left in deb-java; the queue comes back to it.");
  });
  test("the end card counts what the session wrote", () => {
    expect(sessionWords(9, 10, 1)).toBe("9 labels written this session (10 from hints, 1 by hand).");
    expect(sessionWords(0, 0, 0)).toBe("0 labels written this session.");
  });
});

describe("history days", () => {
  test("group by the local day and head it Today, Yesterday or the date", () => {
    const now = new Date(2026, 9, 20, 9, 30);
    expect(dayKey(new Date(2026, 9, 20, 0, 5).toISOString())).toBe("2026-10-20");
    expect(dayWords("2026-10-20", now)).toBe("Today");
    expect(dayWords("2026-10-19", now)).toBe("Yesterday");
    expect(dayWords("2026-10-12", now)).toContain("12");
  });
  test("a session counts labels from the second it started", () => {
    expect(sessionLabels(["2026-10-20T05:04:28Z", "2026-10-20T05:04:27Z", "2026-10-20T05:04:26Z"], "2026-10-20T05:04:27.512Z")).toBe(2);
  });
});
