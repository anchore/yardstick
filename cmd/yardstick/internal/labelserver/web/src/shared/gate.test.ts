import { describe, expect, test } from "bun:test";
import type { CheckResult } from "../gen/wire";
import { bar, barLayout, endsGate, noResult, regressionRisk } from "./gate";
import type { Row } from "./rows";

function check(over: Partial<CheckResult>): CheckResult {
  return { name: "noNewFalseNegatives", description: "", valueMeans: "new FNs", direction: "atMost", threshold: 0, value: { worst: 3, best: 0 }, state: "undecided", ...over };
}
function row(gate?: Row["gate"]): Row {
  return { id: "r", match: "m", row: "r", vulnerability: "CVE-1", group: "g", sourcePackage: "p", package: { ref: "pkg:apk/alpine/p@1" }, verdict: "unlabeled", inCandidate: true, inReference: false, gate };
}

describe("barLayout", () => {
  test("the range reads in drawn order, worst on the failing side", () => {
    // atMost: lower passes, so the threshold's passing side is on the left and best is drawn first
    const b = barLayout(check({ value: { worst: 14, best: 2 }, threshold: 0 }));
    expect(b.rangeText).toBe("best 2 … 14 worst");
    expect(b.thrText).toBe("threshold: pass if ≤ 0");
    const up = barLayout(check({ direction: "atLeast", value: { worst: 0.5, best: 0.875 }, threshold: 0.7 }));
    expect(up.rangeText).toBe("worst 0.500 … 0.875 best");
    expect(up.thrText).toBe("threshold: pass if ≥ 0.700");
  });
  test("without a direction, the passing side is where best lies", () => {
    expect(barLayout(check({ direction: "", value: { worst: 1, best: 5 }, threshold: 3 })).thrText).toBe("threshold: pass if ≥ 3");
    expect(barLayout(check({ direction: "", value: { worst: 5, best: 1 }, threshold: 3 })).thrText).toBe("threshold: pass if ≤ 3");
  });
  test("a settled value says nothing moves it and still gets a visible range", () => {
    const b = barLayout(check({ value: { worst: 2, best: 2 }, threshold: 0 }));
    expect(b.rangeText).toBe("2 (no unlabeled delta moves it)");
    expect(b.range.width).toBe(3);
  });
  test("everything lands inside the bar, with the threshold outside a range it doesn't cut", () => {
    const b = barLayout(check({ value: { worst: 14, best: 2 }, threshold: 0 }));
    for (const x of [b.range.x, b.range.x + b.range.width, b.thrX, b.thrTextX, b.rangeTextX]) {
      expect(x).toBeGreaterThanOrEqual(bar.L);
      expect(x).toBeLessThanOrEqual(bar.W - bar.R);
    }
    expect(b.thrX).toBeLessThan(b.range.x);
  });
  test("a preview that moves the range draws a ghost; one that doesn't, none", () => {
    const c = check({ value: { worst: 3, best: 0 } });
    expect(barLayout(c, check({ value: { worst: 3, best: 0 } })).ghost).toBeNull();
    const moved = barLayout(c, check({ value: { worst: 1, best: 0 } }));
    expect(moved.ghost).not.toBeNull();
    expect(moved.ghost?.width).toBeLessThan(moved.range.width);
    expect(moved.flips).toBe(false);
  });
  test("a preview flips the check only when the range moves and the state changes", () => {
    const c = check({ value: { worst: 3, best: 0 }, state: "undecided" });
    expect(barLayout(c, check({ value: { worst: 0, best: 0 }, state: "pass" })).flips).toBe(true);
    expect(barLayout(c, check({ value: { worst: 3, best: 0 }, state: "pass" })).flips).toBe(false);
  });
});

describe("verdict math", () => {
  test("a label ends the gate when either verdict changes the outcome", () => {
    expect(endsGate("undecided", row({ ifTP: { outcome: "fail" }, ifFP: { outcome: "undecided" } }))).toBe(true);
    expect(endsGate("undecided", row({ ifTP: { outcome: "undecided" }, ifFP: { outcome: "undecided" } }))).toBe(false);
    expect(endsGate(undefined, row({ ifTP: { outcome: "fail" }, ifFP: { outcome: "pass" } }))).toBe(false);
    expect(endsGate("undecided", row())).toBe(false);
  });
  test("a dropped row is a regression risk only while a false-negative check is undecided", () => {
    const fn = check({ counts: "fn", state: "undecided" });
    expect(regressionRisk([fn], "dropped")).toBe(true);
    expect(regressionRisk([fn], "added")).toBe(false);
    expect(regressionRisk([{ ...fn, state: "pass" }], "dropped")).toBe(false);
    expect(regressionRisk([{ ...fn, counts: "fp" }], "dropped")).toBe(false);
  });
  test("a gate with no result says why", () => {
    expect(noResult(undefined)).toBe("undecided");
    expect(noResult({ name: "g", locator: "", rerun: true })).toBe("undecided · re-scan needed");
  });
});
