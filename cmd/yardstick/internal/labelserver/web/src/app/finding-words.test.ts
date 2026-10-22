import { describe, expect, test } from "bun:test";
import type { CheckResult, StateCause, StateRow } from "../gen/wire";
import { effect, panel, reasons, seenWith, shortSource } from "./finding-words";

const row = (o: Partial<StateRow>) => ({ id: "r1", verdict: "unlabeled", ...o }) as StateRow;
const check = (name: string, failsOn: string[] = []) => ({ name, failsOn }) as CheckResult;

describe("effect", () => {
  test("on a check route, the check's own finding says", () => {
    expect(effect({ check: "f1NotWorse", checkEffect: "decides", row: row({}), checks: [] })).toEqual({ kind: "decides", text: "this label decides f1NotWorse" });
    expect(effect({ check: "f1NotWorse", checkEffect: "could-move", row: row({}), checks: [] })).toEqual({ kind: "could-move", text: "labeling this can flip f1NotWorse" });
    expect(effect({ check: "f1NotWorse", checkEffect: "counted", row: row({}), checks: [] })).toBeNull();
  });
  test("off a check, the gate's checks say", () => {
    const checks = [check("f1NotWorse", ["r1"]), check("noNewFalsePositives", ["r1"]), check("other")];
    expect(effect({ check: null, row: row({ verdict: "fp" }), checks })?.text).toBe("this label decides f1NotWorse, noNewFalsePositives");
    const open = row({ gate: { couldFlip: ["f1NotWorse"], ifTP: { outcome: "pass" }, ifFP: { outcome: "fail" } } });
    expect(effect({ check: null, row: open, checks: [] })).toEqual({ kind: "could-move", text: "labeling this can flip f1NotWorse" });
    expect(effect({ check: null, row: row({}), checks: [] })).toBeNull();
  });
});

describe("shortSource", () => {
  test("is the corpus's last segment and its ref", () => {
    expect(shortSource("github.com/anchore/claims@main")).toBe("claims@main");
    expect(shortSource("https://github.com/anchore/claims.git@v1")).toBe("claims@v1");
    expect(shortSource("/Users/me/ws/claims/")).toBe("claims");
  });
  test("drops the verdict the row's source list appends", () => {
    expect(shortSource("/ws/claims: fp")).toBe("claims");
  });
});

test("seenWith leaves out the grype DB's checksum", () => {
  const l = { seenIn: { tools: [{ name: "grype", version: "v0.116.1" }, { name: "grype-db", version: "sha256:abc" }, { name: "syft", version: "v1.14.0" }] } };
  expect(seenWith(l as never)).toBe("grype v0.116.1, syft v1.14.0");
  expect(seenWith(undefined)).toBe("");
});

test("reasons are the verdict's, sorted, keeping one on file the vocabulary lacks", () => {
  const v = { justifications: { fp: { "fix-installed": "the fix is installed", "code-not-present": "not present" } } };
  expect(reasons(v, "fp").map(([j]) => j)).toEqual(["code-not-present", "fix-installed"]);
  expect(reasons(v, "fp", "not-recorded").map(([j]) => j)).toEqual(["not-recorded", "code-not-present", "fix-installed"]);
  expect(reasons(v, "tp")).toEqual([]);
});

describe("panel", () => {
  const causes = [{ id: "c", pending: ["r1"] }] as StateCause[];
  const pending = { id: "h", verdict: "tp", status: "pending" } as const;
  test("an unlabeled row with a hint shows the hint, then the form", () => {
    expect(panel(row({ hint: pending }), [])).toEqual({ onFile: false, hint: true, cause: null, heading: "Or label it yourself" });
  });
  test("a pending cause member shows the cause", () => {
    expect(panel(row({}), causes)).toMatchObject({ hint: false, cause: { id: "c" }, heading: "Or label it yourself" });
  });
  test("a labeled row shows its label and a relabel, and no hint", () => {
    expect(panel(row({ verdict: "fp", hint: { ...pending, status: "disagrees" } }), causes)).toEqual({ onFile: true, hint: false, cause: null, heading: "Relabel" });
  });
  test("an unclear row is on file and still open", () => {
    expect(panel(row({ verdict: "unclear", hint: pending }), [])).toMatchObject({ onFile: true, hint: true, heading: "Relabel" });
  });
  test("nothing on file and no hint is a plain form", () => {
    expect(panel(row({}), []).heading).toBe("Label");
  });
});
