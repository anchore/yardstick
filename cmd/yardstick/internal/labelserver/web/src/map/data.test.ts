import { describe, expect, test } from "bun:test";
import type { CheckResult, State, StateCause } from "../gen/wire";
import type { Row } from "../shared/rows";
import { allRows, cardsFor, diffRows, groupRows, groups, nextGroup, tally, tier, unchanged } from "./data";

let n = 0;
function row(over: Partial<Row>): Row {
  const id = (++n).toString(16).padStart(16, "0");
  return { id, match: id, row: id, vulnerability: `CVE-${n}`, group: "g", sourcePackage: "openssl", package: { ref: "pkg:apk/alpine/openssl@3" }, verdict: "unlabeled", inCandidate: true, inReference: false, ...over };
}
const fnCheck: CheckResult = { name: "noNewFalseNegatives", description: "", valueMeans: "new FNs", counts: "fn", direction: "atMost", threshold: 0, value: { worst: 2, best: 0 }, state: "undecided" };
const bearsFn = { bears: ["noNewFalseNegatives"], ifTP: { outcome: "undecided" }, ifFP: { outcome: "undecided" } };

function state(rows: Row[][], causes: StateCause[] = [], outcome = "undecided"): State {
  return {
    scans: { id: "g", created: "", gate: "", label: "", compared: "", subjects: rows.map((_, i) => ({ name: `s${i}`, slug: `s${i}` })) },
    author: "me",
    subjects: rows.map((r, i) => ({ name: `s${i}`, slug: `s${i}`, changes: { tp: 0, fp: 0, unclear: 0, hinted: 0, open: 0, total: 0 }, rows: r })),
    causes,
    explanations: [],
    gate: { name: "g", locator: "", result: { outcome, ci: outcome, checks: [fnCheck] } },
  };
}

describe("rows in scope", () => {
  const added = row({}), dropped = row({ inCandidate: false, inReference: true }), both = row({ inReference: true }), neither = row({ inCandidate: false });
  const st = state([[added, dropped], [both, neither]]);
  test("diffRows takes only one-sided rows, allRows every reported one, both by image", () => {
    expect(diffRows(st, null).map((x) => [x.r.id, x.dir, x.si])).toEqual([[added.id, "added", 0], [dropped.id, "dropped", 0]]);
    expect(allRows(st, null).map((x) => x.dir)).toEqual(["added", "dropped", "both"]);
    expect(allRows(st, 1).map((x) => x.r.id)).toEqual([both.id]);
  });
  test("a passing gate with no differences is unchanged", () => {
    expect(unchanged(state([[both]], [], "pass"))).toEqual({ shared: 1, images: 1 });
    expect(unchanged(state([[added]], [], "pass"))).toBeNull();
    expect(unchanged(state([[both]]))).toBeNull();
  });
});

describe("tally", () => {
  test("counts rows by label state, hints, research and what bears on the gate", () => {
    const list = [
      row({ verdict: "tp" }), row({ verdict: "fp" }), row({ verdict: "unclear", gate: { couldFlip: ["x"], ifTP: { outcome: "fail" }, ifFP: { outcome: "pass" } } }),
      row({ hint: { id: "h", verdict: "fp", status: "pending" }, researchLevel: "triaged" }),
      row({ researched: true, gate: bearsFn }),
    ].map((r) => ({ r, si: 0, dir: "added" as const }));
    expect(tally(list)).toEqual({ n: 5, tp: 1, fp: 1, unclear: 1, open: 2, hinted: 1, triaged: 1, researched: 1, decisive: 1, bears: 1 });
  });
});

describe("tier", () => {
  const st = state([[]]);
  test("a labeled row sinks; one whose label ends the gate leads", () => {
    expect(tier(st, row({ verdict: "tp" }), "added")).toBe(9);
    expect(tier(st, row({ gate: { ifTP: { outcome: "fail" }, ifFP: { outcome: "undecided" } } }), "added")).toBe(0);
  });
  test("a dropped row is a regression risk unless the agent reads it as FP", () => {
    expect(tier(st, row({ gate: bearsFn }), "dropped")).toBe(1);
    expect(tier(st, row({ gate: bearsFn, hint: { id: "h", verdict: "fp", status: "pending", confidence: "high" } }), "dropped")).toBe(2);
  });
  test("agent hints rank by confidence, then the rest; both-sided rows trail their tier", () => {
    const hint = (confidence?: string) => row({ hint: { id: "h", verdict: "tp", status: "pending", confidence } });
    expect(tier(st, hint("high"), "added")).toBe(2);
    expect(tier(st, hint("medium"), "added")).toBe(2.3);
    expect(tier(st, hint(), "added")).toBe(2.6);
    expect(tier(st, row({}), "added")).toBe(3);
    expect(tier(st, row({}), "both")).toBe(3.05);
  });
});

describe("groups and cards", () => {
  const a = row({ sourcePackage: "zlib", gate: bearsFn }), b = row({ sourcePackage: "zlib", gate: bearsFn });
  const c = row({ sourcePackage: "glibc", inCandidate: false, inReference: true, gate: bearsFn });
  const d = row({ sourcePackage: "curl", gate: bearsFn, causes: ["c1"] }), e = row({ sourcePackage: "curl", gate: bearsFn, causes: ["c1"] });
  const cause: StateCause = { id: "c1", title: "curl backport", verdict: "fp", author: { kind: "agent" }, sourcePackage: "curl", rows: [d.id, e.id], pending: [d.id, e.id], conflicts: [], labeled: 0, accepted: 0 };
  const st = state([[a, b, c, d, e]], [cause]);
  const items = allRows(st, null);

  test("a check's rows fold into causes and packages, the cheapest tier first, then the biggest", () => {
    expect(groups(st, items).map((g) => g.key)).toEqual(["p|1|dropped|glibc", "c|c1", "p|3|added|zlib"]);
  });
  test("a card spec opens its group's rows, ordered by tier then package", () => {
    const cards = cardsFor(st, null, { kind: "tier", check: fnCheck.name, tier: 3, dir: "added", pkg: "zlib" });
    expect(cards?.title).toBe("noNewFalseNegatives › + zlib");
    expect(cards && [...cards.ids]).toEqual([a.id, b.id]);
    const cc = cardsFor(st, null, { kind: "cause", check: fnCheck.name, cause: "c1" });
    expect(cc?.title).toBe("noNewFalseNegatives › ✦ curl backport");
    expect(cc && groupRows(st, null, cc).map((x) => x.r.id)).toEqual([d.id, e.id]);
  });
  test("a delta spec opens a reason's package; an unknown check opens nothing", () => {
    const cards = cardsFor(st, null, { kind: "delta", dir: "added", why: "none", pkg: "zlib" });
    expect(cards?.title).toBe("+ candidate added › no computed reason › zlib");
    expect(cardsFor(st, null, { kind: "cause", check: "nope", cause: "c1" })).toBeNull();
  });
  test("the next group is the following one with something open, wrapping around", () => {
    expect(nextGroup(st, null, { kind: "cause", check: fnCheck.name, cause: "c1" })?.g.key).toBe("p|3|added|zlib");
    expect(nextGroup(st, null, { kind: "tier", check: fnCheck.name, tier: 3, dir: "added", pkg: "zlib" })?.g.key).toBe("p|1|dropped|glibc");
    expect(nextGroup(st, null, { kind: "delta", dir: "added", why: "none", pkg: null })).toBeNull();
  });
});
