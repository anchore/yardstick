import { describe, expect, test } from "bun:test";
import type { State } from "../gen/wire";
import type { Row } from "../shared/rows";
import { diffRows, reasonTitle, tally } from "./scandata";

let n = 0;
function row(over: Partial<Row>): Row {
  const id = (++n).toString(16).padStart(16, "0");
  return { id, match: id, row: id, vulnerability: `CVE-${n}`, group: "g", sourcePackage: "openssl", package: { ref: "pkg:apk/alpine/openssl@3" }, verdict: "unlabeled", inCandidate: true, inReference: false, ...over };
}

function state(rows: Row[][]): State {
  return {
    scans: { id: "g", created: "", gate: "", label: "", compared: "", subjects: rows.map((_, i) => ({ name: `s${i}`, slug: `s${i}` })) },
    author: "me",
    subjects: rows.map((r, i) => ({ name: `s${i}`, slug: `s${i}`, changes: { tp: 0, fp: 0, unclear: 0, hinted: 0, open: 0, total: 0 }, rows: r })),
    causes: [],
    explanations: [{ id: "x1", title: "the DBs disagree", rows: [] } as unknown as State["explanations"][number]],
  };
}

describe("diffRows", () => {
  test("takes only one-sided rows, by image", () => {
    const added = row({}), dropped = row({ inCandidate: false, inReference: true }), both = row({ inReference: true }), neither = row({ inCandidate: false });
    const st = state([[added, dropped], [both, neither, row({})]]);
    expect(diffRows(st, 0).map((x) => [x.r.id, x.dir, x.si])).toEqual([[added.id, "added", 0], [dropped.id, "dropped", 0]]);
    expect(diffRows(st, null)).toHaveLength(3);
  });
});

describe("tally", () => {
  test("counts rows by label state, and the open ones with a hint", () => {
    const list = [
      row({ verdict: "tp" }), row({ verdict: "fp" }), row({ verdict: "unclear" }),
      row({ hint: { id: "h", verdict: "fp", status: "pending" } }), row({}),
    ].map((r) => ({ r, si: 0, dir: "added" as const }));
    expect(tally(list)).toEqual({ n: 5, tp: 1, fp: 1, unclear: 1, open: 2, hinted: 1 });
  });
});

describe("reasonTitle", () => {
  test("is the explanation every row shares, else the computed reason", () => {
    const st = state([[]]);
    const a = row({ explanation: "x1" }), b = row({ explanation: "x1" }), c = row({});
    const items = (rs: Row[]) => rs.map((r) => ({ r, si: 0, dir: "added" as const }));
    expect(reasonTitle(st, items([a, b]), "added")).toBe("✎ the DBs disagree");
    expect(reasonTitle(st, items([a, c]), "added")).not.toContain("✎");
  });
});
