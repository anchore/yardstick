import { describe, expect, test } from "bun:test";
import type { CheckFindings, Finding, State, StateRow, claimsv1 } from "../gen/wire";
import { checkRows, gateRows, nextOpen as nextOpenRow, shownRows } from "./listing";
import { fromCheck, fromState, nextOpen, position } from "./neighbors";
import type { Filters } from "./route";

const img = (slug: string) => ({ name: slug.replace(/-(\w+)$/, ":$1"), slug, ref: `ghcr.io/x/${slug}` });
const f = (row: string | undefined, image: string, vuln: string, pkg: string, label: claimsv1.Verdict | null, hint = false): Finding => ({
  row, image: img(image), vulnerability: vuln, package: { name: pkg, version: "1.0" }, direction: "added",
  label: label ? { verdict: label, source: "/ws/claims" } : null, hint: hint ? { verdict: "tp", kind: "proposal" } : null, effect: "counted",
});
const findings = [
  f("a", "deb-617d48d", "CVE-2005-2541", "tar", null, true),
  f("b", "deb-617d48d", "CVE-2026-18508", "tar", null),
  f(undefined, "deb-617d48d", "CVE-2026-1", "unmet", "tp"),
  f("c", "java-e363e44", "GHSA-jfh8-c2jp-5v3q", "log4j-core", "unclear", true),
  f("d", "java-e363e44", "CVE-2011-3389", "libgnutls30", "fp"),
];
const ids = (xs: { id: string }[]) => xs.map((x) => x.id);
const cf = { findings } as CheckFindings;
const gate = { subjects: [{ slug: "deb-617d48d" }, { slug: "java-e363e44" }] } as State;
const check = (f: Filters) => fromCheck(cf, gate, f);

describe("fromCheck", () => {
  test("keeps the check's order and drops what no finding page shows", () => {
    expect(ids(check({}))).toEqual(["a", "b", "c", "d"]);
  });
  test("filters by image, verdict, hint and search as the table does", () => {
    expect(ids(check({ image: "java-e363e44" }))).toEqual(["c", "d"]);
    expect(ids(check({ verdict: "unlabeled" }))).toEqual(["a", "b"]);
    expect(ids(check({ verdict: "unclear" }))).toEqual(["c"]);
    expect(ids(check({ hint: "yes" }))).toEqual(["a", "c"]);
    expect(ids(check({ q: "tar 2026" }))).toEqual(["b"]);
    expect(ids(check({ q: "java" }))).toEqual(["c", "d"]);
  });
  test("unclear stays open, tp and fp don't", () => {
    expect(check({}).map((x) => x.open)).toEqual([true, true, true, false]);
  });
});

describe("fromState", () => {
  const row = (id: string, vuln: string, ref: string, verdict: string, changed = true, hint?: string): StateRow =>
    ({ id, vulnerability: vuln, package: { ref }, verdict, inCandidate: true, inReference: !changed, hint: hint ? { id: "h", verdict: "tp", status: hint } : undefined } as StateRow);
  const s = {
    scans: { subjects: [] },
    causes: [{ id: "c1", pending: ["u1"] }],
    subjects: [
      { name: "deb:617d48d", slug: "deb-617d48d", rows: [row("t1", "CVE-2005-2541", "pkg:deb/debian/tar@1.34", "unlabeled", true, "pending"), row("same", "CVE-1", "pkg:deb/debian/x@1", "unlabeled", false), row("u1", "CVE-2026-3184", "pkg:deb/debian/util-linux@2.38", "unlabeled")] },
      { name: "java:e363e44", slug: "java-e363e44", rows: [row("j1", "GHSA-jfh8-c2jp-5v3q", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "tp")] },
    ],
  } as unknown as State;
  test("is every changed row in report order when no row has an effect", () => {
    expect(ids(fromState(s, {}))).toEqual(["t1", "u1", "j1"]);
  });
  test("counts a pending cause member as hinted", () => {
    expect(ids(fromState(s, { hint: "yes" }))).toEqual(["t1", "u1"]);
  });
  test("filters by image, verdict and the package's name and version", () => {
    expect(ids(fromState(s, { image: "java-e363e44" }))).toEqual(["j1"]);
    expect(ids(fromState(s, { verdict: "tp" }))).toEqual(["j1"]);
    expect(ids(fromState(s, { q: "util-linux 2.38" }))).toEqual(["u1"]);
  });
});

describe("position", () => {
  const items = ["a", "b", "c"].map((id) => ({ id, open: true }));
  test("names the rows either side", () => {
    expect(position(items, "b")).toEqual({ index: 1, total: 3, open: true, prev: "a", next: "c" });
    expect(position(items, "a")).toEqual({ index: 0, total: 3, open: true, prev: undefined, next: "b" });
  });
  test("off the list, j goes to the first and k to the last", () => {
    expect(position(items, "z")).toEqual({ index: -1, total: 3, open: true, prev: "c", next: "a" });
  });

  // a, c and e are open; b and d are labeled
  const mixed = ["a", "b", "c", "d", "e"].map((id) => ({ id, open: "ace".includes(id) }));
  test("j and k walk the open rows only, and the pager counts them", () => {
    expect(position(mixed, "a")).toEqual({ index: 0, total: 3, open: true, prev: undefined, next: "c" });
    expect(position(mixed, "c")).toEqual({ index: 1, total: 3, open: true, prev: "a", next: "e" });
  });
  test("from a labeled row, j and k go to the nearest open rows", () => {
    expect(position(mixed, "d")).toEqual({ index: -1, total: 3, open: true, prev: "c", next: "e" });
  });
  test("⌥j and ⌥k walk every row", () => {
    expect(position(mixed, "c", true)).toEqual({ index: 2, total: 5, open: false, prev: "b", next: "d" });
  });
  test("a list with nothing open, such as one filtered to TP, walks every row", () => {
    const labeled = mixed.map((x) => ({ ...x, open: false }));
    expect(position(labeled, "b")).toEqual({ index: 1, total: 5, open: false, prev: "a", next: "c" });
  });
});

// the reported bug: "Label next" opened the right row at "9 of 12", because the gate's list was in
// report order while "next" picked by effect
describe("Label next lands at the top of what j walks", () => {
  const row = (id: string, verdict: string, effect: string) =>
    ({ id, vulnerability: id, package: { ref: "pkg:deb/debian/tar@1.34" }, verdict, inCandidate: true, inReference: false, effect });
  const s = { scans: { subjects: [] }, causes: [], subjects: [
    { name: "deb:1", slug: "deb-1", rows: [row("t1", "unlabeled", "counted"), row("f1", "fp", "counted"), row("t2", "unlabeled", "counted")] },
    { name: "java:1", slug: "java-1", rows: [row("j0", "tp", "decides"), row("j1", "unlabeled", "could-move"), row("j2", "unclear", "could-move")] },
  ] } as unknown as State;
  test("on the gate's list", () => {
    const next = nextOpenRow(gateRows(s))!;
    expect(next.id).toBe("j1");
    expect(position(fromState(s, {}), next.id!)).toMatchObject({ index: 0, total: 4, open: true, next: "j2" });
  });
  test("on a check's list, which the server sorts the same way", () => {
    const next = nextOpenRow(checkRows(cf))!;
    expect(position(check({}), next.row!)).toMatchObject({ index: 0, open: true });
  });
});

describe("nextOpen", () => {
  const items = [{ id: "a", open: true }, { id: "b", open: false }, { id: "c", open: true }, { id: "d", open: true }];
  test("is the next open row, wrapping round", () => {
    expect(nextOpen(items, "a")).toBe("c");
    expect(nextOpen(items, "d")).toBe("a");
  });
  test("skips the rows just labeled", () => {
    expect(nextOpen(items, "a", ["a", "c"])).toBe("d");
    expect(nextOpen(items, "a", ["c", "d"])).toBeUndefined();
  });
  test("off the list, starts from the top", () => {
    expect(nextOpen(items, "z")).toBe("a");
  });
});

// the finding page walks what the table shows: the same rows, filter and order, pkg and the purl
// search included, which the page's own filter once lacked
describe("j and k walk the table's rows", () => {
  const filters: Filters[] = [{}, { image: "java-e363e44" }, { verdict: "unlabeled" }, { hint: "yes" }, { q: "tar 2026" }, { pkg: "tar" }, { q: "pkg:maven" }, { image: "nope" }, { image: "deb-617d48d", verdict: "unlabeled", hint: "yes" }];
  const purl = (pkg: string) => `pkg:${pkg === "log4j-core" ? "maven/org.apache.logging.log4j" : "deb/debian"}/${pkg}@1.0`;
  const withPurl = { findings: findings.map((x) => ({ ...x, package: { ...x.package, purl: purl(x.package.name) } })) } as CheckFindings;
  for (const f of filters) {
    test(`on a check, ${JSON.stringify(f)}`, () => {
      const table = shownRows(checkRows(withPurl), f, f.image === "nope" ? null : f.image ?? null).flatMap((x) => (x.row ? [x.row] : []));
      expect(ids(fromCheck(withPurl, gate, f))).toEqual(table);
    });
  }
  test("the gate's Findings tab", () => {
    const st = {
      scans: { subjects: [] }, causes: [],
      subjects: [{ name: "deb:1", slug: "deb-1", rows: [
        { id: "a", vulnerability: "CVE-1", package: { ref: "pkg:deb/debian/tar@1.34%2Bdfsg" }, verdict: "unlabeled", inCandidate: true, inReference: false },
        { id: "b", vulnerability: "CVE-2", package: { ref: "pkg:deb/debian/mount@2.38" }, sourcePackage: "util-linux", verdict: "fp", inCandidate: false, inReference: true },
      ] }],
    } as unknown as State;
    for (const f of [{}, { pkg: "util-linux" }, { q: "1.34+dfsg" }, { verdict: "fp" } as Filters]) {
      expect(ids(fromState(st, f))).toEqual(shownRows(gateRows(st), f, null).map((x) => x.id));
    }
    expect(ids(fromState(st, { pkg: "util-linux" }))).toEqual(["b"]);
  });
});
