import { describe, expect, test } from "bun:test";
import type { Finding, State, StateRow } from "../gen/wire";
import { fromCheck, fromState, nextOpen, position } from "./neighbors";

const img = (slug: string) => ({ name: slug.replace(/-(\w+)$/, ":$1"), slug, ref: `ghcr.io/x/${slug}` });
const f = (row: string | undefined, image: string, vuln: string, pkg: string, label: string | null, hint = false): Finding => ({
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

describe("fromCheck", () => {
  test("keeps the check's order and drops what no finding page shows", () => {
    expect(ids(fromCheck(findings, {}))).toEqual(["a", "b", "c", "d"]);
  });
  test("filters by image, verdict, hint and search as the table does", () => {
    expect(ids(fromCheck(findings, { image: "java-e363e44" }))).toEqual(["c", "d"]);
    expect(ids(fromCheck(findings, { verdict: "unlabeled" }))).toEqual(["a", "b"]);
    expect(ids(fromCheck(findings, { verdict: "unclear" }))).toEqual(["c"]);
    expect(ids(fromCheck(findings, { hint: "yes" }))).toEqual(["a", "c"]);
    expect(ids(fromCheck(findings, { q: "tar 2026" }))).toEqual(["b"]);
    expect(ids(fromCheck(findings, { q: "java" }))).toEqual(["c", "d"]);
  });
  test("unclear stays open, tp and fp don't", () => {
    expect(fromCheck(findings, {}).map((x) => x.open)).toEqual([true, true, true, false]);
  });
});

describe("fromState", () => {
  const row = (id: string, vuln: string, ref: string, verdict: string, changed = true, hint?: string): StateRow =>
    ({ id, vulnerability: vuln, package: { ref }, verdict, inCandidate: true, inReference: !changed, hint: hint ? { id: "h", verdict: "tp", status: hint } : undefined } as StateRow);
  const s = {
    causes: [{ id: "c1", pending: ["u1"] }],
    subjects: [
      { name: "deb:617d48d", slug: "deb-617d48d", rows: [row("t1", "CVE-2005-2541", "pkg:deb/debian/tar@1.34", "unlabeled", true, "pending"), row("same", "CVE-1", "pkg:deb/debian/x@1", "unlabeled", false), row("u1", "CVE-2026-3184", "pkg:deb/debian/util-linux@2.38", "unlabeled")] },
      { name: "java:e363e44", slug: "java-e363e44", rows: [row("j1", "GHSA-jfh8-c2jp-5v3q", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "tp")] },
    ],
  } as unknown as State;
  test("is every changed row in report order", () => {
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
    expect(position(items, "b")).toEqual({ index: 1, total: 3, prev: "a", next: "c" });
    expect(position(items, "a")).toEqual({ index: 0, total: 3, prev: undefined, next: "b" });
  });
  test("off the list, j goes to the first and k to the last", () => {
    expect(position(items, "z")).toEqual({ index: -1, total: 3, prev: "c", next: "a" });
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
