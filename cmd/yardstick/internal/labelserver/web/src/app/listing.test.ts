import { describe, expect, test } from "bun:test";
import type { CheckFindings, GateLabel, State } from "../gen/wire";
import { checkRows, chipCounts, chipFilters, chipOf, gateRows, inChip, mergeLabels, nextOpen, pageInfo, shortSource, square, sumTally, type FRow } from "./listing";

const img = { name: "grype-quality-java-log4j-two-jars:e363e44", slug: "grype-quality-java-log4j-two-jars-e363e44", ref: "oci:ghcr.io/anchore/test-images/grype-quality-java-log4j-two-jars:e363e44@sha256:e363" };

const row = (id: string, label: FRow["label"], extra: Partial<FRow> = {}): FRow =>
  ({ id, row: id, label, vuln: "CVE-1", pkg: "tar", version: "1.34", purl: "pkg:deb/debian/tar@1.34", src: "tar", image: img, change: "added", hint: null, effect: "counted", ...extra });

describe("chips", () => {
  const rows = [row("a", "unlabeled", { hint: { verdict: "tp", kind: "proposal" } }), row("b", "unlabeled"), row("c", "tp"), row("d", "fp"), row("e", "unclear", { hint: { verdict: "tp", kind: "cause" } })];
  test("counts each chip over the rows given", () => {
    expect(chipCounts(rows)).toEqual({ all: 5, unlabeled: 2, tp: 1, fp: 1, unclear: 1, hint: 2 });
  });
  test("a chip is its filters and back", () => {
    for (const c of ["all", "unlabeled", "tp", "fp", "unclear", "hint"] as const) expect(chipOf(chipFilters(c) as never)).toBe(c);
    expect(rows.filter((r) => inChip(r, "hint")).map((r) => r.id)).toEqual(["a", "e"]);
  });
  test("label next prefers an open row a label can still move", () => {
    expect(nextOpen([row("x", "tp"), row("y", "unlabeled"), row("z", "unclear", { effect: "could-move" })])?.id).toBe("z");
    expect(nextOpen([row("x", "tp"), row("y", "unlabeled")])?.id).toBe("y");
    expect(nextOpen([row("x", "tp"), row("n", "unlabeled", { row: undefined })])).toBeUndefined();
  });
});

describe("pageInfo", () => {
  test("pages of 50, 1-based, clamped", () => {
    expect(pageInfo(120)).toEqual({ page: 1, pages: 3, offset: 0, from: 1, to: 50 });
    expect(pageInfo(120, 3)).toEqual({ page: 3, pages: 3, offset: 100, from: 101, to: 120 });
    expect(pageInfo(120, 9).page).toBe(3);
    expect(pageInfo(0)).toEqual({ page: 1, pages: 1, offset: 0, from: 0, to: 0 });
  });
});

describe("the gate list", () => {
  const t = (open: number, total: number) => ({ tp: 0, fp: total - open, unclear: 0, hinted: 0, open, total });
  test("an image's square is open, changed or none", () => {
    expect([square(t(2, 4)), square(t(0, 3)), square(t(0, 0)), square(undefined)]).toEqual(["open", "chg", "none", "none"]);
  });
  test("tallies add up", () => {
    expect(sumTally([t(2, 4), t(1, 1)])).toEqual({ tp: 0, fp: 2, unclear: 0, hinted: 0, open: 3, total: 5 });
  });
});

describe("shortSource", () => {
  test("a local corpus is its directory's name, a repository keeps its ref", () => {
    expect(shortSource("/private/var/folders/x/T/workspace/claims")).toBe("claims");
    expect(shortSource("/tmp/workspace/claims/")).toBe("claims");
    expect(shortSource("github.com/anchore/match-claims@main")).toBe("match-claims@main");
    expect(shortSource("https://github.com/anchore/match-claims@v1.2")).toBe("match-claims@v1.2");
    expect(shortSource("claims")).toBe("claims");
  });
});

describe("rows", () => {
  test("a gate's changed rows, with the cause a row is pending in as its hint", () => {
    const st = {
      scans: { subjects: [{ name: img.name, slug: img.slug, ref: img.ref }] },
      causes: [{ id: "c1", verdict: "tp", confidence: "medium", pending: ["r3"] }],
      subjects: [{ name: img.name, slug: img.slug, rows: [
        { id: "r1", vulnerability: "GHSA-1", package: { ref: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }, verdict: "unlabeled", inCandidate: true, inReference: false, hint: { verdict: "tp", confidence: "medium", status: "pending" }, effect: "could-move" },
        { id: "r2", vulnerability: "GHSA-2", package: { ref: "pkg:deb/debian/tar@1.34" }, verdict: "fp", inCandidate: false, inReference: true, effect: "decides" },
        { id: "r3", vulnerability: "GHSA-3", package: { ref: "pkg:deb/debian/mount@2.38" }, verdict: "unlabeled", inCandidate: true, inReference: false, sourcePackage: "util-linux", effect: "counted" },
        { id: "r4", vulnerability: "GHSA-4", package: { ref: "pkg:deb/debian/libc6@2.36" }, verdict: "tp", inCandidate: true, inReference: true },
      ] }],
    } as unknown as State;
    const rs = gateRows(st);
    expect(rs.map((r) => `${r.id} ${r.label} ${r.change} ${r.effect} ${r.hint?.kind ?? "-"} ${r.src}`)).toEqual([
      "r1 unlabeled added could-move proposal log4j-core",
      "r2 fp dropped decides - tar",
      "r3 unlabeled added counted cause util-linux",
    ]);
    expect(rs[0]).toMatchObject({ pkg: "log4j-core", version: "2.14.1", image: img });
    expect(rs[2].hint).toEqual({ verdict: "tp", confidence: "medium", kind: "cause", cause: "c1" });
  });

  test("a check's findings, an unmet expectation with no row keyed by what it is about", () => {
    const f = { findings: [
      { row: "r1", image: img, vulnerability: "GHSA-1", package: { name: "log4j-core", version: "2.14.1", purl: "pkg:maven/x/log4j-core@2.14.1" }, direction: "added", label: { verdict: "unclear", source: "s" }, hint: { verdict: "tp", kind: "proposal" }, effect: "could-move" },
      { image: img, vulnerability: "GHSA-9", package: { name: "", purl: "pkg:deb/debian/tar@1.34" }, direction: "neither", label: { verdict: "tp", source: "" }, hint: null, effect: "decides" },
    ] } as unknown as CheckFindings;
    const rs = checkRows(f);
    expect(rs.map((r) => `${r.id} ${r.label} ${r.effect} ${r.pkg} ${r.version}`)).toEqual([
      "r1 unclear could-move log4j-core 2.14.1",
      `${img.slug}|pkg:deb/debian/tar@1.34|GHSA-9 tp decides tar 1.34`,
    ]);
    expect(rs[1].row).toBeUndefined();
  });
});

describe("mergeLabels", () => {
  const l = (vuln: string, image: typeof img | null, row?: string): GateLabel =>
    ({ verdict: "fp", vulnerability: vuln, package: { name: "tar", purl: "pkg:deb/debian/tar" }, image, source: "/w/claims", author: "e2e", firstIssued: "", lastUpdated: `2026-10-0${vuln.length % 9}`, decides: [], row });
  test("a label two gates count is listed once, opening in a gate where it sits on a row", () => {
    const out = mergeLabels([
      { gate: "deb-npm", labels: [l("CVE-1", img), l("CVE-22", null)] },
      { gate: "deb-java", labels: [l("CVE-1", img, "r1"), l("CVE-333", img)] },
    ]);
    expect(out.map((x) => `${x.vulnerability} ${x.gates.join(",")} ${x.gate} ${x.row ?? "-"}`)).toEqual([
      "CVE-333 deb-java deb-java -",
      "CVE-22 deb-npm deb-npm -",
      "CVE-1 deb-npm,deb-java deb-java r1",
    ]);
  });
});
