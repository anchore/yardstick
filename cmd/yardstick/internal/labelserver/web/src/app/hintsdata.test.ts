import { describe, expect, test } from "bun:test";
import type { CrossFinding, HintEntry } from "../gen/wire";
import { aloneWords, hintedRows, hintsHref, imageHints, inScope, parseScope, preselected, previewLabels, rowCount, stillOpen, waitWords, workNumbers } from "./hintsdata";

const deb = { name: "deb:617d48d", slug: "deb-617d48d", ref: "deb" }, java = { name: "java:e363e44", slug: "java-e363e44", ref: "java" };

// hint is a seed-shaped hint: rows as [row, image, package], each in the gates given
function hint(id: string, verdict: string, rows: [string, typeof deb, string][], gates: string[], o: Partial<HintEntry> = {}): HintEntry {
  return {
    id, verdict, confidence: "medium", status: "pending", kind: "proposal", author: {} as HintEntry["author"], group: "decides", replaces: false,
    rows: rows.map(([row, image, pkg]) => ({ row, image, vulnerability: `V-${id}`, package: { name: pkg }, direction: "added", gates })),
    gates: gates.map((gate) => ({ gate, rows: rows.map(([r]) => r), outcome: "fail", after: "fail" })),
    ...o,
  } as HintEntry;
}

// the seed's five hints: tar in both gates, gzip in deb-npm, util-linux (a cause, 4 rows) and the
// two log4j proposals (two jars each), vc5p replacing an unclear label
const tar = hint("tar", "fp", [["t1", deb, "tar"]], ["deb-java", "deb-npm"]);
const gzip = hint("gzip", "fp", [["g1", deb, "gzip"]], ["deb-npm"]);
const util = hint("util", "tp", [["u1", deb, "util-linux"], ["u2", deb, "libblkid1"], ["u3", deb, "libmount1"], ["u4", deb, "mount"]], ["deb-java"], { kind: "cause" });
const jfh8 = hint("jfh8", "tp", [["j1", java, "log4j-core"], ["j2", java, "log4j-core"]], ["deb-java"]);
const vc5p = hint("vc5p", "tp", [["v1", java, "log4j-core"], ["v2", java, "log4j-core"]], ["deb-java"], { replaces: true });
const all = [tar, gzip, util, jfh8, vc5p];

describe("the review page's scope", () => {
  test("round-trips through its URL", () => {
    expect(hintsHref({})).toBe("/ui/hints");
    const s = { gate: "deb-java", image: deb.slug, low: true };
    expect(parseScope(new URL(hintsHref(s), "http://x").search)).toEqual(s);
    expect(parseScope("?low=0")).toEqual({});
  });

  test("filters by gate and image, and counts the low-confidence hints it leaves out", () => {
    const low = hint("low", "tp", [["l1", java, "x"]], ["deb-java"], { confidence: "low" });
    expect(inScope([...all, low], {}).hints).toHaveLength(5);
    expect(inScope([...all, low], {}).low).toBe(1);
    expect(inScope([...all, low], { low: true }).hints).toHaveLength(6);
    expect(inScope(all, { gate: "deb-npm" }).hints.map((h) => h.id)).toEqual(["tar", "gzip"]);
    expect(inScope([...all, low], { image: java.slug })).toEqual({ hints: [jfh8, vc5p], low: 1 });
  });
});

test("preselection is medium confidence and up, never a hint replacing a person's label", () => {
  expect(all.filter(preselected).map((h) => h.id)).toEqual(["tar", "gzip", "util", "jfh8"]);
  expect(preselected({ ...tar, confidence: "high" })).toBe(true);
  expect(preselected({ ...tar, confidence: "low" })).toBe(false);
  expect(preselected({ ...tar, confidence: "" })).toBe(false);
});

test("a row in two gates counts once", () => {
  expect(rowCount(all.filter(preselected))).toBe(8);
  expect(rowCount(all)).toBe(10);
});

describe("previewLabels", () => {
  test("unions the selected hints' rows per gate, with each hint's verdict", () => {
    const p = previewLabels([tar, gzip, jfh8]);
    expect(Object.fromEntries(p)).toEqual({ "deb-java": { t1: "fp", j1: "tp", j2: "tp" }, "deb-npm": { t1: "fp", g1: "fp" } });
  });
  test("leaves out a hint that closes nothing, and keeps the first of two that disagree", () => {
    const unclear = hint("u", "unclear", [["t1", deb, "tar"]], ["deb-java"]);
    const other = hint("o", "tp", [["t1", deb, "tar"]], ["deb-java"]);
    expect(Object.fromEntries(previewLabels([unclear, tar, other]))).toEqual({ "deb-java": { t1: "fp" }, "deb-npm": { t1: "fp" } });
  });
});

test("hintedRows are each gate's covered rows", () => {
  const h = hintedRows(all);
  expect(h.get("deb-java")?.size).toBe(9);
  expect([...(h.get("deb-npm") ?? [])]).toEqual(["t1", "g1"]);
});

test("imageHints counts a gate's hints and rows per image, and the ones replacing a label", () => {
  const java1 = imageHints(all, "deb-java");
  expect(java1.get(deb.slug)).toEqual({ hints: 2, rows: 5, replaces: 0 });
  expect(java1.get(java.slug)).toEqual({ hints: 2, rows: 4, replaces: 1 });
  expect(imageHints(all, "deb-npm").get(deb.slug)).toEqual({ hints: 2, rows: 2, replaces: 0 });
});

describe("stillOpen", () => {
  const open = [
    { gate: "deb-java", row: "t1", vuln: "V-tar", pkg: "tar" }, { gate: "deb-java", row: "h1", vuln: "CVE-2026-18508", pkg: "tar" },
    { gate: "deb-java", row: "v1", vuln: "V-vc5p", pkg: "log4j-core" }, { gate: "deb-java", row: "v2", vuln: "V-vc5p", pkg: "log4j-core" },
    { gate: "deb-npm", row: "t1", vuln: "V-tar", pkg: "tar" }, { gate: "deb-npm", row: "b1", vuln: "GHSA-67hx", pkg: "@babel/traverse" },
  ];
  test("lists rows with no hint and each unchecked hint once, across gates", () => {
    expect(stillOpen(open, all, new Set(["tar", "gzip", "util", "jfh8"]))).toEqual([
      { text: "tar CVE-2026-18508", gates: ["deb-java"], why: "no hint" },
      { text: "log4j-core V-vc5p (2 matches)", gates: ["deb-java"], why: "hint unchecked" },
      { text: "@babel/traverse GHSA-67hx", gates: ["deb-npm"], why: "no hint" },
    ]);
  });
  test("an unchecked hint in two gates is one line naming both", () => {
    expect(stillOpen(open, all, new Set(["vc5p"]))[0]).toEqual({ text: "tar V-tar", gates: ["deb-java", "deb-npm"], why: "hint unchecked" });
  });
});

test("aloneWords says what every hint does to a gate", () => {
  expect(aloneWords("undecided", "pass")).toBe("passes on hints alone");
  expect(aloneWords("fail", "undecided")).toBe("undecided on hints alone");
  expect(aloneWords("fail", "fail")).toBe("hints alone don't change it");
  expect(aloneWords("pass", "pass")).toBe("passes already");
});

test("workNumbers count findings once across rows, hinted by a proposal or a cause", () => {
  const f = (vulnerability: string, ref: string, o: Partial<CrossFinding> = {}) => ({ vulnerability, image: "img", package: { ref }, in: [], ...o }) as unknown as CrossFinding;
  const pending = { status: "pending" } as CrossFinding["hint"];
  // log4j's two jars are two rows and one finding
  const rows = [f("tar", "deb/tar", { hint: pending }), f("util", "deb/util", { cause: { id: "c", title: "", gate: "g" } }),
    f("jfh8", "maven/log4j", { hint: pending }), f("jfh8", "maven/log4j", { hint: pending }), f("hand", "deb/tar"), f("babel", "npm/babel")];
  expect(workNumbers(rows)).toEqual({ open: 5, hinted: 3, needYou: 2 });
});

test("waitWords name the first few rows a gate still waits on", () => {
  const r = (n: number) => ({ gate: "g", row: `r${n}`, vuln: `CVE-${n}`, pkg: "p" });
  expect(waitWords("deb-java", [r(1)])).toBe("deb-java then waits on 1 match with no hint: p CVE-1.");
  expect(waitWords("g", [r(1), r(2), r(3), r(4)])).toBe("g then waits on 4 matches with no hint: p CVE-1, p CVE-2, p CVE-3 and 1 more.");
  expect(waitWords("deb-java", [r(1)], false)).toBe("deb-java waits on 1 match with no hint: p CVE-1.");
});
