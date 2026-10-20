import { describe, expect, test } from "bun:test";
import { compare, countBy, filterRows, groupRows, nextSort, sortRows } from "./table";

interface F { id: string; vuln: string; image: string; effect: number | null }
const rows: F[] = [
  { id: "a", vuln: "CVE-2019-10", image: "core", effect: 2 },
  { id: "b", vuln: "CVE-2019-9", image: "grype-quality-golang:d89207b", effect: null },
  { id: "c", vuln: "GHSA-qq97-vm5h-rrhg", image: "core", effect: 1 },
  { id: "d", vuln: "cve-2019-9", image: "ubuntu", effect: 1 },
];
const ids = (rs: F[]) => rs.map((r) => r.id);

describe("compare", () => {
  test("numbers numerically, text naturally and without case", () => {
    expect(compare(9, 10)).toBeLessThan(0);
    expect(compare("CVE-2019-9", "CVE-2019-10")).toBeLessThan(0);
    expect(compare("cve-2019-9", "CVE-2019-9")).toBe(0);
  });
  test("empty cells go last either way", () => {
    expect(compare(null, 1, "asc")).toBeGreaterThan(0);
    expect(compare(null, 1, "desc")).toBeGreaterThan(0);
    expect(compare("", undefined)).toBe(0);
  });
});

describe("sortRows", () => {
  test("sorts a copy, stably", () => {
    expect(ids(sortRows(rows, (r) => r.vuln))).toEqual(["b", "d", "a", "c"]);
    expect(ids(sortRows(rows, (r) => r.effect))).toEqual(["c", "d", "a", "b"]);
    expect(ids(sortRows(rows, (r) => r.effect, "desc"))).toEqual(["a", "c", "d", "b"]);
    expect(ids(rows)).toEqual(["a", "b", "c", "d"]);
  });
});

describe("filterRows", () => {
  const text = (r: F) => `${r.vuln} ${r.image}`;
  test("every word, any case", () => {
    expect(ids(filterRows(rows, "core CVE", text))).toEqual(["a"]);
    expect(ids(filterRows(rows, "GOLANG", text))).toEqual(["b"]);
    expect(ids(filterRows(rows, "   ", text))).toEqual(["a", "b", "c", "d"]);
  });
});

describe("groupRows and countBy", () => {
  test("groups in first-seen order", () => {
    expect(groupRows(rows, (r) => r.image).map((g) => [g.key, ids(g.rows)])).toEqual([
      ["core", ["a", "c"]], ["grype-quality-golang:d89207b", ["b"]], ["ubuntu", ["d"]],
    ]);
  });
  test("counts per key", () => {
    expect(countBy(rows, (r) => r.image)).toEqual({ core: 2, "grype-quality-golang:d89207b": 1, ubuntu: 1 });
  });
});

describe("nextSort", () => {
  test("a new column sorts ascending, the same one flips", () => {
    expect(nextSort(null, "vuln")).toEqual({ key: "vuln", dir: "asc" });
    expect(nextSort({ key: "vuln", dir: "asc" }, "vuln")).toEqual({ key: "vuln", dir: "desc" });
    expect(nextSort({ key: "vuln", dir: "desc" }, "image")).toEqual({ key: "image", dir: "asc" });
  });
});
