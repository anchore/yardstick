import { describe, expect, test } from "bun:test";
import { matches, noCounts, order, railKey, splitName, sumCounts, type RailImage } from "./images";

const img = (name: string, open: number, ref = `ghcr.io/anchore/test-images/${name}`): RailImage =>
  ({ name, slug: name.replace(":", "-"), ref, counts: { ...noCounts, open, total: open } });

describe("splitName", () => {
  test("splits before the tag", () => {
    expect(splitName("vulnerabilities-package-name-normalization:984794b")).toEqual(["vulnerabilities-package-name-normalization", ":984794b"]);
    expect(splitName("core")).toEqual(["core", ""]);
  });
  test("a registry port is not a tag", () => {
    expect(splitName("localhost:5000/core")).toEqual(["localhost:5000/core", ""]);
    expect(splitName("localhost:5000/core:1.2")).toEqual(["localhost:5000/core", ":1.2"]);
  });
});

describe("sumCounts", () => {
  test("adds every field", () => {
    const a = { tp: 1, fp: 2, unclear: 0, hinted: 3, open: 4, total: 7 };
    expect(sumCounts([a, a])).toEqual({ tp: 2, fp: 4, unclear: 0, hinted: 6, open: 8, total: 14 });
    expect(sumCounts([])).toEqual(noCounts);
  });
});

describe("order", () => {
  const images = [img("a", 1), img("b", 5), img("c", 0), img("d", 5)];
  test("gate order is the input order", () => expect(order(images, "gate")).toEqual([0, 1, 2, 3]));
  test("most open first, ties in gate order", () => expect(order(images, "open")).toEqual([1, 3, 0, 2]));
});

describe("matches", () => {
  const golang = img("grype-quality-golang:d89207b", 5);
  test("every word, in the name or the reference", () => {
    expect(matches(golang, "GOLANG")).toBe(true);
    expect(matches(golang, "anchore golang")).toBe(true);
    expect(matches(golang, "golang java")).toBe(false);
    expect(matches(golang, "  ")).toBe(true);
  });
});

describe("railKey", () => {
  const all = [0, 1, 2, 3, 4];
  test("digits pick a position when there is an image there", () => {
    expect(railKey("0", 4, 2, all)).toBe(0);
    expect(railKey("4", 4, 0, all)).toBe(4);
    expect(railKey("5", 4, 0, all)).toBeNull();
  });
  test("[ and ] step through the shown positions and stop at the ends", () => {
    expect(railKey("]", 4, 0, all)).toBe(1);
    expect(railKey("]", 4, 4, all)).toBe(4);
    expect(railKey("[", 4, 0, all)).toBe(0);
    expect(railKey("]", 4, 1, [0, 3, 1])).toBe(1);
    expect(railKey("[", 4, 1, [0, 3, 1])).toBe(3);
  });
  test("stepping from a hidden position starts at an end", () => {
    expect(railKey("]", 4, 2, [0, 3])).toBe(0);
    expect(railKey("[", 4, 2, [0, 3])).toBe(3);
  });
  test("other keys are not the rail's", () => {
    expect(railKey("j", 4, 0, all)).toBeNull();
    expect(railKey("]", 4, 0, [])).toBeNull();
  });
});
