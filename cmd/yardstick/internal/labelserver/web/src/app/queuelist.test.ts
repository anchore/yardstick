import { describe, expect, test } from "bun:test";
import type { QueueEntry, QueueGate } from "../gen/wire";
import { position } from "./neighbors";
import { entryGate, exitRoute, newlyDone, ordered, pickNext, queueFor, walk } from "./queuelist";

const gate = (name: string, rows: number, settled = false) => ({ name, rows, settled, outcome: "fail", open: rows, compared: "", images: 2 }) as QueueGate;
const entry = (row: string, ...gates: string[]) =>
  ({ row, key: row, effect: "counted", vulnerability: "CVE", package: { ref: "p" }, sourcePackage: "p", image: "deb", in: gates.map((g) => ({ gate: g, row, dir: "dropped" })), bears: 0, flips: 0 }) as QueueEntry;
const rows = (es: QueueEntry[]) => es.map((e) => e.row);

describe("queueFor", () => {
  test("is every gate from the gates screen and the flow's pages", () => {
    expect(queueFor({ level: "gates", tab: "gates", filters: {} })).toEqual({ level: "queue", filters: {} });
    expect(queueFor({ level: "history", filters: {} })).toEqual({ level: "queue", filters: {} });
    // the research page's image filter narrows it as a gate's does
    expect(queueFor({ level: "research", scope: "gate:deb-java", filters: { image: "core" } })).toEqual({ level: "queue", scope: "image:core", filters: {} });
  });
  test("is the gate from a gate or finding, with a check's rows first from a check", () => {
    expect(queueFor({ level: "gate", gate: "deb-java", tab: "findings", filters: {} })).toEqual({ level: "queue", scope: "gate:deb-java", filters: {} });
    expect(queueFor({ level: "check", gate: "deb-java", check: "f1NotWorse", filters: {} })).toEqual({ level: "queue", scope: "gate:deb-java", check: "f1NotWorse", filters: {} });
    expect(queueFor({ level: "finding", gate: "deb-npm", check: null, row: "x", filters: {} })).toEqual({ level: "queue", scope: "gate:deb-npm", filters: {} });
  });
  test("is the image an image filter names", () => {
    expect(queueFor({ level: "gate", gate: "deb-java", tab: "checks", filters: { image: "npm" } })).toEqual({ level: "queue", scope: "image:npm", filters: {} });
  });
  test("keeps a queue's own scope, without its row", () => {
    expect(queueFor({ level: "queue", row: "x", scope: "gate:g", check: "c", filters: {} })).toEqual({ level: "queue", scope: "gate:g", check: "c", low: undefined, filters: {} });
  });
});

test("exitRoute goes back to the check, gate or gates the queue was entered from", () => {
  expect(exitRoute({ level: "queue", scope: "gate:g", check: "c", filters: {} })).toEqual({ level: "check", gate: "g", check: "c", filters: {} });
  expect(exitRoute({ level: "queue", scope: "gate:g", filters: {} })).toEqual({ level: "gate", gate: "g", tab: "checks", filters: {} });
  expect(exitRoute({ level: "queue", scope: "image:npm", filters: {} })).toEqual({ level: "gates", tab: "gates", filters: {} });
});

describe("entryGate", () => {
  // the tar row is in both gates; once gzip is labeled deb-npm is settled
  const tar = entry("0fe9fc814bcd060a", "deb-npm", "deb-java");
  test("is the closest gate to done", () => {
    expect(entryGate(tar, [gate("deb-npm", 3), gate("deb-java", 10)])).toBe("deb-npm");
  });
  test("passes over a settled gate", () => {
    expect(entryGate(tar, [gate("deb-npm", 2, true), gate("deb-java", 10)])).toBe("deb-java");
  });
  test("is the scope's gate when the row is in it", () => {
    expect(entryGate(tar, [gate("deb-npm", 3), gate("deb-java", 10)], "gate:deb-java")).toBe("deb-java");
  });
});

test("ordered puts the named rows first, then each list, each row once", () => {
  const a = entry("a", "g"), b = entry("b", "g"), c = entry("c", "h"), d = entry("d", "h");
  expect(rows(ordered(["b", "zz"], [a, b], [c, a, d]))).toEqual(["b", "a", "c", "d"]);
});

describe("pickNext", () => {
  const es = ["a", "b", "c"].map((r) => entry(r, "g"));
  test("is the head of the fresh queue, past what was just written", () => {
    expect(pickNext(es, ["a"], [])).toBe("b");
  });
  test("passes over skipped rows until only they are left", () => {
    expect(pickNext(es, [], ["a", "b"])).toBe("c");
    expect(pickNext(es, ["c"], ["a", "b"])).toBe("a");
    expect(pickNext([], [], [])).toBeUndefined();
  });
});

describe("walk", () => {
  const es = ["c", "d"].map((r) => entry(r, "g"));
  const done = [{ row: "a", gate: "g" }, { row: "b", gate: "g" }];
  test("skip labeled steps over the done rows", () => {
    expect(position(walk(es, done), "c")).toMatchObject({ index: 0, total: 2, prev: undefined, next: "d" });
  });
  test("with skip labeled off, k goes back to what was just labeled", () => {
    expect(position(walk(es, done), "c", true)).toMatchObject({ index: 2, total: 4, prev: "b", next: "d" });
  });
});

test("newlyDone is what the last snapshot had and the fresh queue lacks", () => {
  const seen = [{ row: "a", gate: "g" }, { row: "b", gate: "g" }, { row: "c", gate: "h" }];
  expect(newlyDone(seen, [entry("c", "h")], [{ row: "a", gate: "g" }])).toEqual([{ row: "b", gate: "g" }]);
});
