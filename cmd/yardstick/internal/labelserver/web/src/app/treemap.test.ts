import { describe, expect, test } from "bun:test";
import { type Rect, squarify } from "./treemap";

const rect: Rect = { x: 10, y: 20, w: 400, h: 200 };
const close = (a: number, b: number) => expect(Math.abs(a - b)).toBeLessThan(1e-6);

describe("squarify", () => {
  const items = [{ key: "a", value: 6 }, { key: "b", value: 6 }, { key: "c", value: 4 }, { key: "d", value: 3 }, { key: "e", value: 2 }, { key: "f", value: 2 }, { key: "g", value: 1 }];
  const out = squarify(items, rect);

  test("every item gets a block, biggest first, with its share of the area", () => {
    expect(out.map((b) => b.key)).toEqual(["a", "b", "c", "d", "e", "f", "g"]);
    const total = items.reduce((s, i) => s + i.value, 0);
    for (const b of out) close(b.w * b.h, (b.value / total) * rect.w * rect.h);
  });
  test("the blocks tile the rect without leaving it", () => {
    close(out.reduce((s, b) => s + b.w * b.h, 0), rect.w * rect.h);
    for (const b of out) {
      expect(b.x).toBeGreaterThanOrEqual(rect.x - 1e-6);
      expect(b.y).toBeGreaterThanOrEqual(rect.y - 1e-6);
      expect(b.x + b.w).toBeLessThanOrEqual(rect.x + rect.w + 1e-6);
      expect(b.y + b.h).toBeLessThanOrEqual(rect.y + rect.h + 1e-6);
    }
  });
  test("the first row runs along the shorter side", () => {
    // wide rect: the first blocks stack top to bottom in one column at the left edge
    expect(out[0].x).toBe(rect.x);
    expect(out[1].x).toBe(rect.x);
    close(out[1].y, out[0].y + out[0].h);
  });
  test("one item fills the rect; items with no value are left out", () => {
    const one = squarify([{ value: 5 }, { value: 0 }], rect);
    expect(one).toHaveLength(1);
    expect(one[0]).toMatchObject({ x: rect.x, y: rect.y, w: rect.w, h: rect.h });
  });
  test("nothing to lay out, or nowhere to put it, is no blocks", () => {
    expect(squarify([], rect)).toEqual([]);
    expect(squarify([{ value: 1 }], { x: 0, y: 0, w: 0, h: 10 })).toEqual([]);
  });
});
