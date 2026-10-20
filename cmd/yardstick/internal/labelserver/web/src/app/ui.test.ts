import { describe, expect, test } from "bun:test";
import { meterSpan } from "./ui";

describe("meterSpan", () => {
  test("the larger of value and limit sits at 80%", () => {
    expect(meterSpan(0.5, 0)).toEqual({ fill: 0.8, limit: 0 });
    expect(meterSpan(3, 12)).toEqual({ fill: 0.2, limit: 0.8 });
  });
  test("nothing measured and no limit is an empty track", () => {
    expect(meterSpan(0, 0)).toEqual({ fill: 0, limit: 0 });
  });
  test("a value below zero reads as none", () => {
    expect(meterSpan(-0.2, 0.1)).toEqual({ fill: 0, limit: 0.8 });
  });
});
