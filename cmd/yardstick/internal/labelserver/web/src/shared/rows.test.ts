import { describe, expect, test } from "bun:test";
import { decoded, outcome, outcomeRank, pkgOf } from "./rows";

describe("decoded", () => {
  test("undoes a purl's percent escapes", () => {
    expect(decoded("pkg:deb/debian/libstdc%2B%2B6@12.2.0-14%2Bdeb12u1?arch=arm64")).toBe("pkg:deb/debian/libstdc++6@12.2.0-14+deb12u1?arch=arm64");
    expect(decoded("1%3A2.38.1-5%2Bdeb12u3")).toBe("1:2.38.1-5+deb12u3");
  });
  test("leaves a malformed escape and a plain value as they are", () => {
    expect(decoded("100%")).toBe("100%");
    expect(decoded("v0.0.0-20230905200255-921286631fa9")).toBe("v0.0.0-20230905200255-921286631fa9");
  });
});

describe("pkgOf", () => {
  test("names and versions read decoded", () => {
    expect(pkgOf("pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdeb12u1?arch=arm64&distro=debian-12")).toEqual({ type: "deb", name: "tar", version: "1.34+dfsg-1.2+deb12u1" });
    expect(pkgOf("pkg:golang/golang.org/x/net@v0.0.0-20230905200255-921286631fa9")).toEqual({ type: "golang", name: "net", version: "v0.0.0-20230905200255-921286631fa9" });
    expect(pkgOf("pkg:generic/odd@50%")).toMatchObject({ version: "50%" });
  });
});

describe("outcome", () => {
  test("a label and the side that reports it say what the candidate did", () => {
    expect(outcome("added", "tp")).toEqual({ kind: "good", text: "fixed FN" });
    expect(outcome("added", "fp")).toEqual({ kind: "bad", text: "new FP" });
    expect(outcome("dropped", "tp")).toEqual({ kind: "bad", text: "new FN" });
    expect(outcome("dropped", "fp")).toEqual({ kind: "good", text: "fixed FP" });
  });
  test("an open row names the risk labeling settles", () => {
    expect(outcome("added", "unlabeled")).toEqual({ kind: "open", text: "new FP?" });
    expect(outcome("dropped", "unclear")).toEqual({ kind: "open", text: "new FN?" });
    expect(outcome("dropped", undefined)).toEqual({ kind: "open", text: "new FN?" });
  });
  test("a match both or neither scan reports has none", () => {
    expect(outcome("both", "tp")).toBeNull();
    expect(outcome("neither", undefined)).toBeNull();
  });
  test("regressions sort first, then fixes, then open rows", () => {
    const xs = [outcome("added", undefined), outcome("dropped", "fp"), null, outcome("dropped", "tp")];
    expect(xs.sort((a, b) => outcomeRank(a) - outcomeRank(b)).map((o) => o?.text ?? null)).toEqual(["new FN", "fixed FP", "new FP?", null]);
  });
});
