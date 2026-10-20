import { describe, expect, test } from "bun:test";
import { decoded, pkgOf } from "./rows";

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
