import { describe, expect, test } from "bun:test";
import { imageRelease, nsHuman, sameRelease } from "./names";
import type { Row } from "./rows";

const row = (ref: string, distro?: string): Row => ({ id: "r", match: "m", row: "r", vulnerability: "CVE-1", group: "g", sourcePackage: "p", package: { ref }, verdict: "unlabeled", inCandidate: true, inReference: false, candidate: distro ? { distro } : undefined });

describe("names", () => {
  test("namespaces read as distro releases, advisories or NVD", () => {
    expect(nsHuman("ubuntu:distro:ubuntu:24.4")).toBe("Ubuntu 24.04 (noble)");
    expect(nsHuman("ubuntu:distro:ubuntu:22.04+esm")).toBe("Ubuntu 22.04 (jammy) ESM");
    expect(nsHuman("redhat:distro:redhat:9")).toBe("RHEL 9");
    expect(nsHuman("echo:distro:debian:12")).toBe("Debian 12 (bookworm) · echo data");
    expect(nsHuman("github:language:python")).toBe("GitHub advisories · python");
    expect(nsHuman("nvd:cpe")).toBe("NVD (CPE)");
    expect(nsHuman("odd")).toBe("odd");
  });
  test("an image's release comes from grype's distro, else the purl's qualifier", () => {
    expect(imageRelease(row("pkg:deb/debian/zlib@1", "debian 12"))).toEqual({ distro: "debian", version: "12" });
    expect(imageRelease(row("pkg:rpm/redhat/vim@8?distro=rhel-8.6"))).toEqual({ distro: "redhat", version: "8.6" });
    expect(imageRelease(row("pkg:npm/left-pad@1"))).toBeNull();
  });
  test("a namespace is the image's own release on the same version, or a Red Hat major", () => {
    expect(sameRelease("debian:distro:debian:12", { distro: "debian", version: "12" })).toBe(true);
    expect(sameRelease("debian:distro:debian:11", { distro: "debian", version: "12" })).toBe(false);
    expect(sameRelease("redhat:distro:redhat:8", { distro: "redhat", version: "8.6" })).toBe(true);
    expect(sameRelease("github:language:go", { distro: "debian", version: "12" })).toBe(false);
    expect(sameRelease("debian:distro:debian:12", null)).toBe(false);
  });
});
