import { describe, expect, test } from "bun:test";
import { steps } from "./matchpath";
import type { Row } from "./rows";
import { whyTitle } from "./words";

// a CPE match only the reference reported, on a secureos package the candidate's distro record says
// is not affected
const nak: Row = {
  id: "r", match: "m", row: "r", vulnerability: "CVE-2026-4438", group: "g", sourcePackage: "glibc-2.42", verdict: "unlabeled",
  package: { ref: "pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09" }, inCandidate: false, inReference: true,
  reference: { namespace: "nvd:cpe", matchTypes: ["cpe-match"], cpes: ["cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*"], distro: "secureos 2025.09.09" },
  why: { key: "record/distro-not-affected", to: "secureos:distro:secureos:rolling", secondary: [{ key: "record/same-but-unmatched" }] },
  candidateRecords: [
    { vulnerability: "CVE-2026-4438", namespace: "nvd:cpe", cpe: "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*" },
    { vulnerability: "CVE-2026-4438", namespace: "secureos:distro:secureos:rolling", package: "glibc-2.42", constraints: ["< 0"], fixStates: ["fixed"], fixVersions: ["0"] },
  ],
};

describe("match path", () => {
  test("a side whose distro says not affected ends in dropped, on the distro's record", () => {
    const s = steps(nak, "candidate", undefined, { distro: "secureos", version: "2025.09.09" });
    expect(s.map((x) => x.k)).toEqual(["package", "searched", "record", "result"]);
    expect(s[1].t).toBe("SecureOS rolling");
    expect(s[2].sub).toBe("glibc-2.42 not affected · fixed in 0");
    expect(s[3]).toMatchObject({ t: "dropped", sub: "SecureOS rolling says glibc-2.42 is not affected (fixed in 0)", miss: true });
    expect(whyTitle(nak.why, "dropped")).toBe("SecureOS rolling says not affected");
  });
});
