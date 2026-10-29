import { describe, expect, test } from "bun:test";
import { expandable, lanes, recordLine, steps, subFits } from "./matchpath";
import type { Row } from "./rows";
import { whyText, whyTitle } from "./words";

// a CPE match only the reference reported, on a secureos package the candidate's distro record says
// is not affected
const nak: Row = {
  id: "r", match: "m", row: "r", vulnerability: "CVE-2026-4438", group: "g", sourcePackage: "glibc-2.42", verdict: "unlabeled",
  package: { ref: "pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09" }, inCandidate: false, inReference: true,
  reference: { namespace: "nvd:cpe", matchTypes: ["cpe-match"], matchers: ["apk-matcher"], cpes: ["cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*"], constraints: [">= 2.38, <= 2.44 (unknown)"], distro: "secureos 2025.09.09" },
  why: { key: "record/distro-not-affected", to: "secureos:distro:secureos:rolling", secondary: [{ key: "record/same-but-unmatched" }] },
  candidateRecords: [
    { vulnerability: "CVE-2026-4438", namespace: "nvd:cpe", cpe: "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*", constraints: [">= 2.38, <= 2.44"] },
    { vulnerability: "CVE-2026-4438", namespace: "secureos:distro:secureos:rolling", package: "glibc-2.42", constraints: ["< 0"], fixStates: ["fixed"], fixVersions: ["0"] },
  ],
};

describe("match path", () => {
  test("both lanes search by CPE and find the same record; the distro check drops it on one side only", () => {
    const rel = { distro: "secureos", version: "2025.09.09" }, setups = { grype: { candidate: "v0.120.1", reference: "v0.100.0" }, sameDB: true };
    const ls = lanes(nak, undefined, rel, setups);
    const cells = (side: string) => ls.find((l) => l.side === side)!.steps.map((x) => [x.k, x.t, x.sub ?? ""].join(" | "));
    expect(cells("candidate")).toEqual([
      "package | glibc-2.42 2.42-r4 | apk",
      "via | as CPE | cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*",
      "searched | NVD (CPE) | apk matcher",
      "record | CVE-2026-4438 | affected >= 2.38, <= 2.44",
      "distro | SecureOS records | not affected (fixed in 0)",
      "result | dropped | SecureOS says not affected",
    ]);
    expect(cells("reference")).toEqual([
      "package | glibc-2.42 2.42-r4 | apk",
      "via | as CPE | cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*",
      "searched | NVD (CPE) | apk matcher",
      "record | CVE-2026-4438 | affected >= 2.38, <= 2.44",
      "distro | SecureOS records | NAK not applied",
      "result | matched | cpe",
    ]);
    // the same search and record line up undiffed; the distro check and the result differ
    const diffs = (side: string) => ls.find((l) => l.side === side)!.steps.filter((x) => x.diff).map((x) => x.k);
    expect(diffs("candidate")).toEqual(["distro", "result"]);
    expect(diffs("reference")).toEqual(["distro", "result"]);
    // the lanes diverge at the distro check: marked on both, the result after it only differs
    const causes = (side: string) => ls.find((l) => l.side === side)!.steps.filter((x) => x.cause).map((x) => x.k);
    expect(causes("candidate")).toEqual(["distro"]);
    expect(causes("reference")).toEqual(["distro"]);
    // a grype that reported no distro for the image says so, rather than why it didn't apply the record
    const noDistro = { ...nak, reference: { ...nak.reference, distro: undefined } };
    expect(steps(noDistro, "reference", undefined, rel, setups).find((x) => x.k === "distro")).toMatchObject({ sub: "no distro detected",
      detail: "Its DB is the same and has the record saying not affected; grype v0.100.0 reported no distro for the image, so it did not apply the record." });
    // the candidate's matcher is inferred, and says so; shared steps otherwise render alike
    expect(ls[0].steps[2].title).toContain("inferred");
    // every cell fits its subline, or opens to show all of it
    for (const l of ls) for (const st of l.steps) {
      if ((st.sub?.length ?? 0) > subFits) expect(expandable(st)).toBe(true);
    }
    const via = ls[0].steps[1];
    expect(expandable(via) && via.detail).toBe("cpe:2.3:a:gnu:glibc:2.42:*:*:*:*:*:*:*");
    expect(expandable(ls[0].steps[4])).toBe(true);
    expect(whyTitle(nak.why, "dropped")).toBe("SecureOS says not affected");
    expect(whyText(nak.why?.secondary?.[0], "dropped", nak.why?.key)).toBe("both DBs have the same record the reference matched");
    expect(whyText(nak.why?.secondary?.[0], "dropped")).toContain("a matcher or config difference");
  });
  test("other reasons keep their lanes", () => {
    const fix: Row = { ...nak, why: { key: "fix-state/changed", from: "not-fixed", to: "fixed" },
      candidateRecords: [{ vulnerability: "CVE-2026-4438", namespace: "nvd:cpe", cpe: "cpe:2.3:a:gnu:glibc:*:*:*:*:*:*:*:*", constraints: ["< 2.40"] }] };
    expect(steps(fix, "candidate", undefined, null).map((x) => x.k)).toEqual(["package", "searched", "record", "result"]);
    expect(steps(fix, "reference", undefined, null).map((x) => x.k)).toEqual(["package", "via", "searched", "record", "result"]);
    const absent: Row = { ...nak, why: { key: "record/absent-in-candidate" }, candidateStatus: "not-in-db", candidateRecords: [] };
    // the lanes diverge at the first step that differs, whatever the reason
    const absentLanes = lanes(absent as Row, undefined, null);
    expect(absentLanes.map((l) => l.steps.filter((x) => x.cause).map((x) => x.k))).toEqual([["searched"], ["searched"]]);
    expect(steps(absent, "candidate", undefined, null).map((x) => x.t)).toEqual(["glibc-2.42 2.42-r4", "every namespace", "no record", "no match"]);
  });
  test("a lane reads one match detail, not the row's pooled match types and upstreams", () => {
    // binutils' match in a CleanStart scan: an exact-direct detail, then an exact-indirect one that
    // searched by the same name, its upstream
    const det = (type: string) => ({ type, matcher: "apk-matcher",
      searchedBy: { namespace: "cleanstart:distro:cleanstart:rolling", package: { name: "binutils", version: "2.45.1-r0" } },
      found: { vulnerabilityID: "CLEANSTART-2026-GU36052", versionConstraint: "< 2.46.0-r0 (apk)" } });
    const row: Row = { id: "r", match: "m", row: "r", vulnerability: "CLEANSTART-2026-GU36052", group: "g", sourcePackage: "binutils", verdict: "unlabeled",
      package: { ref: "pkg:apk/cleanstart/binutils@2.45.1-r0?arch=x86_64&distro=cleanstart-3.20.3" }, inCandidate: true, inReference: false,
      candidate: { namespace: "cleanstart:distro:cleanstart:rolling", matchTypes: ["exact-direct-match", "exact-indirect-match"], matchers: ["apk-matcher"], upstreams: ["binutils"], constraints: ["< 2.46.0-r0 (apk)"] } };
    const cells = (raw?: Parameters<typeof steps>[2]) => steps(row, "candidate", raw, null).map((x) => [x.k, x.t, x.sub ?? ""].join(" | "));
    expect(cells({ matchDetails: [det("exact-direct-match"), det("exact-indirect-match")] })).toEqual([
      "package | binutils 2.45.1-r0 | apk",
      "searched | cleanstart rolling | apk matcher",
      "record | CLEANSTART-2026-GU36052 | affected < 2.46.0-r0",
      "result | matched | exact-direct",
    ]);
    // an indirect detail that searched by its own name went nowhere via a source package either
    expect(cells({ matchDetails: [det("exact-indirect-match")] }).map((c) => c.split(" | ")[0])).toEqual(["package", "searched", "record", "result"]);
    // one that searched by another name did
    const src = det("exact-indirect-match");
    src.searchedBy.package = { name: "binutils-src", version: "2.45.1-r1" };
    expect(cells({ matchDetails: [src] })[1]).toBe("via | via source package binutils-src | 2.45.1-r1");
    // without a raw match, the row's match types and upstreams are all the lane has: an upstream
    // that is the package's own name is no source package either, and another is
    expect(cells().map((c) => c.split(" | ")[0])).not.toContain("via");
    row.candidate!.upstreams = ["binutils", "binutils-src"];
    expect(cells()[1]).toBe("via | via source package binutils-src | ");
  });
  test("each of the other DB's records says how it relates to the row", () => {
    const [cpe, distro] = nak.candidateRecords ?? [];
    expect(recordLine(nak, cpe, "dropped")).toBe("same record the reference matched (NVD (CPE) glibc, >= 2.38, <= 2.44)");
    expect(recordLine(nak, distro, "dropped")).toBe("SecureOS says glibc-2.42 is not affected (fixed in 0)");
    expect(recordLine(nak, { ...cpe, constraints: [">= 2.0, <= 2.42"] }, "dropped")).toBe("NVD (CPE) glibc · affected >= 2.0, <= 2.42");
    expect(recordLine(nak, { vulnerability: "CVE-2026-4438", namespace: "secureos:distro:secureos:rolling", package: "glibc-2.42", constraints: ["< 2.42-r5"], fixStates: ["fixed"], fixVersions: ["2.42-r5"] }, "dropped"))
      .toBe("SecureOS rolling glibc-2.42 · affected < 2.42-r5 · fixed in 2.42-r5");
  });
});
