import { describe, expect, test } from "bun:test";
import type { GateList, State } from "../gen/wire";
import { actions, findingEntries, gateItems, imageEntries, matching, nextGate, type GateItem } from "./goto";

const t = (open: number, total = open) => ({ tp: 0, fp: 0, unclear: 0, hinted: 0, open, total });
const deb = { name: "deb:617d48d", slug: "deb-617d48d", ref: "ghcr.io/x/deb:617d48d@sha256:1" };
const list = {
  open: "deb-npm",
  gates: [
    { id: "deb-npm", gateOutcome: "undecided", subjects: [deb, { name: "npm:8e253b5", slug: "npm-8e253b5", ref: "ghcr.io/x/npm" }], changes: [t(2), t(1)] },
    { id: "deb-java", gateOutcome: "fail", subjects: [deb, { name: "java:e363e44", slug: "java-e363e44", ref: "ghcr.io/x/java" }], changes: [t(6, 8), { ...t(2, 4), unclear: 2 }] },
    { id: "broken", error: "no scans", subjects: [], changes: [] },
  ],
} as unknown as GateList;

describe("gates", () => {
  test("each with its outcome and open rows, unclear ones open too, an errored one undecided", () => {
    expect(gateItems(list).map((g) => `${g.id} ${g.state} ${g.open}/${g.total}`)).toEqual(["deb-npm undecided 3/3", "deb-java fail 10/12", "broken undecided 0/0"]);
  });

  const gates: GateItem[] = ["a", "b", "c", "d"].map((id) => ({ id, state: "fail", open: id === "c" ? 0 : 1, total: 1 }));
  test("⇧J and ⇧K go to the next and previous gate with open rows, wrapping round", () => {
    expect(nextGate(gates, "a", 1)).toBe("b");
    expect(nextGate(gates, "b", 1)).toBe("d");
    expect(nextGate(gates, "d", 1)).toBe("a");
    expect(nextGate(gates, "d", -1)).toBe("b");
    expect(nextGate(gates, "a", -1)).toBe("d");
  });
  test("from outside every gate, the first or the last; none when no other gate is open", () => {
    expect(nextGate(gates, null, 1)).toBe("a");
    expect(nextGate(gates, null, -1)).toBe("d");
    expect(nextGate(gates.map((g) => ({ ...g, open: g.id === "a" ? 1 : 0 })), "a", 1)).toBeUndefined();
  });
});

describe("the palette", () => {
  test("lists an image once with every gate it's in, opening where it has open rows", () => {
    const es = imageEntries(list);
    expect(es.map((e) => `${e.text}: ${e.detail}`)).toEqual(["deb:617d48d: deb-npm 2 open · deb-java 6 open", "npm:8e253b5: deb-npm 1 open", "java:e363e44: deb-java 4 open"]);
    expect(es[0].href).toBe("/ui/gates/deb-npm/?image=deb-617d48d");
  });

  const row = (id: string, vuln: string, ref: string) => ({ id, vulnerability: vuln, package: { ref }, verdict: "unlabeled", inCandidate: false, inReference: true });
  const st = (rows: ReturnType<typeof row>[]) => ({ scans: { subjects: [] }, causes: [], subjects: [{ name: deb.name, slug: deb.slug, rows }] }) as unknown as State;
  const tar = row("0fe9fc814bcd060a", "CVE-2005-2541", "pkg:deb/debian/tar@1.34");
  const states = [
    { gate: "deb-java", state: st([tar, row("e3bfd3b0b0c30ee6", "CVE-2026-18508", "pkg:deb/debian/tar@1.34")]) },
    { gate: "deb-npm", state: st([tar, row("5e50fe5b2007001a", "CVE-2026-41992", "pkg:deb/debian/gzip@1.12-1")]) },
  ];
  test("lists a row two gates have once, with both gates", () => {
    const fs = findingEntries(states);
    expect(fs.map((e) => `${e.id} ${e.text} · ${e.detail}`)).toEqual([
      "0fe9fc814bcd060a CVE-2005-2541 · tar 1.34 · deb:617d48d · deb-java, deb-npm",
      "e3bfd3b0b0c30ee6 CVE-2026-18508 · tar 1.34 · deb:617d48d · deb-java",
      "5e50fe5b2007001a CVE-2026-41992 · gzip 1.12-1 · deb:617d48d · deb-npm",
    ]);
    expect(fs[0].href).toBe("/ui/gates/deb-java/findings/0fe9fc814bcd060a");
  });
  test("matches every word of the query, and findings only once there is one", () => {
    const fs = findingEntries(states);
    expect(matching(actions, fs, "").shown.map((e) => e.id)).toEqual(["hints", "queue", "research", "history"]);
    expect(matching(actions, fs, "tar 2026").shown.map((e) => e.id)).toEqual(["e3bfd3b0b0c30ee6"]);
    expect(matching(actions, fs, "gzip").shown.map((e) => e.text)).toEqual(["CVE-2026-41992"]);
    // not by the image, whose name may hold a package's
    expect(matching(actions, fs, "deb:617d48d").shown).toEqual([]);
    expect(matching(actions, fs, "hint").shown.map((e) => e.href)).toEqual(["/ui/hints"]);
  });
});
