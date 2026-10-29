import { describe, expect, test } from "bun:test";
import type { UnlistedNamespace } from "../gen/wire";
import { sticky } from "../shared/dom";
import { addedWords, namespaceWords, retried } from "./namespacewords";

// CleanStart in the turnup's gate: each id names one CVE, which doesn't say which kind it is
const cleanstart: UnlistedNamespace = {
  gate: "cleanstart", id: "CLEANSTART-2026-GU36052", namespace: "CLEANSTART", checked: 2,
  example: { id: "CLEANSTART-2026-GU36052", names: ["CVE-2025-11082"] }, file: "additional-claims/vocabulary.yaml",
};
const elsa: UnlistedNamespace = {
  gate: "ol", id: "ELSA-2021-9137", namespace: "ELSA", suggest: "advisory-ids", checked: 1,
  example: { id: "ELSA-2021-9137", names: ["CVE-2020-1971", "CVE-2021-23840"] }, file: "claims/vocabulary.yaml",
};

describe("an unlisted namespace's dialog", () => {
  test("ids naming one vulnerability each: can't tell, neither button primary, the file it writes", () => {
    const w = namespaceWords(cleanstart);
    expect(w.title).toBe("CLEANSTART isn't in the claims vocabulary");
    expect(w.body).toBe("Research and labels on its rows can't be recorded until it is. Each CLEANSTART id in this scan names one vulnerability at most " +
      "(e.g. CLEANSTART-2026-GU36052 → CVE-2025-11082): a disclosure's ids each do, and so can an advisory's, so this scan can't tell which kind CLEANSTART is.");
    expect(w.adds).toEqual([{ list: "vulnerability-namespaces", text: "Add as disclosure", primary: false }, { list: "advisory-ids", text: "Add as advisory", primary: false }]);
    expect(w.small).toBe("Writes additional-claims/vocabulary.yaml; your PR will show the change.");
    expect(w.writable).toBe(true);
    expect(namespaceWords({ ...cleanstart, checked: 1 }).body).toContain("The one CLEANSTART id in this scan names one vulnerability (CLEANSTART-2026-GU36052 → CVE-2025-11082)");
  });
  test("an advisory namespace leads with advisory-ids, as the primary", () => {
    const w = namespaceWords(elsa);
    expect(w.body).toBe("Research and labels on its rows can't be recorded until it is. The one ELSA id in this scan names several vulnerabilities " +
      "(ELSA-2021-9137 → CVE-2020-1971, CVE-2021-23840), so it looks like an advisory namespace.");
    expect(w.adds.map((a) => [a.list, a.primary])).toEqual([["advisory-ids", true], ["vulnerability-namespaces", false]]);
    expect(namespaceWords({ ...elsa, checked: 3 }).body).toContain("Some ELSA ids in this scan name several vulnerabilities (e.g. ELSA-2021-9137 → CVE-2020-1971, CVE-2021-23840)");
  });
  test("no id to judge by, or nowhere to write", () => {
    const w = namespaceWords({ ...cleanstart, checked: 0, example: undefined, file: undefined });
    expect(w.body).toContain("This scan has no CLEANSTART id to judge it by");
    expect(w.adds.map((a) => [a.list, a.primary])).toEqual([["vulnerability-namespaces", false], ["advisory-ids", false]]);
    expect(w.writable).toBe(false);
    expect(w.small).toContain("no local claims source");
  });
  test("the confirmation names the kind and the file", () => {
    expect(addedWords("CLEANSTART", "vulnerability-namespaces", "claims/vocabulary.yaml")).toBe("CLEANSTART added as a disclosure namespace in claims/vocabulary.yaml");
  });
});

// a research start refused for an unlisted namespace until it is added, as the server does
class Refused extends Error { constructor(readonly u: UnlistedNamespace) { super(u.namespace); } }
const unlisted = (e: unknown) => (e instanceof Refused ? e.u : undefined);
function server(lacks: UnlistedNamespace[]) {
  const listed = new Set<string>();
  let starts = 0;
  return {
    starts: () => starts,
    add: (ns: string) => listed.add(ns),
    start: async () => {
      starts++;
      const u = lacks.find((x) => !listed.has(x.namespace));
      if (u) throw new Refused(u);
      return { jobs: ["j1"] };
    },
  };
}

describe("research refused for an unlisted namespace", () => {
  test("adding it starts the same research again, inside the dialog", async () => {
    const s = server([cleanstart]), asked: string[] = [];
    const res = await retried(s.start, unlisted, async (u, after) => { asked.push(u.namespace); s.add(u.namespace); await after(); return true; });
    expect(res).toEqual({ jobs: ["j1"] });
    expect(asked).toEqual(["CLEANSTART"]);
    expect(s.starts()).toBe(2);
  });
  test("closing the dialog starts nothing", async () => {
    const s = server([cleanstart]);
    expect(await retried(s.start, unlisted, async () => false)).toBeNull();
    expect(s.starts()).toBe(1);
  });
  test("a second namespace refused asks again", async () => {
    const s = server([cleanstart, elsa]), asked: string[] = [];
    const res = await retried(s.start, unlisted, async (u, after) => { asked.push(u.namespace); s.add(u.namespace); await after(); return true; });
    expect(res).toEqual({ jobs: ["j1"] });
    expect(asked).toEqual(["CLEANSTART", "ELSA"]);
  });
  test("another refusal is the start's own, before the dialog and inside it", async () => {
    await expect(retried(async () => { throw new Error("research isn't configured"); }, unlisted, async () => true)).rejects.toThrow("research isn't configured");
    let tries = 0;
    const flaky = async () => { if (tries++ === 0) throw new Refused(cleanstart); throw new Error("503: busy"); };
    let shown = "";
    const res = await retried(flaky, unlisted, async (_, after) => { try { await after(); return true; } catch (e) { shown = (e as Error).message; return false; } });
    expect(shown).toBe("503: busy");
    expect(res).toBeNull();
  });
});

describe("toasts", () => {
  test("one longer than a line stays until dismissed", () => {
    expect(sticky("research started; what it finds arrives as an agent hint")).toBe(false);
    expect(sticky(`400: vulnerability CLEANSTART-2026-GU36052: namespace "CLEANSTART" is not in any claims source's vocabulary.yaml`)).toBe(true);
  });
});
