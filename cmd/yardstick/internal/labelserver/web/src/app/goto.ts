// goto.ts is where moving between gates goes: the gates with their open counts, the gate ⇧J and
// ⇧K go to, and the ⌘K palette's entries. Pure: shell.ts, palette.ts and main.ts draw and act.
import type { GateList, State } from "../gen/wire";
import { plural } from "../shared/words";
import { openOf } from "./images";
import { gateRows, sumTally } from "./listing";
import { filterRows } from "./table";
import { formatRoute, gateOf, type Route } from "./route";
import type { State as Status, Verdict } from "./ui";

export interface GateItem { id: string; state: Status; open: number; total: number }


// gateItems are the gates in the list's order, each with its outcome and open rows
export const gateItems = (l: GateList): GateItem[] => l.gates.map((g) => {
  const t = sumTally(g.changes ?? []);
  return { id: g.id, state: (g.error ? "undecided" : g.gateOutcome ?? "undecided") as Status, open: openOf(t), total: t.total };
});

// nextGate is the gate with open rows after current (step 1) or before it (-1), wrapping round;
// from outside every gate, the first or the last with open rows
export function nextGate(gates: GateItem[], current: string | null, step: 1 | -1): string | undefined {
  const at = gates.findIndex((g) => g.id === current);
  const ring = at < 0 ? gates : [...gates.slice(at + 1), ...gates.slice(0, at)];
  return (step > 0 ? ring : [...ring].reverse()).find((g) => g.open > 0)?.id;
}

// ---------- the palette ----------

export type Group = "Gates" | "Images" | "Checks" | "Findings" | "Actions";

export interface Entry {
  group: Group;
  id: string;           // unique within its group, for tests
  text: string;
  detail: string;
  href: string;
  search: string;       // what a query is matched against, every word of it
  state?: Status;       // a gate's or check's
  verdict?: Verdict;    // a finding's
  key?: string;         // an action's key
}

export interface GateStates { gate: string; state: State }

const gateHref = (gate: string, image?: string) => formatRoute({ level: "gate", gate, tab: "checks", filters: image ? { image } : {} });

export function gateEntries(gates: GateItem[]): Entry[] {
  return gates.map((g) => ({ group: "Gates", id: g.id, text: g.id, detail: `${g.open.toLocaleString()} open of ${g.total.toLocaleString()} changed`, href: gateHref(g.id), search: g.id, state: g.state }));
}

// imageEntries list each image once, however many gates scan it, with the gates it's in; it opens
// in the first of them where it has open rows
export function imageEntries(l: GateList): Entry[] {
  const by = new Map<string, { name: string; ref: string; in: { gate: string; slug: string; open: number }[] }>();
  for (const g of l.gates) {
    g.subjects.forEach((s, i) => {
      const ref = s.ref ?? s.name;
      const have = by.get(ref) ?? { name: s.name, ref, in: [] };
      have.in.push({ gate: g.id, slug: s.slug, open: openOf(g.changes?.[i]) });
      by.set(ref, have);
    });
  }
  return [...by.values()].map((x) => {
    const at = x.in.find((a) => a.open) ?? x.in[0];
    return { group: "Images", id: x.ref, text: x.name, detail: x.in.map((a) => `${a.gate} ${a.open} open`).join(" · "),
      href: gateHref(at.gate, at.slug), search: `${x.name} ${x.ref} ${x.in.map((a) => a.gate).join(" ")}` };
  });
}

export function checkEntries(states: GateStates[]): Entry[] {
  return states.flatMap(({ gate, state }) => (state.gate?.result?.checks ?? []).map((c): Entry => ({
    group: "Checks", id: `${gate}/${c.name}`, text: c.name, detail: gate, state: c.state as Status,
    href: formatRoute({ level: "check", gate, check: c.name, filters: {} }), search: `${c.name} ${gate}`,
  })));
}

// findingEntries are every gate's changed rows, each row once (a row id is per image and match, so
// the same id in two gates is one finding), opening in the first gate that has it
export function findingEntries(states: GateStates[]): Entry[] {
  const by = new Map<string, Entry & { gates: string[] }>();
  for (const { gate, state } of states) {
    for (const r of gateRows(state)) {
      if (!r.row) continue;
      const have = by.get(r.row);
      if (have) { have.gates.push(gate); continue; }
      by.set(r.row, { group: "Findings", id: r.row, text: r.vuln, verdict: r.label, gates: [gate],
        // by ID or package only: the seed's image names hold "tar" and "util-linux" too
        detail: `${r.pkg} ${r.version} · ${r.image.name}`, search: `${r.vuln} ${r.pkg} ${r.version} ${r.purl}`,
        href: formatRoute({ level: "finding", gate, check: null, row: r.row, filters: {} }) });
    }
  }
  return [...by.values()].map(({ gates, ...e }) => ({ ...e, detail: `${e.detail} · ${gates.join(", ")}` }));
}

export const actions: Entry[] = [
  { group: "Actions", id: "hints", text: "Review hints", detail: "every pending agent hint, with what it does to each gate", href: "/ui/hints", search: "review hints agent accept", key: "h" },
  { group: "Actions", id: "queue", text: "Label what's left", detail: "one open match at a time, across gates", href: "/ui/queue", search: "label what's left queue next open", key: "n" },
  { group: "Actions", id: "research", text: "Research open matches", detail: "price and start research of the open matches with no hint", href: "/ui/research", search: "research open matches rows agent cost batch", key: "r" },
  { group: "Actions", id: "history", text: "History", detail: "the labels written, newest first", href: "/ui/history", search: "history labels written undo", key: undefined },
  { group: "Actions", id: "jobs", text: "Research jobs", detail: "what research is running, waiting and done", href: "/ui/research/jobs", search: "research jobs running queued cancel log", key: undefined },
];

// routeActions are the actions only some screens have: research this gate (on a gate, check or
// finding) and this check (on a check)
export function routeActions(r: Route | null): Entry[] {
  const gate = r && gateOf(r);
  if (!gate) return [];
  const out: Entry[] = [{ group: "Actions", id: "research-gate", text: "Research this gate", detail: `price and start research of ${gate}'s open matches with no hint`,
    href: formatRoute({ level: "research", scope: `gate:${gate}`, filters: {} }), search: `research this gate ${gate} agent cost` }];
  if (r.level === "check") out.push({ group: "Actions", id: "research-check", text: "Research this check", detail: `the open matches with no hint that bear on ${r.check}`,
    href: formatRoute({ level: "research", scope: `gate:${gate}`, check: r.check, filters: {} }), search: `research this check ${r.check} agent cost` });
  return out;
}

// findingLimit caps the findings a query shows; a real workspace has thousands
export const findingLimit = 30;

// matching is what the palette shows for a query: every entry matching each word of it, findings
// only once there is a query and at most findingLimit of them
export function matching(entries: Entry[], findings: Entry[], q: string): { shown: Entry[]; more: number } {
  const f = q.trim() ? filterRows(findings, q, (e) => e.search) : [];
  return { shown: [...filterRows(entries, q, (e) => e.search), ...f.slice(0, findingLimit)], more: Math.max(0, f.length - findingLimit) };
}

export const moreWords = (n: number) => `${plural(n, "more finding")} match; type more to narrow it`;
