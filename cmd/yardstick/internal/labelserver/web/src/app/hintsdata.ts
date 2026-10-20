// hintsdata.ts is hint review's logic: the review page's scope in its URL, which hints start
// checked, what a selection labels in each gate's preview, what stays open after it, and the work
// numbers the gates page leads with. Pure: hints.ts and banner.ts draw it.
import type { CrossFinding, HintEntry, ResearchSummary } from "../gen/wire";
import { doing, inFlight, type Doing } from "../shared/agent";
import { plural } from "../shared/words";
import type { State as Status } from "./ui";

// HintScope is the review page's query: a gate, an image (slug), and whether low-confidence hints show
export interface HintScope { gate?: string; image?: string; low?: boolean }

export function hintsHref(s: HintScope): string {
  const p = new URLSearchParams();
  if (s.gate) p.set("gate", s.gate);
  if (s.image) p.set("image", s.image);
  if (s.low) p.set("low", "1");
  const q = p.toString();
  return `/ui/hints${q ? `?${q}` : ""}`;
}

export function parseScope(search: string): HintScope {
  const p = new URLSearchParams(search), s: HintScope = {};
  const gate = p.get("gate"), image = p.get("image");
  if (gate) s.gate = gate;
  if (image) s.image = image;
  if (p.get("low") === "1") s.low = true;
  return s;
}

export const isLow = (h: HintEntry) => h.confidence === "low";

// preselected says whether a hint starts checked: medium confidence and up, and never one that
// would replace a label a person wrote
export const preselected = (h: HintEntry) => (h.confidence === "high" || h.confidence === "medium") && !h.replaces;

const inGate = (h: HintEntry, gate?: string) => !gate || h.gates.some((g) => g.gate === gate);
const onImage = (h: HintEntry, image?: string) => !image || h.rows.some((r) => r.image.slug === image);

// inScope is what the review page lists for a scope, as GET /api/hints filters, and how many
// low-confidence hints it leaves out
export function inScope(all: HintEntry[], s: HintScope): { hints: HintEntry[]; low: number } {
  const hints: HintEntry[] = [];
  let low = 0;
  for (const h of all) {
    if (!inGate(h, s.gate) || !onImage(h, s.image)) continue;
    if (isLow(h) && !s.low) low++;
    else hints.push(h);
  }
  return { hints, low };
}

// rowCount is how many rows the hints cover, a row in two gates once (a row id is per image and match)
export const rowCount = (hs: HintEntry[]) => new Set(hs.flatMap((h) => h.rows.map((r) => r.row))).size;

export type Preview = Record<string, "tp" | "fp">;

// previewLabels are, per gate, the labels accepting hs would write there, for that gate's preview.
// Only tp and fp close a row; a row two hints disagree on keeps the first, as accepting does.
export function previewLabels(hs: HintEntry[]): Map<string, Preview> {
  const out = new Map<string, Preview>();
  for (const h of hs) {
    if (h.verdict !== "tp" && h.verdict !== "fp") continue;
    for (const g of h.gates) {
      const labels = out.get(g.gate) ?? {};
      for (const r of g.rows) labels[r] ??= h.verdict;
      out.set(g.gate, labels);
    }
  }
  return out;
}

// hintedRows are, per gate, the rows any of hs covers there
export function hintedRows(hs: HintEntry[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const h of hs) for (const g of h.gates) {
    const s = out.get(g.gate) ?? new Set<string>();
    for (const r of g.rows) s.add(r);
    out.set(g.gate, s);
  }
  return out;
}

export interface ImageHints { hints: number; rows: number; replaces: number }

// imageHints are, per image slug, the hints with rows of that image in gate, those rows, and how
// many of the hints would replace a person's label
export function imageHints(hs: HintEntry[], gate: string): Map<string, ImageHints> {
  const out = new Map<string, ImageHints>(), rows = new Set<string>();
  for (const h of hs) {
    const mine = new Set(h.gates.find((g) => g.gate === gate)?.rows ?? []);
    const seen = new Set<string>();
    for (const r of h.rows) {
      if (!mine.has(r.row)) continue;
      const x = out.get(r.image.slug) ?? { hints: 0, rows: 0, replaces: 0 };
      if (!rows.has(r.row)) { rows.add(r.row); x.rows++; }
      if (!seen.has(r.image.slug)) { seen.add(r.image.slug); x.hints++; if (h.replaces) x.replaces++; }
      out.set(r.image.slug, x);
    }
  }
  return out;
}

// OpenRow is an open row of a gate, as "still open" lists it, with its newest research job
export interface OpenRow { gate: string; row: string; vuln: string; pkg: string; research?: ResearchSummary }

// Left is one line of what stays open after a selection: a hint left unchecked (with its rows), or
// a row no shown hint covers, marked with its job when one is in flight on it
export interface Left { text: string; gates: string[]; why: string; job?: Doing }

// stillOpen is what stays open in the gates' open rows once the selected hints are accepted, in
// the rows' order, each row once however many gates it is in
export function stillOpen(rows: OpenRow[], shown: HintEntry[], selected: Set<string>): Left[] {
  const closed = new Set([...previewLabels(shown.filter((h) => selected.has(h.id))).values()].flatMap((p) => Object.keys(p)));
  const hintOf = new Map<string, HintEntry>();
  for (const h of shown) for (const r of h.rows) if (!hintOf.has(r.row)) hintOf.set(r.row, h);
  const out = new Map<string, Left & { rows: Set<string> }>();
  for (const r of rows) {
    if (closed.has(r.row)) continue;
    const h = hintOf.get(r.row);
    const key = h ? `hint:${h.id}` : `row:${r.row}`;
    const x = out.get(key) ?? {
      text: h ? `${h.rows[0].package.name} ${h.rows[0].vulnerability}` : `${r.pkg} ${r.vuln}`,
      gates: [], rows: new Set<string>(),
      why: !h ? "no hint" : selected.has(h.id) ? "its hint closes nothing" : "hint unchecked",
      ...(!h && inFlight(r.research) && { job: doing(r.research, { open: true, researched: false }) }),
    };
    x.rows.add(r.row);
    if (!x.gates.includes(r.gate)) x.gates.push(r.gate);
    out.set(key, x);
  }
  return [...out.values()].map(({ rows: rs, ...x }) => (rs.size > 1 ? { ...x, text: `${x.text} (${rs.size} matches)` } : x));
}

// aloneWords is what accepting every hint does to a gate, from its outcome now and after
export function aloneWords(before: Status, after: Status): string {
  if (after === "pass") return before === "pass" ? "passes already" : "passes on hints alone";
  return after === before ? "hints alone don't change it" : `${after} on hints alone`;
}

export interface Work { open: number; hinted: number; needYou: number }

// workNumbers are the open findings across gates from the queue's open rows: each finding once,
// however many gates and rows report it (a label is about an image, package and vulnerability, so
// log4j's two jars are one finding), the ones an agent left a hint on, and the ones that need a person
export function workNumbers(rows: CrossFinding[]): Work {
  const by = new Map<string, boolean>();
  for (const f of rows) {
    const k = `${f.image}|${f.package.ref}|${f.vulnerability}`;
    by.set(k, !!by.get(k) || f.hint?.status === "pending" || !!f.cause);
  }
  const hinted = [...by.values()].filter(Boolean).length;
  return { open: by.size, hinted, needYou: by.size - hinted };
}

// waitWords say what a gate still waits on after every hint: the open rows no hint labels. Without
// then, it is what the gate waits on now, for when no hint is pending.
export function waitWords(gate: string, left: OpenRow[], then = true, show = 3): string {
  const names = left.slice(0, show).map((r) => `${r.pkg} ${r.vuln}`).join(", ");
  const more = left.length > show ? ` and ${left.length - show} more` : "";
  return `${gate}${then ? " then" : ""} waits on ${plural(left.length, "match", "matches")} with no hint: ${names}${more}.`;
}
