// listing.ts is the list screens' logic: one finding row shape for every findings table, the filter
// chips and their counts, paging, the gate list's image strip, and labels across gates. Pure: no
// DOM; the screens draw it.
import type { CheckFindings, CrossFinding, GateLabel, ImageRef, State, Tally } from "../gen/wire";
import { pkgOf, srcPkg } from "../shared/rows";
import { openOf } from "./images";
import type { Filters, VerdictFilter } from "./route";
import { filterRows, sortRows } from "./table";
import type { Verdict } from "./ui";

// FHint is a row's pending agent suggestion: its own proposal, or a cause (package hint) listing it
export interface FHint { verdict: string; confidence?: string; kind: "proposal" | "cause"; cause?: string }

export type Effect = "decides" | "could-move" | "counted" | "";

// FRow is one finding as every findings table shows it
export interface FRow {
  id: string;             // the row id, or a made-up key for an unmet expectation no match pairs
  row?: string;           // absent for that expectation, which has no finding page
  label: Verdict;
  vuln: string;
  pkg: string;
  version: string;
  purl: string;
  src: string;            // the source package, which the scan map groups by
  image: ImageRef;
  change: string;         // added, dropped, both or neither
  hint: FHint | null;
  effect: Effect;
}

// effectRank orders findings the way the server's check findings are (gateapi.go effectRank):
// decides, could-move, counted, then none
export const effectRank = (e: Effect) => ["decides", "could-move", "counted", ""].indexOf(e);

const effectOf = (e: string | undefined): Effect => (e === "decides" || e === "could-move" || e === "counted" ? e : "");
const verdictOf = (v: string | undefined): Verdict => (v === "tp" || v === "fp" || v === "unclear" ? v : "unlabeled");
export const isOpen = (r: FRow) => r.label === "unlabeled" || r.label === "unclear";

// gateRows are a gate's changed matches (one setup reports them) from its /state, by effect like a
// check's table, then in report order, so "next" (the first open row) is the first row j walks to
export function gateRows(st: State): FRow[] {
  const out: FRow[] = [];
  st.subjects.forEach((s, si) => {
    const info = st.scans.subjects[si];
    const image: ImageRef = { name: s.name, slug: s.slug, ref: info?.ref ?? s.name };
    for (const r of s.rows) {
      if (r.inCandidate === r.inReference) continue;
      const p = pkgOf(r.package.ref), label = verdictOf(r.verdict);
      const open = label === "unlabeled" || label === "unclear";
      const cause = open ? st.causes.find((c) => c.pending.includes(r.id)) : undefined;
      const hint: FHint | null = open && r.hint?.status === "pending" ? { verdict: r.hint.verdict, confidence: r.hint.confidence, kind: "proposal" }
        : cause ? { verdict: cause.verdict, confidence: cause.confidence, kind: "cause", cause: cause.id } : null;
      out.push({
        id: r.id, row: r.id, label, vuln: r.vulnerability, pkg: p.name, version: p.version, purl: r.package.ref, src: srcPkg(r), image,
        change: r.inCandidate ? "added" : "dropped", hint,
        effect: effectOf(r.effect), // the server's, as the check findings say it
      });
    }
  });
  return sortRows(out, (r) => effectRank(r.effect));
}

// checkRows are a check's findings from its findings API
export function checkRows(f: CheckFindings): FRow[] {
  return f.findings.map((x) => ({
    id: x.row || `${x.image.slug}|${x.package.purl}|${x.vulnerability}`, row: x.row, label: verdictOf(x.label?.verdict),
    vuln: x.vulnerability, pkg: x.package.name || pkgOf(x.package.purl).name, version: x.package.version || pkgOf(x.package.purl).version,
    purl: x.package.purl ?? "", src: x.package.name, image: x.image, change: x.direction,
    hint: x.hint ? { verdict: x.hint.verdict, confidence: x.hint.confidence, kind: x.hint.kind === "cause" ? "cause" : "proposal" } : null,
    effect: effectOf(x.effect),
  }));
}

// rowText is what the search box matches a finding against
export const rowText = (r: FRow) => `${r.vuln} ${r.pkg} ${r.version} ${r.purl} ${r.src} ${r.image.name}`;

// ---------- filter chips ----------

export type Chip = VerdictFilter | "all" | "hint";
export const chips: Chip[] = ["all", "unlabeled", "tp", "fp", "unclear", "hint"];
export const chipWords: Record<Chip, string> = { all: "All", unlabeled: "Unlabeled", tp: "TP", fp: "FP", unclear: "Unclear", hint: "Has hint" };

export const chipOf = (f: Filters): Chip => (f.hint === "yes" ? "hint" : f.verdict ?? "all");
export const chipFilters = (c: Chip): Partial<Filters> =>
  c === "hint" ? { hint: "yes", verdict: undefined } : { verdict: c === "all" ? undefined : c, hint: undefined };
export const inChip = (r: FRow, c: Chip) => c === "all" || (c === "hint" ? !!r.hint : r.label === c);

// chipCounts are each chip's count over rows, which the caller has already scoped to the image and
// the search, so the counts follow them
export function chipCounts(rows: FRow[]): Record<Chip, number> {
  const n = Object.fromEntries(chips.map((c) => [c, 0])) as Record<Chip, number>;
  for (const r of rows) for (const c of chips) if (inChip(r, c)) n[c]++;
  return n;
}

// scopedRows are the rows a findings table's image, package and search filters leave, in its
// order, which its chips count; image is the URL's image when the gate has it, else null
export const scopedRows = (rows: FRow[], f: Filters, image: string | null) =>
  filterRows(rows.filter((x) => (!image || x.image.slug === image) && (!f.pkg || x.src === f.pkg || x.pkg === f.pkg)), f.q ?? "", rowText);

// shownRows are the rows a findings table shows under the URL's filters, in its order. The finding
// page's j and k walk these same rows, so this is the one place a findings filter is decided.
export const shownRows = (rows: FRow[], f: Filters, image: string | null) => scopedRows(rows, f, image).filter((x) => inChip(x, chipOf(f)));

// nextOpen is the first unlabeled (or unclear) row with a finding page, preferring one whose label
// can still move a check; on a list in effect order that is its first open row
export const nextOpen = (rows: FRow[]) =>
  rows.find((r) => r.row && isOpen(r) && (r.effect === "could-move" || r.effect === "decides")) ?? rows.find((r) => r.row && isOpen(r));

// ---------- paging ----------

export const pageSize = 50;

export interface PageInfo { page: number; pages: number; offset: number; from: number; to: number }

// pageInfo places a 1-based page in total rows, clamped to the last page
export function pageInfo(total: number, page = 1, size = pageSize): PageInfo {
  const pages = Math.max(1, Math.ceil(total / size)), p = Math.min(Math.max(1, page), pages), offset = (p - 1) * size;
  return { page: p, pages, offset, from: total ? offset + 1 : 0, to: Math.min(total, offset + size) };
}

// ---------- the gate list ----------

// square is an image's square in a gate's strip: open changes, changes all judged, or none
export const square = (t: Tally | undefined) => (!t?.total ? "none" : openOf(t) ? "open" : "chg");

// sumTally adds tallies up
export function sumTally(ts: Tally[]): Tally {
  const s: Tally = { tp: 0, fp: 0, unclear: 0, hinted: 0, open: 0, total: 0 };
  for (const t of ts) for (const k of Object.keys(s) as (keyof Tally)[]) s[k] += t[k];
  return s;
}

// shortSource is a claims locator as people say it: a repository and its ref, or a directory's
// name, not the absolute path a local corpus has
export function shortSource(s: string): string {
  const t = s.replace(/^[a-z+]+:\/\//, "").replace(/[/\\]+$/, "");
  const [path, ref] = t.split(/@(?=[^/]*$)/);
  const base = path.split(/[/\\]/).pop() || path;
  return ref ? `${base}@${ref}` : base;
}

// ---------- labels across gates ----------

export interface WideLabel extends GateLabel { gates: string[]; gate: string }

// mergeLabels lists every gate's labels once: a label about an image (or a global one) counts in
// each gate that scans it, and is the same label in each. gate is the first gate holding it, where
// its row opens.
export function mergeLabels(byGate: { gate: string; labels: GateLabel[] }[]): WideLabel[] {
  const by = new Map<string, WideLabel>();
  for (const { gate, labels } of byGate) {
    for (const l of labels) {
      const k = [l.verdict, l.vulnerability, l.package.purl, l.image?.ref ?? "global", l.source, l.lastUpdated].join("|");
      const have = by.get(k);
      if (have) {
        have.gates.push(gate);
        if (!have.row && l.row) Object.assign(have, { row: l.row, gate });
      } else by.set(k, { ...l, gates: [gate], gate });
    }
  }
  return [...by.values()].sort((a, b) => b.lastUpdated.localeCompare(a.lastUpdated));
}

// labelText is what the search box matches a label against
export const labelText = (l: GateLabel) => `${l.vulnerability} ${l.package.name} ${l.package.purl} ${l.justification ?? ""} ${l.author} ${l.image?.name ?? "global"}`;

// crossByGate are the cross-gate findings' rows to act on, one per finding, by the gate that writes it
export function crossByGate(fs: CrossFinding[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const f of fs) {
    const a = f.in[0];
    if (!a) continue;
    out.set(a.gate, [...(out.get(a.gate) ?? []), a.row]);
  }
  return out;
}
