// findings.ts is the findings table the gate's Findings tab and a check share (UI-RULES: every list
// is the same table, prefiltered): verdict chips whose counts follow the image and the search, the
// search box, the table, and the bulk bar that accepts hints, researches or labels the rows
// selected. The Agent hint cell says what research is doing on a row and offers it
// (researchtable.ts), and the table follows its rows' jobs while any is in flight.
import type { Vocabulary } from "../gen/wire";
import * as api from "../shared/api";
import { doing, inFlight } from "../shared/agent";
import { el, fill, toast } from "../shared/dom";
import { outcome as outcomeOf, outcomeRank } from "../shared/rows";
import { columnHelp as help, labels as words } from "../shared/words";
import { acceptHints, labelOptions, labelRows } from "./data";
import { chipCounts, chipFilters, chipGroups, chipOf, chipWords, effectRank, inChip, isOpen, scopedRows, shownRows, type FRow } from "./listing";
import { bulkResearch, cellFor, follow, started, type Research } from "./researchtable";
import { withFilters, type Route } from "./route";
import type { Nav } from "./shell";
import { dataTable, type Column, type Table } from "./tableview";
import { couldMove, hint, imageName, outcome, verdict } from "./ui";

export const effectCell = (r: Pick<FRow, "effect">) =>
  r.effect === "could-move" ? couldMove() : r.effect ? el("span", { class: r.effect === "counted" ? "muted" : "" }, r.effect) : el("span", { class: "muted" }, "–");

export const hintWords = (h: FRow["hint"]) => (h ? `${words[h.verdict]?.word ?? h.verdict}${h.confidence ? ` · ${h.confidence}` : ""}` : "");

export const findingColumns: Column<FRow>[] = [
  { key: "label", label: "Label", cell: (r) => verdict(r.label), sort: (r) => r.label, help: help.label },
  { key: "vuln", label: "Vulnerability", cell: (r) => el("span", { class: "strong" }, r.vuln), sort: (r) => r.vuln, title: (r) => r.vuln, truncate: true },
  { key: "package", label: "Package", cell: (r) => el("span", { class: "mono" }, r.pkg, " ", el("small", {}, r.version)), sort: (r) => r.pkg, title: (r) => `${r.purl || r.pkg} ${r.version}`, truncate: true },
  { key: "image", label: "Image", cell: (r) => imageName(r.image.name, r.image.ref), sort: (r) => r.image.name, title: (r) => r.image.ref, truncate: true },
  { key: "outcome", label: "Outcome", cell: (r) => outcome(r.change, r.label) ?? el("span", { class: "muted" }, "–"), sort: (r) => outcomeRank(outcomeOf(r.change, r.label)), help: help.outcome },
  { key: "hint", label: "Agent hint", cell: (r) => (r.hint ? hint(hintWords(r.hint)) : el("span", { class: "muted" }, "–")), sort: (r) => hintWords(r.hint), help: help.hint },
  { key: "effect", label: "Effect", cell: effectCell, sort: (r) => effectRank(r.effect), help: help.effect },
];

// labelPicker is the "Label as…" control: picking a verdict (and reason) calls on with it
export function labelPicker(vocab: Vocabulary | undefined, on: (verdict: string, justification: string) => void) {
  const s = el("select", { class: "select label-as", "aria-label": "Label as", "data-testid": "label-as",
    onchange: () => { const [v, j] = s.value.split(":"); s.value = ""; if (v) on(v, j); } },
  el("option", { value: "" }, "Label as…"),
  labelOptions(vocab).map((o) => el("option", { value: o.value, title: o.title }, o.text)));
  return s;
}

export interface FindingsOptions {
  gate: string;
  route: Route;
  nav: Nav;
  vocab: Vocabulary | undefined;
  open: (r: FRow) => void;
  reload: () => void;         // after a write: fetch again and update
  extra?: HTMLElement[];      // more controls in the filter row, before the search box
  testid?: string;
  research: Research;
  fresh: () => Promise<FRow[]>; // the rows read again, for research in flight
}

export interface FindingsList {
  el: HTMLElement[];
  table: Table<FRow>;
  // update shows rows under a route's filters; image is the selected image's slug when it exists
  update(r: Route, rows: FRow[], image: string | null): FRow[];
}

export function findingsList(o: FindingsOptions): FindingsList {
  let r = o.route, rows: FRow[] = [], image: string | null = null;
  const byId = () => new Map(rows.map((x) => [x.id, x]));
  const redraw = async () => { const next = await o.fresh(); out.update(r, next, image); };
  // start researches rows through the gate, from a table, and shows them queued in place
  async function start(ids: string[]) {
    try {
      const res = await api.research(o.gate, { rows: ids, from: "table" });
      started(res.queued, res.skipped);
    } catch (e) {
      toast((e as Error).message, true);
      return false;
    }
    await redraw().catch(() => undefined);
    return true;
  }
  const columns = findingColumns.map((c): Column<FRow> => (c.key !== "hint" ? c : { ...c,
    cell: (x) => cellFor({ hint: x.hint && hint(hintWords(x.hint)), research: x.research, open: isOpen(x), researched: !!x.researched }, o.research,
      x.row ? () => void start([x.row!]) : null) }));
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image…", "aria-label": "Filter matches", value: r.filters.q ?? "",
    oninput: () => o.nav(withFilters(r, { q: search.value }), true) });
  const chipRow = el("div", { class: "chips", role: "group", "aria-label": "Filter by label" });
  // the scan map's package filter, shown while it's on with a way off
  const pkgChip = el("span", { class: "scope", hidden: true, "data-testid": "package-chip" });
  const table = dataTable<FRow>({
    columns, rows: [], id: (x) => x.id, sort: null, open: o.open, testid: o.testid ?? "findings-table",
    select: { bulk: (ids, clear) => {
      const picked = ids.map((id) => byId().get(id)).filter((x): x is FRow => !!x && !!x.row);
      const hinted = picked.filter((x) => x.hint).length;
      const rs = bulkResearch(picked.map((x) => ({ id: x.row!, open: isOpen(x), hinted: !!x.hint, doing: doing(x.research, { open: isOpen(x), researched: !!x.researched }).kind, shares: x.shares })), o.research,
        { start, clear, page: (ids) => o.nav({ level: "research", scope: `gate:${o.gate}`, rows: ids, filters: {} }) });
      return [
        rs.button,
        el("button", { type: "button", class: `btn${!rs.leads && hinted ? " go" : ""}`, "data-variant": "outline", "data-size": "sm", "data-testid": "bulk-accept", disabled: !hinted,
          onclick: async () => { if (await acceptHints(o.gate, picked)) clear(); o.reload(); } }, `Accept hints (${hinted})`),
        labelPicker(o.vocab, async (v, j) => { if (await labelRows(o.gate, picked.map((x) => x.row!), v, j)) clear(); o.reload(); }),
        rs.why,
      ];
    } },
    foot: (shown) => `${shown.length.toLocaleString()} ${shown.length === 1 ? "match" : "matches"}`,
  });

  const out: FindingsList = {
    el: [el("div", { class: "filters" }, chipRow, pkgChip, o.extra, search), table.el],
    table,
    update(next, all, img) {
      r = next;
      rows = all;
      image = img;
      if (document.activeElement !== search && search.value !== (r.filters.q ?? "")) search.value = r.filters.q ?? "";
      const pkg = r.filters.pkg;
      pkgChip.hidden = !pkg;
      fill(pkgChip, pkg && ["package: ", el("b", {}, pkg), el("button", { type: "button", class: "x", "aria-label": "Clear package filter", onclick: () => o.nav(withFilters(r, { pkg: undefined })) }, "×")]);
      // the chips count what the image, the package and the search leave, so they follow the rail
      // "Researching" shows only while some row in view has a job on it (or while it's picked)
      const scoped = scopedRows(all, r.filters, image), n = chipCounts(scoped), on = chipOf(r.filters);
      const busy = scoped.filter((x) => inChip(x, "researching")).length;
      const chip = (c: typeof on, count: number) => el("button", { type: "button", class: "chip", "aria-pressed": String(c === on), "data-chip": c,
        onclick: () => o.nav(withFilters(r, chipFilters(c))) }, chipWords[c], " ", el("b", {}, count.toLocaleString()));
      fill(chipRow, chipGroups.map((g, i) => el("div", { class: "chip-group" }, g.map((c) => chip(c, n[c])),
        i === chipGroups.length - 1 && (busy > 0 || on === "researching") && chip("researching", busy))));
      const shown = shownRows(all, r.filters, image);
      table.update(shown, image ? ["image"] : []);
      return shown;
    },
  };
  follow(table.el, () => rows.some((x) => inFlight(x.research)), redraw);
  return out;
}

// grouping is the check's "Group by": the table's group headers, or none
export type Grouping = "none" | "image" | "package";
export function grouping(g: Grouping) {
  if (g === "none") return null;
  const key = g === "image" ? (r: FRow) => r.image.name : (r: FRow) => r.pkg;
  return { key, header: (k: string, rs: FRow[]) => [k, el("span", { class: "muted" }, ` · ${rs.length} · ${rs.filter((x) => x.label === "unlabeled").length} unlabeled`)] };
}
