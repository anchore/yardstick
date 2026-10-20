// labelstable.ts is the labels table, the gate's Labels tab and the workspace-wide one: verdict
// chips, a search box, the table and its pager. The findings table's shape without unlabeled rows,
// plus reason, source and author.
import type { GateLabel } from "../gen/wire";
import { el, fill, type Child } from "../shared/dom";
import { pageInfo, shortSource } from "./listing";
import { formatRoute, withFilters, type Route, type VerdictFilter } from "./route";
import type { Nav } from "./shell";
import { dataTable, type Column, type Table } from "./tableview";
import { imageName, verdict } from "./ui";

export type LRow = GateLabel & { gate?: string; gates?: string[] };

const reasonCell = (l: LRow) => !l.justification ? el("span", { class: "muted" }, "–")
  // not-recorded is what most ported labels carry, so it's muted, not read
  : el("span", { class: l.justification === "not-recorded" ? "muted" : "" }, l.justification);

// no column sorts: the table shows one page, newest first, and a sort would order only that page
// ponytail: sort server-side (a sort= on GET labels) if people want to sort every label
export function labelColumns(wide: boolean): Column<LRow>[] {
  return [
    { key: "label", label: "Label", cell: (l) => verdict(l.verdict as "tp" | "fp" | "unclear") },
    { key: "vuln", label: "Vulnerability", cell: (l) => el("span", { class: "strong" }, l.vulnerability), title: (l) => l.vulnerability, truncate: true },
    { key: "package", label: "Package", cell: (l) => el("span", { class: "mono" }, l.package.name, " ", el("small", {}, l.package.version ?? "")), title: (l) => `${l.package.purl ?? l.package.name} ${l.package.version ?? ""}`, truncate: true },
    { key: "image", label: "Image", cell: (l) => (l.image ? imageName(l.image.name, l.image.ref) : el("span", { class: "muted" }, "global")), title: (l) => l.image?.ref ?? "every image", truncate: true },
    { key: "reason", label: "Reason", cell: reasonCell },
    { key: "source", label: "Source", cell: (l) => el("span", { class: "mono" }, shortSource(l.source)), title: (l) => l.source, truncate: true },
    { key: "author", label: "Author", cell: (l) => l.author, truncate: true, title: (l) => l.author },
    ...(wide ? [{ key: "gates", label: "Gates", cell: (l: LRow) => (l.gates ?? []).join(", "), title: (l: LRow) => (l.gates ?? []).join(", "), truncate: true }] : []),
  ];
}

export const labelId = (l: GateLabel) => [l.verdict, l.vulnerability, l.package.purl, l.image?.ref ?? "global", l.source, l.lastUpdated].join("|");

export interface LabelsOptions {
  route: Route;
  nav: Nav;
  wide?: boolean;                  // the workspace-wide table, with a Gates column
  open: (l: LRow) => void;
}

export interface LabelsTable {
  el: HTMLElement[];
  table: Table<LRow>;
  // update shows one page of labels: the total under every filter and the per-verdict counts
  update(r: Route, page: LRow[], total: number, counts: Record<string, number>, imageScoped: boolean): void;
}

const chipVerdicts: (VerdictFilter | "all")[] = ["all", "tp", "fp", "unclear"];
const chipWord: Record<string, string> = { all: "All", tp: "TP", fp: "FP", unclear: "Unclear" };

export function labelsTable(o: LabelsOptions): LabelsTable {
  let r = o.route;
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, reason…", "aria-label": "Filter labels", value: r.filters.q ?? "",
    oninput: () => o.nav(withFilters(r, { q: search.value }), true) });
  const chipRow = el("div", { class: "chips", role: "group", "aria-label": "Filter by verdict" });
  let foot: Child = null;
  const table = dataTable<LRow>({
    columns: labelColumns(!!o.wide), rows: [], id: labelId, sort: null, testid: "labels-table",
    open: (l) => o.open(l), empty: "No labels match.", foot: () => foot,
  });
  return {
    el: [el("div", { class: "filters" }, chipRow, search), table.el],
    table,
    update(next, rows, total, counts, imageScoped) {
      r = next;
      if (document.activeElement !== search && search.value !== (r.filters.q ?? "")) search.value = r.filters.q ?? "";
      const on = r.filters.verdict ?? "all", all = (counts.tp ?? 0) + (counts.fp ?? 0) + (counts.unclear ?? 0);
      fill(chipRow, chipVerdicts.map((v) => el("button", { type: "button", class: "chip", "aria-pressed": String(v === on), "data-chip": v,
        onclick: () => o.nav(withFilters(r, { verdict: v === "all" ? undefined : v })) },
      chipWord[v], " ", el("b", {}, (v === "all" ? all : counts[v] ?? 0).toLocaleString()))));
      const p = pageInfo(total, r.filters.page);
      const link = (page: number, text: string) => el("a", { href: formatRoute(withFilters(r, { page })), "data-testid": `page-${text.includes("next") ? "next" : "prev"}` }, text);
      foot = [el("span", { "data-testid": "page-info" }, total ? `${p.from.toLocaleString()}–${p.to.toLocaleString()} of ${total.toLocaleString()}` : "0 labels"),
        p.page > 1 && [" · ", link(p.page - 1, "‹ prev")], p.page < p.pages && [" · ", link(p.page + 1, "next ›")]];
      table.update(rows, imageScoped ? ["image"] : []);
    },
  };
}
