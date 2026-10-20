// tableview.ts draws the data table every list of findings or labels uses (UI-RULES: "every list
// is the same table, prefiltered"), on Basecoat's table classes: sortable headers, optional row
// checkboxes with a bulk-action bar, optional group headers, and cells that truncate with the full
// value on hover.
import { el, fill, type Child } from "../shared/dom";
import { groupRows, nextSort, sortRows, type Cell, type Sort } from "./table";

export interface Column<T> {
  key: string;
  label: string;
  cell: (row: T) => Child;
  sort?: (row: T) => Cell;      // the column sorts when given
  title?: (row: T) => string;   // the full value on hover; a truncating column wants one
  truncate?: boolean;
  num?: boolean;                // right-aligned, tabular figures
}

export interface TableOptions<T> {
  columns: Column<T>[];
  rows: T[];
  id: (row: T) => string;
  sort?: Sort | null;
  onSort?: (s: Sort) => void;
  group?: { key: (row: T) => string; header: (key: string, rows: T[]) => Child } | null;
  // with select, rows get checkboxes, and bulk is the bar's actions while any are checked
  select?: { bulk: (ids: string[], clear: () => void) => Child };
  open?: (row: T) => void;      // a click on the row, outside its checkbox
  empty?: Child;
  foot?: (shown: T[]) => Child;
  testid?: string;
}

export interface Table<T> {
  el: HTMLElement;
  // update shows new rows (a new filter), keeping the sort and the checked rows still present, and
  // hides the columns named
  update(rows: T[], hide?: string[]): void;
  selected(): string[];
  clear(): void;
}

export function dataTable<T>(o: TableOptions<T>): Table<T> {
  let rows = o.rows, sort = o.sort ?? null, hide = new Set<string>();
  const chosen = new Set<string>();
  const cols = () => o.columns.filter((c) => !hide.has(c.key));

  const bulkCount = el("span", { class: "bulk-n" });
  const bulkActions = el("span", { class: "bulk-actions" });
  const bulk = el("div", { class: "bulk", hidden: true, "data-testid": "bulk-bar" }, bulkCount, el("span", { class: "sp" }), bulkActions,
    el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", onclick: () => clear() }, "Clear"));
  const all = el("input", { type: "checkbox", "aria-label": "Select every row shown", onchange: () => {
    for (const r of rows) if (all.checked) chosen.add(o.id(r)); else chosen.delete(o.id(r));
    draw();
  } });
  const thead = el("thead");
  const tbody = el("tbody");
  const foot = el("div", { class: "dt-foot" });
  const root = el("div", { class: "dt", "data-testid": o.testid ?? "data-table" },
    bulk, el("div", { class: "dt-scroll" }, el("table", { class: "table" }, thead, tbody)), foot);

  function header() {
    fill(thead, el("tr", {},
      o.select && el("th", { class: "ck" }, all),
      cols().map((c) => {
        const on = sort?.key === c.key;
        return el("th", { class: c.num ? "num" : "", "aria-sort": on ? (sort!.dir === "asc" ? "ascending" : "descending") : c.sort ? "none" : null },
          c.sort
            ? el("button", { type: "button", class: "sort", onclick: () => { sort = nextSort(sort, c.key); o.onSort?.(sort); draw(); } },
              c.label, el("span", { class: "dir", "aria-hidden": "true" }, on ? (sort!.dir === "asc" ? "▲" : "▼") : ""))
            : c.label);
      })));
  }

  function line(r: T) {
    const id = o.id(r), on = chosen.has(id);
    const box = o.select && el("input", { type: "checkbox", checked: on, "aria-label": "Select", onchange: () => toggle(id) });
    return el("tr", {
      "data-id": id, "data-state": on ? "selected" : null, class: o.open || o.select ? "clickable" : "",
      onclick: (e: MouseEvent) => {
        if (e.target instanceof HTMLInputElement || (e.target as HTMLElement).closest("a, button")) return;
        if (o.open) o.open(r); else if (o.select) toggle(id);
      },
    },
    box && el("td", { class: "ck" }, box),
    cols().map((c) => {
      // a table cell ignores max-width, so a truncating cell holds a block that has one
      return el("td", { class: c.num ? "num" : null, title: c.title?.(r) }, c.truncate ? el("div", { class: "trunc" }, c.cell(r)) : c.cell(r));
    }));
  }

  function draw() {
    // a checked row the new filter hides is unchecked, so a bulk action only reaches rows on screen
    const ids = new Set(rows.map(o.id));
    for (const id of chosen) if (!ids.has(id)) chosen.delete(id);
    const col = sort && o.columns.find((c) => c.key === sort!.key);
    const shown = col?.sort ? sortRows(rows, col.sort, sort!.dir) : rows;
    const span = cols().length + (o.select ? 1 : 0);
    header();
    if (!shown.length) fill(tbody, el("tr", {}, el("td", { class: "empty", colspan: span }, o.empty ?? "Nothing matches.")));
    else if (o.group) fill(tbody, groupRows(shown, o.group.key).map((g) => [
      el("tr", { class: "group" }, el("td", { colspan: span }, o.group!.header(g.key, g.rows))), g.rows.map(line)]));
    else fill(tbody, shown.map(line));
    all.checked = shown.length > 0 && shown.every((r) => chosen.has(o.id(r)));
    all.indeterminate = !all.checked && chosen.size > 0;
    bulk.hidden = chosen.size === 0;
    bulkCount.textContent = `${chosen.size} selected`;
    if (o.select && chosen.size) fill(bulkActions, o.select.bulk([...chosen], clear));
    fill(foot, o.foot ? o.foot(shown) : `${shown.length.toLocaleString()} ${shown.length === 1 ? "row" : "rows"}`);
  }
  function toggle(id: string) {
    if (chosen.has(id)) chosen.delete(id); else chosen.add(id);
    draw();
  }
  function clear() {
    chosen.clear();
    draw();
  }

  draw();
  return {
    el: root,
    update(next, h = []) { rows = next; hide = new Set(h); draw(); },
    selected: () => [...chosen],
    clear,
  };
}
