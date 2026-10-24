// tableview.ts draws the data table every list of findings or labels uses (UI-RULES: "every list
// is the same table, prefiltered"), on Basecoat's table classes: sortable headers, optional row
// checkboxes with a bulk-action bar, optional group headers, and cells that truncate with the full
// value on hover.
import { el, fill, type Child } from "../shared/dom";
import { groupRows, nextSort, sortRows, type Cell, type Group, type Sort } from "./table";

export interface Column<T> {
  key: string;
  label: string;
  cell: (row: T) => Child;
  sort?: (row: T) => Cell;      // the column sorts when given
  title?: (row: T) => string;   // the full value on hover; a truncating column wants one
  truncate?: boolean;
  num?: boolean;                // right-aligned, tabular figures
  help?: string;                // what the column means, behind a "?" by its header (UI-RULES 11)
}

// tip is the one tooltip every header's "?" shares. It's fixed to the viewport because the table
// clips its overflow, which would cut a tooltip drawn inside it.
let tip: HTMLElement | null = null;
function showTip(at: HTMLElement, text: string) {
  tip ??= document.body.appendChild(el("div", { class: "coltip", role: "tooltip", id: "coltip" }));
  // a line after the first is one value, "name: what it means", so the name is bold
  fill(tip, text.split("\n").map((l, i) => { const at = l.indexOf(": "); return el("div", {}, i && at > 0 ? [el("b", {}, l.slice(0, at)), l.slice(at)] : l); }));
  tip.hidden = false;
  const b = at.getBoundingClientRect();
  tip.style.top = `${b.bottom + 6}px`;
  tip.style.left = `${Math.max(8, Math.min(b.left - 8, innerWidth - tip.offsetWidth - 8))}px`;
}
const hideTip = () => { if (tip) tip.hidden = true; };

function helpMark(text: string) {
  return el("span", { class: "colhelp", tabindex: "0", role: "img", "aria-label": text, "data-testid": "column-help",
    onmouseenter: (e) => showTip(e.currentTarget as HTMLElement, text), onfocus: (e) => showTip(e.currentTarget as HTMLElement, text),
    onmouseleave: hideTip, onblur: hideTip }, "?");
}

export interface TableOptions<T> {
  columns: Column<T>[];
  rows: T[];
  id: (row: T) => string;
  sort?: Sort | null;
  onSort?: (s: Sort) => void;
  group?: { key: (row: T) => string; header: (key: string, rows: T[]) => Child } | null;
  // with select, rows get checkboxes, and bulk is the bar's actions while any are checked. keep holds
  // the checks on rows a new filter hides (the research page builds one batch across searches),
  // link is the rows checked and unchecked with a row (research: every match in its job), and
  // changed hears the checked rows after every draw
  select?: { bulk: (ids: string[], clear: () => void) => Child; keep?: boolean; link?: (id: string) => string[]; changed?: (ids: string[]) => void };
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
  // check checks or unchecks rows (and the rows linked to them), as their boxes would
  check(ids: string[], on: boolean): void;
  clear(): void;
  // regroup draws the rows under other group headers, or none
  regroup(g: TableOptions<T>["group"]): void;
  // key moves the row cursor (j / k) and opens its row (Enter), and says whether it did
  key(e: KeyboardEvent): boolean;
}

export function dataTable<T>(o: TableOptions<T>): Table<T> {
  let rows = o.rows, sort = o.sort ?? null, hide = new Set<string>();
  // order is the rows as drawn, groups included, which the cursor walks; cursor is its index. shown
  // and groups are the rows and groups as drawn, which a change of selection marks in place
  let order: T[] = [], cursor = -1, shown: T[] = [], groups: Group<T>[] = [];
  const chosen = new Set<string>();
  const cols = () => o.columns.filter((c) => !hide.has(c.key));

  const bulkCount = el("span", { class: "bulk-n" });
  const bulkActions = el("span", { class: "bulk-actions" });
  const bulk = el("div", { class: "bulk", hidden: true, "data-testid": "bulk-bar" }, bulkCount, el("span", { class: "sp" }), bulkActions,
    el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", onclick: () => clear() }, "Clear"));
  const all: HTMLInputElement = el("input", { type: "checkbox", "aria-label": "Select every row shown", onchange: () => check(rows.map(o.id), all.checked) });
  const thead = el("thead");
  const tbody = el("tbody");
  const foot = el("div", { class: "dt-foot" });
  const root = el("div", { class: "dt", "data-testid": o.testid ?? "data-table" },
    bulk, el("div", { class: "dt-scroll" }, el("table", { class: "table" }, thead, tbody)), foot);

  function header() {
    hideTip(); // a redraw drops the "?" under the pointer before it can say so
    fill(thead, el("tr", {},
      o.select && el("th", { class: "ck" }, all),
      cols().map((c) => {
        const on = sort?.key === c.key;
        return el("th", { class: c.num ? "num" : "", "aria-sort": on ? (sort!.dir === "asc" ? "ascending" : "descending") : c.sort ? "none" : null },
          c.sort
            ? el("button", { type: "button", class: "sort", onclick: () => { sort = nextSort(sort, c.key); o.onSort?.(sort); draw(); } },
              c.label, el("span", { class: "dir", "aria-hidden": "true" }, on ? (sort!.dir === "asc" ? "▲" : "▼") : ""))
            : c.label,
          // outside the sort button, so hovering or clicking it never sorts
          c.help && helpMark(c.help));
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
    // a checked row the new filter hides is unchecked, so a bulk action only reaches rows on screen,
    // unless the table keeps checks
    if (!o.select?.keep) {
      const ids = new Set(rows.map(o.id));
      for (const id of chosen) if (!ids.has(id)) chosen.delete(id);
    }
    const col = sort && o.columns.find((c) => c.key === sort!.key);
    shown = col?.sort ? sortRows(rows, col.sort, sort!.dir) : rows;
    groups = o.group ? groupRows(shown, o.group.key) : [];
    const span = cols().length + (o.select ? 1 : 0);
    header();
    if (!shown.length) fill(tbody, el("tr", {}, el("td", { class: "empty", colspan: span }, o.empty ?? "Nothing matches.")));
    else if (o.group) fill(tbody, groups.map((g) => [el("tr", { class: "group", "data-group": g.key }, el("td", { colspan: span })), g.rows.map(line)]));
    else fill(tbody, shown.map(line));
    order = o.group ? groups.flatMap((g) => g.rows) : shown;
    cursor = Math.min(cursor, order.length - 1);
    mark();
    fill(foot, o.foot ? o.foot(shown) : `${shown.length.toLocaleString()} ${shown.length === 1 ? "row" : "rows"}`);
    marks();
  }
  // marks shows the selection on the rows as drawn, in place, so a box keeps its focus: each row's
  // box, the header's box, the group headers (which count what's checked) and the bulk bar
  function marks() {
    for (const tr of tbody.querySelectorAll<HTMLElement>("tr[data-id]")) {
      const on = chosen.has(tr.dataset.id!), box = tr.querySelector<HTMLInputElement>("td.ck input");
      if (on) tr.dataset.state = "selected"; else delete tr.dataset.state;
      if (box) box.checked = on;
    }
    if (o.group) {
      for (const tr of tbody.querySelectorAll<HTMLElement>("tr.group")) {
        const g = groups.find((x) => x.key === tr.dataset.group), td = tr.firstElementChild!;
        if (!g) continue;
        const focused = td.contains(document.activeElement);
        fill(td, o.group.header(g.key, g.rows));
        if (focused) td.querySelector<HTMLElement>("input, button, a")?.focus();
      }
    }
    all.checked = shown.length > 0 && shown.every((r) => chosen.has(o.id(r)));
    all.indeterminate = !all.checked && shown.some((r) => chosen.has(o.id(r)));
    bulk.hidden = chosen.size === 0;
    bulkCount.textContent = `${chosen.size} selected`;
    if (o.select && chosen.size) fill(bulkActions, o.select.bulk([...chosen], clear));
    o.select?.changed?.([...chosen]);
  }
  function mark() {
    const at = cursor < 0 ? null : o.id(order[cursor]);
    for (const tr of tbody.querySelectorAll<HTMLElement>("tr[data-id]")) tr.classList.toggle("cursor", tr.dataset.id === at);
  }
  function toggle(id: string) {
    check([id], !chosen.has(id));
  }
  function check(ids: string[], on: boolean) {
    for (const id of ids) for (const x of o.select?.link?.(id) ?? [id]) if (on) chosen.add(x); else chosen.delete(x);
    marks();
  }
  function clear() {
    chosen.clear();
    marks();
  }

  draw();
  return {
    el: root,
    update(next, h = []) { rows = next; hide = new Set(h); draw(); },
    selected: () => [...chosen],
    check,
    clear,
    regroup(g) { o.group = g; draw(); },
    key(e) {
      if (!order.length) return false;
      if (e.key === "j" || e.key === "k") {
        cursor = Math.max(0, Math.min(order.length - 1, cursor + (e.key === "j" ? 1 : -1)));
        mark();
        tbody.querySelector(".cursor")?.scrollIntoView({ block: "nearest" });
        return true;
      }
      if (e.key === "Enter" && cursor >= 0 && o.open) {
        o.open(order[cursor]);
        return true;
      }
      return false;
    },
  };
}
