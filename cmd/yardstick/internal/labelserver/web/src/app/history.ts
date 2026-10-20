// history.ts is /ui/history: the labels in the writable claims source (./claims), newest first and
// grouped by day, each with its finding in every gate it sits on. Labels there are files, so undoing
// one is an edit to its file; the page says which.
import type { History, HistoryLabel } from "../gen/wire";
import { el, fill } from "../shared/dom";
import { justWords, plural } from "../shared/words";
import { getJSON } from "./data";
import { pageInfo, pageSize, shortSource } from "./listing";
import { failed, loading, shown } from "./lists";
import { dayKey, dayWords } from "./queuewords";
import { formatRoute, withFilters, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { dataTable } from "./tableview";
import { imageName, verdict, type Verdict } from "./ui";

type HistoryRoute = Extract<Route, { level: "history" }>;

const findingHref = (gate: string, row: string) => formatRoute({ level: "finding", gate, check: null, row, filters: {} });
const time = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
const id = (l: HistoryLabel) => `${l.source}|${l.file}|${l.label.package ?? ""}|${l.label.vulnerability}`;
const chips: [string, string][] = [["all", "All"], ["tp", "TP"], ["fp", "FP"], ["unclear", "Unclear"]];

export function historyView(host: HTMLElement, r0: HistoryRoute, nav: Nav): View {
  let r = r0, seq = 0;
  const alive = shown(r);
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image, reason, note…", "aria-label": "Filter history", value: r.filters.q ?? "",
    oninput: () => nav(withFilters(r, { q: search.value }), true) });
  const chipRow = el("div", { class: "chips", role: "group", "aria-label": "Filter by verdict" });
  const foot = el("span");
  const table = dataTable<HistoryLabel>({
    testid: "history-table", id, rows: [],
    open: (l) => l.rows[0] && nav({ level: "finding", gate: l.rows[0].gate, check: null, row: l.rows[0].row, filters: {} }),
    group: { key: (l) => dayKey(l.label.lastUpdated), header: (k, rows) => el("span", { "data-testid": "history-day", "data-day": k }, el("b", {}, dayWords(k)), el("small", {}, ` · ${plural(rows.length, "label")}`)) },
    columns: [
      { key: "label", label: "Label", cell: (l) => verdict(l.label.verdict as Verdict) },
      { key: "vuln", label: "Vulnerability", cell: (l) => el("span", { class: "strong" }, l.label.vulnerability), title: (l) => l.label.vulnerability, truncate: true },
      { key: "package", label: "Package", cell: (l) => el("span", { class: "mono" }, l.package.name, " ", el("small", {}, l.package.version ?? "")), title: (l) => l.package.purl ?? l.package.name, truncate: true },
      { key: "image", label: "Image", cell: (l) => (l.imageName ? imageName(l.imageName, l.image) : el("span", { class: "muted" }, "global")), title: (l) => l.image ?? "every image", truncate: true },
      { key: "reason", label: "Reason", cell: (l) => (l.label.justification ? justWords(undefined, l.label.verdict, l.label.justification) : el("span", { class: "muted" }, "–")) },
      // an accepted hint carries its note onto the label, so the note is where a hint shows
      { key: "note", label: "Note", cell: (l) => (l.label.notes?.length ? el("span", { "data-testid": "history-note" }, l.label.notes.map((n) => n.text).join(" · ")) : el("span", { class: "muted" }, "–")),
        title: (l) => (l.label.notes ?? []).map((n) => `${n.author}: ${n.text}`).join("\n"), truncate: true },
      { key: "author", label: "Author", cell: (l) => l.label.author, title: (l) => l.label.author, truncate: true },
      { key: "time", label: "Time", cell: (l) => el("time", { datetime: l.label.lastUpdated, title: l.label.lastUpdated }, time(l.label.lastUpdated)), num: true },
      { key: "findings", label: "Findings", cell: (l) => (l.rows.length ? el("span", { class: "gates" }, l.rows.map((g, i) => {
        // a label on a package in two places (log4j's two jars) sits on two rows of one gate
        const n = l.rows.slice(0, i + 1).filter((x) => x.gate === g.gate).length;
        return el("a", { class: "gchip", href: findingHref(g.gate, g.row), title: g.row, "data-testid": "history-link", "data-gate": g.gate, "data-row": g.row }, n > 1 ? `${g.gate} #${n}` : g.gate);
      }))
        : el("span", { class: "muted", title: "no gate scans a match it labels" }, "none")) },
    ],
    empty: "No labels match.",
    foot: () => foot,
  });

  async function update(next: Route) {
    r = next as HistoryRoute;
    const mine = ++seq, f = r.filters, p = new URLSearchParams({ offset: String(((f.page ?? 1) - 1) * pageSize), limit: String(pageSize) });
    if (f.verdict && f.verdict !== "unlabeled") p.set("verdict", f.verdict);
    if (f.q) p.set("q", f.q);
    let h: History;
    try { h = await getJSON<History>(`/api/history?${p}`); } catch (e) { if (alive()) renderShell(host, r, { title: "History", body: failed(e) }); return; }
    if (mine !== seq || !alive()) return;
    if (!host.contains(table.el)) draw(h);
    if (document.activeElement !== search && search.value !== (f.q ?? "")) search.value = f.q ?? "";
    fill(chipRow, chips.map(([v, w]) => el("button", { type: "button", class: "chip", "aria-pressed": String((f.verdict ?? "all") === v), "data-chip": v,
      onclick: () => nav(withFilters(r, { verdict: v === "all" ? undefined : v as Verdict })) }, w)));
    const pi = pageInfo(h.total, f.page);
    const link = (page: number, text: string, testid: string) => el("a", { href: formatRoute(withFilters(r, { page })), "data-testid": testid }, text);
    fill(foot, el("span", { "data-testid": "page-info" }, h.total ? `${pi.from.toLocaleString()}–${pi.to.toLocaleString()} of ${h.total.toLocaleString()}` : "0 labels"),
      pi.page > 1 && [" · ", link(pi.page - 1, "‹ prev", "page-prev")], pi.page < pi.pages && [" · ", link(pi.page + 1, "next ›", "page-next")]);
    table.update(h.labels);
  }

  function draw(h: History) {
    const where = h.sources.map(shortSource).join(", ") || "the writable claims source";
    renderShell(host, r, {
      title: "History",
      sub: `Labels in ${where}, newest first. Each is a line in its claims file, so undoing one is an edit to that file.`,
      body: el("div", { class: "screen" }, el("div", { class: "filters" }, chipRow, search), table.el),
    });
  }

  renderShell(host, r, { title: "History", body: loading() });
  void update(r);
  return { update: (n) => { void update(n); return true; }, key: (e) => table.key(e) };
}
