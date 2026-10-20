// history.ts is /ui/history: the labels in the writable claims source (./claims), newest first and
// grouped by day, each with its finding in every gate it sits on. since= scopes it to what was
// written since the server started (the default), since a picked time, or all; a label removed here
// leaves ./claims, so a label another claims source holds decides its rows again.
import type { History, HistoryLabel, LabelKey } from "../gen/wire";
import { el, fill } from "../shared/dom";
import { columnHelp, justWords, plural } from "../shared/words";
import { getJSON, revert } from "./data";
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
const keyOf = (l: HistoryLabel): LabelKey => ({ source: l.source, file: l.file, package: l.label.package ?? "", vulnerability: l.label.vulnerability });
// local is an RFC 3339 time as a datetime-local input's value, in the browser's time zone
const local = (iso: string) => { const d = new Date(iso); return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16); };

// query is the API's filters for the route's: no since is the server's start, all is no since
function query(r: HistoryRoute) {
  const f = r.filters, p = new URLSearchParams();
  if (f.since !== "all") p.set("since", f.since ?? "start");
  if (f.verdict && f.verdict !== "unlabeled") p.set("verdict", f.verdict);
  if (f.q) p.set("q", f.q);
  return p;
}

export function historyView(host: HTMLElement, r0: HistoryRoute, nav: Nav): View {
  let r = r0, seq = 0;
  const alive = shown(r);
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image, reason, note…", "aria-label": "Filter history", value: r.filters.q ?? "",
    oninput: () => nav(withFilters(r, { q: search.value }), true) });
  const chipRow = el("div", { class: "chips", role: "group", "aria-label": "Filter by verdict" });
  const since: HTMLSelectElement = el("select", { class: "select since", "data-testid": "history-since", "aria-label": "Since",
    onchange: () => nav(withFilters(r, { since: since.value === "start" ? undefined : since.value === "all" ? "all" : started })) });
  const sinceTime: HTMLInputElement = el("input", { type: "datetime-local", class: "input since-time", "data-testid": "history-since-time", "aria-label": "Since time",
    onchange: () => sinceTime.value && nav(withFilters(r, { since: new Date(sinceTime.value).toISOString() })) });
  const removeAll = el("button", { type: "button", class: "btn", "data-variant": "outline", "data-size": "sm", "data-testid": "history-remove-all", onclick: () => ask(total, () => everyShown()) });
  const confirm = el("div", { class: "confirm", role: "alertdialog", "aria-label": "Confirm removal", "data-testid": "history-confirm", hidden: true });
  const empty = el("span");
  const foot = el("span");
  let started = "", where = "", total = 0, shownLabels: HistoryLabel[] = [];
  const table = dataTable<HistoryLabel>({
    testid: "history-table", id, rows: [],
    open: (l) => l.rows[0] && nav({ level: "finding", gate: l.rows[0].gate, check: null, row: l.rows[0].row, filters: {} }),
    group: { key: (l) => dayKey(l.label.lastUpdated), header: (k, rows) => el("span", { "data-testid": "history-day", "data-day": k }, el("b", {}, dayWords(k)), el("small", {}, ` · ${plural(rows.length, "label")}`)) },
    columns: [
      { key: "label", label: "Label", cell: (l) => verdict(l.label.verdict as Verdict), help: columnHelp.label },
      { key: "vuln", label: "Vulnerability", cell: (l) => el("span", { class: "strong" }, l.label.vulnerability), title: (l) => l.label.vulnerability, truncate: true },
      { key: "package", label: "Package", cell: (l) => el("span", { class: "mono" }, l.package.name, " ", el("small", {}, l.package.version ?? "")), title: (l) => l.package.purl ?? l.package.name, truncate: true },
      { key: "image", label: "Image", cell: (l) => (l.imageName ? imageName(l.imageName, l.image) : el("span", { class: "muted" }, "global")), title: (l) => l.image ?? "every image", truncate: true, help: columnHelp.image },
      { key: "reason", label: "Reason", cell: (l) => (l.label.justification ? justWords(undefined, l.label.verdict, l.label.justification) : el("span", { class: "muted" }, "–")), help: columnHelp.reason },
      // an accepted hint carries its note onto the label, so the note is where a hint shows
      { key: "note", label: "Note", cell: (l) => (l.label.notes?.length ? el("span", { "data-testid": "history-note" }, l.label.notes.map((n) => n.text).join(" · ")) : el("span", { class: "muted" }, "–")),
        title: (l) => (l.label.notes ?? []).map((n) => `${n.author}: ${n.text}`).join("\n"), truncate: true, help: columnHelp.note },
      { key: "author", label: "Author", cell: (l) => l.label.author, title: (l) => l.label.author, truncate: true },
      { key: "time", label: "Time", cell: (l) => el("time", { datetime: l.label.lastUpdated, title: l.label.lastUpdated }, time(l.label.lastUpdated)), num: true },
      { key: "findings", label: "Matches", cell: (l) => (l.rows.length ? el("span", { class: "gates" }, l.rows.map((g, i) => {
        // a label on a package in two places (log4j's two jars) sits on two rows of one gate
        const n = l.rows.slice(0, i + 1).filter((x) => x.gate === g.gate).length;
        return el("a", { class: "gchip", href: findingHref(g.gate, g.row), title: g.row, "data-testid": "history-link", "data-gate": g.gate, "data-row": g.row }, n > 1 ? `${g.gate} #${n}` : g.gate);
      }))
        : el("span", { class: "muted", title: "no gate scans a match it labels" }, "none")), help: columnHelp.findings },
      { key: "remove", label: "", cell: (l) => el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", "data-testid": "history-remove",
        title: `Remove this label from ${shortSource(l.source)}`, onclick: () => void revert([keyOf(l)]) }, "Remove") },
    ],
    select: { bulk: (ids) => el("button", { type: "button", class: "btn", "data-variant": "outline", "data-size": "sm", "data-testid": "history-remove-selected",
      onclick: () => ask(ids.length, async () => shownLabels.filter((l) => ids.includes(id(l))).map(keyOf)) }, `Remove selected (${ids.length})`) },
    empty,
    foot: () => foot,
  });

  // ask confirms a removal of more than one label in the page, then removes them; one goes at once
  function ask(n: number, keys: () => Promise<LabelKey[]>) {
    const go = async () => { confirm.hidden = true; void revert(await keys()); };
    if (n === 1) return void go();
    const yes = el("button", { type: "button", class: "btn", "data-variant": "destructive", "data-size": "sm", "data-testid": "history-confirm-remove", onclick: go }, `Remove ${plural(n, "label")}`);
    fill(confirm, el("span", {}, `Remove ${plural(n, "label")} from ${where}? Where another claims source labels the same match, its label decides again.`),
      el("span", { class: "sp" }), yes,
      el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", "data-testid": "history-confirm-cancel", onclick: () => (confirm.hidden = true) }, "Cancel"));
    confirm.hidden = false;
    yes.focus();
  }
  // everyShown is every label the filters match, on every page
  async function everyShown() {
    const p = query(r);
    p.set("limit", String(total));
    return (await getJSON<History>(`/api/history?${p}`)).labels.map(keyOf);
  }

  async function update(next: Route) {
    r = next as HistoryRoute;
    const mine = ++seq, f = r.filters, p = query(r);
    p.set("offset", String(((f.page ?? 1) - 1) * pageSize));
    p.set("limit", String(pageSize));
    let h: History;
    try { h = await getJSON<History>(`/api/history?${p}`); } catch (e) { if (alive()) renderShell(host, r, { title: "History", body: failed(e) }); return; }
    if (mine !== seq || !alive()) return;
    if (!host.contains(table.el)) draw(h);
    if (document.activeElement !== search && search.value !== (f.q ?? "")) search.value = f.q ?? "";
    started = h.started; total = h.total; shownLabels = h.labels; confirm.hidden = true;
    const picked = f.since && f.since !== "all";
    fill(since, el("option", { value: "start" }, `Since the server started, ${time(started)}`), el("option", { value: "pick" }, "Since a time…"), el("option", { value: "all" }, "All time"));
    since.value = picked ? "pick" : f.since ?? "start";
    sinceTime.hidden = !picked;
    if (picked && document.activeElement !== sinceTime) sinceTime.value = local(f.since!);
    removeAll.disabled = !total;
    fill(removeAll, total > 1 ? `Remove all ${total.toLocaleString()} shown` : "Remove all shown");
    fill(empty, f.since ? "No labels match." : "No labels written since the server started. Pick an earlier time, or All time.");
    const chip = ([v, w]: [string, string]) => el("button", { type: "button", class: "chip", "aria-pressed": String((f.verdict ?? "all") === v), "data-chip": v,
      onclick: () => nav(withFilters(r, { verdict: v === "all" ? undefined : v as Verdict })) }, w);
    // "All" stands alone and the verdicts share a group, as on the match tables
    fill(chipRow, el("div", { class: "chip-group" }, chip(chips[0])), el("div", { class: "chip-group" }, chips.slice(1).map(chip)));
    const pi = pageInfo(h.total, f.page);
    const link = (page: number, text: string, testid: string) => el("a", { href: formatRoute(withFilters(r, { page })), "data-testid": testid }, text);
    fill(foot, el("span", { "data-testid": "page-info" }, h.total ? `${pi.from.toLocaleString()}–${pi.to.toLocaleString()} of ${h.total.toLocaleString()}` : "0 labels"),
      pi.page > 1 && [" · ", link(pi.page - 1, "‹ prev", "page-prev")], pi.page < pi.pages && [" · ", link(pi.page + 1, "next ›", "page-next")]);
    table.update(h.labels);
  }

  function draw(h: History) {
    where = h.sources.map(shortSource).join(", ") || "the writable claims source";
    renderShell(host, r, {
      title: "History",
      sub: `Labels in ${where}, newest first. Removing one lets a label in another claims source decide its match again.`,
      body: el("div", { class: "screen" }, el("div", { class: "filters" }, chipRow, since, sinceTime, search, removeAll), confirm, table.el),
    });
  }

  renderShell(host, r, { title: "History", body: loading() });
  void update(r);
  return {
    update: (n) => { void update(n); return true; },
    key: (e) => {
      if (e.key === "Escape" && !confirm.hidden) { confirm.hidden = true; return true; }
      return table.key(e);
    },
  };
}
