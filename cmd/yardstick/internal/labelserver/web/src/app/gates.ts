// gates.ts is level 0, /ui/gates/: every gate in the workspace, one per row, with tabs for the open
// findings across gates (today's every-gate queue, as a table) and every label in the workspace.
import type { CrossFinding, GateListItem, SharedState } from "../gen/wire";
import { el, fill } from "../shared/dom";
import { pkgOf } from "../shared/rows";
import { plural } from "../shared/words";
import { workBanner, type Work } from "./banner";
import { acceptCross, everyLabel, gateList, labelCross, shared } from "./data";
import { hintWords, labelPicker } from "./findings";
import { labelsTable, type LRow } from "./labelstable";
import { openOf } from "./images";
import { labelText, mergeLabels, pageInfo, shortSource, square, sumTally, type WideLabel } from "./listing";
import { failed, listCursor, loading, primary, shown } from "./lists";
import { queueFor } from "./queuelist";
import { formatRoute, withFilters, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { filterRows } from "./table";
import { dataTable } from "./tableview";
import { couldMove, hint, imageName, status, type State as Status } from "./ui";

const day = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

export function gatesView(host: HTMLElement, r0: Route & { level: "gates" }, nav: Nav): View {
  let r = r0;
  const alive = shown(r);
  // a filter change before the data is in draws the screen again
  const out: View = { update: () => false };
  const load = () => Promise.all([gateList(), shared(), everyLabel()]).then(([list, sh, byGate]) => {
    if (!alive()) return;
    const labels = mergeLabels(byGate);
    const body = el("div", { class: "screen" });
    const work = r.tab === "gates" ? workBanner(list) : null;
    renderShell(host, r, {
      title: "Gates",
      above: work?.el,
      // the banner carries the screen's primary action (UI-RULES 7); the other tabs enter the queue here
      actions: work ? undefined : primary("Label what's left", sh.findings.length ? formatRoute(queueFor(r)) : null),
      tabCounts: { gates: list.gates.length, unlabeled: sh.findings.length, labels: labels.length },
      meta: [...new Set(labels.map((l) => shortSource(l.source)))].join(" + "),
      body,
    });
    const tab = r.tab === "unlabeled" ? unlabeledTab(sh, r, nav, load) : r.tab === "labels" ? labelsTab(labels, r, nav) : gatesTab(list.gates, work);
    fill(body, tab.el);
    out.key = (e) => tab.key(e);
    out.update = (n) => { r = n as typeof r; return tab.update?.(n) ?? false; };
  }).catch((e) => alive() && renderShell(host, r, { title: "Gates", body: failed(e) }));
  renderShell(host, r, { title: "Gates", body: loading() });
  load();
  return out;
}

interface Tab { el: HTMLElement | HTMLElement[]; key: (e: KeyboardEvent) => boolean; update?: (r: Route) => boolean }

// gatesTab is one row per gate: status, name and setups, a square per image, how much is unlabeled
function gatesTab(gates: GateListItem[], work: Work | null): Tab {
  const list = el("div", { class: "lrows gatelist", "data-testid": "gate-rows" }, gates.map((g) => {
    const changes = g.changes ?? [], sum = sumTally(changes), state = (g.error ? "undecided" : g.gateOutcome ?? "undecided") as Status;
    const withOpen = changes.filter((t) => openOf(t)).length;
    return el("a", { class: "lrow", href: formatRoute({ level: "gate", gate: g.id, tab: "checks", filters: {} }), "data-testid": "gate-row", "data-gate": g.id, "data-state": state },
      status(state),
      el("div", { class: "lname" },
        el("div", { class: "name" }, g.id),
        el("div", { class: "desc", title: g.error || g.gateNote || g.gate }, g.error || [g.compared, g.created && `scanned ${day(g.created)}`].filter(Boolean).join(" · "))),
      el("div", { class: "lstrip" },
        el("div", { class: "squares", "aria-hidden": "true" }, g.subjects.map((s, i) => el("i", { class: `sq ${square(changes[i])}`, title: `${s.name}: ${openOf(changes[i])} open of ${changes[i]?.total ?? 0} changed` }))),
        el("small", {}, g.subjects.length === 1 ? `1 image · ${g.subjects[0].name}` : `${plural(g.subjects.length, "image")} · ${withOpen} with open changes`)),
      el("div", { class: "lnum", "data-testid": "gate-unlabeled" }, `${openOf(sum).toLocaleString()} open`, el("small", {}, `of ${sum.total.toLocaleString()} changed`)),
      work?.cell(g.id),
      el("span", { class: "chev", "aria-hidden": "true" }, "›"));
  }));
  return { el: list, key: listCursor(list) };
}

const crossText = (f: CrossFinding) => `${f.vulnerability} ${f.package.ref} ${f.image} ${f.in.map((a) => a.gate).join(" ")}`;

// unlabeledTab is every open finding across gates, the ones whose label decides the most gates first
function unlabeledTab(sh: SharedState, r0: Route, nav: Nav, reload: () => void): Tab {
  let r = r0;
  const byKey = new Map(sh.findings.map((f) => [f.key, f]));
  const table = dataTable<CrossFinding>({
    testid: "unlabeled-table", id: (f) => f.key, rows: [],
    open: (f) => f.in[0] && nav({ level: "finding", gate: f.in[0].gate, check: null, row: f.in[0].row, filters: {} }),
    columns: [
      { key: "vuln", label: "Vulnerability", cell: (f) => el("span", { class: "strong" }, f.vulnerability), sort: (f) => f.vulnerability, title: (f) => f.vulnerability, truncate: true },
      { key: "package", label: "Package", cell: (f) => { const p = pkgOf(f.package.ref); return el("span", { class: "mono" }, p.name, " ", el("small", {}, p.version)); }, sort: (f) => pkgOf(f.package.ref).name, title: (f) => f.package.ref, truncate: true },
      { key: "image", label: "Image", cell: (f) => imageName(f.image), sort: (f) => f.image, title: (f) => f.image, truncate: true },
      { key: "gates", label: "Gates", cell: (f) => el("span", { class: "gates" }, f.in.map((a) => el("span", { class: "gchip", title: `${a.gate}: ${a.dir}` }, a.dir === "added" ? "+ " : a.dir === "dropped" ? "− " : "", a.gate))), sort: (f) => f.in.length, title: (f) => f.in.map((a) => a.gate).join(", "), truncate: true },
      { key: "hint", label: "Agent hint", cell: (f) => (f.hint?.status === "pending" ? hint(hintWords({ verdict: f.hint.verdict, confidence: f.hint.confidence, kind: "proposal" })) : f.cause ? hint("package hint") : el("span", { class: "muted" }, "–")), sort: (f) => f.hint?.verdict ?? (f.cause ? "~" : "") },
      { key: "effect", label: "Effect", cell: (f) => (f.flips ? [couldMove(), el("small", {}, ` in ${plural(f.flips, "gate")}`)] : el("span", { class: "muted" }, `bears on ${plural(f.bears, "gate")}`)), sort: (f) => f.flips * 100 + f.bears, num: false },
    ],
    select: { bulk: (ids, clear) => {
      const fs = ids.map((k) => byKey.get(k)).filter((f): f is CrossFinding => !!f);
      const hinted = fs.filter((f) => f.hint?.status === "pending" || f.cause).length;
      return [
        el("button", { type: "button", class: "btn", "data-variant": "outline", "data-size": "sm", "data-testid": "bulk-accept", disabled: !hinted,
          onclick: async () => { if (await acceptCross(fs)) clear(); reload(); } }, `Accept hints (${hinted})`),
        labelPicker(sh.vocabulary, async (v, j) => { if (await labelCross(fs, v, j)) clear(); reload(); }),
      ];
    } },
    foot: (shown) => plural(shown.length, "open finding"),
    empty: "Nothing open bears on a gate.",
  });
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image, gate…", "aria-label": "Filter findings", value: r.filters.q ?? "",
    oninput: () => nav(withFilters(r, { q: search.value }), true) });
  const update = (n: Route) => {
    r = n;
    table.update(filterRows(sh.findings, r.filters.q ?? "", crossText));
    return true;
  };
  update(r);
  return { el: [el("div", { class: "filters" }, el("p", { class: "help" }, "Labels are about a match, not a gate: one label counts in every gate that reports it."), search), table.el], key: table.key, update };
}

// labelsTab is every label in the workspace, each once however many gates count it
function labelsTab(all: WideLabel[], r0: Route, nav: Nav): Tab {
  const t = labelsTable({ route: r0, nav, wide: true,
    open: (l: LRow) => l.row && l.gate && nav({ level: "finding", gate: l.gate, check: null, row: l.row, filters: {} }) });
  const update = (r: Route) => {
    const q = filterRows(all, r.filters.q ?? "", labelText);
    const counts: Record<string, number> = { tp: 0, fp: 0, unclear: 0 };
    for (const l of q) counts[l.verdict] = (counts[l.verdict] ?? 0) + 1;
    const rows = q.filter((l) => !r.filters.verdict || l.verdict === r.filters.verdict), p = pageInfo(rows.length, r.filters.page);
    t.update(r, rows.slice(p.offset, p.offset + 50), rows.length, counts, false);
    return true;
  };
  update(r0);
  return { el: t.el, key: t.table.key, update };
}
