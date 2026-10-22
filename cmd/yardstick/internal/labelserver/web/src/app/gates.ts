// gates.ts is level 0, /ui/gates/: every gate in the workspace, one per row, with tabs for the open
// findings across gates (today's every-gate queue, as a table) and every label in the workspace.
import type { CrossFinding, GateList, GateListItem, SharedState, State } from "../gen/wire";
import * as api from "../shared/api";
import { doing, inFlight } from "../shared/agent";
import { el, fill, toast } from "../shared/dom";
import { outcome as outcomeOf, pkgOf } from "../shared/rows";
import { columnHelp, plural, sideWords } from "../shared/words";
import { workBanner, type Work } from "./banner";
import { acceptCross, everyLabel, freshShared, gateList, gateState, labelCross, shared } from "./data";
import { hintWords, labelPicker } from "./findings";
import { labelsTable, type LRow } from "./labelstable";
import { openOf } from "./images";
import { labelText, mergeLabels, pageInfo, shortSource, square, sumTally, type WideLabel } from "./listing";
import { failed, keptPrimary, listCursor, loading } from "./lists";
import { queueFor } from "./queuelist";
import { formatRoute, withFilters, type Route } from "./route";
import { bulkResearch, cellFor, follow, researchOf, started, type Research } from "./researchtable";
import { renderShell, type Nav, type View } from "./shell";
import { filterRows } from "./table";
import { dataTable } from "./tableview";
import { couldMove, hint, imageName, outcome, status } from "./ui";

const day = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

export function gatesView(host: HTMLElement, r0: Route & { level: "gates" }, nav: Nav, signal: AbortSignal): View {
  let r = r0;
  // a filter change before the data is in draws the screen again
  const out: View = { update: () => false };
  // the Unlabeled tab prices research by a gate's state: one job costs the same in every gate
  const firstState = () => gateList().then((l) => { const g = l.gates.find((x) => !x.error); return g ? gateState(g.id) : undefined; });
  let list: GateList, sh: SharedState, labels: WideLabel[], st: State | undefined;
  const read = () => Promise.all([gateList(), shared(), everyLabel(), r.tab === "unlabeled" ? firstState() : undefined]).then(([l, s, byGate, t]) => {
    list = l; sh = s; labels = mergeLabels(byGate); st = t;
  });

  // the tab and the banner are built with the first data and kept: a refresh hands them the new data
  const body = el("div", { class: "screen" }), left = keptPrimary("Label what's left");
  let tab: Tab, work: Work | null = null;
  const paint = () => renderShell(host, r, {
    title: "Gates",
    above: work?.el,
    // the banner carries the screen's primary action (UI-RULES 7); the other tabs enter the queue here
    actions: work ? undefined : left(sh.findings.length ? formatRoute(queueFor(r)) : null),
    tabCounts: { gates: list.gates.length, unlabeled: sh.findings.length, labels: labels.length },
    meta: [...new Set(labels.map((l) => shortSource(l.source)))].join(" + "),
    body,
  });

  read().then(() => {
    if (signal.aborted) return;
    work = r.tab === "gates" ? workBanner(list, signal) : null;
    tab = r.tab === "unlabeled" ? unlabeledTab(() => sh, async () => { sh = await freshShared(); }, st, r, nav, signal)
      : r.tab === "labels" ? labelsTab(() => labels, r, nav) : gatesTab(() => list.gates, work);
    fill(body, tab.el);
    paint();
    out.key = (e) => tab.key(e);
    out.update = (n) => { r = n as typeof r; return tab.update?.(n) ?? false; };
    out.refresh = async () => {
      await read();
      if (signal.aborted) return;
      work?.refresh(list);
      tab.refresh();
      paint();
    };
  }).catch((e) => !signal.aborted && renderShell(host, r, { title: "Gates", body: failed(e) }));
  renderShell(host, r, { title: "Gates", body: loading() });
  return out;
}

// refresh draws the tab again from the view's data, read again after a write
interface Tab { el: HTMLElement | HTMLElement[]; key: (e: KeyboardEvent) => boolean; update?: (r: Route) => boolean; refresh: () => void }

// gatesTab is one row per gate: status, name and setups, a square per image, how much is unlabeled
function gatesTab(gates: () => GateListItem[], work: Work | null): Tab {
  const list = el("div", { class: "lrows gatelist", "data-testid": "gate-rows" });
  const draw = () => fill(list, gates().map((g) => {
    const changes = g.changes ?? [], sum = sumTally(changes), state = g.error ? "undecided" : g.gateOutcome ?? "undecided";
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
  draw();
  return { el: list, key: listCursor(list), refresh: draw };
}

const crossText = (f: CrossFinding) => `${f.vulnerability} ${f.package.ref} ${f.image} ${f.in.map((a) => a.gate).join(" ")}`;

// gatesCell is the gates an open finding is in. Every row here is open, so its outcome is a question
// (new FP? or new FN?): asked once when every gate sees the same side, else in each gate's chip.
function gatesCell(f: CrossFinding) {
  const agree = new Set(f.in.map((a) => a.dir)).size === 1;
  return el("span", { class: "gates" }, agree && f.in[0] && outcome(f.in[0].dir, undefined),
    f.in.map((a) => {
      const o = !agree && outcomeOf(a.dir, undefined);
      return el("span", { class: "gchip", title: `${a.gate}: ${sideWords[a.dir]}` }, a.gate, o && el("span", { class: "o", "data-testid": "outcome", "data-outcome": o.kind }, ` ${o.text}`));
    }));
}

// rowsOf are a finding's rows, one per gate's appearance, each once
const rowsOf = (fs: CrossFinding[]) => [...new Set(fs.flatMap((f) => f.in.map((a) => a.row)))];
const crossHint = (f: CrossFinding) => (f.hint?.status === "pending" ? hint(hintWords({ verdict: f.hint.verdict, confidence: f.hint.confidence, kind: "proposal" })) : f.cause ? hint("package hint") : null);
const crossDoing = (f: CrossFinding) => doing(f.research, { open: true, researched: f.research?.status === "done" });

// unlabeledTab is every open finding across gates, the ones whose label decides the most gates
// first. Research here runs each finding once, under the gate the research page would pick.
// sh is the view's data as last read, and fresh reads it again for research in flight
function unlabeledTab(sh: () => SharedState, fresh: () => Promise<void>, st: State | undefined, r0: Route, nav: Nav, signal: AbortSignal): Tab {
  let r = r0;
  let byKey = new Map<string, CrossFinding>();
  const research: Research = researchOf(st);
  const redraw = async () => {
    await fresh();
    update(r);
  };
  async function start(fs: CrossFinding[]) {
    try {
      const res = await api.startResearch({ rows: rowsOf(fs) });
      started(res.jobs?.length ?? 0, res.skipped.active);
    } catch (e) {
      toast((e as Error).message, true);
      return false;
    }
    await redraw().catch(() => undefined);
    return true;
  }
  const table = dataTable<CrossFinding>({
    testid: "unlabeled-table", id: (f) => f.key, rows: [],
    open: (f) => f.in[0] && nav({ level: "finding", gate: f.in[0].gate, check: null, row: f.in[0].row, filters: {} }),
    columns: [
      { key: "vuln", label: "Vulnerability", cell: (f) => el("span", { class: "strong" }, f.vulnerability), sort: (f) => f.vulnerability, title: (f) => f.vulnerability, truncate: true },
      { key: "package", label: "Package", cell: (f) => { const p = pkgOf(f.package.ref); return el("span", { class: "mono" }, p.name, " ", el("small", {}, p.version)); }, sort: (f) => pkgOf(f.package.ref).name, title: (f) => f.package.ref, truncate: true },
      { key: "image", label: "Image", cell: (f) => imageName(f.image), sort: (f) => f.image, title: (f) => f.image, truncate: true },
      { key: "gates", label: "Gates", cell: gatesCell, sort: (f) => f.in.length, help: columnHelp.gates, title: (f) => f.in.map((a) => `${a.gate}: ${sideWords[a.dir]}`).join(", "), truncate: true },
      { key: "hint", label: "Agent hint", cell: (f) => cellFor({ hint: crossHint(f), research: f.research, open: true, researched: f.research?.status === "done" }, research, () => void start([f])), sort: (f) => f.hint?.verdict ?? (f.cause ? "~" : ""), help: columnHelp.crossHint },
      { key: "effect", label: "Effect", cell: (f) => (f.flips ? [couldMove(), el("small", {}, ` in ${plural(f.flips, "gate")}`)] : el("span", { class: "muted" }, `bears on ${plural(f.bears, "gate")}`)), sort: (f) => f.flips * 100 + f.bears, num: false, help: columnHelp.crossEffect },
    ],
    select: { bulk: (ids, clear) => {
      const fs = ids.map((k) => byKey.get(k)).filter((f): f is CrossFinding => !!f);
      const hinted = fs.filter((f) => f.hint?.status === "pending" || f.cause).length;
      // a finding's job covers its siblings: the same vulnerability and source package in its image
      const rs = bulkResearch(fs.map((f) => ({ id: f.key, open: true, hinted: !!crossHint(f), doing: crossDoing(f).kind, job: `${f.image}|${f.sourcePackage}|${f.vulnerability}` })), research,
        { start: (keys) => start(keys.map((k) => byKey.get(k)!)), clear, page: (keys) => nav({ level: "research", rows: rowsOf(keys.map((k) => byKey.get(k)!)), filters: {} }) });
      return [
        rs.button,
        el("button", { type: "button", class: `btn${!rs.leads && hinted ? " go" : ""}`, "data-variant": "outline", "data-size": "sm", "data-testid": "bulk-accept", disabled: !hinted,
          onclick: async () => { if (await acceptCross(fs)) clear(); } }, `Accept hints (${hinted})`),
        labelPicker(sh().vocabulary, async (v, j) => { if (await labelCross(fs, v, j)) clear(); }),
        rs.why,
      ];
    } },
    foot: (shown) => plural(shown.length, "open match", "open matches"),
    empty: "Nothing open bears on a gate.",
  });
  const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image, gate…", "aria-label": "Filter matches", value: r.filters.q ?? "",
    oninput: () => nav(withFilters(r, { q: search.value }), true) });
  function update(n: Route) {
    r = n;
    byKey = new Map(sh().findings.map((f) => [f.key, f]));
    table.update(filterRows(sh().findings, r.filters.q ?? "", crossText));
    return true;
  }
  update(r);
  follow(signal, () => sh().findings.some((f) => inFlight(f.research)), redraw);
  return { el: [el("div", { class: "filters" }, el("p", { class: "help" }, "Labels are about a match, not a gate: one label counts in every gate that reports it."), search), table.el], key: table.key, update, refresh: () => update(r) };
}

// labelsTab is every label in the workspace, each once however many gates count it
function labelsTab(all: () => WideLabel[], r0: Route, nav: Nav): Tab {
  let r = r0;
  const t = labelsTable({ route: r0, nav, wide: true,
    open: (l: LRow) => l.row && l.gate && nav({ level: "finding", gate: l.gate, check: null, row: l.row, filters: {} }) });
  const update = (n: Route) => {
    r = n;
    const q = filterRows(all(), r.filters.q ?? "", labelText);
    const counts: Record<string, number> = { tp: 0, fp: 0, unclear: 0 };
    for (const l of q) counts[l.verdict] = (counts[l.verdict] ?? 0) + 1;
    const rows = q.filter((l) => !r.filters.verdict || l.verdict === r.filters.verdict), p = pageInfo(rows.length, r.filters.page);
    t.update(r, rows.slice(p.offset, p.offset + 50), rows.length, counts, false);
    return true;
  };
  update(r0);
  return { el: t.el, key: t.table.key, update, refresh: () => update(r) };
}
