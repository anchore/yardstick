// research.ts is the research page, /ui/research?scope=: the open matches no agent has looked at
// yet, as the findings lists' table (tableview.ts), grouped by what labeling them can do to a gate,
// beside a sticky panel that prices the checked matches and starts them as one batch. Checking a
// match checks every match in its job, and checks survive a filter change here, unlike any other
// table. Labeling by hand never waits on it: "Label what's left" is here too. check= narrows it to
// the rows bearing on one check, and rows= to a table selection too big to start from the table.
// It also has the scoped Research button the other screens offer.
import type { Basis } from "../gen/research";
import type { GateList, ResearchQueueResponse } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill, toast, type Child } from "../shared/dom";
import { columnHelp as help, plural } from "../shared/words";
import { kick } from "./activity";
import { forget, gateList } from "./data";
import { effectCell } from "./findings";
import { jobsToggle } from "./jobs";
import { effectRank } from "./listing";
import { failed, loading, shown } from "./lists";
import { queueFor } from "./queuelist";
import { formatRoute, withFilters, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { basisWords, estimate, estimateWords, jobsIn, money, modelWords, rowsOf, rowText, type RRow } from "./researchwords";
import { filterRows, groupRows } from "./table";
import { dataTable, type Column, type Table } from "./tableview";
import { imageName, kbd } from "./ui";

type ResearchRoute = Extract<Route, { level: "research" }>;

const groups: Record<string, { title: string; sub: string }> = {
  change: { title: "Can change a gate", sub: "labeling one can move a check" },
  none: { title: "Changes no outcome", sub: "labels still help the corpus" },
};
const chips = [["all"], ["change", "none"], ["checked"]];
const chipWords: Record<string, string> = { all: "All", change: "Can change a gate", none: "Changes no outcome", checked: "Checked" };

// models the page offers; the configured one is added when it is none of these
const models = ["sonnet", "opus", "haiku"];

export function researchView(host: HTMLElement, r: ResearchRoute, nav: Nav): View {
  const alive = shown(r), scope = r.scope ?? "all", rows = r.rows, check = rows ? undefined : r.check;
  const left = el("a", { class: "btn", "data-variant": "outline", href: formatRoute(queueFor(r)), "data-testid": "label-left" }, "Label what's left ", kbd("n"));
  const toggle = jobsToggle("matches");
  // the plan has both groups selected, so each match sits in one job and the change group claims first
  const plan = (model?: string) => api.researchQueue({ scope, check, rows, groups: rows ? undefined : ["change", "none"], model, dryRun: true });
  let update: ((next: ResearchRoute) => void) | null = null;

  Promise.all([gateList(), plan()]).then(([list, first]) => {
    if (alive()) update = draw(list, first);
  }).catch((e) => alive() && renderShell(host, r, { title: "Research open matches", actions: [toggle, left], body: failed(e) }));
  renderShell(host, r, { title: "Research open matches", actions: [toggle, left], body: loading() });

  function draw(list: GateList, first: ResearchQueueResponse) {
    let route = r, basis: Basis = first.estimate.basis, seq = 0, scoped: RRow[] = [], showing: RRow[] = [], checked = new Set<string>();
    const all = rowsOf(first), byId = new Map(all.map((x) => [x.id, x])), byJob = new Map(groupRows(all, (x) => x.job).map((g) => [g.key, g.rows]));
    const chipOf = () => (["change", "none", "checked"].includes(route.filters.chip ?? "") ? route.filters.chip! : "all");
    const inChip = (x: RRow, c: string) => c === "all" || (c === "checked" ? checked.has(x.id) : x.group === c);
    const gates = list.gates.filter((g) => !g.error);
    const chip = (s: string, text: string) => el("a", { class: "chip", href: formatRoute({ level: "research", scope: s, filters: {} }), "aria-pressed": String(scope === s),
      "data-testid": "research-gate-chip", "data-gate": s === "all" ? "" : s.slice(5) }, text);
    // a check narrows the gate's rows to it, and a selection to itself; each chip says so and clears it
    const narrow = (testid: string, label: Child, clear: ResearchRoute) => el("span", { class: "scope", "data-testid": testid }, label,
      el("a", { class: "x", href: formatRoute(clear), "aria-label": "Clear" }, "×"));
    const scopeChips = el("div", { class: "chips" }, chip("all", "All gates"), gates.map((g) => chip(`gate:${g.id}`, g.id)),
      check && narrow("research-check-chip", ["check: ", el("b", {}, check)], { level: "research", scope, filters: {} }),
      rows && narrow("research-rows-chip", `${plural(rows.length, "selected match", "selected matches")}`, { level: "research", scope, filters: {} }));
    const s = first.skipped;
    const skipped = el("div", { class: "skipped", "data-testid": "research-skipped" },
      `Skipped: ${plural(s.researched, "match", "matches")} already researched, ${s.hinted} with an agent hint, ${s.active} queued or running. A match with a hint or a job in flight never gets a second job from here.`);
    const shell = (body: HTMLElement) => renderShell(host, r, {
      title: "Research open matches",
      sub: all.length ? "Open matches with no hint, no finished research and no job in flight; matches that share a job are checked together." : undefined,
      actions: [scopeChips, toggle, left], body: el("div", { class: "screen" }, body),
    });
    if (!all.length) {
      shell(el("div", { class: "rlist" }, el("div", { class: "placeholder", "data-testid": "research-empty" }, "Nothing here to research: every open match in scope has an agent hint, finished research or a job in flight."), skipped));
      return null;
    }

    const each = () => (basis.measured ? `~${money(basis.mean)}` : "–");
    const columns: Column<RRow>[] = [
      { key: "vuln", label: "Vulnerability", cell: (x) => el("span", { class: "strong" }, x.vuln), sort: (x) => x.vuln, title: (x) => x.vuln, truncate: true },
      { key: "package", label: "Package", cell: (x) => el("span", { class: "mono" }, x.pkg, " ", el("small", {}, x.version)), sort: (x) => x.pkg, title: (x) => `${x.pkg} ${x.version}`, truncate: true },
      { key: "image", label: "Image", cell: (x) => imageName(x.image), sort: (x) => x.image, title: (x) => x.image, truncate: true },
      { key: "effect", label: "Effect", cell: effectCell, sort: (x) => effectRank(x.effect), help: help.researchEffect },
      { key: "job", label: "Job", help: help.job, cell: (x) => el("span", { class: "muted", "data-testid": "research-job", "data-gate": x.gate, "data-group": x.group, title: `researched in ${x.gate}` },
        x.siblings ? `shares with ${x.siblings}` : "own job") },
      { key: "price", label: "Price", num: true, help: help.price, cell: (x) => el("span", { class: "cost", "data-testid": "research-row-price" }, x.job === x.id ? each() : "") },
    ];
    // groupHeader is a group's row: a box for every match of it shown, then its matches, jobs and price
    function groupHeader(g: string, rs: RRow[]) {
      const on = new Set(table.selected()), n = rs.filter((x) => on.has(x.id)).length, jobs = jobsIn(rs);
      const box: HTMLInputElement = el("input", { type: "checkbox", checked: n === rs.length, "aria-label": `Check every match shown in ${groups[g].title}`, "data-testid": "research-group-toggle",
        onchange: () => table.check(rs.map((x) => x.id), box.checked) });
      box.indeterminate = n > 0 && n < rs.length;
      return el("span", { class: "rgh", "data-testid": "research-group", "data-group": g }, box, el("span", { class: "t" }, groups[g].title), el("span", { class: "s" }, groups[g].sub),
        el("span", { class: "n" }, `${plural(rs.length, "match", "matches")} · ${plural(jobs, "job")}`, basis.measured && [" · ", el("span", { class: "cost" }, `~${money(jobs * basis.mean)}`)]));
    }

    const search: HTMLInputElement = el("input", { class: "input search", type: "search", placeholder: "Filter by CVE, package, image…", "aria-label": "Filter matches", value: route.filters.q ?? "",
      oninput: () => nav(withFilters(route, { q: search.value }), true) });
    const images = [...new Map(all.map((x) => [x.slug, x.image])).entries()];
    const image: HTMLSelectElement = el("select", { class: "select", "aria-label": "Image", "data-testid": "research-image", onchange: () => nav(withFilters(route, { image: image.value || undefined })) },
      el("option", { value: "" }, "All images"), images.map(([slug, name]) => el("option", { value: slug }, name)));
    const chipRow = el("div", { class: "chips", role: "group", "aria-label": "Filter matches" });

    const cost = el("b", { "data-testid": "research-cost" }), range = el("span", { "data-testid": "research-range" });
    const band = el("div", { class: "band" }), mean = el("div", { class: "mean" });
    const kv = (label: string, testid: string) => { const v = el("span", { "data-testid": testid }); return { v, els: [el("span", {}, label), v] }; };
    const rowsKV = kv("Matches checked", "research-rows"), jobsKV = kv("Jobs", "research-jobs"), tokKV = kv("Tokens", "research-tokens"), timeKV = kv(`Time, ${first.concurrency} at a time`, "research-time");
    const configured = basis.model;
    const model: HTMLSelectElement = el("select", { id: "research-model", "data-testid": "research-model", onchange: () => void price() },
      [...new Set([configured, ...models])].filter(Boolean).map((m) => el("option", { value: m, selected: m === configured }, modelWords(m))));
    const limit: HTMLInputElement = el("input", { id: "research-limit", type: "number", min: "1", placeholder: "all jobs", "data-testid": "research-limit", oninput: () => show() });
    const warn = el("p", { class: "warn", hidden: true, "data-testid": "research-unmeasured" },
      "No finished jobs on this model yet. The estimate shows after the first 3 finish; until then only the job count is known.");
    const start: HTMLButtonElement = el("button", { type: "button", class: "btn", "data-testid": "research-start", onclick: () => void doStart() });
    const foot = el("p", { class: "foot basis", "data-testid": "research-basis" });
    const panel = el("aside", { class: "impact est", "data-testid": "research-estimate", "aria-live": "polite" },
      el("h2", {}, "If you start this"),
      el("div", { class: "money" }, cost, range),
      el("div", { class: "range", "aria-hidden": "true" }, el("div", { class: "track" }), band, mean),
      el("div", { class: "kv" }, rowsKV.els, jobsKV.els, tokKV.els, timeKV.els),
      el("div", { class: "ctl" },
        el("div", {}, el("label", { for: "research-model" }, "Model"), model),
        el("div", {}, el("label", { for: "research-limit" }, "Stop after"), limit)),
      warn, start, foot);

    const table: Table<RRow> = dataTable<RRow>({
      columns, rows: [], id: (x) => x.id, sort: null, testid: "research-table",
      group: { key: (x) => x.group, header: (g, rs) => groupHeader(g, rs) },
      select: {
        keep: true,
        link: (id) => byJob.get(byId.get(id)?.job ?? "")?.map((x) => x.id) ?? [id],
        bulk: (ids) => {
          const on = new Set(ids), hidden = ids.length - showing.filter((x) => on.has(x.id)).length, jobs = jobsIn(all.filter((x) => on.has(x.id)));
          return el("span", { "data-testid": "research-bulk" }, plural(jobs, "job"), basis.measured && ` · ~${money(jobs * basis.mean)}`,
            hidden > 0 && el("span", { "data-testid": "research-hidden" }, ` · ${hidden} hidden by the filter`));
        },
        changed: (ids) => { checked = new Set(ids); drawChips(); show(); },
      },
      empty: "No open match matches the filter.",
      foot: (xs) => plural(xs.length, "match", "matches"),
    });

    shell(el("div", { class: "review" }, el("div", { class: "rlist" }, el("div", { class: "filters" }, chipRow, image, search), table.el, skipped), panel));

    function drawChips() {
      const c = chipOf();
      fill(chipRow, chips.map((grp) => el("div", { class: "chip-group" }, grp.map((id) => el("button", { type: "button", class: "chip", "aria-pressed": String(id === c), "data-chip": id,
        onclick: () => nav(withFilters(route, { chip: id === "all" ? undefined : id })) }, chipWords[id], " ", el("b", {}, String(scoped.filter((x) => inChip(x, id)).length)))))));
    }
    // refresh filters by the image and the search (what the chips count), then the chip
    function refresh() {
      const img = route.filters.image;
      scoped = filterRows(all.filter((x) => !img || x.slug === img), route.filters.q ?? "", rowText);
      if (document.activeElement !== search && search.value !== (route.filters.q ?? "")) search.value = route.filters.q ?? "";
      image.value = img ?? "";
      left.setAttribute("href", formatRoute(queueFor(route)));
      showing = scoped.filter((x) => inChip(x, chipOf()));
      table.update(showing, img ? ["image"] : []);
    }

    // show prices the checked matches: their jobs (up to Stop after) on the model's basis
    function show() {
      const picked = all.filter((x) => checked.has(x.id)), cap = Number(limit.value);
      const jobs = jobsIn(picked), e = estimate(cap > 0 ? Math.min(cap, jobs) : jobs, basis, first.concurrency, picked.length), w = estimateWords(e);
      fill(cost, w.cost); fill(range, w.range);
      fill(rowsKV.v, String(picked.length)); fill(jobsKV.v, String(e.jobs)); fill(tokKV.v, w.tokens); fill(timeKV.v, w.time);
      // the band spans low to high on a scale of every job at the dearest, so checking more widens it
      const top = byJob.size * basis.max;
      const pct = (x: number) => `${top ? (x / top) * 100 : 0}%`;
      band.hidden = mean.hidden = !basis.measured || !e.jobs;
      band.style.left = pct(e.low); band.style.width = pct(e.high - e.low); mean.style.left = pct(e.mean);
      warn.hidden = basis.measured;
      fill(start, e.jobs ? `Start ${plural(e.jobs, "research job")}` : "Check matches to research");
      start.disabled = !e.jobs;
      start.dataset.jobs = String(e.jobs);
      fill(foot, basisWords(basis));
    }

    // price asks the server for the model's per-job numbers, then redraws the prices
    async function price() {
      const mine = ++seq;
      try {
        const p = await plan(model.value);
        if (mine !== seq || !alive()) return;
        basis = p.estimate.basis;
        refresh();
      } catch (e) {
        if (mine === seq) toast(`Couldn't price that: ${(e as Error).message}`, true);
      }
    }

    async function doStart() {
      const ids = table.selected(), cap = Number(limit.value);
      if (!ids.length) return;
      start.disabled = true;
      try {
        const res = await api.researchQueue({ scope, rows: ids, limit: cap > 0 ? cap : undefined, model: model.value });
        toast(res.jobs?.length ? `✦ ${plural(res.jobs.length, "research job")} started; the gates page shows their progress` : "nothing left to research");
        void kick();
      } catch (e) {
        toast((e as Error).message, true);
        start.disabled = false;
        return;
      }
      forget();
      nav({ level: "gates", tab: "gates", filters: {} });
    }

    // a table selection arrives checked whole; otherwise the groups asked for, change alone by default
    const want = rows ? null : new Set(r.groups ?? ["change"]);
    refresh();
    table.check(all.filter((x) => !want || want.has(x.group)).map((x) => x.id), true);
    return (next: ResearchRoute) => { route = next; refresh(); };
  }

  return { update: (next) => { if (!update || next.level !== "research") return false; update(next); return true; } };
}

// ---------- the scoped Research button ----------

export type ScopedWords = (rows: number, jobs: number, group: "change" | "none" | "all") => string;

export interface Scoped {
  el: HTMLAnchorElement;
  // set prices another scope (the image filter changed) and says it in words
  set(to: ResearchRoute, words: ScopedWords): void;
  // go opens the research page, as r does, when the button is showing
  go(): boolean;
}

// scopedResearch is the two-line Research a gate, an image filter, a check, hint review and the
// queue's stopping point offer: "Research" over what it covers, then its price, and r where r
// opens it. It prices the scope with the server's dry run and leads with the matches that can
// change an outcome, else the ones that change none (the research page then opens with that group
// checked); all takes both. Hidden while nothing in scope qualifies.
export function scopedResearch(o: { all?: boolean; key?: boolean; small?: boolean } = {}): Scoped {
  const a = el("a", { class: "btn btn2", "data-variant": "outline", "data-size": o.small ? "sm" : null, hidden: true, "data-testid": "scoped-research" });
  let seq = 0, at = "";
  return {
    el: a,
    go() { if (a.hidden) return false; a.click(); return true; },
    set(to, words) {
      const key = formatRoute(to);
      if (key === at) return;
      at = key;
      const mine = ++seq;
      a.hidden = true;
      api.researchQueue({ scope: to.scope ?? "all", check: to.check, dryRun: true }).then((p) => {
        if (mine !== seq) return;
        const change = p.groups.find((g) => g.group === "change"), none = p.groups.find((g) => g.group === "none");
        const which = o.all ? "all" : change?.jobs.length ? "change" : "none";
        const picked = which === "all" ? [change, none] : [which === "change" ? change : none];
        const jobs = picked.reduce((n, g) => n + (g?.jobs.length ?? 0), 0), rows = picked.reduce((n, g) => n + (g?.rows ?? 0), 0);
        if (!jobs) return;
        const e = estimate(jobs, p.estimate.basis, p.concurrency), text = words(rows, jobs, which);
        a.setAttribute("href", formatRoute({ ...to, ...(which !== "change" && { groups: which === "all" ? ["change", "none"] : ["none"] }) }));
        a.dataset.rows = String(rows);
        a.dataset.group = which;
        a.title = `Research ${text}`;
        fill(a, el("span", { class: "two" }, "Research", el("small", {}, text)), " ",
          el("span", { class: "costpill" }, e.basis.measured ? `~${money(e.mean)}` : plural(jobs, "job")), o.key && [" ", kbd("r")]);
        a.hidden = false;
      }).catch(() => undefined);
    },
  };
}
