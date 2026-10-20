// gate.ts is level 1, /ui/gates/<gate>/: the gate's verdict bar, the image rail, and its tabs:
// Checks (one row per check, with its meter), Findings (every changed match), Labels (every label
// the gate counts, paged) and Scan map (today's treemap).
import type { CheckResult, GateLabels, State } from "../gen/wire";
import { el, fill, toast } from "../shared/dom";
import { fmt, plural } from "../shared/words";
import { freshState, gateLabels, gateState } from "./data";
import { findingsList } from "./findings";
import { noCounts, type RailImage } from "./images";
import { labelsTable } from "./labelstable";
import { gateRows, nextOpen, pageSize, sumTally, type FRow } from "./listing";
import { failed, keptPrimary, listCursor, loading, shown } from "./lists";
import { railHints } from "./hints";
import { imageRail, type Rail } from "./rail";
import { queueFor, researchFor } from "./queuelist";
import { scopedResearch } from "./research";
import { researchOf } from "./researchtable";
import { formatRoute, withFilters, type Route } from "./route";
import { scanMap } from "./scanmap";
import { renderShell, type Nav, type View } from "./shell";
import { imageName, meter, status, verdictBar, type State as Status } from "./ui";

type GateRoute = Route & { level: "gate" };

const day = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
};

// railImages are a gate's images with their changed rows' counts, in gate order
export const railImages = (st: State): RailImage[] =>
  st.subjects.map((s, i) => ({ name: s.name, slug: s.slug, ref: st.scans.subjects[i]?.ref ?? s.name, counts: s.changes ?? noCounts }));

// gateHead is the title row and verdict bar the gate's tabs share
export function gateHead(st: State) {
  const res = st.gate?.result, outcome = (res?.outcome ?? "undecided") as Status;
  return {
    status: status(outcome, true),
    sub: st.gate?.note || [st.scans.compared, plural(st.subjects.length, "image"), st.scans.created && `scanned ${day(st.scans.created)}`].filter(Boolean).join(" · "),
    meta: st.scans.gate.split("/").pop(),
  };
}

export function gateView(host: HTMLElement, r0: GateRoute, nav: Nav): View {
  let r = r0;
  const gate = r.gate, alive = shown(r), out: View = { update: () => false };
  let st: State, all: GateLabels, rows: FRow[] = [], images: RailImage[] = [];
  const imageOf = (slug: string | undefined) => images.find((i) => i.slug === slug) ?? null;
  // the Labels tab's rail counts labels, the others changed matches
  const railed = () => (r.tab === "labels" ? images.map((i) => ({ ...i, counts: { ...noCounts, total: all.perImage[i.slug] ?? 0 } })) : images);
  const read = () => Promise.all([gateState(gate), gateLabels(gate, { limit: 0 })]).then(([s, a]) => {
    st = s; all = a; rows = gateRows(st); images = railImages(st);
  });

  // the components are built with the first data and kept: a refresh hands them the new data
  const body = el("div", { class: "screen" });
  // Research and Label next both follow the image filter (UI-RULES: research wherever labeling is offered)
  const research = scopedResearch({ key: true }), labelNext = keptPrimary("Label next");
  let rail: Rail, tab: Tab;

  // paint draws the shell with the data as last read, and points the components at the route
  function paint(again = false) {
    const img = imageOf(r.filters.image), head = gateHead(st);
    const href = nextOpen(rows.filter((x) => !r.filters.image || x.image.slug === r.filters.image)) ? formatRoute(queueFor(r)) : null;
    renderShell(host, r, {
      title: gate, status: head.status, sub: head.sub, meta: head.meta,
      actions: [research.el, labelNext(href)],
      above: verdictBar(sumTally(st.subjects.map((s) => s.changes))),
      rail,
      scope: img && { label: imageName(img.name, img.ref), clear: () => nav(withFilters(r, { image: undefined })) },
      tabCounts: { checks: st.gate?.result?.checks.length ?? 0, findings: rows.length, labels: all.total },
      body,
    });
    rail.select(img?.slug ?? null);
    tab.update(r, img?.slug ?? null);
    research.set(researchFor(r), (n, _, g) => (img ? `${n} on ${img.name}` : g === "change" ? `${n} that can change the gate` : `${n} that ${n === 1 ? "changes" : "change"} no outcome`), again);
  }

  read().then(() => {
    if (!alive()) return;
    rail = imageRail({ images: railed(), selected: imageOf(r.filters.image)?.slug ?? null, scope: r.tab === "labels" ? "labels" : "gate",
      onSelect: (slug) => nav(withFilters(r, { image: slug ?? undefined })) });
    if (r.tab !== "labels") railHints(rail, gate);
    tab = r.tab === "findings" ? findingsTab(gate, () => rows, async () => (rows = gateRows(await freshState(gate))), r, nav, st)
      : r.tab === "labels" ? labelsTab(gate, r, nav, (slug) => !!imageOf(slug))
        : r.tab === "map" ? mapTab(() => st, r, nav)
          : checksTab(() => st);
    fill(body, tab.el);
    paint();
    out.update = (nr) => { r = nr as GateRoute; paint(); return true; };
    out.refresh = async () => {
      await read();
      if (!alive()) return;
      rail.images(railed());
      if (r.tab !== "labels") railHints(rail, gate);
      paint(true);
    };
    out.key = (e) => (e.key === "r" && research.go()) || tab.key(e) || rail.key(e);
  }).catch((e) => alive() && renderShell(host, r, { title: gate, body: failed(e) }));
  renderShell(host, r, { title: gate, body: loading() });
  return out;
}

interface Tab { el: Node | Node[]; key: (e: KeyboardEvent) => boolean; update: (r: Route, image: string | null) => void }

// ---------- Checks ----------

const units: Record<string, string> = { f1: "worse", fn: "new", fp: "new", unjudged: "unlabeled" };

const sentence = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

// checkMeter is a check's value (the worst case for the candidate) against its limit, one caption:
// "0.500 worse · limit 0"
export function checkMeter(c: CheckResult) {
  const unit = units[c.counts ?? ""];
  return meter({ value: c.value.worst, limit: c.threshold, state: c.state as Status,
    caption: [el("b", {}, fmt(c.value.worst)), unit && ` ${unit}`, ` · limit ${fmt(c.threshold)}`] });
}

// countWords says what labeling does for a check: the labels behind its failing, else how many
// open matches alone move it, else whether any narrow it
export const countWords = (n: ReturnType<typeof checkCounts>) =>
  n.decides ? `${plural(n.decides, "label")} decide it` : n.could ? `${n.could} could move it alone` : n.bearing ? "each narrows it" : "nothing open moves it";

// checkCounts says how many open matches bear on a check and how many labels decide it, in an image
export function checkCounts(st: State, c: CheckResult, image: string | null) {
  const fails = new Set(c.failsOn ?? []);
  let decides = 0, bearing = 0, could = 0;
  for (const s of st.subjects) {
    if (image && s.slug !== image) continue;
    for (const x of s.rows) {
      if (fails.has(x.id)) decides++;
      const open = x.verdict === "unlabeled" || x.verdict === "unclear";
      if (!open || !x.gate) continue;
      if (x.gate.couldFlip?.includes(c.name)) { could++; bearing++; } else if (x.gate.bears?.includes(c.name)) bearing++;
    }
  }
  return { decides, bearing, could };
}

// st is the gate's state as last read
function checksTab(st: () => State): Tab {
  const list = el("div", { class: "lrows", "data-testid": "check-rows" });
  return {
    el: st().gate?.result?.checks.length ? list : el("div", { class: "placeholder" }, st().gate?.note || "This gate has no result to show."),
    key: listCursor(list),
    update(r, image) {
      const s = st();
      fill(list, (s.gate?.result?.checks ?? []).map((c) => {
        const n = checkCounts(s, c, image);
        return el("a", { class: "lrow check", href: formatRoute({ level: "check", gate: s.scans.id, check: c.name, filters: r.filters.image ? { image: r.filters.image } : {} }),
          "data-testid": "check-row", "data-check": c.name, "data-state": c.state },
        status(c.state as Status),
        el("div", { class: "lname" }, el("div", { class: "name" }, c.name), el("div", { class: "desc", title: sentence(c.description) }, c.summary || sentence(c.description))),
        checkMeter(c),
        el("div", { class: "lnum", "data-testid": "check-count" }, `${n.bearing.toLocaleString()} open`,
          el("small", {}, countWords(n))),
        el("span", { class: "chev", "aria-hidden": "true" }, "›"));
      }));
    },
  };
}

// ---------- Findings ----------

// rows are the gate's rows as the view last read them, and fresh reads them again
function findingsTab(gate: string, rows: () => FRow[], fresh: () => Promise<FRow[]>, r0: Route, nav: Nav, st: State): Tab {
  let r = r0;
  const list = findingsList({ gate, route: r, nav, vocab: st.vocabulary, research: researchOf(st), fresh,
    open: (x) => x.row && nav({ level: "finding", gate, check: null, row: x.row, filters: r.filters }) });
  return {
    el: list.el,
    key: list.table.key,
    update(nr, image) { r = nr; list.update(r, rows(), image); },
  };
}

// ---------- Labels ----------

function labelsTab(gate: string, r0: Route, nav: Nav, known: (slug: string | undefined) => boolean): Tab {
  let r = r0;
  const t = labelsTable({ route: r, nav, open: (l) => l.row && nav({ level: "finding", gate, check: null, row: l.row, filters: {} }) });
  return {
    el: t.el,
    key: t.table.key,
    update(nr, image) {
      r = nr;
      const f = r.filters, at = r;
      gateLabels(gate, { verdict: f.verdict === "unlabeled" ? undefined : f.verdict, image: known(image ?? undefined) ? image ?? undefined : undefined, q: f.q, offset: ((f.page ?? 1) - 1) * pageSize, limit: pageSize })
        .then((res: GateLabels) => { if (at === r) t.update(r, res.labels, res.total, res.counts, !!image); })
        .catch((e) => toast((e as Error).message, true));
    },
  };
}

// ---------- Scan map ----------

function mapTab(st: () => State, r0: Route, nav: Nav): Tab {
  let r = r0;
  const box = el("div", { class: "scanmap", "data-testid": "scan-map" });
  return {
    el: box,
    key: () => false,
    update(nr, image) {
      r = nr;
      // a block opens the Findings tab filtered to its source package
      fill(box, scanMap(st(), image, (pkg) => nav({ level: "gate", gate: st().scans.id, tab: "findings", filters: { ...(r.filters.image ? { image: r.filters.image } : {}), pkg } })));
    },
  };
}
