// check.ts is level 2, /ui/gates/<gate>/checks/<check>: the check's summary, a rail counting this
// check's findings per image, and every finding it counts, labeled and unlabeled, in one table
// with chips, search, "Group by" and the bulk bar.
import type { CheckFindings, State } from "../gen/wire";
import { el } from "../shared/dom";
import { checkFindings, freshFindings, freshState, gateState } from "./data";
import { findingsList, grouping, type FindingsList, type Grouping } from "./findings";
import { checkCounts, checkMeter, countWords, railImages } from "./gate";

const sentenceCase = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
import { noCounts, type RailImage } from "./images";
import { checkRows, nextOpen, type FRow } from "./listing";
import { failed, keptPrimary, loading, shown } from "./lists";
import { railHints } from "./hints";
import { imageRail, type Rail } from "./rail";
import { queueFor, researchFor } from "./queuelist";
import { scopedResearch } from "./research";
import { researchOf } from "./researchtable";
import { formatRoute, withFilters, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { imageName, status, type State as Status } from "./ui";

type CheckRoute = Route & { level: "check" };

export function checkView(host: HTMLElement, r0: CheckRoute, nav: Nav): View {
  let r = r0;
  const { gate, check } = r, alive = shown(r), out: View = { update: () => false };
  let f: CheckFindings, st: State, rows: FRow[] = [], images: RailImage[] = [], shownRows: FRow[] = [];
  const imageOf = (slug: string | undefined) => images.find((i) => i.slug === slug) ?? null;
  const read = () => Promise.all([checkFindings(gate, check), gateState(gate)]).then(([nf, ns]) => {
    f = nf; st = ns; rows = checkRows(f, st);
    images = railImages(st).map((i) => ({ ...i, counts: f.images[i.slug] ?? noCounts }));
  });

  // the components are built with the first data and kept: a refresh hands them the new data
  // research of the rows that bear on this check, in its gate whatever the image filter
  const research = scopedResearch({ key: true }), labelNext = keptPrimary("Label next");
  let rail: Rail, list: FindingsList, body: HTMLElement;
  const next = () => nextOpen(shownRows) ?? nextOpen(rows);

  // paint draws the shell with the data as last read, and points the components at the route
  function paint(again = false) {
    const c = f.check, n = checkCounts(st, c, null), img = imageOf(r.filters.image);
    rail.select(img?.slug ?? null);
    shownRows = list.update(r, rows, img?.slug ?? null);
    const href = next() ? formatRoute(queueFor(r)) : null;
    research.set(researchFor(r), (k, _, g) => (g === "change" ? `${k} that could move it` : `${k} that ${k === 1 ? "changes" : "change"} no outcome`), again);
    renderShell(host, r, {
      title: check, status: status(c.state as Status, true),
      sub: f.note || `${c.description.charAt(0).toUpperCase()}${c.description.slice(1)}. ${sentenceCase(countWords(n))}.`,
      actions: [checkMeter(c), research.el, labelNext(href)],
      meta: st.scans.gate.split("/").pop(),
      rail,
      scope: img && { label: imageName(img.name, img.ref), clear: () => nav(withFilters(r, { image: undefined })) },
      body,
    });
  }

  read().then(() => {
    if (!alive()) return;
    rail = imageRail({ images, selected: imageOf(r.filters.image)?.slug ?? null, scope: "check", onSelect: (slug) => nav(withFilters(r, { image: slug ?? undefined })) });
    railHints(rail, gate);

    // "Images" hides the rail, or its dropdown when collapsed, and brings back whichever it was
    let was: [boolean, boolean] | null = null;
    const toggle = el("button", { type: "button", class: "btn", "data-variant": "outline", "data-size": "sm", "aria-pressed": "true", "data-testid": "images-toggle", title: "Show or hide the image list",
      onclick: () => {
        if (was) { [rail.rail.hidden, rail.picker.hidden] = was; was = null; } else { was = [!!rail.rail.hidden, !!rail.picker.hidden]; rail.rail.hidden = rail.picker.hidden = true; }
        toggle.setAttribute("aria-pressed", String(!was));
      } }, "Images");
    const group: HTMLSelectElement = el("select", { class: "select group-by", "aria-label": "Group by", "data-testid": "group-by",
      onchange: () => list.table.regroup(grouping(group.value as Grouping)) },
    (["none", "image", "package"] as Grouping[]).map((g) => el("option", { value: g }, `Group by: ${g}`)));

    const fresh = async () => {
      const [nf, ns] = await Promise.all([freshFindings(gate, check), freshState(gate)]);
      return (rows = checkRows(nf, ns));
    };
    list = findingsList({ gate, route: r, nav, vocab: st.vocabulary, extra: [toggle, group], testid: "check-table", research: researchOf(st), fresh,
      open: (x) => x.row && nav({ level: "finding", gate, check, row: x.row, filters: r.filters }) });
    body = el("div", { class: "screen" }, list.el);
    paint();
    out.update = (nr) => { r = nr as CheckRoute; paint(); return true; };
    out.refresh = async () => {
      await read();
      if (!alive()) return;
      rail.images(images);
      railHints(rail, gate);
      paint(true);
    };
    out.key = (e) => (e.key === "r" && research.go()) || list.table.key(e) || rail.key(e);
  }).catch((e) => alive() && renderShell(host, r, { title: check, body: failed(e) }));
  renderShell(host, r, { title: check, body: loading() });
  return out;
}
