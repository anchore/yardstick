// check.ts is level 2, /ui/gates/<gate>/checks/<check>: the check's summary, a rail counting this
// check's findings per image, and every finding it counts, labeled and unlabeled, in one table
// with chips, search, "Group by" and the bulk bar.
import { el } from "../shared/dom";
import { checkFindings, gateState } from "./data";
import { findingsList, grouping, type Grouping } from "./findings";
import { checkCounts, checkMeter, countWords, railImages } from "./gate";

const sentenceCase = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
import { noCounts } from "./images";
import { checkRows, nextOpen, type FRow } from "./listing";
import { failed, loading, primary, shown } from "./lists";
import { imageRail } from "./rail";
import { formatRoute, withFilters, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { imageName, status, type State as Status } from "./ui";

type CheckRoute = Route & { level: "check" };

export function checkView(host: HTMLElement, r0: CheckRoute, nav: Nav): View {
  let r = r0;
  const { gate, check } = r, alive = shown(r), out: View = { update: () => false };
  const load = () => Promise.all([checkFindings(gate, check), gateState(gate)]).then(([f, st]) => {
    if (!alive()) return;
    const c = f.check, rows = checkRows(f);
    const images = railImages(st).map((i) => ({ ...i, counts: f.images[i.slug] ?? noCounts }));
    const imageOf = (slug: string | undefined) => images.find((i) => i.slug === slug) ?? null;
    const rail = imageRail({ images, selected: imageOf(r.filters.image)?.slug ?? null, scope: "check", onSelect: (slug) => nav(withFilters(r, { image: slug ?? undefined })) });

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

    let shownRows: FRow[] = [];
    const list = findingsList({ gate, route: r, nav, vocab: st.vocabulary, reload: load, extra: [toggle, group], testid: "check-table",
      open: (x) => x.row && nav({ level: "finding", gate, check, row: x.row, filters: r.filters }) });
    const next = () => nextOpen(shownRows) ?? nextOpen(rows);
    const nextRoute = (x: FRow): Route => ({ level: "finding", gate, check, row: x.row!, filters: r.filters });

    const n = checkCounts(st, c, null), first = next();
    const shell = renderShell(host, r, {
      title: check, status: status(c.state as Status, true),
      sub: f.note || `${c.description.charAt(0).toUpperCase()}${c.description.slice(1)}. ${sentenceCase(countWords(n))}.`,
      actions: [checkMeter(c), primary("Label next", first ? formatRoute(nextRoute(first)) : null)],
      meta: st.scans.gate.split("/").pop(),
      rail,
      body: el("div", { class: "screen" }, list.el),
    });
    const update = (nr: Route) => {
      r = nr as CheckRoute;
      const img = imageOf(r.filters.image);
      rail.select(img?.slug ?? null);
      shell.scope(img ? imageName(img.name, img.ref) : null, () => nav(withFilters(r, { image: undefined })));
      shownRows = list.update(r, rows, img?.slug ?? null);
      return true;
    };
    update(r);
    out.update = update;
    out.key = (e) => {
      const x = e.key === "n" ? next() : null;
      if (x) { nav(nextRoute(x)); return true; }
      return list.table.key(e) || rail.key(e);
    };
  }).catch((e) => alive() && renderShell(host, r, { title: check, body: failed(e) }));
  renderShell(host, r, { title: check, body: loading() });
  load();
  return out;
}
