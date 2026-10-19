// nav.ts moves between views: navigation lives in the URL (url.ts), views push history (Esc =
// back), and the selected card and its evidence replace the entry.
import { render } from "./render";
import { ui } from "./state";
import { renderTile } from "./tileview";
import { type CardsSpec, parseURL, urlFor, type View } from "./url";

export const currentURL = () => urlFor(ui.base, ui, ui.state?.scans.subjects);
export const readURL = () => parseURL(ui.base, location, ui.state?.scans.subjects);
export const replaceURL = () => history.replaceState(null, "", currentURL());

// navigate changes the view and pushes it (or replaces the entry, for the selected card)
export function navigate(changes: Partial<View>, { replace = false } = {}) {
  if ("cardsSpec" in changes) ui.pin = null;
  Object.assign(ui, changes);
  const url = currentURL();
  if (url !== location.pathname + location.search + location.hash) {
    if (replace) history.replaceState(null, "", url); else { history.pushState(null, "", url); ui.pushes++; }
  }
  render();
}
// back is Esc: the browser's back through what this page pushed, else the view's parent
export function back() {
  if (ui.pushes > 0) { ui.pushes--; history.back(); return; }
  const s = ui.cardsSpec;
  if (s) navigate({ cardsSpec: null, selected: null, evidence: false, delta: s.kind === "delta", zoom: s.kind === "delta" ? { dir: s.dir, why: s.why } : null });
  else if (ui.zoom) navigate({ zoom: null });
  else if (ui.delta) navigate({ delta: false });
}
// select is the selected card and whether its evidence is open: the same history entry
export function select(id: string | null | undefined, evidence = ui.evidence) {
  if (id !== ui.pin) ui.pin = null;
  ui.selected = id ?? null; ui.evidence = evidence; ui.why = false; ui.receipt = null;
  replaceURL();
  renderTile();
}
export const openSpec = (spec: CardsSpec) => navigate({ cardsSpec: spec, selected: null, evidence: false });
// scope is the image scope; choosing the image in scope again scopes to every image
export function scope(si: number | null) {
  navigate({ si: ui.si === si ? null : si, zoom: null, cardsSpec: null, selected: null, evidence: false });
}
