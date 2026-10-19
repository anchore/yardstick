// yardstick · map, ported from delta's map UI: look first, then label. The gate as range bars, the
// images as small multiples, and the differences as a treemap (direction › reason › source
// package) filled by label state. On a gate run the top level is a board of the checks; clicking a
// group opens the Focus tile (shared/tile.ts) on its findings, under a breadcrumb back to the board.
//
// app.ts boots the page and wires the browser to it: history, keys, theme, resize and the reload
// while research runs. What each part draws lives in its own module, from render.ts down.
import { $, el, must } from "../shared/dom";
import { detail, hinted } from "../shared/rows";
import { acceptCause, acceptRows, currentRow, label, moveCard, nextDecisive, research } from "./actions";
import { type Action, keyAction } from "./keys";
import { renderMap } from "./mapview";
import { back, navigate, readURL, select } from "./nav";
import { load, render } from "./render";
import { activeResearch } from "./research";
import { st, ui } from "./state";
import { renderTile } from "./tileview";

window.addEventListener("popstate", () => { if (ui.state) { ui.pin = null; Object.assign(ui, readURL()); render(); } });

// while research runs, reload now and then so its agent hints show up (not on a match: a reload
// there would redraw the tile under the reader)
setInterval(() => { if (ui.state && !ui.cards && !document.hidden && activeResearch().length) load(); }, 8000);

document.addEventListener("keydown", (e) => {
  const target = e.target as HTMLElement, help = must("#help");
  const x = ui.cards ? currentRow() : null;
  const a = keyAction({ key: e.key, tag: target.tagName, meta: e.metaKey, ctrl: e.ctrlKey, alt: e.altKey }, {
    helpOpen: !help.hidden, cards: !!ui.cards, selected: !!ui.selected, row: !!x,
    away: !!(ui.cardsSpec || ui.zoom || ui.delta), last: !!ui.last, images: ui.state?.subjects.length ?? 0,
  });
  // handled keys do nothing else: "f" focuses the reason picker, and the same keystroke would
  // otherwise land in it and pick the FP option, labeling the match
  if (a) { e.preventDefault(); act(a, e, target, help); }
});

// act carries out a key's action on the current card, when there is one
function act(a: Action, e: KeyboardEvent, target: HTMLElement, help: HTMLElement) {
  const x = ui.cards ? currentRow() : null;
  const sel = x ? [x.r.id] : [];
  switch (a.do) {
    case "blur": target.blur(); break;
    case "closeHelp": help.hidden = true; break;
    case "help": help.hidden = false; break;
    case "move": moveCard(a.by); break;
    case "label": label(a.verdict, sel); break;
    case "accept": acceptRows(sel); break;
    case "acceptAll": {
      const c = x && (x.r.causes || []).map((id) => st().causes.find((k) => k.id === id)).find((k) => k?.pending?.length);
      if (c) acceptCause(c, c.pending); else acceptRows(ui.rows.filter((y) => hinted(y.r) && y.r.hint.confidence === "high").map((y) => y.r.id));
      break;
    }
    case "toggleWhy": ui.why = !ui.why; renderTile(); break;
    case "toggleEvidence": select(ui.selected, !ui.evidence); break;
    case "focusNote": $("#note")?.focus(); e.preventDefault(); break;
    case "research": if (x) research([x.r.id]); break;
    case "openLink": {
      const u = (x && detail(x.r))?.dataSource || (ui.selected ? ui.details.get(ui.selected)?.links?.[0]?.url : undefined);
      if (u) window.open(u, "_blank", "noopener");
      break;
    }
    case "nextDecisive": nextDecisive(); break;
    case "back": back(); break;
    case "last": select(ui.last, false); break;
    case "theme": cycleTheme(); break;
    case "image": navigate({ si: a.si, zoom: null, cardsSpec: null, selected: null, evidence: false }); break;
  }
}

const nextTheme: Record<string, string> = { system: "light", light: "dark", dark: "system" };
function cycleTheme() {
  const cur = localStorage.getItem("yardstick.theme") || "system";
  const next = nextTheme[cur];
  if (next === "system") { localStorage.removeItem("yardstick.theme"); delete document.documentElement.dataset.theme; }
  else { localStorage.setItem("yardstick.theme", next); document.documentElement.dataset.theme = next; }
  must("#theme-button").textContent = `theme: ${next}`;
}

(function boot() {
  if (!ui.gateName) { must("#map").replaceChildren(el("div", { class: "empty" }, "no gate in the URL")); return; }
  ui.base = location.pathname.match(/^.*?\/gates\/[^/]+\//)?.[0] ?? "";
  const help = must("#help");
  must("#theme-button").textContent = `theme: ${localStorage.getItem("yardstick.theme") || "system"}`;
  must("#theme-button").addEventListener("click", cycleTheme);
  must("#help-button").addEventListener("click", () => (help.hidden = false));
  help.addEventListener("click", (e) => { if (e.target === help) help.hidden = true; });
  window.addEventListener("resize", () => { if (!ui.cards && ui.state) renderMap(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) load(); });
  load();
})();
