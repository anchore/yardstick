// main.ts is the /ui/gates/ app: it reads the route from the URL, draws that screen in the shell,
// and owns the history and the keys every screen shares.
//
// basecoat.js is Basecoat's component runtime: it wires up its components (the rail's combobox, the
// gate switcher's dropdown menu, the palette's command) as they enter the document, including ones
// el() builds after load.
import "basecoat-css/basecoat";
import "basecoat-css/combobox";
import "basecoat-css/command";
import "basecoat-css/dropdown-menu";
import { el, must, toast } from "../shared/dom";
import { checkView } from "./check";
import { gateList } from "./data";
import { findingView } from "./finding";
import { gateView } from "./gate";
import { gatesView } from "./gates";
import { hintsView } from "./hints";
import { hintsHref } from "./hintsdata";
import { historyView } from "./history";
import { gateItems, nextGate } from "./goto";
import { kitView } from "./kit";
import { openPalette } from "./palette";
import { queueView } from "./queue";
import { queueFor } from "./queuelist";
import { crumbs, formatRoute, gateOf, inGate, parseRoute, up, type Route } from "./route";
import { renderShell, type View } from "./shell";

const host = must("#app");
let route: Route | null = null;
let view: View = {};

const screenOf = (r: Route) => formatRoute({ ...r, filters: {} });

function nav(r: Route, replace = false) {
  const url = formatRoute(r);
  if (url === location.pathname + location.search) return;
  history[replace ? "replaceState" : "pushState"](null, "", url);
  render();
}

function render() {
  const next = parseRoute(location.pathname, location.search);
  // the same screen with other filters: let it update in place, keeping focus and what's typed
  if (route && next && screenOf(route) === screenOf(next) && view.update?.(next)) {
    route = next;
    return;
  }
  route = next;
  document.title = next ? `${crumbs(next).at(-1)!.label} · yardstick` : "yardstick";
  view = next == null ? notFound()
    : next.level === "kit" ? kitView(host, next, nav)
      : next.level === "gates" ? gatesView(host, next, nav)
        : next.level === "gate" ? gateView(host, next, nav)
          : next.level === "check" ? checkView(host, next, nav)
            : next.level === "finding" ? findingView(host, next, nav)
              : next.level === "hints" ? hintsView(host, next, nav)
                : next.level === "queue" ? queueView(host, next, nav)
                  : historyView(host, next, nav);
}

function notFound(): View {
  renderShell(host, { level: "gates", tab: "gates", filters: {} }, {
    title: "Not found",
    body: el("div", { class: "placeholder", "data-testid": "placeholder" }, "Nothing lives at ", el("code", {}, location.pathname), "."),
  });
  return {};
}

// typing is a focused field that takes text, where a key press is a character, not a command
function typing(t: EventTarget | null): t is HTMLElement {
  if (!(t instanceof HTMLElement)) return false;
  if (t.isContentEditable || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement) return true;
  return t instanceof HTMLInputElement && !["checkbox", "radio", "button", "submit", "reset"].includes(t.type);
}

// stepGate goes to the next (or previous) gate with open rows, at the same level where that makes sense
async function stepGate(step: 1 | -1) {
  const r = route;
  if (!r) return;
  const gate = nextGate(gateItems(await gateList()), gateOf(r), step);
  if (gate) nav(inGate(r, gate)); else toast("no other gate has open rows");
}

document.addEventListener("keydown", (e) => {
  // a key something on the page already took (an open menu), or one inside the palette's dialog
  if (e.defaultPrevented || (e.target as Element).closest?.("dialog")) return;
  if (typing(e.target)) {
    if (e.key === "Escape") e.target.blur();
    return;
  }
  if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
    e.preventDefault();
    openPalette();
    return;
  }
  if (e.metaKey || e.ctrlKey) return;
  if (!e.altKey && (e.key === "J" || e.key === "K")) {
    e.preventDefault();
    void stepGate(e.key === "J" ? 1 : -1).catch((err) => toast((err as Error).message, true));
    return;
  }
  // ⌥ reaches the screen only as ⌥j and ⌥k, which the finding page walks every row with
  if (e.altKey && e.code !== "KeyJ" && e.code !== "KeyK") return;
  // h opens hint review for the gate or image on screen, else every gate
  if (e.key === "h" && !e.altKey && route && route.level !== "hints") {
    e.preventDefault();
    history.pushState(null, "", hintsHref({ gate: gateOf(route) ?? undefined, image: route.filters.image }));
    render();
    return;
  }
  if (view.key?.(e)) {
    e.preventDefault();
    return;
  }
  // n enters the queue at the next open row in this screen's scope (queuelist.ts queueFor)
  if (e.key === "n" && !e.altKey && route) {
    e.preventDefault();
    nav(queueFor(route));
    return;
  }
  // Esc walks up one crumb (UI-RULES 4)
  const parent = e.key === "Escape" && route ? up(route) : null;
  if (parent) {
    e.preventDefault();
    nav(parent);
  }
});

// links inside the app change the view without a page load
document.addEventListener("click", (e) => {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  const a = (e.target as Element).closest?.("a[href]");
  const href = a?.getAttribute("href");
  if (!href?.startsWith("/ui/") || a!.getAttribute("target")) return;
  const u = new URL(href, location.href);
  if (!parseRoute(u.pathname, u.search)) return;
  e.preventDefault();
  if (href !== location.pathname + location.search) {
    history.pushState(null, "", href);
    render();
  }
});

window.addEventListener("popstate", render);
render();
