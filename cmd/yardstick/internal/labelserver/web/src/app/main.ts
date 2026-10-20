// main.ts is the /ui/gates/ app: it reads the route from the URL, draws that screen in the shell,
// and owns the history and the keys every screen shares.
//
// basecoat.js is Basecoat's component runtime: it wires up its components (the rail's combobox here)
// as they enter the document, including ones el() builds after load.
import "basecoat-css/basecoat";
import "basecoat-css/combobox";
import { el, must } from "../shared/dom";
import { checkView } from "./check";
import { findingView } from "./finding";
import { gateView } from "./gate";
import { gatesView } from "./gates";
import { kitView } from "./kit";
import { crumbs, formatRoute, parseRoute, up, type Route } from "./route";
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
            : findingView(host, next, nav);
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

document.addEventListener("keydown", (e) => {
  if (typing(e.target)) {
    if (e.key === "Escape") e.target.blur();
    return;
  }
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (view.key?.(e)) {
    e.preventDefault();
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
  if (!href?.startsWith("/ui/gates/") || a!.getAttribute("target")) return;
  e.preventDefault();
  if (href !== location.pathname + location.search) {
    history.pushState(null, "", href);
    render();
  }
});

window.addEventListener("popstate", render);
render();
