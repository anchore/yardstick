// switcher.ts is the gate crumb's switcher: a Basecoat dropdown menu of every gate with its outcome
// and open rows. Picking one goes to the same level in that gate (route.ts inGate). basecoat.js
// wires the menu up once it is in the document.
import { el, fill } from "../shared/dom";
import { gateList } from "./data";
import { gateItems, type GateItem } from "./goto";
import { formatRoute, inGate, type Route } from "./route";
import { status } from "./ui";

let seq = 0;

export function gateSwitch(r: Route, current: string) {
  const id = `gate-switch-${++seq}`;
  let gates: GateItem[] | string | null = null; // the gates, or why they couldn't load
  const menu = el("div", { role: "menu", id: `${id}-menu`, "aria-labelledby": `${id}-trigger` });
  // the caret is drawn by CSS, so the breadcrumb's text stays its nouns
  const trigger = el("button", { type: "button", id: `${id}-trigger`, class: "btn", "data-variant": "ghost", "data-size": "sm",
    "aria-haspopup": "menu", "aria-controls": `${id}-menu`, "aria-expanded": "false", "aria-label": "Switch gate", title: "Switch gate", "data-testid": "gate-switch-button",
    onclick: () => { if (!open()) show(); } });
  const root = el("div", { class: "dropdown-menu gate-switch", "data-testid": "gate-switch",
    onkeydown: (e) => {
      // keys pressed while the menu is open are the menu's: main.ts skips a key something
      // prevented, and this runs before Basecoat's handler closes the menu on Esc
      if (open()) { if (e.key !== "Tab") e.preventDefault(); } else if (["Enter", " ", "ArrowDown", "ArrowUp"].includes(e.key)) show();
    } },
  trigger, el("div", { "data-popover": "", "aria-hidden": "true" }, menu));
  const open = () => trigger.getAttribute("aria-expanded") === "true";

  // show fills the menu on its way open, so the closed breadcrumb holds no menu text
  function show() {
    fill(menu, typeof gates === "string" || !gates ? el("div", { class: "muted" }, gates ?? "Loading…")
      : gates.map((g) => el("a", { role: "menuitem", href: formatRoute(inGate(r, g.id)),
        "data-testid": "gate-option", "data-gate": g.id, "data-state": g.state, "data-open": g.open, "aria-current": g.id === current ? "true" : null },
      status(g.state), el("span", { class: "gname" }, g.id), el("small", {}, `${g.open.toLocaleString()} open`))));
    (root as HTMLElement & { refresh?: () => void }).refresh?.();
  }
  gateList()
    .then((l) => { gates = gateItems(l); })
    .catch((e) => { gates = `Couldn't load the gates: ${(e as Error).message}`; })
    .finally(() => { if (open()) show(); });
  return root;
}
