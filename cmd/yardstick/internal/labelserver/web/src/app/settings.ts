// settings.ts is the app bar's cog: the reader's standing choices, each kept in this browser, in a
// Basecoat popover that stays open while they change. basecoat.js wires it up once it is in the
// document, as it does the gate switcher.
import { el, svg } from "../shared/dom";

// the two switches are on unless this browser turned them off, so a key is absent for its default
const advanceKey = "yardstick.autoAdvance";      // after labeling, go on to the next match
const skipKey = "yardstick.queueSkipLabeled";    // the queue's j / k step over rows it labeled
const themeKey = "yardstick.theme";              // read by assets/theme.js before the page paints

function isOn(key: string) { try { return localStorage.getItem(key) !== "off"; } catch { return true; } }
function setOn(key: string, on: boolean) {
  try { if (on) localStorage.removeItem(key); else localStorage.setItem(key, "off"); } catch { /* no storage: the default stands */ }
}
export const advancing = () => isOn(advanceKey);
export const skipping = () => isOn(skipKey);

// setTheme keeps the choice and sets data-theme; theme.js keeps Basecoat's dark class in step with
// it, and with the OS while it is unset (system)
function setTheme(t: string) {
  const root = document.documentElement;
  try { if (t === "system") localStorage.removeItem(themeKey); else localStorage.setItem(themeKey, t); } catch { /* no storage: this page only */ }
  if (t === "system") delete root.dataset.theme; else root.dataset.theme = t;
}

// lucide's settings icon
const cog = () => svg("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
  svg("path", { d: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" }),
  svg("circle", { cx: 12, cy: 12, r: 3 }));

let seq = 0;

// settings is the cog and its popover; changed tells the screen on show, which may draw a setting's
// effect (the Save button's words, the queue's pager)
export function settings(changed?: () => void) {
  const id = `settings-${++seq}`;
  const toggle = (key: string, testid: string, words: string, wrap?: string) =>
    el("label", { class: "label", "data-testid": wrap },
      el("input", { type: "checkbox", "data-testid": testid, checked: isOn(key),
        onchange: (e: Event) => { setOn(key, (e.target as HTMLInputElement).checked); changed?.(); } }), words);
  const now = document.documentElement.dataset.theme ?? "system";
  const trigger = el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "icon-sm", "aria-label": "Settings", title: "Settings",
    "aria-haspopup": "dialog", "aria-controls": id, "aria-expanded": "false", "data-testid": "settings-button" }, cog());
  const root = el("div", { class: "popover settings", "data-testid": "settings",
    // keys pressed inside the open popover are its own: Esc closes it rather than walking up a
    // crumb, and j or n don't move the page. Stopping them here leaves Space on a switch and the
    // arrows in the radio group working, which preventDefault (the switcher's way) would not. This
    // runs before Basecoat's own handler on the same element, which closes it on Esc.
    onkeydown: (e) => { if (trigger.getAttribute("aria-expanded") === "true") e.stopPropagation(); } },
  trigger,
  el("div", { id, "data-popover": "", "data-align": "end", "aria-hidden": "true", role: "dialog", "aria-label": "Settings", "data-testid": "settings-panel" },
    el("header", {}, el("h2", {}, "Settings"), el("p", {}, "Kept in this browser.")),
    toggle(advanceKey, "advance-checkbox", "After labeling, go to the next match", "advance-toggle"),
    toggle(skipKey, "queue-skip", "Queue: skip labeled rows"),
    el("fieldset", { class: "theme", role: "radiogroup", "aria-label": "Theme", "data-testid": "settings-theme" },
      el("legend", {}, "Theme"),
      ["system", "light", "dark"].map((t) => el("label", { class: "label" },
        el("input", { type: "radio", class: "input", name: id, value: t, checked: t === now, "data-testid": "theme-option", onchange: () => setTheme(t) }),
        t[0].toUpperCase() + t.slice(1))))));
  return root;
}
