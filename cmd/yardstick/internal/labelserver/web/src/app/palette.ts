// palette.ts is the ⌘K go-to palette on Basecoat's Command component, from any screen: gates,
// images, checks, findings by ID or package, and actions. Entries are links, so picking one (a
// click, or Enter on the active one) goes through main.ts's link handling. The filtering is
// goto.ts's, every word of the query, so the command runs in its manual filter mode.
import { el, fill, toast } from "../shared/dom";
import { gateList, gateState } from "./data";
import { actions, checkEntries, findingEntries, gateEntries, gateItems, imageEntries, matching, moreWords, type Entry, type Group } from "./goto";
import { kbd, status, verdict } from "./ui";

const groups: Group[] = ["Gates", "Images", "Checks", "Findings", "Actions"];

let palette: { dialog: HTMLDialogElement; open(): void } | null = null;

export function openPalette() {
  palette ??= build();
  if (!palette.dialog.open) palette.open();
}

function build() {
  let entries: Entry[] = actions, findings: Entry[] = [], seq = 0;
  const input = el("input", { type: "text", placeholder: "Go to a gate, image, check or finding…", autocomplete: "off", spellcheck: "false",
    role: "combobox", "aria-expanded": "true", "aria-controls": "palette-menu", "aria-autocomplete": "list", "aria-label": "Go to", "data-testid": "palette-input" });
  const menu = el("div", { role: "menu", id: "palette-menu", "aria-orientation": "vertical", "data-empty": "Nothing matches." });
  // the testid is on the command: the dialog itself has no box, its command is fixed in place
  const command = el("div", { class: "command", "data-filter": "manual", "data-testid": "palette" }, el("header", {}, input), menu);
  const dialog = el("dialog", { class: "command-dialog palette", "aria-label": "Go to",
    onclick: (e) => { if (e.target === dialog) dialog.close(); } }, command);

  const item = (e: Entry) => el("a", { role: "menuitem", id: `palette-${++seq}`, href: e.href, "data-testid": "palette-item", "data-group": e.group, "data-id": e.id },
    e.state && status(e.state), e.verdict && verdict(e.verdict),
    el("span", { class: "ptext" }, e.text), el("small", { class: "pdetail", title: e.detail }, e.detail),
    e.key && el("span", { "data-shortcut": "" }, kbd(e.key)));

  function draw() {
    const { shown, more } = matching(entries, findings, input.value);
    fill(menu, groups.map((g) => {
      const es = shown.filter((e) => e.group === g);
      return es.length > 0 && el("div", { role: "group", "aria-labelledby": `palette-${g}` },
        el("span", { role: "heading", id: `palette-${g}` }, g), es.map(item),
        g === "Findings" && more > 0 && el("p", { class: "more", "data-testid": "palette-more" }, moreWords(more)));
    }));
    // Basecoat takes the new items and makes the first one active; it isn't wired up until the
    // dialog has been in the document a moment
    (command as HTMLElement & { refresh?: () => void }).refresh?.();
  }
  input.addEventListener("input", draw);
  document.body.append(dialog);

  return {
    dialog,
    async open() {
      input.value = "";
      draw();
      dialog.showModal();
      input.focus();
      // gates and images from the list, then checks and findings from each gate's state
      try {
        const list = await gateList();
        entries = [...gateEntries(gateItems(list)), ...imageEntries(list), ...actions];
        draw();
        const states = await Promise.all(list.gates.filter((g) => !g.error).map(async (g) => ({ gate: g.id, state: await gateState(g.id) })));
        entries = [...gateEntries(gateItems(list)), ...imageEntries(list), ...checkEntries(states), ...actions];
        findings = findingEntries(states);
        if (dialog.open) draw();
      } catch (e) {
        toast(`Couldn't load the gates: ${(e as Error).message}`, true);
      }
    },
  };
}
