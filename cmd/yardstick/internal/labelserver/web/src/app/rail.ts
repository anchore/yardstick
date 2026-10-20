// rail.ts is the image rail: the numbered image filter on gate and check screens, and the searchable
// dropdown (Basecoat's combobox) it collapses to. It's a filter, not navigation: picking an image
// calls onSelect, and the screen decides what that does to the URL.
import { el, fill } from "../shared/dom";
import { matches, order, railKey, sumCounts, type Counts, type RailImage, type RailSort } from "./images";
import { plural } from "../shared/words";
import { imageName, stackBar } from "./ui";

export interface RailOptions {
  images: RailImage[];          // in gate order, which the number keys follow
  selected: string | null;      // the selected image's slug, null for every image
  onSelect: (slug: string | null) => void;
  // "check" when the counts are one check's findings: an image with none reads "none here";
  // "labels" when they are the labels on each image, which have no verdict bar
  scope?: "gate" | "check" | "labels";
}

export interface Rail {
  rail: HTMLElement;    // the rail, for the layout's left column
  picker: HTMLElement;  // the collapsed dropdown, for the row above the tabs
  // select shows a selection made elsewhere (the URL) without calling onSelect
  select(slug: string | null): void;
  // key handles 0-9, [, ] and /, and says whether it did; the page calls it outside text fields
  key(e: KeyboardEvent): boolean;
}

const collapseKey = "yardstick.rail";
const ALL = "*"; // the combobox's value for every image; Basecoat ignores an empty one

// the collapse choice is the reader's, kept in localStorage, which a locked-down browser may refuse
function collapsed(): boolean {
  try { return localStorage.getItem(collapseKey) === "collapsed"; } catch { return false; }
}
function setCollapsed(on: boolean) {
  try { if (on) localStorage.setItem(collapseKey, "collapsed"); else localStorage.removeItem(collapseKey); } catch { /* kept for this page only */ }
}

// countText is an item's count column
function countText(c: Counts, scope: "gate" | "check" | "labels") {
  if (scope === "labels") return c.total ? plural(c.total, "label") : "no labels";
  if (c.total === 0) return scope === "check" ? "none here" : "no changes";
  if (c.open === 0 && scope === "check") return `${c.total} here`;
  return [el("b", {}, String(c.open)), ` open · ${c.total}`];
}

let seq = 0;

export function imageRail(o: RailOptions): Rail {
  const scope = o.scope ?? "gate", n = o.images.length, all = sumCounts(o.images.map((i) => i.counts));
  const id = `rail-${++seq}`;
  let sel = o.selected, sort: RailSort = "gate";

  // positions: 0 is every image, i+1 is images[i]
  const slugAt = (p: number) => (p === 0 ? null : o.images[p - 1].slug);
  const posOf = (slug: string | null) => (slug == null ? 0 : o.images.findIndex((i) => i.slug === slug) + 1);
  const keyFor = (p: number) => (p <= 9 ? String(p) : "");

  // the rail
  const filter = el("input", { class: "input rail-filter", type: "search", placeholder: "Filter images  /", "aria-label": "Filter images", "data-testid": "rail-filter" });
  const sortBtn = el("button", { type: "button", class: "rail-sort-btn", "data-testid": "rail-sort" });
  const list = el("div", { class: "rail-items" });
  const items: HTMLButtonElement[] = [];
  const item = (p: number) => {
    const img = p === 0 ? null : o.images[p - 1], c = img ? img.counts : all;
    const b = el("button", {
      type: "button", class: `im${p === 0 ? " all" : ""}${c.total === 0 ? " none" : c.open === 0 ? " quiet" : ""}`,
      title: img?.ref, "data-slug": img?.slug ?? "", "data-testid": "rail-image",
      onclick: () => pick(p),
    },
    el("span", { class: "k" }, keyFor(p)),
    p === 0 ? el("span", { class: "imname" }, el("span", { class: "b" }, "All images")) : imageName(img!.name, img!.ref),
    el("span", { class: "ct" }, countText(c, scope)),
    scope !== "labels" && stackBar(c));
    items[p] = b;
    return b;
  };
  for (let p = 0; p <= n; p++) item(p);
  const collapse = el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", title: "Collapse to a dropdown", "data-testid": "rail-collapse", onclick: () => setMode(true) }, "⇤ collapse");
  const rail = el("nav", { class: "rail", "aria-label": scope === "check" ? "Images in this check" : "Images", "data-testid": "image-rail" },
    el("div", { class: "rail-head" }, filter, collapse),
    el("div", { class: "rail-sort" }, el("span", {}, scope === "check" ? "this check's findings" : scope === "labels" ? "labels per image" : "per image"), sortBtn),
    list);

  // the dropdown: Basecoat's combobox, the variant whose trigger is a button and whose search box
  // sits in the popover. basecoat.js finds it once it is in the document and wires it up.
  const options = [0, ...o.images.map((_, i) => i + 1)].map((p) => {
    const img = p === 0 ? null : o.images[p - 1], c = img ? img.counts : all;
    return el("div", { role: "option", "data-value": img?.slug ?? ALL, "data-filter": img ? `${img.name} ${img.ref}` : "all images", title: img?.ref },
      el("span", { class: "k" }, keyFor(p)),
      img ? imageName(img.name) : el("span", { class: "imname" }, el("span", { class: "b" }, "All images")),
      el("span", { class: "ct" }, scope === "labels" ? countText(c, scope) : c.open ? `${c.open} open` : scope === "check" && c.total ? `${c.total} here` : "0 open"));
  });
  const current = el("span", { class: "cur" });
  const trigger = el("button", { type: "button", class: "btn", "data-variant": "outline", "aria-haspopup": "listbox", "aria-expanded": "false", "aria-controls": `${id}-listbox`, "data-testid": "image-picker-button" },
    el("span", { class: "lbl" }, "Image"), current, el("span", { "aria-hidden": "true" }, "▾"),
    // Basecoat writes the picked label here, and with somewhere to write it leaves the search box
    // empty; the trigger shows the name with its tag kept in current instead
    el("span", { "data-value": "", hidden: true }));
  // the combobox reads its selection back from here whenever it opens
  const hidden = el("input", { type: "hidden" });
  const combo = el("div", { class: "combobox rail-picker" },
    trigger,
    el("div", { "data-popover": "", "aria-hidden": "true" },
      el("div", { class: "input-group" },
        el("input", { type: "text", role: "combobox", placeholder: "Filter images", autocomplete: "off", spellcheck: "false", "aria-autocomplete": "list", "aria-expanded": "false", "aria-controls": `${id}-listbox`, "aria-label": "Filter images" })),
      el("div", { role: "listbox", id: `${id}-listbox`, "aria-orientation": "vertical" }, options)),
    hidden);
  combo.addEventListener("change", (e) => {
    // the text field's own change event bubbles here too; only the combobox's carries a value
    if (!(e instanceof CustomEvent)) return;
    const v = (e.detail as { value: string }).value, slug = !v || v === ALL ? null : v;
    if (slug !== sel) pick(posOf(slug));
  });
  const expand = el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", title: "Show the image list", "data-testid": "rail-expand", onclick: () => setMode(false) }, "⇥ Show list");
  const picker = el("div", { class: "picker", "data-testid": "image-picker" }, combo, expand);

  function draw() {
    const q = filter.value;
    sortBtn.textContent = sort === "gate" ? "gate order ▾" : "most open ▾";
    sortBtn.title = sort === "gate" ? "Sort by most open" : "Sort in gate order";
    fill(list, items[0], order(o.images, sort).map((i) => items[i + 1]));
    o.images.forEach((img, i) => (items[i + 1].hidden = !matches(img, q)));
    items.forEach((b, p) => b.setAttribute("aria-pressed", String(p === posOf(sel))));
    const img = sel == null ? null : o.images[posOf(sel) - 1];
    fill(current, img ? imageName(img.name, img.ref) : "All images");
    hidden.value = sel ?? ALL;
    options.forEach((op) => (op.getAttribute("data-value") === (sel ?? ALL) ? op.setAttribute("aria-selected", "true") : op.removeAttribute("aria-selected")));
  }
  function setMode(c: boolean) {
    setCollapsed(c);
    rail.hidden = c;
    picker.hidden = !c;
  }
  function pick(p: number) {
    const slug = slugAt(p);
    if (slug === sel) return;
    sel = slug;
    draw();
    o.onSelect(slug);
  }

  filter.addEventListener("input", draw);
  sortBtn.addEventListener("click", () => { sort = sort === "gate" ? "open" : "gate"; draw(); });
  draw();
  setMode(collapsed());

  return {
    rail, picker,
    select(slug) { if (slug !== sel) { sel = slug; draw(); } },
    key(e) {
      if (e.key === "/") {
        if (rail.hidden) trigger.click(); else filter.focus();
        return true;
      }
      const shown = [0, ...order(o.images, sort).filter((i) => !items[i + 1].hidden).map((i) => i + 1)];
      const p = railKey(e.key, n, posOf(sel), shown);
      if (p == null) return false;
      pick(p);
      return true;
    },
  };
}
