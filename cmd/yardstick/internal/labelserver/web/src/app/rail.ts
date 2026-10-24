// rail.ts is the image rail: the numbered image filter on gate and check screens, and the searchable
// dropdown (Basecoat's combobox) it collapses to. It's a filter, not navigation: picking an image
// calls onSelect, and the screen decides what that does to the URL.
import { el, fill, type Child } from "../shared/dom";
import { matches, openOf, order, railKey, sumCounts, type Counts, type RailImage, type RailSort } from "./images";
import { plural } from "../shared/words";
import { imageName, stackBar } from "./ui";

export interface RailOptions {
  images: RailImage[];          // in gate order, which the number keys follow
  selected: string | null;      // the selected image's slug, null for every image
  onSelect: (slug: string | null) => void;
  // "check" when the counts are one check's findings: an image with none reads "none here";
  // "labels" when they are the labels on each image, which have no verdict bar; "hints" when
  // total is the hinted rows on each image (hint review)
  scope?: Scope;
}

export interface Rail {
  rail: HTMLElement;    // the rail, for the layout's left column
  picker: HTMLElement;  // the collapsed dropdown, for the row above the tabs
  // select shows a selection made elsewhere (the URL) without calling onSelect
  select(slug: string | null): void;
  // key handles 0-9, [, ] and /, and says whether it did; the page calls it outside text fields
  key(e: KeyboardEvent): boolean;
  // hints puts hint review's actions in: one in the rail's head, and one under each image (by slug)
  hints(head: Child, per: (slug: string) => Child): void;
  // images shows new counts for the same images, after a write
  images(images: RailImage[]): void;
}

type Scope = "gate" | "check" | "labels" | "hints";

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
function countText(c: Counts, scope: Scope) {
  if (scope === "labels") return c.total ? plural(c.total, "label") : "no labels";
  if (scope === "hints") return c.total ? plural(c.total, "hinted match", "hinted matches") : "no hints";
  if (c.total === 0) return scope === "check" ? "none here" : "no changes";
  if (openOf(c) === 0 && scope === "check") return `${c.total} here`;
  return [el("b", {}, String(openOf(c))), ` open · ${c.total}`];
}

let seq = 0;

export function imageRail(o: RailOptions): Rail {
  const scope = o.scope ?? "gate", n = o.images.length;
  let all = sumCounts(o.images.map((i) => i.counts));
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
  const cts: HTMLElement[] = [], bars: HTMLElement[] = [], optCts: HTMLElement[] = []; // by position, what counts() fills
  const acts: (HTMLElement | undefined)[] = []; // hint review's action under each image, by position
  const head = el("div", { class: "rail-hints", hidden: true });
  const item = (p: number) => {
    const img = p === 0 ? null : o.images[p - 1];
    const b = el("button", {
      type: "button", title: img?.ref, "data-slug": img?.slug ?? "", "data-testid": "rail-image",
      onclick: () => pick(p),
    },
    el("span", { class: "k" }, keyFor(p)),
    p === 0 ? el("span", { class: "imname" }, el("span", { class: "b" }, "All images")) : imageName(img!.name, img!.ref),
    cts[p] = el("span", { class: "ct" }));
    items[p] = b;
    return b;
  };
  for (let p = 0; p <= n; p++) item(p);
  const collapse = el("button", { type: "button", class: "btn", "data-variant": "ghost", "data-size": "sm", title: "Collapse to a dropdown", "data-testid": "rail-collapse", onclick: () => setMode(true) }, "⇤ collapse");
  const rail = el("nav", { class: "rail", "aria-label": scope === "check" ? "Images in this check" : "Images", "data-testid": "image-rail" },
    el("div", { class: "rail-head" }, filter, collapse),
    el("div", { class: "rail-sort" }, el("span", {}, scope === "check" ? "this check's matches" : scope === "labels" ? "labels per image" : "per image"), sortBtn),
    head, list);

  // the dropdown: Basecoat's combobox, the variant whose trigger is a button and whose search box
  // sits in the popover. basecoat.js finds it once it is in the document and wires it up.
  const options = [0, ...o.images.map((_, i) => i + 1)].map((p) => {
    const img = p === 0 ? null : o.images[p - 1];
    return el("div", { role: "option", "data-value": img?.slug ?? ALL, "data-filter": img ? `${img.name} ${img.ref}` : "all images", title: img?.ref },
      el("span", { class: "k" }, keyFor(p)),
      img ? imageName(img.name) : el("span", { class: "imname" }, el("span", { class: "b" }, "All images")),
      optCts[p] = el("span", { class: "ct" }));
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

  // counts fills each image's counts into its item and its option
  function counts() {
    all = sumCounts(o.images.map((i) => i.counts));
    for (let p = 0; p <= n; p++) {
      const c = p === 0 ? all : o.images[p - 1].counts;
      items[p].className = `im${p === 0 ? " all" : ""}${c.total === 0 ? " none" : scope !== "hints" && openOf(c) === 0 ? " quiet" : ""}`;
      fill(cts[p], countText(c, scope));
      if (scope !== "labels" && scope !== "hints") {
        const bar = stackBar(c);
        if (bars[p]) bars[p].replaceWith(bar); else items[p].append(bar);
        bars[p] = bar;
      }
      fill(optCts[p], scope === "labels" || scope === "hints" ? countText(c, scope) : openOf(c) ? `${openOf(c)} open` : scope === "check" && c.total ? `${c.total} here` : "0 open");
    }
  }

  function draw() {
    const q = filter.value;
    sortBtn.textContent = sort === "gate" ? "gate order ▾" : "most open ▾";
    sortBtn.title = sort === "gate" ? "Sort by most open" : "Sort in gate order";
    fill(list, items[0], order(o.images, sort).map((i) => [items[i + 1], acts[i + 1]]));
    o.images.forEach((img, i) => { items[i + 1].hidden = !matches(img, q); if (acts[i + 1]) acts[i + 1]!.hidden = items[i + 1].hidden; });
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
  counts();
  draw();
  setMode(collapsed());

  return {
    rail, picker,
    select(slug) { if (slug !== sel) { sel = slug; draw(); } },
    // ponytail: the same images in the same order, as a gate's are after a write; a rail for other images is built anew
    images(next) { o.images = next; counts(); draw(); },
    hints(h, per) {
      fill(head, h);
      head.hidden = !h;
      o.images.forEach((img, i) => {
        const a = per(img.slug);
        acts[i + 1] = a ? el("div", { class: "im-act", "data-testid": "rail-act", "data-image": img.slug }, a) : undefined;
      });
      draw();
    },
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
