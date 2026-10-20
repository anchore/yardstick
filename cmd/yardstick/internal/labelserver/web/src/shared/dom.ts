// dom.ts is the render helpers the pages share: el() and svg() build an element from its attributes
// and children, $ and must() find one, toast() shows a passing message.

type Leaf = Node | string | null | undefined | false;
export type Child = Leaf | Child[];

// an attribute named on<event> is a listener; null, undefined and false leave the attribute out.
// style goes through the CSSOM, since the page's CSP (style-src 'self') blocks a style attribute
type Handlers = { [K in keyof HTMLElementEventMap as `on${K}`]?: (e: HTMLElementEventMap[K]) => unknown };
export type Attrs = Handlers & { [k: string]: unknown };

const flat = (children: Child[]) => children.flat(Infinity as 1) as Leaf[];

// nodes are children as a flat list, the absent ones dropped, for a lit-html template, which would
// print false as the text "false"
export const nodes = (...children: Child[]) => flat(children).filter((c): c is Node | string => c != null && c !== false);

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    // a boolean data-* attribute is "true" or "false" so a test can read both
    if (k.startsWith("data-") && typeof v === "boolean") { n.setAttribute(k, String(v)); continue; }
    if (v == null || v === false) continue;
    if (k === "class") n.className = String(v);
    else if (k === "style") n.style.cssText = String(v);
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v as EventListener);
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  n.append(...nodes(...children));
  return n;
}

// fill replaces a node's children, dropping the absent ones as el() does; replaceChildren alone
// turns null into the text "null"
export function fill(n: Element, ...children: Child[]) {
  n.replaceChildren(...nodes(...children));
}

const svgNS = "http://www.w3.org/2000/svg";
export function svg(tag: string, attrs: Attrs = {}, ...children: Child[]): SVGElement {
  const n = document.createElementNS(svgNS, tag) as SVGElement;
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith("data-") && typeof v === "boolean") { n.setAttribute(k, String(v)); continue; }
    if (v == null || v === false) continue;
    if (k === "style") n.style.cssText = String(v);
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v as EventListener);
    else n.setAttribute(k, String(v));
  }
  n.append(...flat(children).filter((c): c is Node | string => Boolean(c)));
  return n;
}

export const $ = <T extends HTMLElement = HTMLElement>(s: string) => document.querySelector<T>(s);

// must is an element the page's HTML always has
export function must<T extends HTMLElement = HTMLElement>(s: string): T {
  const n = document.querySelector<T>(s);
  if (!n) throw new Error(`the page has no ${s}`);
  return n;
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
// an action (a write's Undo) is a button in the toast, which then stays up long enough to reach it
export function toast(msg: string, error = false, action?: { text: string; run: () => void }) {
  const t = $("#toast");
  if (!t) return;
  fill(t, msg, action && el("button", { type: "button", class: "toast-action", "data-testid": "toast-action",
    onclick: () => { t.hidden = true; action.run(); } }, action.text));
  t.className = `toast${error ? " error" : ""}`; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), error ? 6000 : action ? 10000 : 2500);
}
