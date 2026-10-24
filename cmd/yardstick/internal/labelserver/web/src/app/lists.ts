// lists.ts is what the list screens share beyond the shell: the loading and error bodies, the one
// primary button and a cursor for row lists.
import { el } from "../shared/dom";
import { kbd } from "./ui";

export const loading = () => el("div", { class: "placeholder", "data-testid": "loading" }, "Loading…");
export const failed = (e: unknown) => el("div", { class: "placeholder error", "data-testid": "load-error" }, `Couldn't load this: ${(e as Error).message}`);

// primary is the screen's one primary button (UI-RULES 7), "Label next", a link to the finding it
// opens, or disabled when nothing is open
export const primary = (text: string, href: string | null) => href
  ? el("a", { class: "btn", href, "data-testid": "label-next" }, text, " ", kbd("n"))
  : el("button", { type: "button", class: "btn", disabled: true, "data-testid": "label-next", title: "Nothing here is unlabeled" }, text, " ", kbd("n"));

// keptPrimary is primary for a screen that draws its shell again: the same node each time, pointed
// at the new href, and a new one only when it turns between a link and a disabled button
export function keptPrimary(text: string) {
  let b: HTMLElement | null = null;
  return (href: string | null) => {
    if (!b || (b instanceof HTMLAnchorElement) !== !!href) b = primary(text, href);
    else if (href) b.setAttribute("href", href);
    return b;
  };
}

// listCursor walks a list of row links with j and k, by focus; Enter on the focused row follows it
export function listCursor(list: HTMLElement) {
  return (e: KeyboardEvent) => {
    if (e.key !== "j" && e.key !== "k") return false;
    const rows = [...list.querySelectorAll<HTMLElement>("a.lrow")];
    if (!rows.length) return false;
    const at = rows.indexOf(document.activeElement as HTMLElement);
    rows[Math.max(0, Math.min(rows.length - 1, at < 0 ? 0 : at + (e.key === "j" ? 1 : -1)))].focus();
    return true;
  };
}
