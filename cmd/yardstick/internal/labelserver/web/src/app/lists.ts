// lists.ts is what the list screens share beyond the shell: the loading and error bodies, the one
// primary button, a cursor for row lists, and a guard against drawing a screen the reader has left.
import { el } from "../shared/dom";
import { formatRoute, parseRoute, type Route } from "./route";
import { kbd } from "./ui";

export const loading = () => el("div", { class: "placeholder", "data-testid": "loading" }, "Loading…");
export const failed = (e: unknown) => el("div", { class: "placeholder error", "data-testid": "load-error" }, `Couldn't load this: ${(e as Error).message}`);

// primary is the screen's one primary button (UI-RULES 7), "Label next", a link to the finding it
// opens, or disabled when nothing is open
export const primary = (text: string, href: string | null) => href
  ? el("a", { class: "btn", href, "data-testid": "label-next" }, text, " ", kbd("n"))
  : el("button", { type: "button", class: "btn", disabled: true, "data-testid": "label-next", title: "Nothing here is unlabeled" }, text, " ", kbd("n"));

const screen = (r: Route | null) => (r ? formatRoute({ ...r, filters: {} }) : "");

// shown says, later, whether the screen of route r is still the one on show: data that arrives
// after the reader moved on is dropped
export function shown(r: Route): () => boolean {
  const mine = screen(r);
  return () => screen(parseRoute(location.pathname, location.search)) === mine;
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
