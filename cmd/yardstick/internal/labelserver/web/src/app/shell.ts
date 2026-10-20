// shell.ts is the chrome every screen shares (UI-RULES 5): one app bar, one breadcrumb, one title
// row, then the image rail beside the tabs and the screen's body.
import { el, fill, type Child } from "../shared/dom";
import type { Rail } from "./rail";
import { crumbs, formatRoute, gateTabs, gatesTabs, type Route } from "./route";

// View is what main.ts keeps of the screen on show: its keys, and a way to take a change of filters
// in place (true when it did) rather than being drawn again
export interface View {
  key?: (e: KeyboardEvent) => boolean;
  update?: (r: Route) => boolean;
}

// Nav goes to a route, replacing the history entry when replace is set (typing in a search box)
export type Nav = (r: Route, replace?: boolean) => void;

export interface ShellView {
  title: Child;
  status?: Child;        // the state badge before the title
  after?: Child;         // beside the title, such as a finding's label and effect
  sub?: Child;           // at most one line under the title
  actions?: Child;       // the screen's one primary button, and any secondary ones
  above?: Child;         // full width under the title, such as the gate's verdict bar
  rail?: Rail | null;
  tabCounts?: Partial<Record<string, number>>;
  body: Child;
  row?: string;          // the finding's crumb, its vulnerability ID, once known
  crumbEnd?: Child;      // the breadcrumb row's right end, such as a finding's pager
  meta?: Child;          // the app bar's right side
}

export interface Shell {
  // scope puts the image filter's chip beside the rail's dropdown, or takes it away
  scope(label: Child | null, clear?: () => void): void;
  // retab points the tabs at a route whose filters changed in place, so they keep its image
  retab(r: Route): void;
}

const tabWords: Record<string, string> = { gates: "Gates", unlabeled: "Unlabeled", labels: "Labels", checks: "Checks", findings: "Findings", map: "Scan map" };

// tabsFor is the route's tabs, each keeping only the image filter
function tabsFor(r: Route): { id: string; href: string; on: boolean }[] {
  const filters = r.filters.image ? { image: r.filters.image } : {};
  if (r.level === "gates") return gatesTabs.map((t) => ({ id: t, on: t === r.tab, href: formatRoute({ level: "gates", tab: t, filters }) }));
  if (r.level === "gate") return gateTabs.map((t) => ({ id: t, on: t === r.tab, href: formatRoute({ ...r, tab: t, filters }) }));
  return [];
}

export function renderShell(host: HTMLElement, r: Route, v: ShellView): Shell {
  const trail = crumbs(r, v.row);
  const breadcrumb = el("nav", { class: "breadcrumb", "aria-label": "Breadcrumb", "data-testid": "breadcrumb" },
    el("ol", {}, trail.map((c, i) => [
      i > 0 && el("li", { "aria-hidden": "true", class: "sep" }, "›"),
      el("li", {}, i === trail.length - 1 ? el("span", { "aria-current": "page" }, c.label) : el("a", { href: c.href }, c.label)),
    ])));

  const tabs = tabsFor(r);
  const tablist = tabs.length > 0 && el("nav", { class: "tabs", "data-testid": "tabs" },
    el("div", { role: "tablist" }, tabs.map((t) => el("a", { role: "tab", href: t.href, "aria-selected": String(t.on), "data-tab": t.id },
      tabWords[t.id], v.tabCounts?.[t.id] != null && el("span", { class: "ct" }, v.tabCounts[t.id]!.toLocaleString())))));

  const chip = el("span", { class: "scope", hidden: true, "data-testid": "scope-chip" });
  const navrow = el("div", { class: "navrow" }, v.rail?.picker, chip);

  fill(host,
    el("header", { class: "appbar", "data-testid": "app-bar" },
      el("a", { class: "brand", href: "/ui/gates/" }, "yardstick ", el("span", {}, "claims")),
      el("span", { class: "sp" }),
      el("span", { class: "meta" }, v.meta)),
    el("main", { class: "page" },
      v.crumbEnd ? el("div", { class: "crumbrow" }, breadcrumb, el("span", { class: "sp" }), v.crumbEnd) : breadcrumb,
      el("div", { class: "titlerow", "data-testid": "title-row" },
        v.status, el("h1", { "data-testid": "title" }, v.title), v.after, el("span", { class: "sp" }), v.actions,
        v.sub && el("p", { class: "sub" }, v.sub)),
      v.above,
      el("div", { class: "layout" }, v.rail?.rail, el("div", { class: "content" }, navrow, tablist, v.body))));

  return {
    retab(next) {
      if (!tablist) return;
      for (const t of tabsFor(next)) tablist.querySelector(`[data-tab="${t.id}"]`)?.setAttribute("href", t.href);
    },
    scope(label, clear) {
      chip.hidden = label == null;
      fill(chip, label != null && ["image: ", label, el("button", { type: "button", class: "x", "aria-label": "Clear image filter", onclick: () => clear?.() }, "×")]);
    },
  };
}
