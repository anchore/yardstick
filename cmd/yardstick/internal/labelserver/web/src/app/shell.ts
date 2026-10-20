// shell.ts is the chrome every screen shares (UI-RULES 5): one app bar, one breadcrumb, one title
// row, then the image rail beside the tabs and the screen's body.
import { html, nothing, render } from "lit-html";
import { nodes, type Child } from "../shared/dom";
import { activityChip } from "./activity";
import { historyLink } from "./historylink";
import type { Rail } from "./rail";
import { crumbs, formatRoute, gateTabs, gatesTabs, type Route } from "./route";
import { openPalette } from "./palette";
import { settings } from "./settings";
import { gateSwitch } from "./switcher";

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
  scope?: { label: Child; clear: () => void } | null; // the image filter's chip beside the rail's dropdown
  tabCounts?: Partial<Record<string, number>>;
  body: Child;
  row?: string;          // the finding's crumb, its vulnerability ID, once known
  crumbEnd?: Child;      // the breadcrumb row's right end, such as a finding's pager
  meta?: Child;          // the app bar's right side
  bar?: Child;           // under the app bar, such as the queue's
  prefs?: () => void;    // a setting in the cog changed, for a screen that draws its effect
}

const tabWords: Record<string, string> = { gates: "Gates", unlabeled: "Unlabeled", labels: "Labels", checks: "Checks", findings: "Matches", map: "Scan map" };

// tabsFor is the route's tabs, each keeping only the image filter
function tabsFor(r: Route): { id: string; href: string; on: boolean }[] {
  const filters = r.filters.image ? { image: r.filters.image } : {};
  if (r.level === "gates") return gatesTabs.map((t) => ({ id: t, on: t === r.tab, href: formatRoute({ level: "gates", tab: t, filters }) }));
  if (r.level === "gate") return gateTabs.map((t) => ({ id: t, on: t === r.tab, href: formatRoute({ ...r, tab: t, filters }) }));
  return [];
}

// the gate crumb's switcher is kept while the route stays, so drawing the shell again leaves its
// menu open
let switcher: { at: string; el: HTMLElement } | null = null;
function switchFor(r: Route, gate: string) {
  const at = `${formatRoute(r)}|${gate}`;
  if (switcher?.at !== at) switcher = { at, el: gateSwitch(r, gate) };
  return switcher.el;
}

// renderShell draws a screen into host as a lit-html template. Drawn again with new data, the frame
// changes in place, and a component passed as the same node as last time (a table, the rail, the
// label panel) is left alone with its focus, scroll and open menus; a new node replaces it. So a
// screen builds its components once and draws the shell with all its data on every load. lit keeps
// markers in host, so nothing else writes to it.
export function renderShell(host: HTMLElement, r: Route, v: ShellView) {
  const trail = crumbs(r, v.row);
  const breadcrumb = html`<nav class="breadcrumb" aria-label="Breadcrumb" data-testid="breadcrumb"><ol>${trail.map((c, i) => html`${i > 0 ? html`<li aria-hidden="true" class="sep">›</li>` : nothing}<li>${i === trail.length - 1 ? html`<span aria-current="page">${c.label}</span>` : html`<a href=${c.href}>${c.label}</a>`}${c.gate ? switchFor(r, c.gate) : nothing}</li>`)}</ol></nav>`;

  const tabs = tabsFor(r);
  const tablist = tabs.length > 0 ? html`<nav class="tabs" data-testid="tabs"><div role="tablist">${tabs.map((t) => html`<a role="tab" href=${t.href} aria-selected=${String(t.on)} data-tab=${t.id}>${tabWords[t.id]}${v.tabCounts?.[t.id] != null ? html`<span class="ct">${v.tabCounts[t.id]!.toLocaleString()}</span>` : nothing}</a>`)}</div></nav>` : nothing;

  const scope = v.scope ? html`image: ${nodes(v.scope.label)}<button type="button" class="x" aria-label="Clear image filter" @click=${v.scope.clear}>×</button>` : nothing;

  render(html`
    <header class="appbar" data-testid="app-bar">
      <a class="brand" href="/ui/gates/">yardstick <span>claims</span></a>
      <span class="sp"></span>
      <span class="meta">${nodes(v.meta)}</span>
      ${activityChip()}
      ${historyLink()}
      <button type="button" class="btn goto" data-variant="ghost" data-size="sm" data-testid="goto-button" @click=${openPalette}>Go to… <kbd class="kbd">${/Mac|iP/.test(navigator.platform) ? "⌘K" : "Ctrl K"}</kbd></button>
      ${settings(v.prefs)}
    </header>
    ${nodes(v.bar)}
    <main class="page">
      ${v.crumbEnd ? html`<div class="crumbrow">${breadcrumb}<span class="sp"></span>${nodes(v.crumbEnd)}</div>` : breadcrumb}
      <div class="titlerow" data-testid="title-row">
        ${nodes(v.status)}<h1 data-testid="title">${nodes(v.title)}</h1>${nodes(v.after)}<span class="sp"></span>${nodes(v.actions)}
        ${v.sub ? html`<p class="sub">${nodes(v.sub)}</p>` : nothing}
      </div>
      ${nodes(v.above)}
      <div class="layout">${v.rail?.rail ?? nothing}<div class="content"><div class="navrow">${v.rail?.picker ?? nothing}<span class="scope" ?hidden=${!v.scope} data-testid="scope-chip">${scope}</span></div>${tablist}${nodes(v.body)}</div></div>
    </main>`, host);
}
