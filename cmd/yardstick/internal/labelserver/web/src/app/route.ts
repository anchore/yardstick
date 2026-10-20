// route.ts is the app's URL as a view and back, for the four levels in UI-RULES.md. Pure: no DOM,
// no page state; main.ts puts the result in the history.
//
// /ui/gates/[?tab=unlabeled|labels]                   gates (level 0)
// /ui/gates/<gate>/                                   gate, Checks tab (level 1)
// /ui/gates/<gate>/findings | labels | map            gate, another tab
// /ui/gates/<gate>/checks/<check>                     check (level 2)
// /ui/gates/<gate>/checks/<check>/<row>               finding, reached from a check (level 3)
// /ui/gates/<gate>/findings/<row>                     finding, reached from the gate's Findings tab
// /ui/gates/_kit                                      the component kit (not linked from anywhere)
//
// Filters ride in the query string on every level: image (slug), verdict, hint, pkg, q, page.

export const base = "/ui/gates/";

export const gatesTabs = ["gates", "unlabeled", "labels"] as const;
export const gateTabs = ["checks", "findings", "labels", "map"] as const;
export type GatesTab = (typeof gatesTabs)[number];
export type GateTab = (typeof gateTabs)[number];

export const verdicts = ["tp", "fp", "unclear", "unlabeled"] as const;
export type VerdictFilter = (typeof verdicts)[number];

export interface Filters {
  image?: string;          // an image's slug
  verdict?: VerdictFilter;
  hint?: string;           // what W3's hint chip means by it, e.g. "yes"
  pkg?: string;            // a source package, as the scan map's blocks name it
  q?: string;              // free-text search
  page?: number;           // 1-based, left out on page 1
}

export type Route =
  | { level: "gates"; tab: GatesTab; filters: Filters }
  | { level: "gate"; gate: string; tab: GateTab; filters: Filters }
  | { level: "check"; gate: string; check: string; filters: Filters }
  // check is null for a finding opened from the gate's Findings tab
  | { level: "finding"; gate: string; check: string | null; row: string; filters: Filters }
  | { level: "kit"; filters: Filters };

const seg = (s: string) => encodeURIComponent(s);

function query(f: Filters, extra: [string, string][] = []): string {
  const p = new URLSearchParams(extra);
  if (f.image) p.set("image", f.image);
  if (f.verdict) p.set("verdict", f.verdict);
  if (f.hint) p.set("hint", f.hint);
  if (f.pkg) p.set("pkg", f.pkg);
  if (f.q) p.set("q", f.q);
  if (f.page && f.page > 1) p.set("page", String(f.page));
  const s = p.toString();
  return s ? `?${s}` : "";
}

function parseFilters(p: URLSearchParams): Filters {
  const f: Filters = {};
  const image = p.get("image"), verdict = p.get("verdict"), hint = p.get("hint"), pkg = p.get("pkg"), q = p.get("q"), page = Number(p.get("page"));
  if (image) f.image = image;
  if (verdict && (verdicts as readonly string[]).includes(verdict)) f.verdict = verdict as VerdictFilter;
  if (hint) f.hint = hint;
  if (pkg) f.pkg = pkg;
  if (q) f.q = q;
  if (Number.isInteger(page) && page > 1) f.page = page;
  return f;
}

// formatRoute is the route's URL, path and query
export function formatRoute(r: Route): string {
  switch (r.level) {
    case "gates": return base + query(r.filters, r.tab === "gates" ? [] : [["tab", r.tab]]);
    case "kit": return `${base}_kit${query(r.filters)}`;
    case "gate": return `${base}${seg(r.gate)}/${r.tab === "checks" ? "" : r.tab}${query(r.filters)}`;
    case "check": return `${base}${seg(r.gate)}/checks/${seg(r.check)}${query(r.filters)}`;
    case "finding": {
      const list = r.check == null ? "findings" : `checks/${seg(r.check)}`;
      return `${base}${seg(r.gate)}/${list}/${seg(r.row)}${query(r.filters)}`;
    }
  }
}

// parseRoute is the route a location names, or null for a path outside the app's
export function parseRoute(pathname: string, search = ""): Route | null {
  if (!pathname.startsWith(base)) return null;
  const params = new URLSearchParams(search), filters = parseFilters(params);
  let p: string[];
  try {
    p = pathname.slice(base.length).split("/").filter(Boolean).map(decodeURIComponent);
  } catch {
    return null; // a malformed escape
  }
  if (p.length === 0) {
    const tab = params.get("tab");
    return { level: "gates", tab: (gatesTabs as readonly string[]).includes(tab ?? "") ? (tab as GatesTab) : "gates", filters };
  }
  const [gate, a, b, c] = p;
  if (p.length === 1) return gate === "_kit" ? { level: "kit", filters } : { level: "gate", gate, tab: "checks", filters };
  if (a === "checks" && b != null) {
    if (p.length === 3) return { level: "check", gate, check: b, filters };
    if (p.length === 4) return { level: "finding", gate, check: b, row: c, filters };
    return null;
  }
  if (a === "findings" && p.length === 3) return { level: "finding", gate, check: null, row: b, filters };
  if (p.length === 2 && (gateTabs as readonly string[]).includes(a) && a !== "checks") return { level: "gate", gate, tab: a as GateTab, filters };
  return null;
}

// up is the route one crumb up, which Esc goes to, or null at the top. A finding goes back to the
// list it came from with that list's filters; a check keeps only the image on the way to its gate.
export function up(r: Route): Route | null {
  switch (r.level) {
    case "gates": return null;
    case "kit": return { level: "gates", tab: "gates", filters: {} };
    case "gate": return { level: "gates", tab: "gates", filters: {} };
    case "check": return { level: "gate", gate: r.gate, tab: "checks", filters: r.filters.image ? { image: r.filters.image } : {} };
    case "finding":
      return r.check == null
        ? { level: "gate", gate: r.gate, tab: "findings", filters: r.filters }
        : { level: "check", gate: r.gate, check: r.check, filters: r.filters };
  }
}

export interface Crumb { label: string; href: string }

// crumbs is the breadcrumb, nouns only, top first; the last one is the current page. Each crumb is
// where Esc goes from the one after it, so a finding's gate crumb returns to the tab it came from.
// row names the finding's crumb (its vulnerability ID) when the caller knows it, else the row id.
export function crumbs(r: Route, row?: string): Crumb[] {
  const out: Crumb[] = [];
  for (let at: Route | null = r; at; at = up(at)) out.unshift({ label: label(at, row), href: formatRoute(at) });
  return out;
}

function label(r: Route, row?: string): string {
  switch (r.level) {
    case "gates": return "Gates";
    case "kit": return "Component kit";
    case "gate": return r.gate;
    case "check": return r.check;
    case "finding": return row || r.row;
  }
}

// withFilters is the same route with its filters changed; a filter set to undefined is dropped,
// and the page goes back to 1 unless the change is the page
export function withFilters(r: Route, f: Partial<Filters>): Route {
  const next: Filters = { ...r.filters, ...f };
  if (!("page" in f)) delete next.page;
  for (const k of Object.keys(next) as (keyof Filters)[]) if (next[k] == null || next[k] === "") delete next[k];
  return { ...r, filters: next };
}
