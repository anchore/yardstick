// url.ts is the map's view as a URL and back (docs/alternate-uis.md §11). Pure: no DOM, no page
// state; nav.ts puts the result in the history.
//
// /ui/map/gates/<run>/                                   the gate board (the delta map on an ad-hoc run)
// /ui/map/gates/<run>/delta                              the scan-delta map
// /ui/map/gates/<run>/delta/<dir>/<why>                  zoomed into one reason
// /ui/map/gates/<run>/delta/<dir>/<why>/<pkg|all>        cards: a package of that reason (or all of it)
// /ui/map/gates/<run>/check/<name>/cause/<id>            cards: a same-reasoning group of a check
// /ui/map/gates/<run>/check/<name>/tier/<t>/<dir>/<pkg>  cards: a package in one tier of a check
// /ui/map/gates/<run>/check/<name>/fails[/<vuln>/<pkg>]  cards: the claims a failed check fails on
// ?image=<slug> scopes every view to one image; #row=<id>[&evidence] is the selected card.
import type { SubjectInfo } from "../gen/wire";

export interface Zoom { dir: string; why: string }

// CardsSpec says which cards are open; data.ts's cardsFor turns it into rows
export type CardsSpec =
  | { kind: "delta"; dir: string; why: string; pkg: string | null }
  | { kind: "cause"; check: string; cause: string }
  | { kind: "tier"; check: string; tier: number; dir: string; pkg: string }
  | { kind: "fails"; check: string; vuln: string | null; pkg: string | null };

export interface View {
  si: number | null;           // image scope: subject index, or null for every image
  delta: boolean;              // on a gate: the scan-delta map instead of the gate board
  zoom: Zoom | null;           // zoomed into one reason
  cardsSpec: CardsSpec | null;
  selected: string | null;     // row id of the finding on the tile
  evidence: boolean;           // the tile shows more evidence; "&evidence" in the URL
}

export interface Where { pathname: string; search: string; hash: string }

const seg = (x: string | number | null) => encodeURIComponent(String(x));

// urlFor is the view's URL under base, the gate's page path (/ui/map/gates/<gate>/)
export function urlFor(base: string, v: View, subjects: SubjectInfo[] | undefined): string {
  const parts: (string | number | null)[] = [], s = v.cardsSpec;
  if (s?.kind === "delta") parts.push("delta", s.dir, s.why, s.pkg ?? "all");
  else if (s?.kind === "cause") parts.push("check", s.check, "cause", s.cause);
  else if (s?.kind === "tier") parts.push("check", s.check, "tier", s.tier, s.dir, s.pkg);
  else if (s?.kind === "fails") { parts.push("check", s.check, "fails"); if (s.vuln) parts.push(s.vuln, s.pkg); }
  else if (v.zoom) parts.push("delta", v.zoom.dir, v.zoom.why);
  else if (v.delta) parts.push("delta");
  let url = base + parts.map(seg).join("/");
  if (v.si != null) url += `?image=${seg(subjects?.[v.si]?.slug ?? v.si)}`;
  if (v.selected && s) url += `#row=${v.selected}${v.evidence ? "&evidence" : ""}`;
  return url;
}

// parseURL is the view a URL under base says; an image it doesn't know scopes to every image
export function parseURL(base: string, loc: Where, subjects: SubjectInfo[] | undefined): View {
  const p = loc.pathname.slice(base.length).split("/").filter(Boolean).map(decodeURIComponent);
  const st: View = { si: null, delta: false, zoom: null, cardsSpec: null, selected: null, evidence: false };
  const img = new URLSearchParams(loc.search).get("image"), subs = subjects || [];
  if (img != null) {
    const i = subs.findIndex((x) => x.slug === img);
    st.si = i >= 0 ? i : /^\d+$/.test(img) && Number(img) < subs.length ? Number(img) : null;
  }
  if (p[0] === "delta") {
    st.delta = true;
    if (p[1] && p[2]) { st.zoom = { dir: p[1], why: p[2] }; if (p[3]) st.cardsSpec = { kind: "delta", dir: p[1], why: p[2], pkg: p[3] === "all" ? null : p[3] }; }
  } else if (p[0] === "check" && p[1]) {
    if (p[2] === "cause" && p[3]) st.cardsSpec = { kind: "cause", check: p[1], cause: p[3] };
    else if (p[2] === "tier" && p.length >= 6) st.cardsSpec = { kind: "tier", check: p[1], tier: Number(p[3]), dir: p[4], pkg: p[5] };
    else if (p[2] === "fails") st.cardsSpec = { kind: "fails", check: p[1], vuln: p[3] || null, pkg: p[4] || null };
  }
  const h = loc.hash.match(/row=([0-9a-f]{16})(&evidence)?/);
  if (h) { st.selected = h[1]; st.evidence = !!h[2]; }
  return st;
}
