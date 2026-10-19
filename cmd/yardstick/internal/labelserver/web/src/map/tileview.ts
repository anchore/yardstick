// tileview.ts is the tile view: one finding of the open group on the Focus tile (shared/tile.ts),
// under a breadcrumb back to where the group was opened.
import type { claimsv1 } from "../gen/wire";
import { el, must } from "../shared/dom";
import { hinted, isOpen, type Row } from "../shared/rows";
import * as tile from "../shared/tile";
import { dirTitle, marks, plural } from "../shared/words";
import { acceptCause, acceptRows, label, moveCard, research } from "./actions";
import { causeLabels, diffRows, groupRows, hintLabels, nextGroup, reasonTitle, specOfGroup, subjectName, tier, tierNames, tierOf, whyKey } from "./data";
import { navigate, openSpec, replaceURL, select } from "./nav";
import { endPreview, previewOn } from "./preview";
import { render } from "./render";
import { gate, st, ui } from "./state";

const firstOpen = () => (ui.rows.find((x) => isOpen(x.r)) || ui.rows[0])?.r.id;

// crumbs is the one way back from a match (Esc does the same): the board (or the delta map), the
// check (its panel), the group. Testers found three ways back confusing, so there are no others.
function crumbs() {
  const s = ui.cardsSpec, out: HTMLElement[] = [];
  const crumb = (text: string, go: () => void, cls = "", title: string | null = null) => el("button", { class: `crumb ${cls}`, onclick: go, title }, text);
  if (s?.kind === "delta") {
    const rows = diffRows(st(), ui.si).filter((x) => x.dir === s.dir && whyKey(x.r.why) === s.why);
    out.push(crumb("← scan delta map", () => navigate({ cardsSpec: null, selected: null, evidence: false, delta: true, zoom: null }), "home", "back to the scan delta map (Esc)"));
    out.push(crumb(`${dirTitle[s.dir] || s.dir} › ${reasonTitle(st(), rows, s.dir)}`, () => navigate({ cardsSpec: null, selected: null, evidence: false, delta: true, zoom: { dir: s.dir, why: s.why } })));
    if (s.pkg) out.push(crumb(s.pkg, () => select(firstOpen()), "here"));
    return out;
  }
  const c = s && st().gate?.result?.checks.find((k) => k.name === s.check);
  out.push(crumb("← gate board", () => navigate({ cardsSpec: null, selected: null, evidence: false, delta: false, zoom: null }), "home", "back to the gate board (Esc)"));
  if (c) {
    const what = c.state === "fail" ? ` · fails on ${plural((c.failsOn || []).length, "claim")}` : "";
    out.push(crumb(`${c.name} ${c.state}${what}`, () => { ui.scrollTo = c.name; navigate({ cardsSpec: null, selected: null, evidence: false, delta: false, zoom: null }); }, c.state));
  }
  const title = (ui.cards?.title ?? "").replace(/^[^›]*› /, "");
  out.push(crumb(title, () => select(firstOpen()), "here"));
  return out;
}

export function renderTile() {
  must("#map").hidden = true;
  const box = must("#tile");
  box.hidden = false;
  const s = st();
  ui.rows = ui.cards ? groupRows(s, ui.si, ui.cards) : [];
  if (!ui.rows.length) { ui.cards = null; render(); return; }
  if (ui.selected && !ui.rows.some((x) => x.r.id === ui.selected)) ui.selected = null;
  // the claims a failed check fails on are labeled by definition: every one is there to re-examine
  const open = ui.cardsSpec?.kind === "fails" ? ui.rows : ui.rows.filter((x) => isOpen(x.r));
  if (!ui.selected && open.length) { ui.selected = open[0].r.id; replaceURL(); }
  const x = ui.rows.find((y) => y.r.id === ui.selected) || null;
  const i = ui.rows.findIndex((y) => y.r.id === ui.selected);
  const body = el("div", { class: "tile", id: "tilebody" });
  box.replaceChildren(
    el("div", { class: "crumbline" }, ...crumbs().flatMap((cr, k) => [k ? el("span", { class: "sep" }, "›") : null, cr]),
      el("span", { class: "pos" }, x ? `${i + 1} of ${ui.rows.length}` : `${ui.rows.length - open.length} of ${ui.rows.length} labeled`)),
    body);
  if (!x) {
    const nx = nextGroup(s, ui.si, ui.cardsSpec);
    body.replaceChildren(el("div", { class: "done" },
      el("div", { class: "big" }, "Every match in this group is labeled"),
      el("div", { class: "muted" }, ui.last ? [el("button", { class: "ghost", onclick: () => select(ui.last) }, "z · back to the last one"), " "] : null,
        nx ? el("button", { class: "ghost", onclick: () => openSpec(specOfGroup(nx.c, nx.g)) }, `next: ${nx.g.cause ? `✦ ${nx.g.cause.title}` : `${marks[nx.g.dir]} ${nx.g.pkg}`} · ${plural(nx.g.rows.filter((y) => isOpen(y.r)).length, "unlabeled match", "unlabeled matches")}`) : null)));
    return;
  }
  const spec = ui.cardsSpec, check = spec && spec.kind !== "delta" ? s.gate?.result?.checks.find((k) => k.name === spec.check) : null;
  tile.render(body, {
    state: s, gateName: gate(),
    r: x.r, si: x.si, dir: x.dir, check, reexamine: spec?.kind === "fails",
    tierName: x.r.gate ? tierNames[tierOf(tier(s, x.r, x.dir))] || null : null,
    counter: `${i + 1} of ${ui.rows.length} in this group`,
    receipt: ui.receipt, backKey: "z", canStay: true,
    why: ui.why, more: ui.evidence, note: ui.note,
    matches: ui.matches, details: ui.details, subjectName: (si) => subjectName(s, si),
    on: {
      label: (v, j) => label(v, [x.r.id], j), accept: (rows) => acceptRows(rows), acceptCause: (cause) => acceptCause(cause, cause.pending), research: (rows) => research(rows),
      toggleWhy: () => { ui.why = !ui.why; renderTile(); }, toggleMore: () => select(ui.selected, !ui.evidence),
      note: (t) => (ui.note = t), skip: () => moveCard(1),
    },
  });
  previewTileAccepts(body, x.r);
}

// previewTileAccepts wires the tile's two accept controls to the ribbon's preview: the label button
// that carries the agent hint (accept it on this match), and "accept all N" for a package hint.
// shared/tile.ts has no hook for this, so they're found by the classes it gives them.
function previewTileAccepts(body: HTMLElement, r: Row) {
  endPreview();
  const wire = (b: Element | null, labelsOf: () => Record<string, claimsv1.Verdict>, what: string) => {
    if (b) for (const [k, f] of Object.entries(previewOn(labelsOf, what))) b.addEventListener(k.slice(2), f);
  };
  if (hinted(r)) wire(body.querySelector(".buttons .btn.hinted"), () => hintLabels([r]), `the agent hint on ${r.vulnerability}`);
  const cause = (r.causes || []).map((id) => st().causes.find((k) => k.id === id)).find((k) => k && k.pending?.length > 1);
  if (cause) wire(body.querySelector(".sec-agent .group button"), () => causeLabels(cause, cause.pending), `the package hint on ${plural(cause.pending.length, "match", "matches")}`);
}
