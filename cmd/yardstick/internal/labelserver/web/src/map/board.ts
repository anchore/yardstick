// board.ts draws the gate board: one panel per check, what decides it, and the cheapest labels
// first, grouped by what one action settles.
import type { CheckResult, claimsv1 } from "../gen/wire";
import { el, must } from "../shared/dom";
import { hinted, isOpen, pkgOf, srcPkg } from "../shared/rows";
import { dots, fmt, labels, marks, plural } from "../shared/words";
import { acceptCause, acceptIds } from "./actions";
import { allRows, bearing, causeLabels, failingClaims, type Group, groupBy, groups, hintLabels, specOfGroup, subjectName, tierNames, tierOf, unchanged } from "./data";
import { openSpec } from "./nav";
import { previewOn } from "./preview";
import { render } from "./render";
import { researchControls, researchedMark } from "./research";
import { gateBar } from "./ribbon";
import { st, ui } from "./state";

export function renderBoard() {
  must("#tile").hidden = true;
  const map = must("#map");
  map.hidden = false;
  map.style.gridTemplateRows = "auto 1fr";
  if (ui.scrollTo) { const name = ui.scrollTo; ui.scrollTo = null; ui.opened.add(`pass|${name}`); setTimeout(() => document.getElementById(`panel-${name}`)?.scrollIntoView({ block: "start" }), 0); }
  const s = st(), res = s.gate?.result, same = unchanged(s);
  if (!res) return;
  if (same) {
    map.style.gridTemplateRows = "1fr";
    map.replaceChildren(el("div", { class: "same" },
      el("div", { class: "big" }, "✓ No differences"),
      el("p", {}, `The candidate and the reference report exactly the same ${plural(same.shared, "match", "matches")} in ${plural(same.images, "image")}. Nothing changed, so there is nothing to label and no check sees a change.`),
      el("p", { class: "muted" }, "If the candidate was meant to change something, these images don't exercise it: add images that do and re-scan."),
      el("p", { class: "muted" }, `checks, all passing: ${res.checks.map((c) => c.name).join(", ")}`)));
    return;
  }
  const bearingRows = allRows(s, ui.si).filter((x) => isOpen(x.r) && x.r.gate), both = bearingRows.filter((x) => x.dir === "both").length;
  const crumbs = el("div", { class: "crumbs" }, el("b", {}, ui.si == null ? "every image" : subjectName(s, ui.si)),
    el("span", {}, ` · ${plural(bearingRows.length - both, "unlabeled delta")}${both ? ` and ${both} unlabeled matches both scans report` : ""} could move a check · each panel is one check: what it needs, and the labels that get there cheapest`),
    el("span", { class: "spacer" }), researchControls());
  map.replaceChildren(crumbs, el("div", { class: "board" }, ...res.checks.map((c) => panel(c))));
}

function panel(c: CheckResult) {
  const s = st();
  const rng = c.value.worst === c.value.best ? fmt(c.value.worst) : `${fmt(c.value.worst)} (worst) … ${fmt(c.value.best)} (best)`;
  // a passing check has nothing to act on: it folds to its head, and the head unfolds it
  const key = `pass|${c.name}`, folded = c.state === "pass" && !ui.opened.has(key);
  const toggle = () => { if (ui.opened.has(key)) ui.opened.delete(key); else ui.opened.add(key); render(); };
  const box = el("section", { class: `panel ${c.state}${folded ? " folded" : ""}`, id: `panel-${c.name}` });
  box.append(el("div", { class: "panel-head", ...(c.state === "pass" ? { onclick: toggle, title: folded ? "show this check" : "fold this check" } : {}) },
    el("span", { class: `band band-${c.state}` }, c.state), el("b", { class: "nm" }, c.name), el("span", { class: "means" }, folded ? `${c.valueMeans} ${rng} against ${fmt(c.threshold)}` : c.valueMeans),
    c.state === "pass" ? el("span", { class: "fold" }, folded ? "▸" : "▾") : null));
  if (folded) return box;
  box.append(el("div", { class: "desc" }, c.description), gateBar(c, { head: false }));
  if (c.state === "pass") {
    box.append(el("div", { class: "decides" }, `Passes even in the worst case: ${c.valueMeans} ${rng} against ${fmt(c.threshold)}. No label here can change it.`));
    return box;
  }
  if (c.state === "fail") {
    const claims = failingClaims(s, ui.si, c);
    box.append(el("div", { class: "decides" }, `Fails even in the best case: ${c.valueMeans} ${rng} against ${fmt(c.threshold)}. `,
      claims.length ? "It fails on claims already recorded, not on unlabeled matches; no amount of labeling changes it. Re-examine these (a newer claim wins):" : "Nothing open changes it."));
    if (claims.length) {
      const byVuln = groupBy(claims, (x) => `${x.r.vulnerability}|${srcPkg(x.r)}`);
      box.append(el("div", { class: "claims" }, ...[...byVuln.values()].map((list) => {
        const r = list[0].r, mark = researchedMark(list.map((x) => x.r));
        return el("button", { class: "claim", onclick: () => openSpec({ kind: "fails", check: c.name, vuln: r.vulnerability, pkg: srcPkg(r) }) },
          el("span", { class: `chip v-${r.verdict}` }, `${labels[r.verdict].glyph} ${labels[r.verdict].word}`), " ", el("b", {}, r.vulnerability), ` · ${srcPkg(r)}${list.length > 1 ? ` ×${list.length}` : ""} · ${marks[list[0].dir]} ${[...new Set(list.map((x) => subjectName(s, x.si)))].join(", ")}`,
          mark ? [" ", mark] : null);
      })));
      box.append(el("button", { class: "ghost", onclick: () => openSpec({ kind: "fails", check: c.name, vuln: null, pkg: null }) }, `re-examine all ${claims.length}`));
    }
    return box;
  }
  // undecided: the distance, then the cheapest labels that get there. The server sends no estimate
  // of how many labels decide it (delta's did), so there is no distance to give.
  box.append(el("div", { class: "decides" }, `${c.valueMeans}: ${rng} against ${fmt(c.threshold)}. `, "No labeling can decide it from here."));
  const gs = groups(s, bearing(s, ui.si, c)), max = Math.max(1, ...gs.map((g) => g.rows.length));
  // each tier shows its biggest groups; the long tail unfolds per tier, so a tier of singletons
  // never hides the big accept in the next one
  const caps: Record<number, number> = { 0: Infinity, 1: 6, 2: 8, 3: 4 };
  const list = el("div", { class: "groups" });
  for (const t of [0, 1, 2, 3]) {
    const inTier = gs.filter((x) => tierOf(x.tier) === t);
    if (!inTier.length) continue;
    const key = `${c.name}|${t}`, shown = ui.opened.has(key) ? inTier : inTier.slice(0, caps[t]);
    list.append(el("div", { class: "tier" }, tierNames[t], ` · ${plural(inTier.reduce((n, x) => n + x.rows.length, 0), "match", "matches")} in ${plural(inTier.length, "group")}`));
    for (const g of shown) list.append(groupRow(g, max, c));
    if (inTier.length > shown.length) list.append(el("button", { class: "ghost more", onclick: () => { ui.opened.add(key); render(); } }, `+ ${inTier.length - shown.length} more`));
  }
  if (!gs.length) list.append(el("div", { class: "muted" }, "nothing open bears on it"));
  box.append(list);
  return box;
}

const confRank: Record<string, number> = { high: 0, medium: 1, low: 2 };

// groupRow is one thing to act on: its bar is how many labels one action settles
function groupRow(g: Group, max: number, c: CheckResult) {
  const n = g.rows.length, hintedRows = g.rows.filter((x) => hinted(x.r)), first = g.rows[0].r.hint;
  const allHinted = hintedRows.length === n;
  const v = g.cause?.verdict || (allHinted && g.rows.every((x) => x.r.hint?.verdict === first?.verdict) ? first?.verdict : null);
  const conf = g.cause?.confidence || (allHinted ? g.rows.reduce((a, x) => { const cf = x.r.hint?.confidence ?? ""; return confRank[cf] > confRank[a] ? cf : a; }, "high") : null);
  const title = g.cause ? g.cause.title : `${g.pkg} · ${n === 1 ? g.rows[0].r.vulnerability : plural(n, "match", "matches")}`;
  const open = () => openSpec(specOfGroup(c, g));
  const cause = g.cause, ids = g.rows.map((x) => x.r.id);
  return el("div", { class: `group t${tierOf(g.tier)}` },
    el("div", { class: "bar" }, el("span", { class: v ? `fill v-${v}` : "fill", style: `width:${(100 * n) / max}%` })),
    el("button", { class: "gtitle", onclick: open, title: g.rows.slice(0, 8).map((x) => `${x.r.vulnerability} ${pkgOf(x.r.package.ref).name}`).join("\n") + (n > 8 ? `\n…` : "") },
      el("span", { class: "n" }, String(n)), " ", el("span", { class: "mk" }, marks[g.dir]), " ", cause ? el("span", { class: "star" }, "✦ ") : null, title),
    v ? el("span", { class: `sugg v-${v}` }, `${labels[v].glyph} ${labels[v].word}? ${dots[conf ?? ""] || ""}`) : el("span", { class: "muted" }, "no agent hint"),
    researchedMark(g.rows.map((x) => x.r)) || el("span", {}),
    cause && cause.pending.length ? acceptButton(`accept ${ids.filter((id) => cause.pending.includes(id)).length} ✦`, () => acceptCause(cause, ids),
      () => causeLabels(cause, ids), `the package hint on ${title}`)
      : hintedRows.length && v ? acceptButton(`accept ${hintedRows.length} ✦`, () => acceptIds(hintedRows.map((x) => x.r.id)),
        () => hintLabels(g.rows.map((x) => x.r)), `the ${plural(hintedRows.length, "agent hint")} on ${title}`) : el("span", {}),
    el("button", { class: "ghost", onclick: open }, "open"));
}
// acceptButton is an "accept N ✦" control: hovering it previews on the gate's bars where accepting
// would move them
const acceptButton = (text: string, onclick: () => void, labelsOf: () => Record<string, claimsv1.Verdict>, what: string) =>
  el("button", { class: "ghost accept", onclick, ...previewOn(labelsOf, what) }, text);
