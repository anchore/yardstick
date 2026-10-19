// mapview.ts draws the scan-delta map: the differences as a treemap (direction › reason › source
// package), each block filled by label state; clicking a package opens its cards.
import { el, must, svg } from "../shared/dom";
import { srcPkg } from "../shared/rows";
import { clip, dirTitle, plural } from "../shared/words";
import { diffRows, groupBy, type Item, reasonTitle, subjectName, type Tally, tally, whyKey } from "./data";
import { navigate, openSpec } from "./nav";
import { researchControls } from "./research";
import { st, ui } from "./state";
import { type Rect, squarify } from "./treemap";

interface Node { key: string; title: string; list: Item[]; value: number }
type Block = Node & Rect;

export function renderMap() {
  must("#tile").hidden = true;
  const map = must("#map");
  map.hidden = false;
  const s = st(), rows = diffRows(s, ui.si), zoom = ui.zoom;
  const crumbs = el("div", { class: "crumbs", "data-testid": "crumbs" },
    el("button", { "data-testid": "zoom-out", onclick: () => navigate({ zoom: null, cardsSpec: null, selected: null, evidence: false }) }, ui.si == null ? "every image" : subjectName(s, ui.si)),
    zoom ? [" › ", el("b", { "data-testid": "zoom-title", "data-dir": zoom.dir, "data-why": zoom.why }, `${dirTitle[zoom.dir]} › ${reasonTitle(s, rows.filter((x) => x.dir === zoom.dir && whyKey(x.r.why) === zoom.why), zoom.dir)}`),
      el("button", { class: "ghost", "data-testid": "label-all-cards", style: "text-decoration:none;margin-left:8px", onclick: () => openSpec({ kind: "delta", dir: zoom.dir, why: zoom.why, pkg: null }) }, "label all as cards")]
      : el("span", {}, " · a block is a source package: its size is how many matches, the bar at its bottom how they're labeled; click one to label its matches, or a reason's title to look at that reason alone"),
    el("span", { class: "spacer" }), researchControls(),
  );
  const W = Math.max(600, map.clientWidth || 900), H = Math.max(300, (map.clientHeight || 500) - 60);
  const tree = svg("svg", { class: "tree", "data-testid": "treemap", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
  tree.append(svg("defs", {}, svg("pattern", { id: "hatchmap", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    svg("line", { x1: 0, y1: 0, x2: 0, y2: 6, stroke: "currentColor", "stroke-width": 2, opacity: .3 }))));
  if (!rows.length) {
    tree.append(svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "empty", "data-testid": "treemap-empty" }, "no differences in scope"));
  } else if (zoom) {
    const inZoom = rows.filter((x) => x.dir === zoom.dir && whyKey(x.r.why) === zoom.why);
    packages(tree, inZoom, { x: 2, y: 2, w: W - 4, h: H - 4 }, zoom.dir, zoom.why);
  } else {
    const dirs = (["added", "dropped"] as const).map((dir) => ({ dir, list: rows.filter((x) => x.dir === dir) })).filter((d) => d.list.length);
    const total = rows.length, gap = 10;
    let x = 2;
    for (const d of dirs) {
      const w = dirs.length === 1 ? W - 4 : Math.max((W - 4 - gap) * 0.22, ((W - 4 - gap) * d.list.length) / total);
      const width = dirs.length === 1 ? w : Math.min(w, W - 4 - gap - (W - 4 - gap) * 0.22);
      tree.append(svg("rect", { x, y: 0, width, height: H, class: `dirbg-${d.dir}`, "data-testid": "dir-region", "data-dir": d.dir, "data-count": d.list.length }));
      tree.append(svg("text", { x: x + 6, y: 15, class: "dir", "data-testid": "dir-label", "data-dir": d.dir }, `${dirTitle[d.dir]} · ${d.list.length}`));
      const items: Node[] = [...groupBy(d.list, (x) => whyKey(x.r.why))].map(([k, list]) => ({ key: k, title: reasonTitle(s, list, d.dir), list, value: list.length }));
      // one reason: no reason level to draw, the packages take the panel and the reason is its subtitle
      if (items.length === 1) {
        tree.append(svg("text", { x: x + 6, y: 32, class: "sub" }, `${items[0].title} · ${items[0].list.length}`));
        packages(tree, items[0].list, { x: x + 2, y: 38, w: width - 4, h: H - 40 }, d.dir, items[0].key);
      } else {
        for (const b of squarify(items, { x: x + 2, y: 22, w: width - 4, h: H - 24 })) reasonBlock(tree, b, d.dir);
      }
      x += width + gap;
    }
  }
  const legend = el("div", { class: "legend", "data-testid": "legend" }, el("span", {}, el("i", { class: "i-tp" }), "TP real match"), el("span", {}, el("i", { class: "i-fp" }), "FP false match"), el("span", {}, el("i", { class: "i-unclear" }), "unclear"),
    el("span", {}, el("i", { class: "i-hint" }), "unlabeled, with an agent hint"), el("span", {}, el("i", { class: "i-open" }), "unlabeled"), el("span", {}, "◆ could change the verdict"));
  map.replaceChildren(crumbs, tree, el("div", { class: "hover-line", id: "hover", "data-testid": "hover-line" }), legend);
  map.style.gridTemplateRows = "auto 1fr auto auto";
}

// reasonBlock is one reason's area: a header strip (click: that reason alone) over its packages.
function reasonBlock(tree: SVGElement, b: Block, dir: string) {
  const t = tally(b.list), head = 20;
  const g = svg("g", { "data-testid": "reason-block", "data-dir": dir, "data-why": b.key, "data-count": t.n, onmouseenter: () => hover(b, t), onmouseleave: () => hover(null) });
  g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, class: "reason" }));
  g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: Math.min(head, b.h), class: "reason-head", "data-testid": "reason-head", "data-dir": dir, "data-why": b.key, onclick: () => navigate({ zoom: { dir, why: b.key } }) },
    svg("title", {}, `${b.title} · ${plural(t.n, "line")} · click to look at this reason alone`)));
  if (b.w > 60 && b.h > head) g.append(svg("text", { x: b.x + 5, y: b.y + 14, class: "ttl" }, clip(`${t.decisive ? "◆ " : ""}${b.title} · ${t.n}`, b.w / 7)));
  tree.append(g);
  if (b.h > head + 12) packages(tree, b.list, { x: b.x + 1, y: b.y + head + 1, w: b.w - 2, h: b.h - head - 2 }, dir, b.key);
}

// packages draws one block per source package into rect; clicking one opens its cards.
function packages(tree: SVGElement, list: Item[], rect: Rect, dir: string, why: string) {
  const items: Node[] = [...groupBy(list, (x) => srcPkg(x.r))].map(([k, l]) => ({ key: k, title: k, list: l, value: l.length }));
  for (const b of squarify(items, rect)) tree.append(block(b, dir, why, () => openSpec({ kind: "delta", dir, why, pkg: b.key })));
}

// block draws one package block: its name and count, ◆ when it holds lines that could change the
// verdict, and a bar at its bottom with its labels (TP, FP, unclear, suggested; the rest open).
function block(b: Block, dir: string, why: string, onclick: () => void) {
  const t = tally(b.list);
  const g = svg("g", { "data-testid": "block", "data-dir": dir, "data-why": why, "data-package": b.key, "data-count": t.n, "data-tp": t.tp, "data-fp": t.fp, "data-unclear": t.unclear, "data-open": t.open, "data-hinted": t.hinted, "data-decisive": t.decisive, onclick, onmouseenter: () => hover(b, t), onmouseleave: () => hover(null) });
  g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, class: "blk" }, svg("title", {}, `${b.title} · ${plural(t.n, "line")} · ${t.tp} TP · ${t.fp} FP · ${t.unclear} unclear · ${t.open} unlabeled (${t.hinted} with an agent hint)${t.researched ? ` · ✦ ${t.researched} researched` : ""}${t.triaged ? ` · ✦ ${t.triaged} triaged` : ""}${t.decisive ? ` · ◆ ${t.decisive} could change the verdict` : ""}\nclick to label these as cards`)));
  const pad = Math.min(4, b.w / 10, b.h / 10), barH = Math.min(8, Math.max(3, b.h / 6));
  let off = 0;
  const by = b.y + b.h - pad - barH, bw = b.w - 2 * pad;
  g.append(svg("rect", { x: b.x + pad, y: by, width: Math.max(0, bw), height: barH, class: "bar-track", "pointer-events": "none" }));
  for (const [k, n] of [["tp", t.tp], ["fp", t.fp], ["unclear", t.unclear], ["hint", t.hinted]] as [string, number][]) {
    if (!n) continue;
    const w = (bw * n) / t.n;
    g.append(svg("rect", { x: b.x + pad + off, y: by, width: w, height: barH, class: `fill-${k}`, "pointer-events": "none" }));
    off += w;
  }
  if (b.w > 60 && b.h > 34) {
    g.append(svg("text", { x: b.x + 5, y: b.y + 14, class: "ttl" }, clip(`${t.decisive ? "◆ " : ""}${b.title}`, b.w / 7)));
    g.append(svg("text", { x: b.x + 5, y: b.y + 27, class: "sub" }, clip(`${t.n} · ${t.open} open${t.hinted ? ` · ✦ ${t.hinted}` : ""}`, b.w / 6.5)));
  } else if (b.w > 24 && b.h > 16) {
    g.append(svg("text", { x: b.x + 3, y: b.y + 11, class: "sub" }, clip(`${b.title} ${t.n}`, b.w / 6.5)));
  }
  return g;
}

function hover(b: Block | null, t?: Tally) {
  const line = document.getElementById("hover");
  if (!line) return;
  if (!b || !t) { line.textContent = ""; return; }
  const checks = [...new Set(b.list.flatMap((x) => x.r.gate?.couldFlip || []))];
  const pkgs = [...new Set(b.list.map((x) => srcPkg(x.r)))];
  line.textContent = `${b.title} · ${plural(t.n, "line")} in ${plural(pkgs.length, "source package")} · ${t.tp} TP · ${t.fp} FP · ${t.open} unlabeled, ${t.hinted} with an agent hint${t.researched ? ` · ✦ ${t.researched} researched` : ""}${t.triaged ? ` · ✦ ${t.triaged} triaged` : ""}` +
    (t.decisive ? ` · ◆ ${t.decisive} could change ${checks.join(", ")}` : t.bears ? ` · ${t.bears} could narrow a check` : "");
}
