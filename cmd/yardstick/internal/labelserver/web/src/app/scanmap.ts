// scanmap.ts is the gate's Scan map tab: the scan-delta treemap (direction › reason › source
// package, each block's bar its labels), laid out by treemap.ts from scandata.ts; a block opens
// the Findings tab filtered to its package.
import type { State } from "../gen/wire";
import { el, svg } from "../shared/dom";
import { srcPkg } from "../shared/rows";
import { clip, dirTitle, plural } from "../shared/words";
import { diffRows, groupBy, type Item, reasonTitle, tally, whyKey } from "./scandata";
import { type Rect, squarify } from "./treemap";

const W = 1100, H = 520;

interface Node { key: string; title: string; list: Item[]; value: number }

export function scanMap(st: State, image: string | null, open: (pkg: string) => void): HTMLElement {
  const si = image ? st.subjects.findIndex((s) => s.slug === image) : -1;
  const rows = diffRows(st, si < 0 ? null : si);
  const tree = svg("svg", { class: "tree", "data-testid": "treemap", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Changed matches by direction, reason and source package" });
  tree.append(svg("defs", {}, svg("pattern", { id: "hatchmap", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    svg("line", { x1: 0, y1: 0, x2: 0, y2: 6, class: "hatch" }))));
  if (!rows.length) {
    tree.append(svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "sub" }, "No changes in scope"));
  } else {
    const dirs = (["added", "dropped"] as const).map((dir) => ({ dir, list: rows.filter((x) => x.dir === dir) })).filter((d) => d.list.length);
    const gap = 10, room = W - 4 - gap;
    let x = 2;
    for (const d of dirs) {
      // each direction gets its share of the width, but never under a fifth
      const width = dirs.length === 1 ? W - 4 : Math.min(Math.max(room * 0.22, (room * d.list.length) / rows.length), room * 0.78);
      tree.append(svg("rect", { x, y: 0, width, height: H, class: `dirbg ${d.dir}`, "data-testid": "dir-region", "data-dir": d.dir, "data-count": d.list.length }));
      tree.append(svg("text", { x: x + 6, y: 15, class: "dir" }, `${dirTitle[d.dir]} · ${d.list.length}`));
      const reasons: Node[] = [...groupBy(d.list, (i) => whyKey(i.r.why))].map(([k, list]) => ({ key: k, title: reasonTitle(st, list, d.dir), list, value: list.length }));
      for (const b of squarify(reasons, { x: x + 2, y: 22, w: width - 4, h: H - 24 })) {
        const head = 20;
        tree.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, class: "reason" }));
        tree.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: Math.min(head, b.h), class: "reason-head" }, svg("title", {}, `${b.title} · ${plural(b.list.length, "match", "matches")}`)));
        if (b.w > 60 && b.h > head) tree.append(svg("text", { x: b.x + 5, y: b.y + 14, class: "ttl" }, clip(`${b.title} · ${b.list.length}`, b.w / 7)));
        if (b.h > head + 12) packages(tree, b.list, { x: b.x + 1, y: b.y + head + 1, w: b.w - 2, h: b.h - head - 2 }, open);
      }
      x += width + gap;
    }
  }
  const legend = el("div", { class: "verbar" }, el("div", { class: "legend" },
    el("span", { class: "tp" }, "TP"), el("span", { class: "fp" }, "FP"), el("span", { class: "unclear" }, "unclear"),
    el("span", { class: "hinted" }, "unlabeled with a hint"), el("span", { class: "open" }, "unlabeled"),
    el("span", { class: "total" }, "· a block is a source package, sized by its changed matches; click one to list them")));
  return el("div", { class: "scanmap-in" }, tree, legend);
}

// packages draws one block per source package in rect: its name, count and a bar of its labels
function packages(tree: SVGElement, list: Item[], rect: Rect, open: (pkg: string) => void) {
  const items: Node[] = [...groupBy(list, (i) => srcPkg(i.r))].map(([k, l]) => ({ key: k, title: k, list: l, value: l.length }));
  for (const b of squarify(items, rect)) {
    const t = tally(b.list);
    const g = svg("g", { class: "block", "data-testid": "block", "data-package": b.key, "data-count": t.n, onclick: () => open(b.key) });
    g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, class: "blk" },
      svg("title", {}, `${b.title} · ${plural(t.n, "match", "matches")} · ${t.tp} TP · ${t.fp} FP · ${t.unclear} unclear · ${t.open} unlabeled (${t.hinted} with a hint)`)));
    const pad = Math.min(4, b.w / 10, b.h / 10), barH = Math.min(8, Math.max(3, b.h / 6)), bw = b.w - 2 * pad, by = b.y + b.h - pad - barH;
    g.append(svg("rect", { x: b.x + pad, y: by, width: Math.max(0, bw), height: barH, class: "bar-track" }));
    let off = 0;
    for (const [k, n] of [["tp", t.tp], ["fp", t.fp], ["unclear", t.unclear], ["hint", t.hinted]] as [string, number][]) {
      if (!n) continue;
      const w = (bw * n) / t.n;
      g.append(svg("rect", { x: b.x + pad + off, y: by, width: w, height: barH, class: `fill-${k}` }));
      off += w;
    }
    if (b.w > 60 && b.h > 34) {
      g.append(svg("text", { x: b.x + 5, y: b.y + 14, class: "ttl" }, clip(b.title, b.w / 7)));
      g.append(svg("text", { x: b.x + 5, y: b.y + 27, class: "sub" }, clip(`${t.n} · ${t.open} open`, b.w / 6.5)));
    } else if (b.w > 24 && b.h > 16) {
      g.append(svg("text", { x: b.x + 3, y: b.y + 11, class: "sub" }, clip(`${b.title} ${t.n}`, b.w / 6.5)));
    }
    tree.append(g);
  }
}
