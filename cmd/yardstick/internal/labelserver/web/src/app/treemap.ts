// treemap.ts is the squarified treemap layout the scan-delta map draws with. Pure: no DOM.

export interface Rect { x: number; y: number; w: number; h: number }

function worstRatio(row: { area: number }[], side: number) {
  const s = row.reduce((a, i) => a + i.area, 0), mx = Math.max(...row.map((i) => i.area)), mn = Math.min(...row.map((i) => i.area));
  return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn));
}

// squarify lays items (with value) into rect, biggest first, rows along the shorter side; items
// with no value are left out
export function squarify<T extends { value: number }>(items: T[], rect: Rect): (T & Rect & { area: number })[] {
  const out: (T & Rect & { area: number })[] = [];
  let { x, y, w, h } = rect;
  const total = items.reduce((s, i) => s + i.value, 0);
  let list = items.filter((i) => i.value > 0).sort((a, b) => b.value - a.value).map((i) => ({ ...i, area: (i.value / total) * w * h }));
  while (list.length && w > 0 && h > 0) {
    const horizontal = w >= h; // the row is a column stacked left to right when wide
    const side = horizontal ? h : w;
    let row: typeof list = [], best = Infinity;
    for (const it of list) {
      const cand = [...row, it], r = worstRatio(cand, side);
      if (r <= best) { row = cand; best = r; } else break;
    }
    const rowArea = row.reduce((s, i) => s + i.area, 0), thick = rowArea / side;
    let off = 0;
    for (const it of row) {
      const len = it.area / thick;
      out.push(horizontal ? { ...it, x, y: y + off, w: thick, h: len } : { ...it, x: x + off, y, w: len, h: thick });
      off += len;
    }
    if (horizontal) { x += thick; w -= thick; } else { y += thick; h -= thick; }
    list = list.slice(row.length);
  }
  return out;
}
