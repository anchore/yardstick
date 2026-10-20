// neighbors.ts is the list a finding page walks with j and k: the parent table's rows in its order,
// under the filters the URL carries. The rows and the filter are the table's own (listing.ts), so
// the two can't disagree. Pure: finding-data.ts fetches, this decides.
import type { CheckFindings, State } from "../gen/wire";
import { checkRows, gateRows, isOpen, shownRows, type FRow } from "./listing";
import type { Filters } from "./route";

// Item is one finding in the list: its row and whether it's still open to labeling
export interface Item { id: string; open: boolean }

// items are the rows with a finding page; an unmet expectation no match pairs has none
const items = (rows: FRow[]): Item[] => rows.flatMap((r) => (r.row ? [{ id: r.row, open: isOpen(r) }] : []));

// image is the URL's image when the gate has it, as the table takes it
const image = (s: State, f: Filters) => (f.image && s.subjects.some((x) => x.slug === f.image) ? f.image : null);

// fromCheck is a check's findings (GET checks/{check}/findings) as its table lists them
export const fromCheck = (cf: CheckFindings, s: State, f: Filters): Item[] => items(shownRows(checkRows(cf), f, image(s, f)));

// fromState is the gate's Findings tab: every changed row in report order
export const fromState = (s: State, f: Filters): Item[] => items(shownRows(gateRows(s), f, image(s, f)));

// position is where a row sits in the list (index -1 when the filters leave it out) and the rows
// j and k go to; off the list, j goes to the first and k to the last
export function position(items: Item[], id: string) {
  const i = items.findIndex((x) => x.id === id);
  return {
    index: i, total: items.length,
    prev: i < 0 ? items.at(-1)?.id : items[i - 1]?.id,
    next: i < 0 ? items[0]?.id : items[i + 1]?.id,
  };
}

// nextOpen is the next open row after this one, wrapping round, skipping the rows just labeled
export function nextOpen(items: Item[], id: string, done: string[] = []): string | undefined {
  const i = items.findIndex((x) => x.id === id);
  const ring = i < 0 ? items : [...items.slice(i + 1), ...items.slice(0, i)];
  return ring.find((x) => x.open && x.id !== id && !done.includes(x.id))?.id;
}
