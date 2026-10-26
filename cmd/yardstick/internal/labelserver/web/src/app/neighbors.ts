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

// fromState is the gate's Findings tab: every changed row, by effect then report order
export const fromState = (s: State, f: Filters): Item[] => items(shownRows(gateRows(s), f, image(s, f)));

// position is where a row sits among the rows j and k walk and the rows either side of it they go
// to. j and k walk the open rows (all is ⌥j and ⌥k, every row); a list with nothing open, such as
// one filtered to TP, walks every row. index is -1 for a row not walked (labeled, or filtered out);
// from a labeled row j and k go to the nearest open rows, and off the list to the first and last.
export function position(items: Item[], id: string, all = false) {
  const open = !all && items.some((x) => x.open);
  const walked = (xs: Item[]) => (open ? xs.filter((x) => x.open) : xs);
  const at = items.findIndex((x) => x.id === id), list = walked(items);
  return {
    index: list.findIndex((x) => x.id === id), total: list.length, open,
    prev: (at < 0 ? list : walked(items.slice(0, at))).at(-1)?.id,
    next: (at < 0 ? list : walked(items.slice(at + 1)))[0]?.id,
  };
}

// nextOpen is the next open row after this one, wrapping round, skipping the rows just labeled
export function nextOpen(items: Item[], id: string, done: string[] = []): string | undefined {
  const i = items.findIndex((x) => x.id === id);
  const ring = i < 0 ? items : [...items.slice(i + 1), ...items.slice(0, i)];
  return ring.find((x) => x.open && x.id !== id && !done.includes(x.id))?.id;
}
