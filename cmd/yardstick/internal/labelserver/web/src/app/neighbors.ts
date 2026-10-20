// neighbors.ts is the list a finding page walks with j and k: the parent table's rows in its order,
// under the filters the URL carries, filtered the way the table filters them. Pure: finding-data.ts
// fetches, this decides.
import type { Finding, State } from "../gen/wire";
import { hinted, pkgOf } from "../shared/rows";
import type { Filters } from "./route";
import { filterRows } from "./table";

// Item is one finding in the list: its row and whether it's still open to labeling
export interface Item { id: string; open: boolean }

// Candidate is a parent table's row as its filters see it; id is absent for an unmet expectation,
// which the table lists but no finding page shows
interface Candidate { id?: string; image: string; verdict: string; hinted: boolean; text: string }

// open is unlabeled or unclear: unclear doesn't judge a row
const open = (verdict: string) => verdict === "unlabeled" || verdict === "unclear";

// filtered keeps what the image, verdict, hint and search filters keep, in the table's order
export function filtered(cs: Candidate[], f: Filters): Item[] {
  const kept = cs.filter((c) => (!f.image || c.image === f.image) && (!f.verdict || c.verdict === f.verdict) && (f.hint !== "yes" || c.hinted));
  return filterRows(kept, f.q ?? "", (c) => c.text).flatMap((c) => (c.id ? [{ id: c.id, open: open(c.verdict) }] : []));
}

// fromCheck is a check's findings (GET checks/{check}/findings) as its table lists them
export const fromCheck = (findings: Finding[], f: Filters): Item[] =>
  filtered(findings.map((x) => ({
    id: x.row, image: x.image.slug, verdict: x.label?.verdict ?? "unlabeled", hinted: !!x.hint,
    text: `${x.vulnerability} ${x.package.name} ${x.package.version ?? ""} ${x.image.name}`,
  })), f);

// fromState is the gate's Findings tab: every changed row in report order. A row is hinted with a
// pending hint of its own or as a pending member of a cause, as the server's tallies count it.
export function fromState(s: State, f: Filters): Item[] {
  const pending = new Set((s.causes ?? []).flatMap((c) => c.pending));
  return filtered(s.subjects.flatMap((sub) => sub.rows.filter((r) => r.inCandidate !== r.inReference).map((r) => {
    const p = pkgOf(r.package.ref);
    return { id: r.id, image: sub.slug, verdict: r.verdict, hinted: hinted(r) || (open(r.verdict) && pending.has(r.id)), text: `${r.vulnerability} ${p.name} ${p.version} ${sub.name}` };
  })), f);
}

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
