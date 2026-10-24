// finding-data.ts loads what a finding page shows: the gate's state (vocabulary, causes, research,
// the result), the row with everything the old tile showed of it, grype's raw matches, and the
// parent list j and k walk (a check's findings, or the gate's changed rows).
import type { MatchesResponse, RowResponse, State, StateRow } from "../gen/wire";
import * as api from "../shared/api";
import { checkFindings, freshFindings, freshState, gateState } from "./data";
import { fromCheck, fromState, type Item } from "./neighbors";
import type { Filters } from "./route";

export interface FindingData {
  state: State;
  detail: RowResponse;
  row: StateRow;
  matches: MatchesResponse | null;   // null when grype's raw matches could not be read
  list: Item[];
  checkEffect?: string;              // decides, could-move or counted, on a check route
  image: { name: string; slug: string; ref: string };
}

// loadFinding reads the page's data: the gate's state and the check's list from data.ts's cache (a
// write clears it; fresh reads them again, for research in flight), the row itself every time, and
// the raw matches as the view read them once, since a run's raw matches never change
export async function loadFinding(gate: string, id: string, check: string | null, filters: Filters, raw: Promise<MatchesResponse | null>, o: { signal?: AbortSignal; fresh?: boolean } = {}): Promise<FindingData> {
  const [state, detail, matches, cf] = await Promise.all([
    o.fresh ? freshState(gate) : gateState(gate), api.row(gate, id, o.signal), raw,
    check ? (o.fresh ? freshFindings : checkFindings)(gate, check) : Promise.resolve(null),
  ]);
  const si = state.subjects.findIndex((s) => s.rows.some((r) => r.id === id));
  const sub = state.subjects[si] ?? state.subjects[0];
  return {
    state, detail, matches,
    // the state's row carries what the lists do (the gate effect); the row endpoint's the same fields
    row: sub?.rows.find((r) => r.id === id) ?? detail.row,
    list: cf ? fromCheck(cf, state, filters) : fromState(state, filters),
    checkEffect: cf?.findings.find((f) => f.row === id)?.effect,
    image: { name: sub?.name ?? "", slug: sub?.slug ?? "", ref: detail.subject.replace(/^(oci|docker|registry):/, "") },
  };
}
