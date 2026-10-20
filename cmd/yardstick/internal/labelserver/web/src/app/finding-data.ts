// finding-data.ts loads what a finding page shows: the gate's state (vocabulary, causes, research,
// the result), the row with everything the old tile showed of it, grype's raw matches, and the
// parent list j and k walk (a check's findings, or the gate's changed rows).
import type { CheckFindings, MatchesResponse, RowResponse, State, StateRow } from "../gen/wire";
import * as api from "../shared/api";
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

const checkFindings = (gate: string, check: string) =>
  fetch(`/api/gates/${encodeURIComponent(gate)}/checks/${encodeURIComponent(check)}/findings`).then(async (r) => {
    if (!r.ok) throw new Error(`${r.status}: ${(await r.text()).trim() || r.statusText}`);
    return r.json() as Promise<CheckFindings>;
  });

export async function loadFinding(gate: string, id: string, check: string | null, filters: Filters): Promise<FindingData> {
  const [state, detail, matches, cf] = await Promise.all([
    api.state(gate), api.row(gate, id),
    // the raw matches only draw the lanes and the Raw match tab; the page stands without them
    api.matches(gate, id).catch(() => null),
    check ? checkFindings(gate, check) : Promise.resolve(null),
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

// researching is a row's research still queued or running
export const researching = (r: StateRow) => ["queued", "running"].includes(r.research?.status ?? "");
