// api.ts is the write token and the per-gate API calls the finding page and the lists' writes
// make, typed against the server's generated wire types.
import type {
  AcceptCauseResponse, AcceptResponse, CancelResponse, LabelKey, LabelsRequest, LabelsResponse, MatchesResponse, ResearchBatch, ResearchQueueRequest,
  ResearchQueueResponse, ResearchRequest, ResearchResponse, RevertResponse, RowResponse, State,
} from "../gen/wire";

export const token = document.querySelector<HTMLMetaElement>('meta[name="yardstick-token"]')?.content ?? "";

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text()).trim() || r.statusText}`);
  return r.json() as Promise<T>;
}
const gatePath = (gate: string, path: string) => `/api/gates/${encodeURIComponent(gate)}${path}`;
const get = <T>(gate: string, path: string) => call<T>(gatePath(gate, path));
const postTo = <T>(path: string, body: unknown) => call<T>(path, {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Yardstick-Token": token },
  body: JSON.stringify(body),
});
const post = <T>(gate: string, path: string, body: unknown) => postTo<T>(gatePath(gate, path), body);

export const state = (gate: string) => get<State>(gate, "/state");
export const row = (gate: string, id: string) => get<RowResponse>(gate, `/rows/${id}`);
export const matches = (gate: string, id: string) => get<MatchesResponse>(gate, `/rows/${id}/matches`);
export const labels = (gate: string, body: LabelsRequest) => post<LabelsResponse>(gate, "/labels", body);
export const accept = (gate: string, rows: string[]) => post<AcceptResponse>(gate, "/accept", { rows });
export const acceptCause = (gate: string, cause: string, rows: string[]) =>
  post<AcceptCauseResponse>(gate, `/package-hints/${encodeURIComponent(cause)}/accept`, { rows });
// research takes rows, or a selection the server resolves (ResearchRequest's rows are then left out)
export const research = (gate: string, body: Partial<ResearchRequest>) => post<ResearchResponse>(gate, "/research", body);
// revert removes labels from the writable claims source: a write's labels undo it
export const revert = (labels: LabelKey[]) => postTo<RevertResponse>("/api/history/revert", { labels });

// the research queue across gates: plan (dryRun) or start a batch, the newest batch's progress (null
// when none ever ran), and cancelling the rest of one
export const researchQueue = (body: ResearchQueueRequest) => postTo<ResearchQueueResponse>("/api/research", body);
export const researchBatch = () => call<ResearchBatch | null>("/api/research/batch");
export const cancelBatch = (id: string) => postTo<CancelResponse>("/api/research/batch/cancel", { id });
