// api.ts is what the map pages share: the write token, where the page is (which gate), and the
// API calls, typed against the server's generated wire types. Ported from delta, where it was
// shared by several UIs.
import type {
  AcceptCauseResponse, AcceptResponse, CancelResponse, GateResult, LabelsRequest, LabelsResponse, MatchesResponse,
  ResearchRequest, ResearchResponse, RowResponse, SharedState, State, claimsv1,
} from "../gen/wire";

export const token = document.querySelector<HTMLMetaElement>('meta[name="yardstick-token"]')?.content ?? "";

// where: the UI and gate from the path, /ui/<name>/gates/<gate>/<rest>
export function where() {
  const m = location.pathname.match(/^\/ui\/([^/]+)\/gates\/([^/]+)\/?(.*)$/);
  const ui = m?.[1] || location.pathname.match(/^\/ui\/([^/]+)\//)?.[1] || "queue";
  return { ui, gate: m ? decodeURIComponent(m[2]) : null, rest: m?.[3] || "" };
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text()).trim() || r.statusText}`);
  return r.json() as Promise<T>;
}
const gatePath = (gate: string, path: string) => `/api/gates/${encodeURIComponent(gate)}${path}`;
const get = <T>(gate: string, path: string) => call<T>(gatePath(gate, path));
const post = <T>(gate: string, path: string, body: unknown) => call<T>(gatePath(gate, path), {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Yardstick-Token": token },
  body: JSON.stringify(body),
});

export const shared = () => call<SharedState>("/api/gates/shared");
export const state = (gate: string) => get<State>(gate, "/state");
export const row = (gate: string, id: string) => get<RowResponse>(gate, `/rows/${id}`);
export const matches = (gate: string, id: string) => get<MatchesResponse>(gate, `/rows/${id}/matches`);
export const labels = (gate: string, body: LabelsRequest) => post<LabelsResponse>(gate, "/labels", body);
export const accept = (gate: string, rows: string[]) => post<AcceptResponse>(gate, "/accept", { rows });
export const acceptCause = (gate: string, cause: string, rows: string[]) =>
  post<AcceptCauseResponse>(gate, `/package-hints/${encodeURIComponent(cause)}/accept`, { rows });
// preview is the gate as if these rows had these labels; it writes nothing
export const preview = (gate: string, labelsByRow: Record<string, claimsv1.Verdict>) => post<GateResult>(gate, "/preview", { labels: labelsByRow });
// research takes rows, or a selection the server resolves (ResearchRequest's rows are then left out)
export const research = (gate: string, body: Partial<ResearchRequest>) => post<ResearchResponse>(gate, "/research", body);
export const cancelResearch = (gate: string, rows: string[]) => post<CancelResponse>(gate, "/research/cancel", { rows });
