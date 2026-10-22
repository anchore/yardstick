// api.ts is the label server's HTTP API as the UI uses it: every endpoint, typed against the
// server's generated wire types, with path segments encoded and the write token sent on each POST.
// data.ts caches the reads the screens share on top of it. A read takes the view's AbortSignal
// where its caller has one.
import type {
  AcceptCauseResponse, AcceptResponse, CancelResponse, CheckFindings, GateLabels, GateList, GateResult, HintsAcceptResponse, HintsResponse, History,
  LabelKey, LabelsRequest, LabelsResponse, MatchesResponse, Queue, ResearchBatch, ResearchFrom, ResearchJobs, ResearchQueueRequest,
  ResearchQueueResponse, ResearchResponse, RevertResponse, RowResponse, SharedState, State, WriteError, claimsv1,
} from "../gen/wire";

export const token = document.querySelector<HTMLMetaElement>('meta[name="yardstick-token"]')?.content ?? "";

// ApiError is a request the server refused. labels are what a write placed before it failed (the
// server's WriteError), which an Undo can still take back.
export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly labels: LabelKey[] = []) {
    super(`${status}: ${message}`);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) {
    if (r.headers.get("Content-Type")?.startsWith("application/json")) {
      const e = (await r.json()) as WriteError;
      throw new ApiError(r.status, e.error, e.labels ?? []);
    }
    throw new ApiError(r.status, (await r.text()).trim() || r.statusText);
  }
  return r.json() as Promise<T>;
}

const get = <T>(path: string, signal?: AbortSignal) => call<T>(path, { signal });
const post = <T>(path: string, body: unknown) => call<T>(path, {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-Yardstick-Token": token },
  body: JSON.stringify(body),
});

const seg = encodeURIComponent;
const gatePath = (gate: string, path = "") => `/api/gates/${seg(gate)}${path}`;
// query is a query string from the values set, "" when none is
function query(q: object) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v != null && v !== "" && v !== false) p.set(k, v === true ? "1" : String(v));
  return p.size ? `?${p}` : "";
}

// ---------- reads ----------

export const gates = (signal?: AbortSignal) => get<GateList>("/api/gates", signal);
export const shared = (signal?: AbortSignal) => get<SharedState>("/api/gates/shared", signal);
export const state = (gate: string, signal?: AbortSignal) => get<State>(gatePath(gate, "/state"), signal);
export const checkFindings = (gate: string, check: string, signal?: AbortSignal) => get<CheckFindings>(gatePath(gate, `/checks/${seg(check)}/findings`), signal);

export interface LabelQuery { verdict?: string; image?: string; q?: string; offset?: number; limit?: number }
export const gateLabels = (gate: string, q: LabelQuery = {}, signal?: AbortSignal) => get<GateLabels>(gatePath(gate, `/labels${query(q)}`), signal);

export const row = (gate: string, id: string, signal?: AbortSignal) => get<RowResponse>(gatePath(gate, `/rows/${seg(id)}`), signal);
export const matches = (gate: string, id: string, signal?: AbortSignal) => get<MatchesResponse>(gatePath(gate, `/rows/${seg(id)}/matches`), signal);

// hints is every pending hint, unclear included; the pages filter. Never cached: a hint is gone
// once accepted anywhere.
export const hints = (signal?: AbortSignal) => get<HintsResponse>("/api/hints?low=1", signal);
// queue is the open rows across gates in a scope (all, gate:<g>, image:<slug>), unclear hints kept with low
export const queue = (scope: string, low: boolean, signal?: AbortSignal) => get<Queue>(`/api/queue${query({ scope, low })}`, signal);

// history is the labels in the writable claims source; since is start (the server's), a time, or
// left out for all time
export interface HistoryQuery { since?: string; verdict?: string; q?: string; offset?: number; limit?: number }
export const history = (q: HistoryQuery, signal?: AbortSignal) => get<History>(`/api/history${query(q)}`, signal);

// preview is a gate's result as if rows were labeled so; nothing is written
export const preview = (gate: string, labels: Record<string, claimsv1.Verdict>) => post<GateResult>(gatePath(gate, "/preview"), { labels });

// every research job, newest first, and where the work in flight stands; the newest batch's
// progress (null when none ever ran)
export const researchJobs = (signal?: AbortSignal) => get<ResearchJobs>("/api/research/jobs", signal);
export const researchBatch = (signal?: AbortSignal) => get<ResearchBatch | null>("/api/research/batch", signal);

// ---------- writes ----------

export const labels = (gate: string, body: LabelsRequest) => post<LabelsResponse>(gatePath(gate, "/labels"), body);
export const accept = (gate: string, rows: string[]) => post<AcceptResponse>(gatePath(gate, "/accept"), { rows });
export const acceptCause = (gate: string, cause: string, rows: string[]) =>
  post<AcceptCauseResponse>(gatePath(gate, `/package-hints/${seg(cause)}/accept`), { rows });
export const acceptHints = (hints: string[]) => post<HintsAcceptResponse>("/api/hints/accept", { hints });
// revert takes back a write's labels: a key with a prior puts that label back, one without is
// removed (history's Remove sends keys with none)
export const revert = (labels: LabelKey[]) => post<RevertResponse>("/api/history/revert", { labels });

// research starts jobs on rows of one gate, from a table or a match
export const research = (gate: string, rows: string[], from: ResearchFrom) => post<ResearchResponse>(gatePath(gate, "/research"), { rows, from });
// cancelResearch cancels the newest research job on each row, when this server holds it
export const cancelResearch = (gate: string, rows: string[]) => post<CancelResponse>(gatePath(gate, "/research/cancel"), { rows });

// the research queue across gates: planResearch prices a batch and starts nothing, startResearch
// spends money, so the two never share a call
type QueueBody = Omit<ResearchQueueRequest, "dryRun">;
export const planResearch = (body: QueueBody) => post<ResearchQueueResponse>("/api/research", { ...body, dryRun: true });
export const startResearch = (body: QueueBody) => post<ResearchQueueResponse>("/api/research", body);
// cancelBatch cancels the rest of a batch
export const cancelBatch = (id: string) => post<CancelResponse>("/api/research/batch/cancel", { id });
