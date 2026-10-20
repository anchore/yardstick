// data.ts is what the /ui/gates/ screens read and write: the API calls, cached until the next write,
// and the writes the lists' actions make (labels, accepted hints) through the existing routes.
import type { CheckFindings, CrossFinding, GateLabels, GateList, SharedState, State, Vocabulary } from "../gen/wire";
import * as api from "../shared/api";
import { toast } from "../shared/dom";
import { labels as words, plural } from "../shared/words";
import { crossByGate, type FRow } from "./listing";

const cache = new Map<string, Promise<unknown>>();

async function getJSON<T>(path: string): Promise<T> {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${r.status}: ${(await r.text()).trim() || r.statusText}`);
  return r.json() as Promise<T>;
}

// once is a GET, shared by every screen until a write clears the cache; a failure is not kept
function once<T>(path: string): Promise<T> {
  let p = cache.get(path) as Promise<T> | undefined;
  if (!p) {
    p = getJSON<T>(path);
    cache.set(path, p);
    p.catch(() => cache.delete(path));
  }
  return p;
}

// forget drops every cached GET, for a write made outside this module (the finding page's)
export const forget = () => cache.clear();

const g = (gate: string) => `/api/gates/${encodeURIComponent(gate)}`;

export const gateList = () => once<GateList>("/api/gates");
export const shared = () => once<SharedState>("/api/gates/shared");
export const gateState = (gate: string) => once<State>(`${g(gate)}/state`);
export const checkFindings = (gate: string, check: string) => once<CheckFindings>(`${g(gate)}/checks/${encodeURIComponent(check)}/findings`);

export interface LabelQuery { verdict?: string; image?: string; q?: string; offset?: number; limit?: number }
export function gateLabels(gate: string, q: LabelQuery = {}) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v != null && v !== "") p.set(k, String(v));
  return once<GateLabels>(`${g(gate)}/labels${p.size ? `?${p}` : ""}`);
}

// everyLabel is every gate's labels, unpaged, for the workspace-wide Labels tab
export async function everyLabel() {
  const gates = (await gateList()).gates.filter((x) => !x.error);
  return Promise.all(gates.map(async (x) => ({ gate: x.id, labels: (await gateLabels(x.id, { limit: 1_000_000 })).labels })));
}

// ---------- writes ----------

async function write(what: () => Promise<string>) {
  try {
    const text = await what();
    cache.clear();
    toast(text);
    return true;
  } catch (e) {
    cache.clear();
    toast((e as Error).message, true);
    return false;
  }
}

// acceptHints endorses the pending hints on rows of one gate: a row's own proposal, else the cause
// (package hint) it is a pending member of
export function acceptHints(gate: string, rows: FRow[]) {
  return write(async () => {
    const hinted = rows.filter((r) => r.row && r.hint);
    if (!hinted.length) throw new Error("no agent hint to accept on the rows selected");
    const proposals = hinted.filter((r) => r.hint!.kind === "proposal").map((r) => r.row!);
    const causes = new Map<string, string[]>();
    const st = hinted.some((r) => r.hint!.kind === "cause" && !r.hint!.cause) ? await gateState(gate) : null;
    for (const r of hinted) {
      if (r.hint!.kind !== "cause") continue;
      const id = r.hint!.cause ?? st?.causes.find((c) => c.pending.includes(r.row!))?.id;
      if (id) causes.set(id, [...(causes.get(id) ?? []), r.row!]);
    }
    let n = proposals.length ? (await api.accept(gate, proposals)).written : 0;
    for (const [id, ids] of causes) n += (await api.acceptCause(gate, id, ids)).written;
    return `✦ ${plural(n, "agent hint")} accepted as your labels`;
  });
}

// labelRows writes one verdict on rows of a gate; fp and unclear carry a reason from the vocabulary
export function labelRows(gate: string, rows: string[], verdict: string, justification = "") {
  return write(async () => {
    const res = await api.labels(gate, { rows, verdict, justification, note: "", scope: "subject" });
    return `${words[verdict].glyph} ${plural(res.written, "label")} written as ${words[verdict].word}${res.overridden?.length ? ", overriding the agent hint" : ""}`;
  });
}

// acceptCross accepts the hints on cross-gate findings, each through a gate that reports it
export function acceptCross(fs: CrossFinding[]) {
  return write(async () => {
    let n = 0;
    const withHint = fs.filter((f) => f.hint?.status === "pending");
    for (const [gate, rows] of crossByGate(withHint)) n += (await api.accept(gate, rows)).written;
    for (const f of fs.filter((x) => !withHint.includes(x) && x.cause)) {
      const a = f.in.find((x) => x.gate === f.cause!.gate);
      if (a) n += (await api.acceptCause(a.gate, f.cause!.id, [a.row])).written;
    }
    if (!n && !withHint.length) throw new Error("no agent hint to accept on the findings selected");
    return `✦ ${plural(n, "agent hint")} accepted as your labels`;
  });
}

// labelCross labels cross-gate findings, each through a gate that reports it; the label counts in
// every gate that reports the match
export function labelCross(fs: CrossFinding[], verdict: string, justification = "") {
  return write(async () => {
    let n = 0;
    for (const [gate, rows] of crossByGate(fs)) n += (await api.labels(gate, { rows, verdict, justification, note: "", scope: "subject" })).written;
    return `${words[verdict].glyph} ${plural(n, "label")} written as ${words[verdict].word}`;
  });
}

// labelOptions are "Label as…" choices, verdict:justification; TP needs no reason, the rest do
export function labelOptions(vocab: Vocabulary | undefined): { value: string; text: string; title?: string }[] {
  const out: { value: string; text: string; title?: string }[] = [{ value: "tp:", text: "TP" }];
  for (const v of ["tp", "fp", "unclear"]) {
    for (const [j, desc] of Object.entries(vocab?.justifications?.[v] ?? {}).sort()) out.push({ value: `${v}:${j}`, text: `${words[v].word} · ${j}`, title: desc });
  }
  return out;
}
