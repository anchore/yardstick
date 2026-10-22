// data.ts is what the /ui/gates/ screens read and write: the API calls, cached until the next write,
// and the writes the lists' actions make (labels, accepted hints) through the existing routes.
import type { CheckFindings, CrossFinding, GateLabels, GateList, LabelKey, SharedState, State, Vocabulary, claimsv1 } from "../gen/wire";
import * as api from "../shared/api";
import { toast } from "../shared/dom";
import { labels as words, plural } from "../shared/words";
import { recount } from "./historylink";
import { crossByGate, type FRow } from "./listing";

const cache = new Map<string, Promise<unknown>>();

// getJSON is a GET that skips the cache, for what must be fresh (the queue after a write)
export async function getJSON<T>(path: string): Promise<T> {
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

// fresh is a cached GET read again, for a list following research in flight
function fresh<T>(path: string): Promise<T> {
  cache.delete(path);
  return once<T>(path);
}

const g = (gate: string) => `/api/gates/${encodeURIComponent(gate)}`;

export const gateList = () => once<GateList>("/api/gates");
export const shared = () => once<SharedState>("/api/gates/shared");
export const gateState = (gate: string) => once<State>(`${g(gate)}/state`);
export const checkFindings = (gate: string, check: string) => once<CheckFindings>(`${g(gate)}/checks/${encodeURIComponent(check)}/findings`);
export const freshState = (gate: string) => fresh<State>(`${g(gate)}/state`);
export const freshFindings = (gate: string, check: string) => fresh<CheckFindings>(`${g(gate)}/checks/${encodeURIComponent(check)}/findings`);
export const freshShared = () => fresh<SharedState>("/api/gates/shared");

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

// changed is how every write that stays on its screen says so: the cache is dropped and main.ts has
// the screen refresh in place
export function changed() {
  cache.clear();
  dispatchEvent(new Event("yardstick:changed"));
}

// revert removes labels from the writable claims source, then refreshes the screen
export async function revert(labels: LabelKey[]) {
  try {
    toast(`${plural((await api.revert(labels)).removed, "label")} removed`);
    return true;
  } catch (e) {
    toast((e as Error).message, true);
    return false;
  } finally {
    void recount();
    changed();
  }
}

// written is a write's toast, with an Undo that removes the labels it wrote
export function written(text: string, labels: LabelKey[] | undefined) {
  void recount();
  toast(text, false, labels?.length ? { text: "Undo", run: () => void revert(labels) } : undefined);
}

async function write(what: (keys: LabelKey[]) => Promise<string>) {
  const keys: LabelKey[] = [];
  try {
    const text = await what(keys);
    written(text, keys);
    return true;
  } catch (e) {
    // a write across gates can fail part way, after writing some
    void recount();
    toast((e as Error).message, true);
    return false;
  } finally {
    changed();
  }
}

// acceptHints endorses the pending hints on rows of one gate: a row's own proposal, else the cause
// (package hint) it is a pending member of
export function acceptHints(gate: string, rows: FRow[]) {
  return write(async (keys) => {
    const hinted = rows.filter((r) => r.row && r.hint);
    if (!hinted.length) throw new Error("no agent hint to accept on the matches selected");
    const proposals = hinted.filter((r) => r.hint!.kind === "proposal").map((r) => r.row!);
    const causes = new Map<string, string[]>();
    const st = hinted.some((r) => r.hint!.kind === "cause" && !r.hint!.cause) ? await gateState(gate) : null;
    for (const r of hinted) {
      if (r.hint!.kind !== "cause") continue;
      const id = r.hint!.cause ?? st?.causes.find((c) => c.pending.includes(r.row!))?.id;
      if (id) causes.set(id, [...(causes.get(id) ?? []), r.row!]);
    }
    let n = 0;
    const add = (res: { written: number; labels: LabelKey[] }) => { n += res.written; keys.push(...res.labels); };
    if (proposals.length) add(await api.accept(gate, proposals));
    for (const [id, ids] of causes) add(await api.acceptCause(gate, id, ids));
    return `✦ ${plural(n, "agent hint")} accepted as your labels`;
  });
}

// labelRows writes one verdict on rows of a gate; fp and unclear carry a reason from the vocabulary
export function labelRows(gate: string, rows: string[], verdict: claimsv1.Verdict, justification = "") {
  return write(async (keys) => {
    const res = await api.labels(gate, { rows, verdict, justification, note: "", scope: "subject" });
    keys.push(...res.labels);
    return `${words[verdict].glyph} ${plural(res.written, "label")} written as ${words[verdict].word}${res.overridden?.length ? ", overriding the agent hint" : ""}`;
  });
}

// acceptCross accepts the hints on cross-gate findings, each through a gate that reports it
export function acceptCross(fs: CrossFinding[]) {
  return write(async (keys) => {
    let n = 0;
    const add = (res: { written: number; labels: LabelKey[] }) => { n += res.written; keys.push(...res.labels); };
    const withHint = fs.filter((f) => f.hint?.status === "pending");
    for (const [gate, rows] of crossByGate(withHint)) add(await api.accept(gate, rows));
    for (const f of fs.filter((x) => !withHint.includes(x) && x.cause)) {
      const a = f.in.find((x) => x.gate === f.cause!.gate);
      if (a) add(await api.acceptCause(a.gate, f.cause!.id, [a.row]));
    }
    if (!n && !withHint.length) throw new Error("no agent hint to accept on the matches selected");
    return `✦ ${plural(n, "agent hint")} accepted as your labels`;
  });
}

// labelCross labels cross-gate findings, each through a gate that reports it; the label counts in
// every gate that reports the match
export function labelCross(fs: CrossFinding[], verdict: claimsv1.Verdict, justification = "") {
  return write(async (keys) => {
    let n = 0;
    for (const [gate, rows] of crossByGate(fs)) {
      const res = await api.labels(gate, { rows, verdict, justification, note: "", scope: "subject" });
      n += res.written; keys.push(...res.labels);
    }
    return `${words[verdict].glyph} ${plural(n, "label")} written as ${words[verdict].word}`;
  });
}

// LabelOption is a "Label as…" choice: a verdict and reason, its value verdict:justification
export interface LabelOption { verdict: claimsv1.Verdict; justification: string; value: string; text: string; title?: string }

// labelOptions are the "Label as…" choices; TP needs no reason, the rest do
export function labelOptions(vocab: Vocabulary | undefined): LabelOption[] {
  const out: LabelOption[] = [{ verdict: "tp", justification: "", value: "tp:", text: "TP" }];
  for (const v of ["tp", "fp", "unclear"] as const) {
    for (const [j, desc] of Object.entries(vocab?.justifications?.[v] ?? {}).sort()) out.push({ verdict: v, justification: j, value: `${v}:${j}`, text: `${words[v].word} · ${j}`, title: desc });
  }
  return out;
}
