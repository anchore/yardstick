// data.ts is what the /ui/gates/ screens read and write: the API's reads (shared/api.ts), cached
// until the next write, and the writes the lists' actions make (labels, accepted hints).
import type { CrossFinding, LabelKey, RevertResponse, Vocabulary, claimsv1 } from "../gen/wire";
import * as api from "../shared/api";
import { toast } from "../shared/dom";
import { labels as words, plural } from "../shared/words";
import { recount } from "./historylink";
import { crossByGate, type FRow } from "./listing";

const cache = new Map<string, Promise<unknown>>();

// once is a read, shared by every screen until a write clears the cache; a failure is not kept
function once<T>(key: string, read: () => Promise<T>): Promise<T> {
  let p = cache.get(key) as Promise<T> | undefined;
  if (!p) {
    p = read();
    cache.set(key, p);
    p.catch(() => cache.delete(key));
  }
  return p;
}

// forget drops every cached read, for a write that leaves its screen (the finding page's, which
// goes on to the next match)
export const forget = () => cache.clear();

// fresh is a cached read made again, for a list following research in flight
function fresh<T>(key: string, read: () => Promise<T>): Promise<T> {
  cache.delete(key);
  return once(key, read);
}

export const gateList = () => once("gates", () => api.gates());
export const shared = () => once("shared", () => api.shared());
export const gateState = (gate: string) => once(`state|${gate}`, () => api.state(gate));
export const checkFindings = (gate: string, check: string) => once(`findings|${gate}|${check}`, () => api.checkFindings(gate, check));
export const freshState = (gate: string) => fresh(`state|${gate}`, () => api.state(gate));
export const freshFindings = (gate: string, check: string) => fresh(`findings|${gate}|${check}`, () => api.checkFindings(gate, check));
export const freshShared = () => fresh("shared", () => api.shared());
export const gateLabels = (gate: string, q: api.LabelQuery = {}) => once(`labels|${gate}|${JSON.stringify(q)}`, () => api.gateLabels(gate, q));

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

// revertWords says what a revert did: the labels it took out, and the ones a write had replaced
// that it put back
export function revertWords(res: RevertResponse) {
  const removed = res.removed && `${plural(res.removed, "label")} removed`;
  const back = res.restored && `${plural(res.restored, "earlier label")} put back`;
  return [removed, back].filter(Boolean).join(", ") || "nothing to undo";
}

// revert takes labels back out of the writable claims source, then refreshes the screen. A write's
// keys carry the label each replaced, which revert puts back rather than leaving the match unlabeled
export async function revert(labels: LabelKey[]) {
  try {
    toast(revertWords(await api.revert(labels)));
    return true;
  } catch (e) {
    toast((e as Error).message, true);
    return false;
  } finally {
    void recount();
    changed();
  }
}

// written is a write's toast, with an Undo that takes back the labels it wrote
export function written(text: string, labels: LabelKey[] | undefined) {
  void recount();
  toast(text, false, labels?.length ? { text: "Undo", run: () => void revert(labels) } : undefined);
}

// writeFailed is a write's error toast. Labels that landed before it failed (landed, from earlier
// calls of a write across gates, and the server's WriteError) are said, with an Undo for them.
export function writeFailed(e: unknown, landed: LabelKey[] = []) {
  const keys = [...landed, ...(e instanceof api.ApiError ? e.labels : [])];
  void recount();
  if (!keys.length) return toast((e as Error).message, true);
  toast(`${(e as Error).message}; ${plural(keys.length, "label")} written before it failed`, true, { text: "Undo", run: () => void revert(keys) });
}

async function write(what: (keys: LabelKey[]) => Promise<string>) {
  const keys: LabelKey[] = [];
  try {
    const text = await what(keys);
    written(text, keys);
    return true;
  } catch (e) {
    // a write across gates can fail part way, after writing some
    writeFailed(e, keys);
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
