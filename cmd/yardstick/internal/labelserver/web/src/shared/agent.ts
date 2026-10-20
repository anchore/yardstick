// agent.ts says where an agent hint came from and where the row's research is: the words and
// glyphs the tables' Agent hint cell, the finding page and hint review share.
import type { HintSummary, ResearchSummary } from "../gen/wire";
import type { Row } from "./rows";

// provenance says where a hint came from: the skill, and who started the research that left it
const originWords: Record<string, string> = { "label-ui": "requested in the label UI", cli: "requested with yardstick", "research-job": "requester not recorded" };
export function provenance(h: HintSummary) {
  const skill = h.skill || "an agent";
  return `✦ ${skill}${h.origin && h.origin !== "skill-run" && originWords[h.origin] ? ` · ${originWords[h.origin]}` : ""}`;
}

// inFlight is a research job still queued or running
export const inFlight = (j: { status: string } | undefined | null) => j?.status === "queued" || j?.status === "running";

// failedJob is a job that stopped without finishing: failed, timed out or interrupted
export const failedJob = (j: { status: string } | undefined | null) => j?.status === "failed" || j?.status === "timed-out" || j?.status === "interrupted";

// ordinal is 1st, 2nd, 3rd, 4th, 11th, 22nd
export function ordinal(n: number) {
  const t = n % 100, s = t >= 11 && t <= 13 ? "th" : ["th", "st", "nd", "rd"][n % 10] ?? "th";
  return `${n}${s}`;
}

// clock is a duration as a stopwatch reads it: 0:41, 12:05, 1:02:09
export function clock(ms: number) {
  const s = Math.max(0, Math.floor(ms / 1000)), h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = String(s % 60).padStart(2, "0");
  return h ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

// since is the stopwatch from an ISO time to now
export const since = (iso: string | undefined, now = Date.now()) => (iso ? clock(now - Date.parse(iso)) : "");

// queuePlace is a queued job's place in line, "1st of 13", or nothing when this server isn't holding it
export const queuePlace = (j: ResearchSummary) => (j.position ? `${ordinal(j.position)} of ${j.queueLength ?? j.position}` : "");

const modelName = (m: string | undefined) => (m ? m[0].toUpperCase() + m.slice(1) : "");

// Doing is what research is doing on a row with no hint showing, as one cell: researching (counting
// up from start), queued (its place in line), failed (the error on hover), researched with no hint,
// or nothing yet (offer, a Research button on an open row). none is a row there is nothing to say
// about: labeled, or research can't be offered.
export interface Doing {
  kind: "running" | "queued" | "failed" | "nohint" | "offer" | "none";
  word: string;
  small?: string;      // the time running or the place in line
  since?: string;      // when running started, for the cell to count up from
  title?: string;      // on hover: the batch and model, or the error
}

export function doing(j: ResearchSummary | undefined, o: { open: boolean; researched: boolean }, now = Date.now()): Doing {
  const on = j && [j.batch && `batch ${j.batch.slice(0, 8)}`, modelName(j.model)].filter(Boolean).join(" · ");
  if (j?.status === "running") return { kind: "running", word: "researching", small: since(j.started, now), since: j.started, title: on || undefined };
  if (j?.status === "queued") return { kind: "queued", word: "queued", small: queuePlace(j), title: on || undefined };
  if (!o.open) return { kind: "none", word: "" };
  if (failedJob(j)) return { kind: "failed", word: "failed", title: j!.error || j!.status };
  if (o.researched || j?.status === "done") return { kind: "nohint", word: "researched, no hint" };
  return { kind: "offer", word: "Research" };
}

// researchLine says where the row's newest research job is when the "✦ researched" mark doesn't
// already: in the table's words while queued or running, failed, or done after the hint shown
// without leaving a new one
export function researchLine(r: Row, now = Date.now()) {
  const j = r.research;
  if (!j) return "";
  if (inFlight(j)) {
    const d = doing(j, { open: true, researched: false }, now);
    return [d.word, [d.small, j.status === "running" && modelName(j.model)].filter(Boolean).join(" · ")].filter(Boolean).join(" ");
  }
  if (j.status === "cancelled") return "research cancelled";
  if (j.status !== "done") return `research ${j.status}${j.error ? `: ${j.error}` : ""}`;
  if (!r.hint) return "";
  const fresh = r.hint.written && j.started && new Date(r.hint.written) >= new Date(j.started);
  const when = j.finished ? ` ${new Date(j.finished).toLocaleDateString()}` : "";
  return fresh ? "" : `research${when} left no new agent hint; the one here is older`;
}

// jobHref is a job's row on the jobs page
export const jobHref = (id: string) => `/ui/research/jobs#job-${id}`;
