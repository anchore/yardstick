// agent.ts says where an agent hint came from and where the row's research is: the words and
// glyphs the tables' Agent hint cell, the finding page and hint review share.
import type { HintSummary, ResearchDetail, ResearchSummary, research } from "../gen/wire";
import type { Row } from "./rows";
import { cap } from "./words";

// provenance says where a hint came from: the skill, and who started the research that left it
const originWords: Record<string, string> = { "label-ui": "requested in the label UI", cli: "requested with yardstick", "research-job": "requester not recorded" };
export function provenance(h: HintSummary) {
  const skill = h.skill || "an agent";
  return `✦ ${skill}${h.origin && h.origin !== "skill-run" && originWords[h.origin] ? ` · ${originWords[h.origin]}` : ""}`;
}

// inFlight is a research job still queued or running
export const inFlight = (j: { status: research.Status } | undefined | null) => j?.status === "queued" || j?.status === "running";

// failedJob is a job that stopped without finishing: failed, timed out or interrupted
export const failedJob = (j: { status: research.Status } | undefined | null) => j?.status === "failed" || j?.status === "timed-out" || j?.status === "interrupted";

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

const modelName = (m: string | undefined) => cap(m ?? "");

// Doing is what research is doing on a row with no hint showing, as one cell: researching (counting
// up from start), queued (its place in line), failed (the error on hover), researched but nothing
// recorded (why on hover), researched with no hint, or nothing yet (offer, a Research button on an
// open row). none is a row there is nothing to say
// about: labeled, or research can't be offered.
export interface Doing {
  kind: "running" | "queued" | "failed" | "notrecorded" | "nohint" | "offer" | "none";
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
  // the newest job is the one to say: an earlier run that recorded nothing is no reason now
  if (j?.status === "not-recorded") return { kind: "notrecorded", word: "researched, not recorded", title: j.error || undefined };
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
  // the finding page's research section says what it concluded and why nothing was recorded
  if (j.status === "not-recorded") return "";
  if (j.status !== "done") return `research ${j.status}${j.error ? `: ${j.error}` : ""}`;
  if (!r.hint) return "";
  const fresh = r.hint.written && j.started && new Date(r.hint.written) >= new Date(j.started);
  const when = j.finished ? ` ${new Date(j.finished).toLocaleDateString()}` : "";
  return fresh ? "" : `research${when} left no new agent hint; the one here is older`;
}

// jobHref is a job's row on the jobs page
export const jobHref = (id: string) => `/ui/research/jobs#job-${id}`;

// Outcome is what the finding page's research section says of the row's newest job: a head line
// (when, on what, for how much) and what came of it. recorded left the hint the page shows;
// notrecorded concluded but nothing was recorded, nothing ran without writing a conclusion, and
// both say why; running, failed and cancelled are the job's own state.
export interface Outcome {
  kind: "running" | "recorded" | "notrecorded" | "nothing" | "failed" | "cancelled";
  head: string;
  text: string;
}

// stamp is when a job ran, as the section heads it: "Oct 28, 21:35"
const stamp = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

export function researchOutcome(j: ResearchSummary, d: ResearchDetail | undefined, when: (iso: string) => string = stamp, now = Date.now()): Outcome {
  const at = j.finished || j.started || j.queued;
  const head = [`${inFlight(j) ? "Researching" : "Researched"}${at && !inFlight(j) ? ` ${when(at)}` : ""}`, modelName(j.model), j.costUSD ? `$${j.costUSD.toFixed(2)}` : ""]
    .filter(Boolean).join(" · ");
  if (inFlight(j)) {
    const w = doing(j, { open: true, researched: false }, now);
    return { kind: "running", head, text: [w.word, w.small].filter(Boolean).join(" ") };
  }
  if (failedJob(j)) return { kind: "failed", head, text: `Research ${j.status === "failed" ? "failed" : j.status.replace("-", " ")}${j.error ? `: ${j.error}` : "."}` };
  if (j.status === "cancelled") return { kind: "cancelled", head, text: "Research was cancelled before it finished." };
  const why = j.error || "the agent ended without proposing";
  if (j.status === "not-recorded") {
    const p = d?.output?.proposal;
    return p
      ? { kind: "notrecorded", head, text: `Research concluded ${[p.verdict, p.justification, p.confidence].filter(Boolean).join(" · ")} but it wasn't recorded: ${why}` }
      : { kind: "nothing", head, text: `Research ran but wrote no result: ${why}` };
  }
  return { kind: "recorded", head, text: "Recorded as an agent hint." };
}
