// agent.ts says where an agent hint came from and where the row's research is.
import type { HintSummary } from "../gen/wire";
import type { Row } from "./rows";

// provenance says where a hint came from: the skill, and who started the research that left it
const originWords: Record<string, string> = { "label-ui": "requested in the label UI", cli: "requested with yardstick", "research-job": "requester not recorded" };
export function provenance(h: HintSummary) {
  const skill = h.skill || "an agent";
  return `✦ ${skill}${h.origin && h.origin !== "skill-run" && originWords[h.origin] ? ` · ${originWords[h.origin]}` : ""}`;
}

// researchLine says where the row's newest research job is when the "✦ researched" mark doesn't
// already: running, failed, or done after the hint shown without leaving a new one
export function researchLine(r: Row) {
  const j = r.research;
  if (!j) return "";
  if (j.status === "queued" || j.status === "running") return `⧗ research ${j.status}`;
  if (j.status === "cancelled") return "research cancelled";
  if (j.status !== "done") return `research ${j.status}${j.error ? `: ${j.error}` : ""}`;
  if (!r.hint) return "";
  const fresh = r.hint.written && j.started && new Date(r.hint.written) >= new Date(j.started);
  const when = j.finished ? ` ${new Date(j.finished).toLocaleDateString()}` : "";
  return fresh ? "" : `research${when} left no new agent hint; the one here is older`;
}
