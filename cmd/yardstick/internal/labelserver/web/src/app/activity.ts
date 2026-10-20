// activity.ts is the top bar's research chip, on every screen: "2 researching · 13 queued" while any
// job is queued or running (it opens the jobs page), "✦ 5 new hints" once research jobs have left
// hints nobody has accepted yet (it opens hint review), and nothing otherwise. It reads
// GET /api/research/jobs every couple of seconds while anything is in flight, and once on load and
// on focus otherwise. The tables, the jobs page and hint review follow research through the same
// reads (onJobs) rather than polling on their own.
import type { HintsResponse, ResearchJobs, ResearchJobsSummary } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill } from "../shared/dom";
import { plural } from "../shared/words";
import { getJSON } from "./data";
import { activityWords, newHints } from "./researchwords";

// poll is how often the jobs are read while any is in flight
const poll = 2000;

let last: ResearchJobs | null = null, timer: ReturnType<typeof setTimeout> | undefined, started = false;
const listeners = new Set<(j: ResearchJobs) => boolean | void>();
const chip = el("a", { class: "activity", hidden: true, "data-testid": "activity" });

export const busy = (s: ResearchJobsSummary | null | undefined) => !!s && s.running + s.queued > 0;

// latest is the newest read of the jobs, null before the first
export const latest = () => last;

// onJobs calls back with every read of the jobs from now on, until it returns false
export function onJobs(cb: (j: ResearchJobs) => boolean | void) {
  listeners.add(cb);
}

// activityChip is the chip, for the shell to put in each screen's app bar
export function activityChip() {
  if (!started) {
    started = true;
    void kick();
    addEventListener("focus", () => void kick());
  }
  return chip;
}

// kick reads the jobs now: after starting research, and from the poll
export async function kick() {
  clearTimeout(timer);
  try {
    const j = await api.researchJobs();
    last = j;
    for (const cb of [...listeners]) if (cb(j) === false) listeners.delete(cb);
    if (busy(j.summary)) draw("busy", activityWords(j.summary));
    else {
      // the hints research jobs left, pending until someone accepts them
      const n = newHints(j.jobs, (await getJSON<HintsResponse>("/api/hints?low=1")).hints);
      draw(n ? "hints" : "", n ? `✦ ${plural(n, "new hint")}` : "");
    }
  } catch {
    // research may be off here, or the server gone: the chip stays as it was
  }
  if (busy(last?.summary)) timer = setTimeout(() => void kick(), poll);
}

function draw(state: "" | "busy" | "hints", text: string) {
  chip.hidden = !state;
  chip.dataset.state = state;
  chip.className = `activity${state === "hints" ? " hints" : ""}`;
  chip.setAttribute("href", state === "hints" ? "/ui/hints" : "/ui/research/jobs");
  chip.title = state === "busy" ? "Research jobs" : state === "hints" ? "Review the hints research left" : "";
  fill(chip, state === "busy" && el("span", { class: "spin", "aria-hidden": "true" }), text);
}
