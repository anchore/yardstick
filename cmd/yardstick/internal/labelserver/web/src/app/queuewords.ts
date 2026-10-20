// queuewords.ts is what the queue says: why a row is next, what each verdict does to its gates, the
// progress line, the cards between gates and at the end, and the history page's days. Pure: no DOM.
import type { CrossAppearance, OutcomeEffect, QueueEntry, QueueGate } from "../gen/wire";
import { plural } from "../shared/words";

const is: Record<string, string> = { pass: "passes", fail: "fails", undecided: "is undecided" };
const adj: Record<string, string> = { pass: "passing", fail: "failing", undecided: "undecided" };

// changes says a label on the row moves the gate's outcome one way or the other
const changes = (a: CrossAppearance) => !!a.effect && (a.effect.ifTP.outcome !== a.outcome || a.effect.ifFP.outcome !== a.outcome);

// does is what a verdict does to a gate, "passes it" or "fails noNewFalseNegatives"
function does(o: OutcomeEffect, now: string | undefined): string {
  if (o.outcome === now) return `leaves it ${adj[o.outcome] ?? o.outcome}`;
  if (o.outcome === "fail") return `fails ${o.fails?.length ? o.fails.join(", ") : "it"}`;
  return o.outcome === "pass" ? "passes it" : "leaves it undecided";
}

// decideClause is how a label decides one gate: "FP passes it; TP fails noNewFalseNegatives"
function decideClause(a: CrossAppearance): string {
  const { ifFP, ifTP } = a.effect!;
  const fp = does(ifFP, a.outcome), tp = does(ifTP, a.outcome);
  return fp === tp ? `either label ${fp}` : `FP ${fp}; TP ${tp}`;
}

// whyNext is "Why this one is next": where its gate stands, then what a label here does, from the
// entry's per-gate ifTP / ifFP outcomes
export function whyNext(e: QueueEntry, gate: string, gates: QueueGate[]): string {
  const g = gates.find((x) => x.name === gate), rows = g?.rows ?? 0;
  const where = `${gate} ${is[g?.outcome ?? ""] ?? g?.outcome ?? "has no outcome"}${rows <= 1 ? " and this is its only open match." : `, with ${plural(rows, "open match", "open matches")}.`}`;
  const moving = e.in.filter(changes);
  if (moving.length === 1) {
    const a = moving[0];
    return `${where} A label here decides ${a.gate === gate ? "it" : a.gate}: ${decideClause(a)}.`;
  }
  if (moving.length > 1) return `${where} A label here decides ${moving.length} gates: ${moving.map((a) => `in ${a.gate}, ${decideClause(a)}`).join("; ")}.`;
  const bears = [...new Set(e.in.flatMap((a) => a.effect?.bears ?? []))];
  if (bears.length) return `${where} No label here changes an outcome on its own, but it counts toward ${bears.join(", ")}.`;
  return `${where} No label here changes any gate's outcome: ${e.in.length === 1 ? "its gate is" : "every gate it is in is"} decided either way.`;
}

const gateDoes = (a: CrossAppearance, o: OutcomeEffect) => o.outcome === a.outcome
  ? `${a.gate} ${o.outcome === "undecided" ? "stays undecided" : `still ${is[o.outcome] ?? o.outcome}`}`
  : `${a.gate} ${o.outcome === "fail" && o.fails?.length ? `fails ${o.fails.join(", ")}` : is[o.outcome] ?? o.outcome}`;

// GateLines are what TP and FP each do to the row's gates, one line per verdict in the label panel
// ("deb-java passes", "deb-java fails noNewFalseNegatives"), or none when no label moves a gate.
// Unclear judges nothing, so it moves nothing.
export type GateLines = { tp: string; fp: string } | { none: string };
export function outcomeLines(e: QueueEntry): GateLines {
  const bearing = e.in.filter((a) => a.effect);
  if (!e.in.some(changes)) return { none: "No label here changes a gate's outcome." };
  const does = (k: "ifTP" | "ifFP") => bearing.map((a) => gateDoes(a, a.effect![k])).join(", ");
  return { tp: does("ifTP"), fp: does("ifFP") };
}

// progress is the queue bar's "3 of 12 done · 9 left", and how full its track is
export function progress(done: number, left: number) {
  const total = done + left;
  return { text: `${done.toLocaleString()} of ${total.toLocaleString()} done · ${left.toLocaleString()} left`, frac: total ? done / total : 1 };
}

// ---------- cards ----------

export interface Boundary { gate: string; before?: string; after: string; left: number; settled: boolean; next: string; nextRows: number; nextSettled: boolean }

// boundaryWords are the card after a gate's last open row in the queue: its new outcome, and the
// next gate
export function boundaryWords(b: Boundary) {
  const rows = plural(b.left, "match", "matches"), one = b.left === 1;
  const left = !b.left ? "" : b.settled ? ` The ${rows} left in ${b.gate} ${one ? "changes" : "change"} nothing, so ${one ? "it comes" : "they come"} last.`
    : ` ${rows} left in ${b.gate}; the queue comes back to ${one ? "it" : "them"}.`;
  const why = b.nextSettled ? ` None of its matches changes ${b.next}'s outcome.` : "";
  return {
    headline: `${b.gate} ${is[b.after] ?? b.after}`,
    foot: `Next in the queue: ${b.next}, ${plural(b.nextRows, "open match", "open matches")}.${why}${left}`,
  };
}

// sessionWords is the end card's line on what this queue wrote: labels, and the rows they closed
// (one label can close a row in several gates, so the two counts differ)
export function sessionWords(labels: number, hints: number, hand: number) {
  const how = [hints && `${hints} from hints`, hand && `${hand} by hand`].filter(Boolean).join(", ");
  return `${plural(labels, "label")} written this session${how ? `, closing ${plural(hints + hand, "match", "matches")}: ${how}` : ""}.`;
}

// settledWords is the stopping point's line: what's left changes nothing
export const settledWords = (left: number) => `The ${plural(left, "match", "matches")} left ${left === 1 ? "changes" : "change"} no outcome; label ${left === 1 ? "it" : "them"} or stop here.`;

// ---------- history ----------

// dayKey is a timestamp's day in the reader's time zone, which the history page groups by
export function dayKey(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// dayWords is a day as the history page heads it: Today, Yesterday, else the date
export function dayWords(key: string, now = new Date()): string {
  const today = dayKey(now.toISOString()), y = new Date(now);
  y.setDate(y.getDate() - 1);
  if (key === today) return "Today";
  if (key === dayKey(y.toISOString())) return "Yesterday";
  const d = new Date(`${key}T12:00:00`);
  return Number.isNaN(d.getTime()) ? key : d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
}

// sessionLabels counts the labels written since a queue started, from history's newest first
// timestamps; the files keep whole seconds, so the start is too
export function sessionLabels(updated: string[], start: string): number {
  const from = Math.floor(new Date(start).getTime() / 1000) * 1000;
  return updated.filter((t) => new Date(t).getTime() >= from).length;
}
