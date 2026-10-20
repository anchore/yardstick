// queue.ts is the queue, /ui/queue/<row>?scope=: the finding page in queue mode, one open row at a
// time across gates, in the order GET /api/queue gives. It adds the queue bar (scope, progress,
// exit), why the row is next, and what each verdict does, and after each write reads the queue
// fresh to pick the next row, or a card: a gate boundary, the stopping point, or the end. The logic
// is queuelist.ts's and the words queuewords.ts's.
import type { CheckFindings, History, LabelKey, Queue, QueueEntry } from "../gen/wire";
import { el, toast } from "../shared/dom";
import { boundaryCard, endCard, stopCard } from "./cards";
import { getJSON, written } from "./data";
import { findingView, type QueueMode } from "./finding";
import { checkRows, isOpen } from "./listing";
import { failed, loading, shown } from "./lists";
import { position, type Item } from "./neighbors";
import { entryGate, exitRoute, newlyDone, ordered, pickNext, scopeGate, walk, type DoneRow, type QueueRoute } from "./queuelist";
import { boundaryWords, outcomeLines, progress, sessionLabels, sessionWords, settledWords, whyNext } from "./queuewords";
import { formatRoute } from "./route";
import { skipping } from "./settings";
import { renderShell, type Nav, type View } from "./shell";
import { kbd, status, step, type State } from "./ui";

// ---------- the session: what this queue has done since it started, kept in this tab ----------

interface Session {
  key: string;          // the scope it is for
  start: string;        // when it started, which the end card counts labels from
  done: DoneRow[];      // rows labeled since, in order
  seen: DoneRow[];      // the last snapshot's rows, to tell what was labeled since
  skipped: string[];    // rows passed over with j or Skip
  hints: number;        // rows closed by accepting a hint, and by hand
  hand: number;
  stopped: boolean;     // the stopping point card has been shown
}

const sessionKey = "yardstick.queue";
let memory: Session | null = null; // when this tab has no session storage
const scopeKey = (r: QueueRoute) => `${r.scope ?? "all"}|${r.check ?? ""}|${r.low ? 1 : 0}`;

function session(r: QueueRoute, restart: boolean): Session {
  let s = memory;
  try { s = JSON.parse(sessionStorage.getItem(sessionKey) ?? "null") ?? s; } catch { /* no storage: the memory copy stands */ }
  if (restart || !s || s.key !== scopeKey(r)) s = { key: scopeKey(r), start: new Date().toISOString(), done: [], seen: [], skipped: [], hints: 0, hand: 0, stopped: false };
  return s;
}
function keep(s: Session) {
  memory = s;
  try { sessionStorage.setItem(sessionKey, JSON.stringify(s)); } catch { /* no storage: kept in memory */ }
}

// ---------- data ----------

// fetchQueue is the queue the route names, fresh: a gate scope is that gate's rows (a check's open
// rows first) and then every other gate's, since the queue continues across gates
async function fetchQueue(r: QueueRoute): Promise<Queue> {
  const get = (scope: string) => getJSON<Queue>(`/api/queue?scope=${encodeURIComponent(scope)}${r.low ? "&low=1" : ""}`);
  const gate = scopeGate(r.scope);
  if (!gate) return get(r.scope ?? "all");
  const [mine, all, cf] = await Promise.all([get(r.scope!), get("all"),
    r.check ? getJSON<CheckFindings>(`/api/gates/${encodeURIComponent(gate)}/checks/${encodeURIComponent(r.check)}/findings`) : null]);
  const first = cf ? checkRows(cf).filter((x) => x.row && isOpen(x)).map((x) => x.row!) : [];
  return { ...all, entries: ordered(first, mine.entries, all.entries) };
}

// ---------- the view ----------

export function queueView(host: HTMLElement, r: QueueRoute, nav: Nav): View {
  const alive = shown(r), out: View = {};
  const s = session(r, !r.row);
  const go = (row: string, replace = false) => nav({ ...r, row }, replace);
  const exit = () => nav(exitRoute(r));
  const gatesHref = formatRoute({ level: "gates", tab: "gates", filters: {} });

  // note takes a fresh queue's news into the session: the rows gone from it are done
  function note(q: Queue) {
    const newly = newlyDone(s.seen, q.entries, s.done);
    s.done.push(...newly);
    s.seen = q.entries.map((e) => ({ row: e.row, gate: entryGate(e, q.gates, r.scope) }));
    keep(s);
    return newly;
  }

  // ---------- the queue bar ----------

  function bar(q: Queue, items: Item[] | null) {
    const opts: [string, string][] = [["all", "All gates"], ...q.gates.map((g): [string, string] => [`gate:${g.name}`, `Gate: ${g.name}`])];
    if (r.scope?.startsWith("image:")) opts.push([r.scope, `Image: ${r.scope.slice(6)}`]);
    const open = new Set(q.entries.map((e) => e.row)), done = s.done.filter((d) => !open.has(d.row)).length;
    const p = progress(done, q.entries.length);
    const fill = el("i");
    fill.style.width = `${(p.frac * 100).toFixed(1)}%`;
    const pos = items && r.row ? position(items, r.row, !skipping()) : null;
    const link = (row: string | undefined, way: "previous" | "next") => step(row && formatRoute({ ...r, row }), way, `queue-pager-${way}`);
    const cur = r.scope ?? "all";
    const scope: HTMLSelectElement = el("select", { class: "select", "aria-label": "Scope", "data-testid": "queue-scope",
      onchange: () => nav({ level: "queue", ...(scope.value !== "all" && { scope: scope.value }), ...(r.low && { low: true }), filters: {} }) },
    opts.map(([v, t]) => el("option", { value: v, selected: v === cur }, t)));
    return el("div", { class: "qbar", "data-testid": "queue-bar" },
      el("b", {}, "Labeling"),
      scope,
      el("div", { class: "prog" },
        el("div", { class: "track", "aria-hidden": "true" }, fill),
        el("span", { class: "quiet", "data-testid": "queue-progress", "data-done": done, "data-left": q.entries.length }, p.text)),
      // the pager is where this row sits and the way to the next one, apart from how much is done
      pos && el("span", { class: "pager qbox", "data-testid": "queue-pager", "data-index": pos.index + 1, "data-total": pos.total },
        link(pos.prev, "previous"), pos.index >= 0 ? `${pos.index + 1} of ${pos.total}` : "labeled", link(pos.next, "next")),
      el("span", { class: "qbox" },
        el("button", { type: "button", class: "step", "aria-label": "Exit", title: "Exit (esc)", "data-testid": "queue-exit", onclick: exit }, "✕", kbd("esc"))));
  }

  // ---------- cards ----------

  // showCard draws a card in the finding's place; Enter takes its primary button unless a control has the focus
  function showCard(q: Queue, title: string, state: string | null, body: HTMLElement, go: () => void) {
    renderShell(host, r, { title, status: state && status(state as State, true), bar: bar(q, null), body });
    out.key = (e) => {
      if (e.key === "Enter" && e.target === document.body) { go(); return true; }
      if (e.key === "Escape") { exit(); return true; }
      return false;
    };
  }

  async function showEnd(q: Queue) {
    let written = 0;
    try { written = sessionLabels((await getJSON<History>("/api/history?limit=500")).labels.map((l) => l.label.lastUpdated), s.start); } catch { /* the count is left at 0 */ }
    if (!alive()) return;
    showCard(q, "Nothing left to label", null,
      endCard({ gates: q.gates, foot: `${sessionWords(written, s.hints, s.hand)} They are in ./claims.`, back: gatesHref, history: "/ui/history" }),
      () => nav({ level: "gates", tab: "gates", filters: {} }));
  }

  function showStop(q: Queue) {
    s.stopped = true;
    keep(s);
    const next = () => { const row = pickNext(q.entries, [], s.skipped); if (row) go(row); };
    showCard(q, "Every gate is decided", null, stopCard({ gates: q.gates, left: q.entries, foot: settledWords(q.entries.length), back: gatesHref, go: next }), next);
  }

  // ---------- after a write ----------

  async function after(e: QueueEntry | undefined, gate: string, rows: string[], text: string, how: "hint" | "hand", keys: LabelKey[]) {
    let q: Queue;
    try { q = await fetchQueue(r); } catch (err) { toast((err as Error).message, true); return; }
    if (!alive()) return;
    s[how === "hint" ? "hints" : "hand"] += Math.max(1, note(q).length);
    keep(s);
    written(text, keys);
    if (!q.entries.length) return showEnd(q);
    if (q.settled && !s.stopped) return showStop(q);
    const row = pickNext(q.entries, rows, s.skipped)!;
    const next = entryGate(q.entries.find((x) => x.row === row)!, q.gates, r.scope);
    if (next === gate) return go(row);
    // leaving a gate's last open row in the queue: say what happened to it, and what's next
    const was = q.gates.find((g) => g.name === gate), to = q.gates.find((g) => g.name === next);
    const before = e?.in.find((a) => a.gate === gate)?.outcome, after = was?.outcome ?? "undecided";
    const w = boundaryWords({ gate, before, after, left: was?.rows ?? 0, settled: !!was?.settled, next, nextRows: to?.rows ?? 0, nextSettled: !!to?.settled });
    showCard(q, w.headline, after,
      boundaryCard({ label: `After ${e?.vulnerability ?? "that label"}`, gate, before, after, next, foot: w.foot, go: () => go(row),
        back: formatRoute({ level: "gate", gate, tab: "checks", filters: {} }) }),
      () => go(row));
  }

  // ---------- load ----------

  async function load() {
    let q: Queue;
    try { q = await fetchQueue(r); } catch (e) {
      if (alive()) renderShell(host, r, { title: "Labeling", body: failed(e) });
      return;
    }
    if (!alive()) return;
    note(q);
    if (!r.row) {
      if (!q.entries.length) return showEnd(q);
      if (q.settled && !s.stopped) return showStop(q);
      return go(q.entries[0].row, true);
    }
    const row = r.row, e = q.entries.find((x) => x.row === row);
    const gate = e ? entryGate(e, q.gates, r.scope) : s.done.find((d) => d.row === row)?.gate;
    if (!gate) {
      renderShell(host, r, { title: "Labeling", bar: bar(q, null),
        body: el("div", { class: "placeholder", "data-testid": "placeholder" }, "This match isn't open in this queue. ", el("a", { href: formatRoute({ ...r, row: undefined }) }, "Start the queue from its next match")) });
      out.key = (ev) => (ev.key === "Escape" ? (exit(), true) : false);
      return;
    }
    const items = walk(q.entries, s.done);
    const mode: QueueMode = {
      route: r,
      bar: bar(q, items),
      // "skip labeled" moves the pager, so the bar is drawn again in place, leaving the cog open
      prefs() { const b = bar(q, items); (mode.bar as Element).replaceWith(b); mode.bar = b; },
      why: e && el("div", { class: "why-next", "data-testid": "why-next" }, el("b", {}, "Why this one is next"), el("span", {}, whyNext(e, gate, q.gates))),
      outcomes: e && outcomeLines(e),
      step(dir, all) {
        const p = position(items, row, all || !skipping()), to = dir > 0 ? p.next : p.prev;
        if (dir > 0 && e && !s.skipped.includes(row)) { s.skipped.push(row); keep(s); }
        if (to) go(to); else toast(dir > 0 ? "last one in the queue" : "first one in the queue");
      },
      next: (rows, text, how, keys) => after(e, gate, rows, text, how, keys),
      key(ev) {
        if (ev.key === "Escape") { exit(); return true; }
        if (ev.key === "n") {
          const to = pickNext(q.entries, [row], s.skipped);
          if (to) go(to); else toast("nothing else is open in this queue");
          return true;
        }
        return false;
      },
    };
    out.key = findingView(host, { level: "finding", gate, check: null, row, filters: {} }, nav, mode).key;
  }

  renderShell(host, r, { title: "Labeling", body: loading() });
  void load();
  return out;
}
