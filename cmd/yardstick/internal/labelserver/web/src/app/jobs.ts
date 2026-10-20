// jobs.ts is the jobs page, /ui/research/jobs: every research job the server knows about, however
// it was started (the research page, a table, a finding), as one list in three groups (running,
// queued in the order they will run, finished newest first) under a summary of the work in flight
// with Cancel and the way on to the hints it left. It follows the top bar's reads of the jobs
// (activity.ts) rather than polling on its own. The words are researchwords.ts's.
import type { Basis } from "../gen/research";
import type { HintEntry, HintsResponse, ResearchJob, ResearchJobs, State } from "../gen/wire";
import * as api from "../shared/api";
import { inFlight, failedJob } from "../shared/agent";
import { el, fill, toast, type Child } from "../shared/dom";
import { pkgOf } from "../shared/rows";
import { labels as words, plural } from "../shared/words";
import { busy, kick, latest, onJobs } from "./activity";
import { gateState, getJSON } from "./data";
import { hintsHref } from "./hintsdata";
import { failed, loading, shown } from "./lists";
import { started, tick } from "./researchtable";
import { costWords, fromWords, jobGroups, liveLog, modelWords, money, newHints, stateWords, timeWords } from "./researchwords";
import { formatRoute, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { hint, imageName, kbd } from "./ui";

// shown before "and N more" in the queued and finished groups
const listed = { queued: 10, finished: 20 };

// jobsToggle is the header toggle the research page and the jobs page share: Open matches or Jobs N
export function jobsToggle(on: "matches" | "jobs") {
  const n = el("b", {}, latest() ? String(latest()!.jobs.length) : "");
  if (!latest()) api.researchJobs().then((j) => fill(n, String(j.jobs.length))).catch(() => undefined);
  const tab = (id: string, href: string, text: Child) => el("a", { class: "chip", href, "aria-pressed": String(on === id), "data-tab": id }, text);
  return el("div", { class: "chips", "data-testid": "research-toggle" }, tab("matches", "/ui/research", "Open matches"), tab("jobs", "/ui/research/jobs", ["Jobs ", n]));
}

// Where is a job's rows as the page names them: the image, and every version they cover
interface Where { image: string; versions: string[] }

export function jobsView(host: HTMLElement, r: Extract<Route, { level: "jobs" }>, _nav: Nav): View {
  const alive = shown(r);
  const more = { queued: false, finished: false };
  const sum = el("section", { class: "jsum", "data-testid": "jobs-summary" });
  const list = el("div", { class: "jt", "data-testid": "jobs-list" });
  const sub = el("span", {});
  let basis: Basis | null = null, concurrency = 0, pending: HintEntry[] = [], scrolled = false;
  const where = new Map<string, Where>();
  const shell = (body: Child) => renderShell(host, r, { title: "Research jobs", sub, actions: jobsToggle("jobs"), body });

  async function load() {
    const [j, plan, hints] = await Promise.all([api.researchJobs(), api.researchQueue({ scope: "all", dryRun: true }).catch(() => null),
      getJSON<HintsResponse>("/api/hints?low=1").catch(() => null)]);
    basis = plan?.estimate.basis ?? null;
    pending = hints?.hints ?? [];
    await place(j);
    if (!alive()) return;
    shell(el("div", { class: "screen" }, sum, list));
    draw(j);
    // the top bar reads the jobs while any is in flight; the page redraws on each read
    onJobs((next) => {
      if (!alive() || !list.isConnected) return false;
      void place(next).then(() => draw(next));
    });
    void kick();
  }

  // place finds the image and versions of each job's rows in its gate's state
  async function place(j: ResearchJobs) {
    const gates = [...new Set(j.jobs.map((x) => x.gate).filter((g): g is string => !!g))];
    const states = new Map<string, State | null>(await Promise.all(gates.map(async (g) => [g, await gateState(g).catch(() => null)] as const)));
    for (const x of j.jobs) {
      if (where.has(x.id) || !x.gate) continue;
      const st = states.get(x.gate), sub = st?.subjects.find((s) => s.rows.some((y) => y.id === x.rows[0]));
      if (!sub) continue;
      const ids = new Set(x.rows), versions = [...new Set(sub.rows.filter((y) => ids.has(y.id)).map((y) => pkgOf(y.package.ref).version).filter(Boolean))];
      where.set(x.id, { image: sub.name, versions });
    }
  }

  function draw(j: ResearchJobs) {
    const s = j.summary, g = jobGroups(j.jobs), on = busy(s);
    concurrency = s.concurrency;
    fill(sub, `${modelWords(j.jobs[0]?.model ?? basis?.model ?? "")}, ${concurrency || "?"} at a time. Jobs write hints, never labels.`);
    const big = (b: Child, word: string, testid: string) => el("div", { class: "big" }, el("b", { "data-testid": testid }, b), el("span", {}, word));
    const finished = s.done + s.failed + s.cancelled, act = s.running + s.queued;
    const fresh = newHints(j.jobs, pending);
    const review = fresh > 0 && el("a", { class: "btn", href: hintsHref({}), "data-testid": "jobs-review" }, `Review ${plural(fresh, "new hint")} `, kbd("h"));
    const so = (["fp", "tp", "unclear"] as const).filter((v) => s.hints[v] > 0).map((v) => `${s.hints[v]} ${words[v].word}`).join(", ");
    if (on) {
      fill(sum,
        el("div", { class: "bigs" }, big(String(s.running), "running", "jobs-running"), big(String(s.queued), "queued", "jobs-queued"), big(String(finished), "finished", "jobs-finished"),
          el("div", { class: "big" }, el("b", { class: "cost", "data-testid": "jobs-spent" }, money(s.spent)), el("span", {}, s.estimate ? `spent of about ${money(s.estimate)}` : "spent, the rest not measured")),
          big(s.secondsLeft ? `~${Math.max(1, Math.round(s.secondsLeft / 60))} min` : "–", "left", "jobs-left")),
        el("div", { class: "acts" },
          el("button", { type: "button", class: "btn", "data-variant": "outline", "data-testid": "jobs-cancel-all", onclick: () => void cancel(j.jobs.filter((x) => inFlight(x) && x.cancellable)) },
            `Cancel ${act} `, el("span", { class: "quiet" }, "running and queued")),
          review),
        el("div", { class: "workstack", "aria-hidden": "true" }, [["done", finished], ["running", s.running], ["queued", s.queued]].filter(([, n]) => +n > 0).map(([c, n]) => el("i", { class: String(c), style: `flex:${n}` }))),
        el("div", { class: "legend" }, el("span", { class: "done" }, `finished ${finished}`), el("span", { class: "running" }, `running ${s.running}`), el("span", { class: "queued" }, `queued ${s.queued}`),
          so && el("span", { class: "hinted" }, `hints so far: ${so}`)));
    } else {
      const spent = j.jobs.reduce((n, x) => n + (x.usage?.costUSD ?? 0), 0);
      fill(sum,
        el("div", { class: "bigs" }, big("0", "running", "jobs-running"), big(String(g.finished.length), "finished", "jobs-finished"),
          el("div", { class: "big" }, el("b", { class: "cost", "data-testid": "jobs-spent" }, money(spent)), el("span", {}, "spent on these jobs"))),
        el("div", { class: "acts" }, review));
    }
    sum.dataset.active = String(on);

    const header = el("div", { class: "jr2 h" }, ["State", "Match", "Image", "Started from"].map((t) => el("span", {}, t)),
      el("span", { class: "r" }, "Time"), el("span", { class: "r" }, "Cost"), el("span", {}, "Result"), el("span", {}));
    const group = (id: "running" | "queued" | "finished", title: string, note: string, jobs: ResearchJob[]) => {
      if (!jobs.length) return null;
      const cap = id === "running" || more[id as "queued" | "finished"] ? jobs.length : listed[id as "queued" | "finished"];
      const rest = jobs.length - cap;
      return [
        el("div", { class: "gh", "data-testid": "jobs-group", "data-group": id }, el("b", {}, title), el("span", {}, note)),
        jobs.slice(0, cap).map((x) => line(x, id)),
        rest > 0 && el("div", { class: "more" }, `and ${rest} more · `,
          el("button", { type: "button", class: "lk", "data-testid": "jobs-more", onclick: () => { more[id as "queued" | "finished"] = true; draw(j); } }, "show all")),
      ];
    };
    fill(list, j.jobs.length ? [header,
      group("running", "Running", String(g.running.length), g.running),
      group("queued", "Queued", `${g.queued.length}, in the order they will run`, g.queued),
      group("finished", "Finished", `${g.finished.length} · newest first`, g.finished)]
      : el("div", { class: "placeholder", "data-testid": "jobs-empty" }, "No research jobs yet. ", el("a", { href: "/ui/research" }, "Research open matches")));
    // a job linked from a table cell or a finding is marked and scrolled to, once
    const at = location.hash.startsWith("#job-") ? list.querySelector<HTMLElement>(`[id="${CSS.escape(location.hash.slice(1))}"]`) : null;
    at?.classList.add("on");
    if (at && !scrolled) { scrolled = true; at.scrollIntoView({ block: "center" }); }
  }

  // line is one job: its state, the match, where it was started, how long, what it cost, what it left
  function line(x: ResearchJob, group: string) {
    const w = where.get(x.id), row = x.rows[0];
    const finding = x.gate && row ? formatRoute({ level: "finding", gate: x.gate, check: null, row, filters: {} }) : null;
    const state = x.status === "running" ? "run" : x.status === "queued" ? "q" : failedJob(x) ? "fail" : x.status === "done" ? "ok" : "cancel";
    const time = timeWords(x, basis, concurrency);
    if (x.status === "running") tick();
    const result: Child = x.status === "done"
      ? x.hints.length ? [x.hints.map((h) => hint(`${words[h.verdict]?.word ?? h.verdict}${h.confidence ? ` · ${h.confidence}` : ""}`)), " ", finding && el("a", { class: "lk", href: finding, "data-testid": "job-review" }, "review")]
        : el("span", { class: "quiet" }, "no hint")
      : failedJob(x) ? el("span", { class: "err", title: x.error }, x.error || x.status)
        : x.status === "cancelled" ? el("span", { class: "quiet" }, x.started ? "cancelled" : "cancelled before it started") : null;
    return el("div", { class: "jr2", id: `job-${x.id}`, "data-testid": "job-row", "data-job": x.id, "data-state": x.status, "data-group": group },
      el("span", { class: `rs ${state}` }, stateWords(x)),
      el("span", { class: "v" }, finding ? el("a", { href: finding }, x.vulnerability) : x.vulnerability,
        el("span", { class: "pkg", title: x.package }, [pkgOf(x.package).name, w?.versions.join(", ") || pkgOf(x.package).version].filter(Boolean).join(" "))),
      el("span", { class: "img" }, w ? imageName(w.image) : el("span", { class: "quiet" }, "–")),
      el("span", { class: "from", title: x.batch ? `batch ${x.batch}` : undefined }, fromWords(x)),
      el("span", { class: "r", "data-since": x.status === "running" ? x.started : null }, time),
      el("span", { class: `r${x.usage ? " cost" : ""}` }, costWords(x, basis)),
      el("span", { class: "res" }, result),
      el("span", { class: "acts2" },
        x.started && el("a", { class: "lk", href: `/api/research/${encodeURIComponent(x.id)}/log`, target: "_blank", rel: "noopener", title: x.status === "running" ? liveLog : undefined, "data-testid": "job-log" }, "log"),
        inFlight(x) && x.cancellable && x.gate && el("button", { type: "button", class: "lk", "data-testid": "job-cancel", onclick: () => void cancel([x]) }, "cancel"),
        (failedJob(x) || x.status === "cancelled") && x.gate && el("button", { type: "button", class: "lk", "data-testid": "job-retry", onclick: () => void retry(x) }, "retry")));
  }

  // cancel stops jobs through their gates, each by its first row
  async function cancel(jobs: ResearchJob[]) {
    const by = new Map<string, string[]>();
    for (const x of jobs) if (x.gate) by.set(x.gate, [...(by.get(x.gate) ?? []), x.rows[0]]);
    let n = 0;
    try {
      for (const [gate, rows] of by) n += (await api.cancelResearch(gate, rows)).cancelled.length;
      toast(`${plural(n, "research job")} cancelled; finished hints stay`);
    } catch (e) {
      toast((e as Error).message, true);
    }
    void kick();
  }

  // retry starts a failed or cancelled job's rows again, from where it was first started
  async function retry(x: ResearchJob) {
    try {
      const res = await api.research(x.gate!, { rows: x.rows, from: x.from === "finding" ? "finding" : "table" });
      started(res.queued, res.skipped);
    } catch (e) {
      toast((e as Error).message, true);
    }
  }

  renderShell(host, r, { title: "Research jobs", actions: jobsToggle("jobs"), body: loading() });
  load().catch((e) => alive() && renderShell(host, r, { title: "Research jobs", body: failed(e) }));
  return {};
}
