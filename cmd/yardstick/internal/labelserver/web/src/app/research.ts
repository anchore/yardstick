// research.ts is the research page, /ui/research?scope=: the open rows no agent has looked at yet,
// grouped by what labeling them can do to a gate, each group with its jobs, beside a sticky panel
// that prices the selection with the server's dry run as it changes and starts it as one batch.
// Shaped like hint review (hints.ts). Labeling by hand never waits on it: "Label what's left" is here too.
import type { GateList, ResearchGroup, ResearchQueueResponse } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill, toast } from "../shared/dom";
import { plural } from "../shared/words";
import { forget, gateList } from "./data";
import { failed, loading, shown } from "./lists";
import { queueFor } from "./queuelist";
import { formatRoute, type Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { basisWords, estimateWords, money, modelWords } from "./researchwords";
import { imageName, kbd } from "./ui";

type ResearchRoute = Extract<Route, { level: "research" }>;

const groups: { id: string; title: string; sub: string }[] = [
  { id: "change", title: "Can change a gate", sub: "a label on any of these can still decide or move a check in a gate that isn't settled" },
  { id: "none", title: "Changes no outcome", sub: "labels here still help the corpus, they just don't move a gate today" },
];

// models the page offers; the configured one is added when it is none of these
const models = ["sonnet", "opus", "haiku"];
// shown is how many jobs a group lists before "and N more"
const listed = 5;

export function researchView(host: HTMLElement, r: ResearchRoute, nav: Nav): View {
  const alive = shown(r), scope = r.scope ?? "all";
  // the second group starts unchecked: that's where a batch spends money for no outcome
  const on: Record<string, boolean> = { change: true, none: false };
  const left = el("a", { class: "btn", "data-variant": "outline", href: formatRoute(queueFor(r)), "data-testid": "label-left" }, "Label what's left ", kbd("n"));

  Promise.all([gateList(), api.researchQueue({ scope, dryRun: true })]).then(([list, first]) => {
    if (alive()) draw(list, first);
  }).catch((e) => alive() && renderShell(host, r, { title: "Research open matches", actions: left, body: failed(e) }));
  renderShell(host, r, { title: "Research open matches", actions: left, body: loading() });

  function draw(list: GateList, first: ResearchQueueResponse) {
    const gates = list.gates.filter((g) => !g.error);
    const chip = (s: string, text: string) => el("a", { class: "chip", href: formatRoute({ level: "research", scope: s, filters: {} }), "aria-pressed": String(scope === s),
      "data-testid": "research-gate-chip", "data-gate": s === "all" ? "" : s.slice(5) }, text);
    const chips = el("div", { class: "chips" }, chip("all", "All gates"), gates.map((g) => chip(`gate:${g.id}`, g.id)));
    const total = first.groups.reduce((n, g) => n + g.rows, 0);
    const inGates = new Set(first.groups.flatMap((g) => g.jobs.map((j) => j.gate))).size;
    const s = first.skipped;
    const skipped = el("div", { class: "skipped", "data-testid": "research-skipped" },
      `Skipped: ${plural(s.researched, "match", "matches")} already researched, ${s.hinted} with an agent hint, ${s.active} queued or running. A match with a hint or a job in flight never gets a second job from here.`);

    const shell = (body: HTMLElement) => renderShell(host, r, {
      title: "Research open matches",
      sub: total ? `${plural(total, "open match", "open matches")} with no hint, in ${plural(inGates, "gate")}` : undefined,
      actions: [chips, left], body: el("div", { class: "screen" }, body),
    });
    if (!total) {
      shell(el("div", { class: "rgroups" }, el("div", { class: "placeholder", "data-testid": "research-empty" }, "Nothing here to research: every open match in scope has an agent hint, finished research or a job in flight."), skipped));
      return;
    }

    // the groups, each with its select box; their job lists follow every plan, since a selected
    // group claims shared rows first
    const parts = groups.map((g) => {
      const box: HTMLInputElement = el("input", { type: "checkbox", checked: on[g.id], "aria-label": `Research the matches that ${g.title.toLowerCase()}`, "data-testid": "research-group-toggle",
        onchange: () => { on[g.id] = box.checked; schedule(); } });
      const count = el("span", { class: "n" }), jobs = el("div", { class: "rjobs" });
      const root = el("div", { class: "rgrp", "data-testid": "research-group", "data-group": g.id },
        el("header", {}, box, el("span", { class: "t" }, g.title), count, el("span", { class: "s" }, g.sub)), jobs);
      return { id: g.id, root, count, jobs };
    });

    const cost = el("b", { "data-testid": "research-cost" }), range = el("span", { "data-testid": "research-range" });
    const band = el("div", { class: "band" }), mean = el("div", { class: "mean" });
    const kv = (label: string, testid: string) => { const v = el("span", { "data-testid": testid }); return { v, els: [el("span", {}, label), v] }; };
    const jobsKV = kv("Jobs", "research-jobs"), rowsKV = kv("Matches covered", "research-rows"), tokKV = kv("Tokens", "research-tokens"), timeKV = kv(`Time, ${first.concurrency} at a time`, "research-time");
    const configured = first.estimate.basis.model;
    const model: HTMLSelectElement = el("select", { id: "research-model", "data-testid": "research-model", onchange: () => schedule() },
      [...new Set([configured, ...models])].filter(Boolean).map((m) => el("option", { value: m, selected: m === configured }, modelWords(m))));
    const limit: HTMLInputElement = el("input", { id: "research-limit", type: "number", min: "1", placeholder: "all jobs", "data-testid": "research-limit", oninput: () => schedule() });
    const warn = el("p", { class: "warn", hidden: true, "data-testid": "research-unmeasured" },
      "No finished jobs on this model yet. The estimate shows after the first 3 finish; until then only the job count is known.");
    const start: HTMLButtonElement = el("button", { type: "button", class: "btn", "data-testid": "research-start", onclick: () => void doStart() });
    const basis = el("p", { class: "foot basis", "data-testid": "research-basis" });
    const panel = el("aside", { class: "impact est", "data-testid": "research-estimate", "aria-live": "polite" },
      el("h2", {}, "If you start this"),
      el("div", { class: "money" }, cost, range),
      el("div", { class: "range", "aria-hidden": "true" }, el("div", { class: "track" }), band, mean),
      el("div", { class: "kv" }, jobsKV.els, rowsKV.els, tokKV.els, timeKV.els),
      el("div", { class: "ctl" },
        el("div", {}, el("label", { for: "research-model" }, "Model"), model),
        el("div", {}, el("label", { for: "research-limit" }, "Stop after"), limit)),
      warn, start, basis);

    shell(el("div", { class: "review" }, el("div", { class: "rgroups" }, parts.map((p) => p.root), skipped), panel));

    let seq = 0, timer: ReturnType<typeof setTimeout> | undefined, plan = first;
    const chosen = () => groups.map((g) => g.id).filter((id) => on[id]);
    const request = () => ({ scope, groups: chosen(), limit: Number(limit.value) > 0 ? Number(limit.value) : undefined, model: model.value });

    function show(p: ResearchQueueResponse) {
      const b = p.estimate.basis, picked = chosen().length > 0;
      for (const part of parts) {
        const g = p.groups.find((x) => x.group === part.id)!;
        part.root.hidden = !g.jobs.length;
        fill(part.count, `${plural(g.rows, "match", "matches")} · ${plural(g.jobs.length, "job")}`, b.measured && [" · ", el("span", { class: "cost" }, money(g.jobs.length * b.mean))]);
        fill(part.jobs, jobList(g, b.measured ? b.mean : 0));
      }
      // nothing checked asks the server for nothing; the panel says so
      const e = picked ? p.estimate : { ...p.estimate, jobs: 0, rows: 0 };
      const w = estimateWords(e);
      fill(cost, w.cost); fill(range, w.range);
      fill(jobsKV.v, String(e.jobs)); fill(rowsKV.v, String(e.rows)); fill(tokKV.v, w.tokens); fill(timeKV.v, w.time);
      // the band spans low to high on a scale of every job at the dearest, so checking more widens it
      const top = p.groups.reduce((n, g) => n + g.jobs.length, 0) * b.max;
      const pct = (x: number) => `${top ? (x / top) * 100 : 0}%`;
      band.hidden = mean.hidden = !b.measured || !e.jobs;
      band.style.left = pct(e.low); band.style.width = pct(e.high - e.low); mean.style.left = pct(e.mean);
      warn.hidden = b.measured;
      fill(start, e.jobs ? `Start ${plural(e.jobs, "research job")}` : "Select matches to research");
      start.disabled = !e.jobs;
      start.dataset.jobs = String(e.jobs);
      fill(basis, basisWords(b));
    }

    function schedule() {
      clearTimeout(timer);
      if (!chosen().length) { show(plan); return; }
      timer = setTimeout(async () => {
        const mine = ++seq;
        try {
          const p = await api.researchQueue({ ...request(), dryRun: true });
          if (mine !== seq || !alive()) return;
          plan = p;
          show(p);
        } catch (e) {
          if (mine === seq) toast(`Couldn't price that: ${(e as Error).message}`, true);
        }
      }, 150);
    }

    async function doStart() {
      if (!chosen().length) return;
      start.disabled = true;
      try {
        const res = await api.researchQueue(request());
        toast(res.jobs?.length ? `✦ ${plural(res.jobs.length, "research job")} started; the gates page shows their progress` : "nothing left to research");
      } catch (e) {
        toast((e as Error).message, true);
        start.disabled = false;
        return;
      }
      forget();
      nav({ level: "gates", tab: "gates", filters: {} });
    }

    show(first);
  }

  return {};
}

// jobList is a group's jobs, the first few and then how many more
function jobList(g: ResearchGroup, each: number) {
  const rest = g.jobs.slice(listed), pkgs = new Set(rest.map((j) => j.package.name));
  return [
    g.jobs.slice(0, listed).map((j) => el("div", { class: "rjob", "data-testid": "research-job", "data-gate": j.gate, "data-row": j.rows[0] },
      el("span", { class: "v" }, j.vulnerability),
      el("span", { class: "pk", title: `${j.package.name} ${j.package.version ?? ""} · ${j.image} · researched in ${j.gate}` }, `${j.package.name} ${j.package.version ?? ""} · `, imageName(j.image)),
      el("span", { class: "r" }, plural(j.rows.length, "match", "matches")),
      el("span", { class: "r cost" }, each ? money(each) : ""))),
    rest.length > 0 && el("div", { class: "more", "data-testid": "research-more" }, `and ${plural(rest.length, "more job")}${pkgs.size === 1 ? ` on ${[...pkgs][0]}` : ""}`),
  ];
}
