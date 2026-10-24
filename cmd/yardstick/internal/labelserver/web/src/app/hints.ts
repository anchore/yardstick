// hints.ts is hint review, /ui/hints?gate=&image=&low=: every pending agent hint in the scope,
// grouped by what accepting it alone does, checked per hintsdata's preselection, beside a sticky
// panel that previews the selection's joint effect on every gate it touches and accepts it in one go.
import type { GateList, GateResult, HintEntry, ResearchJobsSummary, State, Vocabulary } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill, place, toast, type Child } from "../shared/dom";
import { dots, labels as words, plural, sideWords } from "../shared/words";
import { changed, gateList, gateState, writeFailed, written } from "./data";
import { hintsHref, hintsRoute, imageHints, inScope, preselected, scopeOf, previewLabels, rowCount, stillOpen, type OpenRow } from "./hintsdata";
import { noCounts, type RailImage } from "./images";
import { gateRows, isOpen } from "./listing";
import { failed, loading } from "./lists";
import { imageRail, type Rail } from "./rail";
import { busy, kick, latest, onJobs } from "./activity";
import { scopedResearch } from "./research";
import { about } from "./researchwords";
import type { Route } from "./route";
import { renderShell, type Nav, type View } from "./shell";
import { imageName, outcome, status, verdict } from "./ui";

const groups: { id: string; title: string; sub: string }[] = [
  { id: "decides", title: "Decide a gate", sub: "accepting one of these changes a gate's outcome on its own" },
  { id: "needed", title: "Needed to decide a gate", sub: "each closes open matches a gate that isn't passing counts" },
  { id: "none", title: "Close a match, no outcome change", sub: "accepting these changes no gate's outcome" },
];

const andList = (xs: string[]) => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);
const uniq = (xs: string[]) => [...new Set(xs)];

// stateWord is a state as colored text with its word (UI-RULES 8)
const stateWord = (s: string) => el("span", { class: `sw ${s}` }, s);

interface Data { list: GateList; all: HintEntry[]; states: Map<string, State> }

type HintsRoute = Route & { level: "hints" };

export function hintsView(host: HTMLElement, r0: HintsRoute, nav: Nav, signal: AbortSignal): View {
  let r = r0;
  const out: View = { update: () => false, refresh: async () => { await load(); } };
  // the reader's own checks, over preselection; kept across filter changes, cleared by an accept
  const chosen = new Map<string, boolean>();
  let data: Data | null = null;

  // the screen's parts are built once and drawn again in place with each load and each change of
  // scope, so a refresh after a write keeps the reader's scroll, focus and checks (UI-RULES 14)
  const strip = onTheWay(signal);
  const chips = el("div", { class: "chips" });
  const lowBox: HTMLInputElement = el("input", { type: "checkbox", "data-testid": "hint-low-toggle",
    onchange: () => nav(hintsRoute({ ...scopeOf(r), low: lowBox.checked })) });
  const lowCount = el("span", { class: "muted", "data-testid": "hint-low-count" });
  const filters = el("div", { class: "filters" }, el("label", { class: "label lowtoggle" }, lowBox, "Show unclear"), lowCount);
  const igs = el("div", { class: "igs" });
  const left = el("div", { class: "left", "data-testid": "impact-left" });
  // the open matches in scope no agent has looked at, offered for research
  const research = scopedResearch({ all: true, small: true });
  const accept: HTMLButtonElement = el("button", { type: "button", class: "btn", "data-testid": "accept-hints", onclick: () => void doAccept() });
  const impact = el("aside", { class: "impact", "data-testid": "impact", "aria-live": "polite" },
    el("h2", {}, "If you accept the selected"), igs,
    el("div", { class: "ig" }, el("span", { class: "caps" }, "Still open after this"), left, research.el),
    accept,
    el("p", { class: "foot" }, "Nothing is written until you accept. Accepted hints become labels with the agent's note, attributed to you."));
  const hgroups = el("div", { class: "hgroups" });
  const review = el("div", { class: "review" }, hgroups, impact);
  const empty = el("div", { class: "placeholder", "data-testid": "hints-empty" }, "No pending agent hints here.");
  const main = el("div", {});
  const body = el("div", { class: "screen" }, strip, filters, main);
  let rail: Rail | null = null, railFor = "";

  // each group's box and list, and each hint's row, kept while it shows the same
  const groupEls = new Map(groups.map((g) => {
    const box: HTMLInputElement = el("input", { type: "checkbox", "aria-label": `Select every hint in ${g.title}`, "data-testid": "hint-group-toggle",
      onchange: () => { for (const h of hints.filter((x) => x.group === g.id)) { chosen.set(h.id, box.checked); rowEls.get(h.id)!.box.checked = box.checked; } refresh(); } });
    const list = el("div", { class: "hgrp", "data-testid": "hint-group", "data-group": g.id },
      el("header", {}, box, el("span", { class: "t" }, g.title), el("span", { class: "s" }, g.sub)));
    return [g.id, { box, list }] as const;
  }));
  const rowEls = new Map<string, { key: string; el: HTMLElement; box: HTMLInputElement }>();

  // what the last draw showed: the hints in scope, and the open rows that stay open after them
  let hints: HintEntry[] = [], open: OpenRow[] = [];

  const load = () => Promise.all([gateList(), api.hints()]).then(async ([list, res]) => {
    const gates = list.gates.filter((g) => !g.error);
    const states = new Map(await Promise.all(gates.map(async (g) => [g.id, await gateState(g.id)] as const)));
    if (signal.aborted) return;
    data = { list, all: res.hints, states };
    draw(true);
    out.update = (next) => { r = next as HintsRoute; draw(); return true; };
  }).catch((e) => !signal.aborted && renderShell(host, r, { title: "Agent hints", body: failed(e) }));

  // draw shows the data as last read under the route; again is a load after a write, which prices
  // research again
  function draw(again = false) {
    const d = data!, scope = scopeOf(r), shown = inScope(d.all, scope);
    hints = shown.hints;
    const gates = d.list.gates.filter((g) => !g.error && (!scope.gate || g.id === scope.gate));
    const vocab = [...d.states.values()].find((s) => s.vocabulary)?.vocabulary;

    // the image filter: every image in the gates in scope, counting the hinted rows on each
    const byImage = new Map<string, Set<string>>();
    for (const h of inScope(d.all, { ...scope, image: undefined }).hints) for (const x of h.rows) {
      byImage.set(x.image.slug, (byImage.get(x.image.slug) ?? new Set()).add(x.row));
    }
    const images = new Map<string, RailImage>();
    for (const g of gates) g.subjects.forEach((s) => images.has(s.slug) || images.set(s.slug, { name: s.name, slug: s.slug, ref: s.ref ?? s.name, counts: { ...noCounts, total: byImage.get(s.slug)?.size ?? 0 } }));
    const img = scope.image ? images.get(scope.image) ?? null : null;
    // the rail is made again only when the gate scope changes its images
    const slugs = [...images.keys()].join(" ");
    if (!rail || railFor !== slugs) {
      rail = imageRail({ images: [...images.values()], selected: img?.slug ?? null, scope: "hints", onSelect: (slug) => nav(hintsRoute({ ...scopeOf(r), image: slug ?? undefined })) });
      railFor = slugs;
    } else {
      rail.images([...images.values()]);
      rail.select(img?.slug ?? null);
    }

    const chip = (gate: string | undefined, text: string, n: number) => el("a", { class: "chip", href: hintsHref({ ...scope, gate }), "aria-pressed": String(scope.gate === gate),
      "data-testid": "hint-gate-chip", "data-gate": gate ?? "" }, text, el("b", {}, String(n)));
    const scopedAll = inScope(d.all, { ...scope, gate: undefined }).hints;
    fill(chips, chip(undefined, "All gates", scopedAll.length),
      d.list.gates.filter((g) => !g.error).map((g) => chip(g.id, g.id, scopedAll.filter((h) => h.gates.some((x) => x.gate === g.id)).length)));

    lowBox.checked = !!scope.low;
    fill(lowCount, shown.low ? `${plural(shown.low, "unclear hint")} hidden` : scope.low ? "" : "no unclear hints");

    // the hint rows, each kept while its hint reads the same, checked as the reader left it
    const shownGroups: HTMLElement[] = [];
    for (const g of groups) {
      const hs = hints.filter((h) => h.group === g.id), ge = groupEls.get(g.id)!;
      if (!hs.length) continue;
      place(ge.list, [ge.list.firstElementChild!, ...hs.map((h) => hintEl(h, vocab))]);
      shownGroups.push(ge.list);
    }
    for (const h of hints) rowEls.get(h.id)!.box.checked = chosen.get(h.id) ?? preselected(h);
    place(hgroups, shownGroups);
    place(main, [hints.length ? review : empty]);

    research.set({ level: "research", ...(scope.image ? { scope: `image:${scope.image}` } : scope.gate ? { scope: `gate:${scope.gate}` } : {}), filters: {} },
      (n) => `the ${n} with no job`, again);

    renderShell(host, r, {
      title: "Agent hints",
      sub: hints.length ? `${plural(hints.length, "hint")} on ${plural(rowCount(hints), "match", "matches")} · ${uniq(hints.map((h) => h.skill || h.author.skill || "agent")).join(", ")}` : undefined,
      actions: chips,
      rail,
      scope: img && { label: imageName(img.name, img.ref), clear: () => nav(hintsRoute({ ...scopeOf(r), image: undefined })) },
      body,
    });
    out.key = (e) => rail!.key(e);

    // the open rows in scope, for what stays open
    open = gates.flatMap((g) => gateRows(d.states.get(g.id)!)
      .filter((x) => x.row && isOpen(x) && (!scope.image || x.image.slug === scope.image))
      .map((x) => ({ gate: g.id, row: x.row!, vuln: x.vuln, pkg: x.pkg, research: x.research })));
    refresh();
  }

  // hintEl is a hint's row, made again only when the hint reads differently
  function hintEl(h: HintEntry, vocab: Vocabulary | undefined) {
    const key = JSON.stringify(h), have = rowEls.get(h.id);
    if (have?.key === key) return have.el;
    const box: HTMLInputElement = el("input", { type: "checkbox", "aria-label": `Accept ${h.rows[0]?.vulnerability ?? h.id}`, "data-testid": "hint-check",
      onchange: () => { chosen.set(h.id, box.checked); refresh(); } });
    const row = hintRow(h, box, vocab);
    rowEls.set(h.id, { key, el: row, box });
    return row;
  }

  let seq = 0, timer: ReturnType<typeof setTimeout> | undefined;
  const selected = () => hints.filter((h) => rowEls.get(h.id)?.box.checked);

  // refresh shows what the selection does: the group boxes, Accept, what stays open, and (a little
  // later, as the checks settle) each touched gate's preview
  function refresh() {
    const sel = selected(), ids = new Set(sel.map((h) => h.id));
    for (const g of groups) {
      const all = hints.filter((h) => h.group === g.id), n = all.filter((h) => ids.has(h.id)).length, box = groupEls.get(g.id)!.box;
      box.checked = all.length > 0 && n === all.length;
      box.indeterminate = n > 0 && n < all.length;
    }
    const rows = rowCount(sel);
    fill(accept, sel.length ? `Accept ${plural(sel.length, "hint")} on ${plural(rows, "match", "matches")}` : "Select hints to accept");
    accept.disabled = !sel.length;
    accept.dataset.hints = String(sel.length);
    accept.dataset.rows = String(rows);
    const items = stillOpen(open, hints, ids);
    fill(left, items.length ? [items.slice(0, 8).map((x) => el("div", { class: "it", "data-testid": "impact-left-item" }, el("span", {}, x.text),
      el("small", {}, `${x.gates.join(", ")} · `, x.job
        ? el("span", { class: `rs ${x.job.kind === "running" ? "run" : "q"}`, "data-testid": "impact-left-job", "data-state": x.job.kind }, [x.job.word, x.job.small].filter(Boolean).join(" "))
        : x.why))),
      items.length > 8 && el("small", {}, `and ${items.length - 8} more`)] : el("span", { class: "muted" }, "Nothing in scope."));
    clearTimeout(timer);
    timer = setTimeout(() => void previewAll(sel), 150);
  }

  // previewAll runs each touched gate's preview with the selection's labels there
  async function previewAll(sel: HintEntry[]) {
    const mine = ++seq, labels = previewLabels(sel);
    if (!labels.size) { fill(igs, el("p", { class: "muted" }, "Select hints to see what they do to each gate.")); return; }
    try {
      const res = await Promise.all([...labels].map(async ([gate, l]) => [gate, await api.preview(gate, l)] as const));
      if (mine !== seq || signal.aborted) return;
      fill(igs, res.map(([gate, after]) => impactGate(gate, data!.states.get(gate)?.gate?.result, after)));
    } catch (e) {
      if (mine === seq && !signal.aborted) fill(igs, el("p", { class: "muted" }, `Couldn't preview: ${(e as Error).message}`));
    }
  }

  async function doAccept() {
    const ids = selected().map((h) => h.id);
    if (!ids.length) return;
    accept.disabled = true;
    try {
      const res = await api.acceptHints(ids);
      written(`✦ ${plural(res.written.length, "label")} written from ${plural(ids.length, "hint")}${res.skipped.length ? `, ${plural(res.skipped.length, "match", "matches")} skipped` : ""}`, res.labels);
      // the reader's checks go with an accept that worked; a failed one keeps them for another try
      chosen.clear();
    } catch (e) {
      writeFailed(e);
    }
    changed();
  }

  renderShell(host, r, { title: "Agent hints", body: loading() });
  load();
  return out;
}

// onTheWay is the strip saying more hints are coming while research is in flight, with the way to
// the jobs; it follows the top bar's reads of the jobs
function onTheWay(signal: AbortSignal) {
  const strip = el("div", { class: "strip", hidden: true, "data-testid": "hints-on-the-way" });
  const draw = (s: ResearchJobsSummary) => {
    strip.hidden = !busy(s);
    const doing = [s.running && `${s.running} researching`, s.queued && `${s.queued} queued`].filter(Boolean).join(", ");
    fill(strip, el("span", { class: "rs run" }, `${s.running + s.queued} more on the way`),
      el("span", { class: "quiet" }, [doing, s.secondsLeft && about(s.secondsLeft)].filter(Boolean).join(" · ")),
      el("span", { class: "sp" }), el("a", { class: "lk", href: "/ui/research/jobs", "data-testid": "hints-jobs" }, "View jobs"));
  };
  const was = latest();
  if (was) draw(was.summary);
  onJobs((j) => { if (signal.aborted) return false; draw(j.summary); });
  void kick();
  return strip;
}

// byLine is what accepting the hint makes its row (a TP or FP hint), else the side that reports it,
// and the gates it's in
function byLine(dir: string, v: string, gates: string[]): Child[] {
  const o = v === "tp" || v === "fp" ? outcome(dir, v, true) : null;
  const where = `in ${andList(gates)}`;
  if (o) return ["accepting makes it ", o, ` · ${where}`];
  return [[sideWords[dir], where].filter(Boolean).join(" · ")];
}

// hintRow is one hint: what it is about, what it says and why, and what it does per gate
function hintRow(h: HintEntry, box: HTMLInputElement, vocab: Vocabulary | undefined) {
  const first = h.rows[0], gates = h.gates.map((g) => g.gate);
  const pkgs = uniq(h.rows.map((x) => x.package.name)), imgs = uniq(h.rows.map((x) => x.image.name));
  const rows = h.rows.length > 1 ? plural(h.rows.length, "match", "matches") : "";
  const replaced = h.rows.find((x) => x.label)?.label;
  return el("label", { class: "hrow", "data-testid": "hint-item", "data-hint": h.id, "data-group": h.group, "data-verdict": h.verdict, "data-confidence": h.confidence ?? "", "data-replaces": h.replaces },
    box,
    el("div", { class: "what" },
      el("div", { class: "v" }, first?.vulnerability ?? h.id, " ", el("small", {}, [h.kind === "cause" ? "package hint" : "", rows].filter(Boolean).join(" · "))),
      el("div", { class: "pk", title: `${pkgs.join(", ")} · ${imgs.join(", ")}` }, `${pkgs.join(", ")} ${first?.package.version ?? ""} · ${imgs.join(", ")}`),
      el("div", { class: "by" }, byLine(first?.direction ?? "", h.verdict, gates))),
    el("div", { class: "says" },
      el("div", {}, verdict(h.verdict), " ", el("span", { class: "conf", title: `${h.confidence || "no"} confidence` }, dots[h.confidence ?? ""] ?? "")),
      el("div", { class: "why" }, h.title || h.cause || vocab?.justifications?.[h.verdict]?.[h.justification ?? ""] || h.justification || words[h.verdict].long),
      el("small", {}, [h.justification, h.skill || h.author.skill].filter(Boolean).join(" · "))),
    el("div", { class: "fx" },
      h.gates.map((g): Child => (g.after !== g.outcome
        ? el("span", { class: "could-move" }, `${g.gate} ${g.outcome} → ${g.after}`)
        : el("span", {}, `${g.gate}: closes ${plural(g.rows.length, "open match", "open matches")}`))),
      h.replaces && el("span", { class: "flag", "data-testid": "hint-replaces" },
        `replaces ${replaced ? `${replaced.verdict === "tp" ? "a" : "an"} ${words[replaced.verdict].word} label` : "a label"}${replaced?.note ? `: "${replaced.note}"` : ""}`),
      h.replaces && el("small", {}, "left unchecked: it overrides a person")));
}

// impactGate is a gate before and after the selection, and each of its checks
function impactGate(gate: string, before: GateResult | undefined, after: GateResult) {
  const was = before?.outcome ?? "undecided", now = after.outcome;
  const prior = new Map((before?.checks ?? []).map((c) => [c.name, c.state]));
  return el("div", { class: "ig", "data-testid": "impact-gate", "data-gate": gate, "data-before": was, "data-after": now },
    el("div", { class: "gname" }, status(was), el("span", { class: "arrow" }, "→"), status(now), el("span", {}, gate)),
    after.checks.map((c) => {
      const b = prior.get(c.name) ?? c.state;
      return el("div", { class: "ck", "data-testid": "impact-check", "data-check": c.name, "data-before": b, "data-after": c.state },
        el("span", { class: "cn", title: c.name }, c.name),
        el("span", {}, b === c.state ? stateWord(c.state) : [stateWord(b), " → ", stateWord(c.state)]));
    }));
}

// railHints puts hint review's ways in on a gate's image rail: "Review all N hints" in its head, and
// under each image with hints, how many on how many rows, the ones replacing a label, and "Accept…",
// which opens review scoped to that image (accepting always goes through review)
export function railHints(rail: Rail, gate: string) {
  api.hints().then((res) => {
    // with none, a rail drawn again after a write takes the old ones away
    const { hints } = inScope(res.hints, { gate });
    const per = imageHints(hints, gate);
    rail.hints(
      hints.length > 0 && el("a", { class: "btn", "data-variant": "outline", "data-size": "sm", href: hintsHref({ gate }), "data-testid": "rail-review-all" }, `Review all ${plural(hints.length, "hint")}`),
      (slug) => {
        const x = per.get(slug);
        return x && [
          el("span", { class: "hint", "data-testid": "rail-hints" }, `${plural(x.hints, "hint")} on ${plural(x.rows, "match", "matches")}`),
          x.replaces > 0 && el("span", { class: "flag", "data-testid": "rail-replaces" }, `${x.replaces} ${x.replaces === 1 ? "overrides" : "override"} a label`),
          el("a", { class: "btn", "data-variant": "outline", "data-size": "sm", href: hintsHref({ gate, image: slug }), "data-testid": "rail-accept", "data-image": slug }, "Accept…"),
        ];
      });
  }).catch((e) => toast(`Couldn't load the agent hints: ${(e as Error).message}`, true));
}
