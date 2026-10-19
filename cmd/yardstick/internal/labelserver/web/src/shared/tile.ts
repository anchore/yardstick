// tile.ts is the Focus tile: everything that renders one finding, ported from delta. The page keeps
// its own layout, ordering, URLs and keys and calls render(container, ctx). ctx carries the run's
// state, the row, the check being worked on, the page's toggles and caches, and the actions the
// buttons call.
//
// receipt is { text, plain?, from? }: set it once per label and keep the same object across
// re-renders. canStay says the page honours autoAdvance() (false: stay on the labeled match after
// a label), and shows the switch for it.
import type { CheckResult, MatchesResponse, RowResponse, State, StateCause, claimsv1 } from "../gen/wire";
import * as api from "./api";
import { agent } from "./agent";
import { $, el, fill, toast } from "./dom";
import { endsGate } from "./gate";
import { matchPath, records } from "./matchpath";
import { type Release, imageRelease, releaseHuman } from "./names";
import { type Dir, hinted, matchName, pkgOf, type Row } from "./rows";
import { dirWords, firstSentence, justWords, labels, marks, ruleWords, whyText } from "./words";

export interface Receipt { text: string; plain?: boolean; from?: Row }

export interface TileCtx {
  state: State;
  gateName: string;
  r: Row;
  si: number;
  dir: Dir;
  check: CheckResult | null | undefined;
  reexamine: boolean;
  tierName: string | null;
  counter: string;
  receipt: Receipt | null;
  backKey: string;
  canStay: boolean;
  why: boolean;
  more: boolean;
  note: string;
  matches: Map<string, MatchesResponse>;
  details: Map<string, RowResponse>;
  subjectName: (si: number) => string;
  on: {
    label: (verdict: string, justification?: string) => void;
    accept: (rows: string[]) => void;
    acceptCause: (cause: StateCause) => void;
    research: (rows: string[]) => void;
    toggleWhy: () => void;
    toggleMore: () => void;
    note: (text: string) => void;
    skip?: () => void;
  };
}

let shown: string | null = null; // the row id on screen, so late fetches don't paint over the next finding

// ---------- what a label does ----------

// effects is the glossary's fixed/introduced table: what a TP or FP label on a delta says about
// the candidate. A match both scans report has no entry: its label fixes or introduces nothing.
const effects: Record<string, Record<string, string>> = {
  added: { tp: "fixed a false negative", fp: "introduced a false positive" },
  dropped: { tp: "introduced a false negative", fp: "fixed a false positive" },
};

// effect is the first line of the label box: a fact about the candidate, not about the gate. A
// TP or FP label states the one that applies; otherwise it says what each label would mean.
function effect(ctx: TileCtx) {
  const { r, dir, check: c } = ctx, e = effects[dir];
  if (!e) return null;
  if (r.verdict === "tp" || r.verdict === "fp") {
    return el("div", { class: "effect fact" }, el("b", {}, `The candidate ${e[r.verdict]}`),
      ctx.reexamine && c ? el("span", { class: "muted" }, ` · ${c.name} fails on this label; relabel it if it's wrong`) : null);
  }
  const half = (v: string, lead: string) => el("span", { class: "eff", id: `eff-${v}` }, "If ", el("span", { class: `v-${v}` }, `${labels[v].glyph} ${labels[v].word}`), `: ${lead} ${e[v]}`);
  return el("div", { class: "effect" }, half("tp", "the candidate"), el("span", { class: "muted" }, " · "), half("fp", "it"));
}
// preview lights the half of the effect line that the hovered or focused button would make true
function preview(v: string | null) {
  for (const k of ["tp", "fp"]) $(`#eff-${k}`)?.classList.toggle("lit", k === v);
}

// ---------- after labeling: the receipt and whether to move on ----------

// autoAdvance is the reader's standing choice, kept in localStorage: after a label, move to the
// next match (the default) or stay on the one just labeled. Pages that honour it pass canStay.
const advanceKey = "yardstick.autoAdvance";
export const autoAdvance = () => localStorage.getItem(advanceKey) !== "off";
export const setAutoAdvance = (on: boolean) => (on ? localStorage.removeItem(advanceKey) : localStorage.setItem(advanceKey, "off"));

// A page sets ctx.receipt = { text } once per label and keeps that object while it re-renders.
// The tile remembers which row was on screen when a receipt's page moved to another, so the
// receipt can name both the match labeled and the one now shown, for as long as it stands.
let shownRow: Row | null = null;
const receiptFrom = new WeakMap<Receipt, Row>();
function receipt(ctx: TileCtx, prev: Row | null) {
  const { r, receipt: rc } = ctx;
  const counter = el("div", { class: "receipt muted" }, ctx.counter || "", ctx.tierName ? ` · ${ctx.tierName}` : "");
  if (!rc) return counter;
  if (rc.from == null && !receiptFrom.has(rc) && prev && prev.id !== r.id) receiptFrom.set(rc, prev);
  const from = rc.from || receiptFrom.get(rc);
  const what = rc.text.replace(/ recorded\b/, "");
  const bar = rc.plain ? el("div", { class: "receipt bar", role: "status" }, el("b", {}, rc.text))
    : from ? el("div", { class: "receipt bar moved", role: "status" }, "Labeled ", el("b", {}, matchName(from)), `: ${what}`, el("span", { class: "sep" }, " · "), "now on ", el("b", {}, matchName(r)),
      ctx.backKey ? [el("span", { class: "sep" }, " · "), "back ", el("kbd", {}, ctx.backKey)] : null)
      : el("div", { class: "receipt bar", role: "status" }, "Labeled ", el("b", {}, matchName(r)), `: ${what}`, ctx.on.skip ? [el("span", { class: "sep" }, " · "), "next ", el("kbd", {}, "j")] : null);
  return [bar, counter];
}
// advanceToggle is the standing "after labeling, go to the next match" switch
const advanceToggle = (ctx: TileCtx) => (ctx.canStay ? el("label", { class: "advance", title: "kept in this browser" },
  el("input", { type: "checkbox", checked: autoAdvance(), onchange: (e) => { const t = e.target as HTMLInputElement; setAutoAdvance(t.checked); t.blur(); } }),
  " after labeling, go to the next match") : null);

// ---------- the tile ----------

export function render(container: HTMLElement, ctx: TileCtx) {
  const { state, r, dir, on } = ctx;
  shown = r.id;
  const prev = shownRow;
  shownRow = r;
  const pk = pkgOf(r.package.ref);
  const h = hinted(r) ? r.hint : null;
  const rel = imageRelease(r);
  const cause = (r.causes || []).map((id) => (state.causes || []).find((k) => k.id === id)).find((k) => k && k.pending?.length > 1);
  const btn = (v: string, key: string) => el("button", {
    class: `btn ${v}${r.verdict === v ? " filled" : ""}${h?.verdict === v ? " hinted" : h ? " quiet" : ""}`,
    title: h?.verdict === v ? "the agent hint: accept it (a)" : labels[v].long,
    onclick: () => (h?.verdict === v ? on.accept([r.id]) : on.label(v)),
    onmouseenter: () => preview(v), onmouseleave: () => preview(null), onfocus: () => preview(v), onblur: () => preview(null),
  }, h?.verdict === v ? el("span", { class: "cap" }, "✦ agent hint") : null, el("span", { class: "lbl" }, `${labels[v].glyph} ${labels[v].word}`, el("kbd", {}, key)));
  container.classList.add("tile");
  fill(container,
    receipt(ctx, prev),
    el("div", { class: "title" },
      el("span", { class: "mark", title: dirWords[dir] }, marks[dir]),
      el("span", { class: "vuln" }, r.vulnerability),
      el("span", { class: "pkg" }, `${pk.name} ${pk.version}`),
      el("span", { class: "img" }, ctx.subjectName(ctx.si), rel ? ` · ${releaseHuman(rel)}` : ""),
      (r.aliases || []).filter((a) => a !== r.vulnerability).map((a) => el("span", { class: "alias" }, a)),
      !ctx.reexamine && endsGate(state.gate?.result?.outcome, r) ? el("span", { class: "decisive" }, "◆ a label here ends the gate") : null),
    // three sections that look different on purpose: why the scans differ (open, on the page), what
    // the agent thinks (its tinted card), and the label (one solid box: what it does, the
    // controls, who labeled it)
    el("section", { class: "sec sec-why" },
      el("h2", {}, "Why the scans differ"),
      el("div", { class: "why" }, el("b", {}, `${dirWords[dir][0].toUpperCase()}${dirWords[dir].slice(1)}`), r.why ? `: ${whyText(r.why, dir)}` : "", (r.why?.secondary || []).map((s) => ` · ${whyText(s, dir)}`)),
      el("div", { id: "path" }, matchPath(r, ctx.matches.get(r.id), rel)),
      records(r, dir, rel)),
    el("section", { class: "sec sec-agent" }, agent(ctx, h || r.hint, cause)),
    el("section", { class: "sec sec-label" },
      el("h2", {}, "Label"),
      effect(ctx),
      el("div", { class: "buttons" }, btn("tp", "t"), btn("fp", "f"), btn("unclear", "u"), on.skip ? el("button", { class: "btn skip", onclick: () => on.skip?.() }, "skip", el("kbd", {}, "j")) : null, advanceToggle(ctx)),
      picker(ctx),
      el("input", { class: "note", id: "note", placeholder: "note for the label (n)", value: ctx.note || "", oninput: (e) => on.note((e.target as HTMLInputElement).value),
        onkeydown: (e) => { if (e.key === "Escape" || e.key === "Enter") { (e.target as HTMLInputElement).blur(); e.stopPropagation(); } } }),
      r.label ? el("div", { class: "labeled", id: "labeled" }) : null),
    ctx.more ? more(ctx) : el("div", { class: "muted" }, el("button", { class: "ghost", onclick: () => on.toggleMore() }, "more evidence"), " ", el("kbd", {}, "e"), " links, the label's sources, grype's raw match"),
  );
  fillDetail(ctx);
  fillPath(ctx, rel);
}

// matchesOf is the row's raw matches, fetched once per row
async function matchesOf(ctx: TileCtx): Promise<MatchesResponse | undefined> {
  const { r } = ctx;
  let m = ctx.matches.get(r.id);
  if (!m) { try { m = await api.matches(ctx.gateName, r.id); } catch (e) { toast((e as Error).message, true); return; } ctx.matches.set(r.id, m); }
  return m;
}

// fillPath redraws the match path once grype's raw match details are here
async function fillPath(ctx: TileCtx, rel: Release | null) {
  const { r } = ctx;
  if (ctx.matches.has(r.id)) return;
  const m = await matchesOf(ctx);
  if (!m || shown !== r.id) return;
  $("#path")?.replaceChildren(matchPath(r, m, rel));
}

function more(ctx: TileCtx) {
  const { r } = ctx;
  const box = el("div", { class: "more" },
    el("h3", {}, "read more"), el("div", { class: "links", id: "links" }, el("span", { class: "muted" }, "loading…")),
    el("h3", {}, "the label, and every claims source holding it"), el("div", { class: "claims", id: "claims" }, "…"),
    el("h3", {}, "grype's raw match, and the syft artifact"), el("div", { class: "raw" }, el("pre", { id: "raw-c" }, "…"), el("pre", { id: "raw-r" }, "…"), el("pre", { id: "raw-a" }, "…")));
  (async () => {
    const m = await matchesOf(ctx);
    if (!m || shown !== r.id) return;
    const show = (id: string, v: unknown, none: string) => { const p = $(id); if (p) p.textContent = v == null || (Array.isArray(v) && !v.length) ? none : JSON.stringify(Array.isArray(v) && v.length === 1 ? v[0] : v, null, 2); };
    show("#raw-c", m.candidate, "candidate: no match"); show("#raw-r", m.reference, "reference: no match"); show("#raw-a", m.artifact, m.sbomMissing ? `SBOM not found: ${m.sbomMissing}` : "no artifact");
  })();
  return box;
}

async function fillDetail(ctx: TileCtx) {
  const { r } = ctx;
  let d = ctx.details.get(r.id);
  if (!d) { try { d = await api.row(ctx.gateName, r.id); } catch (e) { toast((e as Error).message, true); return; } ctx.details.set(r.id, d); }
  if (shown !== r.id) return;
  const { label, hint } = d;
  // who labeled it, when, how, and their note: the quiet last part of the label box
  const lb = $("#labeled");
  if (lb) {
    lb.replaceChildren(...(label ? [labelLine(ctx.state, label)] : []));
  }
  const hr = $("#hint-reason"), hn = $("#hint-note");
  if (hr && hint) {
    const rule = hint.policy?.rule, basis = rule?.basis, note = hint.proposal?.note || "";
    // the rule's title, then its basis, then the justification, then the note; a headline cut from
    // the note goes away while the whole note shows below it
    const own = rule?.title || (basis ? basis[0].toUpperCase() + basis.slice(1) : "") || justWords(ctx.state, hint.proposal?.verdict, hint.proposal?.justification);
    hr.textContent = own || (hn ? "" : firstSentence(note) || ruleWords(rule?.rule));
  }
  if (hn && hint) {
    const p = hint.proposal, pol = hint.policy;
    hn.textContent = p.note || "(no note)";
    // one fact per line: where it came from, which field, what it said
    const link = (f: claimsv1.Fact) => (/^https?:\/\//.test(f.url || "") ? el("a", { href: f.url, target: "_blank", rel: "noopener noreferrer" }, f.source) : f.source);
    const facts = (p.evidence || []).flatMap((e) => e.facts || []);
    $("#hint-facts")?.replaceChildren(...(facts.length ? facts.map((f) => el("li", {}, el("span", { class: "src" }, link(f)), el("span", { class: "fld" }, f.field || ""), el("span", { class: "val" }, f.value ?? "")))
      : [el("li", { class: "muted" }, "no recorded facts")]));
    const hru = $("#hint-rule");
    if (hru && pol?.rule) hru.textContent = `rule: ${pol.rule.basis || ruleWords(pol.rule.rule)}${pol.rule.decision ? ` · policy ${pol.rule.decision}` : ""}${pol.problems?.length ? ` · ⚠ ${pol.problems.join("; ")}` : ""}`;
  }
  const links = $("#links");
  if (links) {
    const groups = new Map<string, RowResponse["links"]>();
    for (const l of d.links || []) { let g = groups.get(l.group); if (!g) groups.set(l.group, (g = [])); g.push(l); }
    links.replaceChildren(...(groups.size ? [...groups].map(([g, ls]) => el("div", { class: "lgroup" }, el("span", { class: "grp" }, g + ": "), ls.map((l) => el("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, l.label)))) : [el("span", { class: "muted" }, "no links")]));
  }
  const cl = $("#claims");
  if (cl) {
    // a label's history is its corpus's git history; here is where it is now
    cl.replaceChildren(...(label ? [labelLine(ctx.state, label), el("div", { class: "muted" }, `${label.global ? "global · " : ""}${label.file}`),
      ...(label.sources || []).map((s) => el("div", { class: "muted" }, s))] : [el("span", { class: "muted" }, "no label yet")]));
  }
}

// labelLine is a label as its file holds it: verdict, reason, who and when, and its notes. A note
// says who and when only where that is not the label's own author, or there are several.
function labelLine(state: State, lv: NonNullable<RowResponse["label"]>) {
  const l = lv.label, notes = l.notes || [];
  const whoWhen = (n: claimsv1.Note) => notes.length > 1 || n.author !== l.author ? `${n.author} · ${new Date(n.at).toLocaleDateString()}: ` : "";
  return el("div", { class: "who" },
    el("span", { class: `v-${l.verdict}` }, `${labels[l.verdict]?.glyph || ""} ${labels[l.verdict]?.word || l.verdict}`),
    `${l.justification ? ` · ${justWords(state, l.verdict, l.justification)}` : ""} by ${l.author || "?"} · ${new Date(l.lastUpdated).toLocaleDateString()}${l.evidence?.[0]?.rule ? ` · rule: ${ruleWords(l.evidence[0].rule)}` : ""}`,
    ...notes.map((n) => el("div", { class: "lnote" }, whoWhen(n) + n.text)));
}

// picker is the justification picker: FP and unclear need one, from the claims vocabulary, and
// choosing one labels the match with its verdict. TP's are optional, so they're offered too.
function picker(ctx: TileCtx) {
  const js = ctx.state.vocabulary?.justifications || {};
  return el("select", { class: "note", id: "justification", title: "the reason for the label: choosing one labels the match",
    onchange: (e) => { const [v, j] = (e.target as HTMLSelectElement).value.split(":"); if (v) ctx.on.label(v, j); } },
  el("option", { value: "" }, "label with a reason…"),
  ...["fp", "unclear", "tp"].filter((v) => js[v]).map((v) => el("optgroup", { label: `${labels[v].glyph} ${labels[v].word}` },
    ...Object.entries(js[v]).sort().map(([j, desc]) => el("option", { value: `${v}:${j}` }, `${labels[v].word} · ${desc}`)))));
}
