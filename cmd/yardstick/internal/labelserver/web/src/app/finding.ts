// finding.ts is level 3, one finding: the title row (ID, label, effect), the content on the left in
// tabs (why the scans differ, evidence, grype's raw match, the labels on file), the label panel
// sticky on the right, and j / k through the list the URL's filters name. The content is the old
// map page's tile, reorganized.
import type { claimsv1, LabelKey } from "../gen/wire";
import * as api from "../shared/api";
import { el, toast, type Child } from "../shared/dom";
import { records, matchPath } from "../shared/matchpath";
import { imageRelease, releaseName } from "../shared/names";
import { decoded, direction, pkgOf } from "../shared/rows";
import { dirWords, justWords, labels, plural, ruleWords, whyText } from "../shared/words";
import { kick } from "./activity";
import { forget, written } from "./data";
import { loadFinding, researching, type FindingData } from "./finding-data";
import { effect, mutedReason, pendingCause, seenWith, shortSource, type Dir } from "./finding-words";
import { labelPanel, type Draft, type LabelPanel } from "./labelpanel";
import type { GateLines } from "./queuewords";
import { nextOpen, position, type Item } from "./neighbors";
import { formatRoute, type Route } from "./route";
import { advancing } from "./settings";
import { renderShell, type Nav, type View } from "./shell";
import { step, verdict, type Verdict } from "./ui";

type FindingRoute = Extract<Route, { level: "finding" }>;

// QueueMode is the queue's hold on the page (queue.ts): its bar, why the row is next, the outcome
// lines under the verdicts, and where j / k, Skip and Save and next go
export interface QueueMode {
  route: Route;                                  // the queue's own, which the page stays live on
  bar: Child;
  prefs: () => void;                             // a setting in the cog changed: redraw the bar
  why: Child;
  outcomes: GateLines | undefined;
  step: (dir: 1 | -1, all: boolean) => void;     // j / k, Skip, and ⌥j / ⌥k over every row
  next: (rows: string[], text: string, how: "hint" | "hand", keys: LabelKey[]) => Promise<void>;
  key: (e: KeyboardEvent) => boolean;            // n, Esc
}

// the tab is the reader's standing choice, kept in this browser
const tabKey = "yardstick.findingTab";
const tabIds = ["why", "evidence", "raw", "labels"] as const;
type Tab = (typeof tabIds)[number];
function savedTab(): Tab {
  try {
    const t = localStorage.getItem(tabKey) as Tab;
    return tabIds.includes(t) ? t : "why";
  } catch { return "why"; }
}
function saveTab(t: Tab) { try { localStorage.setItem(tabKey, t); } catch { /* no storage: the tab resets next time */ } }

const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));
let current = 0; // the newest load anywhere on the page; an older one finishing late doesn't paint
let views = 0;   // the newest finding view; research polling stops when its view is gone
// the last list loaded, so j and k pressed again before the next finding loads still walk it
let lastList: { key: string; items: Item[] } | null = null;

export function findingView(host: HTMLElement, r: FindingRoute, nav: Nav, q?: QueueMode): View {
  const gen = ++views, path = formatRoute(q?.route ?? r).split("?")[0];
  // live is this view still on screen: no newer finding view, and the URL still names this row
  const live = () => gen === views && location.pathname === path;
  const listKey = formatRoute({ ...r, row: "" });
  let d: FindingData | null = null;
  let lp: LabelPanel | null = null;
  const draft: Draft = { note: "" };
  const at = (row: string): Route => ({ ...r, row });
  const go = (row: string | undefined, none: string) => (row ? nav(at(row)) : toast(none));

  async function load() {
    const mine = ++current;
    // this page writes and researches outside data.ts, so the lists read fresh after it
    forget();
    try {
      const next = await loadFinding(r.gate, r.row, r.check, r.filters);
      if (mine !== current || !live()) return;
      d = next;
      lastList = { key: listKey, items: next.list };
      paint();
      if (researching(next.row)) void follow();
    } catch (e) {
      if (mine !== current || !live()) return;
      renderShell(host, r, { title: "Not found", body: el("div", { class: "placeholder", "data-testid": "placeholder" }, (e as Error).message) });
    }
  }

  function paint() {
    if (!d) return;
    const { row, state } = d;
    const dir = direction(row) as Dir, pk = pkgOf(row.package.ref);
    // the release is called out only for a distro package: a language package in the same image
    // isn't matched against it
    const rel = /[?&]distro=/.test(row.package.ref) ? imageRelease(row) : null;
    const eff = effect({ check: r.check, checkEffect: d.checkEffect, row, checks: state.gate?.result?.checks ?? [] });
    // the pager counts what j and k walk: the list's open rows, or every row when none is open
    const pos = position(d.list, row.id), of = `${pos.total}${pos.open ? " open" : ""}`;
    const where = pos.index >= 0 ? `${pos.index + 1} of ${of}` : `${d.list.some((x) => x.id === row.id) ? "labeled" : "not in this list"} · ${of}`;
    const pager = el("span", { class: "pager", "data-testid": "pager", "data-index": pos.index + 1, "data-total": pos.total, "data-open": pos.open },
      pageLink(pos.prev, "previous"), where, pageLink(pos.next, "next"));
    const aliases = (row.aliases ?? []).filter((a) => a !== row.vulnerability);
    lp = labelPanel(d, draft, advancing(), { save, accept, acceptAll, skip: () => (q ? q.step(1, false) : go(pos.next, "last one in this list")), research, cancelResearch }, q?.outcomes);
    renderShell(host, r, {
      title: row.vulnerability,
      row: row.vulnerability,
      after: [
        verdict(row.verdict as Verdict),
        eff && el("span", { class: eff.kind === "could-move" ? "could-move" : "decides", "data-testid": "finding-effect", "data-effect": eff.kind }, eff.text),
      ],
      // what was matched (package, its ecosystem, the distro release, which decides most of the
      // matching), then where: the image, and which side reports it with what the candidate did
      sub: el("span", { class: "fsub", "data-testid": "finding-sub" },
        el("span", { class: "fline" },
          el("span", { class: "mono pkgv", "data-testid": "finding-package", title: row.package.ref }, el("b", {}, pk.name), " ", el("span", { class: "ver" }, pk.version)),
          pk.type && el("span", { class: "ptype" }, pk.type),
          rel && el("span", { class: "distro", "data-testid": "finding-distro", title: `${rel.distro} ${rel.version}` }, el("span", { class: "dk" }, "distro"), releaseName(rel))),
        el("span", { class: "fline" },
          el("span", { class: "img", title: d.image.ref, "data-testid": "finding-image" }, d.image.name),
          sides(dir),
          aliases.length ? el("span", {}, `alias ${aliases.join(", ")}`) : "")),
      crumbEnd: q ? null : pager,
      bar: q?.bar,
      prefs: () => { lp?.advance(advancing()); q?.prefs(); },
      meta: state.scans.gate,
      body: el("div", { class: "finding", "data-testid": "finding", "data-row": row.id, "data-verdict": row.verdict },
        el("div", { class: "fcontent" }, q?.why, tabs(d)), lp.el),
    });
  }

  // sides reads left to right, reference then candidate: a solid box reports the match, a dashed
  // one doesn't, and the words say what that makes it
  function sides(dir: Dir) {
    const side = (name: string, on: boolean) => el("span", { class: `side${on ? " on" : ""}` }, el("i", {}, on ? "●" : "○"), name);
    return el("span", { class: "sides" },
      side("reference", dir === "dropped" || dir === "both"), "→", side("candidate", dir === "added" || dir === "both"),
      el("span", { class: "said", "data-testid": "finding-direction", "data-dir": dir }, dirWords[dir]));
  }

  function pageLink(row: string | undefined, way: "previous" | "next") {
    return step(row && formatRoute(at(row)), way, `pager-${way}`);
  }

  // ---------- writes ----------

  // after moves on to the next open finding of the list when the switch is on, else redraws this one
  async function after(rows: string[], text: string, how: "hint" | "hand", keys: LabelKey[]) {
    const list = d?.list ?? [];
    Object.assign(draft, { verdict: undefined, reason: undefined, note: "" });
    if (q && advancing()) return q.next(rows, text, how, keys);
    const next = advancing() ? nextOpen(list, r.row, rows) : undefined;
    if (next) { written(text, keys); nav(at(next)); return; }
    written(advancing() ? `${text} · nothing left to label in this list` : text, keys);
    await load();
  }
  async function write(rows: string[], text: string, call: () => Promise<{ labels: LabelKey[] }>, how: "hint" | "hand" = "hint") {
    let keys: LabelKey[];
    try { keys = (await call()).labels; } catch (e) { toast((e as Error).message, true); return; }
    await after(rows, text, how, keys);
  }
  const said = (v: string) => `${labels[v]?.glyph ?? ""} ${labels[v]?.word ?? v}`;

  function save() {
    if (!d) return;
    const v = draft.verdict;
    if (!v) return toast("pick TP, FP or Unclear first (t, f, u)");
    if (v !== "tp" && !draft.reason) { lp?.focusReason(); return toast(`${labels[v].word} needs a reason: pick one`); }
    const id = d.row.id;
    void write([id], `${d.row.vulnerability}: ${said(v)}${draft.reason ? ` · ${justWords(d.state, v, draft.reason)}` : ""}`,
      () => api.labels(r.gate, { rows: [id], verdict: v, justification: draft.reason ?? "", note: draft.note, scope: "subject" }), "hand");
  }
  // accept takes the row's own hint, else accepts its cause for this row alone
  function accept() {
    if (!d) return;
    const { row, state } = d, id = row.id;
    const cause = pendingCause(state.causes, id);
    if (row.hint?.status === "pending" && ["unlabeled", "unclear"].includes(row.verdict)) {
      void write([id], `${row.vulnerability}: ${said(row.hint.verdict)}, the ✦ agent hint accepted`, () => api.accept(r.gate, [id]));
    } else if (cause) {
      void write([id], `${row.vulnerability}: ${said(cause.verdict)}, the ✦ package hint accepted`, () => api.acceptCause(r.gate, cause.id, [id]));
    } else toast("no agent hint to accept here");
  }
  function acceptAll(c = d && pendingCause(d.state.causes, d.row.id)) {
    if (!c) return toast("no package hint to accept here");
    void write(c.pending, `${said(c.verdict)}, the ✦ package hint accepted on ${plural(c.pending.length, "match", "matches")}`, () => api.acceptCause(r.gate, c.id, c.pending));
  }

  // research starts an agent on this row and redraws while it runs, so its hint shows up here
  async function research() {
    if (!d) return;
    const off = d.state.research && !d.state.research.available ? d.state.research : null;
    if (off) return toast(`research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}`, true);
    try { await api.research(r.gate, { rows: [d.row.id], from: "finding" }); } catch (e) { return toast((e as Error).message, true); }
    toast("research started; what it finds arrives as an agent hint");
    void kick();
    await load();
    await follow();
  }
  // follow redraws while a job is queued or running on the row, however it was started
  let following = false;
  async function follow() {
    if (following) return;
    following = true;
    for (let i = 0; i < 300 && d && researching(d.row) && live(); i++) {
      await sleep(2000);
      if (live()) await load();
    }
    following = false;
  }
  async function cancelResearch() {
    if (!d) return;
    try {
      const res = await api.cancelResearch(r.gate, [d.row.id]);
      toast(res.cancelled.length ? "research cancelled" : res.notCancelled[0]?.why ?? "nothing to cancel");
    } catch (e) { return toast((e as Error).message, true); }
    void kick();
    await load();
  }

  // ---------- keys (UI-RULES: the same at every level) ----------

  function key(e: KeyboardEvent): boolean {
    // in the queue, j and k walk the queue, and Enter saves unless a control has the focus
    if (q) {
      if (e.altKey && (e.code === "KeyJ" || e.code === "KeyK")) { q.step(e.code === "KeyJ" ? 1 : -1, true); return true; }
      if (e.key === "j" || e.key === "k") { q.step(e.key === "j" ? 1 : -1, false); return true; }
      const t = e.target as Element;
      if (e.key === "Enter" && d && (t === document.body || t.closest?.("[data-testid=verdict-button]"))) { save(); return true; }
      if (q.key(e)) return true;
    }
    const list = d?.list ?? (lastList?.key === listKey ? lastList.items : null);
    if (!list) return false;
    // ⌥j and ⌥k walk every row, labeled or not; e.code, since ⌥ changes e.key on a Mac
    if (e.altKey) {
      const pos = position(list, r.row, true);
      if (e.code === "KeyJ") { go(pos.next, "last one in this list"); return true; }
      if (e.code === "KeyK") { go(pos.prev, "first one in this list"); return true; }
      return false;
    }
    const pos = position(list, r.row);
    switch (e.key) {
      case "j": go(pos.next, "last one in this list"); return true;
      case "k": go(pos.prev, "first one in this list"); return true;
    }
    if (!d) return false;
    switch (e.key) {
      case "t": lp?.pick("tp"); return true;
      case "f": lp?.pick("fp"); lp?.focusReason(); return true;
      case "u": lp?.pick("unclear"); lp?.focusReason(); return true;
      case "a": accept(); return true;
      case "A": acceptAll(); return true;
      case "R": void research(); return true;
    }
    return false;
  }

  void load();
  return { key };
}

// ---------- the content tabs ----------

function tabs(d: FindingData) {
  const n = d.detail.label?.sources?.length ?? (d.detail.label ? 1 : 0);
  const words: Record<Tab, string> = { why: "Why it differs", evidence: "Evidence", raw: "Raw match", labels: `Labels on file (${n})` };
  const body: Record<Tab, () => HTMLElement> = { why: () => whyTab(d), evidence: () => evidenceTab(d), raw: () => rawTab(d), labels: () => labelsTab(d) };
  let cur = savedTab();
  const buttons = tabIds.map((t) => el("button", { type: "button", role: "tab", id: `ft-${t}`, "aria-controls": `fp-${t}`, "aria-selected": String(t === cur), "data-tab": t, onclick: () => show(t) }, words[t]));
  const panels = tabIds.map((t) => el("div", { role: "tabpanel", id: `fp-${t}`, "aria-labelledby": `ft-${t}`, hidden: t !== cur, "data-testid": `tab-${t}` }, body[t]()));
  function show(t: Tab) {
    cur = t;
    saveTab(t);
    buttons.forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === t)));
    panels.forEach((p) => (p.hidden = p.id !== `fp-${t}`));
  }
  return el("div", { class: "tabs ftabs", "data-testid": "finding-tabs" }, el("nav", { role: "tablist", "data-variant": "line", "aria-orientation": "horizontal", "aria-label": "About this match" }, buttons), panels);
}

const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const kv = (pairs: [string, unknown][]) =>
  el("dl", { class: "kv" }, pairs.filter(([, v]) => v != null && v !== "").map(([k, v]) => [el("dt", {}, k), el("dd", {}, v as string | Node)]));

// whyTab is today's "why the scans differ": the computed reason, both sides' match path, what the
// other DB holds for the package elsewhere, and the match's identity in full
function whyTab(d: FindingData) {
  const { row } = d, dir = direction(row), rel = imageRelease(row);
  const flips = row.gate?.couldFlip ?? [], bears = (row.gate?.bears ?? []).filter((c) => !flips.includes(c));
  return el("div", { class: "why" },
    el("p", { "data-testid": "why-text" }, el("b", {}, cap(dirWords[dir])), row.why ? `: ${whyText(row.why, dir)}` : "", (row.why?.secondary ?? []).map((s) => ` · ${whyText(s, dir)}`)),
    el("div", { class: "lanes", "data-testid": "match-path" }, matchPath(row, d.matches ?? undefined, rel)),
    records(row, dir, rel),
    kv([
      ["Package", el("span", { class: "mono", title: row.package.ref, "data-testid": "finding-purl" }, decoded(row.package.ref))],
      ["Image", el("span", { class: "mono", "data-testid": "finding-ref" }, d.image.ref)],
      ["Location", row.location && el("span", { class: "mono" }, row.location)],
      ["Could flip", flips.join(", ")],
      ["Also bears on", bears.join(", ")],
    ]));
}

// evidenceTab is where to read more, grouped as the server groups the links (the records the DBs
// cited, lookups, the distro's tracker), and an agent's explanation of the change if there is one
function evidenceTab(d: FindingData) {
  const groups = new Map<string, typeof d.detail.links>();
  for (const l of d.detail.links ?? []) groups.set(l.group, [...(groups.get(l.group) ?? []), l]);
  const x = d.detail.explanation;
  return el("div", { class: "evidence", "data-testid": "evidence-links" },
    groups.size === 0 && el("p", { class: "muted" }, "No links for this match."),
    [...groups].map(([g, ls]) => el("section", {}, el("h3", {}, g),
      el("ul", { class: "links" }, ls.map((l) => el("li", {}, el("a", { href: l.url, target: "_blank", rel: "noopener noreferrer" }, l.label)))))),
    x && el("section", { class: "explanation", "data-testid": "explanation" },
      el("h3", {}, "Agent explanation"),
      el("p", {}, el("b", {}, x.title)),
      x.note && el("p", {}, x.note),
      x.facts?.length ? el("ul", { class: "links" }, x.facts.map((f) => el("li", {}, factLine(f)))) : null,
      x.openQuestions?.length ? [el("p", { class: "help" }, "Open questions"), el("ul", {}, x.openQuestions.map((q) => el("li", {}, q)))] : null,
      el("p", { class: "help" }, `✦ ${x.author.skill || x.author.name || "an agent"} · ${new Date(x.timestamp).toLocaleDateString()}`)));
}
const factLine = (f: claimsv1.Fact) => [/^https?:\/\//.test(f.url ?? "") ? el("a", { href: f.url, target: "_blank", rel: "noopener noreferrer" }, f.source) : f.source, " ", el("code", {}, f.field), " ", f.value];

// rawTab is grype's raw match from each side and the syft artifact, verbatim, each scrolling in
// its own box
function rawTab(d: FindingData) {
  const m = d.matches;
  const json = (v: unknown) => JSON.stringify(Array.isArray(v) && v.length === 1 ? v[0] : v, null, 2);
  const block = (title: string, id: string, v: unknown, none: string) =>
    el("details", { class: "raw", open: true }, el("summary", {}, title),
      el("pre", { "data-testid": id }, v == null || (Array.isArray(v) && !v.length) ? none : json(v)));
  if (!m) return el("p", { class: "muted" }, "grype's raw matches could not be read.");
  return el("div", { class: "rawtab" },
    block("The candidate's grype match", "raw-candidate", m.candidate, "no match on the candidate's side"),
    block("The reference's grype match", "raw-reference", m.reference, "no match on the reference's side"),
    block("The syft artifact", "raw-artifact", m.artifact, m.sbomMissing ? `SBOM not found: ${m.sbomMissing}` : "no artifact"));
}

// labelsTab is the label deciding the match as its file holds it, and every claims source holding
// its key
function labelsTab(d: FindingData) {
  const lv = d.detail.label;
  if (!lv) return el("p", { class: "muted", "data-testid": "no-labels" }, "No label on file for this match.");
  const l = lv.label, notes = l.notes ?? [];
  return el("div", { class: "labels" },
    el("section", { class: "labelcard", "data-testid": "label-record", "data-verdict": l.verdict, "data-author": l.author },
      el("div", { class: "line" }, verdict(l.verdict as Verdict),
        el("span", { class: `reason${mutedReason(l.justification) ? " muted" : ""}` }, l.justification ? justWords(d.state, l.verdict, l.justification) : "no reason")),
      kv([
        ["Author", l.author || "?"],
        ["Issued", new Date(l.firstIssued).toLocaleDateString()],
        ["Updated", new Date(l.lastUpdated).toLocaleDateString()],
        ["File", el("span", { class: "mono" }, `${lv.global ? "global · " : ""}${lv.file}`)],
        ["Seen with", seenWith(l)],
        ["Rule", ruleWords(l.evidence?.[0]?.rule)],
      ]),
      notes.length > 0 && el("ul", { class: "notes" }, notes.map((n) => el("li", { "data-testid": "label-note" }, el("span", { class: "help" }, `${n.author} · ${new Date(n.at).toLocaleDateString()}`), el("p", {}, n.text))))),
    el("h3", {}, "Every claims source holding it"),
    el("ul", { class: "sources", "data-testid": "label-sources" }, (lv.sources ?? []).map((s) => {
      const v = s.match(/: (tp|fp|unclear)$/)?.[1];
      return el("li", { title: s }, v && verdict(v as Verdict), el("span", { class: "mono" }, shortSource(s)));
    })));
}
