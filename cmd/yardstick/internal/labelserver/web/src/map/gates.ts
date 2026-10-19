// yardstick · map · every gate, ported from delta. Labels are about a package in an image and a vulnerability, not about
// a run, so one label counts in every gate whose newest run reports the finding. This page puts
// the gates side by side and lists the open findings by how many gates one label decides: first
// the ones that alone change a check, then by how many gates they bear on. A label is the truth
// about the match (TP is the tool working), so each gate chip says what TP and FP would do there;
// the same label can help one gate and hurt another.

import type { CrossAppearance, CrossCause, CrossFinding, HintSummary, PkgRef, SharedState } from "../gen/wire";
import * as api from "../shared/api";
import { el, fill, must } from "../shared/dom";
import { labels, marks, plural } from "../shared/words";

const ui: {
  state: SharedState | null;
  gate: string | null;     // only findings that bear on this gate (?gate=)
  group: string | null;    // the unfolded group's key (?group=)
  more: Set<string>;       // tiers and groups showing everything
  status: { text: string; error?: boolean; busy?: boolean } | null;  // the last action's; stays until the next one or dismissed
} = {
  state: null,
  gate: null,
  group: null,
  more: new Set(),
  status: null,
};

// st is the loaded state; nothing renders before load has it
function st(): SharedState {
  if (!ui.state) throw new Error("the gates are not loaded");
  return ui.state;
}

const dirWords: Record<string, string> = { added: "only the candidate reports it", dropped: "only the reference reports it", both: "both sides report it" };

// pkg:rpm/redhat/vim-minimal@8.0.1763-19.el8_6.2?arch=… → vim-minimal 8.0.1763-19.el8_6.2
function pkgName(p: PkgRef | undefined) {
  const m = (p?.ref || "").match(/^pkg:[^/]+\/(?:.*\/)?([^/@?]+)@([^?#]+)/);
  return m ? `${decodeURIComponent(m[1])} ${decodeURIComponent(m[2])}` : p?.ref || "?";
}

// ---------- the URL: ?gate=<name>&group=<key> ----------

function readURL() {
  const q = new URLSearchParams(location.search);
  ui.gate = q.get("gate");
  ui.group = q.get("group");
}
function navigate(patch: { gate?: string | null; group?: string | null }) {
  Object.assign(ui, patch);
  const q = new URLSearchParams();
  if (ui.gate) q.set("gate", ui.gate);
  if (ui.group) q.set("group", ui.group);
  history.pushState(null, "", `${location.pathname}${q.size ? `?${q}` : ""}`);
  render();
}
addEventListener("popstate", () => { readURL(); render(); });

// ---------- grouping ----------

const bearsIn = (f: CrossFinding, gate: string) => f.in.some((a) => a.gate === gate && a.effect);

// groups folds findings into what one action settles: a same-reasoning group, else a source
// package in an image
interface Group { key: string; cause: CrossCause | undefined; image: string; pkg: string; findings: CrossFinding[]; flips: number; bears: number }
function groups(findings: CrossFinding[]): Group[] {
  const by = new Map<string, Group>();
  for (const f of findings) {
    const key = f.cause ? `c:${f.cause.id}` : `p:${f.image}|${f.sourcePackage}`;
    let g = by.get(key);
    if (!g) by.set(key, (g = { key, cause: f.cause, image: f.image, pkg: f.sourcePackage, findings: [], flips: 0, bears: 0 }));
    g.findings.push(f);
    g.flips = Math.max(g.flips, f.flips);
    g.bears = Math.max(g.bears, f.bears);
  }
  return [...by.values()].sort((a, b) => (b.flips - a.flips) || (b.bears - a.bears) || (b.findings.length - a.findings.length) || a.pkg.localeCompare(b.pkg));
}
const tierOf = (g: Group) => (g.flips ? "flip" : String(g.bears));
const tierTitle = (t: string) => (t === "flip" ? "◆ a label here alone changes a check" : t === "1" ? "bears on one gate" : `bears on ${t} gates`);

// ---------- render ----------

function render() {
  renderGates();
  renderStatus();
  renderList();
}

function renderGates() {
  // the gates that need labels first; a passing gate shrinks to its name, as on the board
  const order = [...st().gates].sort((a, b) => Number(a.outcome === "pass") - Number(b.outcome === "pass") || b.open - a.open);
  must("#gates").replaceChildren(...order.map((g) => {
    const quiet = g.outcome === "pass" && ui.gate !== g.name;
    return el("div", { class: `gtile ${g.outcome}${ui.gate === g.name ? " on" : ""}${quiet ? " quiet" : ""}`, "data-testid": "gate-card", "data-gate": g.name, "data-state": g.outcome, "data-open": g.open, "data-active": ui.gate === g.name, title: `${g.description || g.name}${g.note ? `\n${g.note}` : ""}\n\nclick: only the findings that bear on it`,
      onclick: () => navigate({ gate: ui.gate === g.name ? null : g.name, group: null }) },
      el("div", { class: "top" }, el("span", { class: `band band-${g.outcome}`, "data-testid": "gate-outcome", "data-state": g.outcome }, g.outcome), el("span", { class: "nm" }, g.name)),
      quiet ? null : [
        el("div", { class: "cmp" }, `${g.compared} · ${plural(g.images, "image")}`),
        el("div", { class: "checks" }, ...(g.checks || []).map((c) => el("span", { class: `ck ${c.state}`, "data-testid": "gate-check", "data-check": c.name, "data-state": c.state, title: `${c.valueMeans}: ${c.state}` }, c.name))),
      ],
      el("div", { class: "foot" }, g.open ? `${g.open} open bear on it` : "nothing open bears on it",
        el("a", { href: `/ui/map/gates/${encodeURIComponent(g.name)}/`, "data-testid": "gate-board-link", "data-gate": g.name, onclick: (e) => e.stopPropagation(), title: "this gate's board" }, "board ›")),
    );
  }));
}

function renderStatus() {
  const box = must("#status"), s = ui.status;
  box.hidden = !s;
  if (!s) return;
  box.className = `status${s.error ? " error" : ""}`;
  box.dataset.state = s.error ? "error" : s.busy ? "busy" : "done";
  fill(box, el("span", {}, s.text), s.busy ? null : el("button", { class: "ghost", "data-testid": "status-dismiss", onclick: () => { ui.status = null; renderStatus(); } }, "dismiss"));
}

function renderList() {
  const all = st().findings, gate = ui.gate;
  const findings = gate ? all.filter((f) => bearsIn(f, gate)) : all;
  const gs = groups(findings);
  const list = must("#list");
  const head = el("div", { class: "crumbs", "data-testid": "list-head", "data-gate": ui.gate ?? "" }, el("b", {}, ui.gate ? `bearing on ${ui.gate}` : "every gate"),
    el("span", {}, ` · ${plural(findings.length, "open finding")} in ${plural(gs.length, "group")} · ${findings.filter((f) => f.bears > 1).length} of them bear on more than one gate`),
    ui.gate ? el("button", { "data-testid": "clear-gate-filter", onclick: () => navigate({ gate: null, group: null }) }, "every gate") : null);
  const out: HTMLElement[] = [head];
  const tiers = [...new Set(gs.map(tierOf))];
  for (const t of tiers) {
    const inTier = gs.filter((g) => tierOf(g) === t);
    const n = inTier.reduce((k, g) => k + g.findings.length, 0);
    out.push(el("div", { class: "xtier", "data-testid": "tier", "data-tier": t, "data-count": inTier.length }, tierTitle(t), ` · ${plural(n, "finding")} in ${plural(inTier.length, "group")}`));
    // the unfolded group always shows, wherever it sits in its tier
    const cap = ui.more.has(`t:${t}`) ? Infinity : 12;
    const shown = inTier.filter((g, i) => i < cap || g.key === ui.group);
    for (const g of shown) out.push(groupCard(g));
    if (inTier.length > shown.length) out.push(el("button", { class: "ghost more", "data-testid": "tier-more", "data-tier": t, onclick: () => { ui.more.add(`t:${t}`); render(); } }, `+ ${inTier.length - shown.length} more`));
  }
  if (!gs.length) out.push(el("div", { class: "muted", "data-testid": "list-empty" }, "nothing open bears on a gate"));
  list.replaceChildren(...out);
}

// gateChips: one chip per gate whose run reports any of the findings
function gateChips(findings: CrossFinding[]) {
  const by = new Map<string, { dirs: Set<string>; bears: number; flips: number }>();
  for (const f of findings) for (const a of f.in) {
    let c = by.get(a.gate);
    if (!c) by.set(a.gate, (c = { dirs: new Set(), bears: 0, flips: 0 }));
    c.dirs.add(a.dir);
    if (a.effect) c.bears++;
    if (a.effect?.couldFlip?.length) c.flips++;
  }
  return el("div", { class: "chips" }, ...st().gates.flatMap((g) => {
    const c = by.get(g.name);
    if (!c) return [];
    const dirs = [...c.dirs].map((d) => marks[d]).join("");
    return [el("span", { class: `gchip${c.flips ? " flip" : ""}${c.bears ? "" : " inert"}`, "data-testid": "gate-chip", "data-gate": g.name, "data-bears": c.bears, "data-flips": c.flips,
      title: `${g.name} (${g.outcome}): ${[...c.dirs].map((d) => dirWords[d]).join("; ")}\n${c.bears ? `${c.bears} bear on a check${c.flips ? `, ${c.flips} could change one alone` : ""}` : "they count, but can't change it: the gate is decided"}` },
      el("span", { class: "d" }, dirs), g.name, findings.length > 1 && c.bears ? el("span", { class: "eff" }, `${c.bears}${c.flips ? ` · ◆${c.flips}` : ""}`) : null)];
  }));
}

// effectChip: what labeling one finding does in one gate
function effectChip(a: CrossAppearance) {
  const g = st().gates.find((x) => x.name === a.gate);
  const e = a.effect;
  if (!e) return el("span", { class: "gchip inert", "data-testid": "gate-effect", "data-gate": a.gate, title: `${a.gate} (${g?.outcome}): ${dirWords[a.dir]}; the label counts, but the gate is decided` }, el("span", { class: "d" }, marks[a.dir]), a.gate);
  const flips = e.couldFlip?.length;
  const moved = (o: string) => o !== g?.outcome;
  // the gate's outcome when a label moves it, else the check it decides (either label does)
  const outcomes = [["TP", e.ifTP.outcome], ["FP", e.ifFP.outcome]].filter(([, o]) => moved(o));
  const eff = !flips ? null : outcomes.length ? outcomes.map(([v, o], i) => [i ? " · " : null, `${v}→`, el("span", { class: o }, o)]) : `◆ ${(e.couldFlip || []).join(", ")}`;
  return el("span", { class: `gchip${flips ? " flip" : ""}`, "data-testid": "gate-effect", "data-gate": a.gate, "data-if-tp": e.ifTP.outcome, "data-if-fp": e.ifFP.outcome,
    title: `${a.gate} (${g?.outcome}): ${dirWords[a.dir]}\nnarrows ${(e.bears || []).join(", ") || "–"}${flips ? `\nalone changes ${(e.couldFlip || []).join(", ")}` : ""}\nif TP the gate is ${e.ifTP.outcome}; if FP, ${e.ifFP.outcome}` },
    el("span", { class: "d" }, marks[a.dir]), a.gate, eff ? el("span", { class: "eff" }, eff) : null);
}

function hintChip(h: HintSummary | undefined) {
  if (!h || h.status !== "pending") return null;
  return el("span", { class: `hint v-${h.verdict}`, "data-testid": "hint-chip", "data-verdict": h.verdict, "data-confidence": h.confidence ?? "", "aria-label": `${labels[h.verdict]?.word || h.verdict} hint`, title: `${h.skill || "agent"}: ${h.rule || ""}${h.title || h.justification ? `\n${h.title || h.justification}` : ""}` }, `✦ ${labels[h.verdict]?.word || h.verdict}? ${h.confidence || ""}`);
}

function actions(findings: CrossFinding[], scope: "group" | "finding") {
  const pending = findings.filter((f) => f.hint?.status === "pending");
  const verdicts = new Set<string>(pending.map((f) => f.hint?.verdict ?? ""));
  const many = findings.length > 1 ? ` ${findings.length}` : "";
  return el("div", { class: "xacts", "data-testid": "actions", "data-scope": scope, onclick: (e) => e.stopPropagation() },
    pending.length ? el("button", { class: "ghost", "data-testid": "accept-button", "data-scope": scope, "data-count": pending.length, title: "endorse the agent's suggestions: your claims, with their reasons and facts", onclick: () => accept(pending) },
      `✦ accept${pending.length > 1 ? ` ${pending.length}` : ""}${verdicts.size === 1 ? ` ${labels[[...verdicts][0]]?.word}` : ""}`) : null,
    el("button", { class: "ghost tp", "data-testid": "label-button", "data-verdict": "tp", "data-scope": scope, title: `label${many} TP: the label counts in every gate that reports it`, onclick: () => label(findings, "tp") }, `${labels.tp.glyph} TP${many}`),
    // FP and unclear need a reason from the claims vocabulary: choosing one labels
    ...["fp", "unclear"].map((v) => el("select", { class: `ghost ${v}`, "data-testid": "label-select", "data-verdict": v, "data-scope": scope, title: `label${many} ${labels[v].word}, with a reason: the label counts in every gate that reports it`,
      onchange: (e) => { const j = (e.target as HTMLSelectElement).value; if (j) label(findings, v, j); } },
    el("option", { value: "" }, `${labels[v].glyph} ${labels[v].word}${many} because…`),
    ...Object.entries(st().vocabulary?.justifications?.[v] || {}).sort().map(([j, desc]) => el("option", { value: j, "data-testid": "justification-option", "data-justification": j }, desc)))),
  );
}

function groupCard(g: Group) {
  const open = ui.group === g.key;
  const hinted = g.findings.filter((f) => f.hint?.status === "pending");
  const title = g.cause ? `✦ ${g.cause.title}` : `${g.pkg} · ${g.image}`;
  const sub = `${plural(g.findings.length, "finding")}${g.cause ? ` · ${g.pkg} · ${g.image}` : ""}${hinted.length ? ` · ${hinted.length} with a suggestion` : ""}`;
  const card = el("section", { class: `xgroup${g.cause ? " cause" : ""}`, "data-testid": "finding-group", "data-group": g.key, "data-open": open, "data-count": g.findings.length, "data-hinted": hinted.length, "data-package": g.pkg, "data-image": g.image },
    el("div", { class: "xhead", "data-testid": "group-head", onclick: () => navigate({ group: open ? null : g.key }) },
      el("div", {}, el("span", { class: "ttl" }, open ? "▾ " : "▸ ", title), " ", el("span", { class: "sub" }, sub)),
      actions(g.findings, "group"),
      gateChips(g.findings)));
  if (open) {
    const cap = ui.more.has(g.key) ? Infinity : 40;
    const rows = el("div", { class: "xrows", "data-testid": "finding-rows" }, ...g.findings.slice(0, cap).map((f) => el("div", { class: "xrow", "data-testid": "finding", "data-row": f.in[0]?.row, "data-gate": f.in[0]?.gate, "data-vulnerability": f.vulnerability, "data-package": pkgName(f.package), "data-image": f.image },
      el("div", {}, el("span", { class: "vuln" }, f.vulnerability), " ", hintChip(f.hint), el("div", { class: "pkg" }, pkgName(f.package))),
      el("div", { class: "chips" }, ...f.in.map((a) => effectChip(a))),
      actions([f], "finding"))));
    if (g.findings.length > cap) rows.append(el("button", { class: "ghost more", "data-testid": "show-more", "data-group": g.key, onclick: () => { ui.more.add(g.key); render(); } }, `+ ${g.findings.length - cap} more`));
    card.append(rows);
  }
  return card;
}

// ---------- acting: one label per finding, written through any gate that reports it ----------

function byGate(findings: CrossFinding[]) {
  const out = new Map<string, string[]>();
  for (const f of findings) {
    const a = f.in[0];
    let rows = out.get(a.gate);
    if (!rows) out.set(a.gate, (rows = []));
    rows.push(a.row);
  }
  return out;
}

async function act(what: string, findings: CrossFinding[], send: (gate: string, rows: string[]) => Promise<unknown>) {
  const before = new Map(st().gates.map((g) => [g.name, g]));
  const gates = new Set(findings.flatMap((f) => f.in.map((a) => a.gate)));
  ui.status = { text: `${what} ${plural(findings.length, "finding")}; they count in ${plural(gates.size, "gate")}. Rescoring every gate…`, busy: true };
  renderStatus();
  try {
    for (const [gate, rows] of byGate(findings)) await send(gate, rows);
    await load();
    const moved: string[] = [];
    for (const g of st().gates) {
      const b = before.get(g.name);
      if (!b) continue;
      if (b.outcome !== g.outcome) moved.push(`${g.name} ${b.outcome} → ${g.outcome}`);
      for (const c of g.checks || []) {
        const bc = (b.checks || []).find((x) => x.name === c.name);
        if (bc && bc.state !== c.state) moved.push(`${g.name} ${c.name} ${bc.state} → ${c.state}`);
      }
    }
    ui.status = { text: `${what} ${plural(findings.length, "finding")} in ${plural(gates.size, "gate")}. ${moved.length ? `Changed: ${moved.join(" · ")}.` : "No gate or check changed state; the ranges narrowed."}` };
  } catch (e) {
    ui.status = { text: `${what} failed: ${(e as Error).message}`, error: true };
  }
  render();
}
const label = (findings: CrossFinding[], verdict: string, justification = "") => act(`Labeled ${labels[verdict].glyph} ${labels[verdict].word}:`, findings,
  (gate, rows) => api.labels(gate, { rows, verdict, justification, note: "", scope: "subject" }));
const accept = (findings: CrossFinding[]) => act("Accepted the suggestions on", findings, (gate, rows) => api.accept(gate, rows));

async function load() {
  ui.state = await api.shared();
}

(async () => {
  readURL();
  ui.status = { text: "Scoring every gate…", busy: true };
  renderStatus();
  try {
    await load();
    ui.status = null;
    render();
  } catch (e) {
    ui.status = { text: `Couldn't load the gates: ${(e as Error).message}`, error: true };
    renderStatus();
  }
})();
