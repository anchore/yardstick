// yardstick · map · every gate, ported from delta. Labels are about a package in an image and a vulnerability, not about
// a run, so one label counts in every gate whose newest run reports the finding. This page puts
// the gates side by side and lists the open findings by how many gates one label decides: first
// the ones that alone change a check, then by how many gates they bear on. A label is the truth
// about the match (TP is the tool working), so each gate chip says what TP and FP would do there;
// the same label can help one gate and hurt another.

import { call, post } from "../shared/api";

const $ = (s) => document.querySelector(s);

const ui = {
  state: null,
  gate: null,        // only findings that bear on this gate (?gate=)
  group: null,       // the unfolded group's key (?group=)
  more: new Set(),   // tiers and groups showing everything
  status: null,      // { text, error } of the last action; stays until the next one or dismissed
};

const labels = { tp: { glyph: "●", word: "TP" }, fp: { glyph: "○", word: "FP" }, unclear: { glyph: "◐", word: "unclear" } };
const marks = { added: "+", dropped: "−", both: "=" };
const dirWords = { added: "only the candidate reports it", dropped: "only the reference reports it", both: "both sides report it" };

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  n.append(...children.flat(Infinity).filter((c) => c != null && c !== false));
  return n;
}
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
// pkg:rpm/redhat/vim-minimal@8.0.1763-19.el8_6.2?arch=… → vim-minimal 8.0.1763-19.el8_6.2
function pkgName(p) {
  const m = (p?.ref || "").match(/^pkg:[^/]+\/(?:.*\/)?([^/@?]+)@([^?#]+)/);
  return m ? `${decodeURIComponent(m[1])} ${decodeURIComponent(m[2])}` : p?.ref || "?";
}

// ---------- the URL: ?gate=<name>&group=<key> ----------

function readURL() {
  const q = new URLSearchParams(location.search);
  ui.gate = q.get("gate");
  ui.group = q.get("group");
}
function navigate(patch) {
  Object.assign(ui, patch);
  const q = new URLSearchParams();
  if (ui.gate) q.set("gate", ui.gate);
  if (ui.group) q.set("group", ui.group);
  history.pushState(null, "", `${location.pathname}${q.size ? `?${q}` : ""}`);
  render();
}
addEventListener("popstate", () => { readURL(); render(); });

// ---------- grouping ----------

const bearsIn = (f, gate) => f.in.some((a) => a.gate === gate && a.effect);

// groups folds findings into what one action settles: a same-reasoning group, else a source
// package in an image
function groups(findings) {
  const by = new Map();
  for (const f of findings) {
    const key = f.cause ? `c:${f.cause.id}` : `p:${f.image}|${f.sourcePackage}`;
    if (!by.has(key)) by.set(key, { key, cause: f.cause, image: f.image, pkg: f.sourcePackage, findings: [], flips: 0, bears: 0 });
    const g = by.get(key);
    g.findings.push(f);
    g.flips = Math.max(g.flips, f.flips);
    g.bears = Math.max(g.bears, f.bears);
  }
  return [...by.values()].sort((a, b) => (b.flips - a.flips) || (b.bears - a.bears) || (b.findings.length - a.findings.length) || a.pkg.localeCompare(b.pkg));
}
const tierOf = (g) => (g.flips ? "flip" : String(g.bears));
const tierTitle = (t) => (t === "flip" ? "◆ a label here alone changes a check" : t === "1" ? "bears on one gate" : `bears on ${t} gates`);

// ---------- render ----------

function render() {
  renderGates();
  renderStatus();
  renderList();
}

function renderGates() {
  const st = ui.state;
  // the gates that need labels first; a passing gate shrinks to its name, as on the board
  const order = [...st.gates].sort((a, b) => Number(a.outcome === "pass") - Number(b.outcome === "pass") || b.open - a.open);
  $("#gates").replaceChildren(...order.map((g) => {
    const quiet = g.outcome === "pass" && ui.gate !== g.name;
    return el("div", { class: `gtile ${g.outcome}${ui.gate === g.name ? " on" : ""}${quiet ? " quiet" : ""}`, title: `${g.description || g.name}${g.note ? `\n${g.note}` : ""}\n\nclick: only the findings that bear on it`,
      onclick: () => navigate({ gate: ui.gate === g.name ? null : g.name, group: null }) },
      el("div", { class: "top" }, el("span", { class: `band band-${g.outcome}` }, g.outcome === "pass" && g.better ? `pass · ${g.better}` : g.outcome), el("span", { class: "nm" }, g.name)),
      quiet ? null : [
        el("div", { class: "cmp" }, `${g.compared} · ${plural(g.images, "image")}`),
        el("div", { class: "checks" }, ...(g.checks || []).map((c) => el("span", { class: `ck ${c.state}`, title: `${c.valueMeans}: ${c.state}${c.estimate ? ` · about ${c.estimate.toDecide} labels could decide it` : ""}` }, c.name))),
      ],
      el("div", { class: "foot" }, g.open ? `${g.open} open bear on it` : "nothing open bears on it",
        el("a", { href: `/ui/map/gates/${encodeURIComponent(g.name)}/`, onclick: (e) => e.stopPropagation(), title: "this gate's board" }, "board ›")),
    );
  }));
}

function renderStatus() {
  const box = $("#status"), s = ui.status;
  box.hidden = !s;
  if (!s) return;
  box.className = `status${s.error ? " error" : ""}`;
  box.replaceChildren(el("span", {}, s.text), s.busy ? null : el("button", { class: "ghost", onclick: () => { ui.status = null; renderStatus(); } }, "dismiss"));
}

function renderList() {
  const st = ui.state;
  const findings = ui.gate ? st.findings.filter((f) => bearsIn(f, ui.gate)) : st.findings;
  const gs = groups(findings);
  const list = $("#list");
  const head = el("div", { class: "crumbs" }, el("b", {}, ui.gate ? `bearing on ${ui.gate}` : "every gate"),
    el("span", {}, ` · ${plural(findings.length, "open finding")} in ${plural(gs.length, "group")} · ${findings.filter((f) => f.bears > 1).length} of them bear on more than one gate`),
    ui.gate ? el("button", { onclick: () => navigate({ gate: null, group: null }) }, "every gate") : null);
  const out = [head];
  const tiers = [...new Set(gs.map(tierOf))];
  for (const t of tiers) {
    const inTier = gs.filter((g) => tierOf(g) === t);
    const n = inTier.reduce((k, g) => k + g.findings.length, 0);
    out.push(el("div", { class: "xtier" }, tierTitle(t), ` · ${plural(n, "finding")} in ${plural(inTier.length, "group")}`));
    // the unfolded group always shows, wherever it sits in its tier
    const cap = ui.more.has(`t:${t}`) ? Infinity : 12;
    const shown = inTier.filter((g, i) => i < cap || g.key === ui.group);
    for (const g of shown) out.push(groupCard(g));
    if (inTier.length > shown.length) out.push(el("button", { class: "ghost more", onclick: () => { ui.more.add(`t:${t}`); render(); } }, `+ ${inTier.length - shown.length} more`));
  }
  if (!gs.length) out.push(el("div", { class: "muted" }, "nothing open bears on a gate"));
  list.replaceChildren(...out);
}

// gateChips: one chip per gate whose run reports any of the findings
function gateChips(findings) {
  const by = new Map();
  for (const f of findings) for (const a of f.in) {
    if (!by.has(a.gate)) by.set(a.gate, { dirs: new Set(), bears: 0, flips: 0 });
    const c = by.get(a.gate);
    c.dirs.add(a.dir);
    if (a.effect) c.bears++;
    if (a.effect?.couldFlip?.length) c.flips++;
  }
  return el("div", { class: "chips" }, ...ui.state.gates.filter((g) => by.has(g.name)).map((g) => {
    const c = by.get(g.name);
    const dirs = [...c.dirs].map((d) => marks[d]).join("");
    return el("span", { class: `gchip${c.flips ? " flip" : ""}${c.bears ? "" : " inert"}`,
      title: `${g.name} (${g.outcome}): ${[...c.dirs].map((d) => dirWords[d]).join("; ")}\n${c.bears ? `${c.bears} bear on a check${c.flips ? `, ${c.flips} could change one alone` : ""}` : "they count, but can't change it: the gate is decided"}` },
      el("span", { class: "d" }, dirs), g.name, findings.length > 1 && c.bears ? el("span", { class: "eff" }, `${c.bears}${c.flips ? ` · ◆${c.flips}` : ""}`) : null);
  }));
}

// effectChip: what labeling one finding does in one gate
function effectChip(f, a) {
  const g = ui.state.gates.find((x) => x.name === a.gate);
  const e = a.effect;
  if (!e) return el("span", { class: "gchip inert", title: `${a.gate} (${g?.outcome}): ${dirWords[a.dir]}; the label counts, but the gate is decided` }, el("span", { class: "d" }, marks[a.dir]), a.gate);
  const flips = e.couldFlip?.length;
  const moved = (o) => o !== g?.outcome;
  // the gate's outcome when a label moves it, else the check it decides (either label does)
  const outcomes = [["TP", e.ifTP.outcome], ["FP", e.ifFP.outcome]].filter(([, o]) => moved(o));
  const eff = !flips ? null : outcomes.length ? outcomes.map(([v, o], i) => [i ? " · " : null, `${v}→`, el("span", { class: o }, o)]) : `◆ ${e.couldFlip.join(", ")}`;
  return el("span", { class: `gchip${flips ? " flip" : ""}`,
    title: `${a.gate} (${g?.outcome}): ${dirWords[a.dir]}\nnarrows ${(e.bears || []).join(", ") || "–"}${flips ? `\nalone changes ${e.couldFlip.join(", ")}` : ""}\nif TP the gate is ${e.ifTP.outcome}; if FP, ${e.ifFP.outcome}` },
    el("span", { class: "d" }, marks[a.dir]), a.gate, eff ? el("span", { class: "eff" }, eff) : null);
}

function hintChip(h) {
  if (!h || h.status !== "pending") return null;
  return el("span", { class: `hint v-${h.verdict}`, title: `${h.skill || "agent"}: ${h.rule || ""}${h.title || h.justification ? `\n${h.title || h.justification}` : ""}` }, `✦ ${labels[h.verdict]?.word || h.verdict}? ${h.confidence || ""}`);
}

function actions(findings) {
  const pending = findings.filter((f) => f.hint?.status === "pending");
  const verdicts = new Set<string>(pending.map((f) => f.hint.verdict));
  const many = findings.length > 1 ? ` ${findings.length}` : "";
  return el("div", { class: "xacts", onclick: (e) => e.stopPropagation() },
    pending.length ? el("button", { class: "ghost", title: "endorse the agent's suggestions: your claims, with their reasons and facts", onclick: () => accept(pending) },
      `✦ accept${pending.length > 1 ? ` ${pending.length}` : ""}${verdicts.size === 1 ? ` ${labels[[...verdicts][0]]?.word}` : ""}`) : null,
    el("button", { class: "ghost tp", title: `label${many} TP: the label counts in every gate that reports it`, onclick: () => label(findings, "tp") }, `${labels.tp.glyph} TP${many}`),
    // FP and unclear need a reason from the claims vocabulary: choosing one labels
    ...["fp", "unclear"].map((v) => el("select", { class: `ghost ${v}`, title: `label${many} ${labels[v].word}, with a reason: the label counts in every gate that reports it`,
      onchange: (e) => e.target.value && label(findings, v, e.target.value) },
    el("option", { value: "" }, `${labels[v].glyph} ${labels[v].word}${many} because…`),
    ...Object.entries(ui.state.vocabulary?.justifications?.[v] || {}).sort().map(([j, desc]) => el("option", { value: j }, desc)))),
  );
}

function groupCard(g) {
  const open = ui.group === g.key;
  const hinted = g.findings.filter((f) => f.hint?.status === "pending");
  const title = g.cause ? `✦ ${g.cause.title}` : `${g.pkg} · ${g.image}`;
  const sub = `${plural(g.findings.length, "finding")}${g.cause ? ` · ${g.pkg} · ${g.image}` : ""}${hinted.length ? ` · ${hinted.length} with a suggestion` : ""}`;
  const card = el("section", { class: `xgroup${g.cause ? " cause" : ""}` },
    el("div", { class: "xhead", onclick: () => navigate({ group: open ? null : g.key }) },
      el("div", {}, el("span", { class: "ttl" }, open ? "▾ " : "▸ ", title), " ", el("span", { class: "sub" }, sub)),
      actions(g.findings),
      gateChips(g.findings)));
  if (open) {
    const cap = ui.more.has(g.key) ? Infinity : 40;
    const rows = el("div", { class: "xrows" }, ...g.findings.slice(0, cap).map((f) => el("div", { class: "xrow" },
      el("div", {}, el("span", { class: "vuln" }, f.vulnerability), " ", hintChip(f.hint), el("div", { class: "pkg" }, pkgName(f.package))),
      el("div", { class: "chips" }, ...f.in.map((a) => effectChip(f, a))),
      actions([f]))));
    if (g.findings.length > cap) rows.append(el("button", { class: "ghost more", onclick: () => { ui.more.add(g.key); render(); } }, `+ ${g.findings.length - cap} more`));
    card.append(rows);
  }
  return card;
}

// ---------- acting: one label per finding, written through any gate that reports it ----------

function byGate(findings) {
  const out = new Map();
  for (const f of findings) {
    const a = f.in[0];
    if (!out.has(a.gate)) out.set(a.gate, []);
    out.get(a.gate).push(a.row);
  }
  return out;
}

async function act(what, findings, send) {
  const before = new Map<string, any>(ui.state.gates.map((g) => [g.name, g]));
  const gates = new Set(findings.flatMap((f) => f.in.map((a) => a.gate)));
  ui.status = { text: `${what} ${plural(findings.length, "finding")}; they count in ${plural(gates.size, "gate")}. Rescoring every gate…`, busy: true };
  renderStatus();
  try {
    for (const [gate, rows] of byGate(findings)) await send(gate, rows);
    await load();
    const moved = [];
    for (const g of ui.state.gates) {
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
    ui.status = { text: `${what} failed: ${e.message}`, error: true };
  }
  render();
}
const label = (findings, verdict, justification = "") => act(`Labeled ${labels[verdict].glyph} ${labels[verdict].word}:`, findings,
  (gate, rows) => post(gate, "/labels", { rows, verdict, justification, note: "", scope: "subject" }));
const accept = (findings) => act("Accepted the suggestions on", findings, (gate, rows) => post(gate, "/accept", { rows }));

async function load() {
  ui.state = await call("/api/gates/shared");
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
    ui.status = { text: `Couldn't load the gates: ${e.message}`, error: true };
    renderStatus();
  }
})();
