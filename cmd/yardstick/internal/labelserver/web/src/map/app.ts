// yardstick · map, ported from delta's map UI: look first, then label. The gate as range bars, the
// images as small multiples, and the differences as a treemap (direction › reason › source
// package) filled by label state. On a gate run the top level is a board of the checks; clicking a
// group opens the Focus tile (shared/tile.ts) on its findings, under a breadcrumb back to the board.

import { where, get, post } from "../shared/api";
import * as tile from "../shared/tile";

const $ = (s) => document.querySelector(s);

const ui = {
  gateName: where().gate,
  state: null,
  si: null,            // image scope: subject index, or null for every image
  delta: false,        // on a gate: the scan-delta map instead of the gate board
  opened: new Set(),   // board panels whose full group list is unfolded
  zoom: null,          // { dir, why } when zoomed into one reason
  cardsSpec: null,     // which cards are open, from the URL (cardsFor turns it into rows)
  cards: null,         // { title, ids } derived from cardsSpec on each render
  base: "",            // this gate's page path, /ui/map/gates/<gate>/
  pushes: 0,           // history entries this page pushed (Esc goes back through them)
  booted: false,
  rows: [],            // the open group's rows, in order
  selected: null,      // row id of the finding on the tile
  evidence: false,     // the tile shows more evidence (links, claims, raw JSON); "&evidence" in the URL
  why: false,          // the tile shows the agent's note and facts
  details: new Map(),
  matches: new Map(),
  note: "",
  receipt: null,
  pin: null,           // a match just labeled that stays on screen though it left its group
  preview: null,       // { key, what, result }: the gate if a hovered accept were clicked
  research: null,      // { counts: { "no-hint": n, "could-move-check": n }, scope }: dry-run counts
  last: null,
  scrollTo: null,      // the board panel to scroll to on the next render, by check name
};

const labels = {
  tp: { glyph: "●", word: "TP", long: "real match" },
  fp: { glyph: "○", word: "FP", long: "false match" },
  unclear: { glyph: "◐", word: "unclear", long: "unclear" },
  unlabeled: { glyph: "◌", word: "unlabeled", long: "unlabeled" },
};
const dots = { high: "•••", medium: "••◦", low: "•◦◦" };
const marks = { added: "+", dropped: "−", both: "=", neither: "∅" };
const dirTitle = { added: "+ candidate added", dropped: "− candidate dropped" };

// ---------- helpers ----------

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
const svgNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, ...children) {
  const n = document.createElementNS(svgNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v); else n.setAttribute(k, v);
  }
  n.append(...children.flat(Infinity).filter(Boolean));
  return n;
}
const plural = (n, w, many = `${w}s`) => `${n} ${n === 1 ? w : many}`;
const fmt = (x) => (Number.isInteger(x) ? String(x) : Math.abs(x) < 10 ? x.toFixed(3) : x.toFixed(1));
const signed = (x) => (x > 0 ? `+${fmt(x)}` : fmt(x));
let toastTimer;
function toast(msg, error = false) {
  const t = $("#toast");
  t.textContent = msg; t.className = `toast${error ? " error" : ""}`; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), error ? 6000 : 2500);
}
function direction(r) {
  if (r.inCandidate && !r.inReference) return "added";
  if (!r.inCandidate && r.inReference) return "dropped";
  return r.inCandidate ? "both" : "neither";
}
function pkgOf(ref) {
  const m = (ref || "").match(/^pkg:[^/]+\/(?:.*\/)?([^@?#]+)(?:@([^?#]+))?/);
  return { name: decodeURIComponent(m?.[1] || ref || ""), version: decodeURIComponent(m?.[2] || "") };
}
const detail = (r) => r.candidate || r.reference;
const otherRecords = (r) => (direction(r) === "added" ? r.referenceRecords : r.candidateRecords) || [];
const decisive = (r) => !!r.gate?.couldFlip?.length;
const bears = (r) => !!r.gate?.bears?.length;
const isOpen = (r) => r.verdict === "unlabeled" || r.verdict === "unclear" || !!r.conflict;
const hinted = (r) => r.hint?.status === "pending" && isOpen(r);
const srcPkg = (r) => r.sourcePackage || pkgOf(r.package.ref).name;
function disposition(dir, verdict) {
  if (dir === "added") return verdict === "tp" ? "good" : verdict === "fp" ? "bad" : "";
  if (dir === "dropped") return verdict === "tp" ? "bad" : verdict === "fp" ? "good" : "";
  return "";
}
function whyTitle(w, dir) {
  if (!w) return "no computed reason";
  const other = dir === "added" ? "reference" : "candidate";
  switch (w.key) {
    case "record/rejected-in-candidate": return "rejected in the candidate's DB";
    case "record/rejected-in-reference": return "rejected in the reference DB";
    case "record/absent-in-reference": return `new record${w.to ? ` in ${w.to}` : ""}`;
    case "record/absent-in-candidate": return `record gone${w.from ? ` from ${w.from}` : ""}`;
    case "package/absent-in-reference": return "vulnerability known, package newly affected";
    case "package/absent-in-candidate": return "vulnerability known, package no longer affected";
    case "namespace/changed": return `namespace ${w.from} → ${w.to}`;
    case "fix-state/changed": return `fix state ${w.from} → ${w.to}`;
    case "constraint/changed": return "version constraint changed";
    case "record/same-but-unmatched": return `same record in the ${other} DB, no match`;
    case "match-type/cpe-only": return "matched by CPE only";
    case "matcher/changed": return "matcher changed";
    case "unexplained": return "unexplained";
    default: return w.key;
  }
}
// reasonTitle is a reason node's title: the agent's explanation when every row under it shares one
// (an explanation never changes a verdict, it only says why the setups differ), else the computed
// reason
function reasonTitle(list, dir) {
  const id = list[0]?.r.explanation;
  const ex = id && list.every((x) => x.r.explanation === id) && (ui.state.explanations || []).find((e) => e.id === id);
  return ex ? `✎ ${ex.title}` : whyTitle(list[0]?.r.why, dir);
}
const whyKey = (w) => (w ? `${w.key}|${w.from || ""}|${w.to || ""}` : "none");
function subjectName(si) {
  const s = ui.state.scans.subjects?.[si];
  return s?.name || s?.slug || `subject ${si + 1}`;
}

// ---------- data ----------

async function load() {
  try {
    ui.state = await get(ui.gateName, "/state");
  } catch (e) {
    $("#map").replaceChildren(el("div", { class: "empty" }, e.message));
    return;
  }
  ui.details.clear();
  ui.matches.clear();
  previews.clear(); ui.preview = null;
  document.title = `yardstick · map · ${ui.state.scans.label || ui.gateName}`;
  if (!ui.booted) { ui.booted = true; Object.assign(ui, parseURL()); }
  render();
  countForResearch();
}

// diffRows are the differing rows in scope, each with its subject index
function diffRows(si = ui.si) {
  const out = [];
  ui.state.subjects.forEach((s, i) => {
    if (si != null && i !== si) return;
    for (const r of s.rows) { const d = direction(r); if (d === "added" || d === "dropped") out.push({ r, si: i, dir: d }); }
  });
  return out;
}

// tally counts a set of rows by label state
function tally(list) {
  const t = { n: list.length, tp: 0, fp: 0, unclear: 0, open: 0, hinted: 0, triaged: 0, researched: 0, decisive: 0, bears: 0, conflicts: 0 };
  for (const { r } of list) {
    if (r.verdict === "tp" && !r.conflict) t.tp++;
    else if (r.verdict === "fp" && !r.conflict) t.fp++;
    else if (r.verdict === "unclear" && !r.conflict) t.unclear++;
    else t.open++;
    if (hinted(r)) t.hinted++;
    if (isResearched(r)) t.researched++;
    else if (researchLevel(r) === "triaged") t.triaged++;
    if (r.conflict) t.conflicts++;
    if (isOpen(r) && decisive(r)) t.decisive++;
    else if (isOpen(r) && bears(r)) t.bears++;
  }
  return t;
}


// ---------- navigation lives in the URL (docs/alternate-uis.md §11) ----------
// /ui/map/gates/<run>/                                   the gate board (the delta map on an ad-hoc run)
// /ui/map/gates/<run>/delta                              the scan-delta map
// /ui/map/gates/<run>/delta/<dir>/<why>                  zoomed into one reason
// /ui/map/gates/<run>/delta/<dir>/<why>/<pkg|all>        cards: a package of that reason (or all of it)
// /ui/map/gates/<run>/check/<name>/cause/<id>            cards: a same-reasoning group of a check
// /ui/map/gates/<run>/check/<name>/tier/<t>/<dir>/<pkg>  cards: a package in one tier of a check
// /ui/map/gates/<run>/check/<name>/fails[/<vuln>/<pkg>]  cards: the claims a failed check fails on
// ?image=<slug> scopes every view to one image; #row=<id>[&evidence] is the selected card.
// Views push history (Esc = back); the selected card and its evidence replace the entry.
const seg = (x) => encodeURIComponent(String(x));
function urlFor() {
  const parts = [], s = ui.cardsSpec;
  if (s?.kind === "delta") parts.push("delta", s.dir, s.why, s.pkg ?? "all");
  else if (s?.kind === "cause") parts.push("check", s.check, "cause", s.cause);
  else if (s?.kind === "tier") parts.push("check", s.check, "tier", s.tier, s.dir, s.pkg);
  else if (s?.kind === "fails") { parts.push("check", s.check, "fails"); if (s.vuln) parts.push(s.vuln, s.pkg); }
  else if (ui.zoom) parts.push("delta", ui.zoom.dir, ui.zoom.why);
  else if (ui.delta) parts.push("delta");
  let url = ui.base + parts.map(seg).join("/");
  if (ui.si != null) url += `?image=${seg(ui.state?.scans.subjects?.[ui.si]?.slug ?? ui.si)}`;
  if (ui.selected && s) url += `#row=${ui.selected}${ui.evidence ? "&evidence" : ""}`;
  return url;
}
function parseURL() {
  const p = location.pathname.slice(ui.base.length).split("/").filter(Boolean).map(decodeURIComponent);
  const st = { si: null, delta: false, zoom: null, cardsSpec: null, selected: null, evidence: false };
  const img = new URLSearchParams(location.search).get("image"), subs = ui.state?.scans.subjects || [];
  if (img != null) {
    const i = subs.findIndex((x) => x.slug === img || (x.oldSlugs || []).includes(img));
    st.si = i >= 0 ? i : /^\d+$/.test(img) && Number(img) < subs.length ? Number(img) : null;
  }
  if (p[0] === "delta") {
    st.delta = true;
    if (p[1] && p[2]) { st.zoom = { dir: p[1], why: p[2] }; if (p[3]) st.cardsSpec = { kind: "delta", dir: p[1], why: p[2], pkg: p[3] === "all" ? null : p[3] }; }
  } else if (p[0] === "check" && p[1]) {
    if (p[2] === "cause" && p[3]) st.cardsSpec = { kind: "cause", check: p[1], cause: p[3] };
    else if (p[2] === "tier" && p.length >= 6) st.cardsSpec = { kind: "tier", check: p[1], tier: Number(p[3]), dir: p[4], pkg: p[5] };
    else if (p[2] === "fails") st.cardsSpec = { kind: "fails", check: p[1], vuln: p[3] || null, pkg: p[4] || null };
  }
  const h = location.hash.match(/row=([0-9a-f]{16})(&evidence)?/);
  if (h) { st.selected = h[1]; st.evidence = !!h[2]; }
  return st;
}
// navigate changes the view and pushes it (or replaces the entry, for the selected card)
function navigate(changes, { replace = false } = {}) {
  if ("cardsSpec" in changes) ui.pin = null;
  Object.assign(ui, changes);
  const url = urlFor();
  if (url !== location.pathname + location.search + location.hash) {
    if (replace) history.replaceState(null, "", url); else { history.pushState(null, "", url); ui.pushes++; }
  }
  render();
}
// back is Esc: the browser's back through what this page pushed, else the view's parent
function back() {
  if (ui.pushes > 0) { ui.pushes--; history.back(); return; }
  const s = ui.cardsSpec;
  if (s) navigate({ cardsSpec: null, selected: null, evidence: false, delta: s.kind === "delta", zoom: s.kind === "delta" ? { dir: s.dir, why: s.why } : null });
  else if (ui.zoom) navigate({ zoom: null });
  else if (ui.delta) navigate({ delta: false });
}
// select is the selected card and whether its evidence is open: the same history entry
function select(id, evidence = ui.evidence) {
  if (id !== ui.pin) ui.pin = null;
  ui.selected = id; ui.evidence = evidence; ui.why = false; ui.receipt = null;
  history.replaceState(null, "", urlFor());
  renderTile();
}
window.addEventListener("popstate", () => { if (ui.state) { Object.assign(ui, parseURL()); render(); } });

// cardsFor turns the URL's card spec into the rows to show, from the current state
function cardsFor(s) {
  if (!s) return null;
  if (s.kind === "delta") {
    const rows = diffRows().filter((x) => x.dir === s.dir && whyKey(x.r.why) === s.why && (s.pkg == null || srcPkg(x.r) === s.pkg));
    return { title: `${dirTitle[s.dir] || s.dir} › ${reasonTitle(rows, s.dir)}${s.pkg ? ` › ${s.pkg}` : ""}`, ids: new Set(rows.map((x) => x.r.id)) };
  }
  const c = ui.state.gate?.result?.checks.find((k) => k.name === s.check);
  if (!c) return null;
  if (s.kind === "fails") {
    let rows = failingClaims(c);
    if (s.vuln) rows = rows.filter((x) => x.r.vulnerability === s.vuln && srcPkg(x.r) === s.pkg);
    return { title: s.vuln ? `${c.name} fails on ${s.vuln} · ${s.pkg}` : `${c.name}: the ${plural(rows.length, "claim")} it fails on`, ids: new Set(rows.map((x) => x.r.id)) };
  }
  const gs = groups(bearing(c));
  const g = s.kind === "cause" ? gs.find((x) => x.cause?.id === s.cause) : gs.find((x) => !x.cause && tierOf(x.tier) === s.tier && x.dir === s.dir && x.pkg === s.pkg);
  if (!g) return null;
  return { title: `${c.name} › ${g.cause ? `✦ ${g.cause.title}` : `${marks[g.dir]} ${g.pkg}`}`, ids: new Set(g.rows.map((x) => x.r.id)) };
}
const specOfGroup = (c, g) => (g.cause ? { kind: "cause", check: c.name, cause: g.cause.id } : { kind: "tier", check: c.name, tier: tierOf(g.tier), dir: g.dir, pkg: g.pkg });
const openSpec = (spec) => navigate({ cardsSpec: spec, selected: null, evidence: false });

// ---------- render ----------

function render() {
  ui.cards = cardsFor(ui.cardsSpec);
  if (ui.cards && ui.pin) ui.cards.ids.add(ui.pin); // staying on a match just labeled (afterWrite)
  if (ui.cardsSpec && !ui.cards?.ids.size) { ui.cardsSpec = null; ui.cards = null; history.replaceState(null, "", urlFor()); }
  renderHeader();
  renderGate();
  renderImages();
  if (ui.research && ui.research.scope !== researchScope()) countForResearch(); // the image scope changed
  if (ui.cards) renderTile();
  else if (ui.state.gate?.result && !ui.delta) renderBoard();
  else renderMap();
}

function renderHeader() {
  const st = ui.state, c = st.candidate || {}, r = st.reference || c;
  const field = (k, v, title) => el("span", { class: "field", "data-k": k, title }, v);
  const gv = (s) => s.grype?.spec?.version || s.grype?.spec?.path;
  const grype = gv(c) === gv(r) ? el("b", {}, gv(c) || "?") : [el("b", {}, gv(r) || "?"), " → ", el("b", {}, gv(c) || "?")];
  const dbName = (db) => (db?.source || db?.requested || "").split("/").pop().replace(/^vulnerability-db_/, "").replace(/\.tar\.zst$/, "") || "?";
  const db = c.db?.checksum && c.db.checksum === r.db?.checksum ? el("b", {}, dbName(c.db)) : [el("b", {}, dbName(r.db)), " → ", el("b", {}, dbName(c.db))];
  const cfgName = (f) => (f ? f.path.split("/").pop() : "default");
  const cfg = (c.config?.sha256 || "") === (r.config?.sha256 || "") ? el("b", {}, cfgName(c.config)) : [el("b", {}, cfgName(r.config)), " → ", el("b", {}, cfgName(c.config))];
  $("#compared").replaceChildren(
    field("gate", el("b", {}, st.gate?.name || st.scans.id), st.gate?.description || ""),
    field("scanned", el("b", {}, new Date(st.scans.created).toLocaleDateString(undefined, { month: "short", day: "numeric" })), `${new Date(st.scans.created).toLocaleString()}: re-scan only when the gate's subjects or setups change; labels count at once`),
    field("grype", grype, `${gv(r)} (reference) vs ${gv(c)} (candidate)`),
    field("DB", db, `${r.db?.checksum || ""} (reference)\n${c.db?.checksum || ""} (candidate)`),
    field("config", cfg, `${r.config?.path || "grype defaults"} (reference)\n${c.config?.path || "grype defaults"} (candidate)`),
  );
}

// noResult says why a gate has no result, which makes it undecided: it has no gate file (so no
// checks), or it changed since it was scanned (so it needs re-scanning, with the command in note).
function noResult(g) {
  return g?.noFile ? "undecided · no checks" : g?.rerun ? "undecided · re-scan needed" : "undecided";
}

// unchanged: a passing gate whose scans don't differ in any image. Its checks compare nothing to
// nothing, so it gets one plain headline instead of a board of zeroes. Returns the matches both
// sides report and the image count, else null.
function unchanged() {
  if (ui.state.gate?.result?.outcome !== "pass" || diffRows(null).length) return null;
  return { shared: allRows(null).length, images: ui.state.subjects.length };
}

// the gate: one range bar per check, worst → best against the threshold
function renderGate() {
  const g = ui.state.gate, box = $("#gate");
  const all = diffRows(null), t = tally(all);
  if (!g?.result) {
    box.replaceChildren(el("span", { class: "band band-undecided", title: g?.note || "" }, noResult(g)),
      g?.note ? el("span", { class: "muted" }, g.note) : null,
      el("span", { class: "summary" }, `${plural(t.n, "delta")} · ${t.open} unlabeled · ${t.hinted} with an agent hint`));
    return;
  }
  const res = g.result, same = unchanged();
  if (same) {
    box.replaceChildren(el("span", { class: "band band-pass" }, "✓ no differences"),
      el("span", { class: "summary" }, `gate ${g.name} · both sides report the same ${plural(same.shared, "match", "matches")} in ${plural(same.images, "image")}: nothing to label`));
    return;
  }
  const est = res.checks.filter((c) => c.state === "undecided" && c.estimate).map((c) => c.estimate.toDecide);
  const onBoard = !ui.delta && !ui.cards;
  // The board and the delta map are two views of the gate: this switches between them. On a match
  // the breadcrumb is the one way back (Esc too), so the switch isn't offered there.
  const p = ui.preview;
  box.replaceChildren(
    el("span", { class: `band band-${res.outcome}` }, res.outcome),
    el("span", { class: "summary" }, `gate ${g.name} · ${res.ci === res.outcome ? "" : `CI reads it as ${res.ci} · `}${plural(res.checks.length, "check")}: ${res.checks.filter((c) => c.state === "pass").length} pass, ${res.checks.filter((c) => c.state === "fail").length} fail, ${res.checks.filter((c) => c.state === "undecided").length} undecided`),
    ui.cards ? null : el("button", { class: "ghost", onclick: () => navigate({ delta: onBoard, zoom: null, cardsSpec: null, selected: null, evidence: false }) }, onBoard ? "scan delta map" : "gate board"),
    ...(onBoard ? [] : res.checks.map((c) => gateBar(c))),
    // while an accept is hovered, the last line says what the dashed ghosts are, in the same place,
    // so the ribbon keeps its height and the hovered control doesn't move
    p ? el("span", { class: "summary preview-note" }, p.result ? `dashed: where the bars would be if ${p.what} were accepted${p.result.outcome !== res.outcome ? ` · the gate would be ${p.result.outcome}` : ""}` : `working out where ${p.what} would move the bars…`)
      : el("span", { class: "summary" }, res.outcome === "undecided" ? `◆ ${plural(t.decisive, "delta")} could change the verdict${est.length ? ` · about ${Math.min(...est)} labels could decide it (an estimate)` : ""}` : `${t.open} unlabeled of ${t.n}`),
  );
}

// ---------- previewing an accept: where the bars would move ----------

// previewAccept shows, while an accept control is hovered, the gate as if its agent hints were
// accepted: labels maps row id → the verdict accepting would write. The server evaluates it
// (POST /preview writes nothing); results are cached by their rows until the next load.
const previews = new Map();
async function previewAccept(labelsByRow, what) {
  const ids = Object.keys(labelsByRow);
  if (!ids.length || !ui.state.gate?.result) return;
  const key = ids.sort().map((id) => `${id}=${labelsByRow[id]}`).join(",");
  ui.preview = { key, what, result: previews.get(key) || null };
  showPreview();
  if (ui.preview.result) return;
  try {
    const result = await post(ui.gateName, "/preview", { labels: labelsByRow });
    previews.set(key, result);
    if (ui.preview?.key === key) { ui.preview.result = result; showPreview(); }
  } catch (e) {
    if (ui.preview?.key === key) ui.preview = null;
    showPreview();
  }
}
function endPreview() { if (ui.preview) { ui.preview = null; showPreview(); } }
// showPreview redraws the ribbon and the board's bars in place, leaving the hovered control alone
function showPreview() {
  renderGate();
  const checks = ui.state.gate?.result?.checks || [];
  for (const n of document.querySelectorAll<HTMLElement>(".panel .gcheck[data-check]")) {
    const c = checks.find((k) => k.name === n.dataset.check);
    if (c) n.replaceWith(gateBar(c, { head: false }));
  }
}
// previewOn wires hover and focus on an accept control to the preview
const previewOn = (labelsOf, what) => ({
  onmouseenter: () => previewAccept(labelsOf(), what), onmouseleave: endPreview,
  onfocus: () => previewAccept(labelsOf(), what), onblur: endPreview,
});
// hintLabels is what accepting the pending agent hints on these rows would write
function hintLabels(rows) {
  const out = {};
  for (const r of rows) if (hinted(r)) out[r.id] = r.hint.verdict;
  return out;
}
function causeLabels(cause, ids) {
  const out = {};
  for (const id of ids) if (cause.pending.includes(id)) out[id] = cause.verdict;
  return out;
}

// gateBar draws one check: its name and state over a bar of where its value can still land (worst
// to best case for the candidate, until the open deltas are labeled) against the threshold line.
// Both marks say what they are on the bar itself. With ui.preview (hovering an accept control),
// a dashed ghost range shows where the bar would move if those agent hints were accepted.
function gateBar(c, { head = true } = {}) {
  const worst = c.value.worst, best = c.value.best, thr = c.threshold;
  const ghost = ui.preview?.result?.checks.find((k) => k.name === c.name);
  const moved = ghost && (ghost.value.worst !== worst || ghost.value.best !== best);
  // the passing side is the check's direction (atLeast: right); without one, where "best" lies
  const passRight = c.direction ? c.direction === "atLeast" : best >= worst;
  const vals = [worst, best, thr, ...(moved ? [ghost.value.worst, ghost.value.best] : [])];
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const pad = (hi - lo || Math.max(Math.abs(thr), 1) * 0.5) * 0.3, min = lo - pad, max = hi + pad;
  const W = 260, H = 40, L = 4, R = 4, Y = 18;
  const x = (v) => L + ((v - min) / (max - min)) * (W - L - R);
  const a = x(Math.min(worst, best)), b = x(Math.max(worst, best));
  const t = x(thr);
  // a label centered at x, kept inside the bar (cw: about a character's width at its size)
  const centered = (text, at, cw) => Math.max(L + (text.length * cw) / 2, Math.min(W - R - (text.length * cw) / 2, at));
  // over the range, in its drawn order: "worst 14 … 2 best" or "best 2 … 14 worst"
  const worstLeft = x(worst) <= x(best);
  const ends = worstLeft ? [["worst", worst], ["best", best]] : [["best", best], ["worst", worst]];
  const rangeText = worst === best ? `${fmt(worst)} (no unlabeled delta moves it)` : `${ends[0][0]} ${fmt(ends[0][1])} … ${fmt(ends[1][1])} ${ends[1][0]}`;
  // under the threshold line: what it is and which side passes
  const thrText = `threshold: pass if ${passRight ? "≥" : "≤"} ${fmt(thr)}`;
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}` },
    svg("line", { x1: L, x2: W - R, y1: Y + 5, y2: Y + 5, class: "axis" }),
    svg("rect", { x: a, y: Y, width: Math.max(3, b - a), height: 10, rx: 3, class: "range" },
      svg("title", {}, `${c.valueMeans}: ${fmt(worst)} in the worst case … ${fmt(best)} in the best case for the candidate. Labeling the open deltas narrows it.`)),
    moved ? svg("rect", { x: x(Math.min(ghost.value.worst, ghost.value.best)), y: Y - 3, width: Math.max(3, x(Math.max(ghost.value.worst, ghost.value.best)) - x(Math.min(ghost.value.worst, ghost.value.best))), height: 16, rx: 3, class: "ghost-range" }) : null,
    svg("line", { x1: t, x2: t, y1: Y - 5, y2: Y + 15, class: "thr" }, svg("title", {}, thrText)),
    svg("text", { x: centered(thrText, t, 5.2), y: H - 1, "text-anchor": "middle", class: "side" }, thrText),
    svg("text", { x: centered(rangeText, (a + b) / 2, 6), y: Y - 7, "text-anchor": "middle" }, rangeText),
  );
  // a preview that changes the check's state says so: in the head, or (on a board panel, whose head
  // is elsewhere) after the range, so the panel doesn't grow under the hovered control
  const flips = moved && ghost.state !== c.state;
  if (flips && !head) s.lastChild.textContent += `  → ${ghost.state}`;
  const st = flips ? [el("span", { class: "st" }, c.state), el("span", { class: `st to ${ghost.state}` }, ` → ${ghost.state}`)] : el("span", { class: "st" }, c.state);
  return el("div", { class: `gcheck ${c.state}${moved ? " previewing" : ""}`, title: c.description, "data-check": c.name },
    head ? el("div", { class: "nm" }, c.name, " ", st) : null, s);
}

function renderImages() {
  const box = $("#images");
  const subs = ui.state.subjects.map((s, si) => ({ si, t: tally(diffRows(si)) }));
  box.replaceChildren(
    el("div", { class: `img${ui.si == null ? " on" : ""}`, onclick: () => scope(null) }, el("div", { class: "nm" }, "every image"), stack(tally(diffRows(null))), nums(tally(diffRows(null)))),
    ...subs.map(({ si, t }) => el("div", { class: `img${ui.si === si ? " on" : ""}${t.n ? "" : " quiet"}`, title: `${subjectName(si)} (${si + 1})`, onclick: () => scope(si) },
      el("div", { class: "nm" }, `${si + 1} · ${subjectName(si)}`), stack(t), nums(t))),
  );
}
function stack(t) {
  const seg = (k, n) => (n ? el("span", { class: `seg-${k}`, style: `width:${(n / t.n) * 100}%`, title: `${n} ${k}` }) : null);
  return el("div", { class: "stack" }, t.n ? [seg("tp", t.tp), seg("fp", t.fp), seg("unclear", t.unclear), seg("hint", t.hinted)] : null);
}
function nums(t) {
  return el("div", { class: "nums" }, el("span", {}, el("b", {}, String(t.n)), " diff"), el("span", {}, el("b", {}, String(t.open)), " open"), t.decisive ? el("span", { class: "decisive" }, `◆ ${t.decisive}`) : null);
}
function scope(si) {
  navigate({ si: ui.si === si ? null : si, zoom: null, cardsSpec: null, selected: null, evidence: false });
}

// ---------- the treemap ----------

function worstRatio(row, side) {
  const s = row.reduce((a, i) => a + i.area, 0), mx = Math.max(...row.map((i) => i.area)), mn = Math.min(...row.map((i) => i.area));
  return Math.max((side * side * mx) / (s * s), (s * s) / (side * side * mn));
}
// squarify lays items (with value) into rect, biggest first, rows along the shorter side
function squarify(items, rect) {
  const out = [];
  let { x, y, w, h } = rect;
  const total = items.reduce((s, i) => s + i.value, 0);
  let list = items.filter((i) => i.value > 0).sort((a, b) => b.value - a.value).map((i) => ({ ...i, area: (i.value / total) * w * h }));
  while (list.length && w > 0 && h > 0) {
    const horizontal = w >= h; // the row is a column stacked left to right when wide
    const side = horizontal ? h : w;
    let row = [], best = Infinity;
    for (const it of list) {
      const cand = [...row, it], r = worstRatio(cand, side);
      if (r <= best) { row = cand; best = r; } else break;
    }
    const rowArea = row.reduce((s, i) => s + i.area, 0), thick = rowArea / side;
    let off = 0;
    for (const it of row) {
      const len = it.area / thick;
      out.push(horizontal ? { ...it, x, y: y + off, w: thick, h: len } : { ...it, x: x + off, y, w: len, h: thick });
      off += len;
    }
    if (horizontal) { x += thick; w -= thick; } else { y += thick; h -= thick; }
    list = list.slice(row.length);
  }
  return out;
}

function groupBy(list, keyOf) {
  const m = new Map();
  for (const it of list) { const k = keyOf(it); if (!m.has(k)) m.set(k, []); m.get(k).push(it); }
  return m;
}

function renderMap() {
  $("#tile").hidden = true;
  const map = $("#map");
  map.hidden = false;
  const rows = diffRows();
  const crumbs = el("div", { class: "crumbs" },
    el("button", { onclick: () => navigate({ zoom: null, cardsSpec: null, selected: null, evidence: false }) }, ui.si == null ? "every image" : subjectName(ui.si)),
    ui.zoom ? [" › ", el("b", {}, `${dirTitle[ui.zoom.dir]} › ${reasonTitle(rows.filter((x) => x.dir === ui.zoom.dir && whyKey(x.r.why) === ui.zoom.why), ui.zoom.dir)}`),
      el("button", { class: "ghost", style: "text-decoration:none;margin-left:8px", onclick: () => openSpec({ kind: "delta", dir: ui.zoom.dir, why: ui.zoom.why, pkg: null }) }, "label all as cards")]
      : el("span", {}, " · a block is a source package: its size is how many matches, the bar at its bottom how they're labeled; click one to label its matches, or a reason's title to look at that reason alone"),
    el("span", { class: "spacer" }), researchControls(),
  );
  const W = Math.max(600, map.clientWidth || 900), H = Math.max(300, (map.clientHeight || 500) - 60);
  const tree = svg("svg", { class: "tree", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
  tree.append(svg("defs", {}, svg("pattern", { id: "hatchmap", width: 6, height: 6, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" },
    svg("line", { x1: 0, y1: 0, x2: 0, y2: 6, stroke: "currentColor", "stroke-width": 2, opacity: .3 }))));
  if (!rows.length) {
    tree.append(svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", class: "empty" }, "no differences in scope"));
  } else if (ui.zoom) {
    const inZoom = rows.filter((x) => x.dir === ui.zoom.dir && whyKey(x.r.why) === ui.zoom.why);
    packages(tree, inZoom, { x: 2, y: 2, w: W - 4, h: H - 4 }, ui.zoom.dir, ui.zoom.why);
  } else {
    const dirs = ["added", "dropped"].map((dir) => ({ dir, list: rows.filter((x) => x.dir === dir) })).filter((d) => d.list.length);
    const total = rows.length, gap = 10;
    let x = 2;
    for (const d of dirs) {
      const w = dirs.length === 1 ? W - 4 : Math.max((W - 4 - gap) * 0.22, ((W - 4 - gap) * d.list.length) / total);
      const width = dirs.length === 1 ? w : Math.min(w, W - 4 - gap - (W - 4 - gap) * 0.22);
      tree.append(svg("rect", { x, y: 0, width, height: H, class: `dirbg-${d.dir}` }));
      tree.append(svg("text", { x: x + 6, y: 15, class: "dir" }, `${dirTitle[d.dir]} · ${d.list.length}`));
      const items = [...groupBy(d.list, (x) => whyKey(x.r.why))].map(([k, list]) => ({ key: k, title: reasonTitle(list, d.dir), list, value: list.length }));
      // one reason: no reason level to draw, the packages take the panel and the reason is its subtitle
      if (items.length === 1) {
        tree.append(svg("text", { x: x + 6, y: 32, class: "sub" }, `${items[0].title} · ${items[0].list.length}`));
        packages(tree, items[0].list, { x: x + 2, y: 38, w: width - 4, h: H - 40 }, d.dir, items[0].key);
      } else {
        for (const b of squarify(items, { x: x + 2, y: 22, w: width - 4, h: H - 24 })) reasonBlock(tree, b, d.dir);
      }
      x += width + gap;
    }
  }
  const legend = el("div", { class: "legend" }, el("span", {}, el("i", { class: "i-tp" }), "TP real match"), el("span", {}, el("i", { class: "i-fp" }), "FP false match"), el("span", {}, el("i", { class: "i-unclear" }), "unclear"),
    el("span", {}, el("i", { class: "i-hint" }), "unlabeled, with an agent hint"), el("span", {}, el("i", { class: "i-open" }), "unlabeled"), el("span", {}, "◆ could change the verdict"));
  map.replaceChildren(crumbs, tree, el("div", { class: "hover-line", id: "hover" }), legend);
  map.style.gridTemplateRows = "auto 1fr auto auto";
}

// reasonBlock is one reason's area: a header strip (click: that reason alone) over its packages.
function reasonBlock(tree, b, dir) {
  const t = tally(b.list), head = 20;
  const g = svg("g", { onmouseenter: () => hover(b, t), onmouseleave: () => hover(null) });
  g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, class: "reason" }));
  g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: Math.min(head, b.h), class: "reason-head", onclick: () => navigate({ zoom: { dir, why: b.key } }) },
    svg("title", {}, `${b.title} · ${plural(t.n, "line")} · click to look at this reason alone`)));
  if (b.w > 60 && b.h > head) g.append(svg("text", { x: b.x + 5, y: b.y + 14, class: "ttl" }, clip(`${t.decisive ? "◆ " : ""}${b.title} · ${t.n}`, b.w / 7)));
  tree.append(g);
  if (b.h > head + 12) packages(tree, b.list, { x: b.x + 1, y: b.y + head + 1, w: b.w - 2, h: b.h - head - 2 }, dir, b.key);
}

// packages draws one block per source package into rect; clicking one opens its cards.
function packages(tree, list, rect, dir, why) {
  const items = [...groupBy(list, (x) => srcPkg(x.r))].map(([k, l]) => ({ key: k, title: k, list: l, value: l.length }));
  for (const b of squarify(items, rect)) tree.append(block(b, () => openSpec({ kind: "delta", dir, why, pkg: b.key })));
}

// block draws one package block: its name and count, ◆ when it holds lines that could change the
// verdict, and a bar at its bottom with its labels (TP, FP, unclear, suggested; the rest open).
function block(b, onclick) {
  const t = tally(b.list);
  const g = svg("g", { onclick, onmouseenter: () => hover(b, t), onmouseleave: () => hover(null) });
  g.append(svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, class: "blk" }, svg("title", {}, `${b.title} · ${plural(t.n, "line")} · ${t.tp} TP · ${t.fp} FP · ${t.unclear} unclear · ${t.open} unlabeled (${t.hinted} with an agent hint)${t.researched ? ` · ✦ ${t.researched} researched` : ""}${t.triaged ? ` · ✦ ${t.triaged} triaged` : ""}${t.decisive ? ` · ◆ ${t.decisive} could change the verdict` : ""}\nclick to label these as cards`)));
  const pad = Math.min(4, b.w / 10, b.h / 10), barH = Math.min(8, Math.max(3, b.h / 6));
  let off = 0;
  const by = b.y + b.h - pad - barH, bw = b.w - 2 * pad;
  g.append(svg("rect", { x: b.x + pad, y: by, width: Math.max(0, bw), height: barH, class: "bar-track", "pointer-events": "none" }));
  for (const [k, n] of [["tp", t.tp], ["fp", t.fp], ["unclear", t.unclear], ["hint", t.hinted]] as [string, number][]) {
    if (!n) continue;
    const w = (bw * n) / t.n;
    g.append(svg("rect", { x: b.x + pad + off, y: by, width: w, height: barH, class: `fill-${k}`, "pointer-events": "none" }));
    off += w;
  }
  if (b.w > 60 && b.h > 34) {
    g.append(svg("text", { x: b.x + 5, y: b.y + 14, class: "ttl" }, clip(`${t.decisive ? "◆ " : ""}${b.title}`, b.w / 7)));
    g.append(svg("text", { x: b.x + 5, y: b.y + 27, class: "sub" }, clip(`${t.n} · ${t.open} open${t.hinted ? ` · ✦ ${t.hinted}` : ""}`, b.w / 6.5)));
  } else if (b.w > 24 && b.h > 16) {
    g.append(svg("text", { x: b.x + 3, y: b.y + 11, class: "sub" }, clip(`${b.title} ${t.n}`, b.w / 6.5)));
  }
  return g;
}
const clip = (s, n) => (s.length > n ? `${s.slice(0, Math.max(1, Math.floor(n) - 1))}…` : s);

function hover(b, t?) {
  const line = $("#hover");
  if (!line) return;
  if (!b) { line.textContent = ""; return; }
  const checks = [...new Set(b.list.flatMap((x) => x.r.gate?.couldFlip || []))];
  const pkgs = [...new Set(b.list.map((x) => srcPkg(x.r)))];
  line.textContent = `${b.title} · ${plural(t.n, "line")} in ${plural(pkgs.length, "source package")} · ${t.tp} TP · ${t.fp} FP · ${t.open} unlabeled, ${t.hinted} with an agent hint${t.researched ? ` · ✦ ${t.researched} researched` : ""}${t.triaged ? ` · ✦ ${t.triaged} triaged` : ""}` +
    (t.decisive ? ` · ◆ ${t.decisive} could change ${checks.join(", ")}` : t.bears ? ` · ${t.bears} could narrow a check` : "");
}


// ---------- the gate board: one panel per check, what decides it, and the cheapest labels first ----------

// tier ranks an open row by what its label does for the gate: 0 ends the gate now, 1 a dropped
// finding (one TP is a regression: fails noNewFalseNegatives outright), 2 agent-suggested (high
// confidence first; one accept can label many), 3 the rest; findings both sides report come last
// within a tier, since only the F1 check feels them.
function tier(r, dir) {
  const res = ui.state.gate?.result, now = res?.outcome;
  if (!isOpen(r)) return 9;
  const g = r.gate;
  if (g && now && (g.ifTP?.outcome !== now || g.ifFP?.outcome !== now)) return 0;
  // a dropped finding is a regression risk while a check that counts false negatives is open (the
  // check says what it counts); one the agent already reads as FP is a cleanup to accept
  const fnOpen = (res?.checks || []).some((c) => c.counts === "fn" && c.state === "undecided");
  let t = dir === "dropped" && fnOpen && !(hinted(r) && r.hint.verdict === "fp") ? 1 : hinted(r) ? 2 + (({ high: 0, medium: 0.3, low: 0.6 })[r.hint.confidence] ?? 0.6) : 3;
  if (dir === "both") t += 0.05;
  return t;
}
const tierNames = { 0: "a label here ends the gate now", 1: "− dropped: a TP here is a regression", 2: "✦ agent hint: one accept can label many", 3: "the rest" };
const tierOf = (t) => Math.min(3, Math.floor(t));

// failingClaims are the rows whose existing claims a failed check counts against it: the check
// names them (failsOn); a check that doesn't has none to show.
function failingClaims(c) {
  const ids = new Set(c.failsOn || []);
  return ids.size ? allRows().filter((x) => ids.has(x.r.id)) : [];
}

// bearing lists the open rows whose label narrows a check
const bearing = (c) => allRows().filter((x) => x.r.gate && isOpen(x.r) && ((x.r.gate.bears || []).includes(c.name) || (x.r.gate.couldFlip || []).includes(c.name)));

// groups folds a check's bearing rows into the things one action settles: a same-reasoning group
// (one accept labels every pending member) or a source package in one direction, by tier.
function groups(rows) {
  const causes = new Map(ui.state.causes.map((c) => [c.id, c]));
  const byKey = new Map();
  for (const x of rows) {
    const cause = (x.r.causes || []).map((id) => causes.get(id)).find((c) => c && c.pending?.includes(x.r.id));
    const t = tier(x.r, x.dir);
    const key = cause ? `c|${cause.id}` : `p|${tierOf(t)}|${x.dir}|${srcPkg(x.r)}`;
    if (!byKey.has(key)) byKey.set(key, { key, tier: t, cause, dir: x.dir, pkg: srcPkg(x.r), rows: [] });
    const g = byKey.get(key);
    g.rows.push(x);
    g.tier = Math.min(g.tier, t);
  }
  return [...byKey.values()].sort((a, b) => (tierOf(a.tier) - tierOf(b.tier)) || (b.rows.length - a.rows.length) || (a.tier - b.tier) || a.pkg.localeCompare(b.pkg));
}

function renderBoard() {
  $("#tile").hidden = true;
  const map = $("#map");
  map.hidden = false;
  map.style.gridTemplateRows = "auto 1fr";
  if (ui.scrollTo) { const name = ui.scrollTo; ui.scrollTo = null; ui.opened.add(`pass|${name}`); setTimeout(() => document.getElementById(`panel-${name}`)?.scrollIntoView({ block: "start" }), 0); }
  const res = ui.state.gate.result, same = unchanged();
  if (same) {
    map.style.gridTemplateRows = "1fr";
    map.replaceChildren(el("div", { class: "same" },
      el("div", { class: "big" }, "✓ No differences"),
      el("p", {}, `The candidate and the reference report exactly the same ${plural(same.shared, "match", "matches")} in ${plural(same.images, "image")}. Nothing changed, so there is nothing to label and no check sees a change.`),
      el("p", { class: "muted" }, "If the candidate was meant to change something, these images don't exercise it: add images that do and re-scan."),
      el("p", { class: "muted" }, `checks, all passing: ${res.checks.map((c) => c.name).join(", ")}`)));
    return;
  }
  const bearingRows = allRows().filter((x) => isOpen(x.r) && x.r.gate), both = bearingRows.filter((x) => x.dir === "both").length;
  const crumbs = el("div", { class: "crumbs" }, el("b", {}, ui.si == null ? "every image" : subjectName(ui.si)),
    el("span", {}, ` · ${plural(bearingRows.length - both, "unlabeled delta")}${both ? ` and ${both} unlabeled matches both scans report` : ""} could move a check · each panel is one check: what it needs, and the labels that get there cheapest`),
    el("span", { class: "spacer" }), researchControls());
  map.replaceChildren(crumbs, el("div", { class: "board" }, ...res.checks.map((c) => panel(c, open))));
}

function panel(c, open) {
  const rng = c.value.worst === c.value.best ? fmt(c.value.worst) : `${fmt(c.value.worst)} (worst) … ${fmt(c.value.best)} (best)`;
  // a passing check has nothing to act on: it folds to its head, and the head unfolds it
  const key = `pass|${c.name}`, folded = c.state === "pass" && !ui.opened.has(key);
  const toggle = () => { ui.opened.has(key) ? ui.opened.delete(key) : ui.opened.add(key); render(); };
  const box = el("section", { class: `panel ${c.state}${folded ? " folded" : ""}`, id: `panel-${c.name}` });
  box.append(el("div", { class: "panel-head", ...(c.state === "pass" ? { onclick: toggle, title: folded ? "show this check" : "fold this check" } : {}) },
    el("span", { class: `band band-${c.state}` }, c.state), el("b", { class: "nm" }, c.name), el("span", { class: "means" }, folded ? `${c.valueMeans} ${rng} against ${fmt(c.threshold)}` : c.valueMeans),
    c.state === "pass" ? el("span", { class: "fold" }, folded ? "▸" : "▾") : null));
  if (folded) return box;
  box.append(el("div", { class: "desc" }, c.description), gateBar(c, { head: false }));
  if (c.state === "pass") {
    box.append(el("div", { class: "decides" }, `Passes even in the worst case: ${c.valueMeans} ${rng} against ${fmt(c.threshold)}. No label here can change it.`));
    return box;
  }
  if (c.state === "fail") {
    const claims = failingClaims(c);
    box.append(el("div", { class: "decides" }, `Fails even in the best case: ${c.valueMeans} ${rng} against ${fmt(c.threshold)}. `,
      claims.length ? "It fails on claims already recorded, not on unlabeled matches; no amount of labeling changes it. Re-examine these (a newer claim wins):" : "Nothing open changes it."));
    if (claims.length) {
      const byVuln = groupBy(claims, (x) => `${x.r.vulnerability}|${srcPkg(x.r)}`);
      box.append(el("div", { class: "claims" }, ...[...byVuln.values()].map((list) => el("button", { class: "claim", onclick: () => openSpec({ kind: "fails", check: c.name, vuln: list[0].r.vulnerability, pkg: srcPkg(list[0].r) }) },
        el("span", { class: `chip v-${list[0].r.verdict}` }, `${labels[list[0].r.verdict].glyph} ${labels[list[0].r.verdict].word}`), " ", el("b", {}, list[0].r.vulnerability), ` · ${srcPkg(list[0].r)}${list.length > 1 ? ` ×${list.length}` : ""} · ${marks[list[0].dir]} ${[...new Set(list.map((x) => subjectName(x.si)))].join(", ")}`,
        researchedMark(list.map((x) => x.r)) ? [" ", researchedMark(list.map((x) => x.r))] : null))));
      box.append(el("button", { class: "ghost", onclick: () => openSpec({ kind: "fails", check: c.name, vuln: null, pkg: null }) }, `re-examine all ${claims.length}`));
    }
    return box;
  }
  // undecided: the distance, then the cheapest labels that get there
  const e = c.estimate, rows = bearing(c);
  const dist = [];
  if (!e || e.decidable === false) dist.push("No labeling can decide it from here.");
  else if (e.toPass != null && e.toFail != null) dist.push(`about ${plural(e.toPass, "label")} in the candidate's favor would pass it`, `${plural(e.toFail, "label")} against would fail it`);
  else if (e.toPass != null) dist.push(`about ${plural(e.toPass, "more label")} would pass it, whatever they say`);
  else if (e.toFail != null) dist.push(`${plural(e.toFail, "label")} against the candidate would fail it`);
  else dist.push(`about ${plural(e.toDecide, "label")} could decide it`);
  const far = e && e.toDecide > 0.6 * Math.max(1, rows.length);
  box.append(el("div", { class: "decides" }, `${c.valueMeans}: ${rng} against ${fmt(c.threshold)}. `, dist.join(" · "), e ? " (estimates)." : "",
    far ? el("span", { class: "far" }, ` That is ${e.toDecide} of the ${rows.length} that could move it: far. Aim for the cheapest wins below, or change the gate's threshold.`) : null));
  if (e) box.append(el("div", { class: "dist", title: `${e.toDecide} labels to decide, of ${rows.length} that could move it` }, el("span", { style: `width:${Math.min(100, (100 * e.toDecide) / Math.max(1, rows.length))}%` })));
  const gs = groups(rows), max = Math.max(1, ...gs.map((g) => g.rows.length));
  // each tier shows its biggest groups; the long tail unfolds per tier, so a tier of singletons
  // never hides the big accept in the next one
  const caps = { 0: Infinity, 1: 6, 2: 8, 3: 4 };
  const list = el("div", { class: "groups" });
  for (const t of [0, 1, 2, 3]) {
    const inTier = gs.filter((x) => tierOf(x.tier) === t);
    if (!inTier.length) continue;
    const key = `${c.name}|${t}`, shown = ui.opened.has(key) ? inTier : inTier.slice(0, caps[t]);
    list.append(el("div", { class: "tier" }, tierNames[t], ` · ${plural(inTier.reduce((n, x) => n + x.rows.length, 0), "match", "matches")} in ${plural(inTier.length, "group")}`));
    for (const g of shown) list.append(groupRow(g, max, c));
    if (inTier.length > shown.length) list.append(el("button", { class: "ghost more", onclick: () => { ui.opened.add(key); render(); } }, `+ ${inTier.length - shown.length} more`));
  }
  if (!gs.length) list.append(el("div", { class: "muted" }, "nothing open bears on it"));
  box.append(list);
  return box;
}

// groupRow is one thing to act on: its bar is how many labels one action settles
function groupRow(g, max, c) {
  const n = g.rows.length, t = tally(g.rows), v = g.cause?.verdict || (g.rows.every((x) => hinted(x.r) && x.r.hint.verdict === g.rows[0].r.hint.verdict) ? g.rows[0].r.hint.verdict : null);
  const conf = g.cause?.confidence || (g.rows.every((x) => hinted(x.r)) ? g.rows.reduce((a, x) => (({ high: 0, medium: 1, low: 2 })[x.r.hint.confidence] > ({ high: 0, medium: 1, low: 2 })[a] ? x.r.hint.confidence : a), "high") : null);
  const title = g.cause ? g.cause.title : `${g.pkg} · ${n === 1 ? g.rows[0].r.vulnerability : plural(n, "match", "matches")}`;
  const open = () => openSpec(specOfGroup(c, g));
  return el("div", { class: `group t${tierOf(g.tier)}` },
    el("div", { class: "bar" }, el("span", { class: v ? `fill v-${v}` : "fill", style: `width:${(100 * n) / max}%` })),
    el("button", { class: "gtitle", onclick: open, title: g.rows.slice(0, 8).map((x) => `${x.r.vulnerability} ${pkgOf(x.r.package.ref).name}`).join("\n") + (n > 8 ? `\n…` : "") },
      el("span", { class: "n" }, String(n)), " ", el("span", { class: "mk" }, marks[g.dir]), " ", g.cause ? el("span", { class: "star" }, "✦ ") : null, title),
    v ? el("span", { class: `sugg v-${v}` }, `${labels[v].glyph} ${labels[v].word}? ${dots[conf] || ""}`) : el("span", { class: "muted" }, "no agent hint"),
    researchedMark(g.rows.map((x) => x.r)) || el("span", {}),
    g.cause && g.cause.pending.length ? acceptButton(`accept ${g.rows.filter((x) => g.cause.pending.includes(x.r.id)).length} ✦`, () => acceptCause(g.cause, g.rows.map((x) => x.r.id)),
      () => causeLabels(g.cause, g.rows.map((x) => x.r.id)), `the package hint on ${title}`)
      : t.hinted && v ? acceptButton(`accept ${t.hinted} ✦`, () => acceptIds(g.rows.filter((x) => hinted(x.r)).map((x) => x.r.id)),
        () => hintLabels(g.rows.map((x) => x.r)), `the ${plural(t.hinted, "agent hint")} on ${title}`) : el("span", {}),
    el("button", { class: "ghost", onclick: open }, "open"));
}
// acceptButton is an "accept N ✦" control: hovering it previews on the gate's bars where accepting
// would move them
const acceptButton = (text, onclick, labelsOf, what) => el("button", { class: "ghost accept", onclick, ...previewOn(labelsOf, what) }, text);

// ---------- "✦ researched" and "✦ triaged": how far an agent has looked at a match ----------

// Three levels (Will, 2026-10-13): none, triaged (a triage-deltas hint, no research-vuln output) and
// researched (research-vuln output exists, from any source). Map decides through the tile's rules
// (shared/tile.js), which read the server's row.researchLevel; a match shows only its highest level.
const isResearched = (r) => tile.h.isResearched(r);
const researchLevel = (r) => tile.h.researchLevel(r);

// researchedText is a match's provenance, for a tooltip: which level, who had its say, who asked
function researchedText(r) {
  const head = `${r.vulnerability} ${pkgOf(r.package.ref).name}`;
  if (!r.hint) return `${head}: ✦ researched, no hint${r.researchedBy?.length ? ` (${r.researchedBy.join(", ")})` : ""}`;
  const h = r.hint, extra = [h.model, h.researchJob ? `research ${h.researchJob}` : ""].filter(Boolean).join(" · ");
  return `${head}: ${tile.h.provenance(h)}${extra ? ` (${extra})` : ""}`;
}

// researchedMark is the neutral "✦ researched" / "✦ triaged" mark for a list of matches (one or
// many), or null when no agent has looked at any of them
function researchedMark(rows) {
  const done = rows.filter(isResearched), triaged = rows.filter((r) => !isResearched(r) && researchLevel(r) === "triaged");
  if (!done.length && !triaged.length) return null;
  const noHint = done.every((r) => !r.hint);
  const parts = [];
  if (done.length) parts.push(done.length < rows.length ? `✦ ${done.length} of ${rows.length} researched` : noHint ? "✦ researched, no hint" : "✦ researched");
  if (triaged.length) parts.push(triaged.length < rows.length ? `✦ ${triaged.length} of ${rows.length} triaged` : "✦ triaged");
  const shown = [...done, ...triaged];
  const title = shown.slice(0, 8).map(researchedText).join("\n") + (shown.length > 8 ? `\n… and ${shown.length - 8} more` : "");
  return el("span", { class: "researched", title }, parts.join(" · "));
}

// acceptCause accepts a package hint for the given member rows
async function acceptCause(cause, rows) {
  rows = rows.filter((id) => cause.pending.includes(id));
  if (!rows.length) return toast("no agent hint to accept in that group");
  try {
    const res = await post(ui.gateName, `/package-hints/${encodeURIComponent(cause.id)}/accept`, { rows });
    const text = `${labels[cause.verdict].glyph} ${labels[cause.verdict].word}, the ✦ package hint accepted on ${plural(res.written ?? rows.length, "match", "matches")}`;
    if (ui.cards) await afterWrite(rows, text); else { toast(text); await load(); }
  } catch (e) { toast(e.message, true); }
}
async function acceptIds(rows) {
  if (!rows.length) return toast("no agent hint to accept there");
  try {
    const res = await post(ui.gateName, "/accept", { rows });
    const text = `✦ ${plural(res.written, "agent hint")} accepted as your labels`;
    if (ui.cards) await afterWrite(rows, text); else { toast(text); await load(); }
  } catch (e) { toast(e.message, true); }
}

// ---------- the tile view: one finding of the open group, under a breadcrumb ----------

// allRows is every row in scope, with its subject and direction (both-sided rows included: open
// ones bear on the F1 check too)
function allRows(si = ui.si) {
  const out = [];
  ui.state.subjects.forEach((s, i) => {
    if (si != null && i !== si) return;
    for (const r of s.rows) { const d = direction(r); if (d !== "neither") out.push({ r, si: i, dir: d }); }
  });
  return out;
}

// groupRows is the open group's rows in the group's order: by tier, open first, then package and id
function groupRows() {
  const c = ui.cards;
  return allRows().filter((x) => c.ids.has(x.r.id))
    .sort((a, b) => (tier(a.r, a.dir) - tier(b.r, b.dir)) || (Number(isOpen(b.r)) - Number(isOpen(a.r))) || srcPkg(a.r).localeCompare(srcPkg(b.r)) || a.r.vulnerability.localeCompare(b.r.vulnerability));
}

// crumbs is the one way back from a match (Esc does the same): the board (or the delta map), the
// check (its panel), the group. Testers found three ways back confusing, so there are no others.
function crumbs() {
  const s = ui.cardsSpec, c = s && ui.state.gate?.result?.checks.find((k) => k.name === s.check);
  const out = [];
  const crumb = (text, go, cls = "", title = null) => el("button", { class: `crumb ${cls}`, onclick: go, title }, text);
  if (s.kind === "delta") {
    const rows = diffRows().filter((x) => x.dir === s.dir && whyKey(x.r.why) === s.why);
    out.push(crumb("← scan delta map", () => navigate({ cardsSpec: null, selected: null, evidence: false, delta: true, zoom: null }), "home", "back to the scan delta map (Esc)"));
    out.push(crumb(`${dirTitle[s.dir] || s.dir} › ${reasonTitle(rows, s.dir)}`, () => navigate({ cardsSpec: null, selected: null, evidence: false, delta: true, zoom: { dir: s.dir, why: s.why } })));
    if (s.pkg) out.push(crumb(s.pkg, () => select(firstOpen()), "here"));
    return out;
  }
  out.push(crumb("← gate board", () => navigate({ cardsSpec: null, selected: null, evidence: false, delta: false, zoom: null }), "home", "back to the gate board (Esc)"));
  if (c) {
    const e = c.estimate;
    const what = c.state === "undecided" && e ? ` · ${e.toPass ?? "–"} for / ${e.toFail ?? "–"} against` : c.state === "fail" ? ` · fails on ${plural((c.failsOn || []).length, "claim")}` : "";
    out.push(crumb(`${c.name} ${c.state}${what}`, () => { ui.scrollTo = c.name; navigate({ cardsSpec: null, selected: null, evidence: false, delta: false, zoom: null }); }, c.state));
  }
  const title = ui.cards.title.replace(/^[^›]*› /, "");
  out.push(crumb(title, () => select(firstOpen()), "here"));
  return out;
}
const firstOpen = () => (ui.rows.find((x) => isOpen(x.r)) || ui.rows[0])?.r.id;

// nextGroup is the next group of the same check with something open, after the one shown
function nextGroup() {
  const s = ui.cardsSpec, c = s && ui.state.gate?.result?.checks.find((k) => k.name === s.check);
  if (!c || !["cause", "tier"].includes(s.kind)) return null;
  const gs = groups(bearing(c)), i = gs.findIndex((g) => (s.kind === "cause" ? g.cause?.id === s.cause : !g.cause && tierOf(g.tier) === s.tier && g.dir === s.dir && g.pkg === s.pkg));
  const ring = [...gs.slice(i + 1), ...gs.slice(0, Math.max(0, i))];
  const g = ring.find((x) => x.rows.some((y) => isOpen(y.r)));
  return g ? { g, c } : null;
}

function renderTile() {
  $("#map").hidden = true;
  const box = $("#tile");
  box.hidden = false;
  ui.rows = groupRows();
  if (!ui.rows.length) { ui.cards = null; render(); return; }
  if (ui.selected && !ui.rows.some((x) => x.r.id === ui.selected)) ui.selected = null;
  // the claims a failed check fails on are labeled by definition: every one is there to re-examine
  const open = ui.cardsSpec?.kind === "fails" ? ui.rows : ui.rows.filter((x) => isOpen(x.r));
  if (!ui.selected && open.length) { ui.selected = open[0].r.id; history.replaceState(null, "", urlFor()); }
  const x = ui.rows.find((y) => y.r.id === ui.selected) || null;
  const i = ui.rows.findIndex((y) => y.r.id === ui.selected);
  const body = el("div", { class: "tile", id: "tilebody" });
  box.replaceChildren(
    el("div", { class: "crumbline" }, ...crumbs().flatMap((cr, k) => [k ? el("span", { class: "sep" }, "›") : null, cr]),
      el("span", { class: "pos" }, x ? `${i + 1} of ${ui.rows.length}` : `${ui.rows.length - open.length} of ${ui.rows.length} labeled`)),
    body);
  if (!x) {
    const nx = nextGroup();
    body.replaceChildren(el("div", { class: "done" },
      el("div", { class: "big" }, "Every match in this group is labeled"),
      el("div", { class: "muted" }, ui.last ? [el("button", { class: "ghost", onclick: () => select(ui.last) }, "z · back to the last one"), " "] : null,
        nx ? el("button", { class: "ghost", onclick: () => openSpec(specOfGroup(nx.c, nx.g)) }, `next: ${nx.g.cause ? `✦ ${nx.g.cause.title}` : `${marks[nx.g.dir]} ${nx.g.pkg}`} · ${plural(nx.g.rows.filter((y) => isOpen(y.r)).length, "unlabeled match", "unlabeled matches")}`) : null)));
    return;
  }
  const c = ui.cardsSpec?.check ? ui.state.gate?.result?.checks.find((k) => k.name === ui.cardsSpec.check) : null;
  tile.render(body, {
    state: ui.state, gateName: ui.gateName, get,
    r: x.r, si: x.si, dir: x.dir, check: c, reexamine: ui.cardsSpec?.kind === "fails",
    tierName: x.r.gate ? tierNames[tierOf(tier(x.r, x.dir))] || null : null,
    counter: `${i + 1} of ${ui.rows.length} in this group`,
    receipt: ui.receipt, backKey: "z", canStay: true,
    why: ui.why, more: ui.evidence, note: ui.note,
    matches: ui.matches, details: ui.details, subjectName,
    on: {
      label: (v, j) => label(v, [x.r.id], j), accept: (rows) => acceptRows(rows), acceptCause: (cause) => acceptCause(cause, cause.pending), research: (rows) => research(rows),
      toggleWhy: () => { ui.why = !ui.why; renderTile(); }, toggleMore: () => select(ui.selected, !ui.evidence),
      note: (t) => (ui.note = t), skip: () => moveCard(1),
    },
  });
  previewTileAccepts(body, x.r);
}

// previewTileAccepts wires the tile's two accept controls to the ribbon's preview: the label button
// that carries the agent hint (accept it on this match), and "accept all N" for a package hint.
// shared/tile.js has no hook for this, so they're found by the classes it gives them.
function previewTileAccepts(body, r) {
  endPreview();
  const wire = (b, labelsOf, what) => { if (b) for (const [k, f] of Object.entries(previewOn(labelsOf, what))) b.addEventListener(k.slice(2), f); };
  if (hinted(r)) wire(body.querySelector(".buttons .btn.hinted"), () => hintLabels([r]), `the agent hint on ${r.vulnerability}`);
  const cause = (r.causes || []).map((id) => ui.state.causes.find((k) => k.id === id)).find((k) => k?.pending?.length > 1);
  if (cause) wire(body.querySelector(".sec-agent .group button"), () => causeLabels(cause, cause.pending), `the package hint on ${plural(cause.pending.length, "match", "matches")}`);
}

// ---------- research a selection of the gate's matches ----------
// Two targeted selections, never "everything" (Will, 2026-10-13; docs/decisions.md, Agents 5): the
// server resolves them to unlabeled matches that research-vuln hasn't been run on (see "✦ researched"
// below), with no research queued or running; "with no agent hint" takes only those with no hint at
// all, "that could move a check" also takes the triaged ones. A dry run counts them for the control's text. A click starts research at once (the next
// researchBatch of them); the status stays, with cancel, while any of it runs.

const researchBatch = 20;
const selections = [
  { select: "could-move-check", words: "that could move a check" },
  { select: "no-hint", words: "with no agent hint" },
];
const researchScope = () => (ui.si == null ? "" : ui.state.scans.subjects?.[ui.si]?.slug || "");

// countForResearch asks the server, as a dry run, how many matches each selection takes in scope
async function countForResearch() {
  if (!ui.state?.researchConcurrency) { ui.research = null; return; }
  const scope = researchScope(), counts = {};
  ui.research = { ...ui.research, scope, counts: ui.research?.scope === scope ? ui.research.counts : null };
  await Promise.all(selections.map(async ({ select }) => {
    try {
      const res = await post(ui.gateName, "/research", { select, ...(scope ? { subject: scope } : {}), dryRun: true });
      counts[select] = res.matches;
    } catch { counts[select] = 0; } // e.g. a gate with no checks: nothing could move one
  }));
  if (researchScope() !== scope) return; // the scope changed meanwhile: its own count is coming
  ui.research = { ...ui.research, scope, counts };
  for (const n of document.querySelectorAll(".research-ctl")) n.replaceWith(researchControls());
}

// activeResearch is the matches in scope with research queued or running
const activeResearch = () => allRows().filter((x) => ["queued", "running"].includes(x.r.research?.status));

// researchOff is why research cannot start here (the yardstick plugin missing or at another
// version, or claude not on PATH), with the command to copy; null while it can
const researchOff = () => (ui.state?.research && !ui.state.research.available ? ui.state.research : null);

function researchControls() {
  const box = el("span", { class: "research-ctl" });
  const off = researchOff();
  if (off) {
    box.append(el("span", { class: "research-off", title: off.reason }, `⚠ research disabled: ${off.reason}`,
      off.command ? [" ", el("code", {}, off.command), " ", el("button", { class: "ghost", title: "copy the command", onclick: () => navigator.clipboard?.writeText(off.command).then(() => toast("copied"), () => toast(off.command)) }, "copy")] : null));
    return box;
  }
  if (!ui.state?.researchConcurrency) return box;
  const active = activeResearch(), started = ui.research?.started;
  if (active.length) {
    const cancellable = active.filter((x) => x.r.research.cancellable);
    box.append(el("span", { class: "researching", title: `${plural(new Set(active.map((x) => x.r.research.job)).size, "research run")} queued or running, ${ui.state.researchConcurrency} at a time; agent hints arrive as they finish` },
      `⧗ researching ${plural(active.length, "match", "matches")}`,
      cancellable.length ? [" ", el("button", { class: "ghost", title: "cancel the research queued or running here", onclick: () => cancelResearch(cancellable.map((x) => x.r.id)) }, "✕ cancel")] : null));
  } else if (started) {
    box.append(el("span", { class: "researching done", title: "agent hints are on the matches; this note stays until you dismiss it" },
      started.cancelled ? `research cancelled · ${plural(started.matches, "match", "matches")} asked for` : `✦ research finished on ${plural(started.matches, "match", "matches")}`,
      " ", el("button", { class: "ghost", title: "dismiss", onclick: () => { ui.research.started = null; render(); } }, "✕")));
  }
  const counts = ui.research?.scope === researchScope() ? ui.research.counts : null;
  for (const { select, words } of selections) {
    const n = counts?.[select];
    if (n == null) continue;
    if (!n) { box.append(el("span", { class: "muted", title: "unlabeled matches that research-vuln hasn't been run on (researched ones are left out), with no research queued or running" }, `no match ${words} is left to research`)); continue; }
    const take = Math.min(n, researchBatch);
    box.append(el("button", { class: "ghost research", onclick: () => startResearch(select, take),
      title: `${take < n ? `the first ${take} of ${n}${select === "could-move-check" ? ", those that could flip a check first" : ""}` : `all ${n}`}${ui.si == null ? " in every image" : ` in ${subjectName(ui.si)}`}; unlabeled matches research-vuln hasn't been run on yet (already researched ones are left out). ${ui.state.researchConcurrency} at a time; each costs tokens.` },
      `research ${take < n ? `${take} of ${n}` : n} ${n === 1 ? "match" : "matches"} ${words}`));
  }
  return box;
}

async function startResearch(select, limit) {
  const scope = researchScope();
  try {
    const res = await post(ui.gateName, "/research", { select, limit, ...(scope ? { subject: scope } : {}) });
    ui.research = { ...ui.research, started: { matches: res.matches, jobs: res.jobs } };
  } catch (e) { return toast(e.message, true); }
  await load();
}
async function cancelResearch(rows) {
  try {
    await post(ui.gateName, "/research/cancel", { rows });
    if (ui.research?.started) ui.research.started.cancelled = true;
  } catch (e) { return toast(e.message, true); }
  setTimeout(() => load(), 400); // let the jobs record it
}

// while research runs, reload now and then so its agent hints show up (not on a match: a reload
// there would redraw the tile under the reader)
setInterval(() => { if (ui.state && !ui.cards && !document.hidden && activeResearch().length) load(); }, 8000);

// ---------- actions ----------

// label writes a verdict; FP and unclear need a justification from the vocabulary, picked on the
// tile (without one, the picker takes focus)
async function label(verdict, rows, justification = "") {
  if (!rows.length) return toast("no match selected");
  if (verdict !== "tp" && !justification) {
    $("#justification")?.focus();
    return toast(`${labels[verdict].word} needs a reason: pick one under the buttons`);
  }
  try {
    const res = await post(ui.gateName, "/labels", { rows, verdict, justification, note: ui.note, scope: "subject" });
    const l = labels[verdict];
    await afterWrite(rows, `${l.glyph} ${l.word}${res.conflicts?.length ? " · ⚡ now in conflict with another person's label" : ""}${res.overridden?.length ? " · overrides the agent hint" : ""}`);
  } catch (e) {
    toast(e.message, true);
  }
}
async function acceptRows(rows) {
  const byId = new Map(ui.rows.map((x) => [x.r.id, x.r]));
  rows = rows.filter((id) => hinted(byId.get(id) || {}));
  if (!rows.length) return toast("no agent hint to accept here");
  const v = byId.get(rows[0]).hint.verdict;
  try {
    const res = await post(ui.gateName, "/accept", { rows });
    await afterWrite(rows, `${labels[v].glyph} ${labels[v].word}, the ✦ agent hint accepted${res.written > 1 ? ` on ${plural(res.written, "match", "matches")}` : ""}${res.conflicts?.length ? " · ⚡ in conflict" : ""}`);
  } catch (e) {
    toast(e.message, true);
  }
}
async function research(rows) {
  const off = researchOff();
  if (off) return toast(`research disabled: ${off.reason}${off.command ? `; run ${off.command}` : ""}`, true);
  try { await post(ui.gateName, "/research", { rows }); toast("research started; what it finds arrives as an agent hint"); load(); } catch (e) { toast(e.message, true); }
}
// afterWrite moves on to the next unlabeled match of the group (replacing the entry: the labeled
// one left the group, so back from its successor lands on the board, not on a dead stop), or stays
// on the labeled one when the reader turned the tile's "go to the next match" switch off. The
// tile's standing receipt bar says what happened, so there's no toast.
async function afterWrite(rows, text) {
  const stay = !tile.autoAdvance();
  ui.last = ui.selected;
  ui.note = ""; ui.why = false;
  const i = ui.rows.findIndex((x) => x.r.id === ui.selected);
  const todo = (x) => !rows.includes(x.r.id) && (ui.cardsSpec?.kind === "fails" || isOpen(x.r));
  const next = ui.rows.slice(i + 1).find(todo) || ui.rows.slice(0, i).find(todo);
  ui.receipt = { text };
  ui.pin = stay ? ui.selected : null; // a labeled match leaves its group: keep it there to stay on it
  await load();
  if (!ui.cards) return;
  ui.selected = tile.autoAdvance() ? (next?.r.id || null) : ui.selected;
  ui.evidence = false;
  history.replaceState(null, "", urlFor());
  renderTile();
}
function moveCard(delta) {
  if (!ui.cards || !ui.rows.length) return;
  const i = ui.rows.findIndex((x) => x.r.id === ui.selected);
  const j = Math.max(0, Math.min(ui.rows.length - 1, i + delta));
  if (j === i) return toast(delta > 0 ? "last one in this group" : "first one in this group");
  select(ui.rows[j].r.id, false);
}
function nextDecisive() {
  if (!ui.cards) return toast("open a group first");
  const i = ui.rows.findIndex((x) => x.r.id === ui.selected);
  const ring = [...ui.rows.slice(i + 1), ...ui.rows.slice(0, i + 1)];
  const next = ring.find((x) => isOpen(x.r) && decisive(x.r)) || ring.find((x) => isOpen(x.r) && bears(x.r));
  if (!next) return toast("nothing here could change the verdict");
  select(next.r.id, false);
}
const currentRow = () => ui.rows.find((x) => x.r.id === ui.selected) || null;

// ---------- keys ----------

document.addEventListener("keydown", (e) => {
  const target = e.target as HTMLElement;
  if (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) { if (e.key === "Escape") target.blur(); return; }
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const help = $("#help");
  if (!help.hidden) { if (e.key === "Escape" || e.key === "?") help.hidden = true; return; }
  const x = ui.cards ? currentRow() : null;
  const sel = x ? [x.r.id] : [];
  switch (e.key) {
    case "j": moveCard(1); break;
    case "k": moveCard(-1); break;
    case "t": label("tp", sel); break;
    case "f": label("fp", sel); break;
    case "u": label("unclear", sel); break;
    case "a": acceptRows(sel); break;
    case "A": { const c = x && (x.r.causes || []).map((id) => ui.state.causes.find((k) => k.id === id)).find((k) => k?.pending?.length); if (c) acceptCause(c, c.pending); else acceptRows(ui.rows.filter((y) => hinted(y.r) && y.r.hint.confidence === "high").map((y) => y.r.id)); break; }
    case "w": if (ui.cards) { ui.why = !ui.why; renderTile(); } break;
    case "e": case "Enter": if (ui.cards && ui.selected) select(ui.selected, !ui.evidence); break;
    case "n": if (ui.cards) { $("#note")?.focus(); e.preventDefault(); } break;
    case "R": if (x) research([x.r.id]); break;
    case "o": { const d = x && detail(x.r); const u = d?.dataSource || ui.details.get(ui.selected)?.links?.[0]?.url; if (u) window.open(u, "_blank", "noopener"); break; }
    case "v": nextDecisive(); break;
    case "Escape": if (ui.cardsSpec || ui.zoom || ui.delta) back(); break;
    case "z": if (ui.last && ui.cards) select(ui.last, false); break;
    case "D": cycleTheme(); break;
    case "?": help.hidden = false; break;
    case "0": scope(null); break;
    default:
      if (/^[1-9]$/.test(e.key) && Number(e.key) <= ui.state.subjects.length) navigate({ si: Number(e.key) - 1, zoom: null, cardsSpec: null, selected: null, evidence: false });
      else return;
  }
});

function cycleTheme() {
  const cur = localStorage.getItem("yardstick.theme") || "system";
  const next = { system: "light", light: "dark", dark: "system" }[cur];
  if (next === "system") { localStorage.removeItem("yardstick.theme"); delete document.documentElement.dataset.theme; }
  else { localStorage.setItem("yardstick.theme", next); document.documentElement.dataset.theme = next; }
  $("#theme-button").textContent = `theme: ${next}`;
}

(function boot() {
  if (!ui.gateName) { $("#map").replaceChildren(el("div", { class: "empty" }, "no gate in the URL")); return; }
  ui.base = location.pathname.match(/^.*?\/gates\/[^/]+\//)[0];
  $("#theme-button").textContent = `theme: ${localStorage.getItem("yardstick.theme") || "system"}`;
  $("#theme-button").addEventListener("click", cycleTheme);
  $("#help-button").addEventListener("click", () => ($("#help").hidden = false));
  $("#help").addEventListener("click", (e) => { if (e.target === $("#help")) $("#help").hidden = true; });
  window.addEventListener("resize", () => { if (!ui.cards && ui.state) renderMap(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) load(); });
  load();
})();
