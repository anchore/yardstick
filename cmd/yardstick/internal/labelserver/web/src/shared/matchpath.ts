// matchpath.ts is the tile's match path: how each side's grype got from the package to the match
// (or where it stopped), one lane per side, and what the other DB has for the package elsewhere.
import type { MatchesResponse } from "../gen/wire";
import { el } from "./dom";
import { type Release, distroName, nsHuman, sameRelease } from "./names";
import { otherRecords, pkgOf, type Row } from "./rows";

// GrypeMatch is the little of grype's raw match JSON the path reads; the wire passes it verbatim
interface GrypeMatch {
  matchDetails?: {
    type?: string;
    matcher?: string;
    searchedBy?: SearchedBy;
    found?: { vulnerabilityID?: string; versionConstraint?: string };
  }[];
}
interface SearchedBy { namespace?: string; cpes?: string[]; package?: { name?: string; version?: string } }

// Step is one cell of a lane: its text, a short subline, and the detail a click or Enter on the cell
// shows in full
// Diff marks a step the other lane lacks or has otherwise, and cause the first kind of step that differs:
// where the lanes diverge. Neither says which lane is right; that is the labeler's call.
export interface Step { k: string; t: string; sub?: string; title?: string; detail?: string; same?: boolean; diff?: boolean; cause?: boolean }

// subFits is how long a subline can be and still fit its cell (11px mono in a 320px cell)
export const subFits = 40;
// expandable says whether a cell holds more than it shows: a detail, or a subline its cell clips
export const expandable = (s: Step) => !!s.detail || (s.sub?.length ?? 0) > subFits;
type Side = "candidate" | "reference";
// Setups is what the lanes know of each setup beyond the row: its grype version, and whether the two
// read the same DB
export interface Setups { grype?: Partial<Record<Side, string>>; sameDB?: boolean }


// steps reads grype's matchDetails (from the raw match) into the steps of the path. Without a
// match, the lane stops where the row's data says it diverged.
export function steps(r: Row, side: Side, raw: GrypeMatch | undefined, rel: Release | null, setups: Setups = {}): Step[] {
  const pk = pkgOf(r.package.ref), d = side === "candidate" ? r.candidate : r.reference;
  const out: Step[] = [{ k: "package", t: `${pk.name} ${pk.version}`, sub: pk.type || "" }];
  const md = raw?.matchDetails?.[0];
  if (d) {
    // with a raw match, every cell reads its first detail: the row pools all the match's details, so
    // mixing it in can put one detail's search beside another's result
    const sb: SearchedBy = md?.searchedBy || {}, fd = md?.found || {};
    const types = md ? [md.type || ""] : d.matchTypes || [];
    const ns = md ? sb.namespace : d.namespace, matcher = md ? md.matcher || "" : (d.matchers || [])[0] || "";
    const viaName = !types.includes("exact-indirect-match") ? null : md ? (sb.package?.name !== pk.name ? sb.package?.name : null) : (d.upstreams || [])[0];
    if (types.includes("cpe-match") || sb.cpes?.length) out.push(viaCPE(md ? sb.cpes || [] : d.cpes || []));
    else if (viaName) out.push({ k: "via", t: `via source package ${viaName}`, sub: sb.package?.version && sb.package.version !== pk.version ? sb.package.version : "" });
    out.push({ k: "searched", t: nsHuman(ns), sub: matcher.replace(/-matcher$/, " matcher"), title: ns, same: sameRelease(ns, rel) });
    const cons = md ? fd.versionConstraint || "" : (d.constraints || [])[0] || "";
    out.push({ k: "record", t: `${fd.vulnerabilityID || r.vulnerability}`, sub: `affected ${cons && cons !== "none" ? cons.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${d.fixState === "fixed" && d.fixVersions?.length ? ` · fixed in ${d.fixVersions[0]}` : d.fixState ? ` · ${d.fixState.replace(/-/g, " ")}` : ""}`, title: cons });
    if (r.why?.key === "record/distro-not-affected") out.push(notApplied(r, side, d, setups));
    out.push({ k: "result", t: "matched", sub: (types[0] || "").replace(/-match$/, "") });
    return out;
  }
  // no match on this side: where did it stop?
  const w = r.why?.key || "", status = side === "candidate" ? r.candidateStatus : r.referenceStatus;
  const recs = side === "candidate" ? r.candidateRecords : r.referenceRecords;
  const other = side === "candidate" ? r.reference : r.candidate;
  const otherNs = other?.namespace;
  const mine = (recs || []).find((x) => sameRelease(x.namespace, rel)) || (recs || [])[0];
  if (status === "rejected") { out.push({ k: "searched", t: nsHuman(otherNs), title: otherNs }, { k: "record", t: r.vulnerability, sub: "rejected" }, { k: "result", t: "no match" }); return out; }
  if (status === "not-in-db" || /^record\/absent/.test(w)) { out.push({ k: "searched", t: "every namespace", sub: "all aliases" }, { k: "record", t: "no record", sub: `${r.vulnerability} is not in this DB` }, { k: "result", t: "no match" }); return out; }
  if (/^package\/absent/.test(w)) {
    out.push({ k: "searched", t: nsHuman(otherNs), title: otherNs, same: sameRelease(otherNs, rel) });
    out.push({ k: "record", t: "no record for this package", sub: mine ? `the DB has it under ${nsHuman(mine.namespace)}` : `${r.vulnerability} is known, ${pk.name}${r.sourcePackage && r.sourcePackage !== pk.name ? ` / ${r.sourcePackage}` : ""} isn't listed`, title: mine?.namespace });
    out.push({ k: "result", t: "no match" });
    return out;
  }
  if (w === "record/distro-not-affected") {
    // this grype searched as the other did and found the same record, then its distro check found
    // the distro's record saying fixed in 0, and dropped the match
    const ns = r.why?.to || r.why?.from || "", nak = (recs || []).find((x) => x.namespace === ns);
    const found = other && (recs || []).find((x) => x.namespace === other.namespace && x !== nak);
    if (other && found) {
      if ((other.matchTypes || []).includes("cpe-match")) out.push(viaCPE(other.cpes || []));
      // grype picks the matcher by package type, so this grype searched with the other's matcher
      const matcher = (other.matchers || [])[0] || "", otherSide = side === "candidate" ? "reference" : "candidate";
      out.push({ k: "searched", t: nsHuman(other.namespace), sub: matcher.replace(/-matcher$/, " matcher"), same: sameRelease(other.namespace, rel),
        title: matcher ? `${other.namespace}, by the ${matcher}: inferred, since grype picks the matcher by package type and the ${otherSide}'s grype used it on this package` : other.namespace });
      const c = constraintsOf(found.constraints);
      out.push({ k: "record", t: found.vulnerability || r.vulnerability, sub: `affected ${c.length ? c.join(" || ") : "every version"}`, title: (found.constraints || []).join(" || ") });
    }
    const pkg = nak?.package || pk.name;
    const grype = setups.grype?.[side] ? `grype ${setups.grype[side]}` : "its grype";
    out.push({ k: "distro", t: `${distroName(ns)} records`, sub: "not affected (fixed in 0)", diff: true,
      detail: `${ns} lists ${pkg} ${(nak?.constraints || ["< 0"]).join(" || ")}, fixed in 0: not affected, so ${grype} dropped the match` });
    out.push({ k: "result", t: "dropped", sub: `${distroName(ns)} says not affected` });
    return out;
  }
  if (mine) {
    const c = (mine.constraints || [])[0] || "";
    const changed = /^(constraint|fix-state|namespace)\/changed$/.test(w);
    out.push({ k: "searched", t: nsHuman(mine.namespace), title: mine.namespace, same: sameRelease(mine.namespace, rel), diff: w === "namespace/changed" });
    out.push({ k: "record", t: mine.vulnerability || r.vulnerability, sub: `affected ${c && c !== "none" ? c.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${mine.fixVersions?.length ? ` · fixed in ${mine.fixVersions[0]}` : mine.fixStates?.length ? ` · ${mine.fixStates.join("/").replace(/-/g, " ")}` : ""}`, title: (mine.constraints || []).join(" || "), diff: changed });
    out.push({ k: "result", t: "no match", sub: w === "record/same-but-unmatched" ? "same record: the matcher or its config differs" : changed ? "the record differs" : "" });
    return out;
  }
  out.push({ k: "result", t: "no match", sub: w === "unexplained" ? "unexplained by the match's data" : "" });
  return out;
}

// viaCPE is the step searching by the package's CPEs, all of them in its detail
const viaCPE = (cpes: string[]): Step => ({ k: "via", t: "as CPE", sub: cpes[0] || "", detail: cpes.length ? cpes.join("\n") : undefined });

// notApplied is the distro check on the side that matched though the other side's distro record says
// not affected: what its scan shows, never a guess at why (it may not have looked, or looked and
// not applied it)
function notApplied(r: Row, side: Side, d: NonNullable<Row["candidate"]>, setups: Setups): Step {
  const ns = r.why?.to || r.why?.from || "", grype = setups.grype?.[side] ? `grype ${setups.grype[side]}` : "its grype";
  const db = setups.sameDB ? "Its DB is the same and has the record saying not affected; " : "";
  return { k: "distro", t: `${distroName(ns)} records`, sub: d.distro ? "NAK not applied" : "no distro detected", diff: true,
    detail: `${db}${d.distro ? `${grype} scanned ${d.distro} and did not apply the record` : `${grype} reported no distro for the image, so it did not apply the record`}.` };
}

// the kinds of step, in path order: a lane puts each step in its kind's column, so equivalent steps
// (namespace and namespace, record and record) line up, and a kind one side lacks is an empty slot
const stepKinds = ["package", "via", "searched", "record", "distro", "result"];

export interface Lane { side: Side; steps: Step[] }
const byKind = (l: Lane, k: string) => l.steps.find((s) => s.k === k);

// lanes is both sides' steps, each step marked diff when the other lane has no step of that kind,
// or its text differs
export function lanes(r: Row, m: MatchesResponse | undefined, rel: Release | null, setups: Setups = {}): Lane[] {
  const out = (["candidate", "reference"] as const).map((side) => ({ side, steps: steps(r, side, m?.[side]?.[0] as GrypeMatch | undefined, rel, setups) }));
  for (const l of out) for (const s of l.steps) {
    const ol = out.find((x) => x !== l), o = ol && byKind(ol, s.k);
    // the record's constraint and fix are part of what it is; a step's matcher or match type isn't
    if (!o || o.t !== s.t || (s.k === "record" && (o.sub || "") !== (s.sub || ""))) s.diff = true;
  }
  // the first kind of step both lanes have and differ on, so the mark sits on both; else the first that differs
  const both = (k: string) => out.every((l) => byKind(l, k)) && out.some((l) => byKind(l, k)?.diff);
  const first = stepKinds.find(both) ?? stepKinds.find((k) => out.some((l) => byKind(l, k)?.diff));
  for (const l of out) { const s = first && byKind(l, first); if (s) s.cause = true; }
  return out;
}

export function matchPath(r: Row, m: MatchesResponse | undefined, rel: Release | null, setups: Setups = {}) {
  const ls = lanes(r, m, rel, setups);
  const chip = (s: Step) => {
    const n = el("span", { class: `step ${s.k}${s.diff ? " diff" : ""}${s.cause ? " cause" : ""}${s.same ? " same" : ""}`, title: s.title || "" },
      el("span", { class: "t" }, s.t), s.sub ? el("span", { class: "sub" }, s.sub) : null, s.same ? el("span", { class: "mine" }, "this image's release") : null);
    if (expandable(s)) opens(n, s.detail || s.sub || "");
    return n;
  };
  const kinds = stepKinds.filter((k) => ls.some((l) => byKind(l, k)));
  // one grid row per lane: the side's name, then a cell per kind with an arrow before it
  const path = el("div", { class: `path k${kinds.length}`, "data-testid": "match-lanes" }, ls.flatMap((l) => [
    el("span", { class: "lane-k" }, l.side),
    kinds.flatMap((k, i) => { const s = byKind(l, k);
      return [i ? el("span", { class: `arrow${s ? "" : " none"}` }, s ? "→" : "") : null, s ? chip(s) : el("span", { class: "slot", title: `no ${k} step on the ${l.side} side` })]; }),
  ]));
  // once laid out, a subline its cell clips opens too, however short it was expected to be
  requestAnimationFrame(() => path.querySelectorAll<HTMLElement>(".step:not(.more) .sub").forEach((sub) => {
    if (sub.scrollWidth > sub.clientWidth) opens(sub.parentElement as HTMLElement, sub.textContent || "");
  }));
  return path;
}

// opens makes a cell that holds more than it shows open in place on a click, Enter or Space,
// showing all of it
function opens(n: HTMLElement, full: string) {
  const toggle = () => { const open = n.classList.toggle("open"); n.setAttribute("aria-expanded", String(open)); };
  n.classList.add("more");
  n.setAttribute("role", "button");
  n.setAttribute("tabindex", "0");
  n.setAttribute("aria-expanded", "false");
  n.dataset.testid = "lane-step-more";
  n.addEventListener("click", toggle);
  n.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
  n.append(el("span", { class: "full" }, full));
}

// constraintsOf are a record's or a match's version constraints as the DB lists them: grype's
// " (type)" suffix dropped, and its "||"-joined ranges apart
const constraintsOf = (list: string[] | undefined) =>
  (list || []).flatMap((c) => c.replace(/\s*\((\w[\w-]*)\)$/, "").split("||")).map((c) => c.trim()).filter((c) => c && c !== "none").sort();
// cpeProduct is a CPE's product ("glibc" for cpe:2.3:a:gnu:glibc:*:...)
const cpeProduct = (cpe: string) => cpe.split(":")[4] || cpe;
type Rec = NonNullable<Row["candidateRecords"]>[number];

// recordLine says how one of the other DB's records relates to the row: the same record the other
// setup matched, a distro saying the package is not affected, else what the record covers
export function recordLine(r: Row, rec: Rec, dir: string): string {
  const found = dir === "added" ? r.candidate : r.reference, finder = dir === "added" ? "candidate" : "reference";
  const what = rec.cpe ? `${nsHuman(rec.namespace)} ${cpeProduct(rec.cpe)}` : `${nsHuman(rec.namespace)} ${rec.package || ""}`.trim();
  const cons = constraintsOf(rec.constraints);
  if (rec.package && (cons.length ? cons.every((c) => c === "< 0") : (rec.fixVersions || []).join() === "0" && (rec.fixStates || []).includes("fixed")))
    return `${distroName(rec.namespace)} says ${rec.package} is not affected (fixed in 0)`;
  const fc = constraintsOf(found?.constraints);
  if (found && rec.namespace === found.namespace && !!rec.cpe === (found.matchTypes || []).every((t) => t === "cpe-match") && cons.join("|") === fc.join("|"))
    return `same record the ${finder} matched (${what}${cons.length ? `, ${cons.join(" ‖ ")}` : ""})`;
  return `${what} · ${cons.length ? `affected ${cons.join(" ‖ ")}` : "every version"}${rec.fixVersions?.length ? ` · fixed in ${rec.fixVersions.join(", ")}` : rec.fixStates?.length ? ` · ${rec.fixStates.join("/").replace(/-/g, " ")}` : ""}`;
}

// records lists what the other DB has for the package, each saying how it relates to the row, the
// image's own release first and bold, the rest dimmed
export function records(r: Row, dir: string, rel: Release | null) {
  // a distro's NAK and the same record the other setup matched are in the lanes already
  const shown = r.why?.key === "record/distro-not-affected";
  const recs = otherRecords(r).filter((rec) => !shown || !/^(same record|.* says .* is not affected)/.test(recordLine(r, rec, dir)));
  if (!recs.length) return null;
  const sorted = [...recs].sort((a, b) => Number(sameRelease(b.namespace, rel)) - Number(sameRelease(a.namespace, rel)));
  return el("section", { class: "records", "data-testid": "other-records" },
    el("h3", {}, `What the ${dir === "added" ? "reference" : "candidate"} DB has for ${pkgOf(r.package.ref).name || r.sourcePackage}`),
    el("ul", {}, sorted.map((rec) => el("li", { class: `rec${sameRelease(rec.namespace, rel) ? " same" : ""}`, title: rec.namespace }, recordLine(r, rec, dir)))));
}
