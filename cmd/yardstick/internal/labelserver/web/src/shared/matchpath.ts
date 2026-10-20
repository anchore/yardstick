// matchpath.ts is the tile's match path: how each side's grype got from the package to the match
// (or where it stopped), one lane per side, and what the other DB has for the package elsewhere.
import type { MatchesResponse } from "../gen/wire";
import { el } from "./dom";
import { type Release, nsHuman, sameRelease } from "./names";
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

export interface Step { k: string; t: string; sub?: string; title?: string; same?: boolean; ok?: boolean; miss?: boolean; diff?: boolean }
type Side = "candidate" | "reference";

const nsChip = (ns: string, cls = "") => el("span", { class: `ns ${cls}`, title: ns }, nsHuman(ns));

// steps reads grype's matchDetails (from the raw match) into the steps of the path. Without a
// match, the lane stops where the row's data says it diverged.
export function steps(r: Row, side: Side, raw: GrypeMatch | undefined, rel: Release | null): Step[] {
  const pk = pkgOf(r.package.ref), d = side === "candidate" ? r.candidate : r.reference;
  const out: Step[] = [{ k: "package", t: `${pk.name} ${pk.version}`, sub: pk.type || "" }];
  const md = raw?.matchDetails?.[0];
  if (d) {
    const sb: SearchedBy = md?.searchedBy || {}, fd = md?.found || {};
    const viaName = sb.package?.name && sb.package.name !== pk.name ? sb.package.name : (d.matchTypes || []).includes("exact-indirect-match") && (d.upstreams || [])[0] ? (d.upstreams || [])[0] : null;
    if (sb.cpes?.length || (d.matchTypes || []).includes("cpe-match")) out.push({ k: "via", t: "as CPE", sub: (sb.cpes || d.cpes || [])[0] || "", title: (sb.cpes || d.cpes || []).join("\n") });
    else if (viaName) out.push({ k: "via", t: `via source package ${viaName}`, sub: sb.package?.version && sb.package.version !== pk.version ? sb.package.version : "" });
    out.push({ k: "searched", t: nsHuman(sb.namespace || d.namespace), sub: (md?.matcher || (d.matchers || [])[0] || "").replace(/-matcher$/, " matcher"), title: sb.namespace || d.namespace, same: sameRelease(sb.namespace || d.namespace, rel) });
    const cons = fd.versionConstraint || (d.constraints || [])[0] || "";
    out.push({ k: "record", t: `${fd.vulnerabilityID || r.vulnerability}`, sub: `affected ${cons && cons !== "none" ? cons.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${d.fixState === "fixed" && d.fixVersions?.length ? ` · fixed in ${d.fixVersions[0]}` : d.fixState ? ` · ${d.fixState.replace(/-/g, " ")}` : ""}`, title: cons });
    out.push({ k: "result", t: "matched", sub: (md?.type || (d.matchTypes || [])[0] || "").replace(/-match$/, ""), ok: true });
    return out;
  }
  // no match on this side: where did it stop?
  const w = r.why?.key || "", status = side === "candidate" ? r.candidateStatus : r.referenceStatus;
  const recs = side === "candidate" ? r.candidateRecords : r.referenceRecords;
  const other = side === "candidate" ? r.reference : r.candidate;
  const otherNs = other?.namespace;
  const mine = (recs || []).find((x) => sameRelease(x.namespace, rel)) || (recs || [])[0];
  if (status === "rejected") { out.push({ k: "searched", t: nsHuman(otherNs), title: otherNs }, { k: "record", t: r.vulnerability, sub: "rejected", miss: true }, { k: "result", t: "no match", miss: true }); return out; }
  if (status === "not-in-db" || /^record\/absent/.test(w)) { out.push({ k: "searched", t: "every namespace", sub: "all aliases" }, { k: "record", t: "no record", sub: `${r.vulnerability} is not in this DB`, miss: true }, { k: "result", t: "no match", miss: true }); return out; }
  if (/^package\/absent/.test(w)) {
    out.push({ k: "searched", t: nsHuman(otherNs), title: otherNs, same: sameRelease(otherNs, rel) });
    out.push({ k: "record", t: "no record for this package", sub: mine ? `the DB has it under ${nsHuman(mine.namespace)}` : `${r.vulnerability} is known, ${pk.name}${r.sourcePackage && r.sourcePackage !== pk.name ? ` / ${r.sourcePackage}` : ""} isn't listed`, miss: true, title: mine?.namespace });
    out.push({ k: "result", t: "no match", miss: true });
    return out;
  }
  if (mine) {
    const c = (mine.constraints || [])[0] || "";
    const changed = /^(constraint|fix-state|namespace)\/changed$/.test(w);
    out.push({ k: "searched", t: nsHuman(mine.namespace), title: mine.namespace, same: sameRelease(mine.namespace, rel), diff: w === "namespace/changed" });
    out.push({ k: "record", t: mine.vulnerability || r.vulnerability, sub: `affected ${c && c !== "none" ? c.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${mine.fixVersions?.length ? ` · fixed in ${mine.fixVersions[0]}` : mine.fixStates?.length ? ` · ${mine.fixStates.join("/").replace(/-/g, " ")}` : ""}`, title: (mine.constraints || []).join(" || "), diff: changed });
    out.push({ k: "result", t: "no match", sub: w === "record/same-but-unmatched" ? "same record: the matcher or its config differs" : changed ? "the record differs" : "", miss: true });
    return out;
  }
  out.push({ k: "result", t: "no match", sub: w === "unexplained" ? "unexplained by the match's data" : "", miss: true });
  return out;
}

// the kinds of step, in path order: a lane puts each step in its kind's column, so equivalent steps
// (namespace and namespace, record and record) line up, and a kind one side lacks is an empty slot
const stepKinds = ["package", "via", "searched", "record", "result"];

export interface Lane { side: Side; steps: Step[] }
const byKind = (l: Lane, k: string) => l.steps.find((s) => s.k === k);

// lanes is both sides' steps, each step marked diff when the other lane has no step of that kind,
// or its text differs
export function lanes(r: Row, m: MatchesResponse | undefined, rel: Release | null): Lane[] {
  const out = (["candidate", "reference"] as const).map((side) => ({ side, steps: steps(r, side, m?.[side]?.[0] as GrypeMatch | undefined, rel) }));
  for (const l of out) for (const s of l.steps) {
    const ol = out.find((x) => x !== l), o = ol && byKind(ol, s.k);
    // the record's constraint and fix are part of what it is; a step's matcher or match type isn't
    if (!o || o.t !== s.t || (s.k === "record" && (o.sub || "") !== (s.sub || ""))) s.diff = true;
  }
  return out;
}

export function matchPath(r: Row, m: MatchesResponse | undefined, rel: Release | null) {
  const ls = lanes(r, m, rel);
  const chip = (s: Step) => el("span", { class: `step ${s.k}${s.diff ? " diff" : ""}${s.miss ? " miss" : ""}${s.ok ? " ok" : ""}${s.same ? " same" : ""}`, title: s.title || "" },
    el("span", { class: "t" }, s.t), s.sub ? el("span", { class: "sub" }, s.sub) : null, s.same ? el("span", { class: "mine" }, "this image's release") : null);
  const kinds = stepKinds.filter((k) => ls.some((l) => byKind(l, k)));
  // one grid row per lane: the side's name, then a cell per kind with an arrow before it
  return el("div", { class: `path k${kinds.length}`, "data-testid": "match-lanes" }, ls.flatMap((l) => [
    el("span", { class: "lane-k" }, l.side),
    kinds.flatMap((k, i) => { const s = byKind(l, k);
      return [i ? el("span", { class: `arrow${s ? "" : " none"}` }, s ? "→" : "") : null, s ? chip(s) : el("span", { class: "slot", title: `no ${k} step on the ${l.side} side` })]; }),
  ]));
}

// records lists what the other DB has for the package in other releases, the image's own release
// first and bold, the rest dimmed
export function records(r: Row, dir: string, rel: Release | null) {
  const recs = otherRecords(r);
  if (!recs.length) return null;
  const sorted = [...recs].sort((a, b) => Number(sameRelease(b.namespace, rel)) - Number(sameRelease(a.namespace, rel)));
  const cons = (list: string[] | undefined) => (list || []).map((c) => c.replace(/\s*\((\w[\w-]*)\)$/, "")).join(" ‖ ");
  return el("div", { class: "records", "data-testid": "other-records" }, el("span", { class: "k" }, `the ${dir === "added" ? "reference" : "candidate"} DB also has, for ${r.sourcePackage || pkgOf(r.package.ref).name}:`),
    sorted.map((rec) => el("div", { class: `rec${sameRelease(rec.namespace, rel) ? " same" : " other"}` }, nsChip(rec.namespace),
      ` · ${rec.constraints?.length ? `affected ${cons(rec.constraints)}` : "every version"}${rec.fixVersions?.length ? ` · fixed in ${rec.fixVersions.join(", ")}` : rec.fixStates?.length ? ` · ${rec.fixStates.join("/").replace(/-/g, " ")}` : ""}`)));
}
