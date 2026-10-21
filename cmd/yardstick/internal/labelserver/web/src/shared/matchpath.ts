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

export interface Step { k: string; t: string; sub?: string; title?: string; same?: boolean; ok?: boolean; miss?: boolean; diff?: boolean }
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
    const sb: SearchedBy = md?.searchedBy || {}, fd = md?.found || {};
    const viaName = sb.package?.name && sb.package.name !== pk.name ? sb.package.name : (d.matchTypes || []).includes("exact-indirect-match") && (d.upstreams || [])[0] ? (d.upstreams || [])[0] : null;
    if (sb.cpes?.length || (d.matchTypes || []).includes("cpe-match")) out.push({ k: "via", t: "as CPE", sub: (sb.cpes || d.cpes || [])[0] || "", title: (sb.cpes || d.cpes || []).join("\n") });
    else if (viaName) out.push({ k: "via", t: `via source package ${viaName}`, sub: sb.package?.version && sb.package.version !== pk.version ? sb.package.version : "" });
    out.push({ k: "searched", t: nsHuman(sb.namespace || d.namespace), sub: (md?.matcher || (d.matchers || [])[0] || "").replace(/-matcher$/, " matcher"), title: sb.namespace || d.namespace, same: sameRelease(sb.namespace || d.namespace, rel) });
    const cons = fd.versionConstraint || (d.constraints || [])[0] || "";
    out.push({ k: "record", t: `${fd.vulnerabilityID || r.vulnerability}`, sub: `affected ${cons && cons !== "none" ? cons.replace(/\s*\((\w[\w-]*)\)$/, "") : "every version"}${d.fixState === "fixed" && d.fixVersions?.length ? ` · fixed in ${d.fixVersions[0]}` : d.fixState ? ` · ${d.fixState.replace(/-/g, " ")}` : ""}`, title: cons });
    if (r.why?.key === "record/distro-not-affected") out.push(notApplied(r, side, d, setups));
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
  if (w === "record/distro-not-affected") {
    // this grype searched as the other did and found the same record, then its distro check found
    // the distro's record saying fixed in 0, and dropped the match
    const ns = r.why?.to || r.why?.from || "", nak = (recs || []).find((x) => x.namespace === ns);
    const found = other && (recs || []).find((x) => x.namespace === other.namespace && x !== nak);
    if (other && found) {
      if ((other.matchTypes || []).includes("cpe-match")) out.push({ k: "via", t: "as CPE", sub: (other.cpes || [])[0] || "", title: (other.cpes || []).join("\n") });
      out.push({ k: "searched", t: nsHuman(other.namespace), title: other.namespace, same: sameRelease(other.namespace, rel) });
      const c = constraintsOf(found.constraints);
      out.push({ k: "record", t: found.vulnerability || r.vulnerability, sub: `affected ${c.length ? c.join(" || ") : "every version"}`, title: (found.constraints || []).join(" || ") });
    }
    const pkg = nak?.package || pk.name;
    out.push({ k: "distro", t: `${distroName(ns)} records`, sub: `${pkg} not affected · fixed in 0`, title: `${ns}: ${pkg} ${(nak?.constraints || ["< 0"]).join(" || ")}, fixed in 0`, miss: true, diff: true });
    out.push({ k: "result", t: "dropped", sub: `${distroName(ns)} says not affected`, miss: true });
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

// notApplied is the distro check on the side that matched though the other side's distro record says
// not affected: what its scan shows, never a guess at why (it may not have looked, or looked and
// not applied it)
function notApplied(r: Row, side: Side, d: NonNullable<Row["candidate"]>, setups: Setups): Step {
  const ns = r.why?.to || r.why?.from || "", grype = setups.grype?.[side] ? `grype ${setups.grype[side]}` : "its grype";
  const sub = d.distro ? `NAK not applied by ${grype}` : `${grype} detected no distro`;
  const db = setups.sameDB ? "its DB is the same and has the record; " : "";
  return { k: "distro", t: `${distroName(ns)} records`, sub, diff: true, title: `${db}${d.distro ? `${grype} scanned ${d.distro} and did not apply the record saying not affected` : `${grype} reported no distro for the image, so the record saying not affected was not applied`}` };
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
  return out;
}

export function matchPath(r: Row, m: MatchesResponse | undefined, rel: Release | null, setups: Setups = {}) {
  const ls = lanes(r, m, rel, setups);
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
