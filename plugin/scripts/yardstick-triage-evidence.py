#!/usr/bin/env python3
"""Gather evidence for every unlabeled delta in a gate (default: $YARDSTICK_GATE, else the gate scanned last) and draft proposals.

    yardstick-triage-evidence.py [--store DIR] [--name RUN] [--gate NAME] [--side cand|ref|both] [--model ID] [--out DIR] [--workers N]

Reads `yardstick score <gate> -o json` (rows carry the grype detail), `yardstick claims list` and
`yardstick claims policy`, and (cached under ~/.cache/yardstick-skills/) cve.org, the Ubuntu tracker, OSV and
the upstream project's GitHub repository advisory for unassessed distro rows (set GITHUB_TOKEN to lift the
60/hour limit). Writes to <out> (default <store>/.yardstick/triage/<run>/<gate>/):

    evidence.md       one section per group (vulnerability x source package), for review
    evidence.json     the same, machine-readable, with the row ids
    groups.json       group number -> row ids (for yardstick-triage-edit.py)
    proposals.jsonl   `yardstick claims agent propose` input: one line per row, with justification, rule, facts, note
    proposals.md      the proposals numbered by group, in three confidence sections
    causes.jsonl      `yardstick claims agent propose-cause` input

Nothing is recorded until someone runs `yardstick claims agent propose proposals.jsonl --gate <gate>`.

Confidence: high = the tracker states it; medium = inferred from version ranges, a human should look;
low = nobody has assessed it, proposed as `unclear`. Rules are named `<source>/<inference>` in evidence[].rule;
they, their verdicts, ceilings and justifications are `rules:` in the claims corpus's vocabulary.yaml.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yardstick_common as dc  # noqa: E402
import yardstick_euvd  # noqa: E402  (optional source; see its docstring)
import yardstick_redhat  # noqa: E402
import yardstick_alpine  # noqa: E402

EUVD = False

SKILL = "triage-deltas"
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
PER_LABEL = "*"  # a rule whose justification depends on the vendor's stated reason (why_from_text)

# the labeling policy, from `yardstick claims policy -o json` (set_policy): rule name -> {verdict, justification,
# ceiling, decision, basis, title}, and justification -> (verdict, line). Empty until set, and then the rules
# are unchecked, as when delta's policy doc was missing.
POLICY: dict[str, dict] = {}
REASONS: dict[str, tuple[str, str]] = {}


def set_policy(policy: dict) -> None:
    POLICY.clear()
    POLICY.update(policy.get("rules") or {})
    REASONS.clear()
    for verdict, kinds in (policy.get("justifications") or {}).items():
        for kind, line in kinds.items():
            REASONS.setdefault(kind, (verdict, line))  # not-recorded is listed under fp and unclear; no rule cites it


def rule_of(p: dict) -> str:
    """A proposal's or cause's rule: its first evidence entry's."""
    return ((p.get("evidence") or [{}])[0]).get("rule", "")


def evidence(rule: str, facts: list[dict], interpretation: str = "") -> list[dict]:
    """The evidence[] a proposal carries. An entry needs at least one fact, so a rule nothing observed for
    is left off (yardstick has no way to cite a rule alone)."""
    e = {"rule": rule, "facts": facts} if rule else {"facts": facts}
    if interpretation:
        e["interpretation"] = interpretation
    return [e] if facts else []


def why_from_text(text: str) -> str:
    """The justification a vendor's not-affected reason supports (the '*' rules): what they say about the code."""
    t = (text or "").lower()
    if re.search(r"code (is )?not (built|present|compiled|shipped|included)|not (built|compiled|shipped)|vulnerable_code_not_present|component_not_present|not installed", t):
        return "vulnerable_code_not_present"
    if re.search(r"windows|macos|darwin|solaris|aix|32.bit|only affects|only on ", t):
        return "other-platform"
    if re.search(r"introduced (later|after)|vulnerable code introduced|predates", t):
        return "introduced-later"
    if re.search(r"\bfixed\b|backport|patched|already (fixed|has)", t):
        return "fix-installed"
    if re.search(r"rejected|withdrawn|disputed", t):
        return "not-a-vulnerability"
    return "vendor-not-affected"


def why_for(rule: str, verdict: str, kind: str | None = None, text: str = "") -> dict | None:
    """The proposal's justification as {kind, text?}: the kind given, else the rule's from the policy (per-row
    rules read the vendor's text). The text is the specific, which goes in the evidence's interpretation.
    Raises when the kind doesn't support the verdict, so a drift fails here rather than in `yardstick claims agent propose`."""
    rule_kind = (POLICY.get(rule) or {}).get("justification", "")
    if not kind:
        kind = why_from_text(text) if rule_kind == PER_LABEL else rule_kind
    if not kind:
        return None
    if REASONS and kind not in REASONS:
        raise ValueError(f"justification {kind} is not under justifications: in vocabulary.yaml (yardstick claims policy)")
    if REASONS and REASONS[kind][0] != verdict:
        raise ValueError(f"justification {kind} supports {REASONS[kind][0]}, not {verdict} (rule {rule or 'judgement'})")
    out = {"kind": kind}
    if text and rule_kind != PER_LABEL:
        out["text"] = text
    return out


def parse_fix_version(desc: str) -> str | None:
    desc = (desc or "").strip()
    if re.match(r"^[0-9][^\s()]*$", desc):
        return desc
    m = re.search(r"\(([0-9][^\s()]*)\)", desc)
    return m.group(1) if m else None


class Verdict:
    """A suggestion. Confidence is clamped to the rule's ceiling in the policy (P-1..P-6)."""

    def __init__(self, verdict: str, confidence: str, rule: str, note: str, facts: list[dict] | None = None, questions: list[str] | None = None,
                 why: str | None = None, why_text: str = ""):
        r = POLICY.get(rule) or {}
        pv, ceiling, decision = r.get("verdict", verdict), r.get("ceiling", confidence), r.get("decision", "?")
        if pv not in ("any", verdict):
            raise ValueError(f"rule {rule} proposes {verdict} but the policy says {pv}")
        if CONF_RANK[confidence] > CONF_RANK[ceiling]:
            confidence = ceiling
        if verdict == "unclear":
            confidence = "low"
        self.verdict, self.confidence, self.rule, self.note, self.decision = verdict, confidence, rule, note, decision
        # why: the justification, the truth about the code (vocabulary.yaml's justifications); the UI's headline
        self.why = why_for(rule, verdict, why, why_text)
        self.facts = [f for f in (facts or []) if f]
        self.questions = questions or []


def suggest_ubuntu(row: dict, cve: str, rec: dict | None, codename: str | None, cna: dict | None, hint: str) -> Verdict:
    new = row["side"] == "candidate"
    src, installed = row["source_pkg"], row["version"]
    who = f"Ubuntu's tracker ({codename})"
    if not rec or not codename:
        return Verdict("unclear", "low", "ubuntu/not-listed", f"{who} has no record for {cve}; nobody has assessed it{hint}",
                       questions=[f"Does {cve} apply to {src} {installed} at all? No tracker has looked."])
    st = dc.ubuntu_statuses(rec, src, codename)
    rels, up = st.get("release") or [], st.get("upstream")
    base = dc.ubuntu_facts(rec, cve, src, codename)
    collapsed = dc.ubuntu_fact_status(rec, src, codename)

    def pocket_fact(entry: dict) -> dict | None:
        value = (entry["status"] + " " + entry["description"]).strip()
        return None if value == collapsed else dc.ubuntu_pocket_fact(cve, src, codename, entry)

    if not rels:
        return Verdict("unclear", "low", "ubuntu/not-listed", f"{who} does not list {src}; nobody has assessed it{hint}", base,
                       [f"Is {src} affected by {cve}? Ubuntu's tracker has no entry for it in {codename}."])
    for r in rels:
        if r["status"] in ("not-affected", "DNE"):
            why = f": {r['description']}" if r["description"] else " without saying why"
            pocket = f" in the {r['pocket']} pocket" if r["pocket"] != "security" else ""
            tail = ", yet the candidate DB still reports it (DB lag or a vunnel/grype-db bug worth a look)" if new else "; the candidate correctly dropped it"
            rule = "ubuntu/not-affected" if r["description"] or r["status"] == "DNE" else "ubuntu/not-affected-no-reason"
            return Verdict("fp", "high", rule, f"{who} marks it {r['status']}{pocket}{why}{tail}", base + [pocket_fact(r)],
                           why_text=r["description"] if r["description"] else ("DNE" if r["status"] == "DNE" else ""))
    fixes = [(r, parse_fix_version(r["description"])) for r in rels if r["status"] == "released"]
    for r, fixv in fixes:
        if fixv and dc.deb_compare(installed, fixv) >= 0:
            return Verdict("fp", "high", "ubuntu/installed-has-fix", f"the image's {installed} already contains the fix ({fixv} via {r['pocket']})", base + [pocket_fact(r)],
                           why_text=f"fixed in {fixv}")
    for r, fixv in fixes:
        if fixv:
            esm = " (ESM-only fix, which grype shows as wont-fix)" if r["pocket"].startswith("esm") else ""
            tail = "" if new else "; the candidate DB dropped a real finding, investigate"
            return Verdict("tp", "high" if new else "medium", "ubuntu/released-newer-than-installed",
                           f"fixed in {fixv} via {r['pocket']}{esm}; the image has {installed}, which predates the fix{tail}", base + [pocket_fact(r)],
                           why_text=f"fixed in {fixv}")
    if fixes:
        return Verdict("tp", "medium", "ubuntu/released-no-version", f"{who} says released but gives no version; treat as affected until checked", base)
    for r in rels:
        if r["status"] in ("needed", "pending", "deferred"):
            tail = "" if new else "; yet the candidate DB dropped it, investigate"
            desc = f", {r['description']}" if r["description"] else ""
            return Verdict("tp", "high" if new else "medium", "ubuntu/needed",
                           f"{who} assessed it as affected (status {r['status']}{desc}), no fix in this release{tail}", base + [pocket_fact(r)])
    for r in rels:
        if r["status"] == "ignored":
            m = re.search(r"\[(.*?)\]", r["description"])
            reason = (m.group(1) if m else r["description"]).lower()
            if re.search(r"code not (built|present|compiled)|not affected|not vulnerable|windows", reason):
                return Verdict("fp", "medium", "ubuntu/ignored-not-applicable", f"{who} ignored it with a triager's note that the code is not built/present or not applicable: {r['description']} (a note, not verified)", base + [pocket_fact(r)],
                               why_text=reason)
            if re.search(r"too intrusive|will not fix|wont fix|won't fix|not going to fix|no fix", reason):
                tail = "" if new else "; yet the candidate DB dropped it, investigate"
                return Verdict("tp", "high" if new else "medium", "ubuntu/ignored-wont-fix", f"{who} assessed it as affected but will not fix it: {r['description']}{tail}", base + [pocket_fact(r)])
    # unassessed: needs-triage, or ignored only because support ended
    r0 = rels[0]
    unassessed = f"{who} has not assessed it ({r0['status']}{': ' + r0['description'] if r0['description'] else ''})"
    inst_up = dc.deb_upstream(installed)
    rel = dc.cna_range_relation(cna, inst_up)
    in_range = rel == "in"
    bounded = dc.cna_affected_summary(cna, bounded_only=True)
    cna_desc = "; ".join(bounded)[:160]
    cna_note = f"; CNA affected range {'includes' if in_range else 'does not include'} upstream {inst_up}: {cna_desc}" if rel is not None else ""
    with_up = base + dc.ubuntu_facts(rec, cve, src, codename, with_upstream=True)[2:]
    cna_f = [dc.cna_fact(cve, cna)] if cna else []
    q = [f"Is the vulnerable code present in {src} {inst_up}? Check the fix commit against the installed upstream version."]
    if rel == "below":
        return Verdict("fp", "medium", "cna/introduced-after-installed",
                       f"the CNA's affected range starts after the image's upstream {inst_up} ({cna_desc}); {unassessed}. Only meaningful if the CNA product is this package's upstream{hint}", with_up + cna_f,
                       [f"Is the CNA's lower bound the version that introduced the bug, and is {src} the same product?"])
    # the upstream project's own GitHub advisory (often only in its repository, not the global database) is the
    # one source that routinely states where the bug was introduced; the CNA and the tracker rarely do
    adv = dc.ghsa_for_cve(cve, cna, global_db=bool(os.environ.get("GITHUB_TOKEN")))
    grel, gdesc = dc.advisory_range_relation(adv, inst_up)
    gfacts = dc.advisory_facts(cve, adv)
    comps = dc.advisory_components(adv)
    row["github_advisory"] = {"ranges": gdesc, "relation": grel, "components": comps, "urls": [g.get("html_url") for g in adv if g.get("html_url")]} if adv else None
    ghsa_note = f"; the project's GitHub advisory range includes {inst_up}: {gdesc}" if grel == "in" else ""
    if comps:
        q = [f"Is the vulnerable code present in {src} {inst_up}? The advisory names {', '.join(comps[:3])}; check it at the installed upstream tag."]
    if grel == "below":
        return Verdict("fp", "medium", "ghsa/introduced-after-installed",
                       f"the project's GitHub advisory says affected {gdesc}, a range that starts after the image's upstream {inst_up}; {unassessed}. Only meaningful if the advisory's project is this package's upstream{hint}", with_up + gfacts,
                       [f"Is the advisory's lower bound the version that introduced the bug ({', '.join(comps[:2]) or 'check the fix commit'})?"])
    if up and up["status"] == "released":
        fixv = parse_fix_version(up["description"])
        if fixv:
            fix_up = dc.deb_upstream(fixv)
            if dc.deb_compare(inst_up, fix_up) >= 0:
                if in_range:
                    return Verdict("unclear", "low", "cna/disagrees-with-upstream-fix",
                                   f"Ubuntu's tracker says upstream fixed it in {fixv} (older than the image's {inst_up}), but the CNA's affected range includes {inst_up} ({cna_desc}); {unassessed}{hint}", with_up + cna_f,
                                   [f"Which is right for {inst_up}: Ubuntu's upstream fix version {fixv} or the CNA range {cna_desc}? Check the fix commit."])
                return Verdict("fp", "medium", "ubuntu/unassessed-upstream-fix-older-than-installed",
                               f"upstream fixed it in {fixv}, and the image's upstream version {inst_up} is at or past that; {unassessed}{cna_note}{hint}", with_up)
            return Verdict("tp", "medium", "ubuntu/unassessed-upstream-fix-newer-than-installed",
                           f"upstream fixed it in {fixv}, newer than the image's upstream {inst_up}; when the bug was introduced is unverified{cna_note}{ghsa_note}; {unassessed}{hint}", with_up + gfacts, q)
    if up and up["status"] == "not-affected":
        return Verdict("fp", "medium", "ubuntu/unassessed-upstream-not-affected", f"Ubuntu's tracker says upstream is not affected ({up['description']}); {unassessed}{hint}", with_up,
                       why_text=up["description"])
    if in_range:
        return Verdict("tp", "medium", "ubuntu/unassessed-cna-range-includes-installed",
                       f"{unassessed}, but the CNA's affected range includes upstream {inst_up}: {cna_desc}{ghsa_note}{hint}", with_up + cna_f + gfacts, q)
    tail = "; the candidate DB dropped it, so check why before labeling" if not new else f"; priority {rec.get('priority')}"
    return Verdict("unclear", "low", "ubuntu/unassessed", f"{unassessed}{tail}{cna_note}{ghsa_note}{hint}", with_up + gfacts, q)


def suggest_redhat(row: dict, cve: str, hint: str) -> Verdict:
    """Red Hat's CSAF VEX (per binary RPM and stream) and Hydra (unfixed states, the analyst statement)."""
    new = row["side"] == "candidate"
    major = (row["distro_version"] or "").split(".")[0]
    binary, installed, src = row["name"], row["version"], row["source_pkg"]
    doc = yardstick_redhat.vex(cve)
    hy = yardstick_redhat.hydra(cve)
    st = yardstick_redhat.binary_status(doc, major, binary, installed, src)
    hs = yardstick_redhat.hydra_state(hy, major, src)
    vex_url = f"https://security.access.redhat.com/data/csaf/v2/vex/{cve.split('-')[1]}/{cve.lower()}.json"
    who = f"Red Hat's VEX (RHEL {major})"
    about = {"vulnerability": cve, "product": f"rhel-{major}", "component": binary}
    value = st["status"] + (f" {st['applicable_fix'][1]}" if st["status"] == "fixed" and st["applicable_fix"] else "") + (f" [{', '.join(st['flags'])}]" if st["flags"] else "")
    facts = [dc.fact("redhat-csaf-vex", about, "status", value, vex_url)]
    if hs and hs.get("fix_state"):
        facts.append(dc.fact("redhat-security-data", {"vulnerability": cve, "product": hs["product_name"], "package": hs.get("package_name") or src}, "fix_state", hs["fix_state"], f"https://access.redhat.com/security/cve/{cve}"))
    statement = (hs or {}).get("statement") or ""
    # a vendor statement that names a module or library the binary does not ship
    files = row.get("files") or []
    comps = yardstick_redhat.components_named(statement + " " + (row.get("nvd_description") or ""))
    if files and comps and not any(yardstick_redhat.files_contain(files, c) for c in comps):
        return Verdict("fp", "high", "sbom/code-not-in-binary",
                       f"Red Hat's statement puts the flaw in {', '.join(comps[:3])}, and {binary} {installed} ships none of it (per the SBOM file list); the srpm {src} builds it, but this binary has no vulnerable code",
                       facts + [dc.fact("sbom", {"package": row["package"], "component": c}, "file", "absent") for c in comps[:3]])
    if st["status"] == "known_not_affected":
        if st["flags"]:
            return Verdict("fp", "high", "rhel/not-affected", f"{who} marks {binary} not affected: {', '.join(st['flags'])}" + ("" if new else "; the candidate correctly dropped it"), facts,
                           why_text=", ".join(st["flags"]))
        return Verdict("fp", "medium", "rhel/not-affected-no-reason", f"{who} marks {binary} not affected without a justification flag" + ("" if new else "; the candidate correctly dropped it"), facts)
    if st["status"] == "fixed" and st["applicable_fix"]:
        minor, fixv, adv = st["applicable_fix"]
        if st["comparison"] is not None and st["comparison"] >= 0:
            return Verdict("fp", "high", "rhel/installed-has-fix", f"the image's {installed} is at or past Red Hat's fix {fixv} (stream {minor}, {adv})", facts, why_text=f"fixed in {fixv}")
        tail = "" if new else "; the candidate DB dropped a real finding, investigate"
        return Verdict("tp", "high" if new else "medium", "rhel/fixed-newer-than-installed", f"Red Hat fixed it in {fixv} (RHEL {minor}, {adv}); the image has {installed}, which predates the fix{tail}", facts)
    fix_state = (hs or {}).get("fix_state") or ""
    if st["status"] == "known_affected" or fix_state in ("Affected", "Fix deferred", "Will not fix"):
        tail = "" if new else "; yet the candidate DB dropped it, investigate"
        how = f"Hydra fix_state {fix_state}" if fix_state else "VEX known_affected"
        return Verdict("tp", "high" if new else "medium", "rhel/affected", f"Red Hat assessed {src} on RHEL {major} as affected ({how}), no fix{tail}", facts)
    if fix_state == "Not affected":
        return Verdict("fp", "medium", "rhel/not-affected-no-reason", f"Red Hat's security data marks {src} on RHEL {major} Not affected (no justification given)", facts)
    if fix_state == "Out of support scope" or st["status"] == "under_investigation":
        return Verdict("unclear", "low", "rhel/unassessed", f"Red Hat has not assessed it for RHEL {major} ({fix_state or st['status']}); nobody has looked{hint}", facts,
                       [f"Is the vulnerable code in {binary} {installed}? Red Hat gives no assessment for RHEL {major}."])
    q = [f"Does Red Hat's advisory data cover {binary} (built from {src}) on RHEL {major}? Neither the VEX nor Hydra lists it."]
    tail = "; the candidate DB dropped it, so check why before labeling" if not new else ""
    return Verdict("unclear", "low", "rhel/not-listed", f"{who} does not list {binary} or {src} for this release{tail}{hint}", facts, q)


def suggest_debian(row: dict, cve: str, hint: str) -> Verdict:
    major = (row["distro_version"] or "").split(".")[0]
    osv = dc.debian_osv_status(cve, row["source_pkg"], major)
    installed = row["version"]
    url = f"https://security-tracker.debian.org/tracker/{cve}"
    facts = [dc.fact("osv", {"vulnerability": f"DEBIAN-{cve}", "package": row["source_pkg"], "ecosystem": f"Debian:{major}"}, "fixed", (osv or {}).get("fixed") or "", url)] if osv else []
    if osv and osv.get("fixed"):
        if dc.deb_compare(installed, osv["fixed"]) < 0:
            return Verdict("tp", "high", "debian/fixed-newer-than-installed", f"Debian fixed it in {osv['fixed']}; the image has {installed}", facts)
        return Verdict("fp", "high", "debian/installed-has-fix", f"the image's {installed} already contains Debian's fix {osv['fixed']}", facts)
    if osv:
        return Verdict("tp", "medium", "debian/affected-unfixed", f"Debian lists the package as affected with no fixed version in this release{hint}", facts)
    return Verdict("unclear", "low", "debian/no-record", f"no Debian OSV record for this package/release; check {url}{hint}",
                   questions=[f"Does Debian's tracker mark {row['source_pkg']} not-affected for {cve}? OSV only carries affected entries."])


GITHUB_ECOSYSTEMS = {"PyPI", "Maven", "npm", "Go", "RubyGems", "crates.io", "NuGet", "Packagist", "Hex", "Pub", "SwiftURL"}


def ecosystem_advisories(row: dict) -> tuple[str | None, str, list[dict], dict | None]:
    """(ecosystem, osv package name, advisories for this package that match the row's ids, the GHSA/OSV record)."""
    p = dc.parse_purl(row["package"])
    eco = dc.OSV_ECOSYSTEM.get(p["type"])
    if not eco:
        return None, p["name"], [], None
    name = dc.osv_package_name(p)
    ids = set([row["vulnerability"], *row["aliases"]])
    # GitHub cross-aliases advisories for a fix and its later bypass (lodash GHSA-35jh lists CVE-2026-4800 and
    # GHSA-r5fr as aliases, and vice versa), so an alias hit can be a sibling advisory with its own range. Rank:
    # the advisory whose own id is the row's vulnerability, then one whose id is in the row's alias group, then
    # alias-only matches.
    def rank(v: dict) -> int:
        if v["id"] == row["vulnerability"]:
            return 0
        if v["id"] in ids:
            return 1
        return 2
    hits = sorted((v for v in dc.osv_query(name, eco) if ids & set([v["id"], *v.get("aliases", [])])), key=rank)
    ghsa_id = next((i for i in [row["vulnerability"], *row["aliases"]] if i.startswith("GHSA-")), None)
    rec = dc.osv_vuln(ghsa_id) if ghsa_id else (hits[0] if hits else None)
    return eco, name, hits, rec


def advisory_for_cve_in_ecosystem(cve: str | None, eco: str) -> list[str] | None:
    """Package names an ecosystem advisory for this CVE lists, via OSV's CVE record aliases -> GHSA, or the
    GitHub advisory API when GITHUB_TOKEN is set (60 requests/hour without one). None if no reviewed advisory;
    an empty list if a reviewed advisory exists but names no package in this ecosystem."""
    if not cve:
        return None
    names: list[str] = []
    found = False
    if os.environ.get("GITHUB_TOKEN"):
        for g in dc.fetch_json(f"https://api.github.com/advisories?cve_id={cve}", headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}) or []:
            if g.get("type") != "reviewed":
                continue  # GitHub mints an unreviewed shell for every CVE; only a reviewed advisory is an assessment
            found = True
            for v in g.get("vulnerabilities", []):
                if (v.get("package") or {}).get("ecosystem", "").lower() == eco.lower():
                    names.append(v["package"].get("name", ""))
        if found:
            return names
    rec = dc.osv_vuln(cve)
    extra = yardstick_euvd.ghsa_ids(cve) if EUVD else []  # EUVD knows the GHSA id even when OSV has no CVE record
    for alias in dict.fromkeys((rec or {}).get("aliases", []) + [a for r in [rec] if r for a in r.get("related", [])] + extra):
        if not alias.startswith("GHSA-"):
            continue
        g = dc.osv_vuln(alias)
        if not g:
            continue  # OSV omits unreviewed GHSA shells (every CVE has one, with no packages); they are not evidence
        found = True
        for a in g.get("affected", []):
            pk = a.get("package") or {}
            if pk.get("ecosystem", "").split(":")[0] == eco:
                names.append(pk.get("name", ""))
    return names if found else None


def suggest_ecosystem(row: dict, cna: dict | None, hint: str) -> Verdict:
    p = dc.parse_purl(row["package"])
    eco, name, hits, rec = ecosystem_advisories(row)
    cve = next((a for a in [row["vulnerability"], *row["aliases"]] if a.startswith("CVE-")), None)
    cpe = "cpe-match" in (row.get("match_types") or [])
    if not eco:
        return Verdict("unclear", "low", "none/no-evidence", f"no advisory source for purl type {p['type']}{hint}")
    url = f"https://osv.dev/vulnerability/{(rec or {}).get('id', row['vulnerability'])}"
    reviewed = (rec or {}).get("database_specific", {}).get("github_reviewed")
    if rec and rec.get("withdrawn"):
        return Verdict("fp", "high", "ghsa/withdrawn", f"{rec['id']} was withdrawn on {rec['withdrawn'][:10]}",
                       [dc.fact("osv", {"vulnerability": rec["id"]}, "withdrawn", rec["withdrawn"], url)])
    if hits:
        v = hits[0]
        affs = [a for a in v.get("affected", []) if (a.get("package") or {}).get("name", "").lower() == name.lower()
                and (a.get("package") or {}).get("ecosystem", "").split(":")[0] == eco]
        # an advisory can carry several entries for one package (one per release line); affected in any wins
        status, fixed, how = "unknown", None, "no range places it"
        for a in affs:
            st, fx, hw = dc.osv_range_status_for(a, p["version"], eco)
            if st == "affected":
                status, fixed, how = st, fx, hw
                break
            if st == "fixed" and status != "affected":
                status, fixed, how = st, fx, hw
        facts = [dc.fact("osv", {"vulnerability": v["id"], "package": name, "ecosystem": eco}, "fixed", fixed or "", f"https://osv.dev/vulnerability/{v['id']}"),
                 dc.fact("osv", {"vulnerability": v["id"]}, "github_reviewed", str(bool(v.get("database_specific", {}).get("github_reviewed"))), f"https://osv.dev/vulnerability/{v['id']}")]
        rev = "GitHub-reviewed " if v.get("database_specific", {}).get("github_reviewed") else "unreviewed "
        via = " (matched by CPE; the ecosystem advisory confirms the package)" if cpe else ""
        if status == "affected":
            conf = "high" if v.get("database_specific", {}).get("github_reviewed") else "medium"
            return Verdict("tp", conf, "ghsa/version-in-affected-range",
                           f"{rev}advisory {v['id']} lists {eco} {name} as affected, {p['version']} is {how}{', fixed in ' + fixed if fixed else ', no fix'}{via}", facts)
        if status == "fixed":
            return Verdict("fp", "high", "ghsa/installed-at-or-past-fix", f"{rev}advisory {v['id']} fixes {eco} {name} in {fixed}; the image has {p['version']}{via}", facts)
        low = dc.osv_below_all_ranges(affs, p["version"], eco)
        if low:
            return Verdict("fp", "medium", "ghsa/introduced-after-installed",
                           f"{rev}advisory {v['id']} says {eco} {name} is affected from {low}; the image's {p['version']} predates every affected range{via}", facts,
                           [f"Is {low} where the bug was introduced, or just the oldest version the advisory bothered to list?"])
        return Verdict("unclear", "low", "ghsa/range-unknown", f"advisory {v['id']} lists {eco} {name} but {how} for {p['version']}{hint}", facts,
                       [f"Which versions of {name} does {v['id']} affect? Its range does not place {p['version']}."])
    if cpe:
        others = advisory_for_cve_in_ecosystem(cve, eco)
        f = [dc.fact("osv", {"vulnerability": cve or row["vulnerability"], "package": name, "ecosystem": eco}, "listed", "false",
                     f"https://osv.dev/vulnerability/{cve or row['vulnerability']}")]
        if others == []:
            return Verdict("unclear", "low", "cpe/advisory-without-packages",
                           f"a GitHub advisory exists for {cve} but names no packages, so nothing confirms or denies {eco} {name}; GitHub does not map EOL lines such as log4j 1.x{hint}", f,
                           [f"Does {name} {p['version']} contain the code {cve} describes? The advisory has no package list to check."])
        if others:
            return Verdict("fp", "medium", "cpe/advisory-lists-other-packages",
                           f"the ecosystem advisory for {cve} lists {eco} {', '.join(sorted(set(others))[:4])}, not {name}; this CPE match is a name collision unless {name} embeds that code{hint}", f)
        if eco in GITHUB_ECOSYSTEMS:
            return Verdict("fp", "medium", "cpe/no-ecosystem-advisory",
                           f"no {eco} advisory exists for {cve or row['vulnerability']} (OSV); the CPE match pairs the CVE's product name with an unrelated {eco} package named {name}{hint}", f)
        return Verdict("unclear", "low", "cpe/no-advisory-source", f"no advisory source covers {eco}; the CPE match is unverified{hint}", f,
                       [f"Is {name} the product {cve} describes?"])
    return Verdict("unclear", "low", "ghsa/package-not-listed", f"no OSV advisory for {eco} {name} matches {row['vulnerability']}, yet grype's GitHub data reports it{hint}",
                   questions=[f"Which advisory does grype's github namespace record for {row['vulnerability']} come from, and does it list {name}?"])


def files_only_libs(files: list[str]) -> bool:
    """True when the binary ships shared libraries and no programs: a library row can still contain the code."""
    progs = [f for f in files if "/bin/" in f or "/sbin/" in f or "/libexec/" in f]
    libs = [f for f in files if ".so" in f.rsplit("/", 1)[-1]]
    return bool(libs) and not progs


def suggest(row: dict, cna: dict | None, hint: str) -> Verdict:
    cve = next((a for a in [row["vulnerability"], *row["aliases"]] if a.startswith("CVE-")), None)
    status = row.get("db_status") or {}
    if cve and ((cna or {}).get("cveMetadata", {}).get("state") == "REJECTED"):
        return Verdict("fp", "high", "cna/rejected", "the CVE has been rejected/withdrawn by its CNA", [dc.cna_fact(cve, cna)])
    if "rejected" in status.values():
        which = ", ".join(k for k, v in status.items() if v == "rejected")
        return Verdict("fp", "high", "cna/rejected", f"the {which} DB records the advisory as rejected", [dc.cna_fact(cve, cna)] if cve else [])
    if "disputed" in status.values():
        hint += "; note the DB marks the advisory disputed"
    files = row.get("files") or []
    if files:
        text = (row.get("nvd_description") or "") + " " + " ".join(
            d.get("value", "") for d in ((cna or {}).get("containers", {}).get("cna", {}).get("descriptions") or []))
        mods = dc.perl_modules_named(text)
        if row["name"].startswith(("perl", "libperl")) and "Perl" in text:
            # bare module names (Storable, Encode) only via the CNA's product field, which names the module
            for a in (cna or {}).get("containers", {}).get("cna", {}).get("affected", []) or []:
                prod = a.get("product") or ""
                if re.match(r"^[A-Z][A-Za-z0-9]*(::[A-Z][A-Za-z0-9_]*)*$", prod) and prod not in ("Perl",) and prod not in mods:
                    mods.append(prod)
        if mods:
            missing = dc.modules_missing_from(files, mods)
            if len(missing) == len(mods):
                facts = [dc.fact("sbom", {"package": row["package"], "module": m}, "file", "absent") for m in missing]
                return Verdict("fp", "high", "sbom/code-not-in-binary",
                               f"the CVE is in {', '.join(mods)}, and {row['name']} {row['version']} installs no {', '.join(m.replace('::', '/') + '.pm' for m in mods)} (per the syft SBOM file list); if another installed package ships the module, that package has its own row", facts)
        # a program the description names with its option ("nsenter --join-cgroup") that a sibling package from the
        # same source ships and this one does not: the srpm/source match carried the finding to the wrong binary (P-10)
        sib = row.get("sibling_programs") or {}
        progs = [p for p in dc.programs_named(text) if p in sib]
        own = {f.rsplit("/", 1)[-1] for f in files}
        missing = [p for p in progs if p not in own]
        library_row = row["name"].startswith("lib") and re.search(r"\blib[a-z0-9]+\b|\blibrary\b", text, re.I)
        if progs and len(missing) == len(progs) and not library_row:
            owners = sorted({o for p in missing for o in sib[p]})
            facts = [dc.fact("sbom", {"package": row["package"], "program": p}, "file", "absent") for p in missing]
            return Verdict("fp", "high", "sbom/code-not-in-binary",
                           f"the CVE is in the {', '.join(missing)} program (named with its option in the description), which {row['name']} {row['version']} does not ship (per the syft SBOM file list); {', '.join(owners)} ships it from the same source package and has its own row", facts)
        # weaker form (P-10, medium): the CNA's product or a bare program name in the description is something a
        # sibling from the same source ships and this binary does not (gdb-gdbserver for a gdb bug, vim-minimal for xxd)
        products = {(a.get("product") or "").strip().lower() for a in ((cna or {}).get("containers", {}).get("cna", {}).get("affected") or [])}
        cands = [c for c in dict.fromkeys(list(products) + [m.lower() for m in re.findall(r"\b([a-z][a-z0-9_.+-]{2,})\b", (row.get("nvd_description") or "")[:400])]) if c in sib and sib[c] and row["name"] not in sib[c] and c not in own]
        if cands and not library_row and not files_only_libs(files):
            owners = sorted({o for c in cands for o in sib[c]})
            facts = [dc.fact("sbom", {"package": row["package"], "program": c}, "file", "absent") for c in cands[:3]]
            return Verdict("fp", "medium", "sbom/sibling-ships-program",
                           f"the CVE names {', '.join(cands[:3])}, a program {', '.join(owners)} ships from the same source and {row['name']} {row['version']} does not (per the syft SBOM file list); this binary carries the match only because it shares the source package", facts,
                           [f"Does {row['name']} contain the affected code some other way (a shared library or embedded copy)?"])
    ptype = dc.parse_purl(row["package"])["type"]
    if ptype in dc.OSV_ECOSYSTEM:  # a language package wherever it sits: its advisory source is the ecosystem's
        return suggest_ecosystem(row, cna, hint)
    if cve and row["distro_type"] == "ubuntu":
        rec = dc.ubuntu_cve(cve)
        if rec and rec.get("status") == "rejected":
            return Verdict("fp", "high", "cna/rejected", "the CVE is marked rejected by Ubuntu's tracker",
                           [dc.fact("ubuntu-cve-tracker", {"vulnerability": cve}, "priority", rec.get("priority") or "", f"https://ubuntu.com/security/{cve}")])
        return suggest_ubuntu(row, cve, rec, dc.ubuntu_codename(row["distro_version"] or ""), cna, hint)
    if cve and row["distro_type"] == "debian" and ptype == "deb":
        return suggest_debian(row, cve, hint)
    if cve and row["distro_type"] in ("redhat", "rhel", "centos") and ptype == "rpm":
        return suggest_redhat(row, cve, hint)
    if cve and row["distro_type"] == "alpine" and ptype == "apk":
        v = suggest_alpine(row, cve, hint)
        if v:
            return v
    if cve:  # no tracker covers this package (built from source, CPE-matched, EOL alpine): the CNA's own range is all there is
        return suggest_cna(row, cve, cna, hint)
    return Verdict("unclear", "low", "none/no-evidence", f"no advisory source for {row['package']}{hint}")


def suggest_alpine(row: dict, cve: str, hint: str) -> Verdict | None:
    br = yardstick_alpine.branch(row["distro_version"] or "")
    origin = row["source_pkg"] or row["name"]
    if not br:
        return None
    st = yardstick_alpine.status(br, origin, cve, row["version"])
    url = f"https://secdb.alpinelinux.org/{br}/"
    facts = [dc.fact("alpine-secdb", {"vulnerability": cve, "package": origin, "branch": br}, "fixed", st["fixed"] or "not-listed", url)]
    if st["status"] == "not-affected":
        return Verdict("fp", "medium", "alpine/not-affected-no-reason", f"Alpine's secdb ({br}) lists {cve} under version 0 for {origin}: the maintainer states it was never affected, with no reason given", facts)
    if st["status"] == "fixed":
        if st["comparison"] is not None and st["comparison"] >= 0:
            return Verdict("fp", "high", "alpine/installed-has-fix", f"Alpine fixed it in {origin} {st['fixed']} ({br}); the image has {row['version']}", facts)
        return Verdict("tp", "high", "alpine/fixed-newer-than-installed", f"Alpine fixed it in {origin} {st['fixed']} ({br}); the image has {row['version']}, which predates the fix", facts)
    return None  # not listed: fall through to the CNA range; EOL branches never list newer CVEs


def suggest_cna(row: dict, cve: str, cna: dict | None, hint: str) -> Verdict:
    inst = dc.deb_upstream(row["version"]) if dc.parse_purl(row["package"])["type"] in ("deb", "apk", "rpm") else row["version"].split("-r")[0]
    rel = dc.cna_range_relation(cna, inst)
    desc = "; ".join(dc.cna_affected_summary(cna, bounded_only=True))[:160]
    f = [dc.cna_fact(cve, cna)] if cna else []
    where = f"no distro tracker covers {row['name']} here"
    if rel == "in":
        return Verdict("tp", "medium", "cna/range-includes-installed", f"the CNA's affected range includes {inst} ({desc}); {where}, and the CNA product must be this package's upstream{hint}", f,
                       [f"Is the vulnerable code present in {row['name']} {inst}? Only the CNA range says so."])
    if rel == "below":
        return Verdict("fp", "medium", "cna/introduced-after-installed", f"the CNA's affected range starts after {inst} ({desc}); {where}{hint}", f,
                       [f"Is the CNA's lower bound the version that introduced the bug?"])
    if rel == "above":
        return Verdict("fp", "medium", "cna/installed-past-range", f"{inst} is past every CNA affected range ({desc}); {where}{hint}", f)
    return Verdict("unclear", "low", "cna/no-range", f"the CNA gives no usable version range and {where}; nobody has assessed it{hint}", f,
                   [f"Which versions of {row['name']} does {cve} affect? Check the fix commit against {inst}."])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default=os.environ.get("YARDSTICK_ROOT") or ".", help="the workspace yardstick runs in, containing .yardstick/ (default: $YARDSTICK_ROOT, else cwd)")
    ap.add_argument("--name", help="run name the gate was scanned under (default: $YARDSTICK_NAME, else default)")
    ap.add_argument("--side", choices=["cand", "ref", "both"], default="both")
    ap.add_argument("--model", default=os.environ.get("CLAUDE_MODEL") or os.environ.get("YARDSTICK_MODEL") or "unknown", help="model id recorded as the proposals' author")
    ap.add_argument("--out", help="output directory (default: <store>/.yardstick/triage/<run>/<gate>)")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--euvd", action="store_true", default=None, help="also consult EUVD (ENISA), provisional; or set YARDSTICK_SKILLS_EUVD=1")
    ap.add_argument("--validate", action="store_true", help="run the rules on rows that already have a tp/fp label and report agreement per rule (prior-label hints off)")
    ap.add_argument("--gate", help="gate (name or file) whose scans to read instead of $YARDSTICK_GATE or the gate scanned last")
    args = ap.parse_args()

    global EUVD
    EUVD = yardstick_euvd.enabled(args.euvd)
    store = Path(args.store).resolve()
    ys = dc.find_yardstick(store)
    set_policy(dc.load_policy(ys, store))
    name = dc.run_name(args.name)
    _, run = dc.load_run(store, name, args.gate)
    report = dc.score(ys, store, name, run)
    run_id = report["name"]
    out = Path(args.out) if args.out else store / ".yardstick" / "triage" / name / run_id
    out.mkdir(parents=True, exist_ok=True)

    prior_by_pkg: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    prior_by_vuln: dict[str, list[str]] = collections.defaultdict(list)
    for c in dc.load_labels(ys, store):
        lb = c["label"]
        if not lb.get("package"):
            continue
        p = dc.parse_purl(lb["package"])
        prior_by_pkg[p["name"]][lb["verdict"]] += 1
        prior_by_vuln[lb["vulnerability"]].append(f"{lb['verdict']} on {p['name']}@{p['version']}")

    sbom_by_subject = {s["name"]: s["path"] for s in run.get("subjects", []) if s.get("path")}

    rows = []
    for subj in report["subjects"]:
        sbom_path = sbom_by_subject.get(subj["name"])
        files_by_pkg = dc.sbom_files(sbom_path) if sbom_path else {}
        programs_by_src = dc.sbom_programs(sbom_path) if sbom_path else {}
        for r in subj["matches"]:
            if args.validate:
                if r.get("verdict") not in ("tp", "fp"):
                    continue
            elif r.get("verdict") or r["inCandidate"] == r["inReference"]:
                continue
            side = "candidate" if r["inCandidate"] else "reference"
            if args.side == "cand" and side != "candidate" or args.side == "ref" and side != "reference":
                continue
            p = dc.parse_purl(r["package"])
            d = r.get(side) or {}
            distro = (d.get("distro") or "").split(" ", 1)
            rows.append({
                "row_id": r["row"], "vulnerability": r["vulnerability"], "aliases": r.get("aliases", []),
                "package": r["package"], "name": p["name"], "version": p["version"],
                "within": subj["name"], "side": side,
                "source_pkg": r.get("sourcePackage") or (d.get("upstreams") or [p["name"]])[0],
                "namespace": d.get("namespace"), "distro_type": distro[0] if d.get("distro") else None,
                "distro_version": distro[1] if len(distro) > 1 else None,
                "fix_state": d.get("fixState"), "fix_versions": d.get("fixVersions"), "constraints": d.get("constraints"),
                "match_types": d.get("matchTypes") or [],
                "locations": [r["location"]] if r.get("location") else [],
                "db_status": {k: r[k + "Status"] for k in ("candidate", "reference") if r.get(k + "Status")},
                "severity": d.get("severity"), "data_source": d.get("dataSource"),
                "nvd_description": None,  # filled from the CNA record in enrich: yardstick's rows carry no description
                "prior_claims_on_package": {} if args.validate else dict(prior_by_pkg.get(p["name"], {})),
                "prior_claims_on_vuln": [] if args.validate else prior_by_vuln.get(r["vulnerability"], []),
                "label": r.get("verdict") if args.validate else None,
                "files": files_by_pkg.get((p["name"], p["version"]), []),
                # programs that packages built from the same source install: "nsenter" -> ["util-linux"]
                "sibling_programs": {b: sorted(o) for b, o in programs_by_src.get(r.get("sourcePackage") or (d.get("upstreams") or [p["name"]])[0], {}).items()},
            })

    def enrich(row: dict) -> dict:
        cve = next((a for a in [row["vulnerability"], *row["aliases"]] if a.startswith("CVE-")), None)
        cna = dc.cve_org(cve) if cve else None
        row["cna_state"] = (cna or {}).get("cveMetadata", {}).get("state")
        if not row["nvd_description"]:  # NVD copies the CNA's English description
            row["nvd_description"] = next((d.get("value") for d in (cna or {}).get("containers", {}).get("cna", {}).get("descriptions") or []
                                           if (d.get("lang") or "en").startswith("en")), None)
        row["cna_affected"] = dc.cna_affected_summary(cna, bounded_only=True)
        row["euvd"] = {"url": yardstick_euvd.url(cve), "aliases": yardstick_euvd.aliases(cve), "products": yardstick_euvd.products(cve)} if (EUVD and cve) else None
        prior = row["prior_claims_on_package"]
        hint = ""
        if sum(prior.values()) >= 5:
            top, n = max(prior.items(), key=lambda kv: kv[1])
            if n / sum(prior.values()) >= 0.8:
                hint = f"; note {n} of {sum(prior.values())} prior labels on this package are {top}"
        v = suggest(row, cna, hint)
        if EUVD and cve and (ef := yardstick_euvd.fact(cve)):
            v.facts.append(ef)
        row["suggestion"] = {"verdict": v.verdict, "confidence": v.confidence, "rule": v.rule, "decision": v.decision,
                             "why": v.why, "note": v.note, "facts": v.facts, "openQuestions": v.questions}
        if cve and row["distro_type"] == "ubuntu":
            rec = dc.ubuntu_cve(cve) or {}
            codename = dc.ubuntu_codename(row["distro_version"] or "")
            st = dc.ubuntu_statuses(rec, row["source_pkg"], codename or "")
            row["tracker"] = {"codename": codename, "release": st.get("release"), "upstream": st.get("upstream"),
                              "priority": rec.get("priority"), "notices": rec.get("notices_ids", []),
                              "notes": [f"{n.get('author') or '?'}: {n['note']}" for n in rec.get("notes", [])]}
        if cve and row["distro_type"] in ("redhat", "rhel", "centos"):
            major = (row["distro_version"] or "").split(".")[0]
            bs = yardstick_redhat.binary_status(yardstick_redhat.vex(cve), major, row["name"], row["version"], row["source_pkg"])
            hs = yardstick_redhat.hydra_state(yardstick_redhat.hydra(cve), major, row["source_pkg"]) or {}
            row["tracker"] = {"redhat": {"status": bs["status"], "flags": bs["flags"], "fix": bs["applicable_fix"], "comparison": bs["comparison"],
                                         "streams": sorted({f[0] for f in bs["fixed"] if f[0]}), "hydra": hs.get("fix_state"), "statement": (hs.get("statement") or "")[:300]}}
        links = [u for u in [f"https://ubuntu.com/security/{cve}" if row["distro_type"] == "ubuntu" and cve else None,
                             f"https://access.redhat.com/security/cve/{cve}" if row["distro_type"] in ("redhat", "rhel", "centos") and cve else None,
                             f"https://security-tracker.debian.org/tracker/{cve}" if row["distro_type"] == "debian" and cve else None,
                             row.get("data_source"), f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None] if u]
        row["links"] = list(dict.fromkeys(links))
        return row

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        rows = list(ex.map(enrich, rows))
    rows.sort(key=lambda r: (r["side"], r["vulnerability"], r["source_pkg"], r["name"]))
    for r in rows:
        r["files"] = len(r.get("files") or [])

    if args.validate:
        out.mkdir(parents=True, exist_ok=True)
        (out / "validate.json").write_text(json.dumps(rows, indent=1))
        tally = collections.defaultdict(collections.Counter)
        for r in rows:
            sg = r["suggestion"]
            outcome = "agree" if sg["verdict"] == r["label"] else "unclear" if sg["verdict"] == "unclear" else "DISAGREE"
            tally[(sg["rule"], sg["verdict"], sg["confidence"])][outcome] += 1
        print(f"validation against {len(rows)} labeled rows in gate {run_id}")
        print(f"{'rule':48} {'suggests':8} {'conf':7} {'agree':>6} {'unclear':>8} {'disagree':>9}")
        for k in sorted(tally, key=lambda k: -sum(tally[k].values())):
            t = tally[k]
            print(f"{k[0]:48} {k[1]:8} {k[2]:7} {t['agree']:6} {t['unclear']:8} {t['DISAGREE']:9}")
        bad = [r for r in rows if r["suggestion"]["verdict"] not in ("unclear", r["label"])]
        if bad:
            print(f"\ndisagreements ({len(bad)}), label vs suggestion:")
            for r in bad[:40]:
                print(f"  {r['label']:3} vs {r['suggestion']['verdict']:3} {r['suggestion']['rule']:40} {r['vulnerability']} {r['name']}@{r['version']}: {r['suggestion']['note'][:140]}")
        print(f"details: {out / 'validate.json'}")
        return

    groups: dict[tuple, list[dict]] = collections.OrderedDict()
    for r in rows:
        groups.setdefault((r["side"], r["vulnerability"], r["source_pkg"]), []).append(r)
    for n, rs in enumerate(groups.values(), 1):
        for r in rs:
            r["group"] = n

    (out / "evidence.json").write_text(json.dumps({"gate": run_id, "name": name, "store": str(store), "rows": rows}, indent=1))
    (out / "groups.json").write_text(json.dumps({str(n): [r["row_id"] for r in rs] for n, rs in enumerate(groups.values(), 1)}, indent=1))

    md = [f"# Triage evidence for gate {run_id}", "",
          f"{len(rows)} unlabeled differences in {len(groups)} groups (one group = one vulnerability on one source package).",
          "Confidence: high = a primary fact; medium = inferred; low = unassessed, proposed as unclear. Rules and ceilings: `yardstick claims policy`.", ""]
    for n, ((side, vuln, src), rs) in enumerate(groups.items(), 1):
        r0, s, t = rs[0], rs[0]["suggestion"], rs[0].get("tracker") or {}
        found = "new in candidate" if side == "candidate" else "dropped by candidate (reference only)"
        md.append(f"## {n}. {vuln} on {src} — {found}")
        md.append(f"- suggest **{s['verdict']}** ({s['confidence']}, rule `{s['rule']}`, {s.get('decision', '?')}): {s['note']}")
        pkgs = ", ".join(r["name"] + "@" + r["version"] for r in rs)
        md.append(f"- packages: {pkgs}")
        md.append(f"- grype: fix {r0.get('fix_state')} {r0.get('fix_versions') or ''}, constraints {r0.get('constraints')}, severity {r0.get('severity')}, namespace {r0.get('namespace')}")
        if t.get("redhat"):
            rh = t["redhat"]
            md.append(f"- red hat: VEX {rh['status']}{' ' + str(rh['flags']) if rh['flags'] else ''}; fix {rh['fix']}; streams {rh['streams']}; hydra {rh['hydra']}; statement: {rh['statement']}")
        elif t:
            rel = "; ".join(f"{x['pocket']}: {x['status']}{' (' + x['description'] + ')' if x['description'] else ''}" for x in t.get("release") or []) or "no entry"
            up = t.get("upstream") or {}
            md.append(f"- ubuntu {t.get('codename')}: {rel}; upstream: {up.get('status')}{' (' + up['description'] + ')' if up.get('description') else ''}; priority {t.get('priority')}; notices {t.get('notices')}")
            for note in t.get("notes", [])[:4]:
                md.append(f"  - note: {note[:300].replace(chr(10), ' ')}")
        if r0.get("cna_affected"):
            md.append(f"- CNA affected: {'; '.join(r0['cna_affected'])[:300]}")
        if r0.get("github_advisory"):
            ga = r0["github_advisory"]
            md.append(f"- GitHub advisory: {ga['ranges'] or 'no version range'}; installed upstream is {ga['relation'] or 'not placed'}"
                      f"{'; names ' + ', '.join(ga['components'][:3]) if ga['components'] else ''}; {' '.join(ga['urls'][:2])}")
        if r0.get("nvd_description"):
            md.append(f"- NVD: {r0['nvd_description'][:400]}")
        if r0["prior_claims_on_package"]:
            md.append(f"- prior labels on {r0['name']}: {r0['prior_claims_on_package']}")
        if r0["prior_claims_on_vuln"]:
            md.append(f"- prior labels on {vuln}: {', '.join(r0['prior_claims_on_vuln'][:6])}")
        if s["openQuestions"]:
            md.append(f"- open: {' '.join(s['openQuestions'])}")
        md.append(f"- rows: {' '.join(r['row_id'] for r in rs)}")
        md.append(f"- links: {' '.join(r0['links'])}")
        md.append("")
    (out / "evidence.md").write_text("\n".join(md))

    props = []
    for r in rows:
        s = r["suggestion"]
        p = {"row": r["row_id"], "verdict": s["verdict"], "confidence": s["confidence"], "note": s["note"],
             "author": {"skill": SKILL, "model": args.model}}
        if s.get("why"):
            p["justification"] = s["why"]["kind"]
        if ev := evidence(s["rule"], s["facts"], (s.get("why") or {}).get("text", "")):
            p["evidence"] = ev
        if s["openQuestions"]:
            p["openQuestions"] = s["openQuestions"]
        props.append(p)
    (out / "proposals.jsonl").write_text("".join(json.dumps(p) + "\n" for p in props))
    write_proposals_md(out, rows, groups)
    n_causes = write_causes(out, rows, {p["row"]: p for p in props}, args.model)

    gsum = collections.Counter((rs[0]["side"], rs[0]["suggestion"]["verdict"], rs[0]["suggestion"]["confidence"]) for rs in groups.values())
    rsum = collections.Counter((r["side"], r["suggestion"]["verdict"], r["suggestion"]["confidence"]) for r in rows)
    print(f"gate {run_id}: {len(rows)} unlabeled deltas, {len(groups)} groups -> {out}")
    print(f"{'side':10} {'verdict':8} {'conf':7} {'groups':>6} {'rows':>6}")
    for k in sorted(gsum):
        print(f"{k[0]:10} {k[1]:8} {k[2]:7} {gsum[k]:6} {rsum[k]:6}")
    print(f"{n_causes} package-level causes drafted in causes.jsonl (one per source package, rule and verdict spanning several findings)")
    print(f"next: review evidence.md, adjust with yardstick-triage-edit.py, then (in {store}) `yardstick claims agent propose {out / 'proposals.jsonl'} --name {name} --gate {run_id}` and `yardstick claims agent propose-cause {out / 'causes.jsonl'} --name {name} --gate {run_id}`")


VERSION_INFERRED_TP = {"ubuntu/unassessed-upstream-fix-newer-than-installed", "ubuntu/unassessed-cna-range-includes-installed", "debian/affected-unfixed"}


def version_gap(installed: str, fix: str) -> tuple[int, int, int]:
    """How far the fix is past the installed upstream version, by leading numeric component (major, minor, patch)."""
    a = [int(x) for x in re.findall(r"\d+", installed)[:3]] + [0, 0, 0]
    b = [int(x) for x in re.findall(r"\d+", fix)[:3]] + [0, 0, 0]
    return (b[0] - a[0], b[1] - a[1], b[2] - a[2])


def research_first(items: list[tuple[int, list[dict], list[dict]]]) -> list[str]:
    """The medium groups whose tp rests only on version inference, widest gap between the installed upstream
    version and the fix first: the wider the gap, the likelier the bug was introduced after the installed
    version, which nothing in the tracker says (review item 7)."""
    ranked = []
    for n, rs, ps in items:
        if ps[0].get("verdict") != "tp" or rule_of(ps[0]) not in VERSION_INFERRED_TP:
            continue
        r0 = rs[0]
        inst_up = dc.deb_upstream(r0["version"])
        fixv = parse_fix_version(((r0.get("tracker") or {}).get("upstream") or {}).get("description") or "")
        fix_up = dc.deb_upstream(fixv) if fixv else None
        ranked.append((version_gap(inst_up, fix_up) if fix_up else (0, 0, 0), -n, inst_up, fix_up, r0))
    if not ranked:
        return []
    ranked.sort(reverse=True)
    md = ["Research first: tp inferred from versions alone, widest gap between installed and fix first. A lower bound",
          "(the GitHub advisory, the CNA's versions, a distro CNA's unaffected older releases, the feature the description names) flips these:", ""]
    for gap, neg_n, inst_up, fix_up, r0 in ranked[:15]:
        ga = r0.get("github_advisory") or {}
        extra = f"; GitHub advisory {ga['ranges']}" if ga.get("ranges") else ""
        if ga.get("components"):
            extra += f", names {', '.join(ga['components'][:2])}"
        md.append(f"- {-neg_n}. {r0['vulnerability']} on {r0['source_pkg']}: {inst_up} → {fix_up or 'fix version unknown'}{extra}")
    return md + [""]


def write_causes(out: Path, rows: list[dict], props: dict[str, dict], model: str) -> int:
    """One cause per (subject, side, source package, rule, verdict, confidence) that spans several findings.
    Members are explicit row ids; the id is stable so a rerun supersedes rather than duplicates. The title
    starts with the rule's `title` from the policy, else its basis."""
    buckets: dict[tuple, list[dict]] = collections.OrderedDict()
    for r in rows:
        p = props.get(r["row_id"])
        if not p:
            continue
        rule = rule_of(p)
        if not p.get("evidence") and p["verdict"] == r["suggestion"]["verdict"]:
            rule = r["suggestion"]["rule"]  # a rule nothing was observed for has no evidence entry to sit in
        # members share a justification too: a cause states one truth about the code
        buckets.setdefault((r["within"], r["side"], r["source_pkg"], rule, p["verdict"], p.get("confidence", ""), p.get("justification", "")), []).append((r, p))
    causes = []
    for (within, side, src, rule, verdict, conf, why), members in buckets.items():
        vulns = {r["vulnerability"] for r, _ in members}
        if len(vulns) < 2 and len(members) < 3:
            continue
        facts, seen = [], set()
        for _, p in members:
            for f in (p.get("evidence") or [{}])[0].get("facts", []):
                k = (f["source"], json.dumps(f["about"], sort_keys=True), f["field"])
                if k not in seen:
                    seen.add(k)
                    facts.append(f)
        notes = collections.Counter(p["note"] for _, p in members)
        common, n = notes.most_common(1)[0]
        pkgs = sorted({r["name"] for r, _ in members})
        pr = POLICY.get(rule) or {}
        # the rule's own justification keeps the id it always had, so reruns still supersede
        slug = re.sub(r"[^a-z0-9]+", "-", (f"{src}-{rule}-{verdict}-{conf}-{side}" + (f"-{why}" if why and why != pr.get("justification") else "")).lower()).strip("-")
        title = (pr.get("title") or pr.get("basis") or rule or "reviewer judgement") + f": {len(vulns)} {'vulnerability' if len(vulns) == 1 else 'vulnerabilities'} on {src}"
        note = (f"{len(members)} findings ({len(vulns)} vulnerabilities across {', '.join(pkgs[:6])}{'…' if len(pkgs) > 6 else ''}) share rule {rule or 'judgement'}: "
                f"{common}" + (f" ({n} of {len(members)} members carry this exact note; the rest differ only in versions)" if n < len(members) else ""))
        c = {"id": f"cause-{slug}", "title": title[:200], "note": note, "sourcePackage": src,
             "direction": "added" if side == "candidate" else "dropped",
             "rows": [r["row_id"] for r, _ in members], "verdict": verdict,
             "author": {"skill": SKILL, "model": model}}
        if ev := evidence(rule, facts):
            c["evidence"] = ev
        if conf:
            c["confidence"] = conf
        if why:
            c["justification"] = why  # every member's truth about the code; the specifics stay per row
        # the subject is filled in by propose-cause from the rows, since a bucket is within one subject
        qs = [q for _, p in members for q in p.get("openQuestions", [])]
        if verdict == "unclear" and qs:
            c["openQuestions"] = list(dict.fromkeys(qs))[:3]
        causes.append(c)
    (out / "causes.jsonl").write_text("".join(json.dumps(c) + "\n" for c in causes))
    return len(causes)


def write_proposals_md(out: Path, rows: list[dict], groups: dict) -> None:
    """Numbered by group in three confidence sections. Rewritten by yardstick-triage-edit.py after edits."""
    props = {}
    for line in (out / "proposals.jsonl").read_text().splitlines():
        if line.strip():
            p = json.loads(line)
            props[p["row"]] = p
    md = ["# Proposed labels", "", f"{len(props)} proposals in {len(groups)} groups. Record them, in the workspace, with:", "",
          "```", f"yardstick claims agent propose {out / 'proposals.jsonl'} --gate <gate>", "```", ""]
    sections = [("high", "## Ready (the tracker states it)"), ("medium", "## Look before accepting (inferred from versions or prior labels)"),
                ("low", "## Nobody has assessed these (proposed as unclear; candidates for /yardstick:research-vuln)")]
    for conf, title in sections:
        items = []
        for n, rs in enumerate(groups.values(), 1):
            ps = [props[r["row_id"]] for r in rs if r["row_id"] in props]
            if ps and ps[0].get("confidence") == conf:
                items.append((n, rs, ps))
        if not items:
            continue
        md += [title, "", f"Groups: {' '.join(str(n) for n, _, _ in items)}", ""]
        if conf == "medium":
            md += research_first(items)
        for n, rs, ps in items:
            p0, r0 = ps[0], rs[0]
            found = "new in candidate" if r0["side"] == "candidate" else "dropped by candidate"
            md.append(f"{n}. **{p0['verdict']}** {r0['vulnerability']} on {r0['source_pkg']} ({found}) `{rule_of(p0) or r0['suggestion']['rule']}`: {p0.get('note', '')}")
            md.append("   - " + ", ".join(f"{r['name']}@{r['version']}" for r in rs))
            md.append("   - " + " ".join(r0.get("links", [])))
        md.append("")
    (out / "proposals.md").write_text("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
