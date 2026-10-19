#!/usr/bin/env python3
"""Collect everything the public record says about one vulnerability on one package, for /yardstick:research-vuln.

    yardstick-vuln-sources.py <VULN-ID | row:<row id>> [--pkg NAME] [--store DIR] [--name RUN] [--gate NAME] [--out DIR] [--model ID]

Writes one file per source under <out> (default <store>/.yardstick/research/<VULN>/<pkg>/) plus SUMMARY.md,
which lists what was found, the key facts, and a link for every source, and proposal.json: a
`yardstick claims agent propose` skeleton (row, author, the facts it observed) with verdict, justification,
confidence, note, the evidence's interpretation and openQuestions left for you. Nothing here decides a
verdict; read SUMMARY.md and the files, reason, fill proposal.json, then, in the workspace,
`jq -c . proposal.json | yardstick claims agent propose --gate <gate>`.

Sources: the gate's scored rows (both grype outputs, both cached DBs, existing labels), cve.org (CNA record),
NVD, OSV (the CVE, Ubuntu's and Debian's records), GitHub advisories, Ubuntu's tracker (JSON + raw
ubuntu-cve-tracker file + USNs + changelogs + Launchpad publishing history + debian/patches on the
security branch), Debian's tracker page and changelog.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yardstick_common as dc  # noqa: E402
import yardstick_euvd  # noqa: E402  (optional source; see its docstring)
import yardstick_redhat  # noqa: E402


def safe_part(s) -> str:
    """One path component from external data (a vuln id, a Go module name with '/', a version): anything
    outside [A-Za-z0-9._+-] becomes '_', and '.' or '..' is refused."""
    s = re.sub(r"[^A-Za-z0-9._+-]", "_", str(s))
    if s in ("", ".", ".."):
        raise ValueError(f"unsafe path component {s!r}")
    return s


def save(out: Path, name: str, body) -> Path | None:
    if body is None:
        return None
    p = (out / safe_part(name)).resolve()
    if not p.is_relative_to(out.resolve()):
        raise ValueError(f"{p} is outside {out}")
    p.write_text(body if isinstance(body, str) else json.dumps(body, indent=1))
    return p


def debian_tracker_table(page: bytes) -> list[list[str]]:
    rows = []
    for r in re.findall(rb"<tr>(.*?)</tr>", page, re.S):
        cells = [html.unescape(re.sub(r"<[^>]+>", "", c.decode(errors="replace"))).strip() for c in re.findall(rb"<t[dh][^>]*>(.*?)</t[dh]>", r, re.S)]
        if cells:
            rows.append(cells)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("vuln")
    ap.add_argument("--pkg", help="package name (binary or source) to focus on; default: every package the assay pairs with the vuln")
    ap.add_argument("--store", default=os.environ.get("YARDSTICK_ROOT") or ".", help="the workspace yardstick runs in, containing .yardstick/ (default: $YARDSTICK_ROOT, else cwd)")
    ap.add_argument("--name", help="run name the gate was scanned under (default: $YARDSTICK_NAME, else default)")
    ap.add_argument("--out")
    ap.add_argument("--model", default=os.environ.get("CLAUDE_MODEL") or os.environ.get("YARDSTICK_MODEL") or "unknown", help="model id recorded as the proposal's author")
    ap.add_argument("--euvd", action="store_true", default=None, help="also consult EUVD (ENISA), provisional; or set YARDSTICK_SKILLS_EUVD=1")
    ap.add_argument("--gate", help="gate (name or file) whose scans to read instead of $YARDSTICK_GATE or the gate scanned last")
    args = ap.parse_args()

    store = Path(args.store).resolve()
    ys = dc.find_yardstick(store)
    name = dc.run_name(args.name)
    report, run = None, {}
    try:
        _, run = dc.load_run(store, name, args.gate)
        report = dc.score(ys, store, name, run)
    except (Exception, SystemExit) as e:  # no workspace or no scans: still useful for pure research
        report_error = str(e)

    vuln = args.vuln.strip()
    row_id = None
    if vuln.startswith("row:"):
        row_id = vuln[4:]
        hit = next((m for _, m in dc.matches(report or {}) if m["row"] == row_id), None)
        if not hit:
            sys.exit(f"no row {row_id} in gate {report and report.get('name')}'s scans under run {name}")
        vuln = hit["vulnerability"]
        args.pkg = args.pkg or dc.parse_purl(hit["package"])["name"]
    out = Path(args.out) if args.out else store / ".yardstick" / "research" / safe_part(vuln) / safe_part(args.pkg or "all")
    out.mkdir(parents=True, exist_ok=True)
    S: list[str] = [f"# Sources for {vuln}" + (f" on {args.pkg}" if args.pkg else ""), ""]
    links: list[str] = []
    facts: list[dict] = []

    # ---- the gate: what grype saw on each side, and what each DB holds ----
    rows, installed, source_pkg, distro, dbs = [], None, None, None, {}
    if not report:
        S.append(f"_No scored gate in {store}: {report_error}_")
    if report:
        setups = run.get("setups") or {}
        dbs = {s: dc.side_grype_and_db(setups[s]) for s in ("candidate", "reference") if s in setups}
        S.append(f"## Gate {report['name']} (run {name})")
        for s in ("candidate", "reference"):
            if s in setups:
                S.append(f"- {s}: grype {setups[s]['grype']['spec']['version']} + {setups[s]['db'].get('source')}")
        for subj in report["subjects"]:
            ref = subj["name"]
            for r in subj["matches"]:
                if vuln != r["vulnerability"] and vuln not in r.get("aliases", []):
                    continue
                p = dc.parse_purl(r["package"])
                if args.pkg and args.pkg not in (p["name"], p["qualifiers"].get("upstream"), r.get("sourcePackage")):
                    continue
                rows.append(r)
                installed = installed or p["version"]
                source_pkg = source_pkg or r.get("sourcePackage")
                lb = r.get("label") or {}
                S.append(f"- row {r['row']}: {r['vulnerability']} on {p['name']}@{p['version']} in {ref[:60]}… candidate={r['inCandidate']} reference={r['inReference']} verdict={r.get('verdict') or 'unlabeled'}{' label ' + lb.get('file', '') if lb else ''}")
                for side in ("candidate", "reference"):
                    d = r.get(side)
                    if d:
                        if not distro and d.get("distro"):
                            t, _, v = d["distro"].partition(" ")
                            distro = {"type": t, "version": v}
                        save(out, f"row-{side}-{p['name']}.json", d)
                        S.append(f"  - {side}: fix {d.get('fixState')} {d.get('fixVersions') or ''}, constraints {d.get('constraints')}, namespace {d.get('namespace')}, severity {d.get('severity')}, dataSource {d.get('dataSource')}")
                    else:
                        S.append(f"  - {side}: no match")
        if not rows:
            S.append(f"- the gate's last scans have no row for {vuln}" + (f" on {args.pkg}" if args.pkg else ""))
        for side, (grype, cd) in dbs.items():
            distro_arg = f"{distro['type']}@{distro['version']}" if distro else None
            recs = dc.grype_db_search(cd, vuln, distro=distro_arg, grype=grype)
            save(out, f"db-{side}.json", recs)
            pk = [((p.get("package") or {}).get("name"), p.get("namespace"), (p.get("detail") or {}).get("ranges")) for v in recs for p in v.get("packages", []) or []
                  if not (source_pkg or args.pkg) or (p.get("package") or {}).get("name") in (source_pkg, args.pkg)]
            S.append(f"- {side} DB ({distro_arg or 'all distros'}): {len(recs)} record(s) for the vuln; this package: {json.dumps(pk)[:500] if pk else 'absent'}")
        S.append("")

    try:
        all_labels = [dict(c["label"], source=c["source"], file=c["file"]) for c in dc.load_labels(ys, store)]
    except Exception:  # no workspace: no labels
        all_labels = []
    vuln_ids = {vuln, *(a for r in rows for a in r.get("aliases", []))}
    on_vuln = [c for c in all_labels if c["vulnerability"] in vuln_ids]
    on_pkg = [c for c in all_labels if args.pkg and dc.parse_purl(c.get("package") or "")["name"] == args.pkg and c not in on_vuln]
    def notes(c):
        # a label's notes, oldest first, as one line
        return "; ".join(n.get("text", "") for n in c.get("notes") or [])

    if on_vuln or on_pkg:
        save(out, "labels.json", {"on_vuln": on_vuln, "on_pkg": on_pkg})
        S.append("## Existing labels")
        for c in sorted(on_vuln, key=lambda c: c.get("lastUpdated", "")):
            p = dc.parse_purl(c.get("package") or "")
            S.append(f"- {c.get('lastUpdated', '')[:10]} {c['verdict']}{' (' + c['justification'] + ')' if c.get('justification') else ''} {c['vulnerability']} on {p['name']}@{p['version']} by {c.get('author')} ({c['file']}): {notes(c)[:200] or 'no note'}")
        if on_pkg:
            import collections
            counts = collections.Counter(c["verdict"] for c in on_pkg)
            S.append(f"- other labels on {args.pkg}: {dict(counts)}; most recent with notes:")
            for c in sorted((c for c in on_pkg if c.get("notes")), key=lambda c: c.get("lastUpdated", ""), reverse=True)[:3]:
                S.append(f"  - {c['verdict']} {c['vulnerability']}: {notes(c)[:200]}")
        S.append("")

    pkg_names = {args.pkg} if args.pkg else set()
    if source_pkg:
        pkg_names.add(source_pkg)
    for r in rows:
        pkg_names.add(dc.parse_purl(r["package"])["name"])
    src = source_pkg or args.pkg

    # ---- the CVE itself ----
    cve = vuln if vuln.startswith("CVE-") else next((a for r in rows for a in r.get("aliases", []) if a.startswith("CVE-")), None)
    ghsas = []
    if cve:
        cna = dc.cve_org(cve)
        save(out, "cve-org.json", cna)
        S.append("## CVE record (cve.org)")
        links.append(f"https://www.cve.org/CVERecord?id={cve}")
        if cna:
            facts.append(dc.cna_fact(cve, cna))
            meta, c = cna.get("cveMetadata", {}), cna.get("containers", {}).get("cna", {})
            S.append(f"- state {meta.get('state')}, published {meta.get('datePublished')}, updated {meta.get('dateUpdated')}, assigner {meta.get('assignerShortName')}")
            S.append(f"- affected: {'; '.join(dc.cna_affected_summary(cna))[:600]}")
            if installed:
                inst_up = dc.deb_upstream(installed)
                S.append(f"- CNA bounded range includes the image's upstream version {inst_up}: {dc.version_in_cna_range(cna, inst_up)} (only meaningful when the CNA product is this package's upstream)")
            for d in c.get("descriptions", [])[:1]:
                S.append(f"- description: {d.get('value', '')[:700]}")
            refs = [r.get("url") for r in c.get("references", []) if r.get("url")]
            S.append(f"- references: {' '.join(refs[:12])}")
            links += refs[:12]
        else:
            S.append("- not found at cve.org")
        nvd = dc.nvd_cve(cve)
        save(out, "nvd.json", nvd)
        links.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        if nvd:
            S.append(f"- NVD: published {nvd.get('published')}, last modified {nvd.get('lastModified')}, status {nvd.get('vulnStatus')}")
            cpes = []
            for conf in nvd.get("configurations", []):
                for node in conf.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        if m.get("vulnerable"):
                            lo = m.get("versionStartIncluding", "")
                            hi = m.get("versionEndExcluding") or m.get("versionEndIncluding", "")
                            cpes.append(f"{m.get('criteria')} [{lo}, {hi}]")
            if cpes:
                S.append(f"- NVD CPE ranges: {'; '.join(cpes)[:600]}")
        ghsas = dc.ghsa_for_cve(cve, cna)  # global database first, then the project's own repository advisories
        save(out, "ghsa.json", ghsas)
        for g in ghsas:
            where = f"repository advisory in {g['repository']}" if g.get("repository") else "global advisory database"
            S.append(f"- GHSA {g['ghsa_id']} ({where}): {g.get('summary')} — {g.get('html_url')}")
            links.append(g.get("html_url"))
        for e in dc.advisory_ranges(ghsas):
            placed = ""
            if installed and e["bounds"]:
                inst_up = dc.deb_upstream(installed)
                rel = dc._range_relation([e["bounds"]], inst_up)
                placed = f"; installed upstream {inst_up} is {'BELOW the lower bound (introduced later?)' if rel == 'below' and e['bounds'][0] not in ('0', '0.0') else rel}"
            S.append(f"  - {e['ghsa_id']} {e['package'] or '?'}: affected {e['range'] or '(no range given)'}{'; patched ' + e['patched'] if e['patched'] else ''}{placed}")
        comps = dc.advisory_components(ghsas)
        if comps:
            S.append(f"  - the advisory names {', '.join(comps[:4])}: check that file at the installed upstream tag (raw.githubusercontent.com/<org>/<repo>/<tag>/<path>)")
        facts += dc.advisory_facts(cve, ghsas)
        S.append("")

    # ---- ecosystem advisory (GHSA via OSV), for non-distro packages ----
    purl = dc.parse_purl(rows[0]["package"]) if rows else {"type": "", "ns": "", "name": args.pkg or "", "version": ""}
    eco = dc.OSV_ECOSYSTEM.get(purl["type"])
    if eco:
        name = dc.osv_package_name(purl)
        ids = [vuln, *[a for r in rows for a in r.get("aliases", [])]]
        ghsa_id = next((i for i in ids if i.startswith("GHSA-")), None)
        S.append(f"## Ecosystem advisory ({eco} {name})")
        pkg_vulns = dc.osv_query(name, eco)
        hits = [v for v in pkg_vulns if set(ids) & set([v["id"], *v.get("aliases", [])])]
        save(out, "osv-package-advisories.json", hits)
        if not hits:
            S.append(f"- no OSV advisory for {eco} {name} matches {', '.join(ids)}; {len(pkg_vulns)} advisories exist for the package")
        for v in hits:
            ds = v.get("database_specific", {})
            S.append(f"- {v['id']} (aliases {v.get('aliases')}): github_reviewed={ds.get('github_reviewed')} reviewed_at={ds.get('github_reviewed_at')} withdrawn={v.get('withdrawn')} published={v.get('published')} modified={v.get('modified')} — https://osv.dev/vulnerability/{v['id']}")
            facts.append(dc.fact("osv", {"vulnerability": v["id"]}, "github_reviewed", str(bool(ds.get("github_reviewed"))), f"https://osv.dev/vulnerability/{v['id']}"))
            for a in v.get("affected", []):
                pk = a.get("package") or {}
                if pk.get("name", "").lower() != name.lower():
                    continue
                st, fx, how = dc.osv_range_status_for(a, purl["version"], eco)
                S.append(f"  - affected entry: ranges {json.dumps(a.get('ranges'))}; {len(a.get('versions') or [])} versions listed; installed {purl['version']} is {st} ({how}) using {dc.compare_for(eco).__name__}")
                facts.append(dc.fact("osv", {"vulnerability": v["id"], "package": name, "ecosystem": eco}, "fixed", fx or "", f"https://osv.dev/vulnerability/{v['id']}"))
            for r in v.get("references", [])[:8]:
                S.append(f"  - ref: {r.get('type')} {r.get('url')}")
                links.append(r.get("url"))
        if ghsa_id:
            links.append(f"https://github.com/advisories/{ghsa_id}")
        if purl["type"] == "maven":
            links.append(f"https://central.sonatype.com/artifact/{purl['ns']}/{purl['name']}/{purl['version']}")
            links.append(f"https://mvnrepository.com/artifact/{purl['ns']}/{purl['name']}")
        elif purl["type"] == "pypi":
            links.append(f"https://pypi.org/project/{purl['name']}/{purl['version']}/")
        elif purl["type"] == "npm":
            links.append(f"https://www.npmjs.com/package/{name}/v/{purl['version']}")
        elif purl["type"] == "golang":
            links.append(f"https://pkg.go.dev/{name}@{purl['version']}")
        if rows and "cpe-match" in ((rows[0].get("candidate") or rows[0].get("reference") or {}).get("matchTypes") or []):
            S.append(f"- matched by CPE: the NVD CPE product is paired with the package name; an ecosystem advisory that does not list {name} means a likely name collision (policy P-9)")
        S.append("")

    if cve and yardstick_euvd.enabled(args.euvd):
        er = yardstick_euvd.record(cve)
        save(out, "euvd.json", er)
        S.append("## EUVD (ENISA), provisional source")
        if er:
            S.append(f"- {er['id']}: aliases {yardstick_euvd.aliases(cve)}; assigner {er.get('assigner')}; updated {er.get('dateUpdated')}; exploited since {er.get('exploitedSince')} (risk, not truth) — {yardstick_euvd.url(cve)}")
            prods = yardstick_euvd.products(cve)
            S.append(f"- products (the CNA's text, not distro packages): {'; '.join(f'{n} {v}' for n, v in prods[:8]) or 'n/a'}")
            links.append(yardstick_euvd.url(cve))
            facts.append(yardstick_euvd.fact(cve))
        else:
            S.append("- no EUVD record found by search")
        S.append("")

    osv = dc.osv_vuln(vuln)
    save(out, "osv.json", osv)
    if osv:
        S.append("## OSV")
        S.append(f"- {osv['id']}: aliases {osv.get('aliases', [])}, published {osv.get('published')}, modified {osv.get('modified')}")
        for a in osv.get("affected", [])[:12]:
            ev = a.get("ranges", [{}])[0].get("events", [])
            pk = a.get("package") or {}
            S.append(f"  - {pk.get('ecosystem', 'git')} {pk.get('name') or a.get('ranges', [{}])[0].get('repo', '')}: {json.dumps(ev)[:300]}")
        links.append(f"https://osv.dev/vulnerability/{vuln}")
        S.append("")

    # ---- Ubuntu ----
    if cve and (not distro or distro.get("type") == "ubuntu"):
        codename = dc.ubuntu_codename(distro["version"]) if distro else None
        u = dc.ubuntu_cve(cve)
        save(out, "ubuntu.json", u)
        S.append("## Ubuntu security tracker")
        links.append(f"https://ubuntu.com/security/{cve}")
        if u:
            if src and codename:
                facts += dc.ubuntu_facts(u, cve, src, codename, with_upstream=True)
                for e in dc.ubuntu_statuses(u, src, codename).get("release") or []:
                    if (e["status"] + " " + e["description"]).strip() != dc.ubuntu_fact_status(u, src, codename):
                        facts.append(dc.ubuntu_pocket_fact(cve, src, codename, e))
            S.append(f"- status {u.get('status')}, priority {u.get('priority')}, published {u.get('published')}, notices {u.get('notices_ids')}")
            for n in u.get("notes", []):
                S.append(f"- note ({n.get('author') or '?'}): {n['note'][:500]}")
            for p in u.get("packages", []):
                if src and p["name"] != src and p["name"] not in pkg_names:
                    continue
                S.append(f"- source package {p['name']} (debian: {p.get('debian')}):")
                for s in p["statuses"]:
                    mark = " <== this image" if s["release_codename"] == codename else ""
                    S.append(f"  - {s['release_codename']} [{s['pocket']}]: {s['status']} {s['description']}{mark}")
                    if installed and s["status"] == "released" and s["release_codename"] == codename:
                        m = re.search(r"([0-9][^\s()]*)", s["description"] or "")
                        if m:
                            S.append(f"    - installed {installed} vs fix {m.group(1)}: {'installed is OLDER (affected)' if dc.deb_compare(installed, m.group(1)) < 0 else 'installed has the fix'}")
            for nid in u.get("notices_ids", []):
                usn = dc.fetch_json(f"https://ubuntu.com/security/notices/{nid}.json")
                save(out, f"{nid}.json", usn)
                if usn:
                    rel = sorted({f"{r['codename']}:{p}" for r in usn.get("release_packages", []) if isinstance(r, dict) for p in [r.get('name')]} if isinstance(usn.get('release_packages'), list) else {k for k in (usn.get('release_packages') or {})})
                    S.append(f"- {nid} ({usn.get('published', '')[:10]}): {usn.get('title')} — https://ubuntu.com/security/notices/{nid}; releases {rel[:8]}")
                    links.append(f"https://ubuntu.com/security/notices/{nid}")
        else:
            S.append("- no record on ubuntu.com")
        raw = dc.ubuntu_tracker_file(cve)
        save(out, "ubuntu-cve-tracker.txt", raw)
        if raw:
            S.append(f"- raw tracker file saved (ubuntu-cve-tracker.txt): https://git.launchpad.net/ubuntu-cve-tracker/tree/active/{cve}")
            links.append(f"https://git.launchpad.net/ubuntu-cve-tracker/log/active/{cve}")
            patches = [l.strip() for l in raw.splitlines() if l.strip().startswith(("upstream:", "patch:", "vendor:", "distro:", "other:", "debdiff:"))]
            if patches:
                S.append("- patches listed by Ubuntu:")
                S += [f"  - {p}" for p in patches[:10]]
            for l in raw.splitlines():
                if l.startswith(("PublicDateAtUSN", "PublicDate:", "CRD:", "Assigned-to")):
                    S.append(f"- {l.strip()}")
            if src and codename:
                per_pocket = [l.strip() for l in raw.splitlines() if re.match(rf"^([\w-]+/)?{re.escape(codename)}_{re.escape(src)}:", l)]
                if per_pocket:
                    S.append(f"- raw tracker statuses for {codename}/{src} per pocket (ubuntu.com's JSON collapses these): {per_pocket}")
        if src and codename:
            lp = dc.fetch_json(f"https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name={src}&distro_series=https://api.launchpad.net/1.0/ubuntu/{codename}&exact_match=true&order_by_date=true")
            save(out, "launchpad-publishing.json", lp)
            if lp and lp.get("entries"):
                S.append(f"- Launchpad publishing history for {src} in {codename} (newest first; version, pocket, status, component, date):")
                seen = set()
                for e in lp["entries"]:
                    key = (e["source_package_version"], e["pocket"])
                    if key in seen:
                        continue
                    seen.add(key)
                    S.append(f"  - {e['source_package_version']} {e['pocket']} {e['status']} {e['component_name']} {e['date_published'][:10]}")
                    if len(seen) >= 12:
                        break
                comp = lp["entries"][0]["component_name"]
                prefix = src[:4] if src.startswith("lib") else src[0]
                for label, ver in (("installed", installed), ("newest", lp["entries"][0]["source_package_version"])):
                    if not ver:
                        continue
                    url = f"https://changelogs.ubuntu.com/changelogs/pool/{comp}/{prefix}/{src}/{src}_{ver}/changelog"
                    body = dc.fetch(url)
                    if body:
                        text = body.decode(errors="replace")
                        save(out, f"changelog-{label}-{ver}.txt", text)
                        hits = [l.strip() for l in text.splitlines() if cve in l]
                        S.append(f"- changelog for {label} {ver}: {url}; lines mentioning {cve}: {hits[:4] if hits else 'none'}")
                        links.append(url)
                    if label == "installed":
                        links.append(f"https://launchpad.net/ubuntu/+source/{src}/+changelog")
                for branch in (f"ubuntu/{codename}-security", f"ubuntu/{codename}-updates", f"ubuntu/{codename}-devel"):
                    body = dc.fetch(f"https://git.launchpad.net/ubuntu/+source/{src}/plain/debian/patches/series?h={branch}")
                    if body and not body.lstrip().startswith(b"<"):
                        series = body.decode(errors="replace")
                        save(out, f"patches-series-{branch.replace('/', '_')}.txt", series)
                        hits = [l for l in series.splitlines() if cve.lower() in l.lower()]
                        S.append(f"- debian/patches/series on {branch}: {len(series.splitlines())} patches; mentioning {cve}: {hits or 'none'} — https://git.launchpad.net/ubuntu/+source/{src}/tree/debian/patches?h={branch}")
                        break
        S.append("")

    # ---- Red Hat ----
    if cve and distro and distro.get("type") in ("redhat", "rhel", "centos"):
        major = (distro.get("version") or "").split(".")[0]
        doc, hy = yardstick_redhat.vex(cve), yardstick_redhat.hydra(cve)
        save(out, "redhat-vex.json", doc)
        save(out, "redhat-hydra.json", hy)
        S.append("## Red Hat security data")
        links.append(f"https://access.redhat.com/security/cve/{cve}")
        if hy:
            S.append(f"- severity {hy.get('threat_severity')}; public {hy.get('public_date')}; statement: {(hy.get('statement') or '').strip()[:600] or 'none'}")
            S.append(f"- mitigation: {(hy.get('mitigation') or {}).get('value', '')[:300] if isinstance(hy.get('mitigation'), dict) else (hy.get('mitigation') or '')[:300]}")
            for ps in hy.get("package_state") or []:
                if ps.get("product_name", "").endswith(f"Linux {major}"):
                    S.append(f"- package_state: {ps.get('product_name')} {ps.get('package_name')}: {ps.get('fix_state')}")
            for ar in hy.get("affected_release") or []:
                if f"Linux {major}" in ar.get("product_name", ""):
                    S.append(f"- affected_release: {ar.get('product_name')} {ar.get('package')} via {ar.get('advisory')} on {ar.get('release_date', '')[:10]}")
                    links.append(f"https://access.redhat.com/errata/{ar.get('advisory')}")
        for r in rows:
            p = dc.parse_purl(r["package"])
            st = yardstick_redhat.binary_status(doc, major, p["name"], p["version"], source_pkg)
            S.append(f"- VEX for {p['name']} {p['version']} on RHEL {major}: {st['status']}{' ' + str(st['flags']) if st['flags'] else ''}; applicable fix {st['applicable_fix']}; installed vs fix: {st['comparison']}; streams {sorted({f[0] for f in st['fixed'] if f[0]})}")
            facts.append(dc.fact("redhat-csaf-vex", {"vulnerability": cve, "product": f"rhel-{major}", "component": p["name"]}, "status",
                                 st["status"] + (f" {st['applicable_fix'][1]}" if st["status"] == "fixed" and st["applicable_fix"] else "") + (f" [{', '.join(st['flags'])}]" if st["flags"] else ""),
                                 f"https://security.access.redhat.com/data/csaf/v2/vex/{cve.split('-')[1]}/{cve.lower()}.json"))
        comps = yardstick_redhat.components_named((hy or {}).get("statement") or "")
        if comps:
            S.append(f"- components named in Red Hat's statement: {comps}; check the binary's file list in the SBOM for them")
        S.append("")

    # ---- Debian ----
    if cve:
        S.append("## Debian security tracker")
        page = dc.fetch(f"https://security-tracker.debian.org/tracker/{cve}")
        links.append(f"https://security-tracker.debian.org/tracker/{cve}")
        if page:
            table = debian_tracker_table(page)
            save(out, "debian-tracker.json", table)
            for row in table:
                if row and (row[0] in ("Name", "Description") or (src and src in row[0]) or row[0] == "" or len(row) >= 4):
                    S.append(f"- {' | '.join(row)[:300]}")
        dosv = dc.osv_vuln(f"DEBIAN-{cve}")
        save(out, "debian-osv.json", dosv)
        if dosv:
            for a in dosv.get("affected", []):
                pk = a.get("package") or {}
                if not src or pk.get("name") == src:
                    S.append(f"- OSV {pk.get('ecosystem')} {pk.get('name')}: {json.dumps(a.get('ranges', [{}])[0].get('events', []))}")
        if src:
            prefix = src[:4] if src.startswith("lib") else src[0]
            url = f"https://metadata.ftp-master.debian.org/changelogs/main/{prefix}/{src}/unstable_changelog"
            body = dc.fetch(url)
            if body:
                text = body.decode(errors="replace")
                save(out, "debian-changelog-unstable.txt", text)
                hits = [l.strip() for l in text.splitlines() if cve in l]
                S.append(f"- Debian unstable changelog lines mentioning {cve}: {hits[:4] if hits else 'none'} — {url}")
                links.append(url)
        S.append("")

    S.append("## Links")
    S += [f"- {l}" for l in dict.fromkeys(l for l in links if l)]
    S.append("")
    S.append(f"Files: {', '.join(sorted(p.name for p in out.iterdir()))}")
    (out / "SUMMARY.md").write_text("\n".join(S) + "\n")
    # the interpretation is the evidence chain in prose; REPORT.md's path goes at its end, since a label has no report field
    skeleton = {"verdict": "", "justification": "", "confidence": "", "note": "",
                "author": {"skill": "research-vuln", "model": args.model},
                "evidence": [{"facts": [f for f in facts if f], "interpretation": f"(report: {out / 'REPORT.md'})"}],
                "openQuestions": []}
    if row_id:
        skeleton = {"row": row_id, **skeleton}
    elif rows:
        skeleton = {"row": rows[0]["row"], **skeleton}
    (out / "proposal.json").write_text(json.dumps(skeleton, indent=1) + "\n")
    if len(rows) > 1:
        (out / "rows.json").write_text(json.dumps([{"row": r["row"], "package": r["package"]} for r in rows], indent=1) + "\n")
    print(f"wrote {out / 'SUMMARY.md'} and {out / 'proposal.json'}" + (f" ({len(rows)} rows share this finding; see rows.json)" if len(rows) > 1 else ""))
    print("\n".join(S))


if __name__ == "__main__":
    main()
