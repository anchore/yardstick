"""EUVD (ENISA's European Vulnerability Database) as an optional source for the yardstick labeling skills.

Provisional. Enable with --euvd on the scripts or YARDSTICK_SKILLS_EUVD=1; off by default. To remove the
source entirely: delete this file and the `euvd` branches in yardstick-triage-evidence.py and
yardstick-vuln-sources.py (grep for "euvd"). Nothing else depends on it.

What EUVD gives us, measured 2026-10-06 on 71 CVEs from the Ubuntu, Python and Java test images:
- aliases: the CVE's GHSA id (62 of 71). This looked useful for CPE triage (find the GitHub advisory
  without the rate-limited GitHub API), but GitHub mints an unreviewed GHSA shell with no package
  data for every CVE, so knowing the id proves nothing; treating EUVD-named advisories as evidence
  turned 1,028 correct CPE false positives into "unclear" on the Java image. Not used by any rule.
- products and version strings: the CNA record's text verbatim ("< 1.4.16", "5.0.0 - 5.15.5",
  "patch: 0:1.13.1-8.el9"); 41 of 71 are "n/a". No distro or ecosystem package data. Shown as
  evidence only; the CNA parser in yardstick_common reads the same text from cve.org.
- exploitedSince, EPSS, scores: risk, not truth (policy P-1); ignored.
Net: no labeling signal the other sources lack, so far. Kept behind the flag for research reading.

API: https://euvdservices.enisa.europa.eu/api/search?text=<CVE> works without a key and returns items
whose `aliases` is a whitespace-separated string of ids. /api/vulnerability?id= answers 403 to every
client tried; /api/enisaid?id=EUVD-… works but needs the EUVD id, which only search reveals.
"""
from __future__ import annotations

import os

import yardstick_common as dc

HEADERS = {"User-Agent": "Mozilla/5.0 (Macintosh) yardstick-skills/0.1"}
BASE = "https://euvdservices.enisa.europa.eu/api"


def enabled(flag: bool | None = None) -> bool:
    return bool(flag) if flag is not None else os.environ.get("YARDSTICK_SKILLS_EUVD", "") not in ("", "0", "false")


def record(cve: str) -> dict | None:
    """The EUVD item whose aliases include the CVE, via search (cached)."""
    if not cve or not cve.startswith("CVE-"):
        return None
    d = dc.fetch_json(f"{BASE}/search?text={cve}&size=5", headers=HEADERS)
    for i in (d or {}).get("items", []):
        if cve in (i.get("aliases") or "").split() or i.get("id") == cve:
            return i
    return None


def aliases(cve: str) -> list[str]:
    r = record(cve)
    return [] if not r else [a for a in (r.get("aliases") or "").split() if a != cve]


def ghsa_ids(cve: str) -> list[str]:
    return [a for a in aliases(cve) if a.startswith("GHSA-")]


def products(cve: str) -> list[tuple[str, str]]:
    """(product name, version text) pairs, 'n/a' entries dropped."""
    r = record(cve)
    out = []
    for p in (r or {}).get("enisaIdProduct", []) or []:
        name = (p.get("product") or {}).get("name") or ""
        ver = p.get("product_version") or ""
        if name and name != "n/a":
            out.append((name, ver))
    return out


def url(cve: str) -> str | None:
    r = record(cve)
    return f"https://euvd.enisa.europa.eu/vulnerability/{r['id']}" if r else None


def fact(cve: str) -> dict | None:
    r = record(cve)
    if not r:
        return None
    return dc.fact("euvd", {"vulnerability": cve}, "aliases", " ".join(sorted(aliases(cve))), url(cve) or "")
