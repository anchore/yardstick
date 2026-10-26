#!/usr/bin/env python3
"""Regression tests for triage rules, with the network stubbed, under the checkout's policy (vocabulary.yaml).

    python3 -I plugin/scripts/test_rules.py        (set YARDSTICK_BIN to skip building yardstick)
"""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yardstick_common as dc  # noqa: E402

ev = importlib.import_module("yardstick-triage-evidence")
ev.set_policy(dc.checkout_policy())  # a rule of the wrong verdict, or not listed with one, raises in Verdict

failures = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        failures.append(f"{name}: {detail}")


def row(vuln: str, aliases: list[str], purl: str, **extra) -> dict:
    p = dc.parse_purl(purl)
    base = {"row_id": "r1", "vulnerability": vuln, "aliases": aliases, "package": purl, "name": p["name"], "version": p["version"],
            "within": "oci:img", "side": "candidate", "source_pkg": p["name"], "namespace": "github:language:npm",
            "distro_type": None, "distro_version": None, "fix_state": "fixed", "fix_versions": [], "constraints": [],
            "match_types": ["exact-direct-match"], "locations": [], "db_status": {}, "severity": "", "data_source": "",
            "nvd_description": "", "prior_claims_on_package": {}, "prior_claims_on_vuln": [], "files": [],
            "sibling_programs": {}}
    base.update(extra)
    return base


# --- bug 6: a cross-aliased sibling advisory must not supply the fix version (lodash CVE-2026-4800) ---
LODASH = [
    {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"],
     "database_specific": {"github_reviewed": True},
     "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]},
    {"id": "GHSA-r5fr-rjxr-66jc", "aliases": ["CVE-2021-23337", "CVE-2026-4800", "GHSA-35jh-r3h4-6jhm"],
     "database_specific": {"github_reviewed": True},
     "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.18.0"}]}]}]},
]
dc.osv_query = lambda name, eco: LODASH if (name, eco) == ("lodash", "npm") else []
dc.osv_vuln = lambda vid: next((v for v in LODASH if v["id"] == vid), None)

v = ev.suggest_ecosystem(row("GHSA-r5fr-rjxr-66jc", ["CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"], "pkg:npm/lodash@4.17.21"), None, "")
check("lodash picks its own advisory", v.rule == "ghsa/version-in-affected-range" and v.verdict == "tp", f"{v.rule} {v.verdict}: {v.note}")
check("lodash facts name GHSA-r5fr", all(f["about"].get("vulnerability") == "GHSA-r5fr-rjxr-66jc" for f in v.facts), str([f["about"] for f in v.facts]))

# the sibling, asked for by its own id, still resolves to itself
v = ev.suggest_ecosystem(row("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"], "pkg:npm/lodash@4.17.21"), None, "")
check("lodash 2021 advisory is fixed at 4.17.21", v.rule == "ghsa/installed-at-or-past-fix" and v.verdict == "fp", f"{v.rule}: {v.note}")

# --- bug 3: installed below every range ---
PB = [{"id": "GHSA-x", "aliases": ["CVE-2026-1"], "database_specific": {"github_reviewed": True},
       "affected": [{"package": {"name": "protobufjs", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.10.0"}, {"fixed": "6.10.3"}]}]},
                    {"package": {"name": "protobufjs", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "7.0.0"}, {"fixed": "7.2.4"}]}]}]}]
dc.osv_query = lambda name, eco: PB
dc.osv_vuln = lambda vid: PB[0]
v = ev.suggest_ecosystem(row("GHSA-x", ["CVE-2026-1", "GHSA-x"], "pkg:npm/protobufjs@6.6.0"), None, "")
check("below every range is introduced-after-installed", v.rule == "ghsa/introduced-after-installed" and v.verdict == "fp", f"{v.rule}: {v.note}")

# --- ordering: maven milestone inside a range ---
# --- proposals: justification from the rule, its facts and rule as one evidence entry ---
check("rule fills the justification", v.why == {"kind": "introduced-later"}, str(v.why))
e = ev.evidence(v.rule, v.facts, "x")
check("evidence entry", e and e[0]["rule"] == v.rule and e[0]["facts"] == v.facts and e[0]["interpretation"] == "x", str(e))
check("no facts, no entry", ev.evidence("none/no-evidence", []) == [])
check("vendor text picks the justification", ev.why_for("ubuntu/not-affected", "fp", None, "code not built") == {"kind": "vulnerable_code_not_present"},
      str(ev.why_for("ubuntu/not-affected", "fp", None, "code not built")))
try:
    ev.why_for("judgement/prior-claims-pattern", "tp", "fix-installed")
    check("a justification of the other verdict raises", False)
except ValueError:
    pass

check("maven 9.1.0.M0 in [7.2.2, 9.4.39)", dc.osv_range_status_for({"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "7.2.2"}, {"fixed": "9.4.39"}]}]}, "9.1.0.M0", "Maven")[0] == "affected")

if failures:
    print("\n".join(failures))
    sys.exit(1)
print(f"ok: {5 + 5} checks")
