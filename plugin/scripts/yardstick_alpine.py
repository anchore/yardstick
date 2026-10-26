"""Alpine's secdb as evidence for apk matches: per branch (v3.19) and repo (main, community), each origin
package's `secfixes` map fixed version -> CVEs; version "0" means the package was never affected.

    https://secdb.alpinelinux.org/v3.19/main.json

Releases past end of life keep their last secdb, so "not listed" on an EOL branch says nothing (P-2).
"""
from __future__ import annotations

import re

import yardstick_common as dc

BASE = "https://secdb.alpinelinux.org"


def branch(distro_version: str) -> str | None:
    m = re.match(r"^(\d+)\.(\d+)", distro_version or "")
    return f"v{m.group(1)}.{m.group(2)}" if m else None


def secfixes(branch_name: str) -> dict[str, dict[str, list[str]]]:
    """origin package -> {version: [CVE, ...]} across main and community (cached a day)."""
    out: dict[str, dict[str, list[str]]] = {}
    for repo in ("main", "community"):
        d = dc.fetch_json(f"{BASE}/{branch_name}/{repo}.json", ttl_hours=24)
        for p in (d or {}).get("packages", []):
            pk = p.get("pkg") or {}
            if pk.get("name") and pk.get("secfixes"):
                out.setdefault(pk["name"], {}).update(pk["secfixes"])
    return out


def status(branch_name: str, origin: str, cve: str, installed: str) -> dict:
    """{'status': not-affected|fixed|not-listed, 'fixed': version, 'comparison': installed vs fixed}."""
    fixes = secfixes(branch_name).get(origin) or {}
    hits = [v for v, cves in fixes.items() if cve in cves]
    if not hits:
        return {"status": "not-listed", "fixed": None, "comparison": None, "listed": bool(fixes)}
    if "0" in hits:
        return {"status": "not-affected", "fixed": "0", "comparison": None, "listed": True}
    fixed = min(hits, key=lambda v: _apk_key(v))
    return {"status": "fixed", "fixed": fixed, "comparison": apk_compare(installed, fixed), "listed": True}


_SUFFIX_RANK = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_key(v: str):
    """apk version ordering, simplified: numeric dotted parts, then letter, then _suffix (pre-release
    suffixes below the bare version, post-release ones above), then -rN."""
    v = v.strip()
    m = re.match(r"^(\d+(?:\.\d+)*)([a-z])?((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:-r(\d+))?$", v)
    if not m:
        return ((), "", (), 0, v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    letter = m.group(2) or ""
    sufs = tuple((_SUFFIX_RANK[s], int(n or 0)) for s, n in re.findall(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)", m.group(3) or ""))
    return (nums, letter, sufs or ((0, 0),), int(m.group(4) or 0), "")


def apk_compare(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    return -1 if ka < kb else 1 if ka > kb else 0
