"""Shared helpers for the yardstick labeling skills (triage-deltas, research-vuln, explain-deltas).

Pure standard library. Every network fetch is cached on disk so a rerun is free.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote

CACHE_DIR = Path(os.environ.get("YARDSTICK_SKILLS_CACHE", Path.home() / ".cache" / "yardstick-skills"))
USER_AGENT = "yardstick-skills/0.1 (+https://github.com/anchore/yardstick)"


# ---------------------------------------------------------------------------
# yardstick CLI and workspace
# ---------------------------------------------------------------------------

def find_yardstick(store: Path | None = None) -> str:
    """$YARDSTICK_BIN, else yardstick on PATH, else <store>/bin/yardstick (a checkout's `go build -o bin/yardstick ./cmd/yardstick`)."""
    for cand in (os.environ.get("YARDSTICK_BIN"), shutil.which("yardstick"), store and str(store / "bin" / "yardstick")):
        if cand and Path(cand).exists():
            return cand
    sys.exit("yardstick binary not found: set YARDSTICK_BIN, put yardstick on PATH, or build it with "
             "`go build -o bin/yardstick ./cmd/yardstick` in a yardstick checkout")


def run_json(cmd: list[str], cwd: Path | None = None, ok: tuple[int, ...] = (0,)):
    """A yardstick command's JSON output. It runs in the workspace, where yardstick finds .yardstick/ and its app config."""
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if res.returncode not in ok:
        raise subprocess.CalledProcessError(res.returncode, cmd, res.stdout, res.stderr)
    return json.loads(res.stdout or "null")


def run_name(name: str | None = None) -> str:
    """The run name yardstick keeps scans under: the one given, else $YARDSTICK_NAME, else default."""
    return name or os.environ.get("YARDSTICK_NAME") or "default"


def load_run(store: Path, name: str, gate: str | None = None) -> tuple[Path, dict]:
    """A gate's run directory and its yardstick-run.json. The gate is a name or a gate file, else
    $YARDSTICK_GATE, else the gate scanned last under the run name."""
    runs = store / ".yardstick" / "runs" / name
    recs = sorted(runs.glob("*/yardstick-run.json"), key=lambda p: p.stat().st_mtime)
    if not recs:
        sys.exit(f"no gate has been scanned under {runs}: run `yardstick <gate.yaml>` first, or pass --store/--name")
    gate = gate or os.environ.get("YARDSTICK_GATE")
    if gate:
        path = Path(gate).resolve() if Path(gate).is_file() else None
        recs = [r for r in recs if r.parent.name == gate or (path and json.loads(r.read_text())["gate"]["path"] == str(path))]
        if not recs:
            sys.exit(f"gate {gate} has not been scanned under {runs}")
    return recs[-1].parent, json.loads(recs[-1].read_text())


def score(ys: str, store: Path, name: str, run: dict) -> dict:
    """A gate's last scans scored against the current labels (`yardstick score <gate> -o json`), the gate's
    entry of the verdict set. Exit 1 is a gate that failed, which still prints the whole set."""
    out = run_json([ys, "score", run["gate"]["name"], "--name", name, "-o", "json"], store, ok=(0, 1))
    return out["gates"][0]


def load_labels(ys: str, store: Path) -> list[dict]:
    """Every label in the workspace's claims sources ({source, file, subject, label}), through the CLI:
    skills never read the corpus's files, so it can change how it keeps them."""
    return run_json([ys, "claims", "list", "-o", "json"], store) or []


def load_policy(ys: str, store: Path | None = None, claims: str | None = None) -> dict:
    """The labeling policy (`yardstick claims policy -o json`): {justifications: {verdict: {name: line}},
    rules: {name: {verdict, justification, ceiling, decision, basis, title}}, factSources, ...}."""
    return run_json([ys, "claims", "policy", "-o", "json"] + (["--claims", claims] if claims else []), store)


def checkout_policy() -> dict:
    """For the tests: the policy the yardstick checkout these scripts sit in reads through its app config
    (the published corpus first), read with $YARDSTICK_BIN, else with a yardstick built from the checkout
    now (a bin/yardstick may be stale)."""
    import tempfile
    repo = Path(__file__).resolve().parents[2]
    ys = os.environ.get("YARDSTICK_BIN")
    if not ys:
        ys = str(Path(tempfile.mkdtemp()) / "yardstick")
        subprocess.run(["go", "build", "-o", ys, "./cmd/yardstick"], cwd=repo, check=True)
    return load_policy(ys, store=repo)


def subject_logs(run: dict) -> dict[str, dict]:
    """subject name -> {side: {path, sha256}}: the grype logs the run kept (paths relative to the run dir)."""
    return {s["name"]: s.get("logs") or {} for s in run.get("subjects", [])}


def side_grype_and_db(setup: dict) -> tuple[str | None, str | None]:
    """The grype binary and the DB cache dir a setup scanned with, as the run record names them
    (`grype.bin`, `db.dir`). A record made before yardstick recorded them gives grype on PATH and no DB."""
    grype, db = (setup.get("grype") or {}).get("bin"), (setup.get("db") or {}).get("dir")
    return (grype if grype and Path(grype).exists() else shutil.which("grype")), (db if db and Path(db).exists() else None)


def matches(gate: dict):
    """(subject, match) for every match row in a scored gate."""
    for subj in gate.get("subjects") or []:
        for m in subj.get("matches") or []:
            yield subj, m


# ---------------------------------------------------------------------------
# purls and versions
# ---------------------------------------------------------------------------

PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?:(?P<ns>[^/]+)/)?(?P<name>[^@?#]+)(?:@(?P<version>[^?#]+))?(?:\?(?P<q>[^#]*))?")


def parse_purl(purl: str) -> dict:
    m = PURL_RE.match(purl)
    if not m:
        return {"type": "", "ns": "", "name": purl, "version": "", "qualifiers": {}}
    q = {}
    for kv in (m.group("q") or "").split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            q[k] = unquote(v)
    return {"type": m.group("type"), "ns": unquote(m.group("ns") or ""), "name": unquote(m.group("name")),
            "version": unquote(m.group("version") or ""), "qualifiers": q}


def _deb_order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_cmp_part(a: str, b: str) -> int:
    while a or b:
        # non-digit prefix
        ia = ib = 0
        while ia < len(a) and not a[ia].isdigit():
            ia += 1
        while ib < len(b) and not b[ib].isdigit():
            ib += 1
        pa, pb = a[:ia], b[:ib]
        i = 0
        while i < len(pa) or i < len(pb):
            ca = _deb_order(pa[i]) if i < len(pa) else 0
            cb = _deb_order(pb[i]) if i < len(pb) else 0
            if ca != cb:
                return -1 if ca < cb else 1
            i += 1
        a, b = a[ia:], b[ib:]
        # digit prefix
        ia = ib = 0
        while ia < len(a) and a[ia].isdigit():
            ia += 1
        while ib < len(b) and b[ib].isdigit():
            ib += 1
        na = int(a[:ia] or "0")
        nb = int(b[:ib] or "0")
        if na != nb:
            return -1 if na < nb else 1
        a, b = a[ia:], b[ib:]
    return 0


def deb_split(v: str) -> tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    upstream, _, revision = v.rpartition("-") if "-" in v else (v, "", "")
    return epoch, upstream, revision


def deb_compare(a: str, b: str) -> int:
    """Compare two Debian package versions: -1, 0 or 1 (same rules as dpkg --compare-versions)."""
    ea, ua, ra = deb_split(a)
    eb, ub, rb = deb_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _deb_cmp_part(ua, ub)
    if c:
        return c
    return _deb_cmp_part(ra, rb)


def deb_upstream(v: str) -> str:
    """The upstream part of a Debian version: '2:1.6.9-2ubuntu1.6' -> '1.6.9', '4.1.0+git191117-2ubuntu0.20.04.14' -> '4.1.0+git191117'."""
    return deb_split(v)[1]


# ---------------------------------------------------------------------------
# cached HTTP
# ---------------------------------------------------------------------------

GITHUB_BLOCKED_UNTIL = 0.0  # epoch seconds; set when api.github.com answers with its rate limit exhausted
_github_lock = threading.Lock()


def _github_rate_limited(reset: str | None) -> None:
    global GITHUB_BLOCKED_UNTIL
    try:
        until = float(reset or 0)
    except ValueError:
        until = 0
    with _github_lock:
        if time.time() < GITHUB_BLOCKED_UNTIL:
            return  # another worker already reported it
        GITHUB_BLOCKED_UNTIL = max(until, time.time() + 600)
        print(f"warning: api.github.com rate limit exhausted until {time.strftime('%H:%M', time.localtime(GITHUB_BLOCKED_UNTIL))}; "
              "GitHub advisory lookups are skipped for the rest of this run (set GITHUB_TOKEN, e.g. `export GITHUB_TOKEN=$(gh auth token)`, for 5000/hour)",
              file=sys.stderr)


def _cache_path(key: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", key)[:200]
    return CACHE_DIR / safe


def fetch(url: str, *, data: bytes | None = None, headers: dict | None = None, ttl_hours: float = 24,
          retries: int = 2) -> bytes | None:
    """GET (or POST when data is given) with an on-disk cache. Returns None on a non-2xx or network failure."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = url + ("|" + data.decode(errors="replace") if data else "")
    p = _cache_path(key)
    if p.exists() and (time.time() - p.stat().st_mtime) < ttl_hours * 3600:
        body = p.read_bytes()
        return None if body == b"__MISS__" else body
    github = url.startswith("https://api.github.com/")
    if github and time.time() < GITHUB_BLOCKED_UNTIL:
        return None  # rate-limited earlier in this run; do not burn retries on every call
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                body = r.read()
            p.write_bytes(body)
            return body
        except urllib.error.HTTPError as e:
            if e.code in (404, 400):
                p.write_bytes(b"__MISS__")
                return None
            if github and e.code in (403, 429) and e.headers.get("x-ratelimit-remaining") == "0":
                _github_rate_limited(e.headers.get("x-ratelimit-reset"))
                return None
            if attempt == retries:
                return None
            time.sleep(1.5 * (attempt + 1))
        except Exception:
            if attempt == retries:
                return None
            time.sleep(1.5 * (attempt + 1))
    return None


def fetch_json(url: str, **kw) -> dict | list | None:
    body = fetch(url, **kw)
    if body is None:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# upstream sources
# ---------------------------------------------------------------------------

UBUNTU_CODENAMES: dict[str, str] = {}


def ubuntu_codename(version: str) -> str | None:
    """'20.04' -> 'focal' using ubuntu.com's release list (cached), with a static fallback."""
    global UBUNTU_CODENAMES
    if not UBUNTU_CODENAMES:
        d = fetch_json("https://ubuntu.com/security/releases.json", ttl_hours=24 * 30)
        if d:
            UBUNTU_CODENAMES = {r["version"]: r["codename"] for r in d.get("releases", []) if r.get("version")}
        UBUNTU_CODENAMES.setdefault("16.04", "xenial")
        UBUNTU_CODENAMES.setdefault("18.04", "bionic")
        UBUNTU_CODENAMES.setdefault("20.04", "focal")
        UBUNTU_CODENAMES.setdefault("22.04", "jammy")
        UBUNTU_CODENAMES.setdefault("24.04", "noble")
    return UBUNTU_CODENAMES.get(version)


def ubuntu_cve(cve: str) -> dict | None:
    """The Ubuntu security tracker's record: per-release, per-source-package statuses, priority, notes, USNs."""
    return fetch_json(f"https://ubuntu.com/security/cves/{cve}.json")


def ubuntu_statuses(record: dict, source_pkg: str, codename: str) -> dict:
    """Pick the statuses for one source package.

    Returns {'release': [{status, pocket, description}, ...], 'upstream': {status, description}}. A release
    can have several entries, one per pocket (security, esm-infra, esm-apps, ...): the ESM pockets carry
    the Ubuntu Pro assessment and fix versions for the same source version.
    """
    out: dict = {"release": []}
    for p in record.get("packages", []):
        if p["name"] != source_pkg:
            continue
        for s in p["statuses"]:
            if s["release_codename"] == codename:
                out["release"].append({"status": s["status"], "pocket": s["pocket"] or "security", "description": s["description"] or ""})
            elif s["release_codename"] == "upstream":
                out["upstream"] = {"status": s["status"], "description": s["description"] or ""}
    return out


def ubuntu_tracker_file(cve: str) -> str | None:
    """The raw ubuntu-cve-tracker record (richer notes, per-pocket statuses, upstream patch URLs)."""
    for d in ("active", "retired", "ignored"):
        body = fetch(f"https://git.launchpad.net/ubuntu-cve-tracker/plain/{d}/{cve}")
        if body and not body.lstrip().startswith(b"<"):
            return body.decode(errors="replace")
    return None


_VER = r"[0-9][0-9A-Za-z.+~_-]*"


def _parse_version_text(text: str) -> tuple[str, str | None, bool] | None:
    """A CNA 'version' written as text: '< 1.4.16', '<= 2.4.16', '>= 1.6.0, < 1.6.51', '5.0.0 - 5.15.5',
    '1.0 through 1.5', '0 <2.8.3'. Returns (lower, upper, upper inclusive) or None."""
    t = text.strip().replace("≤", "<=").replace("≥", ">=")
    m = re.match(rf"^(?:>=\s*)?({_VER})\s*(?:-|through|to|,)\s*(?:<=?\s*)?({_VER})$", t)
    if m:
        return m.group(1), m.group(2), "<=" in t or "-" in t or "through" in t or "to" in t
    m = re.match(rf"^>=\s*({_VER})\s*,?\s*(<=?)\s*({_VER})$", t)
    if m:
        return m.group(1), m.group(3), m.group(2) == "<="
    m = re.match(rf"^(<=?)\s*({_VER})$", t)
    if m:
        return "0", m.group(2), m.group(1) == "<="
    m = re.match(rf"^({_VER})\s*(<=?)\s*({_VER})$", t)
    if m:
        return m.group(1), m.group(3), m.group(2) == "<="
    m = re.match(rf"^>=\s*({_VER})$", t)  # a lower bound only: '>= 2.40' (GitHub repository advisories write these)
    if m:
        return m.group(1), None, False
    return None


def _range_relation(ranges: list[tuple[str, str | None, bool]], version: str) -> str | None:
    """Where `version` sits relative to bounded ranges: 'in', 'below' (older than every lower bound), 'above',
    'out', or None when there are no ranges."""
    if not ranges:
        return None
    below = above = True
    for lo, hi, inclusive in ranges:
        ge_lo = deb_compare(version, lo) >= 0
        lt_hi = hi is None or (deb_compare(version, hi) <= 0 if inclusive else deb_compare(version, hi) < 0)
        if ge_lo and lt_hi:
            return "in"
        if ge_lo:
            below = False
        if lt_hi:
            above = False
    return "below" if below else "above" if above else "out"


def cna_bounded_ranges(record: dict | None) -> list[tuple[str, str | None, bool]]:
    """(lower bound, upper bound or None for open, upper inclusive) for every CNA 'affected' range with numeric bounds."""
    out = []
    for a in (record or {}).get("containers", {}).get("cna", {}).get("affected", []) or []:
        for v in a.get("versions", []) or []:
            if v.get("status") != "affected":
                continue
            lo = str(v.get("version") or "0")
            hi, inclusive = v.get("lessThan"), False
            if not hi:
                hi, inclusive = v.get("lessThanOrEqual"), True
            if hi is None and not re.match(r"^[0-9][0-9A-Za-z.+~_-]*$", lo):
                parsed = _parse_version_text(lo)  # the range is written into the version field as text
                if parsed:
                    out.append(parsed)
                continue
            if hi in ("*", None) and not v.get("lessThanOrEqual") and not v.get("lessThan"):
                continue  # a single version with no range: the version someone tested, not a bound
            if hi == "*":
                hi = None
            if not re.match(r"^[0-9]", lo) or (hi is not None and not re.match(r"^[0-9]", str(hi))):
                continue
            out.append((lo, hi, inclusive))
    return out


def cna_range_relation(record: dict | None, version: str) -> str | None:
    """Where `version` sits relative to the CNA's bounded affected ranges:
    'in' (some range contains it), 'below' (older than every range's lower bound), 'above' (at or past every
    range's upper bound), 'out' (between ranges), or None when the CNA gives no bounded ranges."""
    return _range_relation(cna_bounded_ranges(record), version)


def version_in_cna_range(record: dict | None, version: str) -> bool | None:
    rel = cna_range_relation(record, version)
    return None if rel is None else rel == "in"


# ---------------------------------------------------------------------------
# the syft SBOM: which files a binary package actually installs
# ---------------------------------------------------------------------------

_sbom_cache: dict[str, dict[tuple[str, str], list[str]]] = {}


def _file_path(f) -> str:
    """A package file's path: syft writes {path, ...} for most package types and a bare string for some."""
    return (f.get("path") if isinstance(f, dict) else f) or ""


def sbom_files(path: str) -> dict[tuple[str, str], list[str]]:
    """(name, version) -> installed file paths, from a syft JSON SBOM (dpkg/rpm/apk metadata carries files)."""
    if path in _sbom_cache:
        return _sbom_cache[path]
    out: dict[tuple[str, str], list[str]] = {}
    try:
        doc = json.loads(Path(path).read_text())
        for a in doc.get("artifacts", []):
            files = [x for x in map(_file_path, (a.get("metadata") or {}).get("files", []) or []) if x]
            out[(a.get("name"), a.get("version"))] = files
    except Exception:
        pass
    _sbom_cache[path] = out
    return out


PERL_MODULE_RE = re.compile(r"\b([A-Z][A-Za-z0-9]*(?:::[A-Z][A-Za-z0-9_]*)+)\b")


def perl_modules_named(text: str) -> list[str]:
    """Perl module names mentioned in a description, e.g. 'IO::Uncompress::Unzip'."""
    return list(dict.fromkeys(m for m in PERL_MODULE_RE.findall(text or "") if "::" in m))


BIN_PATH_RE = re.compile(r"^/(?:usr/(?:local/)?)?s?bin/([^/]+)$")
# a program named the way a description names one: with an option ("nsenter --join-cgroup", "sed -i") or in backticks
PROGRAM_RE = re.compile(r"`([a-z][a-z0-9_.+-]{2,})`|\b([a-z][a-z0-9_.+-]{2,})\s+(?:-[a-zA-Z]\b|--[a-z][\w-]*)")


def programs_named(text: str) -> list[str]:
    return list(dict.fromkeys(a or b for a, b in PROGRAM_RE.findall(text or "")))


def sbom_programs(path: str) -> dict[str, dict[str, set[str]]]:
    """source package -> program basename -> binary packages (from that source) that install it under a bin dir."""
    out: dict[str, dict[str, set[str]]] = {}
    try:
        doc = json.loads(Path(path).read_text())
    except Exception:
        return out
    for a in doc.get("artifacts", []):
        p = parse_purl(a.get("purl") or "")
        src = (p.get("qualifiers") or {}).get("upstream") or (a.get("metadata") or {}).get("source") or a.get("name")
        src = (src or "").split("@")[0]
        for f in (a.get("metadata") or {}).get("files", []) or []:
            m = BIN_PATH_RE.match(_file_path(f))
            if m:
                out.setdefault(src, {}).setdefault(m.group(1), set()).add(a.get("name"))
    return out


def modules_missing_from(files: list[str], modules: list[str]) -> list[str]:
    """Named Perl modules whose .pm file the package does not install."""
    missing = []
    for mod in modules:
        rel = mod.replace("::", "/") + ".pm"
        if not any(f.endswith("/" + rel) for f in files):
            missing.append(mod)
    return missing


def cve_org(cve: str) -> dict | None:
    """The CNA record from cve.org (affected products/versions, state, references)."""
    return fetch_json(f"https://cveawg.mitre.org/api/cve/{cve}")


def cna_affected_summary(record: dict | None, bounded_only: bool = False) -> list[str]:
    if not record:
        return []
    out = []
    for a in record.get("containers", {}).get("cna", {}).get("affected", []) or []:
        prod = " ".join(x for x in (a.get("vendor"), a.get("product")) if x and x != "n/a")
        vs = []
        for v in a.get("versions", []) or []:
            if v.get("status") != "affected":
                continue
            bound = v.get("lessThanOrEqual") and f"<= {v['lessThanOrEqual']}" or v.get("lessThan") and f"< {v['lessThan']}" or ""
            if bounded_only and not bound:
                continue
            vs.append(f"{v.get('version')}{' ' + bound if bound else ''}")
        if vs or not bounded_only:
            out.append(f"{prod or '?'}: {', '.join(vs) if vs else a.get('defaultStatus', '?')}")
    return out


def osv_vuln(vuln_id: str) -> dict | None:
    return fetch_json(f"https://api.osv.dev/v1/vulns/{vuln_id}")


def osv_query(pkg: str, ecosystem: str) -> list[dict]:
    d = fetch_json("https://api.osv.dev/v1/query", data=json.dumps({"package": {"name": pkg, "ecosystem": ecosystem}}).encode(),
                   headers={"Content-Type": "application/json"})
    return (d or {}).get("vulns", [])


def debian_osv_status(cve: str, source_pkg: str, major: str) -> dict | None:
    """Debian's view from OSV (DEBIAN-CVE-* records): fixed version for this release, if any."""
    eco = f"Debian:{major}"
    for v in osv_query(source_pkg, eco):
        if v["id"] not in (cve, f"DEBIAN-{cve}") and cve not in v.get("aliases", []):
            continue
        for a in v.get("affected", []):
            if a["package"]["name"] == source_pkg and a["package"]["ecosystem"] == eco:
                events = a.get("ranges", [{}])[0].get("events", [])
                fixed = next((e["fixed"] for e in events if "fixed" in e), None)
                return {"id": v["id"], "fixed": fixed, "events": events}
    return None


def github_headers() -> dict:
    """Bearer auth when GITHUB_TOKEN is set; api.github.com allows 60 requests/hour without it."""
    tok = os.environ.get("GITHUB_TOKEN")
    return {"Authorization": f"Bearer {tok}"} if tok else {}


REPO_ADVISORY_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/security/advisories/(GHSA-[\w-]+)")


def repo_advisory_refs(record: dict | None) -> list[tuple[str, str, str]]:
    """(org, repo, GHSA id) for every repository advisory the CNA record references."""
    out = []
    for r in (record or {}).get("containers", {}).get("cna", {}).get("references", []) or []:
        m = REPO_ADVISORY_RE.search(r.get("url") or "")
        if m and m.groups() not in out:
            out.append(m.groups())
    return out


def ghsa_for_cve(cve: str, cna: dict | None = None, global_db: bool = True) -> list[dict]:
    """GitHub advisories for a CVE. The global database (api.github.com/advisories) only holds advisories
    GitHub has imported; an advisory a project published in its own repository is reachable only through
    the repository endpoint, so every github.com/<org>/<repo>/security/advisories/<id> URL the CNA
    references is followed too. Repository records carry `repository`, `patched_versions` (a string)
    and a `description` naming the component; the global ones carry `first_patched_version`.
    `global_db=False` skips the global lookup (for a distro package it mostly returns GitHub's unreviewed
    shell, which has no range, and every call counts against the 60/hour unauthenticated budget)."""
    out = []
    if global_db:
        d = fetch_json(f"https://api.github.com/advisories?cve_id={cve}", headers=github_headers())
        out = [g for g in d if isinstance(g, dict) and g.get("cve_id") in (None, "", cve)] if isinstance(d, list) else []
    seen = {g.get("ghsa_id") for g in out}
    for org, repo, gid in repo_advisory_refs(cna):
        if gid in seen:
            continue
        g = fetch_json(f"https://api.github.com/repos/{org}/{repo}/security-advisories/{gid}", headers=github_headers())
        if isinstance(g, dict) and g.get("ghsa_id") and (g.get("cve_id") in (None, "", cve)):  # a reference can point at a sibling advisory
            g["repository"] = f"{org}/{repo}"
            out.append(g)
            seen.add(gid)
    return out


def advisory_ranges(advisories: list[dict]) -> list[dict]:
    """One entry per (advisory, vulnerability): the range text, its parsed bounds (or None), patched versions,
    package name and URL."""
    out = []
    for g in advisories:
        for v in g.get("vulnerabilities", []) or []:
            rng = (v.get("vulnerable_version_range") or "").strip()
            patched = v.get("first_patched_version") or v.get("patched_versions") or ""
            out.append({"ghsa_id": g.get("ghsa_id"), "url": g.get("html_url"), "repository": g.get("repository"),
                        "package": ((v.get("package") or {}).get("name") or "").strip(), "ecosystem": (v.get("package") or {}).get("ecosystem") or "",
                        "range": rng, "bounds": _parse_version_text(rng) if rng else None, "patched": patched})
    return out


def advisory_range_relation(advisories: list[dict], version: str) -> tuple[str | None, str]:
    """Where `version` sits relative to the advisories' parsed ranges, and a short description of them.
    Lower bounds of 0 say nothing about introduction, so they never yield 'below'."""
    entries = [e for e in advisory_ranges(advisories) if e["bounds"]]
    desc = "; ".join(f"{e['ghsa_id']}: {e['range']}" + (f" (patched {e['patched']})" if e["patched"] else "") for e in entries)[:200]
    rel = _range_relation([e["bounds"] for e in entries], version)
    if rel == "below" and all(e["bounds"][0] in ("0", "0.0") for e in entries):
        rel = None
    return rel, desc


SOURCE_PATH_RE = re.compile(r"\b((?:[\w-]+/)+[\w-]+\.(?:c|h|cc|cpp|cxx|hpp|py|go|rs|js|ts|java|rb|pm|php|pl))\b")


def advisory_components(advisories: list[dict]) -> list[str]:
    """Source paths a repository advisory's text names ('sys-utils/nsenter.c'): the file to check at the installed tag."""
    found = []
    for g in advisories:
        for m in SOURCE_PATH_RE.findall((g.get("summary") or "") + "\n" + (g.get("description") or "")):
            dirs = m.split("/")[:-1]
            if m in found or {"test", "tests", "tmp", "script_dir", "sys", "usr", "etc", "include"} & set(dirs) or any(len(d) < 2 for d in dirs):
                continue  # the component, not the reporter's probe scripts or system headers
            found.append(m)
    return found


def advisory_facts(cve: str, advisories: list[dict]) -> list[dict]:
    return [fact("ghsa", {"vulnerability": cve, "advisory": e["ghsa_id"], "package": e["package"]},
                 "vulnerable_version_range", e["range"], e["url"] or "") for e in advisory_ranges(advisories) if e["range"]]


def nvd_cve(cve: str) -> dict | None:
    d = fetch_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
    try:
        return d["vulnerabilities"][0]["cve"]
    except (KeyError, IndexError, TypeError):
        return None


def grype_db_search(cache_dir: str | None, vuln: str, pkg: str | None = None, distro: str | None = None, grype: str | None = None) -> list:
    """Ask a cached grype DB what it knows, with the grype that scanned it when given (side_grype_and_db)."""
    grype = grype or shutil.which("grype")
    if not grype or not cache_dir or not Path(cache_dir).exists():
        return []
    env = {**os.environ, "GRYPE_DB_CACHE_DIR": cache_dir, "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_VALIDATE_AGE": "false"}
    cmd = [grype, "db", "search", "--vuln", vuln, "-o", "json"]
    if pkg:
        cmd += ["--pkg", pkg]
    if distro:
        cmd += ["--distro", distro]
    try:
        out = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120).stdout
        return json.loads(out) if out.strip().startswith("[") else []
    except Exception:
        return []


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# facts, in the shape `yardstick claims agent propose` accepts (evidence[].facts)
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fact(source: str, about: dict, field: str, value: str, url: str = "") -> dict:
    f = {"source": source, "about": about, "field": field, "value": value, "observedAt": now_iso()}
    if url:
        f["url"] = url
    return f


def ubuntu_fact_status(record: dict, source_pkg: str, release: str) -> str:
    """The value an `ubuntu-cve-tracker` fact observes for (package, release): the LAST matching
    status entry, '<status> <description>' trimmed, or 'not-listed' (as delta's ubuntu fact source observes it)."""
    value = "not-listed"
    for p in record.get("packages", []):
        if p["name"] != source_pkg:
            continue
        for s in p["statuses"]:
            if s["release_codename"] == release:
                value = (s["status"] + " " + (s["description"] or "")).strip()
    return value


def ubuntu_facts(record: dict, cve: str, source_pkg: str, release: str, with_upstream: bool = False) -> list[dict]:
    url = f"https://ubuntu.com/security/{cve}"
    out = [fact("ubuntu-cve-tracker", {"vulnerability": cve, "package": source_pkg, "release": release}, "status",
                ubuntu_fact_status(record, source_pkg, release), url),
           fact("ubuntu-cve-tracker", {"vulnerability": cve}, "priority", record.get("priority") or "", url)]
    if with_upstream:
        out.append(fact("ubuntu-cve-tracker", {"vulnerability": cve, "package": source_pkg, "release": "upstream"}, "status",
                        ubuntu_fact_status(record, source_pkg, "upstream"), url))
    return out


def ubuntu_pocket_fact(cve: str, source_pkg: str, release: str, entry: dict) -> dict:
    """A per-pocket status, which ubuntu.com's JSON collapses."""
    return fact("ubuntu-cve-tracker-pocket", {"vulnerability": cve, "package": source_pkg, "release": release, "pocket": entry["pocket"]},
                "status", (entry["status"] + " " + entry["description"]).strip(), f"https://ubuntu.com/security/{cve}")


def cna_fact(cve: str, record: dict | None) -> dict | None:
    if not record:
        return None
    return fact("cve.org", {"vulnerability": cve}, "state", record.get("cveMetadata", {}).get("state", ""),
                f"https://www.cve.org/CVERecord?id={cve}")


# ---------------------------------------------------------------------------
# non-distro ecosystems via OSV
# ---------------------------------------------------------------------------

OSV_ECOSYSTEM = {"pypi": "PyPI", "maven": "Maven", "npm": "npm", "golang": "Go", "gem": "RubyGems", "cargo": "crates.io",
                 "nuget": "NuGet", "composer": "Packagist", "hex": "Hex", "pub": "Pub", "swift": "SwiftURL", "hackage": "Hackage"}


def osv_package_name(p: dict) -> str:
    """The name OSV uses for a purl: maven 'group:artifact', npm '@scope/name', go 'host/org/repo'."""
    t, ns, name = p["type"], p["ns"], p["name"]
    if t == "maven":
        return f"{ns}:{name}"
    if t in ("npm", "golang", "composer") and ns:
        return f"{ns}/{name}"
    return name


def osv_affected_for(vuln_ids: list[str], ecosystem: str, name: str) -> tuple[dict | None, dict | None]:
    """Find the OSV record (trying each id) and its affected entry for (ecosystem, name)."""
    for vid in vuln_ids:
        rec = osv_vuln(vid)
        if not rec:
            continue
        for a in rec.get("affected", []):
            pk = a.get("package") or {}
            if pk.get("ecosystem", "").split(":")[0] == ecosystem and pk.get("name", "").lower() == name.lower():
                return rec, a
        return rec, None
    return None, None


def osv_range_status(affected: dict, version: str) -> tuple[str, str | None]:
    """('affected'|'fixed'|'before-introduced'|'unknown', fixed version). Uses dpkg-style ordering as an approximation."""
    fixed = None
    for r in affected.get("ranges", []):
        if r.get("type") == "GIT":
            continue
        introduced, fixed_here = "0", None
        for e in r.get("events", []):
            if "introduced" in e:
                introduced = e["introduced"]
            if "fixed" in e:
                fixed_here = e["fixed"]
            if "last_affected" in e:
                fixed_here = None
        if introduced != "0" and deb_compare(version, introduced) < 0:
            continue
        if fixed_here and deb_compare(version, fixed_here) >= 0:
            fixed = fixed_here
            continue
        return "affected", fixed_here
    if fixed:
        return "fixed", fixed
    if version in affected.get("versions", []):
        return "affected", None
    return "unknown", None


# ---------------------------------------------------------------------------
# ecosystem version ordering (dpkg above; here: Maven, PEP 440, semver)
# ---------------------------------------------------------------------------

def _tokens(v: str) -> list[str]:
    return [t for t in re.split(r"[.\-_+]", v.strip()) if t != ""]


_MAVEN_QUALIFIERS = {"alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4,
                     "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7}


def _maven_items(v: str) -> list[tuple[int, object]]:
    """Maven ComparableVersion, simplified: split on . - and digit/letter boundaries; numbers rank above
    qualifiers; known qualifiers order alpha < beta < milestone < rc < snapshot < (release) < sp; unknown
    qualifiers sort after known ones, lexically. Trailing zeros/empty qualifiers are trimmed."""
    v = v.strip().lower()
    v = re.sub(r"(\d)([a-z])", r"\1-\2", v)
    v = re.sub(r"([a-z])(\d)", r"\1-\2", v)
    items: list[tuple[int, object]] = []
    for t in re.split(r"[.\-]", v):
        if t == "":
            continue
        if t.isdigit():
            items.append((1, int(t)))
        else:
            q = _MAVEN_QUALIFIERS.get(t)
            items.append((0, (q, "")) if q is not None else (0, (8, t)))
    while items and (items[-1] == (1, 0) or items[-1] == (0, (6, ""))):
        items.pop()
    return items


def maven_compare(a: str, b: str) -> int:
    def cmp_item(x, y) -> int:
        # a missing item behaves like the number 0 / the release qualifier
        if x is None and y is None:
            return 0
        if x is None:
            return -cmp_item(y, None)
        if y is None:
            if x[0] == 1:
                return 1 if x[1] > 0 else 0
            q = x[1][0]
            return -1 if q < 6 else 0 if q == 6 else 1
        if x[0] != y[0]:
            return 1 if x[0] == 1 else -1  # numbers sort above qualifiers
        return -1 if x < y else 1 if x > y else 0

    ia, ib = _maven_items(a), _maven_items(b)
    for i in range(max(len(ia), len(ib))):
        c = cmp_item(ia[i] if i < len(ia) else None, ib[i] if i < len(ib) else None)
        if c:
            return c
    return 0


_PEP_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "rc": 2, "c": 2, "pre": 2, "preview": 2}


def _pep440_key(v: str):
    v = v.strip().lower().lstrip("v")
    m = re.match(r"^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[.\-_]?(a|b|c|rc|alpha|beta|pre|preview)[.\-_]?(\d*))?(?:[.\-_]?(post|rev|r)[.\-_]?(\d*))?(?:[.\-_]?dev[.\-_]?(\d*))?(?:\+.*)?$", v)
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    release = [int(x) for x in m.group(2).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre = (_PEP_PRE[m.group(3)], int(m.group(4) or 0)) if m.group(3) else None
    post = int(m.group(6) or 0) if m.group(5) else None
    dev = int(m.group(7) or 0) if m.group(0) and re.search(r"dev\d*(\+.*)?$", v) else None
    # ordering: dev < pre < final < post, per PEP 440
    pre_key = (0, dev if dev is not None else 1 << 30) if pre is None and dev is not None else (1, pre) if pre else (2, 0)
    if pre and dev is not None:
        pre_key = (1, pre, dev)
    post_key = (post if post is not None else -1,)
    return (epoch, release, pre_key, post_key)


def pep440_compare(a: str, b: str) -> int:
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return deb_compare(a, b)
    return -1 if ka < kb else 1 if ka > kb else 0


def semver_compare(a: str, b: str) -> int:
    def key(v: str):
        v = v.strip().lstrip("v")
        core, _, pre = v.partition("-")
        core = core.split("+")[0]
        nums = [int(x) if x.isdigit() else 0 for x in core.split(".")]
        while len(nums) < 3:
            nums.append(0)
        pre_items = [(0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")] if pre else None
        return (nums, 1 if pre_items is None else 0, pre_items or [])
    ka, kb = key(a), key(b)
    return -1 if ka < kb else 1 if ka > kb else 0


def compare_for(ecosystem: str):
    """The comparator for an OSV ecosystem name (or purl type)."""
    e = (ecosystem or "").lower()
    if e in ("maven",):
        return maven_compare
    if e in ("pypi",):
        return pep440_compare
    if e in ("npm", "go", "golang", "crates.io", "cargo", "nuget", "hex", "pub", "rubygems", "gem", "packagist", "composer", "swifturl"):
        return semver_compare
    return deb_compare


def osv_below_all_ranges(affected_entries: list[dict], version: str, ecosystem: str) -> str | None:
    """The lowest `introduced` version when the installed version is below every range of every entry (so the bug
    was introduced after it); None otherwise or when any range starts at 0."""
    cmp = compare_for(ecosystem)
    lows = []
    for a in affected_entries:
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":
                continue
            intro = next((e["introduced"] for e in r.get("events", []) if "introduced" in e), "0")
            if intro == "0" or cmp(version, intro) >= 0:
                return None
            lows.append(intro)
        if version in (a.get("versions") or []):
            return None
    return min(lows, key=lambda v: [v]) if lows else None


def osv_range_status_for(affected: dict, version: str, ecosystem: str) -> tuple[str, str | None, str]:
    """('affected'|'fixed'|'unknown', fixed version, how) using the ecosystem's ordering. An explicit
    `versions` list wins over range arithmetic when it contains the installed version."""
    if version in (affected.get("versions") or []):
        fixed = next((e["fixed"] for r in affected.get("ranges", []) for e in r.get("events", []) if "fixed" in e), None)
        return "affected", fixed, "listed in the advisory's affected versions"
    cmp = compare_for(ecosystem)
    fixed_seen = None
    for r in affected.get("ranges", []):
        if r.get("type") == "GIT":
            continue
        introduced, fixed_here, last = "0", None, None
        for e in r.get("events", []):
            introduced = e.get("introduced", introduced)
            fixed_here = e.get("fixed", fixed_here)
            last = e.get("last_affected", last)
        if introduced != "0" and cmp(version, introduced) < 0:
            continue
        if fixed_here and cmp(version, fixed_here) >= 0:
            fixed_seen = fixed_here
            continue
        if last and cmp(version, last) > 0:
            continue
        return "affected", fixed_here, f"in range [{introduced}, {fixed_here or last or 'open'})"
    if fixed_seen:
        return "fixed", fixed_seen, f"at or past fixed version {fixed_seen}"
    if affected.get("versions"):
        return "unknown", None, "not in the advisory's affected versions list"
    return "unknown", None, "no range places it"


# ---------------------------------------------------------------------------
# rpm versions (rpmvercmp) and NEVRA parsing
# ---------------------------------------------------------------------------

def _rpm_segments(s: str) -> list:
    out = []
    for m in re.finditer(r"(~)|(\^)|([0-9]+)|([a-zA-Z]+)", s):
        if m.group(1):
            out.append(("~",))
        elif m.group(2):
            out.append(("^",))
        elif m.group(3):
            out.append(("n", int(m.group(3))))
        else:
            out.append(("a", m.group(4)))
    return out


def rpmvercmp(a: str, b: str) -> int:
    """rpm's version segment comparison: numeric > alpha, '~' sorts before anything (even end), '^' after end."""
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    i = 0
    while i < len(sa) or i < len(sb):
        x = sa[i] if i < len(sa) else None
        y = sb[i] if i < len(sb) else None
        if x == y:
            i += 1
            continue
        if x is not None and x[0] == "~":
            return -1
        if y is not None and y[0] == "~":
            return 1
        if x is None:
            return -1 if y[0] != "^" else -1
        if y is None:
            return 1 if x[0] != "^" else 1
        if x[0] == "^" or y[0] == "^":
            return -1 if x[0] == "^" else 1
        if x[0] != y[0]:
            return 1 if x[0] == "n" else -1
        return -1 if x[1] < y[1] else 1
    return 0


def rpm_evr(v: str) -> tuple[int, str, str]:
    """'0:2.28-225.el8_8.6' or '2.28-225.el8' -> (epoch, version, release)."""
    epoch = 0
    if ":" in v.split("-")[0]:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    version, _, release = v.partition("-")
    return epoch, version, release


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = rpm_evr(a)
    eb, vb, rb = rpm_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = rpmvercmp(va, vb)
    if c:
        return c
    if not ra or not rb:
        return 0
    return rpmvercmp(ra, rb)


def rpm_nevra(s: str) -> dict | None:
    """'glibc-0:2.28-225.el8_8.6.x86_64' -> {name, epoch, version, release, arch}; also accepts no-epoch and .src."""
    s = s.split("::", 1)[0]  # modular product ids carry '::<module>:<stream>'
    m = re.match(r"^(?P<name>.+?)-(?:(?P<epoch>\d+):)?(?P<version>[^-]+)-(?P<release>[^-]+?)(?:\.(?P<arch>noarch|src|x86_64|i686|aarch64|ppc64le|s390x|armv7hl))?$", s)
    if not m:
        return None
    d = m.groupdict()
    d["epoch"] = int(d["epoch"] or 0)
    return d


def rpm_dist_minor(release: str) -> str | None:
    """'225.el8_8.6' -> '8.8'; '13.el8' -> '8' (the MAIN stream); None if no dist tag."""
    m = re.search(r"\.el(\d+)(?:[_.](\d+))?", release)
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)
