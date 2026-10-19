#!/usr/bin/env python3
"""Gather what /yardstick:explain-deltas needs to say why the two scans of one gate differ.

    yardstick-explain-evidence.py load     [--store DIR] [--name RUN] [--gate NAME] [--model ID]
    yardstick-explain-evidence.py excerpt  [--store DIR] [--name RUN] --gate NAME --subject NN --side candidate|reference --lines A-B [--lines C-D ...]
    yardstick-explain-evidence.py records  [--store DIR] [--name RUN] [--gate NAME] --vuln ID [--vuln ID ...] [--pkg NAME] [--cve-org] [--facts-out FILE]
    yardstick-explain-evidence.py releases --from vX --to vY [--repo anchore/grype] [--grep WORD ...] [--pr N ...] [--facts-out FILE]

load reads `yardstick score <gate> -o json`, the run record (.yardstick/runs/<run>/<gate>/yardstick-run.json)
and `yardstick claims explain ls`, decompresses each side's grype log (checking the sha256 the run record
holds, which is of the decompressed text), and writes <store>/.yardstick/explain/<run>/<gate>/:

    gate.md          what varied between the sides, the reason nodes with counts and priority, and per
                     node the rows with their records and, when logs exist, where each row's package is
                     in both logs (line numbers, CPE searches, found counts, the vulnerability's lines)
    nodes.json       the same, machine-readable
    skeletons.jsonl  one `yardstick claims explain propose` line per node with gate, run, author, reason and
                     members filled in; title and note are empty, so propose refuses a line you forgot to write
    logs/<side>/NN.log   the decompressed logs; line numbers in gate.md refer to these

excerpt prints one log excerpt object per --lines range, in the shape `yardstick claims explain propose`
checks ({side, file, lines, text, sha256}), copied from the decompressed log and refused above 8 KiB.
NN is the subject's index in the run record.

records searches each side's DB with that side's grype for each --vuln (and --pkg), prints one line per
provider / namespace / package / fix state, and writes a `grype-db` "providers" fact per side (and with
--cve-org, cve.org's state) to --facts-out.

releases lists the GitHub releases of --repo after --from up to and including --to, with the release
notes' bullet lines (only those matching a --grep word, case-insensitive, when given), and prints a
fact for each matching line and for each --pr (title and merge time). Cached under
~/.cache/yardstick-skills/; set GITHUB_TOKEN to lift the 60/hour limit.

Store: the workspace yardstick runs in, the directory containing .yardstick/ (default $YARDSTICK_ROOT, else cwd). The gate defaults to
$YARDSTICK_GATE, else the gate scanned last; the run name to $YARDSTICK_NAME, else default.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yardstick_common as dc  # noqa: E402

SKILL = "explain-deltas"
MAX_EXCERPT = 8 * 1024
SIDES = ("candidate", "reference")

# Nodes whose rows usually need no explanation in a DB-only gate: a record the newer DB added (or the older
# one lacked). Everything else is worth explaining; grype- or config-varied gates explain every node.
ROUTINE_IN_DB_RUN = {"record/absent-in-reference", "record/absent-in-candidate"}
FOCUS = ["record/rejected-in-candidate", "record/rejected-in-reference", "package/absent-in-reference",
         "package/absent-in-candidate", "namespace/changed", "fix-state/changed", "constraint/changed",
         "record/same-but-unmatched", "match-type/cpe-only", "matcher/changed", "unexplained"]

SEARCH_RE = re.compile(r"searching for vulnerability matches package=(\S+)")
FOUND_RE = re.compile(r"found (\d+) vulnerabilities package=(\S+)")
CPE_FETCH_RE = re.compile(r"fetched CPE record cpe=(\S+) .*records=(\d+)")
PKG_FETCH_RE = re.compile(r"fetched package record distro=(\S+) .*pkg=package\((\w+)=([^)]*)\) records=(\d+)")
TREE_RE = re.compile(r"[├└]── namespace=(\S+) vuln=(\S+)")
DROPPED_RE = re.compile(r"dropped vuln .*reason=(.*?) vulnerability=(\S+)")
DB_DATE_RE = re.compile(r"_(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)_")


# ---------------------------------------------------------------------------
# store and gate
# ---------------------------------------------------------------------------

def store_root(arg: str | None) -> Path:
    p = Path(arg or os.environ.get("YARDSTICK_ROOT") or ".").expanduser().resolve()
    if p.name == ".yardstick":
        p = p.parent
    if not (p / ".yardstick" / "runs").is_dir():
        sys.exit(f"{p} has no .yardstick/runs: pass --store <the directory yardstick ran in>")
    return p


def explanations(ys: str, store: Path, gate: str, name: str) -> list[dict]:
    try:
        return dc.run_json([ys, "claims", "explain", "ls", "--gate", gate, "--name", name, "-o", "json"], store) or []
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return []


def db_date(side: dict) -> str:
    m = DB_DATE_RE.search((side.get("db") or {}).get("source") or "")
    return m.group(1) if m else ""


def grype_version(side: dict) -> str | None:
    return ((side.get("grype") or {}).get("spec") or {}).get("version")


def varied(setups: dict) -> dict:
    """What differs between the run record's setups: grype version, DB (by checksum), config (by sha256), with both values."""
    c, r = setups.get("candidate") or {}, setups.get("reference") or {}
    out = {}
    cg, rg = grype_version(c), grype_version(r)
    if cg != rg:
        out["grype"] = {"candidate": cg, "reference": rg}
    cd, rd = (c.get("db") or {}).get("checksum"), (r.get("db") or {}).get("checksum")
    if cd != rd:
        out["db"] = {"candidate": db_date(c) or cd, "reference": db_date(r) or rd}
    cc, rc = (c.get("config") or {}).get("sha256"), (r.get("config") or {}).get("sha256")
    if cc != rc:
        out["config"] = {"candidate": (c.get("config") or {}).get("path") or "default",
                         "reference": (r.get("config") or {}).get("path") or "default"}
    return out


def node_key(why: dict) -> str:
    return "|".join([why.get("key", ""), why.get("from", "") or "", why.get("to", "") or ""])


def node_priority(key: str, side_dates: dict, var: dict) -> tuple[int, str]:
    """(0 explain first, 1 explain, 2 usually skip) and why, for one computed key in this gate."""
    if "grype" in var or "config" in var:
        return 0, ("grype varied" if "grype" in var else "config varied") + ": every node is a matcher or config effect until shown otherwise"
    if key in ROUTINE_IN_DB_RUN:
        older = min(side_dates, key=lambda s: side_dates[s] or "~") if all(side_dates.values()) else None
        absent_in = key.rsplit("-", 1)[1]
        if older and absent_in == older:
            return 2, f"a record only the newer DB has ({absent_in} is the older DB): routine unless something is odd"
        return 0, f"the {absent_in} DB is the newer one, so the newer DB dropped a record: surprising"
    return (0 if key in FOCUS[:9] else 1), "focus node"


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------

def decompress_log(run_dir: Path, log: dict, dest: Path) -> tuple[Path, bool]:
    """Write the decompressed log to dest; True when its sha256 matches the run record's."""
    text = gzip.decompress((run_dir / log["path"]).read_bytes())
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(text)
    return dest, hashlib.sha256(text).hexdigest() == log.get("sha256")


def purl_key(purl: str) -> str:
    return unquote(purl.split("?")[0])


def package_blocks(lines: list[str]) -> dict[str, list[dict]]:
    """purl (no qualifiers) -> the blocks where grype matched that package: from its "searching for
    vulnerability matches" line to the line before the next package's, with what happened inside."""
    blocks: dict[str, list[dict]] = collections.defaultdict(list)
    cur = None
    for i, line in enumerate(lines, 1):
        m = SEARCH_RE.search(line)
        if m:
            if cur:
                cur["end"] = i - 1
            cur = {"purl": m.group(1), "start": i, "end": len(lines), "found": None, "foundLine": None,
                   "cpeSearches": [], "pkgSearches": [], "tree": [], "dropped": []}
            blocks[purl_key(m.group(1))].append(cur)
            continue
        if not cur:
            continue
        if m := FOUND_RE.search(line):
            cur["found"], cur["foundLine"] = int(m.group(1)), i
        elif m := CPE_FETCH_RE.search(line):
            cur["cpeSearches"].append({"line": i, "cpe": m.group(1), "records": int(m.group(2))})
        elif m := PKG_FETCH_RE.search(line):
            cur["pkgSearches"].append({"line": i, "distro": m.group(1), "by": m.group(2), "value": m.group(3), "records": int(m.group(4))})
        elif m := TREE_RE.search(line):
            cur["tree"].append({"line": i, "namespace": m.group(1), "vulnerability": m.group(2)})
        elif m := DROPPED_RE.search(line):
            cur["dropped"].append({"line": i, "reason": m.group(1).strip(), "vulnerability": m.group(2)})
    return blocks


def row_in_log(blocks: dict[str, list[dict]], purl: str, vulns: set[str]) -> dict | None:
    """Where one row's package is in one side's log, and what that side did with the row's vulnerability."""
    bs = blocks.get(purl_key(purl))
    if not bs:
        return None
    b = bs[0]
    return {"block": [b["start"], b["end"]], "found": b["found"], "foundLine": b["foundLine"],
            "cpeSearches": len(b["cpeSearches"]), "cpeRecords": sum(c["records"] for c in b["cpeSearches"]),
            "firstCpeSearch": b["cpeSearches"][0] if b["cpeSearches"] else None,
            "matched": [t for t in b["tree"] if t["vulnerability"] in vulns],
            "dropped": [d for d in b["dropped"] if d["vulnerability"] in vulns and d["reason"]]}


def cpe_by_type(blocks: dict[str, list[dict]]) -> dict[str, list[int]]:
    """purl type -> [packages, packages grype searched by CPE] over one log: the quickest way to see that one
    side never ran CPE matching for a package type."""
    out: dict[str, list[int]] = {}
    for purl, bs in blocks.items():
        m = re.match(r"pkg:([a-z0-9.+-]+)/", purl)
        t = m.group(1) if m else "other"  # grype logs some packages without a purl
        c = out.setdefault(t, [0, 0])
        c[0] += 1
        c[1] += any(b["cpeSearches"] for b in bs)
    return dict(sorted(out.items()))


def config_dump(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        if "DEBUG gathering packages" in line:
            break
        out.append(line)
    return out


def config_diff(a: list[str], b: list[str]) -> list[str]:
    """Lines of the config dump that differ (version line and timestamps aside), as '- ref' / '+ cand'."""
    import difflib
    skip = re.compile(r"grype version:|^\s*cache-dir:")  # the DB cache dir differs whenever the DB does
    a2 = [x for x in a if not skip.search(x)]
    b2 = [x for x in b if not skip.search(x)]
    return [d for d in difflib.unified_diff(b2, a2, "reference", "candidate", n=0, lineterm="")
            if d[:1] in "+-" and not d.startswith(("+++", "---"))]


def excerpt(text: str, side: str, file: str, sha: str, start: int, end: int) -> dict:
    lines = text.split("\n")
    if start < 1 or end < start or end > len(lines):
        sys.exit(f"lines {start}-{end} are outside {file} ({len(lines)} lines)")
    body = "\n".join(lines[start - 1:end])
    if len(body.encode()) > MAX_EXCERPT:
        sys.exit(f"lines {start}-{end} of {file} are {len(body.encode())} bytes, more than {MAX_EXCERPT}; cite fewer lines")
    return {"side": side, "file": file, "lines": [start, end], "text": body, "sha256": sha}


# ---------------------------------------------------------------------------
# load
# ---------------------------------------------------------------------------

def compact_row(row: dict, subject: int) -> dict:
    side = "candidate" if row.get("inCandidate") else "reference"
    d = row.get(side) or {}
    other = "reference" if side == "candidate" else "candidate"
    return {"row": row["row"], "vulnerability": row["vulnerability"], "aliases": row.get("aliases") or [],
            "package": row["package"], "sourcePackage": row.get("sourcePackage"), "subject": subject,
            "reportedBy": side, "namespace": d.get("namespace"), "fixState": d.get("fixState"),
            "constraints": d.get("constraints") or [], "matchTypes": d.get("matchTypes") or [],
            "matchers": d.get("matchers") or [], "cpes": d.get("cpes") or [],
            "status": {"candidate": row.get("candidateStatus"), "reference": row.get("referenceStatus")},
            "newInCandidate": row.get("newInCandidate"), "otherRecords": row.get(f"{other}Records") or [],
            "why": row["why"], "verdict": row.get("verdict")}


def build_nodes(report: dict, setups: dict, explained: dict[str, str], var: dict) -> list[dict]:
    """report is the scored gate (`score -o json`'s gates[0]); setups the run record's."""
    dates = {s: db_date(setups.get(s) or {}) for s in SIDES}
    nodes: dict[str, dict] = {}
    for i, subj in enumerate(report.get("subjects") or []):
        for row in subj.get("matches") or []:
            if not row.get("why"):
                continue
            k = node_key(row["why"])
            n = nodes.setdefault(k, {"key": row["why"]["key"], "from": row["why"].get("from", ""), "to": row["why"].get("to", ""),
                                     "rows": [], "explained": 0})
            r = compact_row(row, i)
            if row["row"] in explained:
                r["explanation"] = explained[row["row"]]
                n["explained"] += 1
            n["rows"].append(r)
    out = []
    for n in nodes.values():
        n["priority"], n["priorityWhy"] = node_priority(n["key"], dates, var)
        n["secondary"] = dict(collections.Counter(",".join(s["key"] for s in r["why"].get("secondary") or []) or "-" for r in n["rows"]))
        n["sides"] = dict(collections.Counter(r["reportedBy"] for r in n["rows"]))
        out.append(n)
    out.sort(key=lambda n: (n["priority"], FOCUS.index(n["key"]) if n["key"] in FOCUS else 0, -len(n["rows"])))
    for i, n in enumerate(out, 1):
        n["node"] = i
    return out


def attach_logs(nodes: list[dict], report: dict, run: dict, run_dir: Path, out: Path) -> dict:
    """Decompress every subject's logs, find each row's package in both, and diff the config dumps.
    Nodes number subjects as the scored gate does; logs are the run record's, by subject name."""
    subjects = report.get("subjects") or []
    logs = dc.subject_logs(run)
    index = {s["name"]: n for n, s in enumerate(run.get("subjects") or [])}
    info = {"subjects": [], "configDiff": None}
    blocks: dict[tuple[int, str], dict] = {}
    for i, s in enumerate(subjects):
        entry = {"subject": i, "ref": s["name"], "runIndex": index.get(s["name"])}
        dumps = {}
        for side in SIDES:
            log = logs.get(s["name"], {}).get(side)
            if not log:
                continue
            dest = out / "logs" / Path(log["path"]).with_suffix("")
            path, ok = decompress_log(run_dir, log, dest)
            lines = path.read_text(errors="replace").split("\n")
            entry[side] = {"file": log["path"], "sha256": log["sha256"], "decompressed": str(path), "lines": len(lines), "shaOk": ok}
            blocks[(i, side)] = package_blocks(lines)
            entry[side]["cpeByType"] = cpe_by_type(blocks[(i, side)])
            dumps[side] = config_dump(lines)
        if len(dumps) == 2 and info["configDiff"] is None:
            info["configDiff"] = config_diff(dumps["candidate"], dumps["reference"])
        info["subjects"].append(entry)
    for n in nodes:
        for r in n["rows"]:
            vulns = {r["vulnerability"], *r["aliases"]}
            r["logs"] = {side: row_in_log(blocks[(r["subject"], side)], r["package"], vulns)
                         for side in SIDES if (r["subject"], side) in blocks}
        n["logSummary"] = log_summary(n["rows"])
    return info


def log_summary(rows: list[dict]) -> dict:
    """Per side, over the node's distinct packages: how many the log has, how many it searched by CPE,
    and how many rows' vulnerability it matched or dropped."""
    out = {}
    for side in SIDES:
        pk = {}
        matched = dropped = 0
        for r in rows:
            lg = (r.get("logs") or {}).get(side)
            if lg is None and side not in (r.get("logs") or {}):
                continue
            pk[(r["subject"], r["package"])] = lg
            matched += bool(lg and lg["matched"])
            dropped += bool(lg and lg["dropped"])
        if pk:
            out[side] = {"packages": len(pk), "inLog": sum(1 for v in pk.values() if v),
                         "searchedByCpe": sum(1 for v in pk.values() if v and v["cpeSearches"]),
                         "rowsMatched": matched, "rowsDropped": dropped}
    return out


def skeleton(n: dict, gate: str, run: str, model: str) -> dict:
    slug = re.sub(r"[^a-z0-9]+", "-", f"{n['key']} {n['from']} {n['to']}".lower()).strip("-")
    return {"id": f"expl-{run}-{gate}-{slug}", "gate": gate, "run": run, "title": "", "note": "", "reason": n["key"],
            "members": [{"row": r["row"], "vulnerability": r["vulnerability"], "package": r["package"]}
                        for r in n["rows"] if "explanation" not in r],
            "facts": [], "logExcerpts": [], "openQuestions": [],
            "author": {"kind": "agent", "skill": SKILL, "model": model}}


def fmt_records(recs: list[dict]) -> str:
    if not recs:
        return "none"
    parts = []
    for x in recs[:4]:
        where = x.get("namespace", "")
        what = x.get("cpe") or x.get("package") or ""
        cons = "; ".join(x.get("constraints") or [])[:80]
        parts.append(f"{where} {what} [{'/'.join(x.get('fixStates') or [])}] {cons}".strip())
    return " | ".join(parts) + (f" (+{len(recs) - 4} more)" if len(recs) > 4 else "")


def fmt_log(lg: dict | None) -> str:
    if lg is None:
        return "package not in this log"
    bits = [f"block {lg['block'][0]}-{lg['block'][1]}", f"found {lg['found']} at {lg['foundLine']}" if lg["foundLine"] else "no 'found N' line (grype logs none for 0 matches)",
            f"{lg['cpeSearches']} CPE searches ({lg['cpeRecords']} records)"]
    if lg["firstCpeSearch"]:
        bits.append(f"first CPE search at {lg['firstCpeSearch']['line']}")
    if lg["matched"]:
        bits.append("matched at " + ", ".join(f"{t['line']} ({t['namespace']})" for t in lg["matched"]))
    if lg["dropped"]:
        bits.append("dropped at " + ", ".join(f"{d['line']} ({d['reason']})" for d in lg["dropped"][:3]))
    if not lg["matched"] and not lg["dropped"]:
        bits.append("vulnerability not mentioned")
    return "; ".join(bits)


def write_md(path: Path, gate: str, setups: dict, var: dict, nodes: list[dict], loginfo: dict | None, expl: list[dict]) -> None:
    c, r = setups.get("candidate") or {}, setups.get("reference") or {}
    L = [f"# Explain gate {gate}", ""]
    for name, s in (("candidate", c), ("reference", r)):
        L.append(f"- {name}: grype {grype_version(s)}, DB {db_date(s) or (s.get('db') or {}).get('checksum')}"
                 f" ({(s.get('db') or {}).get('source')}), config {(s.get('config') or {}).get('path') or 'default'}")
    changed = ", ".join(f"{k} ({v['reference']} -> {v['candidate']})" for k, v in var.items())
    L.append(f"- varied: {changed or 'nothing (same grype, DB and config)'}")
    L.append(f"- grype logs: {'kept (see below)' if loginfo else 'none (the run kept no logs; rerun the gate with a yardstick that keeps them)'}")
    if loginfo:
        bad = [f"{e['subject']}/{side}" for e in loginfo["subjects"] for side in SIDES if side in e and not e[side]["shaOk"]]
        L.append(f"- logs decompressed to {path.parent / 'logs'}" + (f"; SHA MISMATCH for {', '.join(bad)}" if bad else "; every sha256 matches the run record"))
        L.append("- CPE searches per subject and package type (packages searched by CPE / packages):")
        for e in loginfo["subjects"]:
            cells = []
            for side in SIDES:
                if side in e:
                    cells.append(side + " " + ", ".join(f"{t} {v[1]}/{v[0]}" for t, v in e[side]["cpeByType"].items()))
            L.append(f"    - s{e['subject']:02d} (run record subject {e['runIndex']:02d}) {e['ref'][:70]}: " + "; ".join(cells))
        cd = loginfo["configDiff"]
        L.append("- config dump (subject 0): " + ("identical on both sides" if not cd else "differs:"))
        L += [f"    {d}" for d in (cd or [])[:40]]
    L.append(f"- existing explanations: {len(expl)}" + "".join(f"\n    - {e['id']}: {e['title']} ({len(e.get('members') or [])} rows)" for e in expl))
    L += ["", "## Nodes", "", "| node | key | from -> to | rows | explained | sides | priority |", "|---|---|---|---|---|---|---|"]
    for n in nodes:
        L.append(f"| {n['node']} | {n['key']} | {n['from']} -> {n['to']} | {len(n['rows'])} | {n['explained']} | "
                 f"{', '.join(f'{k} {v}' for k, v in n['sides'].items())} | {['first', 'explain', 'usually skip'][n['priority']]}: {n['priorityWhy']} |")
    for n in nodes:
        L += ["", f"## Node {n['node']}: {n['key']} {n['from']} -> {n['to']} ({len(n['rows'])} rows)", "",
              f"secondary: {n['secondary']}"]
        if n.get("logSummary"):
            for side, s in n["logSummary"].items():
                L.append(f"{side} log: {s['inLog']}/{s['packages']} packages present, {s['searchedByCpe']} searched by CPE, "
                         f"{s['rowsMatched']} rows matched, {s['rowsDropped']} rows dropped with a reason")
        L.append("")
        for x in n["rows"]:
            ex = f" [explained: {x['explanation']}]" if x.get("explanation") else ""
            L.append(f"- `{x['row']}` s{x['subject']:02d} {x['vulnerability']} {dc.parse_purl(x['package'])['name']}@"
                     f"{dc.parse_purl(x['package'])['version']} by {x['reportedBy']}{ex}: {x['namespace']} {x['fixState']} "
                     f"{'/'.join(x['matchTypes'])} {'/'.join(x['matchers'])}; status c={x['status']['candidate']} r={x['status']['reference']}")
            if x["cpes"]:
                L.append(f"    - cpes: {', '.join(x['cpes'][:3])}")
            L.append(f"    - constraints: {'; '.join(x['constraints'])[:160]}")
            L.append(f"    - other DB's records: {fmt_records(x['otherRecords'])}")
            for side, lg in (x.get("logs") or {}).items():
                L.append(f"    - {side} log: {fmt_log(lg)}")
    path.write_text("\n".join(L) + "\n")


def cmd_load(a) -> None:
    store = store_root(a.store)
    name = dc.run_name(a.name)
    run_dir, run = dc.load_run(store, name, a.gate)
    gate = run["gate"]["name"]
    ys = dc.find_yardstick(store)
    report = dc.score(ys, store, name, run)
    setups = run.get("setups") or {}
    expl = explanations(ys, store, gate, name)
    explained = {m["row"]: e["id"] for e in expl for m in e.get("members") or []}
    var = varied(setups)
    nodes = build_nodes(report, setups, explained, var)
    out = store / ".yardstick" / "explain" / name / gate
    out.mkdir(parents=True, exist_ok=True)
    has_logs = any(dc.subject_logs(run).values())
    loginfo = attach_logs(nodes, report, run, run_dir, out) if has_logs else None
    (out / "nodes.json").write_text(json.dumps({"gate": gate, "run": name, "varied": var, "logs": loginfo, "nodes": nodes}, indent=1))
    with (out / "skeletons.jsonl").open("w") as f:
        for n in nodes:
            sk = skeleton(n, gate, name, a.model)
            if sk["members"]:
                f.write(json.dumps(sk) + "\n")
    write_md(out / "gate.md", gate, setups, var, nodes, loginfo, expl)
    total = sum(len(n["rows"]) for n in nodes)
    print(f"gate {gate} (run {name}): {total} differing rows in {len(nodes)} nodes; varied: {', '.join(var) or 'nothing'}; "
          f"logs: {'yes' if has_logs else 'no'}; {len(explained)} rows already explained", file=sys.stderr)
    print(out / "gate.md")


# ---------------------------------------------------------------------------
# excerpt
# ---------------------------------------------------------------------------

def cmd_excerpt(a) -> None:
    store = store_root(a.store)
    run_dir, meta = dc.load_run(store, dc.run_name(a.name), a.gate)
    subj = meta["subjects"][int(a.subject)]
    log = (subj.get("logs") or {}).get(a.side)
    if not log:
        sys.exit(f"subject {a.subject} has no {a.side} log")
    raw = gzip.decompress((run_dir / log["path"]).read_bytes())
    if hashlib.sha256(raw).hexdigest() != log["sha256"]:
        sys.exit(f"{log['path']} doesn't match the sha256 in the run record")
    text = raw.decode(errors="replace")
    for rng in a.lines:
        s, _, e = rng.partition("-")
        print(json.dumps(excerpt(text, a.side, log["path"], log["sha256"], int(s), int(e or s))))


# ---------------------------------------------------------------------------
# releases
# ---------------------------------------------------------------------------

PR_RE = re.compile(r"/pull/(\d+)")


def releases_between(releases: list[dict], lo: str, hi: str) -> list[dict]:
    """Releases with lo < tag <= hi (semver order), oldest first; drafts and prereleases left out."""
    keep = [x for x in releases if not x.get("draft") and not x.get("prerelease") and x.get("tag_name")
            and dc.semver_compare(x["tag_name"], lo) > 0 and dc.semver_compare(x["tag_name"], hi) <= 0]
    return sorted(keep, key=lambda x: [int(p) if p.isdigit() else 0 for p in x["tag_name"].lstrip("v").split("-")[0].split(".")])


def note_lines(body: str, words: list[str]) -> list[str]:
    out = []
    for line in (body or "").splitlines():
        s = line.strip()
        if not s.startswith(("- ", "* ")) or "→" in s:  # bullets only; skip dependency bumps
            continue
        if not words or any(w.lower() in s.lower() for w in words):
            out.append(s[2:])
    return out


def cmd_releases(a) -> None:
    owner_repo = a.repo
    rels = []
    for page in (1, 2, 3):
        got = dc.fetch_json(f"https://api.github.com/repos/{owner_repo}/releases?per_page=100&page={page}", headers=dc.github_headers())
        if not got:
            break
        rels += got
        if len(got) < 100:
            break
    if not rels:
        sys.exit(f"no releases fetched for {owner_repo} (rate limit? set GITHUB_TOKEN)")
    facts = []
    for rel in releases_between(rels, a.frm, a.to):
        lines = note_lines(rel.get("body") or "", a.grep)
        print(f"## {rel['tag_name']} ({rel.get('published_at', '')[:10]}) {rel['html_url']}")
        for line in lines:
            print(f"- {line}")
            prs = PR_RE.findall(line)
            facts.append(dc.fact("grype-release" if owner_repo == "anchore/grype" else "github-release",
                                 {"repo": owner_repo, "release": rel["tag_name"], **({"pr": prs[0]} if prs else {})},
                                 "release-note", line, rel["html_url"]))
        print()
    print(f"compare: https://github.com/{owner_repo}/compare/{a.frm}...{a.to}")
    for pr in a.pr:
        d = dc.fetch_json(f"https://api.github.com/repos/{owner_repo}/pulls/{pr}", headers=dc.github_headers())
        if not d:
            print(f"PR {pr}: not fetched", file=sys.stderr)
            continue
        print(f"PR #{pr}: {d.get('title')} (merged {d.get('merged_at')}, {d.get('merge_commit_sha', '')[:12]}) {d.get('html_url')}")
        facts.append(dc.fact("github-pr", {"repo": owner_repo, "pr": str(pr)}, "title", d.get("title") or "", d.get("html_url") or ""))
        if d.get("merged_at"):
            facts.append(dc.fact("github-pr", {"repo": owner_repo, "pr": str(pr)}, "merged-at", d["merged_at"], d.get("html_url") or ""))
    print("\n# facts (evidence fact shape)")
    for f in facts:
        print(json.dumps(f))
    if a.facts_out:
        Path(a.facts_out).write_text("".join(json.dumps(f) + "\n" for f in facts))
        print(f"wrote {len(facts)} facts to {a.facts_out}", file=sys.stderr)


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

def summarize_records(out: list) -> list[str]:
    """One line per (provider, namespace, package, fix state) from `grype db search -o json`."""
    lines = set()
    for r in out:
        v = r.get("vulnerability") or {}
        for p in r.get("packages") or [{}]:
            ranges = (p.get("detail") or {}).get("ranges") or [{}]
            fix = "/".join(sorted({(x.get("fix") or {}).get("state") or "?" for x in ranges}))
            what = (p.get("package") or {}).get("name") or (p.get("cpes") or [""])[0]
            lines.add(f"{v.get('provider')} {v.get('status')} {p.get('namespace', '')} {what} [{fix}]".strip())
    return sorted(lines)


def cmd_records(a) -> None:
    store = store_root(a.store)
    _, meta = dc.load_run(store, dc.run_name(a.name), a.gate)
    setups = meta.get("setups") or {}
    facts = []
    for vuln in a.vuln:
        print(f"## {vuln}")
        if a.cve_org and vuln.startswith("CVE-"):
            m = (dc.cve_org(vuln) or {}).get("cveMetadata") or {}
            state = f"{m.get('state')}" + (f" ({m['dateRejected'][:10]})" if m.get("dateRejected") else "")
            print(f"cve.org: {state}")
            facts.append(dc.fact("cve.org", {"vulnerability": vuln}, "state", state, f"https://www.cve.org/CVERecord?id={vuln}"))
        for side in SIDES:
            if side not in setups:
                continue
            sd = setups[side]
            db = sd.get("db") or {}
            grype, cache_dir = dc.side_grype_and_db(sd)
            if not grype or not cache_dir:
                print(f"{side}: cannot search (grype {grype or 'not found'}, DB cache {cache_dir or 'not found for ' + str(db.get('checksum'))})")
                continue
            env = {**__import__("os").environ, "GRYPE_DB_CACHE_DIR": cache_dir, "GRYPE_DB_AUTO_UPDATE": "false",
                   "GRYPE_DB_VALIDATE_AGE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
            cmd = [grype, "db", "search", "--vuln", vuln, "-o", "json"] + (["--pkg", a.pkg] if a.pkg else [])
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=180)
            try:
                out = json.loads(res.stdout) if res.stdout.strip().startswith("[") else []
            except json.JSONDecodeError:
                out = []
            lines = summarize_records(out)
            when = db_date(sd) or db.get("checksum", "")
            print(f"{side} DB {when}: " + ("no records" if not lines else ""))
            for line in lines[:12]:
                print(f"    {line}")
            if len(lines) > 12:
                print(f"    (+{len(lines) - 12} more; pass --pkg to narrow)")
            facts.append(dc.fact("grype-db", {"vulnerability": vuln, "db": f"{side} {when}", "checksum": db.get("checksum", ""),
                                              **({"package": a.pkg} if a.pkg else {})},
                                 "providers", ", ".join(sorted({x.split()[0] for x in lines})) or "none"))
        print()
    if a.facts_out:
        Path(a.facts_out).write_text("".join(json.dumps(f) + "\n" for f in facts))
        print(f"wrote {len(facts)} facts to {a.facts_out}", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("load")
    p.add_argument("--store")
    p.add_argument("--name")
    p.add_argument("--gate")
    p.add_argument("--model", default="unknown")
    p.set_defaults(fn=cmd_load)
    p = sub.add_parser("excerpt")
    p.add_argument("--store")
    p.add_argument("--name")
    p.add_argument("--gate", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--side", required=True, choices=SIDES)
    p.add_argument("--lines", required=True, action="append", help="A-B, 1-based and inclusive; repeat for several excerpts")
    p.set_defaults(fn=cmd_excerpt)
    p = sub.add_parser("releases")
    p.add_argument("--repo", default="anchore/grype")
    p.add_argument("--from", dest="frm", required=True, help="the reference's version (excluded)")
    p.add_argument("--to", required=True, help="the candidate's version (included)")
    p.add_argument("--grep", action="append", default=[])
    p.add_argument("--pr", action="append", default=[])
    p.add_argument("--facts-out", help="also write the facts, one JSON object per line, to this file")
    p.set_defaults(fn=cmd_releases)
    p = sub.add_parser("records")
    p.add_argument("--store")
    p.add_argument("--name")
    p.add_argument("--gate")
    p.add_argument("--vuln", action="append", required=True)
    p.add_argument("--pkg")
    p.add_argument("--cve-org", action="store_true", help="also record cve.org's state (REJECTED and its date)")
    p.add_argument("--facts-out")
    p.set_defaults(fn=cmd_records)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
