#!/usr/bin/env python3
"""Tests for yardstick-explain-evidence.py, offline. python3 -I plugin/scripts/test_explain.py"""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
ex = importlib.import_module("yardstick-explain-evidence")

failures = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        failures.append(f"{name}: {detail}")


# Trimmed from a real grype v0.120.1 trace log (UBI8, libarchive) and its v0.119.0 counterpart.
CAND = """[0000]  INFO grype version: 0.120.1
[0000] DEBUG config:
  match:
      rpm:
          using-cpes: true
  db:
      cache-dir: /cache/sha256-aaa
[0000] DEBUG gathering packages
[0000] TRACE searching for vulnerability matches package=pkg:rpm/redhat/libarchive@3.3.3-3.el8_5?arch=aarch64&distro=rhel-8.6
[0000] TRACE fetched package record distro=redhat@8.6 duration=1.9ms pkg=package(name=libarchive) records=24 vulns=any
[0000] TRACE dropped vuln context=&{Version:0:3.3.3-3.el8_5 (RPM)} op=filterVulns reason= vulnerability=CVE-2021-23177
[0000] TRACE dropped vuln context=[0x236ecb5337d0] op=filterVulns reason=no vulnerabilities matched criteria vulnerability=CVE-2021-23177
[0000] TRACE fetched CPE record cpe=cpe:2.3:a:libarchive:libarchive:3.3.3-3.el8_5:*:*:*:*:*:*:* duration=564.834µs records=74
[0000] DEBUG found 2 vulnerabilities package=pkg:rpm/redhat/libarchive@3.3.3-3.el8_5?arch=aarch64&distro=rhel-8.6
[0000] TRACE   ├── namespace=nvd:cpe vuln=CVE-2021-23177
[0000] TRACE   └── namespace=redhat:distro:redhat:8 vuln=CVE-2025-5914
[0000] TRACE searching for vulnerability matches package=pkg:rpm/redhat/zlib@1.2.11-18.el8_5?arch=aarch64
[0000] TRACE fetched CPE record cpe=cpe:2.3:a:zlib:zlib:1.2.11-18.el8_5:*:*:*:*:*:*:* duration=50µs records=0
[0000] TRACE searching for vulnerability matches package=pkg:pypi/six@1.16.0
"""
REF = CAND.replace("0.120.1", "0.119.0").replace("sha256-aaa", "sha256-bbb")
REF = "\n".join(line for line in REF.split("\n") if "fetched CPE record" not in line and "nvd:cpe" not in line)

cb = ex.package_blocks(CAND.split("\n"))
rb = ex.package_blocks(REF.split("\n"))
purl = "pkg:rpm/redhat/libarchive@3.3.3-3.el8_5?arch=aarch64&distro=rhel-8.6&upstream=libarchive-3.3.3-3.el8_5.src.rpm"
c = ex.row_in_log(cb, purl, {"CVE-2021-23177"})
r = ex.row_in_log(rb, purl, {"CVE-2021-23177"})
check("block found by purl without qualifiers", c is not None and r is not None, f"{c} {r}")
check("candidate block bounds", c and c["block"] == [9, 16], f"{c and c['block']}")
check("candidate CPE search", c and c["cpeSearches"] == 1 and c["cpeRecords"] == 74 and c["firstCpeSearch"]["line"] == 13, f"{c}")
check("candidate matched by nvd:cpe", c and [t["namespace"] for t in c["matched"]] == ["nvd:cpe"], f"{c and c['matched']}")
check("candidate drop with a reason only", c and len(c["dropped"]) == 1 and c["dropped"][0]["reason"] == "no vulnerabilities matched criteria", f"{c}")
check("reference made no CPE search", r and r["cpeSearches"] == 0 and not r["matched"], f"{r}")
check("found line", c and c["found"] == 2 and c["foundLine"] == 14, f"{c}")
check("missing package", ex.row_in_log(cb, "pkg:rpm/redhat/nope@1", set()) is None)
check("percent-encoded purls match", ex.purl_key("pkg:deb/ubuntu/libx11-6@2%3A1.6.9?arch=amd64") == "pkg:deb/ubuntu/libx11-6@2:1.6.9")

check("cpe by type, candidate", ex.cpe_by_type(cb) == {"pypi": [1, 0], "rpm": [2, 2]}, f"{ex.cpe_by_type(cb)}")
check("cpe by type, reference", ex.cpe_by_type(rb) == {"pypi": [1, 0], "rpm": [2, 0]}, f"{ex.cpe_by_type(rb)}")

dc_ = ex.config_diff(ex.config_dump(CAND.split("\n")), ex.config_dump(REF.split("\n")))
check("config diff ignores version and cache dir", dc_ == [], f"{dc_}")
dc2 = ex.config_diff(ex.config_dump(CAND.split("\n")), ex.config_dump(REF.replace("using-cpes: true", "using-cpes: false").split("\n")))
check("config diff shows a changed key", dc2 == ["-          using-cpes: false", "+          using-cpes: true"], f"{dc2}")

text = "a\nb\nc\n"
x = ex.excerpt(text, "candidate", "candidate/00.log.gz", "0" * 64, 2, 3)
check("excerpt text", x["text"] == "b\nc" and x["lines"] == [2, 3], f"{x}")
try:
    ex.excerpt("x" * 9000, "candidate", "f", "0" * 64, 1, 1)
    check("excerpt size cap", False, "no error over 8 KiB")
except SystemExit:
    pass

# a run record's setup
side = lambda g, db, cfg=None: {"grype": {"spec": {"name": "grype", "version": g}}, "db": {"checksum": db, "source": f"/x/vulnerability-db_v6_{db}_1.tar.zst"},
                                "config": cfg}
v = ex.varied({"candidate": side("v0.120.1", "2026-02-20T00:29:07Z"), "reference": side("v0.119.0", "2026-02-20T00:29:07Z")})
check("grype varied", list(v) == ["grype"] and v["grype"]["reference"] == "v0.119.0", f"{v}")
v = ex.varied({"candidate": side("v1", "2026-10-06T00:34:33Z"), "reference": side("v1", "2026-02-20T00:29:07Z")})
check("db varied, dates", list(v) == ["db"] and v["db"]["candidate"] == "2026-10-06T00:34:33Z", f"{v}")

dates = {"candidate": "2026-10-06T00:34:33Z", "reference": "2026-02-20T00:29:07Z"}
check("new record in newer DB is routine", ex.node_priority("record/absent-in-reference", dates, {"db": {}})[0] == 2)
check("record dropped by newer DB is surprising", ex.node_priority("record/absent-in-candidate", dates, {"db": {}})[0] == 0)
check("grype varied explains everything", ex.node_priority("record/absent-in-reference", dates, {"grype": {}})[0] == 0)
check("rejected is a focus node", ex.node_priority("record/rejected-in-candidate", dates, {"db": {}})[0] == 0)

rels = [{"tag_name": t, "draft": False, "prerelease": False} for t in ("v0.118.0", "v0.119.0", "v0.120.0", "v0.120.1", "v0.121.0")]
got = [x["tag_name"] for x in ex.releases_between(rels, "v0.119.0", "v0.120.1")]
check("releases between", got == ["v0.120.0", "v0.120.1"], f"{got}")
body = "### Bug Fixes\n\n- `match.rpm.using-cpes` has no effect [PR [#3753](https://github.com/anchore/grype/pull/3753)]\n- other fix\n" \
       "- github.com/anchore/syft `v1.52.0` → `v1.54.0`\n"
check("note lines grep", ex.note_lines(body, ["using-cpes"]) == [body.split("\n")[2][2:]], f"{ex.note_lines(body, ['using-cpes'])}")
check("note lines skip dependency bumps", len(ex.note_lines(body, [])) == 2, f"{ex.note_lines(body, [])}")

recs = [{"vulnerability": {"provider": "ubuntu", "status": "active"},
         "packages": [{"namespace": "ubuntu:distro:ubuntu:20.04", "package": {"name": "ncurses"},
                       "detail": {"ranges": [{"fix": {"state": "not-fixed"}}]}}]}]
check("record summary", ex.summarize_records(recs) == ["ubuntu active ubuntu:distro:ubuntu:20.04 ncurses [not-fixed]"], f"{ex.summarize_records(recs)}")

# a `yardstick score -o json` match row
row = {"id": "abc/CVE-1", "row": "r1", "vulnerability": "CVE-1", "aliases": ["CVE-1"], "inCandidate": True, "inReference": False,
       "package": "pkg:rpm/redhat/zlib@1", "candidate": {"namespace": "nvd:cpe", "matchTypes": ["cpe-match"]},
       "why": {"key": "record/same-but-unmatched", "secondary": [{"key": "match-type/cpe-only"}]}}
row2 = dict(row, row="r2", vulnerability="CVE-2")
report = {"name": "g", "subjects": [{"name": "oci:x", "matches": [row, row2, {"row": "r3"}]}]}
nodes = ex.build_nodes(report, {"candidate": side("v2", "d"), "reference": side("v1", "d")}, {"r2": "expl-old"}, {"grype": {}})
check("one node, both rows", len(nodes) == 1 and len(nodes[0]["rows"]) == 2 and nodes[0]["explained"] == 1, f"{nodes}")
sk = ex.skeleton(nodes[0], "GATE", "RUN", "m")
check("skeleton leaves explained rows out", [m["row"] for m in sk["members"]] == ["r1"], f"{sk['members']}")
check("skeleton id and empty title", sk["id"] == "expl-RUN-GATE-record-same-but-unmatched" and sk["title"] == "" and sk["reason"] == "record/same-but-unmatched", f"{sk}")
check("skeleton names gate and run", sk["gate"] == "GATE" and sk["run"] == "RUN", f"{sk}")

# yardstick-vuln-sources.py names files from external data (a Go module name holds '/'); each stays in the output dir
import tempfile  # noqa: E402
vs = importlib.import_module("yardstick-vuln-sources")
with tempfile.TemporaryDirectory() as d:
    out = Path(d) / "out"
    out.mkdir()
    for name in ("../x", "a/b", "row-candidate-github.com/foo/bar.json", "/etc/passwd"):
        p = vs.save(out, name, "x")
        check(f"save keeps {name} inside", p.parent == out.resolve() and p.exists(), f"{p}")
    for bad in (".", ".."):
        try:
            vs.save(out, bad, "x")
            check(f"save refuses {bad}", False)
        except ValueError:
            pass
    check("no file escaped", sorted(x.name for x in Path(d).iterdir()) == ["out"], f"{list(Path(d).iterdir())}")
    check("sanitizer", vs.safe_part("golang.org/x/net") == "golang.org_x_net" and vs.safe_part("1:2.3+dfsg-1") == "1_2.3+dfsg-1", "")

print("ok" if not failures else "\n".join(failures))
sys.exit(1 if failures else 0)
