#!/usr/bin/env python3
"""Spot checks for the ecosystem version comparators. python3 -I plugin/scripts/test_versions.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yardstick_common as dc  # noqa: E402

cases = {
    dc.maven_compare: [("9.1.0.M0", "9.4.39", -1), ("9.1.0.M0", "9.1.0", -1), ("9.1.0.M0", "7.2.2", 1), ("1.0-alpha1", "1.0", -1),
                       ("1.0-SNAPSHOT", "1.0", -1), ("1.0", "1.0.0", 0), ("1.0-sp1", "1.0", 1), ("2.0.1", "2.0.1.Final", 0),
                       ("1.0-rc1", "1.0-beta2", 1), ("9.4.43.v20210629", "9.4.39", 1), ("9.4.43.v20210629", "9.4.43", 1),
                       ("1.2.3-RC2", "1.2.3", -1), ("5.3.0.RELEASE", "5.3.0", 0), ("1.0a", "1.0", -1), ("1.4.11.1", "1.4.14", -1),
                       ("2.13.0", "2.12.6", 1), ("3.17.0.7439", "3.17.0", 1)],
    dc.pep440_compare: [("3.8.1", "3.8.2", -1), ("2.13.0", "2.13", 0), ("1.0rc1", "1.0", -1), ("1.0.post1", "1.0", 1),
                        ("1.0.dev1", "1.0a1", -1), ("2.28.1", "2.28.1", 0), ("65.3.0", "65.3", 0), ("4.3.4", "4.3.6", -1),
                        ("1.26.12", "1.26.9", 1), ("0.4.8", "0.4.8", 0), ("2.0.0b1", "2.0.0", -1)],
    dc.semver_compare: [("1.2.3", "1.10.0", -1), ("1.0.0-alpha", "1.0.0", -1), ("v1.2.3", "1.2.3", 0), ("1.0.0-rc.1", "1.0.0-beta.11", 1)],
    dc.deb_compare: [("2.2.9-1ubuntu0.8", "2.2.9-1ubuntu0.8+esm3", -1), ("1:2.34-0.1ubuntu9.3", "2.41.3-1", 1), ("9.50~dfsg", "9.50", -1)],
}
cna_text = [("< 1.4.16", ("0", "1.4.16", False)), ("<= 2.4.16", ("0", "2.4.16", True)), (">= 1.6.0, < 1.6.51", ("1.6.0", "1.6.51", False)),
            ("5.0.0 - 5.15.5", ("5.0.0", "5.15.5", True)), ("0 <2.8.3", ("0", "2.8.3", False)), ("nasm-3.02rc5", None), ("patch: 0:1.13.1-8.el9", None)]
bad = 0
for text, want in cna_text:
    got = dc._parse_version_text(text)
    if got != want:
        bad += 1
        print(f"_parse_version_text({text!r}) = {got}, want {want}")
for fn, cs in cases.items():
    for a, b, want in cs:
        got = fn(a, b)
        if got != want:
            bad += 1
            print(f"{fn.__name__}({a!r}, {b!r}) = {got}, want {want}")
print("ok" if not bad else f"{bad} failures")
sys.exit(1 if bad else 0)
