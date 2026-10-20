# secureos-glibc: a change that needs labels

grype v0.120.1 stopped reporting NVD CPE matches on the secureos image's glibc-2.42 that the secureos security data lists as not affected (fixed at version "0"). Every number below was measured from a run of the gate here on a DB built from `vunnel/`.

## Inputs

- image: `registry.replicated.com/library/grype-test@sha256:3339bcd8...`, package `pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09`
- records: NVD and `secureos:rolling` records for 9 CVEs, plus their EPSS records:
  - CVE-2010-4756 and CVE-2019-1010022, which the corpus labels fp
  - CVE-2025-15281, CVE-2026-0861, CVE-2026-0915, CVE-2026-18374, CVE-2026-19499 and CVE-2026-89092, which `proposals.jsonl` is about
  - CVE-2026-95818, which nobody researched
- labels: `github.com/anchore/match-claims@32064318e375ca3a87ee642bfececd00d701c4de`, then the workspace's `claims/`
- proposals: `proposals.jsonl` holds 6 lines copied unchanged from the demo's research run, real agent output (claude-sonnet-5-5, research-vuln): 4 fp `vendor-not-affected` and 2 unclear `sources-disagree`. They were recorded for gate `grype-upgrade`, so the test drops that field before `claims agent propose --gate glibc`, which refuses a proposal about another gate

The demo saw 26 glibc rows dropped. The 9 here are the ones with exactly one NVD record each: grype's extractor selects by SQL `LIKE '%<id>%'`, which pulls in any longer id the selection is a prefix of, so CVEs like CVE-2026-4046 (which also selects CVE-2026-40460 to 40469) were left out.

## Gate `glibc`: grype v0.100.0 (reference) vs v0.120.1 (candidate)

`header.varied` is grype alone. 9 of 9 matches are dropped by the candidate, by `apk-matcher`, `nvd:cpe cpe-match`, each with the reason `record/same-but-unmatched`, secondary `match-type/cpe-only`.

| check | state | best..worst |
|---|---|---|
| f1NotWorse | undecided | -1..0.88 |
| noNewFalseNegatives | undecided | 0..7 |
| noNewFalsePositives | pass | 0..0 |
| unjudgedChangesAtMost | undecided | 0..7 |

Outcome **undecided**, exit 1.

- fixed: CVE-2010-4756 and CVE-2019-1010022, fp no longer reported
- review: the other 7, unlabeled. Each one's effect: tp fails f1NotWorse and noNewFalseNegatives, fp changes no state

Recording the 6 proposals changes nothing `score` reports. Labeling all 7 review rows fp, one at a time, ends at **pass** with every check at 0 (f1NotWorse -1).
