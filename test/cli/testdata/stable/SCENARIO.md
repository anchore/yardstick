# stable: nothing changed

Both grype versions report the same matches on a deb and an apk image, so the gate passes with real labels behind it. A second gate adds the secureos image, sharing its glibc rows with a third. Every number below was measured from a run of the gates here on a DB built from `vunnel/`.

## Inputs

- images: `ubuntu@sha256:c95b7b93...` (18.10) and `alpine@sha256:ddac200f...` (3.2.3), plus the secureos `grype-test@sha256:3339bcd8...`
- records, plus EPSS for each CVE:
  - ubuntu 18.10: CVE-2016-2781 (coreutils), CVE-2018-20482 (tar), CVE-2019-9169 (libc-bin, libc6)
  - NVD: CVE-2016-9840 and CVE-2016-9841 (zlib), CVE-2018-0732 (libcrypto1.0, libssl1.0). The vunnel alpine data has no 3.2, so grype matches alpine 3.2 by CPE
  - NVD and `secureos:rolling`: CVE-2025-15281 and CVE-2026-95818 on glibc-2.42, which the corpus doesn't label
- labels: `github.com/anchore/match-claims@32064318e375ca3a87ee642bfececd00d701c4de`, then the workspace's `claims/`. The corpus labels all 8 ubuntu and alpine matches tp

## Gate `stable`: grype v0.100.0 (reference) vs v0.120.1 (candidate), ubuntu and alpine

8 matches, all reported by both setups and labeled tp, no changed rows. Every check passes at 0..0. Outcome **pass**, exit 0.

## Gate `shared`: the same two images plus the secureos image

10 matches: 2 of them, CVE-2025-15281 and CVE-2026-95818 on glibc-2.42, dropped by the candidate and unlabeled, each with the reason `record/distro-not-affected` (the candidate DB's `secureos:rolling` record says fixed in 0), secondary `record/same-but-unmatched`.

| check | state | best..worst |
|---|---|---|
| f1NotWorse | undecided | 0..1 |
| noNewFalseNegatives | undecided | 0..2 |
| noNewFalsePositives | pass | 0..0 |
| unlabeledChangesAtMost | fail | 2..2 |

Outcome **fail**: the unlabeled count is measured, not bounded, so 2 over a max of 0 fails.

## Gate `glibc`: the secureos image alone

The same 2 dropped rows, failing the same way. Labeling both fp through this gate moves it to **pass**, and moves `shared` to **pass** with no label written for it. `stable` stays pass.
