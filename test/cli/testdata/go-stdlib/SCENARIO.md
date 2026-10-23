# go-stdlib: a regression labels can't fix

grype v0.115.0 flipped `match.golang.always-use-cpe-for-stdlib` to false, so grype v0.120.1 stops matching the Go stdlib by CPE. Every number below was measured from a run of the gates here on a DB built from `vunnel/`.

## Inputs

- image: `grype-quality-golang:d89207b@sha256:7536ee34...`, its stdlib 1.16.9 and 1.18.4
- records: NVD for CVE-2020-29509, CVE-2020-29511, CVE-2021-29923 (the corpus labels them tp on stdlib 1.16.9), CVE-2021-44716 (labeled fp), CVE-2022-1705 and CVE-2022-1962 (unlabeled), plus their EPSS records. None of them affects stdlib 1.18.4
- labels: `github.com/anchore/claims@dc0289a3a409265fb2c37d3526ec94385998cfcb`, then the workspace's `claims/`

Every gate here also runs the implicit `matchesAtLeast` (min 1), which counts both setups' matches on each subject. It passes in every run below, so the tables leave it out.

## Gate `go-upgrade`: grype v0.100.0 (reference) vs v0.120.1 (candidate)

`header.varied` is grype alone. 6 of 6 matches are dropped by the candidate, all on `pkg:golang/stdlib@1.16.9` by `go-module-matcher`, `nvd:cpe cpe-match`.

| check | state | best..worst |
|---|---|---|
| f1NotWorse | fail | 0.22..0.34 |
| noNewFalseNegatives | fail | 3..5 |
| noNewFalsePositives | pass | 0..0 |
| unlabeledChangesAtMost | fail | 2..2 |

Outcome **fail**, exit 1.

- introduced: CVE-2020-29509, CVE-2020-29511, CVE-2021-29923, tp now missed. Reason `record/same-but-unmatched`, secondary `match-type/cpe-only`
- fixed: CVE-2021-44716, fp no longer reported
- review: CVE-2022-1705 and CVE-2022-1962, unlabeled. Their effects say either verdict leaves every check as it is: the gate stays fail
- CVE-2021-44716, CVE-2022-1705 and CVE-2022-1962 get the reason `constraint/changed`. The two versions spell the same constraint differently (`< 1.17.12,>= 1.18.0, < 1.18.4` and `< 1.17.12, >= 1.18.0, < 1.18.4`), and yardstick compares the text

Labeling both review rows tp leaves the gate failing: noNewFalseNegatives 5..5, f1NotWorse 0.34..0.34, unlabeledChangesAtMost now passes.

## Gate `stdlib-cpe`: v0.120.1 vs v0.120.1, the candidate with `grype/stdlib-cpe.yaml`

`header.varied` is config alone. The same 6 matches come back as **added** rows, each with the reason `record/same-but-unmatched`.

| check | state | best..worst |
|---|---|---|
| f1NotWorse | pass | -0.34..-0.22 |
| noNewFalseNegatives | pass | 0..0 |
| noNewFalsePositives | fail | 1..3 |
| unlabeledChangesAtMost | fail | 2..2 |

Outcome **fail**: CVE-2021-44716 is a labeled fp the config brings back.

The two gates share the review rows. Labeling them tp through `go-upgrade` moves this gate's unlabeledChangesAtMost to pass and noNewFalsePositives to 1..1, with no label written for this gate. It still fails.
