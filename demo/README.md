# yardstick demo

One pass through the local workflow, the way someone changing grype would do it: run a gate, see it fail, fix what's a real regression, label what nobody has judged yet, and get those labels into the claims corpus as a pull request. Everything here is real output.

Run everything from the repository root. The first gate run downloads two grype versions and the vulnerability DB, so it takes about two minutes. Later runs reuse the scans and take seconds.

What's in `demo/`:

- `gates/grype-upgrade.yaml` compares grype v0.100.0 with the latest grype over 14 images, on the same DB.
- `gates/grype-upgrade-stdlib-cpe.yaml` is the same gate with a grype config on the candidate (`grype/stdlib-cpe.yaml`).
- `gates/go-stdlib-cpe.yaml` is that config on the Go image alone.

None of the gates names its claims. They all read the app config, `.yardstick.yaml` at the repo root:

```yaml
claims: [github.com/anchore/match-claims@main, ./claims]
```

That is the published corpus first, then `./claims`, a gitignored scratch directory where new labels are written. yardstick creates it when it's missing.

## 1. Build and pull the corpus

```bash
go build -o bin/yardstick ./cmd/yardstick
bin/yardstick claims pull
bin/yardstick config validate demo/gates/*.yaml
```

```
github.com/anchore/match-claims@main at sha256:af82f6aa7944375d8181213ff812fc0d6b63e31254da662a460fb7fb18da6d01 (commit 32064318e375ca3a87ee642bfececd00d701c4de)
demo/gates/go-stdlib-cpe.yaml: valid, gate go-stdlib-cpe
demo/gates/grype-upgrade-stdlib-cpe.yaml: valid, gate grype-upgrade-stdlib-cpe
demo/gates/grype-upgrade.yaml: valid, gate grype-upgrade
```

`claims pull` downloads the published snapshot into the cache and checks its digest. Any command that reads the corpus does this on first use, so the pull is optional. Snapshots come from `https://yardstick.anchore.io` unless `YARDSTICK_CLAIMS_URL` says otherwise.

## 2. Run the gate

```bash
bin/yardstick demo/gates/grype-upgrade.yaml
```

```
FAIL grype-upgrade  1 check fails, 2 undecided, 1 passes
                                                 worst subject
  FAIL       noNewFalseNegatives    max 0        3..73    changes 1, 2
  UNDECIDED  f1NotWorse             tolerance 0  0..0.89  changes 1, 2
  UNDECIDED  unjudgedChangesAtMost  max 0        0..70    changes 1, 2

what changed  99 of 2709 matches: 99 dropped by the candidate, 0 added

1 go-module-matcher stopped reporting nvd:cpe cpe-match on golang/stdlib
    73 matches, 27 CVEs, 3 packages, on
    anchore/test-images/grype-quality-golang:d89207b@7536ee345532
    introduced: 3 tp, now missed
      CVE-2020-29509, CVE-2020-29511, CVE-2021-29923 on stdlib@1.16.9
      fails noNewFalseNegatives; NO CAUSE
    review: 70 unlabeled
      24 CVEs on stdlib@1.16.9, stdlib@1.18.4 in 2 places
      one labeled tp or fp: no change; the gate stays FAIL

2 apk-matcher stopped reporting nvd:cpe cpe-match on apk/secureos/glibc-2.42
    26 matches, 26 CVEs, 1 package, on library/grype-test@3339bcd874d2
    fixed: 5 fp, no longer reported
      CVE-2010-4756, CVE-2019-1010022, CVE-2019-1010023, CVE-2019-1010024,
      CVE-2019-1010025 on glibc-2.42@2.42-r4
    review: 21 unlabeled
      21 CVEs on glibc-2.42@2.42-r4
      one labeled tp: f1NotWorse FAIL; fp: no change; the gate stays FAIL

FAILED 1 of 1 gates
```

The exit code is 1. Each check shows a range: the best case (only what's labeled counts) to the worst case (every unlabeled row counts against it). A check that passes at one end and fails at the other is undecided, and undecided fails the gate.

The two changes need different fixes:

- **Change 1 is a regression in grype.** The newer grype stopped CPE-matching the Go stdlib, and 3 of the drops are labeled true positives. No labeling fixes that: the report says the gate stays FAIL however the 70 are labeled.
- **Change 2 needs labels.** 21 glibc matches are gone and nobody has judged them. Until someone does, the gate can't say whether dropping them was right.

## 3. Fix the regression

grype v0.115.0 changed the default of `match.golang.always-use-cpe-for-stdlib` to false. `demo/grype/stdlib-cpe.yaml` sets it back, and a gate's setup points `config:` at it. On the Go image alone, that fixes the gate:

```bash
bin/yardstick demo/gates/go-stdlib-cpe.yaml
```

```
PASS go-stdlib-cpe  4 checks pass
PASSED 1 of 1 gates
```

The full gate with the same config is left with change 2:

```bash
bin/yardstick demo/gates/grype-upgrade-stdlib-cpe.yaml
```

```
UNDECIDED grype-upgrade-stdlib-cpe  3 checks undecided, 1 passes (undecided counts as fail)
                                                 worst subject
  UNDECIDED  f1NotWorse             tolerance 0  0..0.89  change 1
  UNDECIDED  noNewFalseNegatives    max 0        0..21    change 1
  UNDECIDED  unjudgedChangesAtMost  max 0        0..21    change 1
```

The header now says `more than one input varied`: the candidate changes both grype and its config, so no delta can be pinned on the grype version alone.

## 4. Draft labels with an agent

This step is optional; you can label everything by hand in step 5. The `triage-deltas` skill in `plugin/` reads every unlabeled row, gathers evidence (the CVE record, OSV, distro trackers, the SBOM's file list) and records a **proposal** for each: a verdict, a justification and the facts behind it. A proposal is not a label and counts for nothing until a person accepts it.

```bash
PATH=$PWD/bin:$PATH claude -p "/yardstick:triage-deltas $PWD grype-upgrade-stdlib-cpe" \
  --plugin-dir $PWD/plugin --allowedTools "Bash Read Write Edit Grep Glob Agent"
wc -l .yardstick/proposals.jsonl .yardstick/causes.jsonl
```

```
      21 .yardstick/proposals.jsonl
       2 .yardstick/causes.jsonl
```

Here it proposed 16 of the glibc rows as tp (medium confidence: the CNA's affected range includes 2.42) and 5 as fp (high: the vulnerable code isn't in the image, such as iconv modules that aren't installed, or a Power8-only bug on x86_64). It grouped them into two **causes**, so each group can be accepted at once. The reasoning per row is in `.yardstick/triage/default/grype-upgrade-stdlib-cpe/proposals.md` and `evidence.md`. Everything under `.yardstick/` is gitignored.

## 5. Review and label in the UI

```bash
bin/yardstick claims serve grype-upgrade-stdlib-cpe --open
```

```
labeling at http://127.0.0.1:7655/ (ctrl-c to stop)
```

The gate's board shows its checks as range bars and the changed matches as a map, grouped by direction, reason and source package. Open a match to label it:

- `t`, `f` and `u` label it tp, fp or unclear. fp and unclear need a justification, picked from the list under the buttons.
- With a proposal, the tile shows its verdict, its evidence and what accepting it does to each check. `a` accepts it, and `A` accepts a whole cause.

Each label is written to `./claims` as you go, with `seenIn` filled from the run, and the board re-scores at once. Read a proposal's evidence before you accept it: here the tp proposals don't check whether secureos backported fixes into 2.42-r4.

`claims add` writes the same label from the command line:

```bash
bin/yardstick claims add --gate demo/gates/grype-upgrade-stdlib-cpe.yaml \
  --subject oci:registry.replicated.com/library/grype-test@sha256:3339bcd874d21fa3ca5bd20636e793c0c33bd71ace3a18a9a3b3d147b91dd000 \
  --package 'pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09' \
  --vulnerability CVE-2026-4046 --verdict fp --justification vulnerable_code_not_present
```

## 6. Re-score

`score` re-reads the last scans against the current labels. It runs neither syft nor grype:

```bash
bin/yardstick score demo/gates/grype-upgrade-stdlib-cpe.yaml
```

```
FAIL grype-upgrade-stdlib-cpe  2 checks fail, 2 pass
                                            worst subject
  FAIL  f1NotWorse             tolerance 0  0.76..0.76  change 1
  FAIL  noNewFalseNegatives    max 0        16..16      change 1

what changed  26 of 2709 matches: 26 dropped by the candidate, 0 added

1 apk-matcher stopped reporting nvd:cpe cpe-match on apk/secureos/glibc-2.42
    26 matches, 26 CVEs, 1 package, on library/grype-test@3339bcd874d2
    introduced: 16 tp, now missed
      16 CVEs on glibc-2.42@2.42-r4
      fails f1NotWorse, noNewFalseNegatives; NO CAUSE
    fixed: 10 fp, no longer reported
      10 CVEs on glibc-2.42@2.42-r4
      fails f1NotWorse
```

The gate is no longer undecided. Both ends of every range agree, and the answer is FAIL: the newer grype misses 16 glibc vulnerabilities on secureos that the older one found, and no grype setting brings them back. That is a grype regression to fix or to accept on purpose. It was there before labeling too; the labels are what made the gate able to say so.

The labels are worth keeping either way, since every gate that scans this image reads them.

## 7. Get the labels into the corpus

`claims promote` moves the scratch labels into a checkout of [anchore/match-claims](https://github.com/anchore/match-claims):

```bash
bin/yardstick claims promote claims --to ~/code/match-claims
```

```
promoted 21 labels into /Users/me/code/match-claims
  copied pkg/oci/registry.replicated.com/library/grype-test/sha256-3339bcd874d21fa3ca5bd20636e793c0c33bd71ace3a18a9a3b3d147b91dd000/sbom.syft.json
```

It doesn't commit or push. In the checkout, branch, commit and run the same check the repository's CI runs on a pull request:

```bash
cd ~/code/match-claims
git switch -c label-secureos-glibc
git commit -s -am "label glibc-2.42 on grype-test"
make validate-changed
```

```
validating 1 image directories changed since origin/main
SBOMs for syft 1.14.0: 1 have
.../match-claims/.tmp/changed: valid
```

The SBOM `promote` copied in is gitignored there: SBOMs live in R2, and the publish workflow uploads any new one. Push the branch and open the pull request.

## 8. After the pull request merges

The publish workflow bundles the corpus, uploads the snapshot and moves `claims/latest-v1.json` to it. Back in this repository:

```bash
bin/yardstick claims pull     # names the new snapshot
rm -rf claims                 # the scratch labels are published now; yardstick recreates the directory
bin/yardstick score demo/gates/grype-upgrade-stdlib-cpe.yaml
```

The verdict is the same as in step 6, now read from the published labels alone, so everyone running these gates gets it.

## More

- `-o check` and `-o subject` lay the same report out by check or by image. `-o table` and `-o json` are there too, and `-o FORMAT=path` writes to a file. `--details passing` and `--details rows` add detail.
- `-v`, `-vv` and `-vvv` log to stderr, so stdout stays the report.
- `--vulnerability` and `--package` narrow the report to some rows. The checks and the exit code are still the whole gate's.
- `--name` keeps several runs of one gate apart under `.yardstick/runs/<name>/`.
- `collect sboms`, `collect scans` and `score` run a gate's three steps one at a time.
- `cache status` and `cache delete` show and clean the scan, tool, DB and claims cache.
- `claims list` and `claims policy` show the labels and the labeling rules. `claims agent` holds what the skills call.

The `cbl-mariner` subject prints a platform warning on every run: its label files record `linux/arm64`, while the run catalogs `linux/amd64`.
