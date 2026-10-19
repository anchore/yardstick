# yardstick demo

One pass through the local workflow, the way someone changing grype would do it: run a gate, see it fail, fix what's a real regression, label what nobody has judged yet, and get those labels into the claims corpus as a pull request. Everything here is real output.

Run everything from the repository root. The first gate run downloads two grype versions and the vulnerability DB, so it takes about two minutes. Later runs reuse the scans and take seconds.

What's in `demo/`:

- `gates/grype-upgrade.yaml` compares grype v0.100.0 (the reference) with v0.120.1 (the candidate) over 14 images. Only grype varies: both setups use the same DB and the same config.
- `gates/grype-upgrade-stdlib-cpe.yaml` is the same gate with one grype config, `grype/stdlib-cpe.yaml`, on both setups.
- `gates/go-stdlib-cpe.yaml` is that gate on the Go image alone.

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

grype v0.115.0 changed the default of `match.golang.always-use-cpe-for-stdlib` to false. `demo/grype/stdlib-cpe.yaml` sets it back to true, which is v0.100.0's default too, and both setups point `config:` at it. The config is held like the DB, so grype is still the only input that varies. On the Go image alone, that fixes the gate:

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

## 4. Label in the UI, with an agent's help

The label UI can send an agent to research each unlabeled match. It runs the `research-vuln` skill from the yardstick Claude Code plugin in `plugin/`, so install that once, from this checkout:

```bash
claude plugin marketplace add ./
claude plugin install yardstick@yardstick
```

A plugin from a local marketplace loads in place, so it always matches the yardstick built here. Then open the gate in the UI:

```bash
bin/yardstick claims serve grype-upgrade-stdlib-cpe --open
```

```
labeling at http://127.0.0.1:7655/ (ctrl-c to stop)
```

Without the plugin, serve says so as it starts, with the command to install it, and everything but research still works.

The gate's board shows its checks as range bars and the changed matches as a map, grouped by direction, reason and source package.

- **Research.** `research 20 of 21 matches that could move a check` on the board sends an agent to each of those matches, two at a time, and `R` in a match's tile researches just that one. Each agent reads the CVE record, the advisories, the distro's security data and the image's SBOM, and records a **proposal**: a verdict, a justification and a note on what decided it. A proposal is not a label and counts for nothing until a person accepts it.
- **Label.** Open a match to see its proposal and what accepting it would do to each check. `a` accepts it. `t`, `f` and `u` label it tp, fp or unclear yourself; fp and unclear need a justification, picked from the list under the buttons.

Here the 21 matches took about 10 minutes. The agents found that the secureos security data lists every one of these CVEs as not affecting `glibc-2.42` (fixed at version "0", with no reason given), so they proposed 16 as fp. For the other 5 they proposed `unclear`, because upstream 2.42 still has the vulnerable code and nobody checked what the apk patches. Read a proposal's note before you accept it: it is an agent's claim, and you are the one vouching for it.

Each label is written to `./claims` as you go, with `seenIn` filled from the run, and the board re-scores at once. `claims add` writes the same label from the command line:

```bash
bin/yardstick claims add --gate demo/gates/grype-upgrade-stdlib-cpe.yaml \
  --subject oci:registry.replicated.com/library/grype-test@sha256:3339bcd874d21fa3ca5bd20636e793c0c33bd71ace3a18a9a3b3d147b91dd000 \
  --package 'pkg:apk/secureos/glibc-2.42@2.42-r4?arch=x86_64&distro=secureos-2025.09.09' \
  --vulnerability CVE-2026-5928 --verdict <tp|fp|unclear> --justification <one listed under that verdict>
```

## 5. Re-score

With all 21 proposals accepted, `score` re-reads the last scans against the new labels. It runs neither syft nor grype:

```bash
bin/yardstick score demo/gates/grype-upgrade-stdlib-cpe.yaml
```

```
UNDECIDED grype-upgrade-stdlib-cpe  3 checks undecided, 1 passes (undecided counts as fail)
                                                 worst subject
  UNDECIDED  f1NotWorse             tolerance 0  0..0.32  change 1
  UNDECIDED  noNewFalseNegatives    max 0        0..5     change 1
  UNDECIDED  unjudgedChangesAtMost  max 0        0..5     change 1

what changed  26 of 2709 matches: 26 dropped by the candidate, 0 added

1 apk-matcher stopped reporting nvd:cpe cpe-match on apk/secureos/glibc-2.42
    26 matches, 26 CVEs, 1 package, on library/grype-test@3339bcd874d2
    fixed: 21 fp, no longer reported
      21 CVEs on glibc-2.42@2.42-r4
    review: 5 unlabeled
      CVE-2025-15281, CVE-2026-5928, CVE-2026-6368, CVE-2026-77117,
      CVE-2026-95818 on glibc-2.42@2.42-r4
      one labeled tp: f1NotWorse FAIL, noNewFalseNegatives FAIL; fp: no change
```

An `unclear` label counts as unjudged, so the gate stays undecided until a person settles those 5. The report says what each answer does: if all 5 are fp, every check reaches 0 and the gate passes, which means the newer grype was right to drop all 26. If even one is tp, `noNewFalseNegatives` fails, and grype v0.120.1 misses a real glibc vulnerability on secureos. Settling them means reading the secureos glibc package's patches, and the board previews either answer before anything is written.

The labels are worth keeping whatever the gate says, since every gate that scans this image reads them.

## 6. Get the labels into the corpus

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

## 7. After the pull request merges

The publish workflow bundles the corpus, uploads the snapshot and moves `claims/latest-v1.json` to it. Back in this repository:

```bash
bin/yardstick claims pull     # names the new snapshot
rm -rf claims                 # the scratch labels are published now; yardstick recreates the directory
bin/yardstick score demo/gates/grype-upgrade-stdlib-cpe.yaml
```

The verdict is the same as in step 5, now read from the published labels alone, so everyone running these gates gets it.

## More

- `-o check` and `-o subject` lay the same report out by check or by image. `-o table` and `-o json` are there too, and `-o FORMAT=path` writes to a file. `--details passing` and `--details rows` add detail.
- `-v`, `-vv` and `-vvv` log to stderr, so stdout stays the report.
- `--vulnerability` and `--package` narrow the report to some rows. The checks and the exit code are still the whole gate's.
- `--name` keeps several runs of one gate apart under `.yardstick/runs/<name>/`.
- `collect sboms`, `collect scans` and `score` run a gate's three steps one at a time.
- `cache status` and `cache delete` show and clean the scan, tool, DB and claims cache.
- `claims list` and `claims policy` show the labels and the labeling rules. `claims agent` holds what the skills call.

The `cbl-mariner` subject prints a platform warning on every run: its label files record `linux/arm64`, while the run catalogs `linux/amd64`.
