# yardstick demo

One pass through the local workflow, the way someone changing grype would do it: run a gate, see it fail, fix what's a real regression, label what nobody has judged yet, and keep those labels with the change that needed them. Everything here is real output.

Run everything from the repository root. The first gate run downloads two grype versions and the vulnerability DB, so it takes about two minutes. Later runs reuse the scans and take seconds.

What's in `demo/`:

- `gates/grype-upgrade.yaml` compares grype v0.100.0 (the reference) with v0.120.1 (the candidate) over 14 images. Only grype varies: both setups use the same DB and the same config.
- `gates/grype-upgrade-stdlib-cpe.yaml` is the same gate with one grype config, `grype/stdlib-cpe.yaml`, on both setups.
- `gates/go-stdlib-cpe.yaml` is that gate on the Go image alone.

None of the gates names its claims. They all read the app config, `.yardstick.yaml` at the repo root:

```yaml
claims: [github.com/anchore/claims@main, ./claims]
```

That is the published corpus first, then `./claims`, a gitignored scratch directory where new labels are written. yardstick creates it when it's missing.

## 1. Build and pull the corpus

```bash
go build -o bin/yardstick ./cmd/yardstick
bin/yardstick claims pull
bin/yardstick config validate demo/gates/*.yaml
```

```
✔ github.com/anchore/claims@main  sha256:af82f6aa7944375d8181213ff812fc0d6b63e31254da662a460fb7fb18da6d01  commit 32064318e375ca3a87ee642bfececd00d701c4de
✔ demo/gates/go-stdlib-cpe.yaml             gate go-stdlib-cpe
✔ demo/gates/grype-upgrade-stdlib-cpe.yaml  gate grype-upgrade-stdlib-cpe
✔ demo/gates/grype-upgrade.yaml             gate grype-upgrade
```

`claims pull` downloads the published snapshot into the cache and checks its digest. Any command that reads the corpus does this on first use, so the pull is optional. Snapshots come from `https://yardstick.anchore.io` unless `YARDSTICK_CLAIMS_URL` says otherwise.

## 2. Run the gate

```bash
bin/yardstick demo/gates/grype-upgrade.yaml
```

```
FAIL grype-upgrade  2 checks fail, 1 undecided, 2 pass
                                                  worst subject
  FAIL       noNewFalseNegatives     max 0        3..73    changes 1, 2
  FAIL       unlabeledChangesAtMost  max 0        70..70   changes 1, 2
  UNDECIDED  f1NotWorse              tolerance 0  0..0.89  changes 1, 2

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

The exit code is 1. Each check shows a range: the best case (only what's labeled counts) to the worst case (every unlabeled row counts against it). A check that passes at one end and fails at the other is undecided, and undecided fails the gate. `unlabeledChangesAtMost` counts the unlabeled rows themselves, which is known exactly, so both ends are the same number and it passes or fails outright.

The two changes need different fixes:

- **Change 1 is a regression in grype.** The newer grype stopped CPE-matching the Go stdlib, and 3 of the drops are labeled true positives. No labeling fixes that: the report says the gate stays FAIL however the 70 are labeled.
- **Change 2 needs labels.** 21 glibc matches are gone and nobody has judged them. Until someone does, the gate can't say whether dropping them was right.

## 3. Fix the regression

grype v0.115.0 changed the default of `match.golang.always-use-cpe-for-stdlib` to false. `demo/grype/stdlib-cpe.yaml` sets it back to true, which is v0.100.0's default too, and both setups point `config:` at it. The config is held like the DB, so grype is still the only input that varies. On the Go image alone, that fixes the gate:

```bash
bin/yardstick demo/gates/go-stdlib-cpe.yaml
```

```
PASS go-stdlib-cpe  5 checks pass
PASSED 1 of 1 gates
```

The full gate with the same config is left with change 2:

```bash
bin/yardstick demo/gates/grype-upgrade-stdlib-cpe.yaml
```

```
FAIL grype-upgrade-stdlib-cpe  1 check fails, 2 undecided, 2 pass
                                                  worst subject
  FAIL       unlabeledChangesAtMost  max 0        21..21   change 1
  UNDECIDED  f1NotWorse              tolerance 0  0..0.89  change 1
  UNDECIDED  noNewFalseNegatives     max 0        0..21    change 1
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
✔ labeling at http://127.0.0.1:7655/  ctrl-c to stop
```

Without the plugin, serve says so as it starts, with the command to install it, and everything but research still works.

The page opens on the list of gates. A gate lists its checks, each with its value against its limit; a check lists every finding it counts, and the gate's Scan map tab draws the changed matches grouped by direction, reason and source package.

- **Research.** `R` on a finding sends an agent to research that match. Each agent reads the CVE record, the advisories, the distro's security data and the image's SBOM, and records a **proposal**: a verdict, a justification and a note on what decided it. A proposal is not a label and counts for nothing until a person accepts it.
- **Label.** Open a finding to see its proposal in its own card. `a` accepts it, and Accept hints on a table accepts the hints of every row selected. `t`, `f` and `u` label it tp, fp or unclear yourself; fp and unclear need a reason, picked from the list under the buttons, and Save writes the label.

Here the 21 matches took about 10 minutes. The agents found that the secureos security data lists every one of these CVEs as not affecting `glibc-2.42` (fixed at version "0", with no reason given), so they proposed 16 as fp. For the other 5 they proposed `unclear`, because upstream 2.42 still has the vulnerable code and nobody checked what the apk patches. Read a proposal's note before you accept it: it is an agent's claim, and you are the one vouching for it.

Each label is written to `./claims` as you go, with `seenIn` filled from the run, and the gate re-scores at once. `claims add` writes the same label from the command line:

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
FAIL grype-upgrade-stdlib-cpe  1 check fails, 2 undecided, 2 pass
                                                  worst subject
  FAIL       unlabeledChangesAtMost  max 0        5..5     change 1
  UNDECIDED  f1NotWorse              tolerance 0  0..0.32  change 1
  UNDECIDED  noNewFalseNegatives     max 0        0..5     change 1

what changed  26 of 2709 matches: 26 dropped by the candidate, 0 added

1 apk-matcher stopped reporting nvd:cpe cpe-match on apk/secureos/glibc-2.42
    26 matches, 26 CVEs, 1 package, on library/grype-test@3339bcd874d2
    fixed: 21 fp, no longer reported
      21 CVEs on glibc-2.42@2.42-r4
    review: 5 unlabeled
      CVE-2025-15281, CVE-2026-5928, CVE-2026-6368, CVE-2026-77117,
      CVE-2026-95818 on glibc-2.42@2.42-r4
      one labeled tp: f1NotWorse FAIL, noNewFalseNegatives FAIL; fp: no change; the gate stays FAIL
```

An `unclear` label counts as unlabeled, so `unlabeledChangesAtMost` fails the gate until a person settles those 5. The report says what each answer does: if all 5 are fp, every check reaches 0 and the gate passes, which means the newer grype was right to drop all 26. If even one is tp, `noNewFalseNegatives` fails, and grype v0.120.1 misses a real glibc vulnerability on secureos. Settling them means reading the secureos glibc package's patches.

The labels are worth keeping whatever the gate says, since every gate that scans this image reads them.

## 6. Keep the labels with the change

Here `./claims` is gitignored scratch, so the labels stop at this checkout. In grype or vunnel the claims directory is committed: new labels are written straight into it and go up with the pull request that needed them. Nothing is copied into [anchore/claims](https://github.com/anchore/claims) by hand; a separate job folds grype's and vunnel's main branches back into it from time to time.

Each of those repos also reads the other's claims from its main branch, through a reference with a path after the repository. grype's `.yardstick.yaml` would read:

```yaml
claims:
  - github.com/anchore/claims@main                # the published corpus
  - github.com/anchore/vunnel/tests/quality/claims@main  # vunnel's claims directory on main
  - ./claims                                            # grype's own, where new labels are written
```

A reference with a path is read from the GitHub archive of the commit the ref resolves to, cached by that commit, so `@main` downloads again only when main has moved. `GITHUB_TOKEN` is sent when it's set. When two sources hold the same label, the last one wins: a correction made in the pull request takes effect right away, and the run warns that the sources disagree and names the one it used.

SBOMs made while labeling aren't copied anywhere either. They reach R2 when the flush job runs, and until then a label read from another repo may need its SBOM rebuilt from the recipe.

## More

- `-o check` and `-o subject` lay the same report out by check or by image. `-o table` and `-o json` are there too, and `-o FORMAT=path` writes to a file. `--details passing` and `--details rows` add detail.
- `-v`, `-vv` and `-vvv` log to stderr, so stdout stays the report.
- `--vulnerability` and `--package` narrow the report to some rows. The checks and the exit code are still the whole gate's.
- `vulnerabilities:` in a gate file narrows what every check sees, in both setups. `maxYear: 2021` drops matches and labels on a vulnerability from a later year: the year is read from a CVE, ALAS or ELSA id, else from the CVE grype relates to the match, and an id with no year is kept. `namespaces: [nvd:cpe, ...]` keeps only the matches from those grype namespaces and filters no labels. It applies when scoring, so `score` re-applies a changed filter without scanning again.
- The `matchesAtLeast` check fails a subject the candidate and the reference together report fewer than `min` matches on, after `vulnerabilities:`, so with `min: 1` only a subject both setups find nothing on fails. Every gate runs it with `min: 1` unless it lists `matchesAtLeast` itself, which is why a gate's report counts one more check than it lists. It reads no labels, so it is never undecided.
- `--name` keeps several runs of one gate apart under `.yardstick/runs/<name>/`.
- `collect sboms`, `collect scans` and `score` run a gate's three steps one at a time.
- `cache status` and `cache delete` show and clean the scan, tool, DB and claims cache.
- `claims list` and `claims policy` show the labels and the labeling rules. `claims agent` holds what the skills call.

The `cbl-mariner` subject prints a platform warning on every run: its label files record `linux/arm64`, while the run catalogs `linux/amd64`.
