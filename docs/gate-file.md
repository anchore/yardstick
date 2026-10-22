# Gate file reference

A gate file is one YAML file describing one gate: the two grype setups it compares, the images or SBOMs it scans, where the labels come from, and the checks that decide whether it passes. `yardstick config validate <gate.yaml>` checks a file without scanning anything. An unknown key anywhere is an error that names the key and its line.

```yaml
schema: v1
name: grype-upgrade                      # optional, defaults to the file name
description: does v0.120.1 match at least as well as v0.100.0?
candidate: {grype: grype@v0.120.1, db: latest}
reference: {grype: grype@v0.100.0, db: latest}
claims:
  - github.com/anchore/match-claims@main
  - ./claims
subjects:
  - oci:docker.io/library/alpine@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9
checks:
  - name: f1NotWorse
  - name: noNewFalseNegatives
  - name: unlabeledChangesAtMost
    params: {max: 0}
undecided: fail
```

## Keys

| key | required | what it is |
|---|---|---|
| `schema` | yes | `v1`, the only format this yardstick reads |
| `name` | no | the gate's name, letters, digits, `.`, `-` and `_`; it names the gate's scans directory. Defaults to the file name without `.yaml` |
| `description` | no | free text, shown in the label UI |
| `candidate` | yes | the setup being judged |
| `reference` | no | the setup it is compared with. Checks that read the reference need one |
| `catalog` | no | how an image's SBOM is built when no claims source holds it |
| `claims` | see below | the claims sources labels are read from, in order |
| `subjects` | yes | what both setups scan, at least one |
| `checks` | yes | the checks, at least one |
| `undecided` | no | `fail` (the default) or `pass`: what an undecided gate means to CI |
| `vulnerabilities` | no | narrows what every check sees |

Relative paths anywhere in the file resolve against the file's directory.

### `candidate` and `reference`

| key | what it is |
|---|---|
| `grype` | `grype@<version>`, `grype@latest`, or a path to a binary |
| `db` | `latest` (what that grype would download), an archive path, an `https://` or `http://` archive URL, or `dir:<path>` for a DB directory. Required, with no default |
| `config` | a grype config file. Without one, grype runs with an empty config, so no `.grype.yaml` around yardstick applies |
| `env` | variables for grype. `GRYPE_DB_AUTO_UPDATE`, `GRYPE_DB_VALIDATE_AGE`, `GRYPE_DB_CACHE_DIR` and `SYFT_CHECK_FOR_APP_UPDATE` are refused, since yardstick pins the DB and update checks itself |

### `catalog`

| key | what it is |
|---|---|
| `syft` | `syft@<version>` (never `syft@latest`), or a path to a binary. Required |
| `config` | a syft config file |
| `platform` | `os/arch[/variant]`, the default for every image subject |
| `env` | variables for syft, with the same refused keys as a setup's |

Without a `catalog:`, the `catalog.yaml` of the first claims source holding one is used.

### `claims`

Each entry is a local directory, `github.com/<owner>/<repo>@main` for a repository's published snapshot, or `github.com/<owner>/<repo>/<path>@<ref>` for a claims directory in a repository at a branch, tag or commit. A label in a later source wins over the same label in an earlier one.

A gate with no `claims:` uses the `claims:` of the app config, `.yardstick.yaml` or `config/yardstick.yaml` in the working directory. `--claims <dir>` appends a local source to either. A command that writes labels needs the last source to be local.

### `subjects`

Each entry is a reference, or a mapping with `ref` and optional `name`, `platform` and `packages`:

- `oci:<image>@sha256:<digest>`: an image, pinned by digest, with or without a tag before the digest
- `sbom:<path>`: an SBOM file scanned as it is

```yaml
subjects:
  - ref: oci:ghcr.io/anchore/test-images/java:56d52bc@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da
    name: java-jars
    platform: linux/amd64
    packages: {keepTypes: [java-archive]}
```

`packages.keepTypes` drops every package of another syft package type (`deb`, `go-module`, `java-archive` and so on; an unknown type is an error) before either setup scans the SBOM. A subject with it needs a `name`, since one image can be listed with several filters. Two subjects may not share a name.

### `checks`

Each entry is `name` and optional `params`. A check is listed once. Params are numbers; a param marked whole takes no fraction, and one with no default is required. The checks are listed [below](#checks-1).

### `vulnerabilities`

| key | what it is |
|---|---|
| `maxYear` | drops matches and labels on a vulnerability from a later year, read from a CVE, ALAS or ELSA id, else from the CVE grype relates the match to. An id with no year is kept |
| `namespaces` | keeps only matches from these grype namespaces, such as `nvd:cpe`. Labels are not filtered by namespace |

It applies when scoring, so `yardstick score` re-applies a changed filter to the same scans.

## How a gate is decided

Every check is computed twice, once in the worst case for the candidate and once in the best. A match only one setup reports that no label judges counts against the candidate in the worst case and for it in the best: in the worst case one the candidate added is an fp and one it dropped is a tp, and the other way round in the best. A label of `unclear` judges nothing. A check passes when even the worst case is within its threshold, fails when even the best case is not, and is undecided otherwise.

A per-subject check is evaluated on each subject alone and takes the worst subject. A per-gate check sums across every subject.

The gate fails if any check fails, is undecided if any is undecided, and passes otherwise. An undecided gate fails CI unless the gate sets `undecided: pass`.

Two rules apply before any check, as Python yardstick applied them:

- **No matches fails.** A gate that lists no `matchesAtLeast` gets one with `min: 1`, so a subject both setups report nothing on fails the gate. It shows in every report as one more check than the file lists. List `matchesAtLeast` yourself to change `min`, or `min: 0` to turn it off.
- **No change passes.** On a subject both setups report the same matches on, every per-subject check passes with "both setups report the same matches", whatever the labels say. When no subject has a change, the same goes for `noNewMisses`. The two floors, `matchesAtLeast` and `expectationsMetAtLeast`, are not comparisons and still apply.

A subject the setups disagree on that no tp or fp label applies to fails `f1NotWorse`, `noNewFalseNegatives` and `noNewFalsePositives` with "no tp or fp label applies to this subject".

An expectation is a tp or fp label that applies to a subject: a tp is met by a setup when one of its matches pairs it, an fp when none does.

## Checks

### `f1NotWorse`

Fails when the candidate's F1 is lower than the reference's by more than tolerance. Per subject; reads the reference.

| param | default | what it is |
|---|---|---|
| `tolerance` | 0 | how far below the reference's F1 the candidate's may be |

F1 is 2PR/(P+R), with precision P over matches (tp matches of all tp and fp matches) and recall R over tp labels (labels the setup's matches pair of all tp labels). Either is 1 when there is nothing to count.

### `noNewFalseNegatives`

Fails when more than max tp labels the reference satisfied are unsatisfied in the candidate. Per subject; reads the reference.

| param | default | what it is |
|---|---|---|
| `max` | 0 | how many tp labels the reference satisfied may go unsatisfied (whole) |

### `noNewFalsePositives`

Fails when more than max candidate matches paired by an fp label were not reported by the reference. Per subject; reads the reference.

| param | default | what it is |
|---|---|---|
| `max` | 0 | how many new matches an fp label pairs are allowed (whole) |

### `unlabeledChangesAtMost`

Fails when more than max unlabeled matches appear in only one setup; labeling them lowers the count. Per subject; reads the reference. The count is known exactly, so it passes or fails and is never undecided.

| param | default | what it is |
|---|---|---|
| `max` | required | how many matches only one setup reports may stay unlabeled (whole) |

### `unlabeledPercentAtMost`

Fails when more than max percent of the candidate's matches are unlabeled. Per subject. Never undecided.

| param | default | what it is |
|---|---|---|
| `max` | required | the percent of the candidate's matches that may be unlabeled, at most 100 |

### `matchesAtLeast`

Fails when the candidate and the reference together report fewer than min matches on a subject, after the gate's vulnerabilities filter. Per subject. Never undecided. Every gate runs it with `min: 1` unless it lists it.

| param | default | what it is |
|---|---|---|
| `min` | required | how many matches the candidate and the reference must report between them on each subject (whole) |

### `expectationsMetAtLeast`

Fails when the candidate meets fewer expectations than min, or than minFraction of all of them. Per gate. Set exactly one of the two params.

| param | default | what it is |
|---|---|---|
| `min` | one of the two | how many expectations the candidate must meet (whole) |
| `minFraction` | one of the two | the fraction of all expectations the candidate must meet, from 0 to 1 |

A gate with no expectations at all fails it. An unlabeled change counts as one more expectation in both cases, unmet in the worst and met in the best.

### `noNewMisses`

Fails when more than max expectations met by the reference are not met by the candidate. Per gate; reads the reference.

| param | default | what it is |
|---|---|---|
| `max` | 0 | how many expectations the reference met the candidate may miss (whole) |

## Differences from 0.16 (Python)

The Python gate config does not carry over; yardstick refuses an app config with `result-sets:` rather than misreading it. What its settings became:

| Python | here |
|---|---|
| `max_f1_regression` | `f1NotWorse` `tolerance` |
| `max_new_false_negatives` | `noNewFalseNegatives` `max` |
| `max_unlabeled_percent` | `unlabeledPercentAtMost` `max` |
| `fail_on_empty_match_set: true` | `matchesAtLeast` `min: 1`, on unless the gate lists `matchesAtLeast` |
| `max_year` | `vulnerabilities.maxYear` |
| `allowed_namespaces` | `vulnerabilities.namespaces` |
| `required_namespaces` | nothing |

What is computed differently:

- **False negatives are gross, not net.** Python failed when the candidate's false negatives exceeded the reference's plus the limit. `noNewFalseNegatives` counts each tp label the reference satisfied and the candidate does not, so a candidate that fixes one miss and adds another passed before and fails now.
- **F1 has another formula.** Python used tp/(tp+0.5(fp+fn)) over one shared count, 0 when there was nothing to count. Here precision is over matches and recall over labels, each 1 when empty. A subject the reference reports nothing on, where the candidate adds one match labeled fp, scored 0 against 0 before; here the reference's F1 is 1 and the candidate's 0, so it fails `f1NotWorse` by 1.
- **Unlabeled matches are bounded, not ignored.** Python scored labeled matches only. Here every check is computed at the worst and the best case, and a gate can be undecided until its open changes are labeled; `undecided:` says what CI does with that.
- **The guards are kept, at the gate.** Python failed an empty match set and passed identical results before comparing labels. Both happen here before any check, as described above.
