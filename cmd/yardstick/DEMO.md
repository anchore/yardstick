# yardstick demo

A walk through the whole workflow against the corpus in `claims/` and the example gates in `config/gates/`. Run everything from the repository root.

The first gate run downloads two grype versions and the current vulnerability DB, so it takes about two minutes. After that a run takes about 15 seconds. Scans land in `.yardstick/runs/default/` (gitignored; step 10 names other runs), and tools and DBs are cached in the user cache directory (`YARDSTICK_CACHE_DIR` overrides it).

## The example gates

None of the gates lists its claims sources. `config/yardstick.yaml`, the app config, names `claims/` once for all of them; yardstick reads it, or `./.yardstick.yaml`, from the working directory only. A gate that lists its own `claims:` replaces it, as `os-packages-remote.yaml` does in step 8, and `--claims` appends after either.

- `config/gates/grype-upgrade.yaml` compares grype v0.100.0 with the latest grype across all 14 corpus images, on the same DB. It **fails**: the newer grype drops some Go stdlib matches labeled true positive.
- `config/gates/grype-upgrade-stdlib-cpe.yaml` is the same gate with a grype config on the candidate (`config/grype/stdlib-cpe.yaml`) that turns the dropped stdlib matches back on. See step 3.
- `config/gates/os-packages.yaml` is the same comparison over 4 distro images. It **passes**.
- `config/gates/label-coverage.yaml` runs one setup and no reference, and checks what share of the matches is unlabeled. It is **undecided**, because the Go image is mostly unlabeled.

`db: latest` gives both setups the same current DB, so these gates vary only grype. That means the old grype reads a newer DB schema than it was built for: v0.100.0 was built against v6.1.1. To compare on a DB from its own time, set `db:` to an archive path or URL.

## 1. Build, and check the inputs

```bash
go build -o bin/yardstick ./cmd/yardstick

bin/yardstick claims validate claims
bin/yardstick config validate config/gates/*.yaml
```

## 2. Run the gates

```bash
bin/yardstick config/gates/os-packages.yaml
bin/yardstick config/gates/grype-upgrade.yaml        # the cause layout: the checks, then what changed, each row once
bin/yardstick config/gates/grype-upgrade.yaml --details rows     # the matches behind each change
bin/yardstick config/gates/grype-upgrade.yaml -o table
bin/yardstick config/gates/grype-upgrade.yaml -o json | jq '.gates[0].checks[] | {name, verdict}'
bin/yardstick config/gates/label-coverage.yaml --details passing
bin/yardstick config/gates/grype-upgrade.yaml -o check -o json=./report.json   # check on stdout, json to a file
```

There are three layouts of one report, picked with `-o`. Each is a different way into the same gate result:

- `cause` (the default): use it to find out what changed and what to label next. Rows are grouped under the matcher change that produced them, each printed once.
- `check`: use it to see whether the gate is OK. It leads with each check, then the subjects and rows that moved it.
- `subject`: use it to see what happened to one image. Each subject gets its counts, its checks and its rows.

```bash
bin/yardstick config/gates/grype-upgrade.yaml                  # cause
bin/yardstick config/gates/grype-upgrade.yaml -o check
bin/yardstick config/gates/grype-upgrade.yaml -o subject
```

`--details passing` adds passing checks and their values to any of them, and `--details rows` also the rows behind them, each with its package's location. `-o` is `FORMAT` or `FORMAT=path` and can be repeated; at most one format goes to stdout. Logs are separate: `-v` is info, `-vv` debug and `-vvv` trace, all on stderr, so stdout stays the report.

```bash
bin/yardstick config/gates/grype-upgrade.yaml -v                              # what each step is doing
bin/yardstick config/gates/grype-upgrade.yaml -vv                             # and the options and commands behind it
bin/yardstick config/gates/grype-upgrade.yaml -o json -vv 2>/dev/null | jq .  # logs dropped, json untouched
```

### Live progress

A plain run in a terminal draws a live view of the setups, SBOMs and scans on stderr, and settles to a one-line summary before the report prints. `-v` switches it to logs, and `-q` or a stderr that isn't a terminal turns it off.

The exit code is 0 when every gate passes, 1 when one fails, and 2 on a load or input error. An undecided check fails the gate by default (`undecided: fail`).

## 3. Why grype-upgrade fails

`noNewFalseNegatives` fails on the Go image. The default `cause` layout groups the rows by what the candidate changed:

```
1 go-module-matcher stopped reporting nvd:cpe cpe-match on golang/stdlib
    73 matches, 27 CVEs, 3 packages, on anchore/test-images/grype-quality-golang:d89207b@7536ee345532
    introduced: 3 tp, now missed
      CVE-2020-29509, CVE-2020-29511, CVE-2021-29923 on stdlib@1.16.9
      fails noNewFalseNegatives; NO CAUSE
    review: 70 unlabeled
      24 CVEs on stdlib@1.16.9, stdlib@1.18.4 in 2 places
      one labeled tp or fp: no change; the gate stays FAIL
```

With `-o check` the same rows sit under the check they fail, one group per label state, delta, package and match type:

```
FAIL noNewFalseNegatives  max 0          worst subject 3..73 tp dropped
  FAIL       3..73        anchore/test-images/grype-quality-golang:d89207b@7536ee345532
    3 tp, dropped by the candidate
      CVE-2020-29509, CVE-2020-29511, CVE-2021-29923 on pkg:golang/stdlib@1.16.9
      nvd:cpe cpe-match; NO CAUSE
    70 unlabeled, dropped by the candidate
      24 CVEs on 3 pkg:golang/stdlib packages (1.16.9, 1.18.4 x2)
      nvd:cpe cpe-match; the gate fails however one is labeled
```

`--details rows` prints every row under its group line.

That is 73 matches on 3 stdlib packages, all of them matches v0.100.0 reports and v0.120.1 does not, and all `cpe-match` / `nvd:cpe` matches: grype v0.115.0 changed the default of `match.golang.always-use-cpe-for-stdlib` from true to false. `best` counts the drops already labeled true positive (3), and `worst` counts every drop that could turn out to be one, so the unlabeled ones are `review` rows.

## 4. Label a match and re-score

Labels are written into the last local claims source. A scratch directory passed with `--claims` keeps the demo out of the corpus. The scans from step 2 still apply: another claims source changes the labels, not what was scanned.

```bash
mkdir -p .demo-claims
bin/yardstick claims add --gate config/gates/grype-upgrade.yaml --claims .demo-claims \
  --subject oci:ghcr.io/anchore/test-images/grype-quality-golang:d89207b@sha256:7536ee345532f674ec9e448e3768db4e546c48220ba2b6ec9bc9cfbfb3b7b74a \
  --package pkg:golang/stdlib@1.16.9 --vulnerability CVE-2022-23773 --verdict tp

bin/yardstick score config/gates/grype-upgrade.yaml --claims .demo-claims -q
```

```
  FAIL noNewFalseNegatives (max 0): worst 73, best 4, threshold 0
  UNDECIDED unjudgedChangesAtMost (max 0): worst 69, best 0, threshold 0
```

`score` runs neither grype nor syft. It re-reads the last scans. The label confirms a dropped true positive, so the check gets worse, not better: `best` (only the labeled drops) goes from 3 to 4, and `worst` (every drop that might be one) stays at 73. The unjudged drops go from 70 to 69.

### Re-score one vulnerability

`--vulnerability` and `--package` narrow the report to the rows of one vulnerability or package, which suits labeling one CVE at a time: label it, re-score with a focus, repeat. Both are repeatable, on `score` and on a gate run. `--vulnerability` also selects a row reported under any alias of the id, and `--package` takes a purl prefix (`pkg:golang/stdlib@1.16.9`) or a purl name (`stdlib`).

```bash
bin/yardstick score config/gates/grype-upgrade.yaml --claims .demo-claims --vulnerability CVE-2022-23773
```

```
focus  rows of CVE-2022-23773; counts, values and outcomes are the whole gate's

FAIL grype-upgrade  1 check fails, 2 undecided, 1 passes
                                                 worst subject
  FAIL       noNewFalseNegatives    max 0        4..73    change 1
  UNDECIDED  f1NotWorse             tolerance 0  0..0.89  change 1
  UNDECIDED  unjudgedChangesAtMost  max 0        0..69    no change

what changed in focus  1 of 1 matches: 1 dropped by the candidate, 0 added

1 go-module-matcher stopped reporting nvd:cpe cpe-match on golang/stdlib
    1 match, 1 CVE, 1 package, on
    anchore/test-images/grype-quality-golang:d89207b@7536ee345532
    introduced: 1 tp, now missed
      CVE-2022-23773 on stdlib@1.16.9
      fails noNewFalseNegatives; NO CAUSE

FAILED 1 of 1 gates
```

Only the rows in focus print. The check values, the outcome and the exit code are still the whole gate's, the same as without the flag, so a focus can't turn a failing gate green. `-o json` narrows its rows the same way and adds a top-level `focus` naming what was given. A focus no row matches prints `no rows match the focus` under each gate.

### One label covers every id of a vulnerability

A label names one id, and pairs a match reported under any alias of it. On the Java image grype reports Spring4Shell on `spring-beans@2.5` as `GHSA-36p3-wjmg-h94x`, relating it to `CVE-2022-22965`, and the corpus has no label for it. Label it by the CVE:

```bash
bin/yardstick claims add --gate config/gates/grype-upgrade.yaml --claims .demo-claims \
  --subject oci:ghcr.io/anchore/test-images/java:56d52bc@sha256:10008791acbc5866de04108746a02a0c4029ce3a4400a9b3dad45d7f2245f9da \
  --package pkg:maven/org.springframework/spring-beans@2.5 --vulnerability CVE-2022-22965 --verdict tp --justification in-affected-range

bin/yardstick score config/gates/grype-upgrade.yaml --claims .demo-claims -o json \
  | jq -c '.gates[0].subjects[] | select(.name|test("/java:")) | .matches[] | select(.package|endswith("spring-beans@2.5")) | {id, vulnerability, verdict, label: .label.vulnerability}'
```

```
{"id":"940f4584cd0b05d6/CVE-2022-22965","vulnerability":"GHSA-36p3-wjmg-h94x","verdict":"tp","label":"CVE-2022-22965"}
{"id":"940f4584cd0b05d6/CVE-2022-22970","vulnerability":"GHSA-hh26-6xwr-ggv7","verdict":null,"label":null}
```

The GHSA match now carries the CVE label's verdict, and the Java image's `tp` count goes from 68 to 69 in both setups. The other `spring-beans` match is a different vulnerability and stays unlabeled. A match's `id` is its package plus its alias group, named by the group's lexically smallest id, which is why both rows show a CVE where grype reported a GHSA. Groups are built from every related id either setup reported plus every label's id, so a link that only one DB knows still pairs. Advisory ids (`advisory-ids` in `claims/vocabulary.yaml`, such as `RHSA` and `DSA`) never join a group, since one advisory can name several CVEs. A match on one pairs the label on each CVE it names.

The match is in both setups, so the label moves no check here, and step 5's numbers are the same with or without it.

## 5. Keep the stdlib CPE matches

The fix on the grype side is a config, not a label. `config/grype/stdlib-cpe.yaml` sets `match.golang.always-use-cpe-for-stdlib: true`, and the candidate in `grype-upgrade-stdlib-cpe.yaml` points `config:` at it:

```bash
bin/yardstick config/gates/grype-upgrade-stdlib-cpe.yaml --claims .demo-claims --details passing
```

```
  varied: grype (grype@v0.100.0 -> grype@v0.120.1), config (none -> .../config/grype/stdlib-cpe.yaml (sha256:44274a...))
  more than one input varied, so no delta can be attributed to one of them
  ...
  UNDECIDED noNewFalseNegatives (max 0): worst 21, best 0, threshold 0
```

The Go image no longer appears under `noNewFalseNegatives` at all (worst 73 is now 21). The gate now varies both grype and its config, which yardstick says in the header, so a remaining delta cannot be pinned on the grype version alone. Here the run is still undecided, but only because of `grype-test`: 21 unlabeled `glibc` matches on `pkg:apk/secureos/...` that v0.100.0 reports and v0.120.1 does not. That is a separate difference, left for someone to label.

## 6. Promote the label into the corpus

This is what a contributor does before opening a pull request against `claims/`:

```bash
bin/yardstick claims promote .demo-claims --to claims
git diff claims
bin/yardstick claims validate claims
```

To undo it:

```bash
git checkout claims && rm -rf .demo-claims
```

## 7. Export the corpus as OpenVEX

```bash
bin/yardstick claims export --vex claims | jq '.statements | length'
```

## 8. Read the corpus as a published snapshot

A gate can name a published corpus instead of a directory. The publish workflow bundles `claims/` into a zip named by its sha256 and serves it from a bucket; here a local Python server stands in for the bucket. `config/gates/os-packages-remote.yaml` is `os-packages.yaml` with `claims: [github.com/anchore/delta-prototype@main]`. The host part of that locator is not contacted: `YARDSTICK_CLAIMS_URL` says where to read from.

Lay out the bucket with the same script the workflow uses:

```bash
BUCKET=$(mktemp -d)
mkdir -p $BUCKET/claims/snapshots
digest=$(.github/scripts/claims-bundle.sh claims $BUCKET/claims/snapshots)     # sha256:<hex>
echo "{\"digest\":\"$digest\"}" > $BUCKET/claims/latest-v1.json
python3 -m http.server 8765 --directory $BUCKET &                               # or another terminal
```

`@main` reads `claims/latest-v1.json`. `@<40-char commit sha>` reads `claims/commits/<sha>.json` (same shape, plus an optional `commit`), and `@sha256:<hex>` skips the pointer.

```bash
YARDSTICK_CLAIMS_URL=http://127.0.0.1:8765 bin/yardstick config/gates/os-packages-remote.yaml -v 2>&1 | grep -i 'claims'
```

```
INFO opening remote claims source github.com/anchore/delta-prototype@main, resolved to snapshot sha256:451e5a...
INFO downloading claims snapshot sha256:451e5a...
INFO verified claims snapshot sha256:451e5a..., 1427545 bytes
  claims: github.com/anchore/delta-prototype@main at sha256:451e5a...
```

The header names the snapshot digest, so the verdict is tied to exact corpus bytes. The zip lands in the cache, which is `~/Library/Caches/yardstick` on macOS, `~/.cache/yardstick` on Linux, or `$YARDSTICK_CACHE_DIR`:

```bash
ls ~/Library/Caches/yardstick/claims/
unzip -l ~/Library/Caches/yardstick/claims/<hex>.zip | head
```

yardstick reads entries straight out of that zip and never unpacks it. The whole zip is hashed as it downloads and kept only if it matches the digest in the pointer (`-vvv` shows the `downloading and verifying` line, and `-v` the `verified` line). A run opens the source once. Every later run logs `using cached claims snapshot` in place of the last two lines, with no download.

To see the check refuse something, append a byte to the served zip and drop the cached copy:

```bash
echo x >> $BUCKET/claims/snapshots/<hex>.zip; rm ~/Library/Caches/yardstick/claims/<hex>.zip
YARDSTICK_CLAIMS_URL=http://127.0.0.1:8765 bin/yardstick config/gates/os-packages-remote.yaml
```

```
ERROR gate os-packages-remote: claims source github.com/anchore/delta-prototype@main: snapshot sha256:451e5a...: the download's digest is sha256:ef5589..., not sha256:451e5a... as published; it was deleted
```

That exits 2 and leaves nothing in `claims/`. Stop the server with `kill %1` when done.

## 9. Reuse scans and manage the cache

A scan is stored under a key built from the SBOM, the grype binary, the DB, the grype config and the declared env. Run the same gate again and every scan is reused. The `-v` log prefix is seconds since the start of the run:

```bash
bin/yardstick config/gates/grype-upgrade.yaml -v   # first run after the scans exist
bin/yardstick config/gates/grype-upgrade.yaml -v
bin/yardstick config/gates/grype-upgrade.yaml -v --rescan
```

```
[0003]  INFO scans of grype-upgrade: 28 reused, 0 ran
[0002]  INFO scans of grype-upgrade: 28 reused, 0 ran
[0021]  INFO scans of grype-upgrade: 0 reused, 28 ran
```

A reused run takes 2 to 3 seconds and a full one about 21. `--rescan` forces every scan to run again.

Change any part of the key and the scans that depend on it run again: a different grype binary, DB, config, declared env, or SBOM. `grype-upgrade-stdlib-cpe.yaml` differs from `grype-upgrade.yaml` only in the candidate's grype config, so the reference scans are reused and the candidate scans run:

```bash
bin/yardstick config/gates/grype-upgrade-stdlib-cpe.yaml -v
```

```
[0011]  INFO scans of grype-upgrade-stdlib-cpe: 14 reused, 14 ran
```

`cache status` shows what the cache holds. The `-o json` form is for scripts:

```bash
bin/yardstick cache status
bin/yardstick cache status -o json | jq '.kinds[] | {kind, entries, size}'
```

```
Path: /Users/me/Library/Caches/yardstick

KIND    ENTRIES  SIZE    OLDEST USE
tools   2        168 MB  2026-10-15T13:03:41-04:00
dbs     1        3.3 GB  2026-10-15T13:03:28-04:00
sboms   0        0 B     -
scans   42       40 MB   2026-10-15T13:03:41-04:00
claims  0        0 B     -
total   45       3.5 GB  2026-10-15T13:03:28-04:00
```

`cache delete` removes entries by kind (`tools`, `dbs`, `sboms`, `scans`, `claims`; every kind when none is named), and with `--older-than` only those last used longer ago than that. The output below is from a scratch cache (`YARDSTICK_CACHE_DIR` pointed at a copy of `tools/` and `scans/`), so the real one stays intact:

```bash
bin/yardstick cache delete scans --older-than 30d
bin/yardstick cache delete scans
bin/yardstick config/gates/grype-upgrade.yaml -v
```

```
removed 0 entries, freed 0 B

removed scans/eb8c8c61...cff98e.json (615 kB)
removed scans/f7c737a9...ed90f8.json (667 kB)
...
removed 42 entries, freed 40 MB

[0021]  INFO scans of grype-upgrade: 0 reused, 28 ran
```

Nothing was older than 30 days, so the first command removed nothing. After the second the next run rescans everything.

Where things live:

- the cache: `~/Library/Caches/yardstick` on macOS, `~/.cache/yardstick` on Linux, or `$YARDSTICK_CACHE_DIR`. It holds tools, DBs, SBOMs, scans and claims, and shrinks only when `cache delete` runs.
- the per-gate copies: `.yardstick/runs/<name>/<gate>/` in the directory you ran from, with `reference/`, `candidate/` and `yardstick-run.json`. The name is `default` unless `--name` says otherwise (step 10).

## 10. Keep runs apart by name

Every run so far wrote to `.yardstick/runs/default/`. `--name` picks another directory, so several runs of one gate can be kept side by side, for example one per branch or per CI job. `YARDSTICK_NAME` sets it once for a whole job, and the flag wins over it:

```bash
bin/yardstick config/gates/os-packages.yaml --name nightly -v
YARDSTICK_NAME=pr bin/yardstick config/gates/os-packages.yaml -v
ls .yardstick/runs
```

```
[0003]  INFO scans of os-packages: 8 reused, 0 ran
[0002]  INFO scans of os-packages: 8 reused, 0 ran

default  nightly  pr
```

The name changes where the copies land, never whether a scan runs: both runs reused every scan from the cache. `score` and `claims add` take the same `--name` and read only that run:

```bash
bin/yardstick score config/gates/os-packages.yaml --name nightly -q
bin/yardstick score config/gates/os-packages.yaml --name pr -q
```

```
PASSED 1 of 1 gates
PASSED 1 of 1 gates
```

A bare `score` reads `default`, not whichever run was last. A name is one path segment of lowercase letters, digits, `.`, `_` and `-`, starting with a letter or digit. Anything else is refused with exit 2 before a gate loads. Python yardstick's `tools/`, `result/` and `labels` can sit beside `runs/` in `.yardstick/`, and yardstick never touches them.

## 11. Run a gate one step at a time

A gate run is three steps, and each also runs on its own: `collect sboms --gate` builds the image SBOMs that no claims source and no cache holds, `collect scans` writes the gate's scans, and `score` scores them. `yardstick <gate.yaml>` is all three in one. Split, a CI job can scan in one step and judge in another, since `collect scans` exits 0 once the scans are written, whatever they would score:

```bash
bin/yardstick collect sboms --gate config/gates/os-packages.yaml
bin/yardstick collect scans config/gates/os-packages.yaml -v
bin/yardstick score config/gates/os-packages.yaml -q
```

```
[0002]  INFO scans of os-packages: 8 reused, 0 ran

PASSED 1 of 1 gates
```

The corpus holds all four SBOMs, so `collect sboms` builds nothing and prints nothing, and it never runs grype. `collect scans` takes the root's flags except `-o` and `--details`, and prints no report.

`--rebuild-sboms` builds every SBOM the gate names, the corpus's included, with the syft `claims/catalog.yaml` pins, and writes each into the cache, where a `--rebuild-sboms` gate run finds it. A second run finds them there and builds nothing:

```bash
bin/yardstick collect sboms --gate config/gates/os-packages.yaml --rebuild-sboms
bin/yardstick collect sboms --gate config/gates/os-packages.yaml --rebuild-sboms
```

```
wrote /Users/me/Library/Caches/yardstick/sboms/sha256:ddac200f...75f9/sha256-668b53d2...05be.syft.json
wrote /Users/me/Library/Caches/yardstick/sboms/sha256:c95b7b93...3114/sha256-668b53d2...05be.syft.json
wrote /Users/me/Library/Caches/yardstick/sboms/sha256:be383459...d507/sha256-668b53d2...05be.syft.json
wrote /Users/me/Library/Caches/yardstick/sboms/sha256:69ae7f13...4b40/sha256-668b53d2...05be.syft.json
```

The first run took about 35 seconds, most of it pulling the four images. A build that fails exits 2 here, where a gate run would warn and scan the SBOM the corpus holds.

## 12. Label in the map UI

`claims serve` is a local web UI over every gate scanned under the run (`--name`, default `default`). It shows a gate's checks as range bars and its deltas as a treemap grouped by direction, then reason, then source package, and opens one match at a time to label. With no gate argument it opens the gate scanned last that can be scored. A gate it cannot score, here `os-packages-remote` without `YARDSTICK_CLAIMS_URL`, is listed with its error and skipped, and the other gates work as usual:

```bash
bin/yardstick claims serve --addr 127.0.0.1:7733 --author "$(git config user.name)"   # --open opens a browser; the default address is 127.0.0.1:7655
```

```
research is disabled: the yardstick plugin is not installed in Claude Code
  to enable it, run: claude plugin install yardstick --marketplace anchore/yardstick
labeling at http://127.0.0.1:7733/ (ctrl-c to stop)
```

`/` redirects to `/ui/map/gates/grype-upgrade/`, the gate's board, and `/ui/map/gates/` is the cross-gate view: every gate's outcome and the open findings that bear on more than one gate. The JSON behind both is plain HTTP:

```bash
curl -s http://127.0.0.1:7733/api/gates | jq -c '{open, gates: [.gates[] | {id, error}]}'
curl -s http://127.0.0.1:7733/api/gates/grype-upgrade/state | jq -c '[.gate.result.checks[] | {name, worst: .value.worst}]'
```

```
{"open":"grype-upgrade","gates":[{"id":"grype-upgrade","error":null},{"id":"os-packages-remote","error":"claims source github.com/anchore/delta-prototype@main: no publication host to read it from; set YARDSTICK_CLAIMS_URL to the base URL snapshots are published under"}]}
[{"name":"f1NotWorse","worst":0.8936170212765957},{"name":"noNewFalseNegatives","worst":73},{"name":"noNewFalsePositives","worst":0},{"name":"unjudgedChangesAtMost","worst":69}]
```

### Label with a justification

In a match's tile, `t`, `f` and `u` label it tp, fp or unclear. fp and unclear need a justification from `vocabulary.yaml`, picked from the select under the buttons; pressing `f` without one focuses the picker. The label is written into the gate's last claims source, here the corpus, with `seenIn` filled from the run, and the gate re-scores at once. Before writing, the tile previews what the label would do to each check. These are the requests the tile makes, for an unlabeled stdlib drop on the Go image (the write token is in the page's `yardstick-token` meta tag):

```bash
G=http://127.0.0.1:7733/api/gates/grype-upgrade
TOKEN=$(curl -s http://127.0.0.1:7733/ui/map/gates/grype-upgrade/ | sed -n 's/.*name="yardstick-token" content="\([^"]*\)".*/\1/p')
curl -s -X POST $G/preview -d '{"labels":{"570fde49d2641fcb":"fp"}}' | jq -c '[.checks[] | {name, worst: .value.worst}]'
curl -s -X POST -H "X-Yardstick-Token: $TOKEN" $G/labels -d '{"rows":["570fde49d2641fcb"],"verdict":"fp","scope":"subject"}'
curl -s -X POST -H "X-Yardstick-Token: $TOKEN" $G/labels \
  -d '{"rows":["570fde49d2641fcb"],"verdict":"fp","justification":"vulnerable_code_not_present","note":"demo","scope":"subject"}'
git diff --stat claims
```

```
[{"name":"f1NotWorse","worst":0.8936170212765957},{"name":"noNewFalseNegatives","worst":72},{"name":"noNewFalsePositives","worst":0},{"name":"unjudgedChangesAtMost","worst":68}]
.../go-module.json: label CVE-2023-24531 on pkg:golang/stdlib@1.16.9: fp needs a justification (one of: component_not_present, different-product, fix-installed, introduced-later, not-a-vulnerability, not-recorded, other-platform, vendor-not-affected, vulnerable_code_not_present)
{"written":1,"overridden":[]}
```

The second request is refused with 400 and writes nothing. After the third, `/state` reads the same as the preview: the drop no longer counts toward `worst` for either check (73 to 72, 69 to 68). Row ids are a hash of the subject and the match, stable across re-scoring; yours are in `/state` and in `score -o json` (`row`). Undo it as in step 6, with `git checkout claims`.

### Agent hints and the plugin

Agents never write labels. They write proposals, package-level causes and explanations to `.yardstick/` (gitignored, beside `runs/`), and the map shows them as hints for a person to accept (`a` on a row, `A` for a cause or every high-confidence hint in view). Accepting writes the same label a person's verdict would. None of it counts for scoring until then.

The skills that write them ship as a Claude Code plugin in `plugin/`: `/yardstick:triage-deltas`, `/yardstick:research-vuln` and `/yardstick:explain-deltas`. The map's research buttons run `research-vuln` jobs in the background, and need the plugin installed at the binary's version, which is what the warning above says:

```bash
claude plugin install yardstick --marketplace anchore/yardstick
```

To try the skills without installing anything, `--plugin-dir` loads the plugin for one session. This triages the gate's unlabeled differences and records three proposals (the skill's script fetches from cve.org, OSV, NVD and GitHub, about 4 minutes for this gate's 90 rows; if Python's certificate check fails behind a proxy, set `SSL_CERT_FILE=/etc/ssl/cert.pem`):

```bash
PATH=$PWD/bin:$PATH claude -p "/yardstick:triage-deltas $PWD grype-upgrade
Run the triage script once, in the foreground. Then record at most 3 proposals: pipe only the first 3 lines
of proposals.jsonl into yardstick claims propose. Skip propose-cause and research, never run yardstick claims add." \
  --plugin-dir $PWD/plugin --model sonnet --allowedTools "Bash Read Write Edit Grep Glob"
wc -l .yardstick/proposals.jsonl
curl -s $G/state | jq -c '[.subjects[].rows[] | select(.hint) | {id, hint: (.hint | {status, verdict, justification, confidence})}]'
```

```
3 .yardstick/proposals.jsonl
[{"id":"570fde49d2641fcb","hint":{"status":"pending","verdict":"fp","justification":"different-product","confidence":"medium"}},{"id":"8a49cd68db6a7e0f","hint":{...}},{"id":"2a98801070c00c18","hint":{...}}]
```

The full triage, every proposal and the evidence behind it, is under `.yardstick/triage/default/grype-upgrade/` (`proposals.md`, `evidence.md`). A proposal is about a subject, package and vulnerability, the same key a label has, so one proposal covers every row of that package in the image (here two `stdlib@1.18.4` binaries). Accepting one is what `a` does in the tile:

```bash
curl -s -X POST -H "X-Yardstick-Token: $TOKEN" $G/accept -d '{"rows":["570fde49d2641fcb"]}'
curl -s $G/rows/570fde49d2641fcb | jq -c '{hint: .hint.status, label: .label.label | {verdict, justification, evidence: (.evidence | length)}}'
```

```
{"written":1}
{"hint":"agrees","label":{"verdict":"fp","justification":"different-product","evidence":1}}
```

The label carries the proposal's justification, note and evidence (its `facts` with their sources and URLs), drops its confidence, and is authored by the person who accepted it. Proposals are agent claims, so read the evidence before accepting: this one rests on OSV having no Go advisory for the CVE. Undo the label with `git checkout claims`; the proposals stay in `.yardstick/` until removed.

### The agent CLI

The skills call these, and they work on their own too. `--gate` takes a gate file or a gate scanned under `--name`, and `score` takes either form as well:

```bash
bin/yardstick score grype-upgrade -q
bin/yardstick claims policy -o json | jq -c '{rules: (.rules | length), justifications: (.justifications | keys)}'
bin/yardstick claims ls -V CVE-2020-29509 -o json | jq -c '.[] | {file, verdict: .label.verdict}'
bin/yardstick claims explain ls --name default --gate grype-upgrade
bin/yardstick claims overrides
```

- `claims propose [file] --gate <gate>` records proposals, one JSON object per line, each naming a `row`. It fills in the subject, package and vulnerability from the row and refuses a line the policy rejects: an unknown rule, a verdict the rule does not give, a confidence over the rule's ceiling, or an fp or unclear with no justification.
- `claims propose-cause` records a cause, one call covering several rows, and `claims explain propose` an explanation of why a group of rows differs, checked against the grype logs the run kept.
- `claims ls` lists the current labels, `claims overrides` the proposals a person overrode, grouped by rule, and `claims policy` the rules and justifications the skills read.

## Known noise

`cbl-mariner` prints a platform warning: its label files record `linux/arm64`, while the corpus catalog builds `linux/amd64`.
