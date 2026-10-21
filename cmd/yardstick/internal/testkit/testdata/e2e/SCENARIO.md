# Label UI end to end scenario

The workspace `make e2e` serves (`testkit.E2E`, started by `testkit/seed`). Every fact below was read from a real scan of this material, and `testkit/e2e_test.go` asserts them, so a drift fails `go test` before any browser does. Row ids are derived from the scan and are the same on every seed.

## What is in the workspace

- `gates/deb-java.yaml`, `gates/deb-npm.yaml`: real gate files, copied from here
- `claims/`: vocabulary, catalog, the labels below, and the SBOMs of the three images (written from `internal/fixture/testdata`, real syft output)
- `tools/`: one stub grype per setup in `setups.yaml`. A stub prints the fixture grype output (v0.120.1, real grype) with the listed matches left out. It is not a grype, so the DB search the report does to explain a change fails and every change reads `unexplained`
- `.yardstick/{proposals,causes,explanations}.jsonl`: recorded through `yardstick claims agent propose`, `propose-cause` and `agent explain propose` from `agent/<gate>/*.jsonl`. Those files name rows as `<subject> <vulnerability> <package name> [<location>]`, the subject by its UI name, and the seed resolves them to ids

Images, as the gates refer to them: plain refs with no `name:`, so the UI calls each by its repository base and tag (`subjectName`), and `?image=` uses that with `:` as `-`. The digest is the fixture image's manifest digest from its SBOM, and the tag is its first 7 hex characters. Below, `deb`, `java` and `npm` are short for these:

| short | ref | UI name | matches |
|---|---|---|---|
| deb | `oci:ghcr.io/anchore/test-images/vulnerabilities-debian-12-tar-util-linux:617d48d@sha256:617d48dd...` | `vulnerabilities-debian-12-tar-util-linux:617d48d` | 235 |
| java | `oci:ghcr.io/anchore/test-images/grype-quality-java-log4j-two-jars:e363e44@sha256:e363e444...` | `grype-quality-java-log4j-two-jars:e363e44` | 14, log4j-core in two jars |
| npm | `oci:ghcr.io/anchore/test-images/grype-quality-npm-babel:8e253b5@sha256:8e253b5f...` | `grype-quality-npm-babel:8e253b5` | 1 |

The images are still the `yardstick-fixture-*` fixtures (the stub grype finds an image by that name inside its SBOM); only the refs the gates use look like real test images.

Setups (`setups.yaml`, matches each stub leaves out, per image):

| setup | deb | java | npm |
|---|---|---|---|
| candidate-a | tar CVE-2005-2541, tar CVE-2026-18508, tar CVE-2026-5704, libgnutls30 CVE-2011-3389 | | |
| reference-a | util-linux, libblkid1, libmount1, mount (all CVE-2026-3184) | log4j-core GHSA-jfh8-c2jp-5v3q, GHSA-vc5p-v9hr-52mj | |
| candidate-b | tar CVE-2005-2541, gzip CVE-2026-41992 | | @babel/traverse GHSA-67hx-6x53-jw92 |
| reference-b | | | |

A match the candidate leaves out is a change the candidate **dropped**; one the reference leaves out is **added** by the candidate.

## Labels already present

Written with `yardstick claims add` (author `e2e`), checked in under `claims/`:

| file | package | vulnerability | verdict | justification |
|---|---|---|---|---|
| `claims/global/deb.json` | `pkg:deb/debian/libgnutls30` | CVE-2011-3389 | fp (global) | fix-installed |
| `claims/pkg/oci/ghcr.io/anchore/test-images/vulnerabilities-debian-12-tar-util-linux/sha256-617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0/deb.json` | `pkg:deb/debian/libc6` | CVE-2026-5450 | tp | no-fix |
| same file | `pkg:deb/debian/tar` | CVE-2026-5704 | fp | fix-installed, note "fixed in the installed 1.34+dfsg-1.2+deb12u1 build" |
| `claims/pkg/oci/ghcr.io/anchore/test-images/grype-quality-java-log4j-two-jars/sha256-e363e4447342edd5320a67f79c6980a1ab26f5a9af3e9fdee5bf14e86b2a4c65/java-archive.json` | `pkg:maven/org.apache.logging.log4j/log4j-core` | GHSA-vc5p-v9hr-52mj | unclear | not-assessed, note "needs a look at the JNDI lookup config" |

The two fp labels sit on dropped changes, so those are judged and not open. libc6 is on a match both setups report (it makes the deb subject score). The unclear label sits on the two vc5p rows, and **unclear does not judge a row**: both stay open.

Vocabulary justifications: fp `fix-installed`; tp `no-fix`; unclear `not-assessed`.

## Gate deb-java (initial outcome fail)

Subjects `deb` and `java` (image order 1, 2). Checks:

| check | state | value (worst subject) |
|---|---|---|
| f1NotWorse (tolerance 0) | fail | 0.5 |
| noNewFalseNegatives (max 0) | fail | 2 |
| noNewFalsePositives (max 0) | fail | 4 |
| unjudgedChangesAtMost (max 0) | fail | 6 |

unjudgedChangesAtMost is a count of unlabeled changes, known exactly, so it passes or fails and is never undecided. `/api/gates` reports `gateOutcome: "fail"`. 12 changes in all: 4 dropped (2 labeled fp), 8 added. 10 are open.

Open rows (all `unlabeled` unless noted). Image is the subject, direction is from the candidate:

| row | image | package | vulnerability | direction | hint | cause | explanation |
|---|---|---|---|---|---|---|---|
| `0fe9fc814bcd060a` | deb | tar 1.34+dfsg-1.2+deb12u1 | CVE-2005-2541 | dropped | fp fix-installed | | |
| `e3bfd3b0b0c30ee6` | deb | tar | CVE-2026-18508 | dropped | none | | |
| `9f5eb52729c83cc1` | deb | util-linux 2.38.1-5+deb12u3 | CVE-2026-3184 | added | | yes | yes |
| `d2572e8f87a44f74` | deb | libblkid1 | CVE-2026-3184 | added | | yes | yes |
| `781d813b74ed9e10` | deb | libmount1 | CVE-2026-3184 | added | | yes | yes |
| `12fab8dbf4fcf9e8` | deb | mount | CVE-2026-3184 | added | | yes | yes |
| `e1af7851f0e60bb4` | java | log4j-core 2.14.1, `/opt/app-a/lib/log4j-core-2.14.1.jar` | GHSA-jfh8-c2jp-5v3q (group CVE-2021-44228) | added | tp no-fix | | |
| `783bbb63489d81a6` | java | log4j-core 2.14.1, `/opt/app-b/lib/log4j-core-2.14.1.jar` | GHSA-jfh8-c2jp-5v3q | added | tp no-fix | | |
| `42c45bf99e4f741b` | java | log4j-core, app-a jar | GHSA-vc5p-v9hr-52mj (group CVE-2025-68161), verdict `unclear` | added | tp no-fix | | |
| `a88b3bd584c62516` | java | log4j-core, app-b jar | GHSA-vc5p-v9hr-52mj, verdict `unclear` | added | tp no-fix | | |

Not open, deltas already labeled fp: `c54934489d4ac861` (libgnutls30 CVE-2011-3389, the global label) and `6d210210168e93db` (tar CVE-2026-5704).

Agent material:

- proposals (hints) are keyed by package and vulnerability, so one covers both jars. Three recorded: tar CVE-2005-2541 fp (medium); log4j-core GHSA-jfh8-c2jp-5v3q tp (medium); log4j-core GHSA-vc5p-v9hr-52mj tp (medium). All by skill `triage-deltas`, model `e2e`
- one cause (package hint) on source package `util-linux`, title "CVE-2026-3184 on util-linux and the binary packages built from it", direction added, tp no-fix medium, 4 members (the four util-linux rows)
- one explanation, "the reference setup does not report CVE-2026-3184 on util-linux", the same 4 rows
- research (`POST .../research`, and `POST /api/research` across gates) runs a stand-in that records a tp proposal (medium, note "e2e research stand-in") for the row it is asked about, then prints a claude result line, so every finished job costs $0.25 (10,030 tokens in, 400 out, 2 s)
- across gates, research on the seed finds two rows with no hint or cause, babel `24160b879ac36bf5` and tar `e3bfd3b0b0c30ee6`, and neither can change a gate; the other 10 open rows have a hint or a cause

Labels that flip deb-java to PASS. Accepting hints and the cause does most of it, one row needs a hand label:

| action | rows | verdict |
|---|---|---|
| accept the tar hint, or label by hand | `0fe9fc814bcd060a` | fp, fix-installed |
| label by hand (no hint) | `e3bfd3b0b0c30ee6` | fp, fix-installed |
| accept the cause for all 4 members, or label each | the 4 util-linux rows | tp, no-fix |
| accept the log4j hint (or label) | `e1af7851f0e60bb4`, `783bbb63489d81a6` | tp, no-fix |
| accept the vc5p hint (or label), replacing the unclear | `42c45bf99e4f741b`, `a88b3bd584c62516` | tp, no-fix |

The outcome moves as the labels land (measured with `claims add` in this order, and the same through the UI). A subject with no tp or fp label at all fails the three checks that read labels (f1NotWorse, noNewFalseNegatives, noNewFalsePositives) with "no tp or fp label applies to this subject", and java has none until its first tp lands:

| after | outcome | checks |
|---|---|---|
| nothing | fail | f1 fail, noNewFN fail, noNewFP fail, unjudged fail (6) |
| both tar rows fp | fail | f1 fail, noNewFN fail, noNewFP fail, unjudged fail (4) |
| plus the 4 util-linux rows tp | fail | f1 fail, noNewFN fail, noNewFP fail, unjudged fail (4, the java rows) |
| plus jfh8 tp (both jars) | fail | f1 and noNewFN pass; noNewFP undecided; unjudged fail (2, the vc5p rows) |
| plus vc5p tp (both jars) | **pass** | all four pass, 0 open |

A tp label on a dropped row would fail noNewFalseNegatives, and an fp label on an added row would fail noNewFalsePositives, so those verdicts do not flip the gate.

## Gate deb-npm (initial outcome fail)

Subjects `deb` and `npm`. One check, `unjudgedChangesAtMost` (max 1), failing with worst-subject value 2 (deb has 2 open, npm has 1). 3 changes, all dropped, all open:

| row | image | package | vulnerability | hint |
|---|---|---|---|---|
| `0fe9fc814bcd060a` | deb | tar | CVE-2005-2541 | fp fix-installed (medium) |
| `5e50fe5b2007001a` | deb | gzip 1.12-1 | CVE-2026-41992 | fp fix-installed (medium) |
| `24160b879ac36bf5` | npm | @babel/traverse 7.22.0 (`/app/node_modules/@babel/traverse/package.json`) | GHSA-67hx-6x53-jw92 (group CVE-2023-45133) | none |

No cause or explanation. The tar row is the same row as in deb-java (same id), so labeling it in either gate moves the other: once it is labeled, deb has 1 open and npm 1, and deb-npm is **pass**. That is the cross-gate effect. Verified by labeling the two tar rows and the rest of deb-java: deb-npm reports pass with 2 rows still open (gzip, babel).

## Every gate (`/ui/gates/?tab=unlabeled`)

`GET /api/gates/shared` lists both gates (deb-npm: fail, open 3; deb-java: fail, open 10) and 10 findings. The tar CVE-2005-2541 finding is in both gates (rows `deb-npm` and `deb-java`, both `0fe9fc814bcd060a`, dropped) with the fp hint. Each other finding is in one gate: gzip CVE-2026-41992 (deb-npm), GHSA-jfh8-c2jp-5v3q and GHSA-vc5p-v9hr-52mj (deb-java, two rows each), GHSA-67hx-6x53-jw92 (deb-npm), tar CVE-2026-18508 (deb-java), and CVE-2026-3184 on util-linux as four findings (deb-java, one row each).

## Notes for the test writer

- every test starts from this workspace: the seed's `POST /__e2e/reset` (called by the shared fixture in `web/e2e/fixtures.ts`) puts the seeded files back and starts a fresh server. Tests run on one worker, since there is one server. Labeling deb-java through is also what settles deb-npm (pass)
- labels land in the files above, with `subject.image` as the gate wrote the ref (tag included); `smoke.spec.ts` reads the deb image's `deb.json`, not `claims/global/deb.json`
- `n` on deb-java opens the log4j row first (a GHSA id, the first open row whose label could move a check), so do not assume a `CVE-` id
- a check lists only what it counts: a labeled row leaves `unjudgedChangesAtMost`, and a tp on an added row leaves `noNewFalsePositives`; `f1NotWorse` lists every changed row, labeled or not
- the image names hold `tar` and `util-linux`, and the binary packages' purls name `util-linux` as upstream, so a search for either matches more than the package; search the purl (`debian/tar@`)
- the gates are listed newest scan first, and two scans across a minute boundary swap, so open a gate by its URL rather than `/`
- the UI writes the row's own purl (version and qualifiers, e.g. `pkg:deb/debian/tar@1.34...?arch=arm64&distro=debian-12`) where `claims add --package` takes a bare one, and an accepted hint carries the proposal's note onto the label; compare labels by package without version
- the labels written for log4j's vc5p sit beside the seeded unclear label (a different package key), so the file holds both; the exact-version tp decides
