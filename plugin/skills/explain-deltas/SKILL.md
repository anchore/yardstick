---
name: explain-deltas
description: For one yardstick gate, explain why its two setups' scans differ, one computed reason node at a time — from both sides' grype logs, the grype release notes and the two DBs' records — and record plain-language reasons with log excerpts and facts through `yardstick claims agent explain propose`. No labels, no evidence about whether a match is real.
argument-hint: [workspace dir] [gate]
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, WebFetch, WebSearch, Agent
---

Explain gate deltas: $ARGUMENTS

The scripts live in this plugin, `${CLAUDE_PLUGIN_ROOT}/scripts`. The **workspace** (`<store>` below)
is the directory yardstick runs in, holding `.yardstick/runs/<run>/<gate>/`; it may be somewhere else,
so pass `--store`. Every `yardstick` command below runs in the workspace. The yardstick binary is
`$YARDSTICK_BIN`, else `yardstick` on PATH, else the workspace's `bin/yardstick`
(`go build -o bin/yardstick ./cmd/yardstick` in a yardstick checkout). The run name is `--name`, else
`$YARDSTICK_NAME`, else `default`.

# What this does

`yardstick score <gate> -o json` gives every row one setup reported a computed reason,
`why: {key, from?, to?, secondary?}` (`yardstick claims agent explain propose` lists the keys, in the order
they are tried, when given one it doesn't know). Rows with the
same key + from + to form a **reason node** in the label UI. A computed reason says *what* differs
("same record, not matched (by CPE)"); you find out **why**, and write it down as a **reason**: a short
title that replaces the node's computed title, a note, the member rows, and the log excerpts and
facts that someone can check. A reason is never evidence: evidence says whether a label is true, a
reason says why the scans differ.

What the gate varies decides where to look:

| varied | typical gate | where to look |
|---|---|---|
| grype version | grype PR gate | both sides' grype logs, plus the release notes / commits between the versions |
| grype config | config change | both sides' logs (the config dump at the top, then the matcher's searches) |
| DB | DB update gate | the records on each side (on the row), the advisory sources and their dates |

# Ground rules

1. **A reason carries no label and no evidence.** It says why the sides differ, never
   whether a finding is real. "Is this finding a tp?" stays with `/yardstick:triage-deltas` and
   `/yardstick:research-vuln`. Don't write "false positive", "correct", "noise" or "should be dropped" in a title
   or note; "grype now matches openssl by CPE" is a reason, "grype now reports CPE false
   positives" is a label.
2. **An excerpt or a fact, or an open question.** Every causal sentence in the note rests on a log excerpt or a
   fact. When you can't show it, say so in `openQuestions` instead of asserting it.
3. **Copy log text exactly**, through the helper's `excerpt` command; `propose` refuses an excerpt that
   is not exactly lines `[start, end]` of the decompressed log, or is over 8 KiB.
4. **Split by real cause, not by computed key.** One node may need several reasons (dpkg rows
   changed by one PR, rpm rows by another), and rows with no excerpt or fact stay unexplained. A row is
   in at most one reason per gate.
5. **Never write to a workspace you were not given.** Reasons go into `<store>/.yardstick/explanations.jsonl` through `yardstick claims agent explain propose`; never write that file directly.

# Phase 1: load the gate (seconds)

Arguments: `[workspace dir] [gate]`. The workspace is the first argument, else `$YARDSTICK_ROOT`,
else the current directory, else ask; the gate is the second, else `$YARDSTICK_GATE`, else the gate
scanned last (`ls -t <store>/.yardstick/runs/<run>`).

```bash
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-explain-evidence.py load --store <store> [--gate <gate>] [--name <run>] --model <your model id>
```

It reads `yardstick score <gate> -o json`, the run record (`.yardstick/runs/<run>/<gate>/yardstick-run.json`)
and `yardstick claims agent explain list --name <run> --gate <gate> -o json`, decompresses every log the run kept (checking
the sha256 the run record holds, which is of the decompressed text) and writes
`<store>/.yardstick/explain/<run>/<gate>/`:

- `gate.md`, read this first:
  - each side's grype version, DB (built date from the archive name) and config, and **what varied**;
  - whether the run kept grype logs, and whether every log's sha256 matched;
  - per subject and package type, how many packages each side searched by CPE (`deb 0/167` on one side
    and `deb 167/167` on the other is a matcher that turned on);
  - the config dump diff (subject 0), so a config change shows as `- ref` / `+ cand` lines;
  - existing reasons;
  - the **nodes** table: key, from → to, rows, rows already explained, which side reported them, and a
    priority (Phase 2);
  - per node, each row: vulnerability, package, the reporting side's namespace / fix state / match
    type / matcher / CPEs / constraints, both DBs' status, **the other DB's records**, and, when logs
    exist, where the package is in each side's log (`block A-B`, `found N at L`, CPE searches with
    record counts, the line where the vulnerability was matched with its namespace, or dropped with
    grype's reason, or "not mentioned").
- `nodes.json`: the same, machine-readable.
- `skeletons.jsonl`: one `yardstick claims agent explain propose` line per node, with `id`, `gate`, `run`
  (the run name), `reason`, `author` and the not-yet-explained `members` filled in, and `title` and
  `note` empty.
- `logs/<side>/NN.log`: the decompressed logs. The line numbers in `gate.md` are theirs, and they
  are the line numbers `propose` checks. `NN` is the subject's index in the run record (`sNN` in
  gate.md is the same index).

Rows already explained are marked and left out of the skeletons. Leave them alone unless asked to redo
them; to redo one, reuse its reason's `id` (the newer line supersedes it).

# Phase 2: prioritise

Explain, in this order:

1. Every node in a gate where **grype or its config varied**. Their rows are matcher or config effects
   until shown otherwise, and they are what a grype PR gate exists to surface.
2. `record/rejected-*`, `package/absent-*`, `namespace/changed`, `fix-state/changed`,
   `constraint/changed`, `record/same-but-unmatched`, `match-type/cpe-only`, `unexplained`.
3. `record/absent-in-<newer DB>` in a DB gate: the newer DB **dropped** a record, which is surprising.

Usually skip `record/absent-in-<older DB>` in a DB gate (a record that is new in the newer DB): the
computed title already says it. Explain it only if something stands out (a burst of records from one
provider, a namespace that never appeared before, a very old CVE that is suddenly new). The priority
column in `gate.md` applies these rules; say in the report which nodes you skipped and why.

For a big node, sample: the log facts in `gate.md` are per row, so check they agree across all rows with
`jq` on `nodes.json`, split by whatever might separate causes (package type, subject, matcher), and
read the logs closely for two or three packages only. For a node reported by the candidate:

```bash
jq '.nodes[0].rows | group_by(.package|split("/")[0]) | map({type: .[0].package|split("/")[0], rows: length,
     candMatchedAfterCpeSearch: map(select(.logs.candidate.cpeSearches>0 and (.logs.candidate.matched|length)>0))|length,
     refNoCpeSearch: map(select(.logs.reference.cpeSearches==0 and (.logs.reference.matched|length)==0))|length,
     subjects: (map(.subject)|unique)})' <store>/.yardstick/explain/<run>/<gate>/nodes.json
```

Equal counts in every column mean one mechanism covers the group; a group whose counts differ needs
its own look, and maybe its own reason.

# Phase 3: gather excerpts and facts, per node

Collect them as you go into two lists per reason: **facts** in the label evidence fact shape,
`{"source", "url", "about": {...}, "field", "value", "observedAt"}` (stable lowercase sources:
`grype-release`, `github-pr`, `github-commit`, `grype-db`, `ubuntu-cve-tracker`, `redhat-csaf`,
`nvd`, `osv`, `cve.org`), and **log excerpts** from the helper:

```bash
x() { python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-explain-evidence.py excerpt --store <store> --name <run> --gate <gate> "$@"; }
x --subject 01 --side candidate --lines 9094-9099 --lines 9445-9447 >  <store>/.yardstick/explain/<run>/<gate>/x-rpm.jsonl
x --subject 01 --side reference --lines 60-61 --lines 3119-3121     >> <store>/.yardstick/explain/<run>/<gate>/x-rpm.jsonl
```

(A shell function, not `X="python3 …"; $X …`: zsh doesn't word-split a variable.) It prints one
`{side, file, lines, text, sha256}` object per range, copied from the log and checked against
the run record. Prefer short excerpts (2 to 15 lines) that show one decision each, and give each
reason at least one excerpt from **each side** when logs exist: what one side did and the other
didn't is the reason.

## Grype or config varied (logs)

1. **Is the config the same?** `gate.md` says whether the config dumps differ. If gate.md says only
   grype varied but the dumps differ (a new default in the new version), that is itself a cause: cite
   the differing lines from both sides' dumps.
2. **What did each side do with the row's package?** For each sampled row, open both logs at the
   package's `block` and compare:
   - `fetched package record distro=… pkg=package(name=…) records=N`: the distro/language search;
   - `fetched CPE record cpe=… records=N`: a CPE search (the matcher's CPE path ran);
   - `dropped vuln … reason=… vulnerability=…`: grype considered the record and rejected it, and why;
   - `found N vulnerabilities package=…` then `├── namespace=… vuln=…`: what it reported. No `found`
     line means 0 matches.
   Typical causes: one side has no `fetched CPE record` lines for the package type at all (the CPE
   path didn't run); both searched but one dropped the record (`reason=` says why: a version
   comparison, a fix state, an ignore rule); the record came back under a different namespace.
   `grep -n '<package name>\|<CVE>' logs/<side>/NN.grype.log` finds the lines.
3. **Which change did it?** For a version change, list the releases in between, reference version
   first (the older one; swap the two if the candidate is older):

   ```bash
   python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-explain-evidence.py releases --from <reference grype> --to <candidate grype> \
       --grep cpe --grep <matcher or package type, e.g. dpkg> [--pr <N> ...] --facts-out <store>/.yardstick/explain/<run>/<gate>/facts-release.jsonl
   ```

   It prints the matching release-note lines with their release URL, the compare URL, and with `--pr N`
   the PR's title and merge time, and writes them as facts (`grype-release` / `github-pr`). Run it once
   without `--pr` to find the candidate PRs, then again with them, once per reason, and keep only
   the facts that reason cites: `jq -c 'select(.about.pr=="3753")' facts-release.jsonl > facts-rpm.jsonl`.
   Read the PR description (`curl -s https://api.github.com/repos/anchore/grype/pulls/<N> | jq -r .body`)
   to confirm it changes what the logs show, before you name it. If the notes don't name it, read the
   compare page (`https://github.com/anchore/grype/compare/<ref>...<cand>`) or the commits API
   (`https://api.github.com/repos/anchore/grype/compare/<ref>...<cand>`, `.commits[].commit.message`)
   and look for commits touching the matcher in the logs (`grype/matcher/<type>/`). Name the PR in the
   title. Without a PR, the reason can still state what the logs show, with an open question
   "which commit between X and Y changed this?".
   The helper calls the GitHub API directly (no `gh` needed; `gh` may not be able to read its config in
   a sandbox). It allows 60 unauthenticated requests an hour, and responses are cached for a day:
   `export GITHUB_TOKEN=$(gh auth token)` first if `gh` works here.

## DB varied (records)

1. The row carries both sides' views: the reporting side's detail (namespace, fix state, constraints)
   and **the other DB's records** (`otherRecords` in nodes.json; from `grype db search` at scan time,
   with each side's own grype against its own DB). Statuses (`active`, `rejected`, `not-in-db`) are per
   DB. That is usually enough to say *what* changed; the reason is *why* the source changed.
2. To see every provider's records for the node's vulnerabilities in both DBs (the row only carries
   the records for its own package), search each side's DB with that side's grype:

   ```bash
   python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-explain-evidence.py records --store <store> --name <run> --gate <gate> \
       --vuln CVE-2023-45918 --vuln CVE-2024-6716 [--pkg ncurses] --cve-org --facts-out <store>/.yardstick/explain/<run>/<gate>/facts-db.jsonl
   ```

   It prints one line per provider / status / namespace / package / fix state per side and writes a
   `grype-db` "providers" fact per vulnerability and side (and cve.org's state with `--cve-org`). It
   finds the side's grype and DB in yardstick's cache (`tools/grype/<version>/grype` and
   `grype-db/<checksum>` under `$YARDSTICK_CACHE_DIR`, else `<user cache>/yardstick`), else grype on
   PATH. A provider present on one side and gone on the other, across several
   vulnerabilities, is the pattern to look for. By hand it is
   `GRYPE_DB_CACHE_DIR=<that grype-db dir> GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false <grype> db search --vuln <CVE> -o json`.
3. Then the source behind the record, for the DB's build date: Ubuntu's tracker
   (`https://ubuntu.com/security/<CVE>` and the raw file, which `yardstick_common.ubuntu_tracker_file`
   fetches), Red Hat (`https://access.redhat.com/security/cve/<CVE>`, CSAF VEX via
   `scripts/yardstick_redhat.py`), NVD (`yardstick_common.nvd_cve`), cve.org (`yardstick_common.cve_org`, for
   REJECTED state and its date), GHSA/OSV. The helpers in `scripts/yardstick_common.py` cache under
   `~/.cache/yardstick-skills/`; import them with
   `python3 -I -c 'import sys; sys.path.insert(0, "${CLAUDE_PLUGIN_ROOT}/scripts"); import yardstick_common as dc; ...'`.
   `dc.ubuntu_facts(dc.ubuntu_cve(cve), cve, source_pkg, "focal")` returns recheckable
   `ubuntu-cve-tracker` facts; the raw tracker file (`dc.ubuntu_tracker_file`) shows every pocket
   (`focal_x: ignored (end of standard support)` next to `esm-infra/focal_x: not-affected`), which
   ubuntu.com's JSON collapses.
   Since vunnel v0.61.0 (anchore/vunnel#1212) the Ubuntu provider reads Canonical's **OSV and OpenVEX
   feeds**, not the tracker, so a DB built after June 2026 follows OSV
   (`dc.fetch_json("https://api.osv.dev/v1/vulns/UBUNTU-<CVE>")`: its `details`, `withdrawn` and
   `affected[].package.ecosystem`, e.g. `Ubuntu:20.04:LTS` vs `Ubuntu:Pro:20.04:LTS`). The tracker can
   still list a package the newer DB no longer has. Since vunnel v0.64.0 (#1342) the provider skips
   a CVE whose OSV `details` starts `** REJECT **` or `Rejected reason:`; a CVE that cve.org rejected
   but whose OSV text doesn't say so is not covered by that rule.
   Typical causes: the CVE was rejected at cve.org between the two builds (cite the rejection date);
   the distro moved the package to not-affected; a new provider namespace took over; an ESM-only fix.
   A record can also change because the DB **build** changed (a vunnel or grype-db release, or a local
   build compared with the published one; the DB source path in gate.md shows which). The DB doesn't
   record its vunnel / grype-db versions, so unless a release note names the change, say what the
   records show and leave "which build change did this?" as an open question. Don't name a release you
   haven't tied to these records. The `releases` helper only reads grype; for a provider change, grep
   the vunnel / grype-db release notes since the older build
   (`https://api.github.com/repos/anchore/vunnel/releases?per_page=40`), list the commits on the
   provider (`…/commits?path=src/vunnel/providers/<name>`), and to tie a PR to the records, grep the
   provider's code at the commit before and after it (`https://raw.githubusercontent.com/anchore/vunnel/<sha>/<path>`).
   Cite them as `github-pr` / `github-commit` facts with `about.repo` set.
4. Scans without logs (log level `none`, or made before capture) take this path only.

If parallelising, one subagent per node at most, each told the node number, the gate.md path, and to
return the reason lines (not to propose them).

# Phase 4: write the reasons

Start from the node's line in `skeletons.jsonl`; write one JSON object per reason (split a node
by cause, each with a distinct `id`, e.g. the skeleton's id plus `-dpkg`) to
`<store>/.yardstick/explain/<run>/<gate>/explanations.jsonl`:

- `title`: becomes the UI node title. Plain words, at most about 80 characters, says **why**, names
  the change: "grype v0.120.0 made match.rpm.using-cpes take effect (anchore/grype#3753)". Not the
  computed reason again, not a label.
- `note`: 2 to 4 sentences: what each side did (from the logs or records), what changed and where
  (release, PR, source record), and the scope ("every rpm package on UBI8; no other package type").
- `reason`: the computed key this reason refines (the skeleton has it); drop it only if it spans
  keys.
- `members`: the rows this cause covers, `{row, vulnerability, package}` (from the skeleton; delete the
  rows that belong elsewhere). Never list a row you did not check belongs to this cause; for a sampled
  node, the `jq` check in Phase 2 is what lets you include the rest.
- `facts`, `logExcerpts`: from Phase 3.
- `openQuestions`: whatever you could not show.
- `author`: `{"kind": "agent", "skill": "explain-deltas", "model": "<your model id>"}`.
- No `verdict`, `confidence`, `justification` or other fields: `propose` rejects unknown fields.

Assemble the lines with `jq` rather than by hand, so excerpts stay byte-exact, e.g.:

```bash
D=<store>/.yardstick/explain/<run>/<gate>
: > $D/explanations.jsonl
jq -c 'select(.reason=="record/same-but-unmatched")' $D/skeletons.jsonl \
  | jq -c --slurpfile x $D/x-rpm.jsonl --slurpfile f $D/facts-rpm.jsonl \
      --arg title "grype v0.120.0 made match.rpm.using-cpes take effect (anchore/grype#3753)" \
      --arg note "Both sides ran with match.rpm.using-cpes: true. …" \
      '.id += "-rpm" | .title = $title | .note = $note | .members |= map(select(.package | startswith("pkg:rpm/")))
       | .logExcerpts = $x | .facts = $f | .openQuestions = []' >> $D/explanations.jsonl
```

(`--arg` keeps apostrophes and quotes in the note out of shell quoting; add
`--argjson q '["…"]'` and `.openQuestions = $q` for open questions.) Scans without logs have no
excerpts; its reasons rest on facts alone.

# Phase 5: propose

```bash
yardstick claims agent explain propose --name <run> --gate <gate> <store>/.yardstick/explain/<run>/<gate>/explanations.jsonl
yardstick claims agent explain list --name <run> --gate <gate>
```

Nothing is written unless every line is valid. Fix what it reports (a member row not in the gate's scans, a
row in two reasons, an excerpt that doesn't match its lines or sha256, an unknown field) in the
file and rerun; don't drop an excerpt or a fact to get past a check.

# Phase 6: report

In chat, numbered:

1. What the gate varied, and each node: rows, explained or not.
2. Each reason: title, member count, support (N excerpts from which sides, which facts), and the
   id `propose` stored.
3. What you left unexplained and why (routine node, no excerpt or fact, sampled out), and the open questions.
4. The SASE: `! yardstick claims serve <gate>` (in the workspace) and what to look for: the map's
   reason nodes whose rows all share one explanation show its title, marked ✎.

# Known gaps

- Log facts are found by grype's trace message text (`searching for vulnerability matches`, `fetched
  CPE record`, `dropped vuln`, `found N vulnerabilities`, the `├──` tree). A grype release that rewords
  them breaks the per-row log summary in `gate.md` (it shows "package not in this log"); the logs
  themselves are still there to grep.
- A debug-level log has no per-record lines (no CPE searches, no drops), so it can show only the
  config dump and the `found N` counts.
- The CPE-by-type summary counts packages with at least one CPE search; it doesn't say which matcher
  made it.
- A DB doesn't record the vunnel / grype-db versions that built it, so a DB-varied reason can
  rarely name the build change behind a record; it names the source change when there is one.
- The helper's parsing is covered by `scripts/test_explain.py` (offline, from trimmed real logs):
  `python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/test_explain.py`.
