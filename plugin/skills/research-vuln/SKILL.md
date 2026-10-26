---
name: research-vuln
description: Deep-dive one vulnerability finding from a yardstick gate — what the bug is, when upstream fixed it, whether the distro shipped or declined the fix, why the two grype DBs disagree — and record a verdict with justification, confidence, reasoning, facts, open questions and a report as a `yardstick claims agent propose` proposal.
argument-hint: <CVE or GHSA id | row:<row id>> [workspace dir] [package name]
disable-model-invocation: true
# the skill reads pages anyone can write (upstream commits, issues, advisories), so it runs only the
# commands it names and writes only under .yardstick/research/; a label is never written here
allowed-tools:
  - Bash(python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-vuln-sources.py *)
  - Bash(yardstick claims agent propose *)
  - Bash(yardstick claims policy)
  - Bash(yardstick claims policy *)
  - Read
  - Grep
  - Glob
  - Edit(.yardstick/research/**)
  - WebFetch
  - WebSearch
---

Research vulnerability: $ARGUMENTS

The scripts live in this plugin, `${CLAUDE_PLUGIN_ROOT}/scripts`. The **workspace** is the directory
yardstick runs in (it holds `.yardstick/runs/`), which may be somewhere else, so pass `--store`
explicitly. Every `yardstick` command below runs in the workspace.

Arguments: the first is `row:<row id>` (a row of `yardstick score <gate> -o json`) or a vulnerability
id. Any other argument that is a directory is the workspace; any other word is the package name.
A research job launched from `yardstick claims serve` runs
`/yardstick:research-vuln row:$YARDSTICK_ROW $YARDSTICK_ROOT` and sets `YARDSTICK_ROOT` (the
workspace), `YARDSTICK_GATE`, `YARDSTICK_NAME` (the run), `YARDSTICK_ROW`, `YARDSTICK_ROWS` (every
row the job covers), `YARDSTICK_RESEARCH_VULNERABILITY`, `YARDSTICK_RESEARCH_PACKAGE`,
`YARDSTICK_BIN`, `YARDSTICK_MODEL` and `YARDSTICK_RESEARCH_JOB`; the helper and `yardstick claims
propose` read them, and propose stamps the job on the proposal.

# The question you are answering

For one vulnerability on one installed package: **does this package, at this exact version, contain
the vulnerable code without the fix?** That decides `tp` (yes) or `fp` (no). The scanner's opinion,
the severity, and whether anyone will ever fix it are context, not the answer. If you cannot get to
yes or no with evidence, the answer is `unclear`, with the open questions written down.

You end with exactly one `yardstick claims agent propose` call. That is the completion signal when this skill
runs headless from `yardstick claims serve`. You never run `yardstick claims add`.

# Phase 1: collect the record (under a minute)

Find the workspace (the directory argument, else `$YARDSTICK_ROOT`, else the current directory). Then:

```bash
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-vuln-sources.py <VULN or row:ID> [--pkg <package>] --store <workspace> --model <your model id> [--gate <gate>] [--name <run>] [--euvd]
```

`--euvd` adds ENISA's EUVD record (provisional: aliases and the CNA's product text; see
`scripts/yardstick_euvd.py`). The gate is `--gate`, else `$YARDSTICK_GATE`, else the gate scanned
last, and the run `--name`, else `$YARDSTICK_NAME`, else `default`. The final `propose` needs the
same gate and run, because row ids are only unique within one gate's last scan under one run.

It writes `<workspace>/.yardstick/research/<VULN>/<package>/`:

- `SUMMARY.md`: both sides' row detail (fix state, constraints, namespace), what each cached DB holds,
  existing labels and notes, the CNA record (state, affected ranges, references), NVD CPE ranges,
  GitHub advisories (the global database and the project's own repository advisory, with its affected
  range, where the installed upstream version sits in it, and the source file it names), OSV, Ubuntu's tracker (every release and pocket for the source package, priority,
  notes, USNs with dates, the raw ubuntu-cve-tracker file with per-pocket statuses and upstream patch
  URLs, Launchpad publishing dates, installed and newest changelogs with the lines that mention the
  CVE, `debian/patches/series` on the security branch), Debian's tracker table and unstable changelog,
  and a link list. One file per source sits next to it.
- `proposal.json`: the `yardstick claims agent propose` skeleton with `row`, `author` and
  `evidence[0].facts` (the facts it observed) filled, and `evidence[0].interpretation` ending with the
  report's path; `verdict`, `justification`, `confidence`, `note`, the rest of the interpretation and
  `openQuestions` are yours.
- `rows.json` when several binary packages share the finding (one proposal each, see Phase 4).

Read `SUMMARY.md` first. Open the per-source files only for what the summary does not settle.

# Phase 2: establish the facts, in this order

Write each fact with its source next to it. Label anything you inferred as inference.

1. **What the bug is**: the function or file, from the CNA/NVD description and the fix commit. Find
   the fix commit via the Ubuntu `Patches_` lines, the CNA references, the GHSA, or the upstream
   advisory. `WebFetch` the commit or PR page when the description does not name the code.
2. **When upstream introduced and fixed it**: the fixed release, and, if the CNA only names the
   version someone fuzzed, the introducing commit. The project's own GitHub advisory in SUMMARY.md
   is the first place to look: its range ("affected >= 2.40") is the maintainers' statement of the
   introduction, and its text names the file. A distro CNA that lists its older releases as
   unaffected is the second: look up what those releases ship (RHEL 8 has util-linux 2.32, RHEL 9
   2.37; both "unaffected" brackets focal's 2.34). Then check whether the touched file or function
   exists at the installed upstream version: `https://raw.githubusercontent.com/<org>/<repo>/<tag>/<path>`
   or the project's tag browser. "The function does not exist at 2.14.02" is the strongest `fp`
   evidence there is; "the vulnerable lines are present unchanged" is the strongest `tp` evidence.
3. **What the distro did with it**: the status for this release in every pocket (ESM pockets carry
   the Ubuntu Pro assessment of the same source version: a "not-affected (code not present)" there
   applies to the non-Pro build too; ubuntu.com's JSON collapses pockets, the raw file does not). The
   reason in brackets. The fix version, compared with the installed version using dpkg ordering.
   Whether the installed version's changelog or patch series mentions the CVE (backports are applied
   without a version bump upstream would recognize). Launchpad dates tell you whether the fix shipped
   before or after the image was built.
4. **Why the two DBs differ**: which side has the record, with what fix state and constraint, and the
   vunnel behavior behind it. Common cases: an ESM-only fix becomes `wont-fix` with no version; a
   tracker status change to not-affected drops the record; a rejected CVE disappears; an alias
   merge moves the ID. If the DB contradicts the tracker, say so: that is a data bug, and
   `/investigate-qg` is the follow-up.
5. **What the prior label said**, if any, and whether its reasoning still holds.

Use `WebSearch` sparingly, for the upstream advisory or mailing-list thread when the record above is
thin. Prefer primary sources: the commit, the tracker, the changelog. Budget: stop at `unclear` with
the open questions rather than keep digging past roughly twenty fetches.

# Phase 3: verdict, justification and confidence

The labeling policy defines these ([labeling-policy.md](https://github.com/anchore/claims/blob/main/labeling-policy.md) in the claims corpus; its rules and
justifications are in `vocabulary.yaml`, which `yardstick claims policy` prints); in short:

- `tp`: the vulnerable code is present at the installed version and no fix is applied.
- `fp`: the code is absent (introduced later, never built, other platform), or the fix is present
  (version ≥ fix, or the CVE appears in the installed changelog/patch series), or the CVE is rejected.
- `unclear`: the evidence does not reach either; `openQuestions` says what would settle it.

`justification` is required for fp and unclear, and belongs on a tp too: one of the justifications
listed under the verdict in `vocabulary.yaml`, naming the truth about the code (`introduced-later`).
The specific, in a few words (the module, file or version: "pdfi, added in 9.55.0"), opens the
evidence's `interpretation`. The UI shows the justification's line as the headline, so the note no
longer has to carry the deciding sentence alone. `yardstick claims agent propose` refuses a justification
that isn't listed under the verdict.

- tp: `fix-newer` (Fix is in a newer version than installed), `no-fix` (Vulnerable code present, no fix
  for this version), `in-affected-range` (Installed version is inside the affected range)
- fp: `fix-installed` (Installed version has the fix), `introduced-later` (Installed version predates the
  vulnerable code), `vulnerable_code_not_present` (Vulnerable code is not in this package), `other-platform` (Bug
  only affects another platform), `not-a-vulnerability` (CVE rejected, withdrawn or disputed by its CNA),
  `different-product` (CVE is about a different product with this name), `vendor-not-affected` (Vendor
  marks it not affected without saying why)
- unclear: `not-assessed` (Nobody has assessed this version), `no-range` (No usable affected range),
  `sources-disagree` (Sources disagree about the affected versions)
- `yardstick claims policy` prints the current set, and wins over this list.

Confidence: **high** when a primary fact states it (fix version vs installed, code inspection, a file
absent from the binary, a rejected CVE, a distro not-affected with a reason; P-5); **medium** when
inferred from version ranges or a triager's note without looking at the code (P-3, P-4), or when
sources disagree but one is clearly better; **low** is not a confidence, it is `unclear` (P-2), and an
`unclear` leaves `confidence` empty, since it claims nothing to be sure of (`propose` refuses one). A
tracker's needs-triage, under-investigation or end-of-support "ignored" is noise, not a signal.
Severity and "assume vulnerable" policies never change the verdict (P-1).

# Phase 4: report and propose

Write `<workspace>/.yardstick/research/<VULN>/<package>/REPORT.md`:

1. One line: verdict, confidence, and the single fact that decides it.
2. Timeline (a short table): CVE published; upstream introduced / fixed; distro status changes and
   USN dates; fix published in the release; when each DB first/last showed it if known.
3. The evidence chain, numbered, each item with its URL and what to look for there.
4. The DB difference and its cause (or "cause unverified").
5. Open questions, if any.

Then fill `proposal.json`: `verdict`, `justification` (Phase 3), `confidence`, `note` (one or two
sentences, the deciding fact first; the UI shows it under the justification line),
`evidence[0].interpretation` (the specific, then the evidence chain in prose, URLs inline; they are
linkified; keep the report path the skeleton put at its end), `openQuestions` (empty unless
`unclear`). Add facts you relied on that the skeleton did not observe to `evidence[0].facts`, as
`{"source","url","about","field","value","observedAt"}`. A fact's source must be listed under
`fact-sources` in `vocabulary.yaml` (`factSources` in `yardstick claims policy -o json`), or propose
refuses the line: use the listed name (`cve.org`, `osv`, `debian-security-tracker`, ...), and
leave out a fact whose source isn't listed (a changelog line, an upstream commit), putting its URL in
the interpretation instead. An evidence entry needs at least one fact; with none, drop `evidence`
and put the reasoning in the note. Then, once, in the workspace:

```bash
yardstick claims agent propose --name "${YARDSTICK_NAME:-default}" --gate <gate> <dir>/proposal.json
```

(`--gate` reads `$YARDSTICK_GATE` when the flag is left off, so a research job may omit it.)

When `rows.json` lists several binary packages, propose once per row with the same content: write a copy of proposal.json per row beside it, `proposal-<row id>.json` with `row` set to that row, and pass them all to a single `propose` call.
In place of `row` a proposal may give `subject` (`{"image": ...}` or `{"sbom": ...}`), `package` and
`vulnerability`; there is no proposal for the package anywhere (a global label), so a broader call
goes in the report and the note.

In chat: the verdict line, the three most important evidence links (full URLs, what to look for), and
the proposal id that `propose` printed. Keep the rest in the file.
