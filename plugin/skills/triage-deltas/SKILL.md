---
name: triage-deltas
description: Walk the unlabeled differences between the two setups of a yardstick gate, say which are obvious tp/fp and the evidence that decided it (the justification, the rule and the facts), and record them as proposals (hints) for a person to accept in `yardstick claims serve`. Never writes labels.
argument-hint: [workspace dir] [gate] [cand | ref]
allowed-tools: Bash, Read, Write, Edit, Grep, Glob, Agent
---

Triage assay deltas: $ARGUMENTS

The scripts live in this plugin, `${CLAUDE_PLUGIN_ROOT}/scripts`. The **workspace** is the directory
yardstick runs in (it holds `.yardstick/runs/` and finds its app config there), which may be somewhere
else, so pass `--store` explicitly. Every `yardstick` command below runs in the workspace.

# What this does

A yardstick gate scans its subjects with a candidate and a reference grype setup and scores both
against the labels in its claims sources (`yardstick claims list`). Rows that only one setup reports and
that no label covers are the **unlabeled differences**; they are what moves when the world moves, and
what a person has to label. You turn each one into a **proposal**: a label authored by an agent that
nobody has vouched for yet, with the rule that decided it and the facts it rests on. The label UI
shows proposals as hints; a person accepts them there, which writes the label.

You propose; a person confirms. This skill never runs `yardstick claims add`.

# Ground rules

These restate the labeling policy ([labeling-policy.md](https://github.com/anchore/match-claims/blob/main/labeling-policy.md) in the claims corpus, with its rules
and justifications in `vocabulary.yaml`, which `yardstick claims policy` prints); the policy wins if
they ever differ.

1. **Label the match, not the risk (P-1).** `tp` means the installed package contains the vulnerable code and
   no fix. A `wont-fix`, a negligible priority, or "needs local access" does not make a finding `fp`.
2. **`fp` needs a stated reason from a primary source (P-3, P-5)**: the distro says not-affected / code not present,
   the installed version is at or past the fix, the CVE was rejected, or the bug is in code this build
   does not have (different platform, a different product with a similar name).
3. **`unclear` beats a guess (P-2).** Nobody-has-assessed-it is a real state; say so, add an open question,
   and leave it for `/yardstick:research-vuln`.
4. **The note is the deciding line.** One or two sentences; the UI shows it first. Facts carry the URLs.
5. **Say what decided it.** `evidence[].rule` names the fixed inference (`ubuntu/not-affected`); a
   judgement call you make in review gets `judgement/<why>` and a note that says so. An evidence
   entry needs at least one fact, so a rule nothing was observed for is left off the proposal.
6. **Every proposal states its justification**: the truth about the code the verdict rests on, as
   one of the justifications listed under its verdict in `vocabulary.yaml`, plus the specific (the
   version, module or file, a few words) as the evidence's `interpretation`. fp and unclear need
   one. The rule is who said so; the justification is what they found; the UI shows the
   justification's line as the headline, then the interpretation ("Vulnerable code is not in this
   package: in libcrypto1.1, which has its own finding"). The script fills it from the rule's
   `justification` (reading the vendor's reason text for the `*` not-affected rules); a judgement
   call sets it with `--evidence justification:"text"`. Evidence says whether the label is true; why
   the two scans differ is a reason, which is `/yardstick:explain-deltas`' job, not this one's.
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

# Phase 0: read the overrides (one command)

When people have labeled against earlier hints, their reasons are the feedback on the rules:

```bash
yardstick claims agent overrides -o json \
  | jq -r '.[] | "\(.rule)\t\(.count)\t\([.overrides[].reason // empty | .kind + ": " + .text] | join("; "))"'
```

A rule overridden for the same reason more than once is a rule to fix (or a policy row to change)
before drafting more of the same. Mention what you found in the report.

# Phase 1: gather evidence (under a minute, mostly cached)

Find the workspace: the argument, else `$YARDSTICK_ROOT`, else the current directory, else ask. It
must contain `.yardstick/runs/<run>/<gate>/` (a gate that has been run). The yardstick binary is
`$YARDSTICK_BIN`, else `yardstick` on PATH, else the workspace's `bin/yardstick` (build with
`go build -o bin/yardstick ./cmd/yardstick` in a yardstick checkout).

```bash
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-evidence.py --store <workspace> [--gate <gate>] [--name <run>] --model <your model id> [--side cand|ref]
```

Without `--gate` it takes `$YARDSTICK_GATE`, else the gate scanned last; `--name` is the run name
(`$YARDSTICK_NAME`, else `default`).

It reads `yardstick score <gate> -o json` (rows carry row ids, source package, fix state, namespace,
advisory status per DB and the package's location), `yardstick claims list`, `yardstick claims policy`
and, cached under
`~/.cache/yardstick-skills/`, cve.org, the Ubuntu tracker, OSV and, for unassessed distro rows, the
upstream project's GitHub advisory (the one the CNA record links under
`github.com/<org>/<repo>/security/advisories/`; it is fetched from the repository endpoint because the
global advisory database usually lacks it, and it is the source that says where a bug was introduced).
GitHub allows 60 unauthenticated requests an hour; `export GITHUB_TOKEN=$(gh auth token)` first on a
gate with many unassessed groups, or the script stops asking GitHub once the limit is hit and says so
on stderr. `--euvd` (or `YARDSTICK_SKILLS_EUVD=1`)
also consults ENISA's EUVD, a provisional source that so far adds nothing a rule can use (its
product text mirrors the CNA; its GHSA aliases are GitHub's unreviewed shells). It shows up as an
evidence line and a fact only. See `scripts/yardstick_euvd.py` for what was measured and how to remove it. It writes `<workspace>/.yardstick/triage/<run>/<gate>/`:

- `evidence.md`: one section per group (vulnerability × source package): grype fix state, the
  tracker's per-pocket statuses, upstream status, priority, notes, CNA ranges, the CNA's description, prior
  labels on the package, the suggestion with its rule and confidence, open questions, row ids.
- `evidence.json`, `groups.json`: the same, machine-readable; group number → row ids.
- `proposals.jsonl`: `yardstick claims agent propose` input, one line per row: `row`, `verdict`,
  `justification`, `confidence`, `note`, `author{skill,model}`, `evidence[{rule,facts,interpretation}]`,
  `openQuestions`. Facts from `ubuntu-cve-tracker` carry status per package/release and priority;
  per-pocket statuses that ubuntu.com collapses go in as `ubuntu-cve-tracker-pocket`. A fact's source
  must be listed under `fact-sources` in `vocabulary.yaml`, or propose refuses the line.
- `proposals.md`: the proposals numbered by group, in three confidence sections.
- `causes.jsonl`: `yardstick claims agent propose-cause` input, one **cause** per source package, rule, verdict and
  direction that spans several findings (two or more vulnerabilities, or three or more rows): a
  title, a note, explicit member row ids, the rule and the members' facts, deduplicated. A person
  accepts a cause once on the package header; the per-row proposals stay, and the UI flags any
  member whose own hint disagrees. Format: `yardstick claims agent propose-cause --help`. Ids are stable
  (`cause-<package>-<rule>-<direction>`), so a rerun supersedes rather than duplicates.

The rules, the verdict and justification each proposes, its confidence ceiling, the policy decision
behind it and its title are `rules:` in the corpus's `vocabulary.yaml` (`yardstick claims policy -o json`);
the decisions themselves are in [labeling-policy.md](https://github.com/anchore/match-claims/blob/main/labeling-policy.md). Sources by package type, then namespace: language packages (pypi, maven, npm, …) always go to the
ecosystem advisory via OSV (`ghsa/*`, `cpe/*`), wherever the image is from; deb on Ubuntu to Ubuntu's
tracker (`ubuntu/*`); rpm on RHEL to Red Hat's CSAF VEX and Hydra (`rhel/*`, per binary RPM and
stream; `scripts/yardstick_redhat.py`); deb on Debian via OSV (`debian/*`); apk on Alpine to the secdb
(`alpine/*`, `scripts/yardstick_alpine.py`), falling back to the CNA's own range (`cna/*`) when the
branch does not list the CVE, as EOL branches never do; anything no tracker covers (built from
source, CPE-matched) to the CNA range (`cna/*`). Read [labeling-policy.md](https://github.com/anchore/match-claims/blob/main/labeling-policy.md) before reviewing: it says what a
label means (the truth of the match, never a business rule, P-1), which tracker statuses are signals
and which are noise (needs-triage, under investigation and end-of-support "ignored" support only
`unclear`, P-2), and what each confidence level requires (P-3 to P-6). The script clamps every
suggestion to its rule's ceiling, and `scripts/test_policy.py` fails when the script and
`vocabulary.yaml` drift. If you want a rule to behave differently, change the policy first.

## Tuning against existing labels

When the claims sources already have human labels (an imported label set), measure the rules before trusting
them on that data source:

```bash
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-evidence.py --store <workspace> [--gate <gate>] --validate --out /tmp/validate
```

It runs the rules on every row that has a tp/fp label (prior-label hints off, so labels cannot
leak) and prints agree / unclear / disagree per rule, then the disagreements with the rule's note.
A disagreement is either a rule to fix or a label to question; `/yardstick:research-vuln` settles which.
Results so far: Ubuntu 20.04 image reviewed by hand (14 of 268 groups changed); Python and Java
images 1,160 of 1,173 labeled rows agree, 3 disagree (two labels look wrong, one OSV gap).

# Phase 2: review (this is where you earn your keep)

Read `evidence.md`. The script is literal; you are not. For every **medium** and **low** group, and a
sample of ten **high** groups, decide whether to keep, change or downgrade the suggestion. Look for:

1. **The CNA's product is not this package.** A LibVNCServer range says nothing about x11vnc 0.9.16;
   a VulDB "found in NASM 2.17rc0" names the version someone fuzzed, not the first affected one.
   Ignore the CNA-range note when the products differ, and say why in the note.
2. **Prior labels on the same package are lopsided** (the evidence says so, e.g. "18 of 21 prior labels
   on this package are fp"). Read two of those labels' notes with
   `yardstick claims list -s <package> -o json`. If the new CVE is the same kind of
   bug in the same embedded or absent code, propose the same verdict at medium confidence with rule
   `judgement/prior-claims-pattern`; otherwise leave it `unclear`.
3. **Code that is not in the matched binary.** The script catches `Foo::Bar` Perl modules by file
   list, and a program the description names with its option (`nsenter --join-cgroup`, `sed -i`)
   when a sibling package from the same source ships it and this one does not (bsdutils, mount and
   the libmount rows for a bug in nsenter; the util-linux row keeps its own verdict). It skips
   `lib*` rows when the text also names a library, since the program may only be the way in to
   library code: check that yourself before accepting one of those. It misses bare module names
   (`Storable`, `Encode`), Python modules and programs named without an option. When the CVE names
   one, look for its file in the binary (`jq '.artifacts[] | select(.name=="perl-base") | .metadata.files[].path' <sbom>`;
   the SBOM path is `subjects[].path` in `.yardstick/runs/<run>/<gate>/yardstick-run.json`). Absent → fp high with rule `judgement/code-not-installed` (P-5).
4. **A binary that links a system library with its own rows** (x11vnc and libvncserver): the CVE is in
   the library, the library's rows carry the verdict, and the linking binary's row is fp medium with
   rule `judgement/linked-system-library` (P-10) and `--evidence vulnerable_code_not_present:"in libvncserver1,
   which has its own finding"`, naming the library that carries the verdict.
5. **Tracker notes that settle it**: "Priority reason: does not affect Ubuntu", "only affects X on
   Windows", "vulnerable code introduced later", "pam_namespace not used in default installations"
   (that last one is a risk note, not an fp: the code is still there). A triager's note is medium at
   best (P-3); it becomes high only when you verify it against the code or a fix version (P-5).
6. **Upstream fixed version older than the installed upstream version** (perl CVEs assigned years
   late): fp medium is right only if the fix is in the upstream release, not a later distro patch.
   Ubuntu's "upstream: released (5.18.1-2)" is a Debian version; the script compares upstream parts.
7. **Upstream fixed version newer than the installed one, introduction unknown**
   (`ubuntu/unassessed-upstream-fix-newer-than-installed`; the largest medium bucket, 108 of 452 rows on
   the focal image). tp medium is the right default and wrong whenever the bug was introduced after
   the installed version, which the tracker never says. `proposals.md` lists these groups under
   "Research first", widest version gap first: 2.34 → 2.42.3 spans eight minor releases and is a
   prime candidate; 1.8.5 → 1.8.8 is not. Before keeping tp on the top of that list, look for a lower
   bound, in this order: the "GitHub advisory" line in the evidence (the script already flips to
   `ghsa/introduced-after-installed` when the installed version is below it; when the line is missing,
   the CNA record had no repository advisory to follow, or GitHub's rate limit hit); the CNA's own
   versions; a distro CNA (Red Hat, SUSE) that lists its older releases as unaffected, which brackets
   the installed version once you look up what those releases ship (RHEL 8 ships util-linux 2.32 and
   RHEL 9 2.37, both "unaffected" for CVE-2026-78408, so focal's 2.34 was never going to be affected;
   `https://access.redhat.com/security/cve/<CVE>` lists the products); a feature or option the
   description names (`nsenter --join-cgroup`) that you can grep for at the installed upstream tag
   (`https://raw.githubusercontent.com/<org>/<repo>/<tag>/<path>`, the path from the advisory line).
   A bound found → fp medium with `judgement/introduced-after-installed` and the bound in the note;
   checked in the code → fp high with `judgement/code-not-installed` (P-5). Nothing found → keep tp
   medium; the open question stays on the proposal for `/yardstick:research-vuln`.
8. **"not-affected but the candidate still reports it"** and **"tracker says affected but the candidate
   dropped it"**: possible vunnel / grype-db bugs, not just labels. Collect them for the summary;
   `/investigate-qg` is the next step.
9. **Non-distro rows** (`ghsa/*`, `cpe/*`): the evidence is the OSV copy of the GitHub advisory for
   the package, compared with the ecosystem's own ordering (PEP 440, Maven, semver;
   `test_versions.py` holds the spot checks). "listed in the advisory's affected versions" is an
   exact hit on the advisory's version list and beats any range arithmetic. A CPE match the
   ecosystem advisory does not support is a name collision until shown otherwise (P-9); the two
   exceptions seen so far are packages that embed the named product's code, so check the jar or
   wheel contents before upgrading one to tp.
10. **Red Hat rows**: the VEX names every binary RPM, so a `rhel/not-affected` with
   `vulnerable_code_not_present` on one binary while its siblings are affected is the srpm-built-but-
   not-vulnerable case (P-10), already fp high. A versioned `known_not_affected` id is a fix build, not
   a verdict; the script treats it as one. `Fix deferred` and `Will not fix` are affirmative (P-6).
   Red Hat's analyst statement often names the module ("only affects mod_proxy"): when the binary's
   file list lacks it the script proposes fp high under `sbom/code-not-in-binary`; check the module
   name is not also compiled into the main binary before accepting.
11. **Wrong dpkg comparison**: epochs (`2:1.6.9…`), `~` sorting before everything, `+esm` after the
   base version. Check with
   `python3 -I -c 'import sys; sys.path.insert(0, "${CLAUDE_PLUGIN_ROOT}/scripts"); import yardstick_common as d; print(d.deb_compare("<a>", "<b>"))'`.

Apply what you decide by group number; the helper rewrites `proposals.jsonl`, `proposals.md` and
`causes.jsonl` (a cause follows its members' rule and verdict, so editing a group moves it), and
clamps your confidence to the rule's ceiling in the policy (a rule-less judgement is capped at medium).
`--evidence kind[:text]` sets the evidence kind; a rule with one in the policy fills it in when you give none, and
`judgement/prior-claims-pattern` needs one from you:

```bash
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-edit.py <dir> 106 --verdict fp --confidence medium \
    --rule judgement/prior-claims-pattern --evidence vulnerable_code_not_present:"in libvncserver1, which has its own finding" \
    --note "x11vnc links the system libvncserver; 18 of 21 prior labels on it are fp"
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-edit.py <dir> 3 7-9 --drop        # propose nothing for these
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-edit.py <dir> 46 --name libssl1.1 --verdict fp --confidence medium \
    --rule judgement/linked-system-library --evidence vulnerable_code_not_present:"in libcrypto1.1, which has its own finding" \
    --note "the bug is in libcrypto; libssl1.1 links the system libcrypto1.1, whose row carries the verdict"
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-edit.py <dir> row:3d5d9ed7d8095adf --verdict unclear --confidence low --question "…"
python3 -I ${CLAUDE_PLUGIN_ROOT}/scripts/yardstick-triage-edit.py <dir> 13 --question "Does IO::Uncompress::Unzip ship in perl-base, or only in perl-modules?"
```

# Phase 3: record the proposals

```bash
yardstick claims agent propose .yardstick/triage/<run>/<gate>/proposals.jsonl --name <run> --gate <gate>
yardstick claims agent propose-cause .yardstick/triage/<run>/<gate>/causes.jsonl --name <run> --gate <gate>
```

Run them in the workspace. `--gate` is required (or `$YARDSTICK_GATE`): row ids are only unique
within one gate's last scan under one run name. The evidence script prints both commands with the
right paths.

Both validate every line first, against the claims vocabulary and the policy too (a justification or
rule not listed, a rule of the other verdict, a confidence above the rule's ceiling, a fact source not
listed), and reject unknown fields, so a schema drift fails loudly: fix the script, do not hand-edit
around it. Proposals land in `.yardstick/proposals.jsonl` as hints, never in the corpus; a newer
proposal for the same subject, package and vulnerability supersedes older ones.

# Phase 4: report

In chat, keep it short and numbered:

1. Counts: groups and rows per section and per verdict, and how many you changed in review.
2. The groups you changed or downgraded, one line each with why.
3. Possible data bugs (review item 8), one line each.
4. The SASE: `! yardstick claims serve <gate>` (in the workspace) and what to look for (hints show on
   their tiles and package headers; accept the high-confidence ones), and the path to `proposals.md`.

# Known gaps

- Only Ubuntu has first-class tracker support; Debian uses OSV's DEBIAN-CVE records (no
  "not-affected" signal); other ecosystems rely on OSV ranges with approximate version ordering.
- One proposal per binary package; a source-package subject does not exist yet. Groups in the UI
  collapse these.
- Rows both sides agree on are never proposed (the gate never scores them).
