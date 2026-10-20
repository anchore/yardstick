# UI rules

The visual and navigation rules every label UI screen follows. Check a PR that touches the UI against this list. The mockups these rules came from are at https://claude.ai/artifact/UwqVwMMszczBhNSbaP3BqD (a real 14-image gate) and https://claude.ai/artifact/34PNnE8apLukPifmDuvCSa (the first pass, on the e2e seed).

## Structure

The UI is a report you browse, with labeling available everywhere. Beside the four levels sit the labeling flow's screens for working through what's open: hint review (`/ui/hints`), the queue (`/ui/queue`) and history (`/ui/history`). Each is one crumb under Gates. Within the levels, "unlabeled" stays a filter on a list.

**Open means unlabeled or unclear**, everywhere: an unclear label doesn't judge a row. Every open count (the rail, gate rows, check rows, the switcher, the pager, the queue) counts both, and `j` / `k` and the queue walk both.

There are four levels. Each click goes one level deeper and adds one crumb to the breadcrumb.

| level | screen | lists | breadcrumb |
|---|---|---|---|
| 0 | Gates | every gate in the workspace | Gates |
| 1 | Gate | the gate's checks (tabs: Checks, Findings, Labels, Scan map) | Gates › deb-java |
| 2 | Check | every finding the check counts, labeled and unlabeled | Gates › deb-java › f1NotWorse |
| 3 | Finding | one match: why the scans differ, evidence, raw data, the label panel | Gates › deb-java › f1NotWorse › GHSA-jfh8-c2jp-5v3q |

Gate and check screens (levels 1 and 2) carry the image rail on the left, collapsible to a dropdown. Finding screens don't; the image is in the title.

- Every list of findings or labels is the same table, prefiltered. The gate's Findings tab is the check table with no check filter, and the Labels tab is that table without unlabeled rows, plus source and author columns.
- Labeled findings are always reachable. A passing gate still lists its checks, and each check still lists the findings and labels that decide it.
- Filters live in the query string (`?image=grype-quality-golang-d89207b&verdict=unlabeled`), so `j` / `k` on a finding walk the same list you came from.
- Grouping is a "Group by" option on the table (by image or by package), not URL segments. Tiers are gone; an agent cause shows as a "package hint" on its rows and as a card on each of its findings.

## Rules

1. **One column, top to bottom.** Lists of same-shape things (gates, checks, findings, labels) stack vertically. Grids are only for things that are actually 2-D, such as the scan map.
2. **State on the left edge.** Status or verdict is the first column of every row, so you scan one vertical line for red. The name comes next. Numbers are right-aligned with tabular figures.
3. **One level of detail per screen.** A parent screen lists its children and stops. Definitions, evidence and raw data live on the child. If something only matters after a click, it appears after the click.
4. **The breadcrumb is the URL, in nouns.** Gates › gate › check › finding. Never a sentence, and never a state ("fail") inside a crumb. `Esc` walks up one crumb.
5. **Chrome doesn't grow with depth.** One app bar, one breadcrumb, one title row. Context the breadcrumb already carries is not repeated as a strip (no check gauges or image cards on a finding).
6. **Tables for many, cards for one.** Three or more of the same thing go in a table with sortable columns. A border or fill marks the one element that is different, such as the label panel.
7. **One primary button per screen.** "Label next" on lists, "Accept hint" or "Save and next" on a finding, "Accept N hints on M rows" on hint review, the card's way on in the queue. The gates screen's is in its work banner: "Review N hints" while hints are pending, otherwise "Label what's left"; its title row has none. Everything else is a secondary or ghost button.
8. **Color always comes with a word or shape.** pass / fail / undecided and TP / FP / unclear always print their word next to the color. Hint purple is never used for a verdict.
9. **A spacing scale of 4, 8, 16, 24, 32.** 24 between sections, 16 inside a group, 8 between a label and its value. Rows are 44px comfortable, 34px compact. No one-off margins.
10. **Design for real names.** A real gate has 14 to about 90 images, displayed names run 4 to 50 characters (`vulnerabilities-package-name-normalization:984794b`), versions run to 58 (`v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible`), and a gate can count thousands of labels. Truncate the repository part of a name, never the tag. The full reference is one hover away everywhere a name appears, and the finding page shows it whole. Test layouts against those lengths, not `deb`.
11. **Help is one line, or it's behind a "?".** Each screen gets at most one sentence of explanation under its title. Check definitions belong in a help drawer, not on every panel; none has shipped yet, so a check's description is its row's one line.

## Screen specifics

- **Gate and check rows** show: status, name with a one-line description, a meter, and a count. The whole row opens the child.
- **The meter** is one bar, one tick for the limit and one caption (`0.500 worse · limit 0`). It replaces the two-line best / worst / threshold gauge.
- **The image rail** is the numbered image filter: `0` for all images, then one row per image in gate order with its number key (`1` to `9`), its name and tag, its open count and a stacked verdict bar. It's a filter, not navigation: choosing an image leaves the breadcrumb alone, puts a scope chip in the title row, and hides the Image column in tables. Past nine images, `/` filters the rail and `[` / `]` step through it. A collapse button swaps the rail for a searchable dropdown in the title row (and back), remembered per viewer.
- **On a check screen** the same rail is available and on by default, with counts for that check's findings per image, so moving between images for one check never leaves the check. An "Images" toggle hides it. Picking an image filters the table in place and the filter chips' counts follow it.
- **The gate's verdict bar** (TP, FP, unclear, unlabeled with a hint, unlabeled) sits above the fold on the gate screen.
- **Reason** is muted when it's the default `not-recorded`, which most ported labels carry.
- **The finding page** puts content on the left, read top to bottom, with tabs for Why it differs, Evidence, Raw match and Labels on file. The label panel sits on the right and stays in place.
- **Agent hints** get their own card with their own Accept button, separate from the TP / FP / Unclear control, so a hint never looks like a choice already made.
- **Bulk actions** appear in a bar over the table when rows are selected: Accept hints, Label as….
- **The gates screen's work banner** says how much is open across gates (each finding once), how much has an agent hint, and what accepting every hint would do to each gate (one preview per gate), with the one primary action. Each gate row adds "N hinted · M need you" and what hints alone achieve.
- **Hint review** (`/ui/hints`) is one batch decision. Hints are grouped by what accepting one alone does (decides a gate, needed to decide a gate, no outcome change), with gate chips, the image rail and "Show low confidence" (off by default) as filters. Medium confidence and up is preselected, never a hint that would replace a person's label, which stays unchecked with its reason. A sticky panel previews every affected gate as the selection changes and lists what stays open. Nothing is written until "Accept N hints on M rows". The rail's "Accept…" opens review scoped to its image; single-row accepts on a finding and table selection stay direct.
- **The queue** (`/ui/queue/<row>`) is the finding page in queue mode: a bar under the app bar (scope, "N of M done · K left", Exit) and "Why this one is next" over the content, which is where the order is explained, row by row. It holds open rows only, one entry per image match even when the row is in several gates, ordered: rows that decide a gate, then by gate (closest to done first), then image, then report order; rows that change nothing come last and say so. Save and next follows the queue.
- **Queue cards** take the finding's place: at a gate boundary (the gate's new outcome, the next gate and its open count, Continue or Back), at the stopping point when no open row can change any gate ("every gate is decided", then the rows left that change nothing), and at the end.
- **The settings cog** at the app bar's right end holds the reader's standing choices, kept in this browser: "After labeling, go to the next match" (on by default; it decides whether Save, and Save in the queue, goes on), "Queue: skip labeled rows" (on by default), and the theme (System, Light, Dark). A choice takes effect at once, and the popover stays open while it changes. Layout and filters stay beside what they affect (the rail's collapse, the "Images" toggle, sort, "Group by", "Show low confidence"). Keys pressed inside the open popover are its own: `Esc` closes it rather than walking up a crumb.
- **History** (`/ui/history`) lists the labels in `./claims`, newest first, grouped by day, each linking to its finding in every gate it sits on. Undoing one is an edit to its claims file; there's no undo button.

## Vocabulary

| thing | word | shape | color token |
|---|---|---|---|
| gate or check passes | pass | filled dot | `--pass` |
| gate or check fails | fail | filled dot | `--fail` |
| labels could still flip it | undecided | filled dot | `--und` |
| true positive | TP | ● | `--tp` |
| false positive | FP | ○ | `--fp` |
| unclear | unclear | ◖ | `--unc` |
| no label yet | unlabeled | dashed outline | none |
| agent hint | hint | ✦ | `--hint` |
| a label here can flip a check | could move | ◆ | none |
| candidate added / dropped | + added / − dropped | + / − | none |

Keys stay the same at every level: `t` `f` `u` label, `a` accepts the hint, `j` / `k` next and previous (on a finding, the next open row, unlabeled or unclear; `⌥j` / `⌥k` walk every row), `n` enter the queue at the next open row in this screen's scope (every gate, this gate then the rest, this check then its gate, or the image filtered to), `h` opens hint review for the gate and image on screen, `⇧J` / `⇧K` next and previous gate with open rows, `⌘K` (or `ctrl+K`) the go-to palette (gates, images, checks, findings, and the actions review hints, label what's left and history), `0` to `9` pick an image, `Esc` up one level. Every gate-level list is in the check tables' order: decides, could move, counted, then the rest, each in report order, and "Label next" enters the queue as `n` does. In the queue, `j` / `k` walk the queue (stepping over rows it labeled while the cog's "Queue: skip labeled rows" is on), `⏎` saves and goes on (on a card, it takes the card's primary button), and `Esc` leaves it for where it was entered from. A finding adds `A` (accept the package hint for every match it covers) and `R` (research); `t` `f` `u` pick the verdict and Save (or Enter in the note) writes it. Lists add `Enter` to open the row under the cursor, and the rail adds `[` / `]` and `/`.
