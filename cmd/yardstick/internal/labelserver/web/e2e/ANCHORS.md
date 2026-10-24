# Test anchors

Select with `getByTestId("<testid>")`, narrow with the `data-*` identity attributes. Do not select by class, id or DOM shape.

- Boolean attributes are the strings `true` / `false`. An attribute shown as `(absent)` is left off when empty.
- `data-verdict` is `tp`, `fp`, `unclear` or `unlabeled` on a row, and `tp`, `fp` or `unclear` on a hint or button.
- `data-state` on a check or gate is `pass`, `fail` or `undecided`.
- Table rows are `tbody tr[data-id]` inside the table's testid; `data-id` is the row id (16 hex), or a made-up key for a row with no finding page.
- Pick one instance by its identity attribute: `page.locator('[data-testid=check-row][data-check=f1NotWorse]')`.

Routes (`route.ts`): `/ui/gates/` (level 0, `?tab=unlabeled|labels`), `/ui/gates/<gate>/` and `findings` / `labels` / `map` (level 1), `/ui/gates/<gate>/checks/<check>` (level 2), and a finding at `/ui/gates/<gate>/checks/<check>/<row>` or `/ui/gates/<gate>/findings/<row>` (level 3). Filters ride in the query: `image` (slug), `verdict`, `hint`, `pkg`, `q`, `page`. The labeling flow's screens sit beside them: hint review at `/ui/hints?gate=&image=&low=1`, research at `/ui/research?scope=all|gate:<g>|image:<slug>` (`check`, `rows` comma-separated, `groups` comma-separated, and the filters `chip`, `image`, `q`) and its jobs at `/ui/research/jobs`, the queue at `/ui/queue` and `/ui/queue/<row>` (`?scope=all|gate:<g>|image:<slug>`, `check`, `low=1`), and `/ui/history` (`?verdict=`, `q`, `page`, `since=all|<RFC 3339 time>`, left out for since the server started). `h` on any screen opens hint review for the gate and image on screen; `r` on the gates, gate and check screens opens research scoped as `n` is; `n` enters the queue for the screen's scope.

## Shell (every screen)

| testid | where | attributes |
|---|---|---|
| `app-bar` | the bar at the top | |
| `breadcrumb` | the crumbs; each crumb above the current one is a link | |
| `gate-switch`, `gate-switch-button` | the gate crumb's switcher and its ▾ trigger; the menu is filled as it opens | |
| `gate-option` | one gate in the switcher, a link to the same level there | `data-gate`, `data-state`, `data-open` (unlabeled and unclear rows), `aria-current` on this gate |
| `goto-button` | "Go to…" in the app bar, which opens the palette like `⌘K` / `ctrl+K` | |
| `history-entry` | "History" in the app bar, a link to `/ui/history`; its title says what the count is | `data-count` (labels written since the server started) |
| `history-count` | the entry's count pill | `hidden` at 0 |
| `activity` | the research chip in the app bar: "2 researching · 13 queued" (a link to the jobs page) or "✦ N new hints" (a link to hint review) | `data-state` `busy` or `hints`, `hidden` with neither |
| `settings`, `settings-button` | the settings cog at the app bar's right end (Basecoat's popover) and its trigger, named "Settings" | `aria-expanded` on the button |
| `settings-panel` | the open popover; keys pressed in it stay in it, and `Esc` closes it | `aria-hidden` while closed |
| `advance-toggle`, `advance-checkbox` | the "Go to the next match" row and its switch (a checkbox with `role="switch"`); off, Save says "Save" and stays on the match, in the queue too | `checked` |
| `queue-skip` | the "Skip labeled matches" switch; on, the queue's `j` / `k` step over rows it labeled | `checked` |
| `settings-theme` | the theme radio group, drawn as a segmented control | |
| `theme-option` | System, Light or Dark | `value` (`system`, `light`, `dark`), `checked` |
| `palette` | the go-to palette (Basecoat's command), visible while open | |
| `palette-input` | its search box | |
| `palette-item` | one entry, a link | `data-group` (`Gates`, `Images`, `Checks`, `Matches`, `Actions`), `data-id` (gate, image ref, `<gate>/<check>`, row id, or `hints` / `queue` / `research` / `history` / `jobs`, and `research-gate` on a gate, check or finding, `research-check` on a check) |
| `palette-more` | how many more findings match than are shown | |
| `title-row` | the title line | |
| `title` | the screen's `h1` | |
| `status` | a state badge: the gate's or check's in `title-row`, and one per gate or check row | text is the state |
| `verdict` | a verdict badge: the finding's in `title-row`, and one per table row | text `TP`, `FP`, `unclear` or `unlabeled` |
| `hint` | an agent hint mark in a table cell | text e.g. `TP · medium`, or `package hint` |
| `outcome` | what a changed row does to the candidate: a table cell's pill, the unlabeled tab's question (a gate chip's when its gates disagree), a hint's by line | text `fixed FN`, `new FP`, `new FN`, `fixed FP`, `new FP?` or `new FN?`; `data-outcome` `good`, `bad` or `open` |
| `column-help` | the "?" by a table header that explains the column; hover or focus shows the text in the page's one `role=tooltip` | `aria-label` is the text |
| `tabs` | the screen's tabs (levels 0 and 1); each tab is `role=tab` | `aria-selected`, `data-tab` |
| `scope-chip` | "image: …" beside the tabs while an image is picked | `hidden` without one |
| `scoped-research` | the two-line Research on a gate, a check, hint review's panel and the queue's stopping point: "Research" over what it covers (the `small`), its price; a link to the research page, hidden while nothing in scope qualifies | `href`, `data-rows`, `data-group` (`change`, `none` or `all`) |
| `label-next` | the primary "Label next" button (a link, or disabled when nothing is open); on the gates screen only on the Unlabeled and Labels tabs, since the Gates tab's work banner carries the primary action | |
| `loading`, `load-error` | the body while loading, or when it failed | |
| `placeholder` | the body of a screen with nothing to show: an unknown URL, a finding that isn't there, a queue row that isn't open | |
| `toast` | transient message | visible while `hidden` is off |
| `toast-action` | Undo in a write's toast: removes the labels that write wrote | |

## Image rail (levels 1 and 2)

| testid | where | attributes |
|---|---|---|
| `image-rail` | the rail | `hidden` when collapsed |
| `rail-image` | one image, the first one being "All images" | `data-slug` (empty for all), `aria-pressed` (picked) |
| `rail-filter`, `rail-sort` | the rail's filter box and sort toggle | |
| `rail-collapse`, `rail-expand` | collapse to the dropdown, and back | |
| `rail-review-all` | "Review all N hints" in the rail's head, a link to review scoped to the gate | |
| `rail-act` | the hint line under an image with pending hints | `data-image` (slug) |
| `rail-hints` | "N hints on M matches" in it | |
| `rail-replaces` | "N overrides a label", when a hint would replace a person's label | |
| `rail-accept` | "Accept…", a link to review scoped to the gate and the image | `data-image` (slug) |
| `image-picker`, `image-picker-button` | the collapsed dropdown and its trigger | |

## Gates (level 0)

| testid | where | attributes |
|---|---|---|
| `gate-rows` | the list of gates | |
| `gate-row` | one gate, a link into it | `data-gate`, `data-state`, `href` |
| `gate-unlabeled` | "N open of M changed": open is unlabeled or unclear, as everywhere | |
| `gate-work` | "N hinted · M need you" (open rows), and "K hints · what hints alone do" | |
| `work-banner` | the open-work banner over the gate list | `data-research`: `none`, `offered` (research is the primary), `running` (the banner is a batch's progress) or `finished` (the newest batch is over) |
| `work-caps` | its first line: "Open work across N gates", "Researching · N jobs", or the finished batch's "Research finished · N jobs · $X" | |
| `work-open`, `work-hinted`, `work-need` | its numbers: open findings across gates (each once), those with an agent hint, the rest | |
| `work-stack` | the hinted / no hint bar (done / running / queued while a batch runs), only its non-empty segments | |
| `work-legend` | the bar's legend, one entry per segment the bar has | each entry's `data-segment`: `hinted`, `you`, `done`, `running`, `queued` |
| `work-rcaps` | the other column's heading: "If you accept every hint" while hints are pending, "Research these N matches" with research leading, "Where each gate stands" otherwise, "So far" while a batch runs | |
| `work-outcome` | one gate if every hint were accepted (its preview), only while hints are pending | `data-gate`, `data-before`, `data-after` |
| `work-standing` | one gate's outcome now, in place of the previews when no hint is pending and research doesn't lead | `data-gate`, `data-outcome` |
| `work-foot` | with research leading, one sentence: "N matches across M gates can still change an outcome. The other K change none."; otherwise what each gate not passing still waits on ("then waits on" after the hints, "waits on" with none pending) | |
| `review-hints`, `label-left` | "Review N hints" (`h`) and "Label what's left" (`n`); review is there and primary while hints are pending, and hidden when none are (`h` still opens an empty review). `label-left` is there in every state | |
| `research-rows` | "Research N matches…" (`r`), a link to `/ui/research`; primary with no hint pending and matches that can change a gate, else ghost with its price; hidden while a batch runs or with nothing to research | `data-rows`, `hidden` |
| `research-price`, `research-summary` | with research primary, the other column's price ("about $0.92") and "N jobs · about 2 min · about 1.3M tokens" | |
| `research-done`, `research-spent`, `research-left` | while a batch runs: jobs done, spent so far, time left | |
| `research-so-far` | one verdict's hints the batch has left | `data-verdict` |
| `research-cancel` | "Cancel N jobs" while a batch runs | |
| `gate-research` | in a gate row's `gate-work`, "research ~$X" for the jobs that can change a gate researched under it, a link to research scoped to the gate | `href` |
| `work-jobs` | "View jobs" in the banner's foot while a batch runs | |
| `unlabeled-table` | the Unlabeled tab: open findings across gates, with the findings tables' `research-cell` and bulk Research | rows keyed by finding |
| `labels-table` | the Labels tab (and the gate's) | |

## Hint review (`/ui/hints`)

| testid | where | attributes |
|---|---|---|
| `hint-gate-chip` | a gate chip in the title row, a link; "All gates" first | `data-gate` (empty for all), `aria-pressed` |
| `hint-low-toggle`, `hint-low-count` | "Show unclear" and how many unclear hints it hides | |
| `hint-group` | a group of hints by what accepting one alone does | `data-group` = decides / needed / none |
| `hint-group-toggle` | its select-all checkbox | `indeterminate` while partly checked |
| `hint-item` | one hint | `data-hint` (id), `data-group`, `data-verdict`, `data-confidence`, `data-replaces` |
| `hint-check` | its checkbox | |
| `hint-replaces` | "replaces an unclear label: …" on a hint that would replace a person's label | |
| `impact` | the panel previewing the selection | |
| `impact-gate` | a gate the selection touches | `data-gate`, `data-before`, `data-after` |
| `impact-check` | one of its checks | `data-check`, `data-before`, `data-after` |
| `impact-left`, `impact-left-item` | what stays open after the selection | |
| `impact-left-job` | on a still-open row with a job in flight, "researching 0:41" or "queued 3rd of 13" | `data-state` `running` or `queued` |
| `hints-on-the-way`, `hints-jobs` | "N more on the way" over the hints while research is in flight, and its "View jobs" | `hidden` with nothing in flight |
| `accept-hints` | "Accept N hints on M matches" | `data-hints`, `data-rows`, `disabled` with none |
| `hints-empty` | the body when no hint is pending in scope | |

## Research (`/ui/research`)

| testid | where | attributes |
|---|---|---|
| `research-gate-chip` | a scope chip in the title row, a link; "All gates" first | `data-gate` (empty for all), `aria-pressed` |
| `research-check-chip`, `research-rows-chip` | "check: f1NotWorse" with `check=`, "N selected matches" with `rows=`; each × clears it | |
| `research-toggle` | "Open matches / Jobs N", here and on the jobs page; each is a link | each one's `data-tab` (`matches`, `jobs`) and `aria-pressed` |
| `research-table` | the open matches, one row each, as the findings tables' table with its `bulk-bar`; checks survive a filter change here | rows keyed by row id |
| `research-group` | in a group's header row: its box, title, and "N matches · M jobs · ~$X" over what is shown | `data-group` = change / none; absent with no row shown |
| `research-group-toggle` | its checkbox, over the matches shown; change starts checked, none unchecked (`groups=` picks them, `rows=` checks every row) | `indeterminate` when some are |
| `research-job` | a row's Job cell: "own job" or "shares with N" | `data-gate` (researched under), `data-group` |
| `research-row-price` | a row's Price cell: one job's price on its job's first match, blank on the others, "–" unmeasured | |
| `research-image` | the image select ("All images"), `?image=` | |
| `research-bulk`, `research-hidden` | in the bulk bar: "N jobs · ~$X", then " · N hidden by the filter" while the filter hides checked matches | |
| `research-skipped` | what was left out: researched, hinted, queued or running | |
| `research-empty` | the body when nothing in scope qualifies | |
| `research-estimate` | the sticky panel | |
| `research-cost`, `research-range` | the mean ("$0.92", or "not measured") and the range ("$0.72 to $1.12", or the job count) | |
| `research-rows`, `research-jobs`, `research-tokens`, `research-time` | the panel's numbers: matches checked, then the jobs they make (up to "Stop after") | |
| `research-model`, `research-limit` | the model select and "Stop after" | |
| `research-unmeasured` | the line saying the model has no finished jobs here | `hidden` when measured |
| `research-start` | "Start N research jobs" | `data-jobs`, `disabled` with none |
| `research-basis` | where the per-job numbers come from | |

Its chips are buttons with `data-chip` (`all`, `change`, `none`, `checked`, `?chip=`) and `aria-pressed`; the count is the `b` inside and follows the search and the image. The search box is the findings tables' (`Filter matches`, `?q=`). `label-left` is in the title row here too, and follows the image filter.

## Research jobs (`/ui/research/jobs`)

| testid | where | attributes |
|---|---|---|
| `jobs-summary` | the work in flight, or with none what has finished | `data-active` |
| `jobs-running`, `jobs-queued`, `jobs-finished`, `jobs-spent`, `jobs-left` | its numbers | |
| `jobs-cancel-all` | "Cancel N running and queued" | |
| `jobs-review` | "Review N new hints", while jobs have left hints nobody has accepted | |
| `jobs-list` | the list | |
| `jobs-group` | a group's heading | `data-group` = running / queued / finished |
| `job-row` | one job; `id` is `job-<id>`, which a cell's link names in its hash, and the row it names is marked | `data-job`, `data-state` (the job's status), `data-group` |
| `job-log`, `job-cancel`, `job-retry`, `job-review` | its log, Cancel (queued or running), Retry (failed or cancelled), and the finding its hint is on | |
| `jobs-more` | "show all" in a group cut short | |
| `jobs-empty` | the body with no jobs | |

## Gate (level 1)

| testid | where | attributes |
|---|---|---|
| `verdict-bar` | the gate's verdict mix and its legend | |
| `check-rows` | the Checks tab | |
| `check-row` | one check, a link to it | `data-check`, `data-state` |
| `meter` | a check's value against its limit, captioned "0.500 worse · limit 0" | |
| `check-count` | "N open" and what labeling does for it | |
| `findings-table` | the Findings tab | |
| `package-chip` | the scan map's `pkg` filter on the Findings tab | `hidden` without one |
| `page-info`, `page-next`, `page-prev` | the Labels tab's pager | |
| `scan-map` | the Scan map tab | |
| `treemap` | the map's svg | |
| `dir-region` | added or dropped | `data-dir`, `data-count` |
| `block` | one source package; click opens the Findings tab filtered to it | `data-package`, `data-count` |

## Check (level 2) and every findings table

| testid | where | attributes |
|---|---|---|
| `check-table` | the check's findings | |
| `images-toggle` | hides and shows the rail | `aria-pressed` |
| `group-by` | the "Group by" select | |
| `bulk-bar` | the bar over a table while rows are checked | |
| `bulk-accept` | "Accept hints (N)" | `disabled` with no hint selected |
| `bulk-research`, `bulk-research-why` | "Research N · ~$X" (an ellipsis when over 10 jobs opens the research page), and the line under the buttons on what it skips | `data-rows`, `data-jobs`, `disabled` with nothing to research |
| `research-cell` | the Agent hint cell when it says what research is doing: a link to the job while queued or running, a button for an open row nobody has looked at | `data-state` = running / queued / failed / nohint / offer |
| `research-retry` | retry in a failed cell | |
| `label-as` | the "Label as…" select, option values `<verdict>:<justification>` | |

Filter chips are buttons with `data-chip` (`all`, `unlabeled`, `tp`, `fp`, `unclear`, `hint`, and `researching` only while a row in view has a job on it) and `aria-pressed`; the count is the `b` inside.

## Finding (level 3)

| testid | where | attributes |
|---|---|---|
| `pager` | "N of M open" beside the breadcrumb: the open rows `j` / `k` walk, or every row when none is open | `data-index` (1-based among them, 0 for a labeled row or one the filters leave out), `data-total`, `data-open` |
| `pager-previous`, `pager-next` | its `k` / `j` links | |
| `finding-effect` | what its label does, in the title row | `data-effect` = decides / could-move |
| `finding-sub`, `finding-package`, `finding-image`, `finding-direction` | the subtitle and its parts | `finding-image` has the full ref in `title`; `finding-direction` has `data-dir` = added / dropped / both / neither |
| `finding-distro` | the distro release chip in the subtitle, only for a purl with a `distro` qualifier | |
| `finding-purl` | the package's purl, decoded, under Why it differs | the raw purl in `title` |
| `finding` | the page body | `data-row`, `data-verdict` |
| `finding-tabs` | the content tabs, `role=tab` | `aria-selected`, `data-tab` = why / evidence / raw / labels |
| `tab-why`, `tab-evidence`, `tab-raw`, `tab-labels` | their panels | |
| `why-text`, `match-path`, `finding-ref` | Why it differs | |
| `lane-step-more` | a lane cell that holds more than it shows (a detail, or a clipped subline), `role=button`; a click, Enter or Space opens it in place | `aria-expanded` |
| `evidence-links`, `explanation` | Evidence | |
| `raw-candidate`, `raw-reference`, `raw-artifact` | Raw match | |
| `label-record`, `label-note`, `label-sources`, `no-labels` | Labels on file | `label-record` has `data-verdict`, `data-author` |
| `label-panel` | the label panel on the right | `data-row`, `data-verdict` |
| `label-on-file` | the label deciding the match | `data-verdict` |
| `reason` | its reason | |
| `label-source` | the claims sources holding it | |
| `hint-card` | the row's own agent hint | `data-status`, `data-verdict`, `data-confidence` |
| `hint-confidence`, `hint-reason`, `hint-facts`, `hint-note` | its parts; `hint-facts` is a `details` holding the note | |
| `researched-mark` | "✦ researched" on a hint research left | |
| `accept-hint` | Accept hint (`a`) | |
| `cause-card` | the package hint the row is a pending member of | `data-count`, `data-verdict` |
| `accept-all` | accept it for every member (`A`) | `data-count` |
| `verdict-button` | TP / FP / Unclear (`t` `f` `u`) | `data-verdict`, `aria-pressed` |
| `label-meaning` | the label panel's line per verdict | |
| `verdict-outcome` | one verdict's line: what it makes the row and, in the queue, what it does to each gate, e.g. `TP → new FN · deb-npm passes` | `data-verdict` `tp` or `fp` |
| `reason-picker` | the reason select | |
| `reason-option` | one reason | |
| `note-input` | the note; Enter saves | |
| `save-label` | "Save and next", or "Save" with the cog's `advance-checkbox` off | |
| `skip-button` | Skip (`j`) | |
| `research-foot`, `research-button`, `research-status` | research (`R`) | `research-button` has `data-researched`; `research-status` has `data-state` (the job's status), and while queued or running reads as the table cell does |
| `research-job-link`, `research-cancel-row` | while a job is queued or running, "view job" and Cancel | |
| `research-price`, `research-shares` | on the button, one job's price ("~$0.23") when measured; under it, "One job, about a minute, shared with …" naming the sibling packages | |

## Component kit (`/ui/gates/_kit`)

| testid | where | attributes |
|---|---|---|
| `kit-gallery`, `kit-table`, `primary` | the kit's parts | |

## Queue (`/ui/queue/<row>`)

The finding page in queue mode: every Finding testid above is there too, except `pager`.

| testid | where | attributes |
|---|---|---|
| `queue-bar` | the bar under the app bar | |
| `queue-scope` | its scope select, option values `all`, `gate:<g>`, `image:<slug>` | |
| `queue-progress` | "N of M done · K left" | `data-done`, `data-left` |
| `queue-pager`, `queue-pager-previous`, `queue-pager-next` | "1 of K" (or "labeled") and its `← k` / `j →` links, on a row | `data-index` (0 for a done row), `data-total` |
| `queue-exit` | ✕ (`esc`), labeled "Exit", back to the check, gate or gates the queue was entered from | |
| `why-next` | "Why this one is next" over the content tabs | |
| `queue-card` | a card in the finding's place | `data-card` = `boundary` / `stop` / `end` |
| `card-gate` | one gate's outcome on a card | `data-gate`, `data-state` |
| `card-continue` | Continue to the next gate, or Keep labeling (`⏎`) | |
| `card-back`, `card-history` | Back to the gate or gates, and See the labels | |
| `card-left` | the stopping point's list of rows left, one `li` each | `li[data-row]` |
| `scoped-research` | on the stopping point, "Research the N left, M jobs" | `href` |
| `card-session` | the end card's line on the labels written this session | |

## History (`/ui/history`)

| testid | where | attributes |
|---|---|---|
| `history-table` | the labels, newest first, one group per day | rows `tbody tr[data-id]`; each has a `time[datetime]` |
| `history-day` | a day's group header, "Today", "Yesterday" or the date | `data-day` (YYYY-MM-DD, local) |
| `history-note` | a label's note, which an accepted hint carries over | |
| `history-link` | a link to the label's finding, one per gate row it sits on | `data-gate`, `data-row` |
| `history-since` | the since select: `start` (since the server started, the default), `pick` (a time) or `all` | |
| `history-since-time` | the picked time, a `datetime-local` input shown with `pick` | |
| `history-remove` | Remove on a row: takes the label out of ./claims at once | |
| `history-remove-selected` | "Remove selected (N)" in the `bulk-bar` while rows are checked | |
| `history-remove-all` | "Remove all N shown": every label the filters match, on every page | `disabled` with none |
| `history-confirm` | the in-page confirm before removing more than one label; `Esc` closes it | |
| `history-confirm-remove`, `history-confirm-cancel` | its Remove N labels and Cancel | |
| `page-info`, `page-next`, `page-prev` | the pager | |

Verdict chips are buttons with `data-chip` (`all`, `tp`, `fp`, `unclear`) and `aria-pressed`.
