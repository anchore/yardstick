# Test anchors

Select with `getByTestId("<testid>")`, narrow with the `data-*` identity attributes. Do not select by class, id or DOM shape.

- Boolean attributes are the strings `true` / `false`. An attribute shown as `(absent)` is left off when empty.
- `data-verdict` is `tp`, `fp`, `unclear` or `unlabeled` on a row, and `tp`, `fp` or `unclear` on a hint or button.
- `data-state` on a check or gate is `pass`, `fail` or `undecided`.
- `data-dir` is `added` (candidate only), `dropped` (reference only) or `both`.
- `data-index` on an image is 0-based (`ui.si`); the visible number is index + 1.
- Pick one instance by its identity attribute: `page.locator('[data-testid=group-row][data-group="p|3|dropped|tar"]')`.

## Shared (every page)

| testid | where | attributes |
|---|---|---|
| `header` | page header (both pages) | |
| `toast` | transient message (map page) | visible while `hidden` is off |
| `status` | cross-gate page status line | `data-state` = busy / done / error |

## Map page (`/ui/map/gates/<gate>/`): regions

| testid | where | attributes |
|---|---|---|
| `compared` | header strip of compared setups | |
| `compared-field` | one field in it | `data-k` = gate / scanned / grype / DB / config |
| `theme-button`, `help-button` | header | |
| `help` | help overlay | `hidden` until opened (`?`) |
| `gate-ribbon` | the gate section under the header | |
| `images` | the small multiples strip | |
| `map` | the section holding the board or the treemap | |
| `board` | the gate board, inside `map` | |
| `treemap` | the delta map svg, inside `map` | |
| `tile-view` | section holding the tile and its breadcrumb | `hidden` unless on a match |
| `tile` | the tile itself (see Tile) | |
| `breadcrumb` | the line above the tile | |
| `crumbs` | the line above the board or treemap | |
| `scope-name` | image scope name on the board's `crumbs` | |
| `hover-line` | text line under the treemap | |
| `legend` | treemap legend | |
| `no-differences` | board body when both sides report the same matches | |

## Gate ribbon

| testid | where | attributes |
|---|---|---|
| `gate-outcome` | overall outcome (ribbon, and each `gate-card`) | `data-state` |
| `gate-summary` | "gate X · N checks: ..." line | |
| `gate-footer` | last ribbon line (open/decisive counts) | |
| `gate-view-toggle` | "scan delta map" / "gate board" button | `data-goes-to` = map / board |
| `check-bar` | one check's bar in the ribbon (only off the board: delta map and tile views) | `data-check`, `data-state`, `data-worst`, `data-best`, `data-threshold`, `data-flips-to` (absent unless a hovered accept flips the check; the new state) |
| `check-state` | state word inside a `check-bar` | |
| `preview-note` | ribbon line while an accept is hovered | |
| `preview-range` | dashed preview range (inside a `check-bar` or `panel-bar`, only during hover) | `data-check` |
| `preview-flip` | "-> state" when the preview flips a check | `data-state` = the new state |

## Images

| testid | where | attributes |
|---|---|---|
| `image-all` | the "every image" control | `data-active` |
| `image` | one small multiple | `data-subject` (name), `data-index`, `data-active`, `data-diffs`, `data-open` |
| `image-decisive` | the "◆ n" count, when any | `aria-label` |

## Board

| testid | where | attributes |
|---|---|---|
| `check-panel` | one check's panel | `data-check`, `data-state`, `data-folded` |
| `panel-head` | its head (clicking folds a passing check) | |
| `panel-fold` | fold caret on a passing check | `aria-label` = folded / open |
| `panel-description`, `panel-decides` | description and the "what decides it" line | |
| `panel-bar` | the panel's bar | same as `check-bar`; `preview-flip` is not drawn here, `data-flips-to` says it |
| `failing-claims` | list on a failed check | |
| `failing-claim` | one claim button | `data-vulnerability`, `data-package`, `data-verdict`, `data-count` |
| `reexamine-all` | "re-examine all N" | `data-count` |
| `groups` | list of groups in an undecided panel | |
| `tier` | tier heading (board and cross-gate page) | `data-tier`, `data-count` (groups) |
| `tier-more` | "+ N more" under a tier (both pages) | `data-tier` |
| `group-row` | one group | `data-group` (key: `c\|<cause>` or `p\|<tier>\|<dir>\|<pkg>`), `data-check`, `data-tier`, `data-dir`, `data-package`, `data-count`, `data-hinted`, `data-verdict` (suggested, empty if none) |
| `group-title` | button that opens the group | |
| `group-count` | the count inside it | |
| `group-hint` | suggested verdict chip, or "no agent hint" | `data-verdict`, `data-confidence`, `aria-label` |
| `group-accept` | "accept N" control (hover draws the preview) | `data-count` |
| `group-open` | "open" button | |
| `groups-empty` | "nothing open bears on it" | |
| `research-controls` | research selection and status area (board and treemap `crumbs`) | |
| `research-select` | "research N matches ..." button | `data-select` = could-move-check / no-hint, `data-count` (matches), `data-take` |
| `research-none` | "no match ... left to research" | `data-select` |
| `research-running` | "researching N matches" | `data-count` |
| `research-cancel`, `research-dismiss`, `research-copy` | its buttons | |
| `research-finished` | "research finished on N matches" | `data-count`, `data-cancelled` |
| `research-off` | "research disabled" notice | |
| `researched-mark` | "researched" / "triaged" mark (board rows, claims, tile) | `data-researched`, `data-triaged`, `data-total` (the tile's cards carry the marks without counts) |

## Treemap

| testid | where | attributes |
|---|---|---|
| `dir-region` | background of added / dropped | `data-dir`, `data-count` |
| `dir-label` | its heading | `data-dir` |
| `reason-block` | one reason's area | `data-dir`, `data-why`, `data-count` |
| `reason-head` | header strip; click zooms to that reason | `data-dir`, `data-why` |
| `block` | one source-package block; click opens its cards | `data-dir`, `data-why`, `data-package`, `data-count`, `data-tp`, `data-fp`, `data-unclear`, `data-open`, `data-hinted`, `data-decisive` |
| `zoom-title` | breadcrumb title when zoomed | `data-dir`, `data-why` |
| `zoom-out` | first crumb button: back to the unzoomed map | |
| `label-all-cards` | "label all as cards" while zoomed | |
| `treemap-empty` | "no differences in scope" | |

## Tile

| testid | where | attributes |
|---|---|---|
| `tile` | tile body | `data-row` (row id), `data-verdict` (current), `data-vulnerability`, `data-package` (name), `data-version`, `data-direction` |
| `breadcrumb` / `crumb` | back path | `crumb` has `data-kind` = home / reason / check / here |
| `tile-position` | "N of M" in the breadcrumb | `data-index` (1-based, absent when the group is done), `data-total` |
| `tile-counter` | "N of M in this group" under the tile's top | |
| `receipt` | "Labeled ..." status after a label | `data-moved` when the tile advanced |
| `tile-title` | title line | |
| `tile-direction` | + / − / = mark | `aria-label` |
| `tile-vulnerability`, `tile-package`, `tile-image`, `tile-alias`, `tile-decisive` | parts of the title | |
| `why-panel` | "Why the scans differ" | |
| `why-text`, `match-path`, `match-lanes`, `other-records` | its parts | |
| `hint-section` | wraps the hint card | |
| `hint-card` | the agent hint card | `data-status` = pending / accepted / agrees / disagrees / none, `data-verdict`, `data-confidence`, `data-open` (note and facts shown) |
| `hint-toggle` | verdict button that opens note and facts (`w`) | `aria-expanded` |
| `hint-verdict` | verdict glyph and word | `aria-label` |
| `hint-confidence`, `hint-reason`, `hint-skill`, `hint-status` | card parts (`hint-status` only when settled) | `hint-status` has `data-status` |
| `hint-note`, `hint-facts`, `hint-rule` | "why" panel contents, present when `data-open="true"` | |
| `cause-offer` | "same reasoning on N matches" | `data-count` |
| `accept-all` | "accept all N" button | `data-count`, `data-verdict` |
| `research-foot` | footer of the hint card | |
| `research-button` | "research" / "research again" | `data-researched` |
| `research-status` | queued / running / failed line | `data-state` |
| `label-section` | the label box | |
| `label-effect` | what a TP or FP would mean | |
| `verdict-buttons` | the button row | |
| `verdict-button` | tp / fp / unclear button | `data-verdict`, `data-current` (is the row's verdict), `data-hinted` (it is the agent hint: clicking accepts it) |
| `skip-button` | skip | |
| `advance-toggle`, `advance-checkbox` | "after labeling, go to the next match" | |
| `justification-picker` | the reason select | |
| `justification-none` | its empty option | |
| `justification-group` | optgroup | `data-verdict` |
| `justification-option` | option, value is `<verdict>:<justification>` | `data-verdict`, `data-justification` |
| `note-input` | note field | |
| `label-record` | who/when box once labeled | |
| `label-line` | the label as stored | `data-verdict`, `data-author` |
| `label-note` | one note on it | |
| `evidence-collapsed`, `evidence-toggle` | "more evidence" | |
| `evidence-panel` | opened evidence | |
| `evidence-links`, `evidence-claims`, `raw-candidate`, `raw-reference`, `raw-artifact` | its parts | |
| `group-done` | "Every match in this group is labeled" | |
| `back-to-last` | "z · back to the last one" | |
| `next-group` | next-group offer | `data-group`, `data-check`, `data-count` |

## Cross-gate page (`/ui/map/gates/`... the "every gate" page)

| testid | where | attributes |
|---|---|---|
| `gate-cards` | row of gate cards | |
| `gate-card` | one gate | `data-gate`, `data-state`, `data-open`, `data-active` (filtering to it) |
| `gate-outcome` | outcome in the card | `data-state` |
| `gate-check` | check chip in the card | `data-check`, `data-state` |
| `gate-board-link` | "board ›" link into the gate | `data-gate`, `href` |
| `list-head` | heading of the findings list | `data-gate` (the filter, empty if none) |
| `clear-gate-filter` | "every gate" button | |
| `finding-list` | the list | |
| `tier` / `tier-more` | as on the board | |
| `finding-group` | one group card | `data-group` (`c:<cause>` or `p:<image>\|<pkg>`), `data-open`, `data-count`, `data-hinted`, `data-package`, `data-image` |
| `group-head` | its head (click toggles) | |
| `gate-chip` | per-gate chip on a group head | `data-gate`, `data-bears`, `data-flips` |
| `finding-rows` | rows of an open group | |
| `finding` | one finding | `data-row`, `data-gate` (the gate the label is written through), `data-vulnerability`, `data-package`, `data-image` |
| `gate-effect` | gate chip on a finding | `data-gate`, `data-if-tp`, `data-if-fp` (absent when the gate is decided) |
| `hint-chip` | pending agent hint | `data-verdict`, `data-confidence`, `aria-label` |
| `actions` | the control strip (group head and finding) | `data-scope` = group / finding |
| `accept-button` | accept suggestions | `data-scope`, `data-count` |
| `label-button` | TP | `data-verdict`=tp, `data-scope` |
| `label-select` | FP / unclear with a reason; choosing an option labels | `data-verdict`, `data-scope` |
| `justification-option` | option in a `label-select` | `data-justification` |
| `show-more` | "+ N more" in an open group | `data-group` |
| `list-empty` | nothing open bears on a gate | |
| `status-dismiss` | dismiss the status | |
