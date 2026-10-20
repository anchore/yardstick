# Test anchors

Select with `getByTestId("<testid>")`, narrow with the `data-*` identity attributes. Do not select by class, id or DOM shape.

- Boolean attributes are the strings `true` / `false`. An attribute shown as `(absent)` is left off when empty.
- `data-verdict` is `tp`, `fp`, `unclear` or `unlabeled` on a row, and `tp`, `fp` or `unclear` on a hint or button.
- `data-state` on a check or gate is `pass`, `fail` or `undecided`.
- Table rows are `tbody tr[data-id]` inside the table's testid; `data-id` is the row id (16 hex), or a made-up key for a row with no finding page.
- Pick one instance by its identity attribute: `page.locator('[data-testid=check-row][data-check=f1NotWorse]')`.

Routes (`route.ts`): `/ui/gates/` (level 0, `?tab=unlabeled|labels`), `/ui/gates/<gate>/` and `findings` / `labels` / `map` (level 1), `/ui/gates/<gate>/checks/<check>` (level 2), and a finding at `/ui/gates/<gate>/checks/<check>/<row>` or `/ui/gates/<gate>/findings/<row>` (level 3). Filters ride in the query: `image` (slug), `verdict`, `hint`, `pkg`, `q`, `page`. The labeling flow's screens sit beside them: `/ui/hints`, `/ui/queue` (and `/ui/queue/<row>`) and `/ui/history`, each a `placeholder` for now.

## Shell (every screen)

| testid | where | attributes |
|---|---|---|
| `app-bar` | the bar at the top | |
| `breadcrumb` | the crumbs; each crumb above the current one is a link | |
| `gate-switch`, `gate-switch-button` | the gate crumb's switcher and its ▾ trigger; the menu is filled as it opens | |
| `gate-option` | one gate in the switcher, a link to the same level there | `data-gate`, `data-state`, `data-open` (unlabeled and unclear rows), `aria-current` on this gate |
| `goto-button` | "Go to…" in the app bar, which opens the palette like `⌘K` / `ctrl+K` | |
| `palette` | the go-to palette (Basecoat's command), visible while open | |
| `palette-input` | its search box | |
| `palette-item` | one entry, a link | `data-group` (`Gates`, `Images`, `Checks`, `Findings`, `Actions`), `data-id` (gate, image ref, `<gate>/<check>`, row id, or `hints` / `queue` / `history`) |
| `palette-more` | how many more findings match than are shown | |
| `title-row` | the title line | |
| `title` | the screen's `h1` | |
| `status` | a state badge: the gate's or check's in `title-row`, and one per gate or check row | text is the state |
| `verdict` | a verdict badge: the finding's in `title-row`, and one per table row | text `TP`, `FP`, `unclear` or `unlabeled` |
| `hint` | an agent hint mark in a table cell | text e.g. `TP · medium`, or `package hint` |
| `tabs` | the screen's tabs (levels 0 and 1); each tab is `role=tab` | `aria-selected`, `data-tab` |
| `scope-chip` | "image: …" beside the tabs while an image is picked | `hidden` without one |
| `label-next` | the primary "Label next" button (a link, or disabled when nothing is open) | |
| `loading`, `load-error` | the body while loading, or when it failed | |
| `toast` | transient message | visible while `hidden` is off |

## Image rail (levels 1 and 2)

| testid | where | attributes |
|---|---|---|
| `image-rail` | the rail | `hidden` when collapsed |
| `rail-image` | one image, the first one being "All images" | `data-slug` (empty for all), `aria-pressed` (picked) |
| `rail-filter`, `rail-sort` | the rail's filter box and sort toggle | |
| `rail-collapse`, `rail-expand` | collapse to the dropdown, and back | |
| `image-picker`, `image-picker-button` | the collapsed dropdown and its trigger | |

## Gates (level 0)

| testid | where | attributes |
|---|---|---|
| `gate-rows` | the list of gates | |
| `gate-row` | one gate, a link into it | `data-gate`, `data-state`, `href` |
| `gate-unlabeled` | "N unlabeled of M changed" | |
| `unlabeled-table` | the Unlabeled tab: open findings across gates | rows keyed by finding |
| `labels-table` | the Labels tab (and the gate's) | |

## Gate (level 1)

| testid | where | attributes |
|---|---|---|
| `verdict-bar` | the gate's verdict mix and its legend | |
| `check-rows` | the Checks tab | |
| `check-row` | one check, a link to it | `data-check`, `data-state` |
| `meter` | a check's value against its limit, captioned "0.500 worse · limit 0" | |
| `check-count` | "N unlabeled" and what labeling does for it | |
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
| `label-as` | the "Label as…" select, option values `<verdict>:<justification>` | |

Filter chips are buttons with `data-chip` (`all`, `unlabeled`, `tp`, `fp`, `unclear`, `hint`) and `aria-pressed`; the count is the `b` inside.

## Finding (level 3)

| testid | where | attributes |
|---|---|---|
| `pager` | "N of M open" beside the breadcrumb: the open rows `j` / `k` walk, or every row when none is open | `data-index` (1-based among them, 0 for a labeled row or one the filters leave out), `data-total`, `data-open` |
| `pager-previous`, `pager-next` | its `k` / `j` links | |
| `finding-effect` | what its label does, in the title row | `data-effect` = decides / could-move |
| `finding-sub`, `finding-package`, `finding-image`, `finding-direction` | the subtitle and its parts | `finding-image` has the full ref in `title` |
| `finding` | the page body | `data-row`, `data-verdict` |
| `finding-tabs` | the content tabs, `role=tab` | `aria-selected`, `data-tab` = why / evidence / raw / labels |
| `tab-why`, `tab-evidence`, `tab-raw`, `tab-labels` | their panels | |
| `why-text`, `match-path`, `finding-ref` | Why it differs | |
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
| `label-meaning` | what a TP and an FP say about the candidate | |
| `reason-picker` | the reason select | |
| `reason-option` | one reason | |
| `note-input` | the note; Enter saves | |
| `save-label` | "Save and next", or "Save" with the switch off | |
| `skip-button` | Skip (`j`) | |
| `advance-toggle`, `advance-checkbox` | "after labeling, go to the next match" | |
| `research-foot`, `research-button`, `research-status` | research (`R`) | `research-button` has `data-researched`; `research-status` has `data-state` |

## Component kit (`/ui/gates/_kit`)

| testid | where | attributes |
|---|---|---|
| `kit-gallery`, `kit-table`, `primary` | the kit's parts | |
