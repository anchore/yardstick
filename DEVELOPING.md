# Developing

After cloning, run `make` to run linting, tests, and other verifications. Helper tools are installed on demand into `.tool/` by [go-make](https://github.com/anchore/go-make) the first time they are needed.

The main tasks are `lint`, `format`, `lint-fix`, `unit` and `snapshot`. `make help` lists the rest.

## Test fixtures

Fixtures under `cmd/yardstick/internal/fixture` are produced by the real, pinned syft, grype, vexctl and oras, never written by hand. `make fixtures` regenerates them and needs docker.

## Label UI

The label UI (`claims serve`) is TypeScript under `cmd/yardstick/internal/labelserver/web/`. The built output is gitignored; the HTML stays committed in `assets/`. No Node is needed on the host: `bun`, `tygo` and `tsc` install on demand into `.tool/`, and Playwright runs on that `bun`.

It is one page, `assets/app/index.html`, routed in the browser (`web/src/app/route.ts`): `/ui/gates/` lists the gates, `/ui/gates/<gate>/` is a gate with its Checks, Findings, Labels and Scan map tabs, `/ui/gates/<gate>/checks/<check>` a check, and a finding opens under the list it came from (`.../checks/<check>/<row>` or `/ui/gates/<gate>/findings/<row>`). Filters ride in the query string. The labeling flow's screens sit beside them: `/ui/hints` reviews pending agent hints (`?gate=`, `image=`, `low=1`), `/ui/research` prices and starts research of the open matches no agent has looked at, one table row per match (`?scope=`, `check=` for one check's rows, `rows=` for a table selection, `groups=` for the groups checked at first, and the filters `chip`, `image` and `q`), `/ui/research/jobs` lists every research job, `/ui/queue` and `/ui/queue/<row>` walk the open rows one at a time across gates (`?scope=all|gate:<g>|image:<slug>`, `check`, `low=1`), and `/ui/history` lists the labels in `./claims`, newest first, from the server's start unless `?since=` says `all` or a time, and removes them; the app bar's History link opens it and counts the labels written since the server started. They read `GET /api/hints`, `GET /api/queue` and `GET /api/history`, accept through `POST /api/hints/accept`, and remove through `POST /api/history/revert`, which a write's toast also calls for its Undo; research plans and starts through `POST /api/research` (`dryRun` to price; each planned job lists its open `matches`, and a start takes the checked ones as `rows`), the gates banner follows a batch through `GET /api/research/batch` and stops it with `POST /api/research/batch/cancel`, and the jobs page, the top bar's research chip and the tables follow jobs through `GET /api/research/jobs`. `/` opens the gate `claims serve` was given, else the gate list, and the old `/ui/map/` URLs redirect to their new screens. `web/UI-RULES.md` holds the rules every screen follows, and `/ui/gates/_kit` shows the components.

- `make generate` builds the UI (bun install, tygo, tsc, esbuild)
- `make dev` runs a live-reload dev server beside `tsc --watch` and prints its URL: save a `.ts` file and the page reloads, save CSS and it swaps in place. It serves the workspace in the repo root (which needs a run under `.yardstick/runs/`) unless `YARDSTICK_DEV_DIR` points at another, and `ARGS` adds `claims serve` flags. A type error shows in the `tsc` output and never stops the server
- `make dev:e2e` is `make dev` over the e2e tests' workspace (the gates, labels and hints in `SCENARIO.md`), rebuilt fresh into `.tmp/dev-e2e` on every start. Research runs the real `claude` command here, not the tests' stand-in
- `make unit` runs the Go tests and `bun test`
- `make e2e` runs the Playwright tests on the host, headless; `make e2e HEADED=1` shows the browser. The first run downloads chromium into Playwright's cache (`~/Library/Caches/ms-playwright` on macOS, `~/.cache/ms-playwright` on Linux). Traces and the report land in `web/test-results/` and `web/playwright-report/`. The workspace it serves, two real gates with labels and agent hints, is described in `cmd/yardstick/internal/testkit/testdata/e2e/SCENARIO.md`; `go test ./cmd/yardstick/internal/testkit` checks that description without a browser
- `make e2e:container` runs the same tests headless in Playwright's linux docker image (the one `@playwright/test` is pinned to), for a sandbox or agent session where a host browser can't start. It mounts the repo and uses the host's `node_modules`; `make e2e` stays the default
- make passes no arguments on to Playwright. To run one spec or pass a flag, build once with `make generate` and call the task: `task e2e:container -- workflow.spec.ts`, `task e2e -- --grep 'Esc'`. The test ids the specs select by are in `web/e2e/ANCHORS.md`
- `make e2e-ui` opens Playwright UI mode in its own window. Run a test there and pick a step to see the page at that point

When e2e fails in CI, download the `playwright-results` artifact and drop its `trace.zip` on https://trace.playwright.dev. The trace loads locally in the browser and nothing is uploaded.

## Output

Every command follows the same few rules, so they read alike:

- stdout is the result, stderr is progress and logs. A report piped to a file has no progress in it.
- Progress is drawn only for something worth waiting on: a download, an install, a build, a scan. Publish it as a task on the bus (`bus.StartTask`) and the live view draws a spinner, then a `✔` or `✘` with how long it took. A command that only reads local files draws nothing.
- A result is a line per thing acted on, led by a mark: `✔` done or valid, `✘` failed, `!` worth a look but failing nothing, `·` nothing to do. Columns line up across lines; the `printer` in `cli/command/print.go` does both.
- Color carries meaning only: green done, red failed, yellow worth a look, faint for detail. It is on only when the stream is a terminal and `NO_COLOR` is unset, and the text reads the same without it.
- No emoji, and no decoration a pipe would have to strip.

## Layout

```
cmd/yardstick/
├── cli/          # the clio application and its commands
├── internal/     # everything else; nothing here is a public API
└── main.go       # entrypoint and target for ldflags (version info)
demo/             # the walkthrough, with the gates and grype config it runs
plugin/           # the yardstick Claude Code plugin (triage, research, explain skills)
```

The claims corpus is not in this repo. A gate names its claims source (a local directory or a published corpus), and yardstick reads it from there.

The Python implementation is on the `python` branch, see [RELEASE.md](RELEASE.md).
