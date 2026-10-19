# Developing

After cloning, run `make` to run linting, tests, and other verifications. Helper tools are installed on demand into `.tool/` by [go-make](https://github.com/anchore/go-make) the first time they are needed.

The main tasks are `lint`, `format`, `lint-fix`, `unit` and `snapshot`. `make help` lists the rest.

## Test fixtures

Fixtures under `cmd/yardstick/internal/fixture` are produced by the real, pinned syft, grype, vexctl and oras, never written by hand. `make fixtures` regenerates them and needs docker.

## Label UI

The label UI (`claims serve`) is TypeScript under `cmd/yardstick/internal/labelserver/web/`. The built output is gitignored; the HTML stays committed in `assets/`. No Node is needed on the host: `bun`, `tygo` and `tsc` install on demand into `.tool/`, and Playwright runs in docker.

- `make generate` builds the UI (bun install, tygo, tsc, esbuild)
- `make dev` runs a live-reload dev server beside `tsc --watch`: save a `.ts` file and the page reloads, save CSS and it swaps in place. It serves the workspace in the repo root (which needs a run under `.yardstick/runs/`) unless `YARDSTICK_DEV_DIR` points at another, and `ARGS` adds `claims serve` flags. A type error shows in the `tsc` output and never stops the server
- `make unit` runs the Go tests and `bun test`
- `make e2e` runs the Playwright tests in docker (needs docker). Traces and the report land in `web/test-results/` and `web/playwright-report/`. The workspace it serves, two real gates with labels and agent hints, is described in `cmd/yardstick/internal/testkit/testdata/e2e/SCENARIO.md`; `go test ./cmd/yardstick/internal/testkit` checks that description without a browser
- `make e2e-ui` starts Playwright UI mode at http://127.0.0.1:8080

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
