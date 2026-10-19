# Developing

After cloning, run `make` to run linting, tests, and other verifications. Helper tools are installed on demand into `.tool/` by [go-make](https://github.com/anchore/go-make) the first time they are needed.

The main tasks are `lint`, `format`, `lint-fix`, `unit` and `snapshot`. `make help` lists the rest.

## Test fixtures

Fixtures under `cmd/yardstick/internal/fixture` are produced by the real, pinned syft, grype, vexctl and oras, never written by hand. `make fixtures` regenerates them and needs docker.

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
