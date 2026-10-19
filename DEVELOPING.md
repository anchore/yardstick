# Developing

After cloning, run `make` to run linting, tests, and other verifications. Helper tools are installed on demand into `.tool/` by [go-make](https://github.com/anchore/go-make) the first time they are needed.

The main tasks are `lint`, `format`, `lint-fix`, `unit` and `snapshot`. `make help` lists the rest.

## Test fixtures

Fixtures under `cmd/yardstick/internal/fixture` are produced by the real, pinned syft, grype, vexctl and oras, never written by hand. `make fixtures` regenerates them and needs docker.

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
