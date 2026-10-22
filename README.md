# yardstick

Measure how a vulnerability scanner's results change between two configurations, judged against labeled claims, and gate on it.

```
yardstick <gate.yaml>...     # run gates: build SBOMs, scan with each setup, score against labels
yardstick collect ...        # build SBOMs and run scans without scoring
yardstick score ...          # re-score the last scans against the current labels
yardstick claims ...         # write, move and check labels in a claims corpus (`claims serve` is the label UI)
```

See [demo/](demo/README.md) for a walkthrough of the whole local workflow: run a gate, label what changed, get the labels into the claims corpus. [docs/gate-file.md](docs/gate-file.md) lists every gate file key and check, and what changed from the Python yardstick's gates.

## Installation

```
curl -sSfL https://get.anchore.io/yardstick | sudo sh -s -- -b /usr/local/bin
```

or `go install github.com/anchore/yardstick/cmd/yardstick@latest`. A `go install` build has the full CLI but no label UI (`claims serve` refuses to start), so use the installer for labeling.

## Python yardstick (0.16.x)

This is a Go rewrite and ships from v0.17.0. It is never published to PyPI, so `pip install yardstick` and existing `yardstick>=0.16` pins keep resolving to the Python implementation, which is maintained on the [`python`](https://github.com/anchore/yardstick/tree/python) branch for patch releases only.
