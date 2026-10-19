# yardstick

Measure how a vulnerability scanner's results change between two configurations, judged against labeled claims, and gate on it.

```
yardstick <gate.yaml>...     # run gates: build SBOMs, scan with each setup, score against labels
yardstick collect ...        # build SBOMs and run scans without scoring
yardstick score ...          # re-score the last scans against the current labels
yardstick claims ...         # write, move and check labels in a claims corpus (`claims serve` is the label UI)
```

See [cmd/yardstick/DEMO.md](cmd/yardstick/DEMO.md) for a walkthrough and [config/gates](config/gates) for example gates.

## Installation

```
curl -sSfL https://get.anchore.io/yardstick | sudo sh -s -- -b /usr/local/bin
```

or `go install github.com/anchore/yardstick/cmd/yardstick@latest`.

## Python yardstick (0.16.x)

This is a Go rewrite and ships from v0.17.0. It is never published to PyPI, so `pip install yardstick` and existing `yardstick>=0.16` pins keep resolving to the Python implementation, which is maintained on the [`python`](https://github.com/anchore/yardstick/tree/python) branch for patch releases only.
