# Developing

## Getting Started

This project requires:
- python (>= 3.11)
- uv (>= 0.5): see [installation instructions](https://docs.astral.sh/uv/getting-started/installation/)

Once you have python and uv installed, get the project bootstrapped:

```bash
# get basic project tooling
make tools

# install project dependencies
uv sync
```

[Pre-commit](https://pre-commit.com/) is used to help enforce static analysis checks with git hooks:

```bash
uv run pre-commit install --hook-type pre-push
```

## Developing

If you want to use a locally-editable copy of yardstick while you develop:

```bash
uv pip uninstall yardstick  #... if you already have yardstick installed in this virtual env
uv pip install -e .
```

To run all static-analysis and tests:

```bash
make
```

Or run them individually:

```bash
make static-analysis
make unit
make cli
```

If you want to see all of the things you can do:

```bash
make help
```
