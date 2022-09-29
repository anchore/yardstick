# Developing

## Getting Started

This project uses [poetry](https://python-poetry.org/) for dependency and virtualenv management. Additionally, [pre-commit](https://pre-commit.com/) hooks are used to enforce static checks.
```
poetry install
poetry run pre-commit install --hook-type pre-push
```
To jump into a poetry-managed virtualenv run `poetry shell`, this will prevent the need for `poetry run...` prefix for each command.

## Developing

To run all validations:
```
make
```

To run unit tests:
```
make unit
```

To run CLI / smoke tests:
```
make cli
```
