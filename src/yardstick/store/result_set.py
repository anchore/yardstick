from __future__ import annotations

import json
import logging
import os
import shutil

from yardstick import artifact
from yardstick.store import config as store_config
from yardstick.store import scan_result, tool


def _store_root(store_root: str | None = None):
    if not store_root:
        store_root = store_config.get().store_root

    return tool.result_set_path(store_root=store_root)


def clear(store_root: str | None = None):
    shutil.rmtree(_store_root(store_root=store_root), ignore_errors=True)


def store_paths(name: str, store_root: str | None = None) -> str:
    parent_dir = _store_root(store_root=store_root)

    return os.path.join(parent_dir, f"{name}.json")


def save(results: artifact.ResultSet, store_root: str | None = None):
    if not isinstance(results, artifact.ResultSet):
        raise RuntimeError(f"only ResultSet is supported, given {type(results)}")

    path = store_paths(results.name, store_root=store_root)
    logging.debug(f"storing result set state {results.name!r}")

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as data_file:
        data_file.write(json.dumps(results.to_dict(), indent=2))  # type: ignore[attr-defined]


def load(name: str, store_root: str | None = None) -> artifact.ResultSet:
    data_path = store_paths(name, store_root=store_root)
    logging.debug(f"loading result set {name!r} location={data_path!r}")

    with open(data_path, encoding="utf-8") as data_file:
        data_json = data_file.read()
    return artifact.ResultSet.from_json(data_json)  # type: ignore[attr-defined]


def load_scan_results(
    name: str,
    year_max_limit: int | None = None,
    store_root: str | None = None,
    skip_sbom_results: bool = False,
) -> list[artifact.ScanResult]:
    data_path = store_paths(name, store_root=store_root)
    logging.debug(
        f"loading scan results from result set {name!r} location={data_path!r}",
    )

    result_set = load(name, store_root=store_root)

    descriptions = [
        result_state.config.path
        for result_state in result_set.state
        if result_state.config
    ]
    return scan_result.load_by_descriptions(
        descriptions,
        year_max_limit=year_max_limit,
        store_root=store_root,
        skip_sbom_results=skip_sbom_results,
    )


def exists(name: str, store_root: str | None = None) -> bool:
    data_path = store_paths(name, store_root=store_root)
    return os.path.exists(data_path)


def load_all(store_root: str | None = None) -> list[artifact.ResultSet]:
    parent_dir = _store_root(store_root=store_root)
    result_sets = []

    for file_name in os.listdir(parent_dir):
        if file_name.endswith(".json"):
            result_sets.append(load(file_name[:-5], store_root=store_root))

    return result_sets
