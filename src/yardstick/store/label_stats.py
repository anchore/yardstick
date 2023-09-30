from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import shutil
from typing import Any

from yardstick import comparison
from yardstick.store import config as store_config

LABEL_STATS_DIR = "label-stats"


def _store_root(store_root: str | None = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root
    return os.path.join(store_root, LABEL_STATS_DIR)


def store_path(
    ids: list[str],
    configuration: list[dict[str, Any]] | None,
    store_root: str | None = None,
) -> str:
    config_str = _configuration_string(configuration)

    filename = "_".join(sorted(ids)) + "_" + config_str + ".json"

    return os.path.join(_store_root(store_root=store_root), filename)


def clear(store_root: str | None = None):
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(_store_root(store_root=store_root))


def save(result: comparison.ImageToolLabelStats, store_root: str | None = None):
    if not isinstance(result, comparison.ImageToolLabelStats):
        raise RuntimeError(
            f"only ImageToolLabelStats is supported, given {type(result)}",
        )

    ids = [c.ID for c in result.configs]
    path = store_path(ids, result.compare_configs, store_root=store_root)
    logging.debug(f"storing label comparison state for {ids!r}")

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as data_file:
        data_file.write(json.dumps(result.to_dict(), indent=2))  # type: ignore[attr-defined]


def _configuration_string(configurations: list[dict[str, str]] | None) -> str:
    if configurations is None:
        return "no-configuration"

    config_strs = []
    for configuration in configurations:
        config_str = ",".join([f"{k}={v}" for k, v in sorted(configuration.items())])
        config_strs.append(config_str)

    return hashlib.sha256(",".join(config_strs).encode("utf-8")).hexdigest()


def load(
    ids: list[str],
    configurations: list[dict[str, Any]] | None = None,
    store_root: str | None = None,
) -> comparison.ImageToolLabelStats:
    data_path = store_path(ids, configurations, store_root=store_root)

    logging.debug(
        f"loading label comparison state for {ids!r} with detailed configurations location={data_path!r}",
    )

    with open(data_path, encoding="utf-8") as data_file:
        data_json = data_file.read()

    return comparison.ImageToolLabelStats.from_json(  # type: ignore[attr-defined]
        data_json,
    )
