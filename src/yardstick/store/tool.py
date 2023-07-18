from __future__ import annotations

import os

from yardstick import artifact
from yardstick.store import config as store_config

TOOL_DIR = "tools"
RESULT_DIR = os.path.join("result", "store")
RESULT_SET_DIR = os.path.join("result", "sets")


def install_path(config: artifact.ScanConfiguration, store_root: str | None = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(
        store_root,
        TOOL_DIR,
        config.tool_name.replace("/", "_"),
        config.tool_version.replace("/", "_"),
    )


def results_path(store_root: str | None = None):
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(store_root, RESULT_DIR)


def result_set_path(store_root: str | None = None):
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(store_root, RESULT_SET_DIR)
