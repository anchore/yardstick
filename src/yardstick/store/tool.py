import os

from yardstick import artifact
from yardstick.store import config as store_config

TOOL_DIR = "tools"
RESULT_DIR = os.path.join("result", "store")
RESULT_SET_DIR = os.path.join("result", "sets")


def install_base(name: str, store_root: str = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(store_config.get().store_root, TOOL_DIR, name.replace("/", "_"))


def install_path(config: artifact.ScanConfiguration, store_root: str = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root

    store_base = install_base(name=config.tool_name, store_root=store_root)

    version = config.tool_version
    if config.tool_name.startswith("grype"):
        version = version.split("+import-db=")[0]

    return os.path.join(
        store_base,
        version.replace("/", "_"),
    )


def results_path(store_root: str = None):
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(store_root, RESULT_DIR)


def result_set_path(store_root: str = None):
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(store_root, RESULT_SET_DIR)
