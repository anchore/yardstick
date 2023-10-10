from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from dataclasses_json import dataclass_json

from yardstick.store import config as store_config

IMAGE_LINEAGE_DIR = os.path.join("image-lineage")
SUFFIX = ".json"


@dataclass_json
@dataclass(frozen=True, eq=True, order=True)
class ImageLineageDocument:
    lineage: dict[str, list[str]]


def store_path(suffix: str = SUFFIX, store_root: str | None = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root

    return os.path.join(store_root, IMAGE_LINEAGE_DIR, "image-lineage" + suffix)


def add(image: str, lineage: list[str], store_root: str | None = None):
    data_path = store_path(store_root=store_root)
    logging.debug(f"storing image lineage to {data_path!r}")

    os.makedirs(os.path.dirname(data_path), exist_ok=True)

    existing = load(store_root=store_root)
    existing[image] = lineage

    with open(data_path, "w", encoding="utf-8") as data_file:
        data_file.write(
            ImageLineageDocument(lineage=existing).to_json(indent=2),  # type: ignore[attr-defined]
        )


def get_parents(image: str, store_root: str | None = None) -> list[str]:
    return load(store_root).get(image, [])


def get(image: str, store_root: str | None = None) -> list[str]:
    result = []
    parents = get_parents(image, store_root=store_root)
    result += parents

    for parent in parents:
        for ancestor in get(parent, store_root=store_root):
            if ancestor not in result:
                result += [ancestor]
    return result


def load(store_root: str | None = None) -> dict[str, list[str]]:
    data_path = store_path(store_root=store_root)
    logging.debug(f"loading image lineage location={data_path!r}")

    if not os.path.exists(data_path):
        return {}

    with open(data_path, encoding="utf-8") as data_file:
        data_json = data_file.read()
        return ImageLineageDocument.from_json(  # type: ignore[attr-defined]
            data_json,
        ).lineage
