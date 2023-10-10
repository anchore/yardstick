from __future__ import annotations

import collections
import glob
import json
import logging
import os

import omitempty  # type: ignore[import]

from yardstick import artifact
from yardstick.store import config as store_config
from yardstick.store import naming
from yardstick.utils import remove_prefix

LABELS_DIR = "labels"


def label_store_root(store_root: str | None = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root
    return os.path.join(store_root, LABELS_DIR)


def store_filename_by_entry(entry: artifact.LabelEntry) -> str:
    if entry.image and entry.image.exact:
        return f"{naming.image.encode(entry.image.exact)}/{entry.ID}.json"
    return f"{entry.ID}.json"


def store_path(filename: str, store_root: str | None = None) -> str:
    return os.path.join(label_store_root(store_root=store_root), filename)


def append_and_update(
    new_and_modified_entries: list[artifact.LabelEntry],
    delete_entries: list[artifact.LabelEntry] | None = None,
    store_root: str | None = None,
) -> None:
    if delete_entries:
        for label_entry in delete_entries:
            filepath = store_path(filename=store_filename_by_entry(entry=label_entry))
            try:
                logging.debug(f"deleting label {label_entry.ID} from {filepath}")
                os.remove(filepath)
            except FileNotFoundError:
                logging.debug(
                    f"skipping deleting on {label_entry.ID} from {filepath}: File not found",
                )
            except Exception as e:
                logging.error(
                    f"failed to delete label {label_entry.ID} from {filepath}: {e}",
                )
                raise e

    save(label_entries=new_and_modified_entries, store_root=store_root)


def delete(
    label_ids_to_delete: list[str],
    store_root: str | None = None,
) -> list[str]:
    """delete_entries takes a list of ids to be deleted and returns a list of deleted files.
    FileNotFound exceptions are ignored."""
    label_store_dir = label_store_root(store_root=store_root)
    deleted_ids = []
    for label_id in label_ids_to_delete:
        g = f"{label_store_dir}/**/{label_id}.json"
        for p in glob.glob(g):
            try:
                os.remove(p)
                deleted_ids.append(label_id)
            except FileNotFoundError:
                logging.debug(
                    f"skipping deleting on {label_id} from {p}: File not found",
                )
            except Exception as e:
                logging.error(f"failed to delete label {label_id} from {p}: {e}")
                raise e
    return deleted_ids


def save(label_entries: list[artifact.LabelEntry], store_root: str | None = None):
    root_path = label_store_root(store_root=store_root)
    logging.debug(f"storing all labels location={root_path}")

    # organize labels into correct destinations
    label_entries_by_destination = collections.defaultdict(set)

    for label_entry in label_entries:
        if not label_entry:
            # don't keep empty labels
            continue

        if not isinstance(label_entry, artifact.LabelEntry):
            raise RuntimeError(
                f"only LabelEntry is supported, given {type(label_entry)}",
            )

        path = store_path(filename=store_filename_by_entry(entry=label_entry))
        label_entries_by_destination[path].add(label_entry)

    for path, destination_label_entries in label_entries_by_destination.items():
        logging.debug(f"overwriting all labels location={path}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as data_file:
            if len(destination_label_entries) == 1:
                json.dump(
                    omitempty(
                        next(iter(destination_label_entries)).to_dict(),  # type: ignore[attr-defined]
                    ),
                    data_file,
                    sort_keys=True,
                )
            else:
                logging.debug(
                    f"writing multiple labels to {path!r}: {[label_entry.ID for label_entry in destination_label_entries]}",
                )
                data_file.write(
                    artifact.LabelEntry.schema().dump(  # type: ignore[attr-defined]
                        sorted(destination_label_entries),
                        many=True,
                    ),
                )


def load_label_file(
    filename: str,
    year_max_limit: int | None = None,
    year_from_cve_only: bool = False,
    store_root: str | None = None,
) -> list[artifact.LabelEntry]:
    # why note take a file path? in this way we control that all input/output data was derived from the same store,
    # and not another store.
    path = store_path(filename=filename, store_root=store_root)

    try:
        with open(path, encoding="utf-8") as data_file:
            data_json = data_file.read()
            if not data_json.strip():
                raise FileNotFoundError

            # dataclass_json does not play nice with method inference here
            try:
                label_entries = [
                    artifact.LabelEntry.from_json(data_json),  # type: ignore[attr-defined]
                ]
            except:  # noqa: E722
                label_entries = artifact.LabelEntry.schema().load(  # type: ignore[attr-defined]
                    data_json,
                    many=True,
                )
            if year_max_limit:
                label_entries = filter_by_year(
                    label_entries,
                    year_max_limit=int(year_max_limit),
                    year_from_cve_only=year_from_cve_only,
                )
            return label_entries

    except FileNotFoundError:
        return []


def load_all(
    year_max_limit: int | None = None,
    year_from_cve_only: bool = False,
    store_root: str | None = None,
) -> list[artifact.LabelEntry]:
    root_path = label_store_root(store_root=store_root)
    logging.debug(f"loading all labels (location={root_path})")

    label_entries: list[artifact.LabelEntry] = []
    files = set(
        list(glob.glob(f"{root_path}/**/**/*.json"))
        + list(glob.glob(f"{root_path}/**/*.json"))
        + list(glob.glob(f"{root_path}/*.json")),
    )
    for file in files:
        filepath = remove_prefix(file, root_path + "/")
        loaded_label_entries = load_label_file(
            filepath,
            year_max_limit=year_max_limit,
            year_from_cve_only=year_from_cve_only,
            store_root=store_root,
        )
        label_entries.extend(loaded_label_entries)

    return label_entries


def load_for_image(
    images: str | list[str],
    year_max_limit: int | None = None,
    year_from_cve_only: bool = False,
    store_root: str | None = None,
) -> list[artifact.LabelEntry]:
    root_path = label_store_root(store_root=store_root)
    if isinstance(images, str):
        images = [images]

    logging.debug(f"loading labels for image (location={root_path} image={images})")

    label_entries: list[artifact.LabelEntry] = []

    # load entries that don't have specific image
    for file in glob.glob(f"{root_path}/*.json"):
        filepath = remove_prefix(file, root_path + "/")
        loaded_label_entries = load_label_file(
            filepath,
            year_max_limit=year_max_limit,
            year_from_cve_only=year_from_cve_only,
            store_root=store_root,
        )
        for entry in loaded_label_entries:
            for image in images:
                if entry.matches_image(image):
                    label_entries.append(entry)

    for image in images:
        for file in set(
            list(glob.glob(f"{root_path}/{naming.image.encode(image)}/**/*.json"))
            + list(glob.glob(f"{root_path}/{naming.image.encode(image)}/*.json")),
        ):
            filename = remove_prefix(file, root_path + "/")
            loaded_label_entries = load_label_file(
                filename,
                year_max_limit=year_max_limit,
                year_from_cve_only=year_from_cve_only,
                store_root=store_root,
            )
            for entry in loaded_label_entries:
                if entry.matches_image(image):
                    label_entries.append(entry)

    return label_entries


# filter_by_year filters out CVE vuln IDs above a given year. We attempt to normalize all vuln IDs to CVEs,
# but will include any if normalization fails.
def filter_by_year(
    label_entries: list[artifact.LabelEntry],
    year_max_limit: int,
    year_from_cve_only: bool = False,
) -> list[artifact.LabelEntry]:
    label_entries_copy = []

    for label_entry in label_entries:
        year = label_entry.effective_year(by_cve=year_from_cve_only)
        if (year and year <= year_max_limit) or not year:
            label_entries_copy.append(label_entry)

    return label_entries_copy
