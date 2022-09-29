import collections
import glob
import json
import logging
import os
from typing import Dict, List, Optional, Union

import omitempty

from yardstick import artifact, label
from yardstick.store import config as store_config
from yardstick.store import naming
from yardstick.utils import remove_prefix

LABELS_DIR = "labels"


def label_store_root(store_root: str = None) -> str:
    if not store_root:
        store_root = store_config.get().store_root
    return os.path.join(store_root, LABELS_DIR)


def store_filename_by_entry(entry: artifact.LabelEntry) -> str:
    if not entry.source or entry.source == label.MANUAL_SOURCE:
        if entry.image.exact:
            return f"{naming.image.encode(entry.image.exact)}/{entry.ID}.json"
        return f"{entry.ID}.json"
    if entry.image.exact:
        return f"{naming.image.encode(entry.image.exact)}/{entry.source}.json"
    return f"{entry.source}.json"


def store_path(filename: str, store_root: str = None) -> str:
    return os.path.join(label_store_root(store_root=store_root), filename)


def append_and_update(
    new_and_modified_entries: List[artifact.LabelEntry], delete_entries: List[str] = None, store_root: str = None
) -> List[artifact.LabelEntry]:
    for label_entry in delete_entries:
        filepath = store_path(filename=store_filename_by_entry(entry=label_entry))
        try:
            os.remove(filepath)
        except:  # pylint: disable=bare-except
            pass

    overwrite_all(label_entries=new_and_modified_entries, store_root=store_root)


def overwrite_all(label_entries: List[artifact.LabelEntry], store_root: str = None):
    root_path = label_store_root(store_root=store_root)
    logging.debug(f"storing all labels location={root_path}")

    # organize labels into correct destinations
    label_entries_by_destination: Dict[str, List[artifact.LabelEntry]] = collections.defaultdict(set)

    for label_entry in label_entries:
        if not label_entry:
            # don't keep empty labels
            continue

        if not isinstance(label_entry, artifact.LabelEntry):
            raise RuntimeError(f"only LabelEntry is supported, given {type(label_entry)}")

        path = store_path(filename=store_filename_by_entry(entry=label_entry))
        label_entries_by_destination[path].add(label_entry)

    for path, destination_label_entries in label_entries_by_destination.items():
        logging.debug(f"overwriting all labels location={path}")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as data_file:
            if len(destination_label_entries) == 1:
                json.dump(
                    omitempty(list(destination_label_entries)[0].to_dict()),  # pylint: disable=not-callable
                    data_file,
                    sort_keys=True,
                )
            else:
                logging.debug(f"writing multiple labels to {path!r}: {[l.ID for l in destination_label_entries]}")
                data_file.write(
                    artifact.LabelEntry.schema().dump(  # pylint: disable=no-member
                        sorted(list(destination_label_entries)), many=True
                    )
                )


def load_label_file(filename: str, year_max_limit: Optional[int] = None, store_root: str = None) -> List[artifact.LabelEntry]:
    # why note take a file path? in this way we control that all input/output data was derived from the same store,
    # and not another store.
    path = store_path(filename=filename, store_root=store_root)
    logging.debug(f"loading labels location={path}")

    try:
        with open(path, "r", encoding="utf-8") as data_file:
            data_json = data_file.read()
            if not data_json.strip():
                raise FileNotFoundError

            # dataclass_json does not play nice with method inference here
            try:
                label_entries = [artifact.LabelEntry.from_json(data_json)]  # pylint: disable=no-member
            except:  # pylint: disable=bare-except
                label_entries = artifact.LabelEntry.schema().load(data_json, many=True)  # pylint: disable=no-member
            if year_max_limit:
                label_entries = filter_by_year(label_entries, int(year_max_limit))
            return label_entries

    except FileNotFoundError:
        return []


def load_all(year_max_limit: Optional[int] = None, store_root: str = None) -> List[artifact.LabelEntry]:
    root_path = label_store_root(store_root=store_root)
    logging.debug(f"loading all labels (location={root_path})")

    label_entries: List[artifact.LabelEntry] = []
    files = set(
        list(glob.glob(f"{root_path}/**/**/*.json"))
        + list(glob.glob(f"{root_path}/**/*.json"))
        + list(glob.glob(f"{root_path}/*.json"))
    )
    for file in files:
        filepath = remove_prefix(file, root_path + "/")
        loaded_label_entries = load_label_file(filepath, year_max_limit=year_max_limit, store_root=store_root)
        label_entries.extend(loaded_label_entries)

    return label_entries


def load_for_image(
    images: Union[str, List[str]], year_max_limit: Optional[int] = None, store_root: str = None
) -> List[artifact.LabelEntry]:
    root_path = label_store_root(store_root=store_root)
    if isinstance(images, str):
        images = [images]

    logging.debug(f"loading labels for image (location={root_path} image={images})")

    label_entries: List[artifact.LabelEntry] = []

    # load entries that don't have specific image
    for file in glob.glob(f"{root_path}/*.json"):
        filepath = remove_prefix(file, root_path + "/")
        loaded_label_entries = load_label_file(filepath, store_root=store_root)
        for entry in loaded_label_entries:
            for image in images:
                if entry.matches_image(image):
                    label_entries.append(entry)

    for image in images:
        for file in set(
            list(glob.glob(f"{root_path}/{naming.image.encode(image)}/**/*.json"))
            + list(glob.glob(f"{root_path}/{naming.image.encode(image)}/*.json"))
        ):
            filename = remove_prefix(file, root_path + "/")
            loaded_label_entries = load_label_file(filename, store_root=store_root)
            for entry in loaded_label_entries:
                if entry.matches_image(image):
                    label_entries.append(entry)

    if year_max_limit:
        label_entries = filter_by_year(label_entries, int(year_max_limit))

    return label_entries


# filter_by_year filters out CVE vuln IDs above a given year. We attempt to normalize all vuln IDs to CVEs,
# but will include any if normalization fails.
def filter_by_year(label_entries: list[artifact.LabelEntry], year_max_limit: int) -> list[artifact.LabelEntry]:
    label_entries_copy = []

    for l in label_entries:
        year = l.effective_cve_year
        if (year and year <= year_max_limit) or not year:
            label_entries_copy.append(l)

    return label_entries_copy
