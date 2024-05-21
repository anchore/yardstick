from typing import List, Optional

from yardstick.artifact import LabelEntry, Match

# note: this cannot be changed, as there is persisted values with this value + store logic based on this
MANUAL_SOURCE = "manual"


def label_entry_matches_image_lineage(
    label_entry: LabelEntry,
    image: Optional[str],
    lineage: Optional[List[str]] = None,
):
    if not lineage:
        lineage = []
    return any(label_entry.matches_image(i) for i in [image, *lineage])


def find_labels_for_match(  # noqa: PLR0913, PLR0912, C901
    image: Optional[str],
    match: Match,
    label_entries: List[LabelEntry],
    lineage: Optional[List[str]] = None,
    must_match_image=True,
    fuzzy_package_match=False,
) -> List[LabelEntry]:
    matched_label_entries: List[LabelEntry] = []
    for label_entry in label_entries:
        # this field must be matched to continue
        if not has_overlapping_vulnerability_id(label_entry, match):
            continue

        # this field must be matched to continue
        if must_match_image and not label_entry_matches_image_lineage(
            label_entry,
            image,
            lineage,
        ):
            continue

        # we need at least one more field to match to consider this label valid for the given match...
        matched_fields = 0

        if label_entry.package:
            if label_entry.package != match.package:
                # if fuzzy mathcing isn't enabled, bail now
                if not fuzzy_package_match:
                    continue

                # names must minimally match with some normalization
                if label_entry.package.name.replace(
                    "-",
                    "_",
                ) != match.package.name.replace("-", "_"):
                    continue

                # version must be a subset or superset of other
                if (
                    label_entry.package.version != match.package.version
                    and label_entry.package.version not in match.package.version
                    and match.package.version not in label_entry.package.version
                ):
                    continue

            matched_fields += 1

        if label_entry.fullentry_fields:
            mismatched = False
            for value in label_entry.fullentry_fields:
                if not _contains_as_value(match.fullentry, value):
                    mismatched = True
                    break
            if mismatched:
                continue
            matched_fields += 1

        if matched_fields > 0:
            # we should match on a minimum number of fields, otherwise a blank entry with a vuln ID will match, which is wrong
            matched_label_entries.append(label_entry)
    return matched_label_entries


def has_overlapping_vulnerability_id(label_entry: LabelEntry, match: Match) -> bool:
    left_ids = {label_entry.vulnerability_id, label_entry.effective_cve}
    right_ids = {match.vulnerability.id, match.vulnerability.cve_id}

    if "" in left_ids:
        left_ids.remove("")

    if "" in right_ids:
        right_ids.remove("")

    return bool(left_ids & right_ids)


def _contains_as_value(o, target):
    if isinstance(o, dict):
        values = [v for k, v in o.items()]
    elif isinstance(o, list):
        values = o
    else:
        return target in o
    for v in values:
        if v == target:
            return True
        if isinstance(v, dict) and _contains_as_value(v, target):
            return True
        if isinstance(v, list) and _contains_as_value(v, target):
            return True
    return False


def merge_label_entries(
    original_entries: List[LabelEntry],
    new_and_modified_entries: List[LabelEntry],
    deleted_ids: Optional[List[str]] = None,
) -> List[LabelEntry]:
    # keep a copy to prevent mutating the argument
    original_entries = original_entries[:]
    new_and_modified_entries = new_and_modified_entries[:]

    # keep list indexes by label entry IDs
    new_and_modified_id_idx = {
        le.ID: idx for idx, le in enumerate(new_and_modified_entries)
    }

    # step 1: take potentially mutated entries and overwrite the original entries
    for original_idx, _ in enumerate(original_entries):
        original_id = original_entries[original_idx].ID
        if original_id in new_and_modified_id_idx:
            # overwrite the old entry with the new data
            new_idx = new_and_modified_id_idx[original_id]
            original_entries[original_idx] = new_and_modified_entries[new_idx]
            # mark this index as not new for later skips
            new_and_modified_entries[new_idx] = None  # type: ignore[call-overload]

    # step 2: there may be entries that are None, which should be deleted (unexpected, but possible)
    original_entries = [entry for entry in original_entries if entry]

    # step 3: everything left behind is a new entry, add it to the list
    new_entries = [entry for entry in new_and_modified_entries if entry]

    # step 4: remove all ids which are explicitly deleted
    if deleted_ids:
        original_entries = [
            entry for entry in original_entries if entry.ID not in deleted_ids
        ]

    # add the new elements to the final result
    return original_entries + new_entries
