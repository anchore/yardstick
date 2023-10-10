from __future__ import annotations

import copy
import glob
import itertools
import json
import logging
import os
import shutil
from collections import defaultdict

from yardstick import artifact
from yardstick.store import config as store_config
from yardstick.store import naming, tool
from yardstick.tool import sbom_generator, tools, vulnerability_scanner


def _store_root(store_root: str | None = None):
    if not store_root:
        store_root = store_config.get().store_root

    return tool.results_path(store_root=store_root)


def clear(store_root: str | None = None):
    shutil.rmtree(_store_root(store_root=store_root), ignore_errors=True)


def store_paths(
    config: artifact.ScanConfiguration,
    suffix: str = naming.SUFFIX,
    store_root: str | None = None,
) -> tuple[str, str]:
    # repo@digest/tool@version/timestamp/data.json
    # repo@digest/tool@version/timestamp/metadata.json

    parent_dir = _store_root(store_root=store_root)
    result_dir = os.path.join(
        parent_dir,
        f"{config.image_encoded}",
        f"{config.tool_name.replace('/', '_')}@{config.tool_version.replace('/', '_')}",
        config.timestamp_rfc3339,
    )

    return os.path.join(result_dir, "data" + suffix), os.path.join(
        result_dir,
        "metadata" + suffix,
    )


# note: we intentionally split up the data and metadata such that matches are recomputed with the latest code changes
def save(raw: str, results: artifact.ScanResult, store_root: str | None = None):
    if not isinstance(results, artifact.ScanResult):
        raise RuntimeError(f"only ScanResult is supported, given {type(results)}")

    data_path, metadata_path = store_paths(results.config, store_root=store_root)
    logging.debug(f"storing result config={results.config!r} location={data_path!r}")

    os.makedirs(os.path.dirname(data_path), exist_ok=True)
    os.makedirs(os.path.dirname(metadata_path), exist_ok=True)

    with open(data_path, "w", encoding="utf-8") as data_file:
        data_file.write(raw)

    results_dict = results.to_dict()  # type: ignore[attr-defined]
    if "matches" in results_dict:
        del results_dict["matches"]
    if "packages" in results_dict:
        del results_dict["packages"]

    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
        metadata_file.write(json.dumps(results_dict, cls=artifact.DTEncoder))


def find(
    by_image: str = "",
    by_tool: str = "",
    by_time: str = "",
    by_description: str = "",
    store_root: str | None = None,
) -> list[artifact.ScanConfiguration]:
    json_path = tool.results_path(store_root=store_root)

    image_spec = "*"
    tool_spec = "*"
    time_spec = "*"

    if by_image:
        img = artifact.Image(by_image)
        if not img.digest:
            raise RuntimeError(f"image {by_image} requires a digest to search by image")
        image_spec = f"{img.repository_encoded}@{img.digest}"

    if by_tool:
        tool_spec = by_tool if "@" in by_tool else f"{by_tool}@*"

    if by_time and by_time != "latest":
        time_spec = by_time

    is_id = "/" not in by_description and by_description

    if by_description and by_description.count("/") >= 2:
        tool_name_side, tool_version_side = by_description.rsplit("@", 1)
        tool_name_side_fields = tool_name_side.rsplit("/", 1)
        tool_name = tool_name_side_fields[-1]
        repos = tool_name_side_fields[0]
        image_spec = repos.replace("/", "+")
        tool_version_side_fields = tool_version_side.rsplit("/", 1)
        tool_version = tool_version_side_fields[0]
        tool_spec = f"{tool_name}@{tool_version}"
        time_spec = tool_version_side_fields[-1]

        # to account for lables with [], which should be escaped
        tool_spec = glob.escape(tool_spec)

    search_tuple = f"{image_spec}/{tool_spec.replace('/', '_')}/{time_spec}"

    results = defaultdict(list)

    glob_str = f"{json_path}/{search_tuple}/metadata.json"

    logging.debug(f"searching for {glob_str}")

    for metadata_file in glob.glob(glob_str):
        image_tool_dir = os.path.dirname(os.path.dirname(metadata_file))
        with open(metadata_file, encoding="utf-8") as fd:
            metadata_dict = json.load(fd)
            cfg = artifact.ScanConfiguration.from_dict(  # type: ignore[attr-defined]
                metadata_dict["config"],
            )

            if is_id and by_description != cfg.ID:
                continue

            results[image_tool_dir].append(cfg)

    for image_tool_dir, configs in results.items():
        results[image_tool_dir] = sorted(
            configs,
            key=lambda c: c.timestamp,
            reverse=True,
        )
        if by_time == "latest":
            results[image_tool_dir] = [results[image_tool_dir][0]]

    return list(itertools.chain(*[result for result in results.values() if result]))


def find_one(*args, **kwargs) -> artifact.ScanConfiguration:
    configs = find(*args, **kwargs)

    if not configs:
        raise RuntimeError(f"no results found for {kwargs}")

    if len(configs) > 1:
        raise RuntimeError(f"multiple results found for {kwargs}")

    return configs[0]


def load_by_descriptions(
    descriptions: list[str],
    year_max_limit: int | None = None,
    year_from_cve_only: bool = False,
    skip_sbom_results: bool = False,
    store_root: str | None = None,
) -> list[artifact.ScanResult]:
    results = []
    for description in descriptions:
        config = find_one(by_description=description, store_root=store_root)
        result = load(
            config=config,
            year_max_limit=year_max_limit,
            year_from_cve_only=year_from_cve_only,
            store_root=store_root,
        )
        if skip_sbom_results and result.packages is not None:
            # note: we look at a NONE value, not just an empty list
            logging.debug(f"skipping SBOM result from {description}")
            continue
        results.append(result)
    return results


def load_all(
    configs: list[artifact.ScanConfiguration],
    year_max_limit: int | None = None,
    year_from_cve_only: bool = False,
    store_root: str | None = None,
) -> list[artifact.ScanResult]:
    return [
        load(
            config,
            year_max_limit=year_max_limit,
            year_from_cve_only=year_from_cve_only,
            store_root=store_root,
        )
        for config in configs
    ]


# note: we read the raw data and metadata and recompute the matches
def load(
    config: artifact.ScanConfiguration,
    year_max_limit: int | None = None,
    year_from_cve_only: bool = False,
    store_root: str | None = None,
) -> artifact.ScanResult:
    data_path, metadata_path = store_paths(config, store_root=store_root)
    logging.debug(f"loading result config={config!r} location={data_path!r}")

    with open(data_path, encoding="utf-8") as data_file:
        data_json = data_file.read()

    with open(metadata_path, encoding="utf-8") as metadata_file:
        metadata_dict = json.load(metadata_file)

    tool_name_and_label = metadata_dict["config"]["tool_name"]
    tool_name = tool_name_and_label.split("[")[0]
    selected_tool = tools[tool_name]

    result = selected_tool.parse(data_json, config=config)

    keys = {}
    if issubclass(selected_tool, vulnerability_scanner.VulnerabilityScanner):
        keys["matches"] = result
    elif issubclass(selected_tool, sbom_generator.SBOMGenerator):
        keys["packages"] = result
    else:
        raise RuntimeError("unknown tool type")

    results = {**metadata_dict, **keys}

    result_obj: artifact.ScanResult = artifact.ScanResult.from_dict(results)  # type: ignore[attr-defined]

    # TODO: allow for searching for more results until there is a matching digest
    if config.image_digest and result_obj.config.image_digest != config.image_digest:
        raise RuntimeError(
            f"scan config has a specific image digest={config.image_digest} that differs from the fetched digest={result_obj.config.image_digest}",
        )

    if year_max_limit:
        results_list = filter_by_year(
            [result_obj],
            year_max_limit=int(year_max_limit),
            year_from_cve_only=year_from_cve_only,
        )
        result_obj = results_list[0]

    return result_obj


def list_all_metadata_json(store_root: str | None = None):
    json_path = tool.results_path(store_root=store_root)
    return glob.glob(f"{json_path}/*/*/*/metadata.json")


def list_all_configs(store_root: str | None = None) -> list[artifact.ScanConfiguration]:
    results = []
    for metadata_file in list_all_metadata_json(store_root=store_root):
        with open(metadata_file, encoding="utf-8") as metadata_file:
            metadata_dict = json.load(metadata_file)
            results.append(
                artifact.ScanConfiguration.from_dict(metadata_dict["config"]),  # type: ignore[attr-defined]
            )
    return sorted(results)


# filter_by_year filters out CVE vuln IDs above a given year. We attempt to normalize all vuln IDs to CVEs,
# but will include any if normalization fails.
def filter_by_year(
    results: list[artifact.ScanResult],
    year_max_limit: int,
    year_from_cve_only: bool = False,
) -> list[artifact.ScanResult]:
    results_copy = copy.deepcopy(results)

    for i, r in enumerate(results):
        results_copy[i].matches = []

        if not r.matches:
            continue

        for m in r.matches:
            year = m.vulnerability.effective_year(by_cve=year_from_cve_only)

            if not year or year <= year_max_limit:
                results_copy[i].matches.append(m)  # type: ignore[union-attr]

    return results_copy
