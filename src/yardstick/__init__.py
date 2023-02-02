import logging
from typing import Optional

from . import arrange, artifact, capture, cli, comparison, label, store, tool, utils


def compare_results(
    descriptions: list[str],
    year_max_limit: Optional[int] = None,
) -> comparison.ByPreservedMatch:
    results = store.scan_result.load_by_descriptions(
        descriptions=descriptions, year_max_limit=year_max_limit, skip_sbom_results=True
    )

    digests = set(r.config.image_digest for r in results)
    if len(digests) != 1:
        raise RuntimeError(f"image digests being compared do not match: {digests}")

    return comparison.ByPreservedMatch(results=results)


def compare_results_against_labels(
    descriptions: list[str],
    result_set: Optional[str] = None,
    fuzzy: bool = False,
    year_max_limit: Optional[int] = None,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
) -> tuple[
    list[artifact.ScanResult],
    list[artifact.LabelEntry],
    dict[str, list[comparison.AgainstLabels]],
    comparison.ImageToolLabelStats,
]:
    descriptions = list(descriptions)

    if result_set:
        descriptions.extend(store.result_set.load(result_set).descriptions)

    if not descriptions:
        raise RuntimeError("no descriptions provided")

    logging.info(f"running label comparison with {descriptions}")

    results = store.scan_result.load_by_descriptions(descriptions, skip_sbom_results=True, year_max_limit=year_max_limit)

    if not label_entries:
        label_entries = store.labels.load_all(year_max_limit=year_max_limit)

    comparisons_by_result_id, stats_by_image_tool_pair = comparison.of_results_against_label(
        *results,
        fuzzy_package_match=fuzzy,
        label_entries=label_entries,
    )

    return results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair


def compare_results_against_labels_by_ecosystem(
    result_set: str,
    fuzzy: bool = False,
    year_max_limit: Optional[int] = None,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
) -> tuple[dict[str, list[artifact.ScanResult]], list[artifact.LabelEntry], comparison.ToolLabelStatsByEcosystem]:
    results = store.result_set.load_scan_results(result_set, year_max_limit=year_max_limit, skip_sbom_results=True)
    results_by_image = arrange.scan_results_by_image(results)

    if not label_entries:
        label_entries = store.labels.load_all(year_max_limit=year_max_limit)

    stats = comparison.of_results_against_label_by_ecosystem(
        results_by_image,
        fuzzy_package_match=fuzzy,
        label_entries=label_entries,
    )
    return results_by_image, label_entries, stats
