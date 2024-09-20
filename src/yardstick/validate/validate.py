import logging
import sys
from typing import Sequence, Optional, Callable

import yardstick
from yardstick import artifact, store, utils
from yardstick.cli import display
from yardstick.validate.delta import compute_deltas
from yardstick.validate.gate import (
    GateInputDescription,
    GateInputResultConfig,
    GateConfig,
    Gate,
)


def guess_tool_orientation(tools: list[str]):
    """
    Given a pair of tools, guess which is latest version, and which is the one
    being compared to the latest version. This should only be used as a fallback.
    Instead, specify reference tool label and candidate tool label in validations.
    Returns (latest_tool, current_tool)
    """
    if len(tools) != 2:
        raise RuntimeError("expected 2 tools, got %s" % tools)
    tool_a, tool_b = sorted(tools)
    if tool_a == tool_b:
        raise ValueError("latest release tool and current tool are the same")
    if tool_a.endswith("latest"):
        return tool_a, tool_b
    elif tool_b.endswith("latest"):
        return tool_b, tool_a

    if "@path:" in tool_a and "@path:" not in tool_b:
        # tool_a is a local build, so compare it against tool_b
        return tool_b, tool_a

    if "@path:" in tool_b and "@path:" not in tool_a:
        # tool_b is a local build, so compare it against tool_a
        return tool_a, tool_b

    return tool_a, tool_b


class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"


if not sys.stdout.isatty():
    bcolors.HEADER = ""
    bcolors.OKBLUE = ""
    bcolors.OKCYAN = ""
    bcolors.OKGREEN = ""
    bcolors.WARNING = ""
    bcolors.FAIL = ""
    bcolors.BOLD = ""
    bcolors.UNDERLINE = ""
    bcolors.RESET = ""


def results_used(
    image: str, results: Sequence[artifact.ScanResult]
) -> GateInputDescription:
    return GateInputDescription(
        image=image,
        configs=[
            GateInputResultConfig(
                id=result.ID,
                tool=result.config.tool,
                tool_label=result.config.tool_label,
            )
            for result in results
        ],
    )


def validate_result_set(
    gate_config: GateConfig,
    result_set: str,
    images: list[str],
    always_run_label_comparison: bool,
    verbosity: int,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
) -> list[Gate]:
    result_set_obj = store.result_set.load(name=result_set)

    if gate_config.allowed_namespaces:
        m_filter = namespace_filter(gate_config.allowed_namespaces)
        logging.info(
            f"only considering matches from allowed namespaces: {' '.join(gate_config.allowed_namespaces)}"
        )
    else:
        m_filter = None

    ret = []
    for image, result_states in result_set_obj.result_state_by_image.items():
        if images and image not in images:
            logging.info(
                f"Skipping image {image!r} because --images is passed but does not include it"
            )
            continue
        tools = ", ".join([s.request.tool for s in result_states])
        logging.info(f"Testing image: {image!r} with {tools!r}")

        gate = validate_image(
            image=image,
            gate_config=gate_config,
            descriptions=[s.config.path for s in result_states if s.config is not None],
            always_run_label_comparison=always_run_label_comparison,
            verbosity=verbosity,
            label_entries=label_entries,
            match_filter=m_filter,
        )
        ret.append(gate)

    return ret


def namespace_filter(
    namespaces: list[str],
) -> Callable[[list[artifact.Match]], list[artifact.Match]]:
    include = set(namespaces)

    def match_filter(matches: list[artifact.Match]) -> list[artifact.Match]:
        result = []
        for match in matches:
            if utils.dig(match.fullentry, "vulnerability", "namespace") in include:
                result.append(match)
        return result

    return match_filter


def validate_image(
    image: str,
    gate_config: GateConfig,
    descriptions: list[str],
    always_run_label_comparison: bool,
    verbosity: int,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
    match_filter: Callable[[list[artifact.Match]], list[artifact.Match]] | None = None,
) -> Gate:
    """
    Compare the results of two different vulnerability scanner configurations with each other,
    and if necessary with label information. Returns a pass-fail Gate based on
    the comparison, which fails if the candidate tool results are worse than the reference
    tool results, as specified by the `gate_config`.

    Parameters
    ----------
    image : str
        The identifier or name of the image being analyzed.
    gate_config : GateConfig
        The configuration object that specifies comparison thresholds, tool labels,
        and allowed/required namespaces.
    descriptions : list[str]
        A list of descriptions or metadata associated with the image results for the comparison.
    always_run_label_comparison : bool
        If True, run comparison against labels even if no differences are found between the
        two tools.
    verbosity : int
        Level of verbosity for displaying comparison details. A higher value means more detailed output.
    label_entries : Optional[list[artifact.LabelEntry]], optional
        To save time, pass label entries. If present, will be used instead of loading from disk.
    match_filter : Callable[[list[artifact.Match]], list[artifact.Match]] | None, optional
        An optional filter function to refine the set of matches used in the comparison, by default None.
        Useful for filtering by namespace, for example.

    Returns
    -------
    Gate
        A `Gate` object that represents the pass/fail status based on the comparison. If the candidate
        tool results are worse than the reference tool according to the `gate_config`, the gate will fail.
        Otherwise, the gate will pass.

    Raises
    ------
    RuntimeError
        If an unexpected number of results (other than 2) are found during the label comparison.
    """
    # Load the relative comparison between the reference and candidate tool runs, without label info.
    # This optimizes performance by allowing early exit if there are no matches or identical results.
    relative_comparison = yardstick.compare_results(
        descriptions=descriptions,
        year_max_limit=gate_config.max_year,
        matches_filter=match_filter,
    )

    # show the relative comparison results
    if verbosity > 0:
        details = verbosity > 1
        display.preserved_matches(
            relative_comparison, details=details, summary=True, common=False
        )

    if gate_config.fail_on_empty_match_set:
        if not sum(
            len(res.matches) if res.matches else 0
            for res in relative_comparison.results
        ):
            return Gate.failing(
                reasons=[
                    "gate configured to fail on empty matches, and no matches found",
                ],
                input_description=results_used(image, relative_comparison.results),
            )

    if not always_run_label_comparison and not sum(
        [
            len(relative_comparison.unique[result.ID])
            for result in relative_comparison.results
        ]
    ):
        return Gate.passing(
            input_description=results_used(image, relative_comparison.results),
        )

    logging.info("Running comparison against labels...")
    # Compare against labels. Because the reference tool configuration and the
    # candidate tool configuration both found matches, and did not find the same
    # set of matches, we need to compare to known-correct label data and do
    # a little stats to determine whether candidate tool is better or the same
    # as reference tool.
    results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = (
        yardstick.compare_results_against_labels(
            descriptions=descriptions,
            year_max_limit=gate_config.max_year,
            label_entries=label_entries,
            matches_filter=match_filter,
        )
    )

    if verbosity > 0:
        show_fns = verbosity > 1
        display.label_comparison(
            results,
            comparisons_by_result_id,
            stats_by_image_tool_pair,
            show_fns=show_fns,
            show_summaries=True,
        )

    if len(results) != 2:
        raise RuntimeError(
            f"validate_image compares results of exactly 2 runs, but found {len(results)}"
        )

    candidate_tool, reference_tool = tool_designations(
        gate_config.candidate_tool_label, [r.config for r in results]
    )

    # keep a list of differences between tools to summarize in UI
    # not that this is different from the statistical comparison;
    # deltas basically a UI/logging concern; the stats are a pass/fail concern.
    deltas = compute_deltas(
        comparisons_by_result_id, reference_tool, relative_comparison
    )

    reference_comparisons_by_images = {
        comp.config.image: comp
        for comp in comparisons_by_result_id.values()
        if comp.config.tool == reference_tool
    }
    reference_comparison = reference_comparisons_by_images[image]
    candidate_comparisons_by_images = {
        comp.config.image: comp
        for comp in comparisons_by_result_id.values()
        if comp.config.tool == candidate_tool
    }
    candidate_comparison = candidate_comparisons_by_images[image]
    return Gate(
        reference_comparison=reference_comparison.summary,
        candidate_comparison=candidate_comparison.summary,
        config=gate_config,
        input_description=results_used(image, relative_comparison.results),
        deltas=deltas,
    )


def tool_designations(
    candidate_tool_label: str, scan_configs: list[artifact.ScanConfiguration]
) -> tuple[str, str]:
    reference_tool, candidate_tool = None, None
    if not candidate_tool_label:
        reference_tool, candidate_tool = guess_tool_orientation(
            [config.tool for config in scan_configs],
        )
        logging.warning(
            f"guessed tool orientation reference:{reference_tool} candidate:{candidate_tool}"
        )
        logging.warning(
            "to avoid guessing, specify reference_tool_label and candidate_tool_label in validation config and re-capture result set"
        )
    if scan_configs[0].tool_label == candidate_tool_label:
        candidate_tool = scan_configs[0].tool
        reference_tool = scan_configs[1].tool
    elif scan_configs[1].tool_label == candidate_tool_label:
        candidate_tool = scan_configs[1].tool
        reference_tool = scan_configs[0].tool
    return candidate_tool, reference_tool
