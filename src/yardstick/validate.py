import sys
from typing import Optional, Sequence

from dataclasses import dataclass, InitVar, field

import yardstick
from yardstick import store, comparison, artifact
from yardstick.cli import display


# see the .yardstick.yaml configuration for details
# TODO: remove this; package specific
default_result_set = "pr_vs_latest_via_sbom"
yardstick.utils.grype_db.raise_on_failure(False)


@dataclass
class GateConfig:
    max_f1_regression: float = 0.0
    max_new_false_negatives: int = 0
    max_unlabeled_percent: int = 0
    max_year: int | None = None


@dataclass
class GateInputDescription:
    result_id: str
    tool: str
    tool_label: str
    image: str


@dataclass
class Delta:
    tool: str
    package_name: str
    package_version: str
    vulnerability_id: str
    added: bool
    label: str | None = None

    @property
    def is_improved(self) -> bool | None:
        if not self.label:
            return None

        if not self.added:
            # the tool which found the unique result is the latest release tool...
            if self.label == artifact.Label.TruePositive.name:
                # drats! we missed a case (this is a new FN)
                return False
            elif artifact.Label.FalsePositive.name in self.label:
                # we got rid of a FP! ["hip!", "hip!"]
                return True
        else:
            # the tool which found the unique result is the current tool...
            if self.label == artifact.Label.TruePositive.name:
                # highest of fives! we found a new TP that the previous tool release missed!
                return True
            elif artifact.Label.FalsePositive.name in self.label:
                # welp, our changes resulted in a new FP... not great, maybe not terrible?
                return False

        return None

    @property
    def commentary(self) -> str:
        commentary = ""
        if self.is_improved and self.label == artifact.Label.TruePositive.name:
            commentary = "(this is a new TP 🙌)"
        elif self.is_improved and self.label == artifact.Label.FalsePositive.name:
            commentary = "(got rid of a former FP 🙌)"
        elif not self.is_improved and self.label == artifact.Label.FalsePositive.name:
            commentary = "(this is a new FP 😱)"
        elif not self.is_improved and self.label == artifact.Label.TruePositive.name:
            commentary = "(this is a new FN 😱)"

        return commentary


@dataclass
class Gate:
    label_comparisons: InitVar[Optional[list[comparison.AgainstLabels]]]
    label_comparison_stats: InitVar[Optional[comparison.ImageToolLabelStats]]

    config: GateConfig

    result_descriptions: list[GateInputDescription] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    deltas: list[Delta] = field(default_factory=list)

    reference_tool_string: str | None = None
    candidate_tool_string: str | None = None

    def __post_init__(
        self,
        label_comparisons: Optional[list[comparison.AgainstLabels]],
        label_comparison_stats: Optional[comparison.ImageToolLabelStats],
    ):
        if not label_comparisons and not label_comparison_stats:
            return

        reasons = []

        # - fail when current F1 score drops below last release F1 score (or F1 score is indeterminate)
        # - fail when indeterminate % > 10%
        # - fail when there is a rise in FNs
        if self.reference_tool_string is None or self.candidate_tool_string is None:
            latest_release_tool, current_tool = guess_tool_orientation(
                label_comparison_stats.tools
            )
        elif self.candidate_tool_string == label_comparison_stats.tools[1]:
            latest_release_tool, current_tool = (
                label_comparison_stats.tools[0],
                label_comparison_stats.tools[1],
            )
        elif self.candidate_tool_string == label_comparison_stats.tools[0]:
            latest_release_tool, current_tool = (
                label_comparison_stats.tools[1],
                label_comparison_stats.tools[0],
            )
        else:
            raise ValueError(
                f"reference tool specified, but not found: {self.reference_tool_string} is not one of {' '.join(label_comparison_stats.tools)}"
            )

        latest_release_comparisons_by_image = {
            comp.config.image: comp
            for comp in label_comparisons
            if comp.config.tool == latest_release_tool
        }
        current_comparisons_by_image = {
            comp.config.image: comp
            for comp in label_comparisons
            if comp.config.tool == current_tool
        }

        for image, comp in current_comparisons_by_image.items():
            latest_f1_score = latest_release_comparisons_by_image[
                image
            ].summary.f1_score
            current_f1_score = comp.summary.f1_score
            if current_f1_score < latest_f1_score - self.config.max_f1_regression:
                reasons.append(
                    f"current F1 score is lower than the latest release F1 score: {bcolors.BOLD+bcolors.UNDERLINE}current={current_f1_score:0.2f} latest={latest_f1_score:0.2f}{bcolors.RESET} image={image}"
                )

            if comp.summary.indeterminate_percent > self.config.max_unlabeled_percent:
                reasons.append(
                    f"current indeterminate matches % is greater than {self.config.max_unlabeled_percent}%: {bcolors.BOLD+bcolors.UNDERLINE}current={comp.summary.indeterminate_percent:0.2f}%{bcolors.RESET} image={image}"
                )

            latest_fns = latest_release_comparisons_by_image[
                image
            ].summary.false_negatives
            current_fns = comp.summary.false_negatives
            if current_fns > latest_fns + self.config.max_new_false_negatives:
                reasons.append(
                    f"current false negatives is greater than the latest release false negatives: {bcolors.BOLD+bcolors.UNDERLINE}current={current_fns} latest={latest_fns}{bcolors.RESET} image={image}"
                )

        self.reasons = reasons

    def passed(self):
        return len(self.reasons) == 0


def guess_tool_orientation(tools: list[str]):
    """
    Given a pair of tools, guess which is latest version, and which is the one
    being compared to the latest version.
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


def show_results_used(results: list[artifact.ScanResult]):
    print("   Results used:")
    for idx, result in enumerate(results):
        branch = "├──"
        if idx == len(results) - 1:
            branch = "└──"
        print(
            f"    {branch} {result.ID} : {result.config.tool} against {result.config.image}"
        )
    print()


def results_used(results: Sequence[artifact.ScanResult]) -> list[GateInputDescription]:
    return [
        GateInputDescription(
            result_id=result.ID,
            tool=result.config.tool,
            tool_label=result.config.tool_label,
            image=result.config.image,
        )
        for result in results
    ]


def validate_result_set(
    # cfg: config.Application, # TODO: bad!
    gate_config: GateConfig,
    result_set: str,
    images: list[str],
    always_run_label_comparison: bool,
    verbosity: int,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
) -> list[Gate]:
    print(
        f"{bcolors.HEADER}{bcolors.BOLD}Validating with {result_set!r}", bcolors.RESET
    )
    result_set_obj = store.result_set.load(name=result_set)

    ret = []
    for image, result_states in result_set_obj.result_state_by_image.items():
        if images and image not in images:
            # print("Skipping image:", image)
            continue
        # print()
        # print("Testing image:", image)
        # for state in result_states:
        #     print("   ", f"with {state.request.tool}")
        # print()

        gate = validate_image(
            gate_config=gate_config,
            descriptions=[s.config.path for s in result_states],
            always_run_label_comparison=always_run_label_comparison,
            verbosity=verbosity,
            label_entries=label_entries,
        )
        ret.append(gate)

        # failure = not gate.passed()
        # if failure:
        #     print(f"{bcolors.FAIL}{bcolors.BOLD}Failed quality gate{bcolors.RESET}")
        # for reason in gate.reasons:
        #     print(f"   - {reason}")

        # print()
        # size = 120
        # print("▁" * size)
        # print("░" * size)
        # print("▔" * size)
    return ret


def validate_image(
    # result_set_obj: artifact.ResultSet,
    gate_config: GateConfig,
    descriptions: list[str],
    always_run_label_comparison: bool,
    verbosity: int,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
    reference_tool_label: str = "reference",
    candidate_tool_label: str = "candidate",
):
    # do a relative comparison
    # - show comparison summary (no gating action)
    # - list out all individual match differences
    # result_set_config = cfg.result_sets[result_set]
    # validation = result_set_config.validations[
    #     0
    # ]  # TODO: support N, don't hard code index
    # reference_tool, candidate_tool = result_set_config.tool_comparisons()

    # print(f"{bcolors.HEADER}Running relative comparison...", bcolors.RESET)
    relative_comparison = yardstick.compare_results(
        descriptions=descriptions, year_max_limit=gate_config.max_year
    )
    # show_results_used(relative_comparison.results)

    # show the relative comparison results
    if verbosity > 0:
        details = verbosity > 1
        display.preserved_matches(
            relative_comparison, details=details, summary=True, common=False
        )
        # print()

    # bail if there are no differences found
    if not always_run_label_comparison and not sum(
        [
            len(relative_comparison.unique[result.ID])
            for result in relative_comparison.results
        ]
    ):
        return Gate(
            None,
            None,
            config=gate_config,
            result_descriptions=list(results_used(relative_comparison.results)),
        )

    # do a label comparison
    # print(f"{bcolors.HEADER}Running comparison against labels...", bcolors.RESET)
    results, label_entries, comparisons_by_result_id, stats_by_image_tool_pair = (
        yardstick.compare_results_against_labels(
            descriptions=descriptions,
            year_max_limit=gate_config.max_year,
            label_entries=label_entries,
        )
    )
    # show_results_used(results)

    if verbosity > 0:
        show_fns = verbosity > 1
        display.label_comparison(
            results,
            comparisons_by_result_id,
            stats_by_image_tool_pair,
            show_fns=show_fns,
            show_summaries=True,
        )

    # TODO: should be specified in config
    reference_tool, candidate_tool = None, None
    for r in results:
        if r.config.tool_label == reference_tool_label:
            reference_tool = r.config.tool
        if r.config.tool_label == candidate_tool_label:
            candidate_tool = r.config.tool

    if reference_tool is None or candidate_tool is None:
        # TODO: log.warn that results should be re-captured with labels
        reference_tool, candidate_tool = guess_tool_orientation(
            [r.config.tool for r in results]
        )

    # keep a list of differences between tools to summarize
    deltas = []

    for result in relative_comparison.results:
        label_comparison = comparisons_by_result_id[result.ID]
        for unique_match in relative_comparison.unique[result.ID]:
            labels = label_comparison.labels_by_match[unique_match.ID]
            if not labels:
                label = "(unknown)"
            elif len(set(labels)) > 1:
                label = ", ".join([la.name for la in labels])
            else:
                label = labels[0].name

            delta = Delta(
                tool=result.config.tool,
                package_name=unique_match.package.name,
                package_version=unique_match.package.version,
                vulnerability_id=unique_match.vulnerability.id,
                added=result.config.tool != reference_tool,
                # added=result.config.tool_label == candidate_tool_label,
                label=label,
            )
            deltas.append(delta)

    # populate the quality gate with data that can evaluate pass/fail conditions
    return Gate(
        label_comparisons=list(comparisons_by_result_id.values()),
        label_comparison_stats=stats_by_image_tool_pair,
        config=gate_config,
        result_descriptions=list(results_used(results)),
        deltas=deltas,
        reference_tool_string=reference_tool,
        candidate_tool_string=candidate_tool,
    )
