import enum
import logging
import sys
from typing import Optional, Sequence, Callable

from dataclasses import dataclass, InitVar, field

import yardstick
from yardstick import store, comparison, artifact, utils
from yardstick.cli import display


@dataclass
class GateConfig:
    max_f1_regression: float = 0.0
    max_new_false_negatives: int = 0
    max_unlabeled_percent: int = 0
    max_year: int | None = None
    reference_tool_label: str = "reference"
    candidate_tool_label: str = "candidate"
    # only consider matches from these namespaces when judging results
    allowed_namespaces: list[str] = field(default_factory=list)
    # fail this gate unless all of these namespaces are present
    required_namespaces: list[str] = field(default_factory=list)
    fail_on_empty_match_set: bool = True


@dataclass
class GateInputResultConfig:
    id: str
    tool: str
    tool_label: str


@dataclass
class GateInputDescription:
    image: str
    configs: list[GateInputResultConfig] = field(default_factory=list)


class DeltaType(enum.Enum):
    Unknown = "Unknown"
    FixedFalseNegative = "FixedFalseNegative"
    FixedFalsePositive = "FixedFalsePositive"
    NewFalseNegative = "NewFalseNegative"
    NewFalsePositive = "NewFalsePositive"


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
        if self.outcome in {DeltaType.FixedFalseNegative, DeltaType.FixedFalsePositive}:
            return True
        if self.outcome in {DeltaType.NewFalseNegative, DeltaType.NewFalsePositive}:
            return False
        return None

    @property
    def commentary(self) -> str:
        commentary = ""
        # if self.is_improved and self.label == artifact.Label.TruePositive.name:
        if self.outcome == DeltaType.FixedFalseNegative:
            commentary = "(this is a new TP 🙌)"
        elif self.outcome == DeltaType.FixedFalsePositive:
            commentary = "(got rid of a former FP 🙌)"
        elif self.outcome == DeltaType.NewFalsePositive:
            commentary = "(this is a new FP 😱)"
        elif self.outcome == DeltaType.NewFalseNegative:
            commentary = "(this is a new FN 😱)"

        return commentary

    @property
    def outcome(self) -> DeltaType:
        # TODO: this would be better handled post init and set I think
        if not self.label:
            return DeltaType.Unknown

        if not self.added:
            # the tool which found the unique result is the reference tool...
            if self.label == artifact.Label.TruePositive.name:
                # drats! we missed a case (this is a new FN)
                return DeltaType.NewFalseNegative
            elif artifact.Label.FalsePositive.name in self.label:
                # we got rid of a FP! ["hip!", "hip!"]
                return DeltaType.FixedFalsePositive
        else:
            # the tool which found the unique result is the current tool...
            if self.label == artifact.Label.TruePositive.name:
                # highest of fives! we found a new TP that the previous tool release missed!
                return DeltaType.FixedFalseNegative
            elif artifact.Label.FalsePositive.name in self.label:
                # welp, our changes resulted in a new FP... not great, maybe not terrible?
                return DeltaType.NewFalsePositive

        return DeltaType.Unknown


@dataclass
class Gate:
    label_comparisons: InitVar[Optional[list[comparison.AgainstLabels]]]
    # label_comparison_stats: InitVar[Optional[comparison.ImageToolLabelStats]]

    config: GateConfig

    reference_tool_string: str
    candidate_tool_string: str
    input_description: GateInputDescription
    reasons: list[str] = field(default_factory=list)
    deltas: list[Delta] = field(default_factory=list)

    def __post_init__(
        self,
        label_comparisons: Optional[list[comparison.AgainstLabels]],
    ):
        if not label_comparisons:
            return

        reasons = []

        # - fail when current F1 score drops below last release F1 score (or F1 score is indeterminate)
        # - fail when indeterminate % > 10%
        # - fail when there is a rise in FNs
        if self.reference_tool_string is None or self.candidate_tool_string is None:
            raise ValueError("must specify reference tool and candidate tool")

        reference_comparisons_by_images = {
            comp.config.image: comp
            for comp in label_comparisons
            if comp.config.tool == self.reference_tool_string
        }
        candidate_comparisons_by_images = {
            comp.config.image: comp
            for comp in label_comparisons
            if comp.config.tool == self.candidate_tool_string
        }

        for image, comp in candidate_comparisons_by_images.items():
            reference_f1_score = reference_comparisons_by_images[image].summary.f1_score
            current_f1_score = comp.summary.f1_score
            if current_f1_score < reference_f1_score - self.config.max_f1_regression:
                reasons.append(
                    f"current F1 score is lower than the latest release F1 score: {bcolors.BOLD + bcolors.UNDERLINE}candidate_score={current_f1_score:0.2f} reference_score={reference_f1_score:0.2f}{bcolors.RESET} image={image}"
                )

            if comp.summary.indeterminate_percent > self.config.max_unlabeled_percent:
                reasons.append(
                    f"current indeterminate matches % is greater than {self.config.max_unlabeled_percent}%: {bcolors.BOLD + bcolors.UNDERLINE}candidate={comp.summary.indeterminate_percent:0.2f}%{bcolors.RESET} image={image}"
                )

            latest_fns = reference_comparisons_by_images[image].summary.false_negatives
            current_fns = comp.summary.false_negatives
            if current_fns > latest_fns + self.config.max_new_false_negatives:
                reasons.append(
                    f"current false negatives is greater than the latest release false negatives: {bcolors.BOLD + bcolors.UNDERLINE}candidate={current_fns} reference={latest_fns}{bcolors.RESET} image={image}"
                )

        self.reasons = reasons

    def passed(self) -> bool:
        return len(self.reasons) == 0

    @classmethod
    def from_reasons(cls, reasons: list[str], input_description: GateInputDescription):
        return cls(
            label_comparisons=[],
            config=GateConfig(),
            reference_tool_string="",
            candidate_tool_string="",
            reasons=reasons,
            input_description=input_description,
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
    logging.info(
        f"{bcolors.HEADER}{bcolors.BOLD}Validating with {result_set!r}{bcolors.RESET}"
    )
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

    def filter(matches: list[artifact.Match]) -> list[artifact.Match]:
        result = []
        for mmatch in matches:
            if utils.dig(mmatch.fullentry, "vulnerability", "namespace") in include:
                result.append(mmatch)
        return result

    return filter


def validate_image(
    image: str,
    gate_config: GateConfig,
    descriptions: list[str],
    always_run_label_comparison: bool,
    verbosity: int,
    label_entries: Optional[list[artifact.LabelEntry]] = None,
    match_filter: Callable[[list[artifact.Match]], list[artifact.Match]] | None = None,
) -> Gate:
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
            return Gate.from_reasons(
                reasons=[
                    "gate configured to fail on empty matches, and no matches found",
                ],
                input_description=results_used(image, relative_comparison.results),
            )

    # bail if there are no differences found
    if not always_run_label_comparison and not sum(
        [
            len(relative_comparison.unique[result.ID])
            for result in relative_comparison.results
        ]
    ):
        return Gate(
            None,
            reference_tool_string="",
            candidate_tool_string="",
            config=gate_config,
            input_description=results_used(image, relative_comparison.results),
        )

    # do a label comparison
    logging.info(f"{bcolors.HEADER}Running comparison against labels...{bcolors.RESET}")
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

    reference_tool, candidate_tool = None, None
    for r in results:
        if r.config.tool_label == gate_config.reference_tool_label:
            reference_tool = r.config.tool
        if r.config.tool_label == gate_config.candidate_tool_label:
            candidate_tool = r.config.tool

    if reference_tool is None or candidate_tool is None:
        reference_tool, candidate_tool = guess_tool_orientation(
            [r.config.tool for r in results]
        )
        logging.warning(
            f"guessed tool orientation reference:{reference_tool} candidate:{candidate_tool}"
        )
        logging.warning(
            "to avoid guessing, specify reference_tool_label and candidate_tool_label in validation config and re-capture result set"
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
    # TODO: we should pass in deltas and have the gate validate things?
    # or what do we need from the summary stats? Maybe deltas and summary stats?
    return Gate(
        label_comparisons=list(comparisons_by_result_id.values()),
        # label_comparison_stats=stats_by_image_tool_pair,
        config=gate_config,
        reference_tool_string=reference_tool,
        candidate_tool_string=candidate_tool,
        input_description=results_used(image, relative_comparison.results),
        deltas=deltas,
    )
