from dataclasses import dataclass, field, InitVar
from typing import Optional

from yardstick import comparison
from yardstick.validate.delta import Delta


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


@dataclass
class Gate:
    reference_comparison: InitVar[Optional[comparison.LabelComparisonSummary]]
    candidate_comparison: InitVar[Optional[comparison.LabelComparisonSummary]]

    config: GateConfig

    input_description: GateInputDescription
    reasons: list[str] = field(default_factory=list)
    deltas: list[Delta] = field(default_factory=list)

    def __post_init__(
        self,
        reference_comparison: Optional[comparison.LabelComparisonSummary],
        candidate_comparison: Optional[comparison.LabelComparisonSummary],
    ):
        if not reference_comparison or not candidate_comparison:
            return

        reasons = []

        reference_f1_score = reference_comparison.f1_score
        current_f1_score = candidate_comparison.f1_score
        if current_f1_score < reference_f1_score - self.config.max_f1_regression:
            reasons.append(
                f"current F1 score is lower than the latest release F1 score: candidate_score={current_f1_score:0.2f} reference_score={reference_f1_score:0.2f} image={self.input_description.image}"
            )

        if (
            candidate_comparison.indeterminate_percent
            > self.config.max_unlabeled_percent
        ):
            reasons.append(
                f"current indeterminate matches % is greater than {self.config.max_unlabeled_percent}%: candidate={candidate_comparison.indeterminate_percent:0.2f}% image={self.input_description.image}"
            )

        reference_fns = reference_comparison.false_negatives
        candidate_fns = candidate_comparison.false_negatives
        if candidate_fns > reference_fns + self.config.max_new_false_negatives:
            reasons.append(
                f"current false negatives is greater than the latest release false negatives: candidate={candidate_fns} reference={reference_fns} image={self.input_description.image}"
            )

        self.reasons = reasons

    def passed(self) -> bool:
        return len(self.reasons) == 0

    @classmethod
    def failing(cls, reasons: list[str], input_description: GateInputDescription):
        """failing bypasses Gate's normal validation calculating and returns a
        gate that is failing for the reasons given."""
        return cls(
            reference_comparison=None,
            candidate_comparison=None,
            config=GateConfig(),
            reasons=reasons,
            input_description=input_description,
        )

    @classmethod
    def passing(cls, input_description: GateInputDescription):
        """passing bypasses a Gate's normal validation and returns a gate that is passing."""
        return cls(
            reference_comparison=None,
            candidate_comparison=None,
            config=GateConfig(),
            reasons=[],  # a gate with no reason to fail is considered passing
            input_description=input_description,
        )
