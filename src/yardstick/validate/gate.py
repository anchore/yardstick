from dataclasses import dataclass, field, InitVar
from typing import Hashable, Iterable, Optional

from yardstick import artifact, comparison
from yardstick.validate.delta import Delta

# the maximum number of matches or label entries listed under a single failure reason
MAX_REASON_DETAILS = 25


@dataclass
class GateConfig:
    max_f1_regression: float = 0.0
    max_new_false_negatives: int = 0
    # when None, the percent of unlabeled matches is not checked
    max_unlabeled_percent: int | None = None
    # when None, new false positives are not checked
    max_new_false_positives: int | None = None
    # when None, unlabeled matches that differ between the tools are not checked
    max_unlabeled_in_delta: int | None = None
    max_year: int | None = None
    year_from_cve_only: bool | None = None
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
    result_set: str | None = None


@dataclass(frozen=True)
class UnlabeledDeltaMatch:
    match: artifact.Match
    # True when only the candidate reported the match, False when only the reference did
    added: bool

    def __str__(self) -> str:
        return f"{describe_match(self.match)} ({'added' if self.added else 'removed'})"


def describe_match(match: artifact.Match) -> str:
    return f"{match.package.name}@{match.package.version} {match.vulnerability.id}"


def describe_label_entry(entry: artifact.LabelEntry) -> str:
    package = f"{entry.package.name}@{entry.package.version}" if entry.package else "(any package)"
    return f"{package} {entry.vulnerability_id} [{entry.label.name}]"


def format_reason(summary: str, details: list[str]) -> str:
    lines = [summary]
    lines.extend(f"      {d}" for d in details[:MAX_REASON_DETAILS])
    if len(details) > MAX_REASON_DETAILS:
        lines.append(f"      ... and {len(details) - MAX_REASON_DETAILS} more")
    return "\n".join(lines)


def _label_entry_key(entry: artifact.LabelEntry) -> Hashable:
    # LabelEntry equality considers the note and source but not the label, so key on the claim itself
    return entry.image, entry.package, entry.vulnerability_id, entry.label


def _label_entry_difference(left: Iterable[artifact.LabelEntry], right: Iterable[artifact.LabelEntry]) -> list[artifact.LabelEntry]:
    right_keys = {_label_entry_key(e) for e in right}
    unique = {_label_entry_key(e): e for e in left if _label_entry_key(e) not in right_keys}
    return sorted(unique.values(), key=describe_label_entry)


def _match_difference(left: Iterable[artifact.Match], right: Iterable[artifact.Match]) -> list[artifact.Match]:
    return sorted(set(left) - set(right))


@dataclass
class Gate:
    reference_comparison: InitVar[Optional[comparison.AgainstLabels]]
    candidate_comparison: InitVar[Optional[comparison.AgainstLabels]]

    config: GateConfig

    input_description: GateInputDescription
    reasons: list[str] = field(default_factory=list)
    deltas: list[Delta] = field(default_factory=list)

    # the number of matches only the candidate reported (added) and only the reference reported (removed)
    added_in_delta: int = 0
    removed_in_delta: int = 0
    unlabeled_in_delta: list[UnlabeledDeltaMatch] = field(default_factory=list)
    # labeled regressions and improvements of the candidate relative to the reference
    new_false_negatives: list[artifact.LabelEntry] = field(default_factory=list)
    fixed_false_negatives: list[artifact.LabelEntry] = field(default_factory=list)
    new_false_positives: list[artifact.Match] = field(default_factory=list)
    fixed_false_positives: list[artifact.Match] = field(default_factory=list)

    relative_comparison: InitVar[Optional[comparison.ByPreservedMatch]] = None

    def __post_init__(
        self,
        reference_comparison: Optional[comparison.AgainstLabels],
        candidate_comparison: Optional[comparison.AgainstLabels],
        relative_comparison: Optional[comparison.ByPreservedMatch],
    ):
        if not reference_comparison or not candidate_comparison:
            return

        self._compute_label_changes(reference_comparison, candidate_comparison)
        if relative_comparison:
            self._compute_delta(reference_comparison, candidate_comparison, relative_comparison)

        reasons = []

        reference_f1_score = reference_comparison.summary.f1_score
        current_f1_score = candidate_comparison.summary.f1_score
        if current_f1_score < reference_f1_score - self.config.max_f1_regression:
            reasons.append(
                f"current F1 score is lower than the latest release F1 score: candidate_score={current_f1_score:0.2f} reference_score={reference_f1_score:0.2f} image={self.input_description.image}"
            )

        indeterminate_percent = candidate_comparison.summary.indeterminate_percent
        if self.config.max_unlabeled_percent is not None and indeterminate_percent > self.config.max_unlabeled_percent:
            reasons.append(
                f"current indeterminate matches % is greater than {self.config.max_unlabeled_percent}%: candidate={indeterminate_percent:0.2f}% image={self.input_description.image}"
            )

        if len(self.new_false_negatives) > self.config.max_new_false_negatives:
            reasons.append(
                format_reason(
                    f"{len(self.new_false_negatives)} new false negatives (max {self.config.max_new_false_negatives}, {len(self.fixed_false_negatives)} fixed): image={self.input_description.image}",
                    [describe_label_entry(e) for e in self.new_false_negatives],
                )
            )

        if self.config.max_new_false_positives is not None and len(self.new_false_positives) > self.config.max_new_false_positives:
            reasons.append(
                format_reason(
                    f"{len(self.new_false_positives)} new false positives (max {self.config.max_new_false_positives}, {len(self.fixed_false_positives)} fixed): image={self.input_description.image}",
                    [describe_match(m) for m in self.new_false_positives],
                )
            )

        if self.config.max_unlabeled_in_delta is not None and len(self.unlabeled_in_delta) > self.config.max_unlabeled_in_delta:
            reasons.append(
                format_reason(
                    f"{len(self.unlabeled_in_delta)} unlabeled matches differ between tools (max {self.config.max_unlabeled_in_delta}): image={self.input_description.image}",
                    [str(u) for u in self.unlabeled_in_delta],
                )
            )

        self.reasons = reasons

    def _compute_label_changes(
        self,
        reference_comparison: comparison.AgainstLabels,
        candidate_comparison: comparison.AgainstLabels,
    ):
        reference_fns = reference_comparison.false_negative_label_entries
        candidate_fns = candidate_comparison.false_negative_label_entries
        self.new_false_negatives = _label_entry_difference(candidate_fns, reference_fns)
        self.fixed_false_negatives = _label_entry_difference(reference_fns, candidate_fns)

        reference_fps = reference_comparison.false_positive_matches
        candidate_fps = candidate_comparison.false_positive_matches
        self.new_false_positives = _match_difference(candidate_fps, reference_fps)
        self.fixed_false_positives = _match_difference(reference_fps, candidate_fps)

    def _compute_delta(
        self,
        reference_comparison: comparison.AgainstLabels,
        candidate_comparison: comparison.AgainstLabels,
        relative_comparison: comparison.ByPreservedMatch,
    ):
        added = relative_comparison.unique.get(candidate_comparison.config.ID, set())
        removed = relative_comparison.unique.get(reference_comparison.config.ID, set())
        self.added_in_delta = len(added)
        self.removed_in_delta = len(removed)

        # a match unique to one tool can only be labeled (or not) relative to that tool's comparison
        candidate_unlabeled = set(candidate_comparison.matches_with_indeterminate_labels)
        reference_unlabeled = set(reference_comparison.matches_with_indeterminate_labels)
        self.unlabeled_in_delta = [UnlabeledDeltaMatch(match=m, added=True) for m in sorted(added) if m in candidate_unlabeled] + [
            UnlabeledDeltaMatch(match=m, added=False) for m in sorted(removed) if m in reference_unlabeled
        ]

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
