import enum
from dataclasses import dataclass

from yardstick import artifact, comparison


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


def compute_deltas(
    comparisons_by_result_id: dict[str, comparison.AgainstLabels],
    reference_tool: str,
    relative_comparison: comparison.ByPreservedMatch,
):
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
                label=label,
            )
            deltas.append(delta)
    return deltas
