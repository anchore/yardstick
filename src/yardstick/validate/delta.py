import enum
from dataclasses import dataclass

from yardstick import artifact


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
