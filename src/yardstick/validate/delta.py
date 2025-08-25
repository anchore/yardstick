import enum
from dataclasses import dataclass

from yardstick import artifact, comparison


def extract_reference_url(match: artifact.Match) -> str | None:
    """Extract the specific vulnerability reference URL from match data."""
    if match.fullentry and isinstance(match.fullentry, dict):
        # Look for URL in vulnerability data
        vuln_data = match.fullentry.get("vulnerability", {})
        if isinstance(vuln_data, dict):
            # Try different possible URL fields
            for url_field in ["dataSource", "url", "reference", "link"]:
                url = vuln_data.get(url_field)
                if url and isinstance(url, str):
                    return url
    return None


def extract_namespace(match: artifact.Match) -> str | None:
    """Extract the vulnerability namespace from match data."""
    if match.fullentry and isinstance(match.fullentry, dict):
        vuln_data = match.fullentry.get("vulnerability", {})
        if isinstance(vuln_data, dict):
            namespace = vuln_data.get("namespace")
            if namespace and isinstance(namespace, str):
                return namespace
    return None


def extract_fixed_version(match: artifact.Match) -> str | None:
    """Extract the fixed version/version constraint from match data."""
    if match.fullentry and isinstance(match.fullentry, dict):
        # Check for fix information in vulnerability.fix.versions (Grype structure)
        vuln_data = match.fullentry.get("vulnerability", {})
        if isinstance(vuln_data, dict):
            fix_data = vuln_data.get("fix", {})
            if isinstance(fix_data, dict):
                # Check for fix state first
                fix_state = fix_data.get("state")
                if fix_state and isinstance(fix_state, str):
                    if fix_state == "fixed":
                        # If state is "fixed", check for versions
                        versions = fix_data.get("versions")
                        if versions and isinstance(versions, list) and versions:
                            return ", ".join(str(v) for v in versions)
                    else:
                        # Return the state for non-fixed states
                        return fix_state
                else:
                    # Fallback to check versions without state
                    versions = fix_data.get("versions")
                    if versions and isinstance(versions, list) and versions:
                        return ", ".join(str(v) for v in versions)

        # Check for suggested version in matchDetails[].fix.suggestedVersion
        match_details = match.fullentry.get("matchDetails", [])
        if isinstance(match_details, list):
            for detail in match_details:
                if isinstance(detail, dict):
                    fix_detail = detail.get("fix", {})
                    if isinstance(fix_detail, dict):
                        suggested = fix_detail.get("suggestedVersion")
                        if suggested and isinstance(suggested, str):
                            return suggested

        # Fallback: Check for other common fix version fields
        if isinstance(vuln_data, dict):
            for fix_field in ["fixVersions", "fixedIn", "fixVersion", "fixed_version"]:
                fix_versions = vuln_data.get(fix_field)
                if fix_versions:
                    if isinstance(fix_versions, list) and fix_versions:
                        return ", ".join(str(v) for v in fix_versions)
                    elif isinstance(fix_versions, str):
                        return fix_versions

        # Check for fix information in match-level data
        for fix_field in ["fixVersions", "fixedIn", "fixVersion", "fixed_version"]:
            fix_versions = match.fullentry.get(fix_field)
            if fix_versions:
                if isinstance(fix_versions, list) and fix_versions:
                    return ", ".join(str(v) for v in fix_versions)
                elif isinstance(fix_versions, str):
                    return fix_versions

    return None


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
    reference_url: str | None = None
    namespace: str | None = None
    fixed_version: str | None = None
    full_match: artifact.Match | None = None

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
                reference_url=extract_reference_url(unique_match),
                namespace=extract_namespace(unique_match),
                fixed_version=extract_fixed_version(unique_match),
                full_match=unique_match,
            )
            deltas.append(delta)
    return deltas
