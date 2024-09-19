import pytest

from yardstick.artifact import Label
from yardstick.validate.delta import Delta, DeltaType


@pytest.mark.parametrize(
    "tool, package_name, package_version, vulnerability_id, added, label, expected_outcome, expected_is_improved, expected_commentary",
    [
        (
            "scanner1",
            "libc",
            "2.29",
            "CVE-2023-1234",
            True,
            Label.TruePositive.name,
            DeltaType.FixedFalseNegative,
            True,
            "(this is a new TP 🙌)",
        ),
        (
            "scanner1",
            "nginx",
            "1.17",
            "CVE-2023-0002",
            False,
            Label.FalsePositive.name,
            DeltaType.FixedFalsePositive,
            True,
            "(got rid of a former FP 🙌)",
        ),
        (
            "scanner2",
            "bash",
            "5.0",
            "CVE-2023-5678",
            False,
            Label.TruePositive.name,
            DeltaType.NewFalseNegative,
            False,
            "(this is a new FN 😱)",
        ),
        (
            "scanner3",
            "zlib",
            "1.2.11",
            "CVE-2023-8888",
            True,
            Label.FalsePositive.name,
            DeltaType.NewFalsePositive,
            False,
            "(this is a new FP 😱)",
        ),
        (
            "scanner4",
            "openssl",
            "1.1.1",
            "CVE-2023-0001",
            True,
            None,
            DeltaType.Unknown,
            None,
            "",
        ),
    ],
)
def test_delta_properties(
    tool,
    package_name,
    package_version,
    vulnerability_id,
    added,
    label,
    expected_outcome,
    expected_is_improved,
    expected_commentary,
):
    """Test Delta properties is_improved, outcome, and commentary based on logical combinations."""

    delta = Delta(
        tool=tool,
        package_name=package_name,
        package_version=package_version,
        vulnerability_id=vulnerability_id,
        added=added,
        label=label,
    )

    assert delta.outcome == expected_outcome
    assert delta.is_improved == expected_is_improved
    assert delta.commentary == expected_commentary
