import typing

from yardstick.artifact import Label, Package
from yardstick.validate.delta import Delta, DeltaType, compute_deltas

import pytest
from unittest.mock import MagicMock
from yardstick.comparison import AgainstLabels, ByPreservedMatch


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


@pytest.fixture
def reference_result():
    """Fixture for creating a mock reference result."""
    return MagicMock(
        name="reference_results", ID="reference", config=MagicMock(tool="reference")
    )


@pytest.fixture
def candidate_result():
    """Fixture for creating a mock candidate result."""
    return MagicMock(
        name="candidate_results", ID="candidate", config=MagicMock(tool="candidate")
    )


@pytest.fixture
def comparisons_by_result_id():
    """Fixture for setting up comparisons with expected label data (source of truth)."""
    comparison = {
        # skip post init calculations on against labels, since
        # we're setting the comparison results directly below
        "reference": typing.cast(AgainstLabels, object.__new__(AgainstLabels)),
        "candidate": typing.cast(AgainstLabels, object.__new__(AgainstLabels)),
    }
    comparison["reference"].labels_by_match = {
        "match1": [Label.TruePositive],
        "match2": [Label.TruePositive],
        "match3": [Label.FalsePositive],
        "match4": [Label.FalsePositive],
    }
    comparison["candidate"].labels_by_match = {
        "match1": [Label.TruePositive],
        "match2": [Label.TruePositive],
        "match3": [Label.FalsePositive],
        "match4": [Label.FalsePositive],
    }
    return comparison


@pytest.fixture
def relative_comparison(reference_result, candidate_result):
    """Fixture for creating a mock relative comparison of reference and candidate."""
    match1 = MagicMock(
        name="match1",
        ID="match1",
        package=Package(name="libc", version="2.29"),
        vulnerability=MagicMock(id="CVE-2023-1234"),
    )
    match2 = MagicMock(
        name="match2",
        ID="match2",
        package=Package(name="nginx", version="1.17"),
        vulnerability=MagicMock(id="CVE-2023-0002"),
    )
    match3 = MagicMock(
        name="match3",
        ID="match3",
        package=Package(name="openssl", version="1.1.1"),
        vulnerability=MagicMock(id="CVE-2023-5678"),
    )
    match4 = MagicMock(
        name="match4",
        ID="match4",
        package=Package(name="zlib", version="1.2.11"),
        vulnerability=MagicMock(id="CVE-2023-8888"),
    )

    result = ByPreservedMatch(
        results=[reference_result, candidate_result],
    )
    result.unique = {
        "reference": [match2, match3],
        "candidate": [match1, match4],
    }
    return result


def test_compute_deltas(comparisons_by_result_id, relative_comparison):
    """Test compute_deltas with realistic comparisons between reference and candidate results."""
    deltas = compute_deltas(
        comparisons_by_result_id=comparisons_by_result_id,
        reference_tool="reference",
        relative_comparison=relative_comparison,
    )

    expected_deltas = [
        Delta(
            tool="reference",
            package_name="nginx",
            package_version="1.17",
            vulnerability_id="CVE-2023-0002",
            added=False,
            label="TruePositive",
        ),
        Delta(
            tool="reference",
            package_name="openssl",
            package_version="1.1.1",
            vulnerability_id="CVE-2023-5678",
            added=False,
            label="FalsePositive",
        ),
        Delta(
            tool="candidate",
            package_name="libc",
            package_version="2.29",
            vulnerability_id="CVE-2023-1234",
            added=True,
            label="TruePositive",
        ),
        Delta(
            tool="candidate",
            package_name="zlib",
            package_version="1.2.11",
            vulnerability_id="CVE-2023-8888",
            added=True,
            label="FalsePositive",
        ),
    ]

    assert len(deltas) == len(expected_deltas)
    for idx, actual in enumerate(deltas):
        assert actual == expected_deltas[idx], f"unequal at {idx}"
