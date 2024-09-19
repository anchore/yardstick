# Sample images
from unittest.mock import patch, MagicMock

import pytest
from mypy.modulefinder import unique

from yardstick import comparison
from yardstick.artifact import (
    LabelEntry,
    Label,
    Package,
    Match,
    Vulnerability,
    ScanConfiguration,
    ScanResult,
)
from yardstick.validate import validate_image, GateConfig


@pytest.fixture()
def compare_results_no_matches():
    return MagicMock(results=[MagicMock(matches=[]), MagicMock(matches=[])])


@pytest.fixture()
def compare_results_identical_matches():
    return MagicMock(
        results=[
            MagicMock(
                matches=[MagicMock()],
                unique={},
            ),
            MagicMock(
                matches=[MagicMock()],
                unique={},
            ),
        ]
    )


@patch("yardstick.compare_results")
def test_validate_fail_on_empty_matches(
    mock_compare_results, compare_results_no_matches
):
    mock_compare_results.return_value = compare_results_no_matches
    gate = validate_image(
        "some image",
        GateConfig(fail_on_empty_match_set=True),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert not gate.passed()
    assert (
        "gate configured to fail on empty matches, and no matches found" in gate.reasons
    )
    assert mock_compare_results.called_once_with(
        descriptions=["some-str", "another-str"],
        year_max_limit=2021,
        matches_filter=None,
    )


@patch("yardstick.compare_results")
def test_validate_dont_fail_on_empty_matches(
    mock_compare_results, compare_results_no_matches
):
    mock_compare_results.return_value = compare_results_no_matches
    gate = validate_image(
        "some image",
        GateConfig(fail_on_empty_match_set=False),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert gate.passed()
    assert mock_compare_results.called_once_with(
        descriptions=["some-str", "another-str"],
        year_max_limit=2021,
        matches_filter=None,
    )


@patch("yardstick.compare_results")
def test_validate_pass_early_identical_match_sets(
    mock_compare_results, compare_results_identical_matches
):
    mock_compare_results.return_value = compare_results_identical_matches
    gate = validate_image(
        "some image",
        GateConfig(fail_on_empty_match_set=False),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert gate.passed()
    assert mock_compare_results.called_once_with(
        descriptions=["some-str", "another-str"],
        year_max_limit=2021,
        matches_filter=None,
    )
