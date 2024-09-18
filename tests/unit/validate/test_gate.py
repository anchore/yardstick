from yardstick.validate import Gate, GateConfig, GateInputDescription, Delta
from yardstick import artifact, comparison


import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_label_comparison():
    """Fixture to create a mock LabelComparisonSummary with defaults."""
    summary = MagicMock()
    summary.f1_score = 0.9
    summary.false_negatives = 5
    summary.indeterminate_percent = 2.0
    return summary


@pytest.mark.parametrize(
    "config, reference_summary, candidate_summary, expected_reasons",
    [
        # Case 1: Candidate has a lower F1 score beyond the allowed threshold -> gate fails
        (
            GateConfig(
                max_f1_regression=0.1,
                max_new_false_negatives=5,
                max_unlabeled_percent=10,
            ),
            MagicMock(f1_score=0.9, false_negatives=5, indeterminate_percent=2.0),
            MagicMock(f1_score=0.7, false_negatives=5, indeterminate_percent=2.0),
            ["current F1 score is lower than the latest release F1 score"],
        ),
        # Case 2: Candidate has too many false negatives -> gate fails
        (
            GateConfig(
                max_f1_regression=0.1,
                max_new_false_negatives=1,
                max_unlabeled_percent=10,
            ),
            MagicMock(f1_score=0.9, false_negatives=5, indeterminate_percent=2.0),
            MagicMock(f1_score=0.85, false_negatives=7, indeterminate_percent=2.0),
            [
                "current false negatives is greater than the latest release false negatives"
            ],
        ),
        # Case 3: Candidate has too high indeterminate percent -> gate fails
        (
            GateConfig(
                max_f1_regression=0.1,
                max_new_false_negatives=5,
                max_unlabeled_percent=5,
            ),
            MagicMock(f1_score=0.9, false_negatives=5, indeterminate_percent=2.0),
            MagicMock(f1_score=0.85, false_negatives=5, indeterminate_percent=6.0),
            ["current indeterminate matches % is greater than"],
        ),
        # Case 4: Candidate passes all thresholds -> gate passes (no reasons)
        (
            GateConfig(
                max_f1_regression=0.1,
                max_new_false_negatives=5,
                max_unlabeled_percent=10,
            ),
            MagicMock(f1_score=0.9, false_negatives=5, indeterminate_percent=2.0),
            MagicMock(f1_score=0.85, false_negatives=5, indeterminate_percent=3.0),
            [],
        ),
    ],
)
def test_gate(config, reference_summary, candidate_summary, expected_reasons):
    """Parameterized test for the Gate class that checks different pass/fail conditions."""

    # Create the Gate instance with the given parameters
    gate = Gate(
        reference_comparison=reference_summary,
        candidate_comparison=candidate_summary,
        config=config,
        input_description=MagicMock(image="test_image"),
    )

    # Check that the reasons list matches the expected outcome
    assert len(gate.reasons) == len(expected_reasons)
    for reason, expected_reason in zip(gate.reasons, expected_reasons):
        assert expected_reason in reason


def test_gate_failing():
    input_description = GateInputDescription(image="some-image", configs=[])
    gate = Gate.failing(["sample failure reason"], input_description)
    assert not gate.passed()
    assert gate.reasons == ["sample failure reason"]


def test_gate_passing():
    input_description = GateInputDescription(image="some-image", configs=[])
    gate = Gate.passing(input_description)
    assert gate.passed()
