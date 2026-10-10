from yardstick.validate import Gate, GateConfig, GateInputDescription
from yardstick.validate.gate import MAX_REASON_DETAILS
from yardstick import artifact


import pytest
from unittest.mock import MagicMock


REFERENCE_ID = "reference-result"
CANDIDATE_ID = "candidate-result"


def _label(vulnerability_id: str, package: str = "package", label: artifact.Label = artifact.Label.TruePositive, **kwargs) -> artifact.LabelEntry:
    return artifact.LabelEntry(
        label=label,
        vulnerability_id=vulnerability_id,
        package=artifact.Package(name=package, version="1.0"),
        user="somebody",
        **kwargs,
    )


def _match(vulnerability_id: str, package: str = "package") -> artifact.Match:
    return artifact.Match(
        vulnerability=artifact.Vulnerability(id=vulnerability_id),
        package=artifact.Package(name=package, version="1.0"),
    )


def _comparison(
    result_id: str,
    f1_score: float = 0.9,
    indeterminate_percent: float = 2.0,
    false_negative_label_entries: set[artifact.LabelEntry] | None = None,
    false_positive_matches: list[artifact.Match] | None = None,
    matches_with_indeterminate_labels: list[artifact.Match] | None = None,
) -> MagicMock:
    """Build a stand-in for comparison.AgainstLabels with real label and match collections."""
    comparison = MagicMock()
    comparison.config.ID = result_id
    comparison.summary.f1_score = f1_score
    comparison.summary.indeterminate_percent = indeterminate_percent
    comparison.false_negative_label_entries = false_negative_label_entries or set()
    comparison.false_positive_matches = false_positive_matches or []
    comparison.matches_with_indeterminate_labels = matches_with_indeterminate_labels or []
    return comparison


def _relative_comparison(added: set[artifact.Match], removed: set[artifact.Match]) -> MagicMock:
    """Build a stand-in for comparison.ByPreservedMatch with the matches unique to each tool."""
    relative = MagicMock()
    relative.unique = {CANDIDATE_ID: added, REFERENCE_ID: removed}
    return relative


def _gate(config: GateConfig, reference: MagicMock, candidate: MagicMock, relative_comparison: MagicMock | None = None) -> Gate:
    return Gate(
        reference_comparison=reference,
        candidate_comparison=candidate,
        config=config,
        input_description=MagicMock(image="test_image"),
        relative_comparison=relative_comparison,
    )


@pytest.mark.parametrize(
    "config, reference, candidate, expected_reasons",
    [
        # Candidate has a lower F1 score beyond the allowed threshold -> gate fails
        (
            GateConfig(max_f1_regression=0.1, max_unlabeled_percent=10),
            _comparison(REFERENCE_ID, f1_score=0.9),
            _comparison(CANDIDATE_ID, f1_score=0.7),
            ["current F1 score is lower than the latest release F1 score"],
        ),
        # Candidate has too high indeterminate percent -> gate fails
        (
            GateConfig(max_f1_regression=0.1, max_unlabeled_percent=5),
            _comparison(REFERENCE_ID, f1_score=0.9, indeterminate_percent=2.0),
            _comparison(CANDIDATE_ID, f1_score=0.85, indeterminate_percent=6.0),
            ["current indeterminate matches % is greater than 5%: candidate=6.00% image=test_image"],
        ),
        # Candidate passes all thresholds -> gate passes (no reasons)
        (
            GateConfig(max_f1_regression=0.1, max_unlabeled_percent=10),
            _comparison(REFERENCE_ID, f1_score=0.9, indeterminate_percent=2.0),
            _comparison(CANDIDATE_ID, f1_score=0.85, indeterminate_percent=3.0),
            [],
        ),
    ],
)
def test_gate(config, reference, candidate, expected_reasons):
    gate = _gate(config, reference, candidate)

    assert len(gate.reasons) == len(expected_reasons)
    for reason, expected_reason in zip(gate.reasons, expected_reasons):
        assert expected_reason in reason


class TestMaxUnlabeledPercent:
    def test_skipped_when_unset(self):
        gate = _gate(
            GateConfig(),
            _comparison(REFERENCE_ID),
            _comparison(CANDIDATE_ID, indeterminate_percent=99.0),
        )
        assert gate.passed()

    def test_existing_reason_when_exceeded(self):
        gate = _gate(
            GateConfig(max_unlabeled_percent=10),
            _comparison(REFERENCE_ID),
            _comparison(CANDIDATE_ID, indeterminate_percent=11.0),
        )
        assert gate.reasons == ["current indeterminate matches % is greater than 10%: candidate=11.00% image=test_image"]


class TestNewFalseNegatives:
    def test_swapped_false_negatives_fail(self):
        # the reference misses C1 and finds C2, the candidate finds C1 and misses C2: equal counts, but C2 is new
        c1, c2 = _label("CVE-2020-0001"), _label("CVE-2020-0002")
        gate = _gate(
            GateConfig(),
            _comparison(REFERENCE_ID, false_negative_label_entries={c1}),
            _comparison(CANDIDATE_ID, false_negative_label_entries={c2}),
        )

        assert len(gate.reasons) == 1
        summary, *details = gate.reasons[0].split("\n")
        assert summary == "1 new false negatives (max 0, 1 fixed): image=test_image"
        assert [d.strip() for d in details] == ["package@1.0 CVE-2020-0002 [TruePositive]"]
        assert gate.new_false_negatives == [c2]
        assert gate.fixed_false_negatives == [c1]

    def test_same_false_negatives_pass(self):
        fns = {_label(f"CVE-2020-000{i}") for i in range(5)}
        gate = _gate(
            GateConfig(),
            _comparison(REFERENCE_ID, false_negative_label_entries=fns),
            _comparison(CANDIDATE_ID, false_negative_label_entries=set(fns)),
        )
        assert gate.passed()

    @pytest.mark.parametrize("max_new_false_negatives, expect_pass", [(0, False), (1, True)])
    def test_one_additional_false_negative(self, max_new_false_negatives, expect_pass):
        fns = {_label(f"CVE-2020-000{i}") for i in range(5)}
        gate = _gate(
            GateConfig(max_new_false_negatives=max_new_false_negatives),
            _comparison(REFERENCE_ID, false_negative_label_entries=fns),
            _comparison(CANDIDATE_ID, false_negative_label_entries=fns | {_label("CVE-2020-0009")}),
        )
        assert gate.passed() == expect_pass

    def test_fixed_false_negatives_are_reported(self):
        fns = sorted((_label(f"CVE-2020-000{i}") for i in range(5)), key=lambda e: e.vulnerability_id)
        gate = _gate(
            GateConfig(),
            _comparison(REFERENCE_ID, false_negative_label_entries=set(fns)),
            _comparison(CANDIDATE_ID, false_negative_label_entries=set(fns[:3])),
        )
        assert gate.passed()
        assert gate.fixed_false_negatives == fns[3:]

    def test_equivalent_label_entries_from_different_files_are_the_same_false_negative(self):
        # same claim, but recorded with a different ID, note, and source
        reference_fn = _label("CVE-2020-0001", ID="from-file-a", note="a", source="manual")
        candidate_fn = _label("CVE-2020-0001", ID="from-file-b", note="b", source="import")
        gate = _gate(
            GateConfig(),
            _comparison(REFERENCE_ID, false_negative_label_entries={reference_fn}),
            _comparison(CANDIDATE_ID, false_negative_label_entries={candidate_fn}),
        )
        assert gate.passed()

    def test_reason_lists_are_capped(self):
        fns = {_label(f"CVE-2020-{i:04d}") for i in range(MAX_REASON_DETAILS + 5)}
        gate = _gate(
            GateConfig(),
            _comparison(REFERENCE_ID),
            _comparison(CANDIDATE_ID, false_negative_label_entries=fns),
        )
        lines = gate.reasons[0].split("\n")
        assert len(lines) == 1 + MAX_REASON_DETAILS + 1
        assert lines[-1].strip() == "... and 5 more"


class TestNewFalsePositives:
    @pytest.mark.parametrize("max_new_false_positives, expect_pass", [(0, False), (1, True), (None, True)])
    def test_new_false_positive(self, max_new_false_positives, expect_pass):
        gate = _gate(
            GateConfig(max_new_false_positives=max_new_false_positives),
            _comparison(REFERENCE_ID),
            _comparison(CANDIDATE_ID, false_positive_matches=[_match("CVE-2020-0001")]),
        )
        assert gate.passed() == expect_pass
        if not expect_pass:
            summary, *details = gate.reasons[0].split("\n")
            assert summary == "1 new false positives (max 0, 0 fixed): image=test_image"
            assert [d.strip() for d in details] == ["package@1.0 CVE-2020-0001"]

    def test_false_positive_reported_by_both_tools_is_not_new(self):
        # distinct match objects (e.g. different full entries) that represent the same match
        reference_fp = artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2020-0001"),
            package=artifact.Package(name="package", version="1.0"),
            fullentry={"from": "reference"},
        )
        candidate_fp = artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2020-0001"),
            package=artifact.Package(name="package", version="1.0"),
            fullentry={"from": "candidate"},
        )
        gate = _gate(
            GateConfig(max_new_false_positives=0),
            _comparison(REFERENCE_ID, false_positive_matches=[reference_fp]),
            _comparison(CANDIDATE_ID, false_positive_matches=[candidate_fp]),
        )
        assert gate.passed()

    def test_dropped_false_positive_is_reported_as_fixed(self):
        fp = _match("CVE-2020-0001")
        gate = _gate(
            GateConfig(max_new_false_positives=0),
            _comparison(REFERENCE_ID, false_positive_matches=[fp]),
            _comparison(CANDIDATE_ID),
        )
        assert gate.passed()
        assert gate.fixed_false_positives == [fp]


class TestUnlabeledInDelta:
    @pytest.fixture
    def large_result(self):
        """100 matches per tool, 50 of them unlabeled, with a delta of 10 matches of which 2 are unlabeled."""
        common = [_match(f"CVE-2020-{i:04d}") for i in range(90)]
        common_unlabeled = common[:48]

        added = [_match(f"CVE-2021-{i:04d}") for i in range(5)]
        removed = [_match(f"CVE-2022-{i:04d}") for i in range(5)]

        reference = _comparison(REFERENCE_ID, matches_with_indeterminate_labels=common_unlabeled + removed[:1])
        candidate = _comparison(CANDIDATE_ID, matches_with_indeterminate_labels=common_unlabeled + added[:1])
        return reference, candidate, _relative_comparison(set(added), set(removed))

    @pytest.mark.parametrize("max_unlabeled_in_delta, expect_pass", [(1, False), (2, True), (None, True)])
    def test_only_delta_is_counted(self, large_result, max_unlabeled_in_delta, expect_pass):
        reference, candidate, relative = large_result
        gate = _gate(GateConfig(max_unlabeled_in_delta=max_unlabeled_in_delta), reference, candidate, relative)

        assert gate.passed() == expect_pass
        assert len(gate.unlabeled_in_delta) == 2
        assert gate.added_in_delta == 5
        assert gate.removed_in_delta == 5
        if not expect_pass:
            summary, *details = gate.reasons[0].split("\n")
            assert summary == "2 unlabeled matches differ between tools (max 1): image=test_image"
            assert [d.strip() for d in details] == [
                "package@1.0 CVE-2021-0000 (added)",
                "package@1.0 CVE-2022-0000 (removed)",
            ]

    def test_unlabeled_match_only_on_reference_side_is_counted(self):
        disappeared = _match("CVE-2020-0003")
        gate = _gate(
            GateConfig(max_unlabeled_in_delta=0),
            _comparison(REFERENCE_ID, matches_with_indeterminate_labels=[disappeared]),
            _comparison(CANDIDATE_ID),
            _relative_comparison(added={_match("CVE-2020-0001"), _match("CVE-2020-0002")}, removed={disappeared}),
        )
        assert not gate.passed()
        assert [(u.match, u.added) for u in gate.unlabeled_in_delta] == [(disappeared, False)]

    def test_match_is_looked_up_against_the_tool_that_reported_it(self):
        # unlabeled for the reference only, but unique to the candidate: labeled as far as the candidate is concerned
        match = _match("CVE-2020-0001")
        gate = _gate(
            GateConfig(max_unlabeled_in_delta=0),
            _comparison(REFERENCE_ID, matches_with_indeterminate_labels=[match]),
            _comparison(CANDIDATE_ID),
            _relative_comparison(added={match}, removed=set()),
        )
        assert gate.passed()

    def test_empty_delta(self):
        unlabeled = [_match(f"CVE-2020-{i:04d}") for i in range(50)]
        gate = _gate(
            GateConfig(max_unlabeled_in_delta=0),
            _comparison(REFERENCE_ID, matches_with_indeterminate_labels=unlabeled),
            _comparison(CANDIDATE_ID, matches_with_indeterminate_labels=unlabeled),
            _relative_comparison(added=set(), removed=set()),
        )
        assert gate.passed()
        assert gate.unlabeled_in_delta == []


def test_gate_failing():
    input_description = GateInputDescription(image="some-image", configs=[])
    gate = Gate.failing(["sample failure reason"], input_description)
    assert not gate.passed()
    assert gate.reasons == ["sample failure reason"]


def test_gate_passing():
    input_description = GateInputDescription(image="some-image", configs=[])
    gate = Gate.passing(input_description)
    assert gate.passed()
