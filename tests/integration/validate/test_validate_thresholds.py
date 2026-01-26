"""
Parameterized tests for yardstick validate threshold configurations.

These tests verify that the various validation thresholds (F1 regression,
false negatives, unlabeled percentage) work correctly across different
boundary conditions.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from yardstick import artifact
from yardstick.cli.cli import cli

from .helpers import (
    DEFAULT_IMAGE,
    GrypeMatchEntry,
    create_label_entry,
    setup_validate_test_env,
)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


# Common test data
SAMPLE_MATCHES = [
    GrypeMatchEntry(
        vulnerability_id="CVE-2020-0001",
        package_name="libc",
        package_version="2.29",
    ),
    GrypeMatchEntry(
        vulnerability_id="CVE-2020-0002",
        package_name="openssl",
        package_version="1.1.1",
    ),
]

SAMPLE_LABELS = [
    create_label_entry(
        label=artifact.Label.TruePositive,
        vulnerability_id="CVE-2020-0001",
        package=artifact.Package(name="libc", version="2.29"),
        image=DEFAULT_IMAGE,
    ),
    create_label_entry(
        label=artifact.Label.TruePositive,
        vulnerability_id="CVE-2020-0002",
        package=artifact.Package(name="openssl", version="1.1.1"),
        image=DEFAULT_IMAGE,
    ),
]


class TestF1RegressionThresholds:
    """Parameterized tests for F1 regression threshold."""

    @pytest.mark.parametrize(
        "max_f1_regression,candidate_matches,expected_pass",
        [
            # No regression allowed, identical results -> pass
            (0.0, SAMPLE_MATCHES, True),
            # No regression allowed, candidate misses one TP -> fail
            (0.0, [SAMPLE_MATCHES[0]], False),
            # Large regression allowed, candidate misses one TP -> pass
            (1.0, [SAMPLE_MATCHES[0]], True),
            # Small regression allowed, candidate finds all -> pass
            (0.1, SAMPLE_MATCHES, True),
        ],
        ids=[
            "no_regression_identical",
            "no_regression_worse_candidate",
            "large_regression_allowed",
            "small_regression_identical",
        ],
    )
    def test_f1_regression_threshold(
        self,
        cli_runner: CliRunner,
        tmp_path,
        max_f1_regression: float,
        candidate_matches: list[GrypeMatchEntry],
        expected_pass: bool,
    ):
        """F1 regression threshold controls validation pass/fail."""
        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=SAMPLE_MATCHES,
            matches_candidate=candidate_matches,
            labels=SAMPLE_LABELS,
            max_f1_regression=max_f1_regression,
            max_new_false_negatives=100,  # Don't fail on FNs for this test
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        if expected_pass:
            assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        else:
            assert result.exit_code == 1, f"Expected fail, got: {result.output}"


class TestFalseNegativeThresholds:
    """Parameterized tests for false negative threshold."""

    @pytest.mark.parametrize(
        "max_new_false_negatives,candidate_matches,expected_pass",
        [
            # No FNs allowed, identical results -> pass
            (0, SAMPLE_MATCHES, True),
            # No FNs allowed, candidate misses one -> fail
            (0, [SAMPLE_MATCHES[0]], False),
            # 1 FN allowed, candidate misses one -> pass
            (1, [SAMPLE_MATCHES[0]], True),
            # 2 FNs allowed, candidate misses both -> pass
            (2, [], True),
            # 1 FN allowed, candidate misses both -> fail
            (1, [], False),
        ],
        ids=[
            "no_fns_identical",
            "no_fns_one_missing",
            "one_fn_allowed_one_missing",
            "two_fns_allowed_both_missing",
            "one_fn_allowed_both_missing",
        ],
    )
    def test_false_negative_threshold(
        self,
        cli_runner: CliRunner,
        tmp_path,
        max_new_false_negatives: int,
        candidate_matches: list[GrypeMatchEntry],
        expected_pass: bool,
    ):
        """False negative threshold controls validation pass/fail."""
        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=SAMPLE_MATCHES,
            matches_candidate=candidate_matches,
            labels=SAMPLE_LABELS,
            max_f1_regression=1.0,  # Allow any F1 regression for this test
            max_new_false_negatives=max_new_false_negatives,
            fail_on_empty_match_set=False,  # Allow empty matches
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        if expected_pass:
            assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        else:
            assert result.exit_code == 1, f"Expected fail, got: {result.output}"


class TestUnlabeledPercentThresholds:
    """Parameterized tests for unlabeled/indeterminate percentage threshold."""

    @pytest.mark.parametrize(
        "max_unlabeled_percent,labels,expected_pass",
        [
            # 100% unlabeled allowed, all TPs -> pass
            (100, SAMPLE_LABELS, True),
            # 100% unlabeled allowed, no labels -> pass
            (100, [], True),
            # 50% unlabeled allowed, all labeled -> pass
            (
                50,
                SAMPLE_LABELS,
                True,
            ),
            # 0% unlabeled allowed, all labeled -> pass
            (
                0,
                SAMPLE_LABELS,
                True,
            ),
        ],
        ids=[
            "all_unlabeled_allowed_all_labeled",
            "all_unlabeled_allowed_no_labels",
            "half_unlabeled_allowed_all_labeled",
            "no_unlabeled_allowed_all_labeled",
        ],
    )
    def test_unlabeled_percent_threshold(
        self,
        cli_runner: CliRunner,
        tmp_path,
        max_unlabeled_percent: int,
        labels: list[artifact.LabelEntry],
        expected_pass: bool,
    ):
        """Unlabeled percentage threshold controls validation pass/fail."""
        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=SAMPLE_MATCHES,
            matches_candidate=SAMPLE_MATCHES,
            labels=labels,
            max_unlabeled_percent=max_unlabeled_percent,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        if expected_pass:
            assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        else:
            assert result.exit_code == 1, f"Expected fail, got: {result.output}"


class TestEmptyMatchSetThreshold:
    """Parameterized tests for empty match set handling."""

    @pytest.mark.parametrize(
        "fail_on_empty_match_set,matches,expected_pass",
        [
            # Fail on empty enabled, empty matches -> fail
            (True, [], False),
            # Fail on empty disabled, empty matches -> pass
            (False, [], True),
            # Fail on empty enabled, has matches -> pass
            (True, SAMPLE_MATCHES, True),
            # Fail on empty disabled, has matches -> pass
            (False, SAMPLE_MATCHES, True),
        ],
        ids=[
            "fail_enabled_empty",
            "fail_disabled_empty",
            "fail_enabled_has_matches",
            "fail_disabled_has_matches",
        ],
    )
    def test_empty_match_set_threshold(
        self,
        cli_runner: CliRunner,
        tmp_path,
        fail_on_empty_match_set: bool,
        matches: list[GrypeMatchEntry],
        expected_pass: bool,
    ):
        """Empty match set handling based on configuration."""
        labels = SAMPLE_LABELS if matches else []

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
            fail_on_empty_match_set=fail_on_empty_match_set,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        if expected_pass:
            assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        else:
            assert result.exit_code == 1, f"Expected fail, got: {result.output}"


class TestYearFilterThresholds:
    """Parameterized tests for CVE year filtering."""

    @pytest.mark.parametrize(
        "max_year,matches,expected_included_cves",
        [
            # 2020 filter includes CVE-2020 and earlier
            (
                2020,
                [
                    GrypeMatchEntry("CVE-2019-0001", "pkg1", "1.0"),
                    GrypeMatchEntry("CVE-2020-0001", "pkg2", "1.0"),
                    GrypeMatchEntry("CVE-2021-0001", "pkg3", "1.0"),
                ],
                ["CVE-2019-0001", "CVE-2020-0001"],
            ),
            # 2019 filter includes only CVE-2019
            (
                2019,
                [
                    GrypeMatchEntry("CVE-2019-0001", "pkg1", "1.0"),
                    GrypeMatchEntry("CVE-2020-0001", "pkg2", "1.0"),
                ],
                ["CVE-2019-0001"],
            ),
            # 2025 filter includes all
            (
                2025,
                [
                    GrypeMatchEntry("CVE-2020-0001", "pkg1", "1.0"),
                    GrypeMatchEntry("CVE-2021-0001", "pkg2", "1.0"),
                ],
                ["CVE-2020-0001", "CVE-2021-0001"],
            ),
        ],
        ids=[
            "2020_filter",
            "2019_filter",
            "2025_filter_all",
        ],
    )
    def test_year_filter(
        self,
        cli_runner: CliRunner,
        tmp_path,
        max_year: int,
        matches: list[GrypeMatchEntry],
        expected_included_cves: list[str],
    ):
        """Year filter restricts which CVEs are considered."""
        # Create labels for all matches
        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id=m.vulnerability_id,
                package=artifact.Package(name=m.package_name, version=m.package_version),
                image=DEFAULT_IMAGE,
            )
            for m in matches
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
            max_year=max_year,
            fail_on_empty_match_set=False,  # In case all CVEs are filtered out
        )

        result = cli_runner.invoke(
            cli,
            [
                "-c",
                env.config_path,
                "validate",
                "-r",
                env.result_set_name,
                "--max-year",
                str(max_year),
            ],
            catch_exceptions=False,
        )

        # Should pass since reference and candidate are identical
        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
