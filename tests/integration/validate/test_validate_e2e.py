"""
End-to-end tests for the `yardstick validate` command.

These tests exercise the complete flow:
config loading → result set loading → scan result loading → comparison → gate evaluation → pass/fail

No mocking of core yardstick functions - uses real file I/O and comparison logic.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from yardstick import artifact
from yardstick.cli.cli import cli

from .helpers import (
    DEFAULT_IMAGE,
    DEFAULT_IMAGE_DIGEST,
    DEFAULT_IMAGE_REPO,
    GrypeMatchEntry,
    ValidateTestEnv,
    create_label_entry,
    setup_validate_test_env,
)


class TestValidateE2E:
    """End-to-end tests for yardstick validate command."""

    def test_validate_passes_identical_results(
        self,
        cli_runner: CliRunner,
        identical_results_env: ValidateTestEnv,
    ):
        """
        When reference and candidate find identical matches, validation should pass.
        """
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                identical_results_env.config_path,
                "validate",
                "-r",
                identical_results_env.result_set_name,
            ],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output

    def test_validate_passes_improved_results(
        self,
        cli_runner: CliRunner,
        improved_results_env: ValidateTestEnv,
    ):
        """
        When candidate finds fewer false positives than reference, validation should pass.
        The candidate tool is improved (better precision).
        """
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                improved_results_env.config_path,
                "validate",
                "-r",
                improved_results_env.result_set_name,
            ],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output

    def test_validate_fails_f1_regression(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When candidate has worse F1 score (more FPs, missed TPs), validation should fail.
        """
        # Reference finds TPs only
        reference_matches = [
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

        # Candidate misses a TP and adds a FP
        candidate_matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
            # Missing CVE-2020-0002 (a TP - false negative)
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0003",  # This is a FP
                package_name="curl",
                package_version="7.68.0",
            ),
        ]

        labels = [
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
            create_label_entry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0003",
                package=artifact.Package(name="curl", version="7.68.0"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=reference_matches,
            matches_candidate=candidate_matches,
            labels=labels,
            max_f1_regression=0.0,  # No regression allowed
            max_new_false_negatives=0,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 1, f"Expected failure, got: {result.output}"
        assert "Quality gate FAILED" in result.output
        # Should mention either F1 regression or false negatives
        assert "F1 score" in result.output or "false negatives" in result.output

    def test_validate_fails_new_false_negatives(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When candidate misses TPs that reference found, validation should fail.
        """
        # Reference finds all TPs
        reference_matches = [
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
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0003",
                package_name="curl",
                package_version="7.68.0",
            ),
        ]

        # Candidate misses two TPs
        candidate_matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
            # Missing CVE-2020-0002 and CVE-2020-0003
        ]

        labels = [
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
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0003",
                package=artifact.Package(name="curl", version="7.68.0"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=reference_matches,
            matches_candidate=candidate_matches,
            labels=labels,
            max_new_false_negatives=0,  # No new FNs allowed
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 1, f"Expected failure, got: {result.output}"
        assert "Quality gate FAILED" in result.output
        assert "false negatives" in result.output.lower()

    def test_validate_fails_unlabeled_percent(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When too many matches have indeterminate/unclear labels, validation should fail.
        We need different results between tools to trigger proper label comparison,
        and have high percentage of Unclear labels.

        Note: Labels without package constraints match any package with that vuln ID.
        """
        # Reference tool finds these matches
        reference_matches = [
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
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0003",
                package_name="curl",
                package_version="7.68.0",
            ),
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0004",
                package_name="nginx",
                package_version="1.17.0",
            ),
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0005",
                package_name="python",
                package_version="3.8.0",
            ),
        ]

        # Candidate finds slightly different matches to trigger comparison
        candidate_matches = [
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
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0003",
                package_name="curl",
                package_version="7.68.0",
            ),
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0004",
                package_name="nginx",
                package_version="1.17.0",
            ),
            # Candidate finds additional match
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0006",
                package_name="bash",
                package_version="5.0",
            ),
        ]

        # Labels without package constraints - match vulnerability ID only
        # 1 TP, rest Unclear = high indeterminate %
        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0001",
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.Unclear,
                vulnerability_id="CVE-2020-0002",
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.Unclear,
                vulnerability_id="CVE-2020-0003",
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.Unclear,
                vulnerability_id="CVE-2020-0004",
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.Unclear,
                vulnerability_id="CVE-2020-0005",
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.Unclear,
                vulnerability_id="CVE-2020-0006",
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=reference_matches,
            matches_candidate=candidate_matches,
            labels=labels,
            max_unlabeled_percent=10,  # Only allow 10% unclear, but we have ~83%
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 1, f"Expected failure, got: {result.output}"
        assert "Quality gate FAILED" in result.output
        assert "indeterminate" in result.output.lower()

    def test_validate_fails_empty_matches(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When no matches are found and fail_on_empty_match_set=true, validation should fail.
        """
        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=[],
            matches_candidate=[],
            labels=[],
            fail_on_empty_match_set=True,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 1, f"Expected failure, got: {result.output}"
        assert "Quality gate FAILED" in result.output
        assert "empty" in result.output.lower() or "no matches" in result.output.lower()

    def test_validate_passes_empty_matches(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When no matches are found and fail_on_empty_match_set=false, validation should pass.
        """
        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=[],
            matches_candidate=[],
            labels=[],
            fail_on_empty_match_set=False,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output

    def test_validate_year_filter(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        With --max-year filter, only CVEs from that year and earlier are considered.
        """
        # Mix of CVEs from different years
        matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2019-0001",  # 2019 - should be included
                package_name="libc",
                package_version="2.29",
            ),
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",  # 2020 - should be included with max_year=2020
                package_name="openssl",
                package_version="1.1.1",
            ),
            GrypeMatchEntry(
                vulnerability_id="CVE-2021-0001",  # 2021 - should be excluded with max_year=2020
                package_name="curl",
                package_version="7.68.0",
            ),
        ]

        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2019-0001",
                package=artifact.Package(name="libc", version="2.29"),
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="openssl", version="1.1.1"),
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2021-0001",
                package=artifact.Package(name="curl", version="7.68.0"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
            max_year=2020,  # Filter to 2020 and earlier
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
                "2020",
            ],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output

    def test_validate_result_set_filter(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        The -r option should select only the specified result set for validation.
        """
        matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
        ]

        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="libc", version="2.29"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
            result_set_name="my-specific-result-set",
        )

        result = cli_runner.invoke(
            cli,
            [
                "-c",
                env.config_path,
                "validate",
                "-r",
                "my-specific-result-set",
            ],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "my-specific-result-set" in result.output
        assert "Quality gate passed" in result.output

    def test_validate_with_verbose_output(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        The -v flag should provide more detailed output.
        """
        matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
        ]

        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="libc", version="2.29"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
        )

        result = cli_runner.invoke(
            cli,
            [
                "-c",
                env.config_path,
                "validate",
                "-r",
                env.result_set_name,
                "-v",
                "-l",  # Force label comparison
            ],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output

    def test_validate_shows_delta_commentary(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When there are differences between tools, delta commentary should be shown.
        """
        # Reference finds one TP
        reference_matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
        ]

        # Candidate finds different match
        candidate_matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0002",
                package_name="openssl",
                package_version="1.1.1",
            ),
        ]

        labels = [
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

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=reference_matches,
            matches_candidate=candidate_matches,
            labels=labels,
            max_f1_regression=1.0,  # Allow regression for this test
            max_new_false_negatives=10,  # Allow FNs for this test
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        # With differences, should show deltas in output
        assert "Deltas" in result.output or "ONLY" in result.output

    def test_validate_requires_result_set(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        Validate command should require --result-set or --all flag.
        """
        matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=[],
        )

        # Don't catch exceptions so we can see the error
        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate"],
            catch_exceptions=True,  # Let Click handle the exception
        )

        assert result.exit_code != 0
        # The error message should mention result-set
        assert "result-set" in str(result.exception).lower() or "result-set" in result.output.lower()


class TestValidateMultipleImages:
    """Tests for validate with multiple images in a result set."""

    def test_validate_multiple_images_all_pass(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When result set contains multiple images and all pass, overall validation passes.
        """
        import datetime
        import os

        import yaml

        from .helpers import (
            ValidateTestEnv,
            create_grype_output,
            create_scan_configuration,
            create_yardstick_config,
            save_label_entries,
            save_result_set,
            save_scan_result,
        )

        # Set up two images
        image1 = f"{DEFAULT_IMAGE_REPO}@sha256:{'a' * 64}"
        image2 = f"{DEFAULT_IMAGE_REPO}@sha256:{'b' * 64}"

        matches1 = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
        ]

        matches2 = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0002",
                package_name="openssl",
                package_version="1.1.1",
            ),
        ]

        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="libc", version="2.29"),
                image=image1,
            ),
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0002",
                package=artifact.Package(name="openssl", version="1.1.1"),
                image=image2,
            ),
        ]

        # Create store structure manually
        store_root = os.path.join(str(tmp_path), ".yardstick")
        os.makedirs(store_root, exist_ok=True)

        env = ValidateTestEnv(
            root=str(tmp_path),
            config_path=os.path.join(str(tmp_path), ".yardstick.yaml"),
            store_root=store_root,
            result_set_name="multi-image-test",
        )

        base_time = datetime.datetime.now(tz=datetime.timezone.utc)

        # Create all scan configurations with consistent timestamps
        ref_config1 = create_scan_configuration(
            image=image1,
            tool_name="grype[reference]",
            tool_version="v1.0.0",
            tool_label="reference",
            timestamp=base_time,
        )
        cand_config1 = create_scan_configuration(
            image=image1,
            tool_name="grype[candidate]",
            tool_version="v1.1.0",
            tool_label="candidate",
            timestamp=base_time + datetime.timedelta(seconds=1),
        )
        ref_config2 = create_scan_configuration(
            image=image2,
            tool_name="grype[reference]",
            tool_version="v1.0.0",
            tool_label="reference",
            timestamp=base_time + datetime.timedelta(seconds=2),
        )
        cand_config2 = create_scan_configuration(
            image=image2,
            tool_name="grype[candidate]",
            tool_version="v1.1.0",
            tool_label="candidate",
            timestamp=base_time + datetime.timedelta(seconds=3),
        )

        # Save all scan results
        save_scan_result(env, ref_config1, create_grype_output(matches1, image1))
        save_scan_result(env, cand_config1, create_grype_output(matches1, image1))
        save_scan_result(env, ref_config2, create_grype_output(matches2, image2))
        save_scan_result(env, cand_config2, create_grype_output(matches2, image2))

        # Save result set with all configs
        save_result_set(
            env,
            [
                (ref_config1, "reference"),
                (cand_config1, "candidate"),
                (ref_config2, "reference"),
                (cand_config2, "candidate"),
            ],
        )

        # Save labels
        save_label_entries(env, labels)

        # Create and save config
        config = {
            "store_root": store_root,
            "result-sets": {
                env.result_set_name: {
                    "description": "Multi-image test result set",
                    "declared": [
                        {"image": image1, "tool": "grype[reference]@v1.0.0", "label": "reference"},
                        {"image": image1, "tool": "grype[candidate]@v1.1.0", "label": "candidate"},
                        {"image": image2, "tool": "grype[reference]@v1.0.0", "label": "reference"},
                        {"image": image2, "tool": "grype[candidate]@v1.1.0", "label": "candidate"},
                    ],
                    "validations": [
                        {
                            "name": "default",
                            "max_f1_regression": 0.0,
                            "max_new_false_negatives": 0,
                            "max_unlabeled_percent": 100,
                            "reference_tool_label": "reference",
                            "candidate_tool_label": "candidate",
                            "fail_on_empty_match_set": True,
                        },
                    ],
                },
            },
        }

        with open(env.config_path, "w") as f:
            yaml.dump(config, f)

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output
        # Both images should be mentioned in output
        assert image1 in result.output or "sha256:a" in result.output
        assert image2 in result.output or "sha256:b" in result.output


class TestValidateEdgeCases:
    """Tests for edge cases and error handling."""

    def test_validate_with_only_fp_matches(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When all matches are false positives, F1 score should be 0.
        """
        matches = [
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

        # All matches are FPs
        labels = [
            create_label_entry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="libc", version="2.29"),
                image=DEFAULT_IMAGE,
            ),
            create_label_entry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0002",
                package=artifact.Package(name="openssl", version="1.1.1"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        # Should pass since both tools have same F1 (no regression)
        assert result.exit_code == 0, f"Expected pass, got: {result.output}"

    def test_validate_with_mixed_labeled_and_unlabeled(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        Matches without labels should be counted as indeterminate.
        """
        matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0002",  # No label for this
                package_name="openssl",
                package_version="1.1.1",
            ),
        ]

        # Only one match has a label
        labels = [
            create_label_entry(
                label=artifact.Label.TruePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="libc", version="2.29"),
                image=DEFAULT_IMAGE,
            ),
        ]

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=matches,
            matches_candidate=matches,
            labels=labels,
            max_unlabeled_percent=100,  # Allow unlabeled for this test
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output

    def test_validate_candidate_finds_new_tp(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """
        When candidate finds a new TP that reference missed, this is an improvement.
        """
        # Reference finds one TP
        reference_matches = [
            GrypeMatchEntry(
                vulnerability_id="CVE-2020-0001",
                package_name="libc",
                package_version="2.29",
            ),
        ]

        # Candidate finds both TPs
        candidate_matches = [
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

        labels = [
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

        env = setup_validate_test_env(
            tmp_path=str(tmp_path),
            matches_reference=reference_matches,
            matches_candidate=candidate_matches,
            labels=labels,
        )

        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "validate", "-r", env.result_set_name],
            catch_exceptions=False,
        )

        # Should pass - candidate is better (found more TPs)
        assert result.exit_code == 0, f"Expected pass, got: {result.output}"
        assert "Quality gate passed" in result.output
