"""
E2E tests for yardstick label CLI commands.

These tests exercise the label subcommands:
- label list
- label add
- label remove
- label apply
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from yardstick.cli.cli import cli

from .helpers import CLITestEnv, DEFAULT_IMAGE


class TestLabelList:
    """Tests for 'yardstick label list' command."""

    def test_list_empty_store(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Listing labels in empty store returns empty output."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "list"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    def test_list_shows_labels(
        self,
        cli_runner: CliRunner,
        env_with_labels: CLITestEnv,
    ):
        """Listing labels shows stored label entries."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "label", "list"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should show our fixture labels
        assert "CVE-2020-0001" in result.output
        assert "CVE-2020-0002" in result.output
        assert "CVE-2020-0003" in result.output

    def test_list_with_image_filter(
        self,
        cli_runner: CliRunner,
        env_with_labels: CLITestEnv,
    ):
        """Filtering by image shows only matching labels."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "label", "list", "-i", DEFAULT_IMAGE],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should show labels for this image
        assert "CVE-2020-0001" in result.output

    def test_list_summarize_flag(
        self,
        cli_runner: CliRunner,
        env_with_labels: CLITestEnv,
    ):
        """Listing with --summarize shows condensed output."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "label", "list", "--summarize"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0


class TestLabelAdd:
    """Tests for 'yardstick label add' command."""

    def test_add_label(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Adding a label creates it in the store."""
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                empty_env.config_path,
                "label",
                "add",
                "-i",
                "test-image@sha256:" + "b" * 64,
                "-c",
                "CVE-2024-1234",
                "-p",
                "test-package",
                "-v",
                "1.0.0",
                "-l",
                "TP",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should output the new label ID
        label_id = result.output.strip()
        assert len(label_id) > 0

        # Verify label was created
        list_result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "list"],
            catch_exceptions=False,
        )
        assert "CVE-2024-1234" in list_result.output

    def test_add_label_with_note(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Adding a label with a note stores the note."""
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                empty_env.config_path,
                "label",
                "add",
                "-i",
                "test-image@sha256:" + "c" * 64,
                "-c",
                "CVE-2024-5678",
                "-p",
                "another-package",
                "-v",
                "2.0.0",
                "-l",
                "FP",
                "-n",
                "This is a test note",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    def test_add_label_various_types(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Can add labels of different types (TP, FP, unclear)."""
        for label_type, vuln_id in [("TP", "CVE-2024-0001"), ("FP", "CVE-2024-0002"), ("unclear", "CVE-2024-0003")]:
            result = cli_runner.invoke(
                cli,
                [
                    "-c",
                    empty_env.config_path,
                    "label",
                    "add",
                    "-i",
                    f"test-image-{label_type}@sha256:" + "d" * 64,
                    "-c",
                    vuln_id,
                    "-p",
                    "pkg",
                    "-v",
                    "1.0.0",
                    "-l",
                    label_type,
                ],
                catch_exceptions=False,
            )
            assert result.exit_code == 0, f"Failed to add {label_type} label"


class TestLabelRemove:
    """Tests for 'yardstick label remove' command."""

    def test_remove_label(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Removing a label deletes it from the store."""
        # First add a label
        add_result = cli_runner.invoke(
            cli,
            [
                "-c",
                empty_env.config_path,
                "label",
                "add",
                "-i",
                "test-image@sha256:" + "e" * 64,
                "-c",
                "CVE-2024-9999",
                "-p",
                "removable-pkg",
                "-v",
                "1.0.0",
                "-l",
                "TP",
            ],
            catch_exceptions=False,
        )
        label_id = add_result.output.strip()

        # Verify it exists
        list_result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "list"],
            catch_exceptions=False,
        )
        assert "CVE-2024-9999" in list_result.output

        # Remove it
        remove_result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "remove", label_id],
            catch_exceptions=False,
        )
        assert remove_result.exit_code == 0
        assert label_id in remove_result.output

        # Verify it's gone
        list_result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "list"],
            catch_exceptions=False,
        )
        assert "CVE-2024-9999" not in list_result.output

    def test_remove_multiple_labels(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Can remove multiple labels at once."""
        # Add two labels
        ids = []
        for i, vuln in enumerate(["CVE-2024-1111", "CVE-2024-2222"]):
            result = cli_runner.invoke(
                cli,
                [
                    "-c",
                    empty_env.config_path,
                    "label",
                    "add",
                    "-i",
                    f"test-image-{i}@sha256:" + "f" * 64,
                    "-c",
                    vuln,
                    "-p",
                    "pkg",
                    "-v",
                    "1.0.0",
                    "-l",
                    "TP",
                ],
                catch_exceptions=False,
            )
            ids.append(result.output.strip())

        # Remove both
        remove_result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "remove", *ids],
            catch_exceptions=False,
        )
        assert remove_result.exit_code == 0


class TestLabelApply:
    """Tests for 'yardstick label apply' command."""

    def test_apply_shows_matching_labels(
        self,
        cli_runner: CliRunner,
        env_with_labels: CLITestEnv,
    ):
        """Apply shows labels that match the scan result."""
        # Get the result ID
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        result_id = list_result.output.strip()

        # Apply labels
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "label", "apply", result_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should show matched labels
        # Our fixture has 3 labels that match the 3 matches in the result
        assert "TruePositive" in result.output or "FalsePositive" in result.output

    def test_apply_with_ids_flag(
        self,
        cli_runner: CliRunner,
        env_with_labels: CLITestEnv,
    ):
        """Apply with --id flag shows only label IDs."""
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        result_id = list_result.output.strip()

        result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "label", "apply", "--id", result_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0


class TestLabelImages:
    """Tests for 'yardstick label images' command."""

    def test_list_images_from_labels(
        self,
        cli_runner: CliRunner,
        env_with_labels: CLITestEnv,
    ):
        """List images shows images that have labels."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_labels.config_path, "label", "images"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "test.io/test-image" in result.output
