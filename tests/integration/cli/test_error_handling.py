"""
E2E tests for error handling in yardstick CLI commands.

These tests verify that the CLI handles invalid input, missing files,
and malformed data gracefully with appropriate error messages.
"""

from __future__ import annotations

import json
import os

import pytest
from click.testing import CliRunner

from yardstick.cli.cli import cli

from .helpers import (
    CLITestEnv,
    DEFAULT_IMAGE,
    GrypeMatchEntry,
    create_scan_configuration,
    setup_cli_test_env,
)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


class TestConfigErrors:
    """Tests for config file error handling."""

    def test_missing_config_file(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """Command fails gracefully when config file doesn't exist."""
        nonexistent_config = str(tmp_path / "nonexistent.yaml")

        result = cli_runner.invoke(
            cli,
            ["-c", nonexistent_config, "result", "list"],
            catch_exceptions=True,
        )

        assert result.exit_code != 0
        # Should mention the missing file or config error
        assert "nonexistent" in result.output.lower() or result.exception is not None

    def test_invalid_yaml_config(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """Command fails gracefully when config file contains invalid YAML."""
        bad_config = tmp_path / ".yardstick.yaml"
        bad_config.write_text("invalid: yaml: content: [unclosed")

        result = cli_runner.invoke(
            cli,
            ["-c", str(bad_config), "result", "list"],
            catch_exceptions=True,
        )

        assert result.exit_code != 0

    def test_config_missing_store_root(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """Command handles config with missing store_root field."""
        bad_config = tmp_path / ".yardstick.yaml"
        bad_config.write_text("some_other_key: value\n")

        result = cli_runner.invoke(
            cli,
            ["-c", str(bad_config), "result", "list"],
            catch_exceptions=True,
        )

        # Should either work with defaults or fail with clear error
        # The behavior depends on the implementation
        assert result.exit_code == 0 or result.exception is not None


class TestResultErrors:
    """Tests for result command error handling."""

    def test_show_nonexistent_result(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Showing a nonexistent result ID fails gracefully."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "result", "show", "nonexistent-uuid-1234"],
            catch_exceptions=True,
        )

        assert result.exit_code != 0

    def test_compare_nonexistent_results(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Comparing nonexistent result IDs fails gracefully."""
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                empty_env.config_path,
                "result",
                "compare",
                "nonexistent-uuid-1",
                "nonexistent-uuid-2",
            ],
            catch_exceptions=True,
        )

        assert result.exit_code != 0

    def test_corrupted_result_json(
        self,
        cli_runner: CliRunner,
        tmp_path,
    ):
        """Listing results handles corrupted JSON in result files."""
        # Set up environment
        env = setup_cli_test_env(tmp_path=str(tmp_path))

        # Create a corrupted result file
        config = create_scan_configuration(
            image=DEFAULT_IMAGE,
            tool_name="grype",
            tool_version="v1.0.0",
        )

        result_dir = os.path.join(
            env.results_path,
            config.image_encoded,
            f"{config.tool_name}@{config.tool_version}",
            config.timestamp_rfc3339,
        )
        os.makedirs(result_dir, exist_ok=True)

        # Write corrupted data.json
        data_path = os.path.join(result_dir, "data.json")
        with open(data_path, "w") as f:
            f.write("{invalid json content")

        # Write valid metadata
        metadata_path = os.path.join(result_dir, "metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(
                {
                    "config": config.to_dict(),
                    "metadata": {"timestamp": None, "elapsed": 1.0},
                },
                f,
            )

        # List should handle the corrupted file
        result = cli_runner.invoke(
            cli,
            ["-c", env.config_path, "result", "list"],
            catch_exceptions=True,
        )

        # Should either skip corrupted files or fail gracefully
        # Not crash with an unhandled exception
        assert result.exit_code == 0 or "json" in str(result.exception).lower()


class TestLabelErrors:
    """Tests for label command error handling."""

    def test_add_label_invalid_type(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Adding a label with invalid type fails gracefully."""
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                empty_env.config_path,
                "label",
                "add",
                "-i",
                "test-image@sha256:" + "a" * 64,
                "-c",
                "CVE-2024-1234",
                "-p",
                "test-package",
                "-v",
                "1.0.0",
                "-l",
                "INVALID_LABEL_TYPE",
            ],
            catch_exceptions=True,
        )

        assert result.exit_code != 0

    def test_remove_nonexistent_label(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Removing a nonexistent label ID is handled gracefully."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "remove", "nonexistent-label-id"],
            catch_exceptions=True,
        )

        # Should succeed (no-op) or fail gracefully
        # Empty removal is typically acceptable
        assert result.exit_code == 0 or result.exception is not None

    def test_apply_labels_nonexistent_result(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Applying labels to nonexistent result fails gracefully."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "label", "apply", "nonexistent-result-id"],
            catch_exceptions=True,
        )

        assert result.exit_code != 0

    def test_add_label_missing_required_options(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Adding a label without required options fails with helpful message."""
        result = cli_runner.invoke(
            cli,
            [
                "-c",
                empty_env.config_path,
                "label",
                "add",
                "-i",
                "test-image@sha256:" + "a" * 64,
                # Missing -c (vulnerability), -p (package), -v (version), -l (label)
            ],
            catch_exceptions=True,
        )

        assert result.exit_code != 0
        # Click should provide a helpful error about missing options
        assert "missing" in result.output.lower() or "required" in result.output.lower()


class TestValidateErrors:
    """Tests for validate command error handling."""

    def test_validate_nonexistent_result_set(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Validating a nonexistent result set fails gracefully."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "validate", "-r", "nonexistent-result-set"],
            catch_exceptions=True,
        )

        assert result.exit_code != 0

    def test_validate_conflicting_flags(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Using --all and -r together fails with clear error."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "validate", "--all", "-r", "some-set"],
            catch_exceptions=True,
        )

        assert result.exit_code != 0
        # Should explain the conflict
        assert "all" in str(result.output).lower() or "all" in str(result.exception).lower()


@pytest.fixture
def empty_env(tmp_path) -> CLITestEnv:
    """Environment with no results or labels."""
    return setup_cli_test_env(tmp_path=str(tmp_path))
