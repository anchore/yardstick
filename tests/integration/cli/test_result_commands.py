"""
E2E tests for yardstick result CLI commands.

These tests exercise the result subcommands:
- result list
- result clear
- result compare
- result show
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from yardstick.cli.cli import cli

from .helpers import CLITestEnv, DEFAULT_IMAGE


class TestResultList:
    """Tests for 'yardstick result list' command."""

    def test_list_empty_store(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Listing results in empty store returns empty output."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "result", "list"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Empty store should produce empty or minimal output
        assert result.output.strip() == ""

    def test_list_single_result(
        self,
        cli_runner: CliRunner,
        env_with_single_result: CLITestEnv,
    ):
        """Listing results shows the captured scan result."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "list"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "grype@v1.0.0" in result.output
        assert "test.io/test-image" in result.output

    def test_list_multiple_results(
        self,
        cli_runner: CliRunner,
        env_with_two_results: CLITestEnv,
    ):
        """Listing results shows all captured scan results."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_two_results.config_path, "result", "list"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "grype@v1.0.0" in result.output
        assert "grype@v1.1.0" in result.output

    def test_list_with_tool_filter(
        self,
        cli_runner: CliRunner,
        env_with_two_results: CLITestEnv,
    ):
        """Filtering by tool name shows only matching results."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_two_results.config_path, "result", "list", "-t", "v1.0.0"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert "grype@v1.0.0" in result.output
        assert "grype@v1.1.0" not in result.output

    def test_list_ids_only(
        self,
        cli_runner: CliRunner,
        env_with_single_result: CLITestEnv,
    ):
        """Listing with --ids flag shows only result IDs."""
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should be a UUID-like string, not the full table output
        output = result.output.strip()
        assert len(output) > 0
        # Should not contain table-like content
        assert "grype@v1.0.0" not in output


class TestResultClear:
    """Tests for 'yardstick result clear' command."""

    def test_clear_empty_store(
        self,
        cli_runner: CliRunner,
        empty_env: CLITestEnv,
    ):
        """Clearing an empty store succeeds."""
        result = cli_runner.invoke(
            cli,
            ["-c", empty_env.config_path, "result", "clear"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    def test_clear_removes_results(
        self,
        cli_runner: CliRunner,
        env_with_single_result: CLITestEnv,
    ):
        """Clearing removes all results from the store."""
        # Verify result exists
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "list"],
            catch_exceptions=False,
        )
        assert "grype@v1.0.0" in list_result.output

        # Clear results
        clear_result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "clear"],
            catch_exceptions=False,
        )
        assert clear_result.exit_code == 0

        # Verify results are gone
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "list"],
            catch_exceptions=False,
        )
        assert list_result.output.strip() == ""


class TestResultCompare:
    """Tests for 'yardstick result compare' command."""

    def test_compare_two_results(
        self,
        cli_runner: CliRunner,
        env_with_two_results: CLITestEnv,
    ):
        """Comparing two results shows differences."""
        # First get the result IDs
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_two_results.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        ids = list_result.output.strip().split("\n")
        assert len(ids) == 2

        # Compare the results
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_two_results.config_path, "result", "compare", ids[0], ids[1]],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should show some comparison output
        # The second result has one additional match (CVE-2020-0004)
        assert "CVE-2020-0004" in result.output or "v1.1.0-only" in result.output.replace(" ", "")

    def test_compare_same_version_results(
        self,
        cli_runner: CliRunner,
        env_with_single_result: CLITestEnv,
    ):
        """Comparing results from the same tool version completes successfully."""
        # Get the result ID
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        result_id = list_result.output.strip()

        # Compare result with itself - just verify command completes
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "compare", result_id, result_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0

    def test_compare_with_summary_flag(
        self,
        cli_runner: CliRunner,
        env_with_two_results: CLITestEnv,
    ):
        """Compare with --summary shows condensed output."""
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_two_results.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        ids = list_result.output.strip().split("\n")

        result = cli_runner.invoke(
            cli,
            ["-c", env_with_two_results.config_path, "result", "compare", "--summary", ids[0], ids[1]],
            catch_exceptions=False,
        )
        assert result.exit_code == 0


class TestResultShow:
    """Tests for 'yardstick result show' command."""

    def test_show_result_by_id(
        self,
        cli_runner: CliRunner,
        env_with_single_result: CLITestEnv,
    ):
        """Showing a result by ID displays match details."""
        # Get the result ID
        list_result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "list", "--ids"],
            catch_exceptions=False,
        )
        result_id = list_result.output.strip()

        # Show the result
        result = cli_runner.invoke(
            cli,
            ["-c", env_with_single_result.config_path, "result", "show", result_id],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # Should show the matches from our fixture
        assert "CVE-2020-0001" in result.output
        assert "libc" in result.output
