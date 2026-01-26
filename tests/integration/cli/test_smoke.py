"""
Smoke tests for yardstick CLI.

These tests verify that the CLI can be invoked without errors,
catching import errors and basic configuration issues.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from yardstick.cli.cli import cli


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


class TestCLISmoke:
    """Basic smoke tests to verify CLI is functional."""

    def test_main_help(self, cli_runner: CliRunner):
        """Main help command works."""
        result = cli_runner.invoke(cli, ["--help"], catch_exceptions=False)

        assert result.exit_code == 0
        assert "yardstick" in result.output.lower() or "usage" in result.output.lower()

    def test_result_help(self, cli_runner: CliRunner):
        """Result subcommand help works."""
        result = cli_runner.invoke(cli, ["result", "--help"], catch_exceptions=False)

        assert result.exit_code == 0
        assert "result" in result.output.lower()

    def test_result_list_help(self, cli_runner: CliRunner):
        """Result list help works."""
        result = cli_runner.invoke(cli, ["result", "list", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_result_compare_help(self, cli_runner: CliRunner):
        """Result compare help works."""
        result = cli_runner.invoke(cli, ["result", "compare", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_result_show_help(self, cli_runner: CliRunner):
        """Result show help works."""
        result = cli_runner.invoke(cli, ["result", "show", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_result_clear_help(self, cli_runner: CliRunner):
        """Result clear help works."""
        result = cli_runner.invoke(cli, ["result", "clear", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_label_help(self, cli_runner: CliRunner):
        """Label subcommand help works."""
        result = cli_runner.invoke(cli, ["label", "--help"], catch_exceptions=False)

        assert result.exit_code == 0
        assert "label" in result.output.lower()

    def test_label_list_help(self, cli_runner: CliRunner):
        """Label list help works."""
        result = cli_runner.invoke(cli, ["label", "list", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_label_add_help(self, cli_runner: CliRunner):
        """Label add help works."""
        result = cli_runner.invoke(cli, ["label", "add", "--help"], catch_exceptions=False)

        assert result.exit_code == 0
        # Should show required options
        assert "image" in result.output.lower() or "-i" in result.output

    def test_label_remove_help(self, cli_runner: CliRunner):
        """Label remove help works."""
        result = cli_runner.invoke(cli, ["label", "remove", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_label_apply_help(self, cli_runner: CliRunner):
        """Label apply help works."""
        result = cli_runner.invoke(cli, ["label", "apply", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_label_compare_help(self, cli_runner: CliRunner):
        """Label compare help works."""
        result = cli_runner.invoke(cli, ["label", "compare", "--help"], catch_exceptions=False)

        assert result.exit_code == 0

    def test_validate_help(self, cli_runner: CliRunner):
        """Validate command help works."""
        result = cli_runner.invoke(cli, ["validate", "--help"], catch_exceptions=False)

        assert result.exit_code == 0
        assert "validate" in result.output.lower() or "result-set" in result.output.lower()

    def test_version_flag_if_exists(self, cli_runner: CliRunner):
        """Version flag works if implemented."""
        result = cli_runner.invoke(cli, ["--version"], catch_exceptions=True)

        # Version flag may or may not be implemented
        # If implemented, should succeed; if not, exit code 2 (Click's "no such option")
        assert result.exit_code in (0, 2)
