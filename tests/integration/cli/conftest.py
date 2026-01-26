"""
Shared pytest fixtures for yardstick CLI E2E tests.
"""

from __future__ import annotations

import datetime

import pytest
from click.testing import CliRunner

from yardstick import artifact

from .helpers import (
    DEFAULT_IMAGE,
    CLITestEnv,
    GrypeMatchEntry,
    create_label_entry,
    create_scan_configuration,
    setup_cli_test_env,
)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_matches() -> list[GrypeMatchEntry]:
    """Provide sample vulnerability matches."""
    return [
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


@pytest.fixture
def sample_labels() -> list[artifact.LabelEntry]:
    """Provide sample labels for testing."""
    return [
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


@pytest.fixture
def empty_env(tmp_path) -> CLITestEnv:
    """Environment with no results or labels."""
    return setup_cli_test_env(tmp_path=str(tmp_path))


@pytest.fixture
def env_with_single_result(tmp_path, sample_matches) -> CLITestEnv:
    """Environment with a single scan result."""
    config = create_scan_configuration(
        image=DEFAULT_IMAGE,
        tool_name="grype",
        tool_version="v1.0.0",
    )
    return setup_cli_test_env(
        tmp_path=str(tmp_path),
        scan_results=[(config, sample_matches)],
    )


@pytest.fixture
def env_with_two_results(tmp_path, sample_matches) -> CLITestEnv:
    """Environment with two scan results from different tool versions."""
    base_time = datetime.datetime.now(tz=datetime.timezone.utc)

    config1 = create_scan_configuration(
        image=DEFAULT_IMAGE,
        tool_name="grype",
        tool_version="v1.0.0",
        timestamp=base_time,
    )

    # Second result has one additional match
    matches2 = sample_matches + [
        GrypeMatchEntry(
            vulnerability_id="CVE-2020-0004",
            package_name="nginx",
            package_version="1.17.0",
        ),
    ]
    config2 = create_scan_configuration(
        image=DEFAULT_IMAGE,
        tool_name="grype",
        tool_version="v1.1.0",
        timestamp=base_time + datetime.timedelta(seconds=1),
    )

    return setup_cli_test_env(
        tmp_path=str(tmp_path),
        scan_results=[
            (config1, sample_matches),
            (config2, matches2),
        ],
    )


@pytest.fixture
def env_with_labels(tmp_path, sample_matches, sample_labels) -> CLITestEnv:
    """Environment with a scan result and labels."""
    config = create_scan_configuration(
        image=DEFAULT_IMAGE,
        tool_name="grype",
        tool_version="v1.0.0",
    )
    return setup_cli_test_env(
        tmp_path=str(tmp_path),
        scan_results=[(config, sample_matches)],
        labels=sample_labels,
    )
