"""
Shared pytest fixtures for yardstick validate E2E tests.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from yardstick import artifact

from .helpers import (
    DEFAULT_IMAGE,
    GrypeMatchEntry,
    ValidateTestEnv,
    create_label_entry,
    setup_validate_test_env,
)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_matches() -> list[GrypeMatchEntry]:
    """
    Provide a set of sample matches for testing.

    Returns 5 matches with different CVEs and packages.
    """
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


@pytest.fixture
def sample_labels() -> list[artifact.LabelEntry]:
    """
    Provide labels for the sample matches.

    - CVE-2020-0001: TP (libc vulnerability)
    - CVE-2020-0002: TP (openssl vulnerability)
    - CVE-2020-0003: FP (curl false positive)
    - CVE-2020-0004: TP (nginx vulnerability)
    - CVE-2020-0005: Unclear (python disputed)
    """
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
        create_label_entry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2020-0004",
            package=artifact.Package(name="nginx", version="1.17.0"),
            image=DEFAULT_IMAGE,
        ),
        create_label_entry(
            label=artifact.Label.Unclear,
            vulnerability_id="CVE-2020-0005",
            package=artifact.Package(name="python", version="3.8.0"),
            image=DEFAULT_IMAGE,
        ),
    ]


@pytest.fixture
def identical_results_env(
    tmp_path,
    sample_matches,
    sample_labels,
) -> ValidateTestEnv:
    """
    Environment where reference and candidate find identical matches.
    Should pass validation.
    """
    return setup_validate_test_env(
        tmp_path=str(tmp_path),
        matches_reference=sample_matches,
        matches_candidate=sample_matches,
        labels=sample_labels,
        max_unlabeled_percent=100,  # Allow unclear matches
    )


@pytest.fixture
def improved_results_env(
    tmp_path,
    sample_labels,
) -> ValidateTestEnv:
    """
    Environment where candidate finds fewer FPs than reference.
    Should pass validation (candidate is better).
    """
    # Reference finds all matches including the FP
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
            vulnerability_id="CVE-2020-0003",  # This is a FP
            package_name="curl",
            package_version="7.68.0",
        ),
        GrypeMatchEntry(
            vulnerability_id="CVE-2020-0004",
            package_name="nginx",
            package_version="1.17.0",
        ),
    ]

    # Candidate doesn't find the FP (improved)
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
            vulnerability_id="CVE-2020-0004",
            package_name="nginx",
            package_version="1.17.0",
        ),
    ]

    return setup_validate_test_env(
        tmp_path=str(tmp_path),
        matches_reference=reference_matches,
        matches_candidate=candidate_matches,
        labels=sample_labels,
        max_unlabeled_percent=100,
    )
