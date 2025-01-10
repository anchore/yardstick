# Sample images
from unittest.mock import patch, MagicMock

import pytest

from yardstick import comparison
from yardstick.artifact import (
    ScanResult,
    ScanConfiguration,
    Package,
    Vulnerability,
    LabelEntry,
    Label,
    Match,
)
from yardstick.validate import validate_image, GateConfig, Delta


@pytest.fixture()
def compare_results_no_matches():
    return MagicMock(results=[MagicMock(matches=[]), MagicMock(matches=[])])


@pytest.fixture()
def compare_results_identical_matches():
    return MagicMock(
        results=[
            MagicMock(
                matches=[MagicMock()],
                unique={},
            ),
            MagicMock(
                matches=[MagicMock()],
                unique={},
            ),
        ]
    )


@patch("yardstick.compare_results")
def test_validate_fail_on_empty_matches(
    mock_compare_results, compare_results_no_matches
):
    mock_compare_results.return_value = compare_results_no_matches
    gate = validate_image(
        "some image",
        GateConfig(fail_on_empty_match_set=True),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert not gate.passed()
    assert (
        "gate configured to fail on empty matches, and no matches found" in gate.reasons
    )
    mock_compare_results.assert_called_once_with(
        descriptions=["some-str", "another-str"],
        year_max_limit=None,
        matches_filter=None,
    )


@patch("yardstick.compare_results")
def test_validate_dont_fail_on_empty_matches(
    mock_compare_results, compare_results_no_matches
):
    mock_compare_results.return_value = compare_results_no_matches
    gate = validate_image(
        "some image",
        GateConfig(fail_on_empty_match_set=False),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert gate.passed()
    mock_compare_results.assert_called_once_with(
        descriptions=["some-str", "another-str"],
        year_max_limit=None,
        matches_filter=None,
    )


@patch("yardstick.compare_results")
def test_validate_pass_early_identical_match_sets(
    mock_compare_results, compare_results_identical_matches
):
    mock_compare_results.return_value = compare_results_identical_matches
    gate = validate_image(
        "some image",
        GateConfig(fail_on_empty_match_set=False),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert gate.passed()
    mock_compare_results.assert_called_once_with(
        descriptions=["some-str", "another-str"],
        year_max_limit=None,
        matches_filter=None,
    )


@pytest.fixture()
def reference_config():
    return ScanConfiguration(
        image_repo="docker.io/anchore/test_images",
        image_digest="f" * 64,
        tool_name="grype",
        tool_version="123",
        tool_label="reference",
        ID="reference-config-uuid",
    )


@pytest.fixture()
def candidate_config():
    return ScanConfiguration(
        image_repo="docker.io/anchore/test_images",
        image_digest="f" * 64,
        tool_name="grype",
        tool_version="1234",
        tool_label="candidate",
        ID="candidate-config-uuid",
    )


@pytest.fixture()
def matches(packages, vulns):
    libc, nginx, openssl, zlib = packages
    vuln1, vuln2, vuln3, vuln4 = vulns
    match1 = Match(
        package=libc,
        vulnerability=vuln1,
    )
    match2 = Match(
        package=nginx,
        vulnerability=vuln2,
    )
    match3 = Match(
        package=openssl,
        vulnerability=vuln3,
    )
    match4 = Match(
        package=zlib,
        vulnerability=vuln4,
    )
    return [match1, match2, match3, match4]


@pytest.fixture()
def reference_results(reference_config, packages, matches):
    match1, match2, match3, match4 = matches
    return ScanResult(
        config=reference_config,
        matches=[match1, match2, match3],
        packages=packages,
    )


@pytest.fixture()
def candidate_results(candidate_config, packages, matches):
    match1, match2, match3, match4 = matches
    return ScanResult(
        config=candidate_config,
        matches=[match1, match2, match3, match4],
        packages=packages,
    )


@pytest.fixture()
def non_identical_results(reference_results, candidate_results):
    return comparison.ByPreservedMatch(results=[reference_results, reference_results])


@pytest.fixture()
def vulns():
    vuln1 = Vulnerability(id="CVE-2021-1234")
    vuln2 = Vulnerability(id="CVE-2021-0002")
    vuln3 = Vulnerability(id="CVE-2021-5678")
    vuln4 = Vulnerability(id="CVE-2021-8888")
    return vuln1, vuln2, vuln3, vuln4


@pytest.fixture()
def packages():
    libc = Package(name="libc", version="2.29")
    nginx = Package(name="nginx", version="1.17")
    openssl = Package(name="openssl", version="1.1.1")
    zlib = Package(name="zlib", version="1.2.11")
    return [libc, nginx, openssl, zlib]


@pytest.fixture()
def deltas():
    return [
        MagicMock(spec=Delta),
        MagicMock(spec=Delta),
    ]


@pytest.fixture()
def label_entries(matches):
    match1, match2, match3, match4 = matches
    return [
        LabelEntry(
            Label.TruePositive,
            vulnerability_id=match1.vulnerability.id,
            package=match1.package,
        ),
        LabelEntry(
            Label.FalsePositive,
            vulnerability_id=match2.vulnerability.id,
            package=match2.package,
        ),
        LabelEntry(
            Label.TruePositive,
            vulnerability_id=match3.vulnerability.id,
            package=match3.package,
        ),
        LabelEntry(
            Label.TruePositive,
            vulnerability_id=match4.vulnerability.id,
            package=match4.package,
        ),
    ]


@pytest.fixture()
def label_comparison_results(reference_results, candidate_results, label_entries):
    compare_configuration = {
        "year_max_limit": 2021,
        "year_from_cve_only": True,
    }
    return (
        [reference_results, candidate_results],
        [],  # label_entries is not used
        {
            reference_results.ID: comparison.AgainstLabels(
                result=reference_results,
                label_entries=label_entries,
                lineage=[],
                compare_configuration=compare_configuration,
            ),
            candidate_results.ID: comparison.AgainstLabels(
                result=candidate_results,
                label_entries=label_entries,
                lineage=[],
                compare_configuration=compare_configuration,
            ),
        },
        MagicMock(name="stats_by_image_tool_pair"),
    )


@patch("yardstick.compare_results")
@patch("yardstick.compare_results_against_labels")
@patch("yardstick.validate.delta.compute_deltas")
def test_validate_non_identical_match_sets(
    mock_compute_deltas,
    mock_compare_against_labels,
    mock_compare_results,
    non_identical_results,
    deltas,
    label_comparison_results,
):
    mock_compare_results.return_value = non_identical_results
    mock_compare_against_labels.return_value = label_comparison_results
    mock_compute_deltas.return_value = deltas
    gate = validate_image(
        f"docker.io/anchore/test_images@{'f' * 64}",
        GateConfig(fail_on_empty_match_set=False),
        descriptions=["some-str", "another-str"],
        always_run_label_comparison=False,
        verbosity=0,
    )
    assert gate.passed()
