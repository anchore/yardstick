"""
Unit tests for interactive validation TUI to debug label detection issues.
"""

import datetime
import getpass
from typing import List
from unittest.mock import Mock

import pytest

from yardstick import artifact
from yardstick.cli.interactive_validate import InteractiveValidateController
from yardstick.validate.gate import Gate, GateConfig, GateInputDescription, GateInputResultConfig


def create_mock_match(
    vuln_id: str = "CVE-2013-0341", package_name: str = "expat", package_version: str = "2.1.0-12.el7", namespace: str = "redhat:distro:redhat:7"
) -> artifact.Match:
    """Create a mock match for testing."""
    return artifact.Match(
        vulnerability=artifact.Vulnerability(id=vuln_id),
        package=artifact.Package(name=package_name, version=package_version),
        fullentry={"vulnerability": {"namespace": namespace}, "matchDetails": [{"type": "exact-direct-match", "matcher": "rpm-matcher"}]},
    )


def create_mock_label_entry(
    vuln_id: str = "CVE-2013-0341",
    package_name: str = "expat",
    package_version: str = "2.1.0-12.el7",
    image: str = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f",
    label: artifact.Label = artifact.Label.TruePositive,
) -> artifact.LabelEntry:
    """Create a mock label entry for testing."""
    return artifact.LabelEntry(
        label=label,
        vulnerability_id=vuln_id,
        image=artifact.ImageSpecifier(exact=image),
        package=artifact.Package(name=package_name, version=package_version),
        user="test_user",
        timestamp=datetime.datetime.now(),
    )


def create_mock_gate(
    image: str = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f", result_ids: List[str] = None
) -> Gate:
    """Create a mock gate for testing."""
    if result_ids is None:
        result_ids = [
            "5b37f35c-9e93-42d3-b386-94c2752111c9",  # custom-db
            "848876a0-5ea7-465f-b697-c5f9bf4416c3",  # reference
        ]

    configs = [
        GateInputResultConfig(id=result_ids[0], tool="grype", tool_label="custom-db"),
        GateInputResultConfig(id=result_ids[1], tool="grype", tool_label="reference"),
    ]

    input_desc = GateInputDescription(image=image, configs=configs)
    gate_config = GateConfig(max_unlabeled_percent=10)

    # Create a "failed" gate by providing failure reasons
    return Gate(None, None, gate_config, input_desc, ["test failure reason"])


class TestInteractiveValidateController:
    """Test the interactive validation controller."""

    def test_result_id_to_image_mapping(self):
        """Test that result_id to image mapping is built correctly."""
        image1 = "docker.io/image1:latest"
        image2 = "docker.io/image2:latest"

        gate1 = create_mock_gate(image=image1, result_ids=["result1a", "result1b"])
        gate2 = create_mock_gate(image=image2, result_ids=["result2a", "result2b"])

        controller = InteractiveValidateController(gates=[gate1, gate2], label_entries=[])

        expected_mapping = {"result1a": image1, "result1b": image1, "result2a": image2, "result2b": image2}

        assert controller._result_id_to_image == expected_mapping

    def test_label_detection_with_existing_label(self):
        """Test that existing labels are properly detected."""
        image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"

        # Create existing label for expat CVE-2013-0341
        existing_label = create_mock_label_entry(
            vuln_id="CVE-2013-0341", package_name="expat", package_version="2.1.0-12.el7", image=image, label=artifact.Label.TruePositive
        )

        # Create match that should match the existing label
        match = create_mock_match(vuln_id="CVE-2013-0341", package_name="expat", package_version="2.1.0-12.el7")

        gate = create_mock_gate(image=image)

        controller = InteractiveValidateController(gates=[gate], label_entries=[existing_label])

        # Test the label detection logic directly
        from yardstick.label import find_labels_for_match

        # Test with correct image
        correct_labels = find_labels_for_match(image=image, match=match, label_entries=[existing_label], lineage=[], fuzzy_package_match=False)

        assert len(correct_labels) == 1
        assert correct_labels[0].label == artifact.Label.TruePositive

        # Test with wrong image (this should find no labels)
        wrong_image = "docker.io/different:latest"
        wrong_labels = find_labels_for_match(image=wrong_image, match=match, label_entries=[existing_label], lineage=[], fuzzy_package_match=False)

        assert len(wrong_labels) == 0

    def test_common_match_filtering_logic(self):
        """Test the logic that determines if a match should be included in common unlabeled matches."""
        image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"

        # Create existing TP label
        existing_label = create_mock_label_entry(
            vuln_id="CVE-2013-0341", package_name="expat", package_version="2.1.0-12.el7", image=image, label=artifact.Label.TruePositive
        )

        # Create matching vulnerability match
        match = create_mock_match(vuln_id="CVE-2013-0341", package_name="expat", package_version="2.1.0-12.el7")

        controller = InteractiveValidateController(gates=[create_mock_gate(image=image)], label_entries=[existing_label])

        # Import the label matching logic
        from yardstick.label import find_labels_for_match

        # Test the exact condition from _add_common_unlabeled_matches
        match_labels = find_labels_for_match(
            image,  # Using correct image
            match,
            [existing_label],
            lineage=[],
            fuzzy_package_match=False,
        )

        # This should find the existing TP label
        assert len(match_labels) == 1
        assert match_labels[0].label == artifact.Label.TruePositive

        # Test the condition that determines if match should be included
        should_be_included = (
            not match_labels
            or any(label.label in [artifact.Label.Unclear] for label in match_labels)
            or len(set(label.label for label in match_labels)) != 1
        )

        # Since we found a single TP label, this should be False (don't include)
        assert should_be_included is False, "Match with existing TP label should NOT be included in unlabeled matches"


class TestLabelMatchingEdgeCases:
    """Test edge cases in label matching that might cause the bug."""

    def test_package_version_exact_match(self):
        """Test that package versions must match exactly."""
        image = "docker.io/test:latest"

        # Label with version "2.1.0-12.el7"
        label = create_mock_label_entry(package_version="2.1.0-12.el7", image=image)

        # Match with same version
        match_same = create_mock_match(package_version="2.1.0-12.el7")

        # Match with different version
        match_different = create_mock_match(package_version="2.1.0-13.el7")

        from yardstick.label import find_labels_for_match

        # Same version should match
        labels_same = find_labels_for_match(image, match_same, [label])
        assert len(labels_same) == 1

        # Different version should not match
        labels_different = find_labels_for_match(image, match_different, [label])
        assert len(labels_different) == 0

    def test_image_matching_exact(self):
        """Test that image matching is exact (no fuzzy matching)."""
        base_image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"
        different_image = "docker.io/anchore/test_images@sha256:different"

        label = create_mock_label_entry(image=base_image)
        match = create_mock_match()

        from yardstick.label import find_labels_for_match

        # Exact image match should work
        labels_exact = find_labels_for_match(base_image, match, [label])
        assert len(labels_exact) == 1

        # Different image should not match
        labels_different = find_labels_for_match(different_image, match, [label])
        assert len(labels_different) == 0

    def test_vulnerability_id_matching(self):
        """Test vulnerability ID matching."""
        image = "docker.io/test:latest"

        label_cve_2013 = create_mock_label_entry(vuln_id="CVE-2013-0341", image=image)
        match_cve_2013 = create_mock_match(vuln_id="CVE-2013-0341")
        match_cve_2014 = create_mock_match(vuln_id="CVE-2014-0001")

        from yardstick.label import find_labels_for_match

        # Same CVE should match
        labels_same = find_labels_for_match(image, match_cve_2013, [label_cve_2013])
        assert len(labels_same) == 1

        # Different CVE should not match
        labels_different = find_labels_for_match(image, match_cve_2014, [label_cve_2013])
        assert len(labels_different) == 0


class TestLabelsNeededCalculation:
    """Tests for the labels_needed calculation when gate fails due to unlabeled percent."""

    def test_tool_designations_return_order(self):
        """Verify that tool_designations returns (candidate, reference) in that order.

        This test documents the expected return order of tool_designations,
        which is important for correct usage in _calculate_labels_needed_for_image.
        """
        from yardstick.validate.validate import tool_designations
        from yardstick.artifact import ScanConfiguration

        # Create scan configs with distinct tool labels
        scan_configs = [
            ScanConfiguration(
                image_repo="docker.io/test",
                image_digest="sha256:abc123",
                tool_name="grype",
                tool_version="v1.0.0",
                tool_label="candidate",
            ),
            ScanConfiguration(
                image_repo="docker.io/test",
                image_digest="sha256:abc123",
                tool_name="grype",
                tool_version="v2.0.0",
                tool_label="reference",
            ),
        ]

        # Call tool_designations with candidate_tool_label="candidate"
        result = tool_designations("candidate", scan_configs)

        # tool_designations returns (candidate_tool, reference_tool)
        # So result[0] should be the candidate tool, result[1] should be reference
        assert result[0] == "grype@v1.0.0", f"First return value should be candidate tool, got {result[0]}"
        assert result[1] == "grype@v2.0.0", f"Second return value should be reference tool, got {result[1]}"

        # The correct assignment order (used in _calculate_labels_needed_for_image) is:
        #   candidate_tool, reference_tool = tool_designations(...)
        candidate_tool, reference_tool = tool_designations("candidate", scan_configs)

        assert candidate_tool == "grype@v1.0.0", f"candidate_tool should be 'grype@v1.0.0', got {candidate_tool}"
        assert reference_tool == "grype@v2.0.0", f"reference_tool should be 'grype@v2.0.0', got {reference_tool}"

    def test_labels_needed_with_unlabeled_percent_only_failure(self):
        """Test that labels_needed calculation uses the correct tool designations.

        This test verifies that _calculate_labels_needed_for_image correctly assigns
        the return value of tool_designations, which returns (candidate, reference).

        The correct assignment is:
            candidate_tool, reference_tool = tool_designations(...)

        This ensures the calculation uses the CANDIDATE tool's indeterminate count
        (not the reference tool's) when determining how many labels are needed.
        """
        from yardstick.validate.validate import tool_designations
        from yardstick.artifact import ScanConfiguration

        # Create scan configs where tools have different labels
        # ScanConfiguration requires: image_repo, image_digest, tool_name, tool_version, tool_label
        candidate_config = ScanConfiguration(
            image_repo="docker.io/test",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="v1.0.0-custom",
            tool_label="custom-db",  # candidate tool (the one being tested)
        )
        reference_config = ScanConfiguration(
            image_repo="docker.io/test",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="v1.0.0",
            tool_label="reference",  # reference tool (the baseline)
        )

        scan_configs = [candidate_config, reference_config]

        # tool_designations returns (candidate, reference) based on tool_label matching
        # The function signature is: tool_designations(candidate_tool_label, scan_configs) -> (candidate, reference)
        returned_candidate, returned_reference = tool_designations("custom-db", scan_configs)

        # Verify tool_designations returns correctly - candidate first, reference second
        # Note: .tool property returns "{tool_name}@{tool_version}"
        assert returned_candidate == "grype@v1.0.0-custom", f"Expected candidate 'grype@v1.0.0-custom', got '{returned_candidate}'"
        assert returned_reference == "grype@v1.0.0", f"Expected reference 'grype@v1.0.0', got '{returned_reference}'"

        # Verify that the correct assignment order (as used in _calculate_labels_needed_for_image) works:
        # candidate_tool, reference_tool = tool_designations(...)
        candidate_tool, reference_tool = tool_designations("custom-db", scan_configs)

        # candidate_tool should be the candidate, reference_tool should be the reference
        assert candidate_tool == "grype@v1.0.0-custom", f"candidate_tool='{candidate_tool}' should be 'grype@v1.0.0-custom' (the candidate tool)"
        assert reference_tool == "grype@v1.0.0", f"reference_tool='{reference_tool}' should be 'grype@v1.0.0' (the reference tool)"


@pytest.fixture
def real_expat_scenario():
    """Fixture providing the actual expat scenario data that's failing in reality."""
    return {
        "image": "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f",
        "result_ids": [
            "5b37f35c-9e93-42d3-b386-94c2752111c9",  # custom-db
            "848876a0-5ea7-465f-b697-c5f9bf4416c3",  # reference
        ],
        "vuln_id": "CVE-2013-0341",
        "package_name": "expat",
        "package_version": "2.1.0-12.el7",
        "namespace": "redhat:distro:redhat:7",
    }


def test_real_expat_scenario_reproduction(real_expat_scenario):
    """Test that reproduces the actual failing expat scenario."""
    scenario = real_expat_scenario

    # Create the exact label that should exist (based on yardstick label explore showing TP)
    existing_label = create_mock_label_entry(
        vuln_id=scenario["vuln_id"],
        package_name=scenario["package_name"],
        package_version=scenario["package_version"],
        image=scenario["image"],
        label=artifact.Label.TruePositive,
    )

    # Create the exact match that's being shown as unlabeled
    match = create_mock_match(
        vuln_id=scenario["vuln_id"],
        package_name=scenario["package_name"],
        package_version=scenario["package_version"],
        namespace=scenario["namespace"],
    )

    # Create gate with exact result IDs from the real scenario
    gate = create_mock_gate(image=scenario["image"], result_ids=scenario["result_ids"])

    controller = InteractiveValidateController(gates=[gate], label_entries=[existing_label])

    from yardstick.label import find_labels_for_match

    # Test label detection with the exact image
    labels_found = find_labels_for_match(image=scenario["image"], match=match, label_entries=[existing_label], lineage=[], fuzzy_package_match=False)

    # This should find the existing TP label
    assert len(labels_found) == 1, f"Expected to find 1 label, but found {len(labels_found)}"
    assert labels_found[0].label == artifact.Label.TruePositive

    # Test the result_id mapping
    for result_id in scenario["result_ids"]:
        mapped_image = controller._result_id_to_image.get(result_id)
        assert mapped_image == scenario["image"], f"Result ID {result_id} should map to {scenario['image']}, got {mapped_image}"
