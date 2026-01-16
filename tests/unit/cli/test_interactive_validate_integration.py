"""
Integration tests to debug the actual interactive validation flow with real label data.
"""

import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from yardstick import artifact, store
from yardstick.cli.interactive_validate import InteractiveValidateController
from yardstick.validate.gate import Gate, GateConfig, GateInputDescription, GateInputResultConfig


def test_label_entries_loaded_correctly():
    """Test that label entries are loaded correctly from the real workspace."""
    # Get the real label entries that would be loaded in the real scenario
    current_dir = Path(__file__).parent.parent.parent.parent  # Go up to repo root
    quality_dir = current_dir / "tests" / "integration" / "quality"  # Might not exist, but test the pattern

    # For now, just test the structure we expect
    image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"

    # Create a realistic label entry that should match the expat scenario
    expected_label = artifact.LabelEntry(
        label=artifact.Label.TruePositive,
        vulnerability_id="CVE-2013-0341",
        image=artifact.ImageSpecifier(exact=image),
        package=artifact.Package(name="expat", version="2.1.0-12.el7"),
        user="test_user",
        timestamp=artifact.datetime.datetime.now(),
    )

    # Test that find_labels_for_match works with this structure
    from yardstick.label import find_labels_for_match

    match = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2013-0341"),
        package=artifact.Package(name="expat", version="2.1.0-12.el7"),
        fullentry={
            "vulnerability": {"namespace": "redhat:distro:redhat:7"},
            "matchDetails": [{"type": "exact-direct-match", "matcher": "rpm-matcher"}],
        },
    )

    found_labels = find_labels_for_match(image=image, match=match, label_entries=[expected_label], lineage=[])

    assert len(found_labels) == 1
    assert found_labels[0].label == artifact.Label.TruePositive


def test_common_match_collection_without_real_results():
    """Test what happens when common match collection can't find real results."""

    image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"
    result_ids = ["5b37f35c-9e93-42d3-b386-94c2752111c9", "848876a0-5ea7-465f-b697-c5f9bf4416c3"]

    # Create a label that should prevent this match from appearing as unlabeled
    existing_label = artifact.LabelEntry(
        label=artifact.Label.TruePositive,
        vulnerability_id="CVE-2013-0341",
        image=artifact.ImageSpecifier(exact=image),
        package=artifact.Package(name="expat", version="2.1.0-12.el7"),
        user="test_user",
        timestamp=artifact.datetime.datetime.now(),
    )

    # Create gate configuration
    configs = [
        GateInputResultConfig(id=result_ids[0], tool="grype", tool_label="custom-db"),
        GateInputResultConfig(id=result_ids[1], tool="grype", tool_label="reference"),
    ]
    input_desc = GateInputDescription(image=image, configs=configs)
    gate_config = GateConfig(max_unlabeled_percent=10)
    failed_gate = Gate(None, None, gate_config, input_desc, ["indeterminate matches % failure"])

    # Create controller - this will try to create relative comparison and will fail
    # because the result IDs don't exist in the store
    controller = InteractiveValidateController(gates=[failed_gate], label_entries=[existing_label])

    # The key insight: if _add_common_unlabeled_matches fails due to missing scan results,
    # then NO common matches will be added, and we'll never get to test the label matching logic
    assert len(controller.matches_to_label) == 0  # No matches should be added if comparison fails

    # But the result_id mapping should still be built correctly
    assert controller._result_id_to_image[result_ids[0]] == image
    assert controller._result_id_to_image[result_ids[1]] == image


def test_diagnosis_of_comparison_failure():
    """Test to diagnose why the comparison creation fails."""

    image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"
    result_ids = ["5b37f35c-9e93-42d3-b386-94c2752111c9", "848876a0-5ea7-465f-b697-c5f9bf4416c3"]

    configs = [
        GateInputResultConfig(id=result_ids[0], tool="grype", tool_label="custom-db"),
        GateInputResultConfig(id=result_ids[1], tool="grype", tool_label="reference"),
    ]
    input_desc = GateInputDescription(image=image, configs=configs)
    gate_config = GateConfig(max_unlabeled_percent=10)
    failed_gate = Gate(None, None, gate_config, input_desc, ["test failure"])

    controller = InteractiveValidateController(gates=[failed_gate], label_entries=[])

    # Manually test what happens when we try to create a comparison
    try:
        import yardstick

        descriptions = [config.id for config in failed_gate.input_description.configs]

        # This should fail because these result IDs don't exist in the store
        gate_relative_comparison = yardstick.compare_results(
            descriptions=descriptions,
            year_max_limit=None,
            year_from_cve_only=False,
            matches_filter=None,
        )

        # If we get here, the comparison worked (shouldn't happen with fake IDs)
        assert False, "Expected comparison to fail with fake result IDs"

    except Exception as e:
        # This is expected - the comparison should fail
        assert "no results found" in str(e).lower() or "not found" in str(e).lower()

        # This explains why no common matches are being found!
        # The real bug might be that the interactive validation is trying to process
        # matches but can't create the relative comparison needed to find common matches


def test_hypothesis_missing_results_cause_incorrect_behavior():
    """Test hypothesis: missing scan results cause the bug because comparison fails."""

    # This test demonstrates the issue:
    # 1. Quality gate fails because some matches are unlabeled
    # 2. Interactive validation tries to find common unlabeled matches
    # 3. It creates per-gate relative comparisons using result IDs
    # 4. These comparisons fail because result IDs don't map to stored results
    # 5. Since comparison fails, no common matches are processed
    # 6. But wait - the interactive TUI still shows matches somehow!

    # The discrepancy suggests that the matches being shown in the TUI
    # are coming from a DIFFERENT source than the common match collection logic

    image = "docker.io/anchore/test_images@sha256:746d31247006cc06434ce91ccf3523b2c230ff6c378ffed7ca1c60bbb48ea86f"

    # Test: where do the matches in the TUI actually come from?
    # Looking back at the initialization, there are multiple places matches could come from:

    # 1. Delta matches from failed gates (these work)
    # 2. Common matches from _add_common_unlabeled_matches (these fail due to missing results)
    # 3. Initial relative comparison provided to constructor (might work?)

    # The bug might be that we're using the wrong image context when we process
    # the initial relative comparison or when we fall back to some other match source
    pass  # This test is more of a hypothesis documentation than actual test
