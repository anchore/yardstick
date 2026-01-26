"""
Fixture data generators for yardstick validate E2E tests.

These helpers extend the shared helpers with validate-specific test environment setup.
"""

from __future__ import annotations

import datetime
import json
import os
from dataclasses import dataclass
from typing import Any

import yaml

from yardstick import artifact

# Re-export shared helpers for convenience
from ..shared.helpers import (
    DEFAULT_IMAGE,
    DEFAULT_IMAGE_DIGEST,
    DEFAULT_IMAGE_REPO,
    BaseTestEnv,
    GrypeMatchEntry,
    create_grype_output,
    create_label_entry,
    create_scan_configuration,
    create_scan_metadata,
    save_config,
    save_label_entry,
    save_label_entries,
    save_scan_result,
)

__all__ = [
    "DEFAULT_IMAGE",
    "DEFAULT_IMAGE_DIGEST",
    "DEFAULT_IMAGE_REPO",
    "ValidateTestEnv",
    "GrypeMatchEntry",
    "create_grype_output",
    "create_label_entry",
    "create_scan_configuration",
    "create_scan_metadata",
    "create_yardstick_config",
    "save_label_entries",
    "save_result_set",
    "save_scan_result",
    "setup_validate_test_env",
]


@dataclass
class ValidateTestEnv(BaseTestEnv):
    """Test environment for validate testing."""

    result_set_name: str = "test-result-set"


def create_yardstick_config(
    store_root: str,
    result_set_name: str,
    image: str,
    reference_tool: str,
    candidate_tool: str,
    max_f1_regression: float = 0.0,
    max_new_false_negatives: int = 0,
    max_unlabeled_percent: int = 100,
    fail_on_empty_match_set: bool = True,
    max_year: int | None = None,
) -> dict[str, Any]:
    """
    Create a .yardstick.yaml config dict.

    Args:
        store_root: Path to .yardstick store directory
        result_set_name: Name of the result set
        image: Image identifier
        reference_tool: Reference tool spec (e.g., "grype@v1.0.0")
        candidate_tool: Candidate tool spec (e.g., "grype@v1.1.0")
        max_f1_regression: Maximum allowed F1 score regression
        max_new_false_negatives: Maximum new false negatives allowed
        max_unlabeled_percent: Maximum percentage of unlabeled matches
        fail_on_empty_match_set: Whether to fail if no matches found
        max_year: Maximum CVE year filter

    Returns:
        Config dict suitable for YAML serialization
    """
    config: dict[str, Any] = {
        "store_root": store_root,
        "result-sets": {
            result_set_name: {
                "description": "Test result set for validation",
                "declared": [
                    {"image": image, "tool": reference_tool, "label": "reference"},
                    {"image": image, "tool": candidate_tool, "label": "candidate"},
                ],
                "validations": [
                    {
                        "name": "default",
                        "max_f1_regression": max_f1_regression,
                        "max_new_false_negatives": max_new_false_negatives,
                        "max_unlabeled_percent": max_unlabeled_percent,
                        "reference_tool_label": "reference",
                        "candidate_tool_label": "candidate",
                        "fail_on_empty_match_set": fail_on_empty_match_set,
                    },
                ],
            },
        },
    }

    if max_year is not None:
        config["default-max-year"] = max_year

    return config


def save_result_set(
    env: ValidateTestEnv,
    configs: list[tuple[artifact.ScanConfiguration, str]],
) -> str:
    """
    Save a result set to the store.

    Args:
        env: Test environment
        configs: List of (ScanConfiguration, tool_label) tuples

    Returns:
        Path to the result set JSON file
    """
    os.makedirs(env.result_sets_path, exist_ok=True)

    # Build result set state
    state = []
    for config, tool_label in configs:
        state.append(
            {
                "request": {
                    "image": config.image,
                    "tool": config.tool,
                    "label": tool_label,
                },
                "config": config.to_dict(),
            }
        )

    result_set = {
        "name": env.result_set_name,
        "state": state,
    }

    path = os.path.join(env.result_sets_path, f"{env.result_set_name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result_set, f, indent=2)

    return path


def setup_validate_test_env(
    tmp_path: str,
    matches_reference: list[GrypeMatchEntry],
    matches_candidate: list[GrypeMatchEntry],
    labels: list[artifact.LabelEntry],
    image: str = DEFAULT_IMAGE,
    reference_version: str = "v1.0.0",
    candidate_version: str = "v1.1.0",
    max_f1_regression: float = 0.0,
    max_new_false_negatives: int = 0,
    max_unlabeled_percent: int = 100,
    fail_on_empty_match_set: bool = True,
    max_year: int | None = None,
    result_set_name: str = "test-result-set",
) -> ValidateTestEnv:
    """
    Set up a complete test environment for validate testing.

    This is the main helper function that creates:
    - .yardstick.yaml config file
    - Scan results for reference and candidate tools
    - Result set JSON
    - Label entries

    Args:
        tmp_path: Temporary directory path
        matches_reference: Matches found by reference tool
        matches_candidate: Matches found by candidate tool
        labels: Label entries for validation
        image: Image identifier
        reference_version: Reference tool version
        candidate_version: Candidate tool version
        max_f1_regression: Maximum F1 regression threshold
        max_new_false_negatives: Maximum new FNs threshold
        max_unlabeled_percent: Maximum unlabeled percentage
        fail_on_empty_match_set: Fail if no matches found
        max_year: CVE year filter
        result_set_name: Name for the result set

    Returns:
        ValidateTestEnv with all paths configured
    """
    # Create store directory
    store_root = os.path.join(tmp_path, ".yardstick")
    os.makedirs(store_root, exist_ok=True)

    # Create environment
    env = ValidateTestEnv(
        root=tmp_path,
        config_path=os.path.join(tmp_path, ".yardstick.yaml"),
        store_root=store_root,
        result_set_name=result_set_name,
    )

    # Create reference and candidate tool names with labels
    ref_tool_name = "grype[reference]"
    cand_tool_name = "grype[candidate]"

    # Create scan configurations
    base_time = datetime.datetime.now(tz=datetime.timezone.utc)

    ref_config = create_scan_configuration(
        image=image,
        tool_name=ref_tool_name,
        tool_version=reference_version,
        tool_label="reference",
        timestamp=base_time,
    )

    cand_config = create_scan_configuration(
        image=image,
        tool_name=cand_tool_name,
        tool_version=candidate_version,
        tool_label="candidate",
        timestamp=base_time + datetime.timedelta(seconds=1),
    )

    # Create and save grype outputs
    ref_output = create_grype_output(matches_reference, image)
    cand_output = create_grype_output(matches_candidate, image)

    save_scan_result(env, ref_config, ref_output)
    save_scan_result(env, cand_config, cand_output)

    # Save result set
    save_result_set(
        env,
        [
            (ref_config, "reference"),
            (cand_config, "candidate"),
        ],
    )

    # Save labels
    if labels:
        save_label_entries(env, labels)

    # Create and save config
    config = create_yardstick_config(
        store_root=store_root,
        result_set_name=result_set_name,
        image=image,
        reference_tool=f"{ref_tool_name}@{reference_version}",
        candidate_tool=f"{cand_tool_name}@{candidate_version}",
        max_f1_regression=max_f1_regression,
        max_new_false_negatives=max_new_false_negatives,
        max_unlabeled_percent=max_unlabeled_percent,
        fail_on_empty_match_set=fail_on_empty_match_set,
        max_year=max_year,
    )

    save_config(env.config_path, config)

    return env
