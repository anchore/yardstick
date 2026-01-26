"""
Fixture data generators for yardstick CLI E2E tests.

These helpers extend the shared helpers with CLI-specific test environment setup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

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
    create_minimal_config,
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
    "CLITestEnv",
    "GrypeMatchEntry",
    "create_grype_output",
    "create_label_entry",
    "create_minimal_config",
    "create_scan_configuration",
    "create_scan_metadata",
    "save_label_entry",
    "save_scan_result",
    "setup_cli_test_env",
]


@dataclass
class CLITestEnv(BaseTestEnv):
    """Test environment for CLI testing."""

    pass  # Inherits all properties from BaseTestEnv


def setup_cli_test_env(
    tmp_path: str,
    scan_results: list[tuple[artifact.ScanConfiguration, list[GrypeMatchEntry]]] | None = None,
    labels: list[artifact.LabelEntry] | None = None,
) -> CLITestEnv:
    """
    Set up a test environment for CLI testing.

    Args:
        tmp_path: Temporary directory path
        scan_results: List of (ScanConfiguration, matches) tuples to create
        labels: Label entries to create

    Returns:
        CLITestEnv with all paths configured
    """
    store_root = os.path.join(tmp_path, ".yardstick")
    os.makedirs(store_root, exist_ok=True)

    env = CLITestEnv(
        root=tmp_path,
        config_path=os.path.join(tmp_path, ".yardstick.yaml"),
        store_root=store_root,
    )

    # Create scan results
    if scan_results:
        for config, matches in scan_results:
            grype_output = create_grype_output(matches, config.image)
            save_scan_result(env, config, grype_output)

    # Create labels
    if labels:
        save_label_entries(env, labels)

    # Create config file
    config = create_minimal_config(store_root)
    save_config(env.config_path, config)

    return env
