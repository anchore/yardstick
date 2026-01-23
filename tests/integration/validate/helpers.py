"""
Fixture data generators for yardstick validate E2E tests.

These helpers create minimal but realistic fixture data for testing the validate
command without requiring real vulnerability scans.
"""

from __future__ import annotations

import datetime
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml

from yardstick import artifact


# Default test image with a deterministic digest
DEFAULT_IMAGE_REPO = "test.io/test-image"
DEFAULT_IMAGE_DIGEST = "sha256:" + "a" * 64
DEFAULT_IMAGE = f"{DEFAULT_IMAGE_REPO}@{DEFAULT_IMAGE_DIGEST}"


@dataclass
class GrypeMatchEntry:
    """Represents a single match in grype JSON output format."""

    vulnerability_id: str
    package_name: str
    package_version: str
    cve_id: str | None = None
    namespace: str = "debian:11"
    fixed_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to grype JSON match format."""
        entry: dict[str, Any] = {
            "vulnerability": {
                "id": self.vulnerability_id,
                "namespace": self.namespace,
                "severity": "High",
            },
            "artifact": {
                "name": self.package_name,
                "version": self.package_version,
                "type": "deb",
            },
            "relatedVulnerabilities": [],
        }

        if self.fixed_version:
            entry["vulnerability"]["fix"] = {"versions": [self.fixed_version]}

        # Add CVE as related vulnerability if different from main ID
        if self.cve_id and self.cve_id != self.vulnerability_id:
            entry["relatedVulnerabilities"].append(
                {
                    "id": self.cve_id,
                    "namespace": "nvd:cpe",
                    "severity": "High",
                }
            )
        elif self.vulnerability_id.startswith("CVE-"):
            # Main ID is already CVE, add it as related too
            entry["relatedVulnerabilities"].append(
                {
                    "id": self.vulnerability_id,
                    "namespace": "nvd:cpe",
                    "severity": "High",
                }
            )

        return entry


def create_grype_output(
    matches: list[GrypeMatchEntry],
    image: str = DEFAULT_IMAGE,
) -> str:
    """
    Create a minimal grype JSON output string.

    Args:
        matches: List of GrypeMatchEntry objects representing vulnerabilities
        image: The image identifier (repo@digest format)

    Returns:
        JSON string in grype output format
    """
    image_obj = artifact.Image(image)

    output = {
        "matches": [m.to_dict() for m in matches],
        "source": {
            "type": "image",
            "target": {
                "repoDigests": [image],
            },
        },
        "descriptor": {
            "name": "grype",
            "version": "0.0.0-test",
            "db": {
                "location": "",  # Empty to avoid DB lookups during tests
            },
        },
    }
    return json.dumps(output)


def create_scan_configuration(
    image: str = DEFAULT_IMAGE,
    tool_name: str = "grype",
    tool_version: str = "v1.0.0",
    tool_label: str | None = None,
    timestamp: datetime.datetime | None = None,
    config_id: str | None = None,
) -> artifact.ScanConfiguration:
    """
    Create a ScanConfiguration for testing.

    Args:
        image: Image identifier (repo@digest format)
        tool_name: Tool name (e.g., "grype" or "grype[reference]")
        tool_version: Tool version string
        tool_label: Optional tool label (reference/candidate)
        timestamp: Scan timestamp (defaults to now)
        config_id: Optional fixed ID (defaults to random UUID)

    Returns:
        ScanConfiguration object
    """
    image_obj = artifact.Image(image)

    if timestamp is None:
        timestamp = datetime.datetime.now(tz=datetime.timezone.utc)

    return artifact.ScanConfiguration(
        image_repo=image_obj.repository,
        image_digest=image_obj.digest,
        image_tag=image_obj.tag,
        tool_name=tool_name,
        tool_version=tool_version,
        tool_label=tool_label,
        timestamp=timestamp,
        ID=config_id or str(uuid.uuid4()),
    )


def create_scan_metadata(
    config: artifact.ScanConfiguration,
    elapsed: float = 1.0,
) -> dict[str, Any]:
    """
    Create metadata dict for a scan result (stored in metadata.json).

    Args:
        config: The ScanConfiguration for this result
        elapsed: Scan duration in seconds

    Returns:
        Dict suitable for JSON serialization as metadata.json
    """
    return {
        "config": config.to_dict(),  # type: ignore[attr-defined]
        "metadata": {
            "timestamp": config.timestamp.isoformat() if config.timestamp else None,
            "elapsed": elapsed,
            "image_digest": config.image_digest,
        },
    }


def create_label_entry(
    label: artifact.Label,
    vulnerability_id: str,
    package: artifact.Package | None = None,
    image: str | None = None,
    label_id: str | None = None,
) -> artifact.LabelEntry:
    """
    Create a LabelEntry for testing.

    Args:
        label: The label (TP, FP, Unclear)
        vulnerability_id: CVE or vulnerability ID
        package: Optional specific package
        image: Optional image constraint (exact match)
        label_id: Optional fixed ID

    Returns:
        LabelEntry object
    """
    image_spec = None
    if image:
        image_spec = artifact.ImageSpecifier(exact=image)

    return artifact.LabelEntry(
        label=label,
        vulnerability_id=vulnerability_id,
        package=package,
        image=image_spec,
        ID=label_id or str(uuid.uuid4()),
        user="test-user",
    )


@dataclass
class ValidateTestEnv:
    """
    Test environment containing all paths and data for validate testing.
    """

    root: str
    config_path: str
    store_root: str
    result_set_name: str = "test-result-set"

    @property
    def results_path(self) -> str:
        # Matches yardstick/store/tool.py RESULT_DIR
        return os.path.join(self.store_root, "result", "store")

    @property
    def labels_path(self) -> str:
        return os.path.join(self.store_root, "labels")

    @property
    def result_sets_path(self) -> str:
        # Matches yardstick/store/tool.py RESULT_SET_DIR
        return os.path.join(self.store_root, "result", "sets")


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


def save_scan_result(
    env: ValidateTestEnv,
    config: artifact.ScanConfiguration,
    grype_output: str,
) -> str:
    """
    Save a scan result to the store.

    Args:
        env: Test environment
        config: ScanConfiguration for this result
        grype_output: Raw grype JSON output

    Returns:
        Path to the result directory
    """
    # Create result directory path: results/<image_encoded>/<tool@version>/<timestamp>/
    result_dir = os.path.join(
        env.results_path,
        config.image_encoded,
        f"{config.tool_name.replace('/', '_')}@{config.tool_version.replace('/', '_')}",
        config.timestamp_rfc3339,
    )
    os.makedirs(result_dir, exist_ok=True)

    # Save data.json (raw grype output)
    data_path = os.path.join(result_dir, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        f.write(grype_output)

    # Save metadata.json
    metadata_path = os.path.join(result_dir, "metadata.json")
    metadata = create_scan_metadata(config)
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f)

    return result_dir


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
                "config": config.to_dict(),  # type: ignore[attr-defined]
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


def save_label_entries(
    env: ValidateTestEnv,
    entries: list[artifact.LabelEntry],
) -> list[str]:
    """
    Save label entries to the store.

    Args:
        env: Test environment
        entries: List of LabelEntry objects

    Returns:
        List of paths to saved label files
    """
    paths = []
    for entry in entries:
        # Determine path based on whether entry has specific image
        if entry.image and entry.image.exact:
            image_encoded = entry.image.exact.replace("/", "+")
            label_dir = os.path.join(env.labels_path, image_encoded)
        else:
            label_dir = env.labels_path

        os.makedirs(label_dir, exist_ok=True)
        path = os.path.join(label_dir, f"{entry.ID}.json")

        # Convert to dict, excluding None values
        entry_dict = entry.to_dict()  # type: ignore[attr-defined]
        # Remove empty values
        entry_dict = {k: v for k, v in entry_dict.items() if v is not None}

        with open(path, "w", encoding="utf-8") as f:
            json.dump(entry_dict, f, sort_keys=True)

        paths.append(path)

    return paths


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

    with open(env.config_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f)

    return env
