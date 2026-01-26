"""
Shared fixture data generators for yardstick integration tests.

These helpers create minimal but realistic fixture data for testing CLI
commands without requiring real vulnerability scans.

Test Data Assumptions
---------------------
The helpers generate synthetic data that mirrors the structure of real grype output.
Key assumptions about the data format:

1. Grype JSON Structure:
   - matches[]: Array of vulnerability matches
   - Each match has: vulnerability.id, vulnerability.namespace, artifact.name/version
   - source.target.repoDigests[]: Array containing image digest
   - descriptor.name/version: Tool identification

2. CVE ID Format:
   - CVE IDs follow pattern: CVE-YYYY-NNNN
   - Year is extracted from the ID for filtering (e.g., CVE-2020-0001 -> year 2020)

3. Label Format:
   - Labels are stored as JSON files in the labels directory
   - Each label has: ID, label (TP/FP/Unclear), vulnerability_id, package, image

4. Store Directory Structure:
   - Results: .yardstick/result/store/<image_encoded>/<tool@version>/<timestamp>/
   - Labels: .yardstick/labels/<image_encoded>/
   - Result sets: .yardstick/result/sets/<name>.json

For the authoritative grype JSON schema, see:
https://github.com/anchore/grype/tree/main/schema/json
"""

from __future__ import annotations

import datetime
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any

import yaml

from yardstick import artifact


# Default test image with a deterministic digest
DEFAULT_IMAGE_REPO = "test.io/test-image"
DEFAULT_IMAGE_DIGEST = "sha256:" + "a" * 64
DEFAULT_IMAGE = f"{DEFAULT_IMAGE_REPO}@{DEFAULT_IMAGE_DIGEST}"


@dataclass
class GrypeMatchEntry:
    """
    Represents a single match in grype JSON output format.

    This is a simplified representation of a grype match for testing purposes.
    Real grype output contains additional fields that are not needed for most tests.
    """

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
        "config": config.to_dict(),
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
class BaseTestEnv:
    """Base test environment with common paths."""

    root: str
    config_path: str
    store_root: str

    @property
    def results_path(self) -> str:
        return os.path.join(self.store_root, "result", "store")

    @property
    def labels_path(self) -> str:
        return os.path.join(self.store_root, "labels")

    @property
    def result_sets_path(self) -> str:
        return os.path.join(self.store_root, "result", "sets")


def save_scan_result(
    env: BaseTestEnv,
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


def save_label_entry(
    env: BaseTestEnv,
    entry: artifact.LabelEntry,
) -> str:
    """
    Save a single label entry to the store.

    Args:
        env: Test environment
        entry: LabelEntry to save

    Returns:
        Path to the saved label file
    """
    if entry.image and entry.image.exact:
        image_encoded = entry.image.exact.replace("/", "+")
        label_dir = os.path.join(env.labels_path, image_encoded)
    else:
        label_dir = env.labels_path

    os.makedirs(label_dir, exist_ok=True)
    path = os.path.join(label_dir, f"{entry.ID}.json")

    entry_dict = entry.to_dict()
    entry_dict = {k: v for k, v in entry_dict.items() if v is not None}

    with open(path, "w", encoding="utf-8") as f:
        json.dump(entry_dict, f, sort_keys=True)

    return path


def save_label_entries(
    env: BaseTestEnv,
    entries: list[artifact.LabelEntry],
) -> list[str]:
    """
    Save multiple label entries to the store.

    Args:
        env: Test environment
        entries: List of LabelEntry objects

    Returns:
        List of paths to saved label files
    """
    return [save_label_entry(env, entry) for entry in entries]


def create_minimal_config(store_root: str) -> dict[str, Any]:
    """Create a minimal .yardstick.yaml config."""
    return {
        "store_root": store_root,
    }


def save_config(config_path: str, config: dict[str, Any]) -> None:
    """Save a config dict to a YAML file."""
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f)
