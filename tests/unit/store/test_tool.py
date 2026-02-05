"""
Tests for yardstick.store.tool module.

These tests verify that tool install paths are correctly computed,
particularly for local path versions using path: and file:// prefixes.
"""

from __future__ import annotations

from unittest import mock

import pytest

from yardstick import artifact
from yardstick.store import tool


@pytest.fixture
def mock_store_config():
    """Mock store config to avoid needing a real config file."""
    mock_config = mock.Mock()
    mock_config.store_root = "/test/store"
    with mock.patch("yardstick.store.tool.store_config.get", return_value=mock_config):
        yield mock_config


class TestInstallPath:
    """Tests for install_path function."""

    def test_semver_version(self, mock_store_config):
        """Standard semver versions are handled correctly."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="v0.65.1",
        )

        path = tool.install_path(config)

        assert path == "/test/store/tools/grype/v0.65.1"

    def test_path_prefix_version(self, mock_store_config):
        """path: prefix versions have slashes normalized to underscores."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="path:/home/user/grype",
        )

        path = tool.install_path(config)

        # Slashes in version are replaced with underscores
        assert path == "/test/store/tools/grype/path:_home_user_grype"

    def test_file_uri_absolute_path(self, mock_store_config):
        """file:// URIs with absolute paths have slashes normalized."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="file:///home/user/grype",
        )

        path = tool.install_path(config)

        # file:///home/user/grype -> file:___home_user_grype
        # (three slashes: file:// + /home)
        assert path == "/test/store/tools/grype/file:___home_user_grype"

    def test_file_uri_relative_path(self, mock_store_config):
        """file:// URIs with relative-style paths are handled."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="file://relative/path/to/grype",
        )

        path = tool.install_path(config)

        # file://relative/path -> file:__relative_path_to_grype
        assert path == "/test/store/tools/grype/file:__relative_path_to_grype"

    def test_grype_with_db_import_suffix(self, mock_store_config):
        """Grype versions with +import-db= suffix are stripped."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="v0.65.1+import-db=/path/to/db.tar.gz",
        )

        path = tool.install_path(config)

        # The +import-db= suffix should be removed for grype
        assert path == "/test/store/tools/grype/v0.65.1"

    def test_file_uri_with_db_import_suffix(self, mock_store_config):
        """file:// URI with +import-db= suffix is stripped for grype."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="grype",
            tool_version="file:///home/user/grype+import-db=/path/to/db.tar.gz",
        )

        path = tool.install_path(config)

        # Both the +import-db suffix is stripped and slashes normalized
        assert path == "/test/store/tools/grype/file:___home_user_grype"

    def test_syft_file_uri(self, mock_store_config):
        """file:// URIs work for syft tool as well."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="syft",
            tool_version="file:///home/user/syft",
        )

        path = tool.install_path(config)

        assert path == "/test/store/tools/syft/file:___home_user_syft"

    def test_tool_name_with_slashes(self, mock_store_config):
        """Tool names with slashes are normalized in the base path."""
        config = artifact.ScanConfiguration(
            image_repo="docker.io/library/alpine",
            image_digest="sha256:abc123",
            tool_name="anchore/grype",
            tool_version="v0.65.1",
        )

        path = tool.install_path(config)

        # Tool name slashes are also replaced with underscores
        assert path == "/test/store/tools/anchore_grype/v0.65.1"


class TestInstallBase:
    """Tests for install_base function."""

    def test_simple_tool_name(self, mock_store_config):
        """Simple tool names produce expected base path."""
        path = tool.install_base("grype")

        assert path == "/test/store/tools/grype"

    def test_tool_name_with_slash(self, mock_store_config):
        """Tool names with slashes are normalized."""
        path = tool.install_base("anchore/grype")

        assert path == "/test/store/tools/anchore_grype"
