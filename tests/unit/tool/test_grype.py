import pytest
import tarfile
import os
import json
from tempfile import TemporaryDirectory
from unittest import mock

import zstandard as zstd
import xxhash

from yardstick.tool.grype import (
    Grype,
    GrypeProfile,
    get_import_checksum,
    handle_legacy_archive,
    handle_zstd_archive,
    handle_db_file,
)


def test_grype_profiles():
    profile_arg = {"name": "test-profile", "config_path": "test-config-path"}
    profile = GrypeProfile(**profile_arg)
    with (
        mock.patch("subprocess.check_output") as check_output,
        mock.patch.dict(os.environ, {}, clear=True),  # Clear env vars
    ):
        check_output.return_value = bytes("test-output", "utf-8")
        tool = Grype(path="test-path", profile=profile, db_identity="oss")
        tool.capture(image="test-image", tool_input=None)
        assert check_output.call_args.args[0] == [
            "test-path/grype",
            "-o",
            "json",
            "test-image",
            "-c",
            "test-config-path",
        ]


def test_grype_no_profile():
    with (
        mock.patch("subprocess.check_output") as check_output,
        mock.patch.dict(os.environ, {}, clear=True),  # Clear env vars
    ):
        check_output.return_value = bytes("test-output", "utf-8")
        tool = Grype(path="test-path", db_identity="oss")
        tool.capture(image="test-image", tool_input=None)
        assert check_output.call_args.args[0] == [
            "test-path/grype",
            "-o",
            "json",
            "test-image",
        ]


def test_install_from_path():
    with (
        mock.patch("subprocess.check_call") as check_call,
        mock.patch(
            "git.Repo",
        ) as repo,
        mock.patch("os.path.exists") as exists,
        mock.patch(
            "os.makedirs",
        ),
        mock.patch(
            "os.chmod",
        ),
        mock.patch.dict(os.environ, {}, clear=True),  # Clear env vars including GRYPE_EXECUTABLE_PATH
    ):
        check_call.return_value = bytes("test-output", "utf-8")
        exists.return_value = True
        fake_repo = mock.Mock()
        fake_repo.git = mock.Mock()
        fake_repo.untracked_files = []
        git_describe_val = "v0.65.1-1-g74a7a67-dirty"
        hash_of_git_diff = "a29864cf5600b481056b6fa30a21cdbabc15287d"[:8]
        fake_repo.git.describe.return_value = git_describe_val
        fake_repo.git.diff.return_value = "test-diff"  # hash is 'a29864cf5600b481056b6fa30a21cdbabc15287d'
        repo.return_value = fake_repo
        version_str = "path:/where/grype/is/cloned"
        normalized_version_str = version_str.replace("/", "_").removeprefix("path:")
        expected_grype_path = f".yardstick/tools/grype/{normalized_version_str}/{git_describe_val}-{hash_of_git_diff}/local_install"
        tool = Grype.install(
            version=version_str,
            path=".yardstick/tools/grype/path:_where_grype_is_cloned",
            update_db=False,
        )
        assert tool.path == expected_grype_path


def test_install_from_file_uri():
    """Test that file:// URI scheme works the same as path: prefix."""
    with (
        mock.patch("subprocess.check_call") as check_call,
        mock.patch(
            "git.Repo",
        ) as repo,
        mock.patch("os.path.exists") as exists,
        mock.patch(
            "os.makedirs",
        ),
        mock.patch(
            "os.chmod",
        ),
        mock.patch.dict(os.environ, {}, clear=True),  # Clear env vars including GRYPE_EXECUTABLE_PATH
    ):
        check_call.return_value = bytes("test-output", "utf-8")
        exists.return_value = True
        fake_repo = mock.Mock()
        fake_repo.git = mock.Mock()
        fake_repo.untracked_files = []
        git_describe_val = "v0.65.1-1-g74a7a67-dirty"
        hash_of_git_diff = "a29864cf5600b481056b6fa30a21cdbabc15287d"[:8]
        fake_repo.git.describe.return_value = git_describe_val
        fake_repo.git.diff.return_value = "test-diff"  # hash is 'a29864cf5600b481056b6fa30a21cdbabc15287d'
        repo.return_value = fake_repo
        # Use file:// URI instead of path: prefix
        # Note: file:///where has 3 slashes (file:// + /where), which becomes file:___where when / -> _
        version_str = "file:///where/grype/is/cloned"
        # The path argument is derived from version_str with / replaced by _ (done elsewhere, passed to install)
        # file:///where/grype/is/cloned -> file:___where_grype_is_cloned
        path_arg = ".yardstick/tools/grype/file:___where_grype_is_cloned"
        # strip_local_path_prefix removes "file://" leaving ___where_grype_is_cloned
        expected_grype_path = f".yardstick/tools/grype/___where_grype_is_cloned/{git_describe_val}-{hash_of_git_diff}/local_install"
        tool = Grype.install(
            version=version_str,
            path=path_arg,
            update_db=False,
        )
        assert tool.path == expected_grype_path


def create_legacy_archive_with_metadata(archive_path, metadata):
    with tarfile.open(archive_path, "w:gz") as tar:
        metadata_path = os.path.join(os.path.dirname(archive_path), "metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f)
        tar.add(metadata_path, arcname="metadata.json")
        os.remove(metadata_path)


def create_zstd_archive_with_db(archive_path, db_content):
    with TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "vulnerability.db")
        with open(db_path, "wb") as f:
            f.write(db_content)

        tar_path = os.path.join(temp_dir, "archive.tar")
        with tarfile.open(tar_path, "w") as tar:
            tar.add(db_path, arcname="vulnerability.db")

        with open(tar_path, "rb") as tar_file, open(archive_path, "wb") as zstd_file:
            dctx = zstd.ZstdCompressor()
            dctx.copy_stream(tar_file, zstd_file)


@pytest.fixture
def legacy_archive(tmp_path):
    archive_path = tmp_path / "db.tar.gz"
    metadata = {"checksum": "12345"}
    create_legacy_archive_with_metadata(archive_path, metadata)
    return archive_path, metadata["checksum"]


@pytest.fixture
def zstd_archive(tmp_path):
    archive_path = tmp_path / "db.tar.zst"
    db_content = b"dummy database content"
    hasher = xxhash.xxh64()
    hasher.update(db_content)
    expected_checksum = hasher.hexdigest()
    create_zstd_archive_with_db(archive_path, db_content)
    return archive_path, expected_checksum


def test_handle_legacy_archive(legacy_archive):
    archive_path, expected_checksum = legacy_archive
    assert handle_legacy_archive(str(archive_path)) == expected_checksum


def test_handle_zstd_archive(zstd_archive):
    archive_path, expected_checksum = zstd_archive
    assert handle_zstd_archive(str(archive_path)) == expected_checksum


def test_handle_import_url():
    # this does not exist on disk, but we can test the URL handling and just hash the URL
    url = "https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.3_2025-07-23T01:30:29Z_1753244566.tar.zst?checksum=sha256%3Af09d1f0b71ebf39b53abffb3c7ecb0435576040b2dfbf6e2e35928b5b3b8c592"
    expected_checksum = "5910fbf3352d25a2"
    assert handle_zstd_archive(url) == expected_checksum


@pytest.fixture
def db_file(tmp_path):
    db_path = tmp_path / "vulnerability.db"
    db_content = b"dummy database file content"
    with open(db_path, "wb") as f:
        f.write(db_content)
    hasher = xxhash.xxh64()
    hasher.update(db_content)
    expected_checksum = hasher.hexdigest()
    return db_path, expected_checksum


def test_handle_db_file(db_file):
    db_path, expected_checksum = db_file
    assert handle_db_file(str(db_path)) == expected_checksum


def test_get_import_checksum_db_file(db_file):
    db_path, expected_checksum = db_file
    assert get_import_checksum(str(db_path)) == expected_checksum


def test_get_import_checksum_legacy_archive(legacy_archive):
    archive_path, expected_checksum = legacy_archive
    assert get_import_checksum(str(archive_path)) == expected_checksum


def test_get_import_checksum_zstd_archive(zstd_archive):
    archive_path, expected_checksum = zstd_archive
    assert get_import_checksum(str(archive_path)) == expected_checksum


def test_get_import_checksum_unsupported():
    with pytest.raises(ValueError, match="unsupported db import path"):
        get_import_checksum("unsupported.txt")


# Tests for GRYPE_EXECUTABLE_PATH environment variable support
class TestGrypeExecutablePathOverride:
    """Test GRYPE_EXECUTABLE_PATH environment variable support."""

    def test_check_executable_path_override_valid_absolute_path(self, tmp_path, mocker):
        """Test _check_executable_path_override returns resolved path for valid absolute path."""
        from yardstick.tool.grype import _check_executable_path_override

        fake_grype = tmp_path / "fake-grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake grype'")
        fake_grype.chmod(0o755)

        # Set environment variable with absolute path
        mocker.patch.dict(os.environ, {"GRYPE_EXECUTABLE_PATH": str(fake_grype)})

        result = _check_executable_path_override()

        # Should return realpath of the executable
        assert result == str(fake_grype.resolve())

    def test_check_executable_path_override_valid_path_on_path(self, tmp_path, mocker):
        """Test _check_executable_path_override searches PATH for relative names."""
        from yardstick.tool.grype import _check_executable_path_override

        # Create a fake grype binary
        fake_grype = tmp_path / "grype"
        fake_grype.write_text("#!/bin/bash\necho 'grype'")
        fake_grype.chmod(0o755)

        # Mock shutil.which to simulate finding grype on PATH
        mock_which = mocker.patch("yardstick.tool.grype.shutil.which")
        mock_which.return_value = str(fake_grype)

        # Set environment variable with relative name
        mocker.patch.dict(os.environ, {"GRYPE_EXECUTABLE_PATH": "grype"})

        result = _check_executable_path_override()

        # Should have called which and returned resolved path
        mock_which.assert_called_once_with("grype")
        assert result == str(fake_grype.resolve())

    def test_check_executable_path_override_invalid_absolute_path(self, mocker):
        """Test _check_executable_path_override returns None for invalid absolute path."""
        from yardstick.tool.grype import _check_executable_path_override

        fake_path = "/nonexistent/grype"

        # Set environment variable to invalid absolute path
        mocker.patch.dict(os.environ, {"GRYPE_EXECUTABLE_PATH": fake_path})

        result = _check_executable_path_override()

        assert result is None

    def test_check_executable_path_override_not_on_path(self, mocker):
        """Test _check_executable_path_override returns None when name not found on PATH."""
        from yardstick.tool.grype import _check_executable_path_override

        # Mock shutil.which to return None (not found on PATH)
        mock_which = mocker.patch("yardstick.tool.grype.shutil.which")
        mock_which.return_value = None

        # Set environment variable to relative name
        mocker.patch.dict(os.environ, {"GRYPE_EXECUTABLE_PATH": "nonexistent-grype"})

        result = _check_executable_path_override()

        assert result is None
        mock_which.assert_called_once_with("nonexistent-grype")

    def test_check_executable_path_override_no_env_var(self, mocker):
        """Test _check_executable_path_override returns None when env var not set."""
        from yardstick.tool.grype import _check_executable_path_override

        # Ensure no environment variable is set
        mocker.patch.dict(os.environ, {}, clear=True)

        result = _check_executable_path_override()

        assert result is None

    def test_install_uses_executable_path_override(self, tmp_path, mocker):
        """Test Grype.install uses result from _check_executable_path_override."""
        fake_grype = tmp_path / "grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake grype'")
        fake_grype.chmod(0o755)

        # Mock the override function to return a path
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = str(fake_grype)

        # Mock run to avoid actual grype execution
        mock_run = mocker.patch.object(Grype, "run")

        result = Grype.install("latest", update_db=False)

        # Should have used the override and created a working directory
        assert result.version_detail == "external-latest"
        assert "external-latest" in result.path
        # Should have created symlink to the binary
        symlink = os.path.join(result.path, "grype")
        assert os.path.islink(symlink) or os.path.exists(symlink)
        mock_override.assert_called_once()

    def test_install_with_executable_path_and_custom_db(self, tmp_path, mocker):
        """Test Grype.install with GRYPE_EXECUTABLE_PATH and custom DB import."""
        fake_grype = tmp_path / "grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake grype'")
        fake_grype.chmod(0o755)

        fake_db = tmp_path / "custom.tar.zst"
        fake_db.write_text("fake db")

        # Mock the override function
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = str(fake_grype)

        # Mock get_import_checksum to avoid processing the fake DB
        mock_checksum = mocker.patch("yardstick.tool.grype.get_import_checksum")
        mock_checksum.return_value = "fake-checksum"

        # Mock os.path.exists to simulate DB doesn't exist
        mock_exists = mocker.patch("os.path.exists")
        mock_exists.return_value = False

        # Mock run to avoid actual grype execution
        mock_run = mocker.patch.object(Grype, "run")

        result = Grype.install(f"main+import-db={fake_db}", update_db=False)

        # Should have imported the DB
        assert mock_run.called
        run_args = mock_run.call_args[0]
        assert "import" in run_args

    def test_install_without_executable_path_continues_normally(self, mocker):
        """Test Grype.install proceeds normally when GRYPE_EXECUTABLE_PATH is not set."""
        # Mock the override to return None
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = None

        # Mock _install_from_installer to avoid actual installation
        mock_install = mocker.patch("yardstick.tool.grype.Grype._install_from_installer")
        mock_grype = mocker.MagicMock(spec=Grype)
        mock_install.return_value = mock_grype

        result = Grype.install("v0.100.0", update_db=False)

        # Should have called normal install process
        mock_install.assert_called_once()
        assert result == mock_grype

    def test_run_with_external_binary_path(self, tmp_path, mocker):
        """Test Grype.run handles external binary path correctly."""
        fake_grype = tmp_path / "grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake output'")
        fake_grype.chmod(0o755)

        # Create Grype instance with path to directory containing binary
        tool = Grype(path=str(tmp_path), db_identity="oss")

        # Mock subprocess.check_output
        mock_check_output = mocker.patch("subprocess.check_output")
        mock_check_output.return_value = b"fake output"

        tool.run("version")

        # Should have called with correct binary path
        called_cmd = mock_check_output.call_args[0][0]
        assert called_cmd[0] == str(fake_grype)

    def test_install_with_executable_path_without_custom_db_respects_update_db_param(self, tmp_path, mocker):
        """Test that update_db parameter is respected when no custom DB specified."""
        fake_grype = tmp_path / "grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake grype'")
        fake_grype.chmod(0o755)

        # Mock the override function
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = str(fake_grype)

        # Mock run to track calls
        mock_run = mocker.patch.object(Grype, "run")

        # Test 1: update_db=True should call db update
        Grype.install("latest", update_db=True)
        assert mock_run.called
        calls = [str(call) for call in mock_run.call_args_list]
        assert any("update" in str(call) for call in calls)

        # Test 2: update_db=False should NOT call db update
        mock_run.reset_mock()
        Grype.install("latest", update_db=False)
        # Should not have called run at all (no db import, no update)
        assert not mock_run.called

    def test_install_with_executable_path_handles_existing_symlink(self, tmp_path, mocker):
        """Test that installing twice doesn't fail on existing symlink (race condition test)."""
        fake_grype = tmp_path / "fake-grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake grype'")
        fake_grype.chmod(0o755)

        # Mock the override function
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = str(fake_grype)

        # Mock run to avoid actual execution
        mock_run = mocker.patch.object(Grype, "run")

        # First install
        result1 = Grype.install("v0.100.0", update_db=False)

        # Second install to same location - should not fail on existing symlink
        result2 = Grype.install("v0.100.0", update_db=False)

        # Both should succeed
        assert result1.path == result2.path
        assert "external-v0.100.0" in result1.path

    def test_install_detects_version_from_external_binary(self, tmp_path, mocker):
        """Test that version_detail is detected from the actual binary, not just the version string."""
        fake_grype = tmp_path / "grype"
        fake_grype.write_text('#!/bin/bash\necho \'{"version": "0.101.1"}\'')
        fake_grype.chmod(0o755)

        # Mock the override function
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = str(fake_grype)

        # Mock subprocess.check_output for version detection
        mock_check_output = mocker.patch("subprocess.check_output")
        mock_check_output.return_value = '{"version": "0.101.1"}'

        # Mock Grype.run to avoid DB operations
        mock_run = mocker.patch.object(Grype, "run")

        result = Grype.install("latest", update_db=False)

        # Should have detected the actual version
        assert result.version_detail == "external-0.101.1"
        # Verify version detection was called
        mock_check_output.assert_called_once()
        call_args = mock_check_output.call_args[0][0]
        assert call_args[1:] == ["version", "-o", "json"]

    def test_install_with_explicit_path_creates_symlink(self, tmp_path, mocker):
        """Test that symlink is created even when path is explicitly provided.

        This catches the bug where symlink creation was inside the 'if not path:' block,
        so it wouldn't create symlinks when grype-db-manager provides an explicit path.
        """
        fake_grype = tmp_path / "fake-grype"
        fake_grype.write_text("#!/bin/bash\necho 'fake grype'")
        fake_grype.chmod(0o755)

        # Mock the override function
        mock_override = mocker.patch("yardstick.tool.grype._check_executable_path_override")
        mock_override.return_value = str(fake_grype)

        # Mock subprocess for version detection
        mock_check_output = mocker.patch("subprocess.check_output")
        mock_check_output.return_value = '{"version": "0.101.1"}'

        # Mock run to avoid DB operations
        mock_run = mocker.patch.object(Grype, "run")

        # Provide explicit path (like grype-db-manager does)
        explicit_path = tmp_path / "custom-install-dir"
        explicit_path.mkdir()

        result = Grype.install("main", path=str(explicit_path), update_db=False)

        # Should have created symlink at the provided path
        expected_symlink = explicit_path / "grype"
        assert expected_symlink.exists() or expected_symlink.is_symlink()
        assert result.path == str(explicit_path)
