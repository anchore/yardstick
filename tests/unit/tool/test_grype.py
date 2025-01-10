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
    handle_legacy_archive,
    handle_zstd_archive,
)


def test_grype_profiles():
    profile_arg = {"name": "test-profile", "config_path": "test-config-path"}
    profile = GrypeProfile(**profile_arg)
    with mock.patch("subprocess.check_output") as check_output:
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
    with mock.patch("subprocess.check_output") as check_output:
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
    ):
        check_call.return_value = bytes("test-output", "utf-8")
        exists.return_value = True
        fake_repo = mock.Mock()
        fake_repo.git = mock.Mock()
        fake_repo.untracked_files = []
        git_describe_val = "v0.65.1-1-g74a7a67-dirty"
        hash_of_git_diff = "a29864cf5600b481056b6fa30a21cdbabc15287d"[:8]
        fake_repo.git.describe.return_value = git_describe_val
        fake_repo.git.diff.return_value = (
            "test-diff"  # hash is 'a29864cf5600b481056b6fa30a21cdbabc15287d'
        )
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
