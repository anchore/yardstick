from unittest import mock

import pytest

from yardstick.tool.grype import Grype, GrypeProfile


def test_grype_profiles():
    profile_arg = {"name": "test-profile", "config_path": "test-config-path"}
    profile = GrypeProfile(**profile_arg)
    with mock.patch("subprocess.check_output") as check_output:
        check_output.return_value = bytes("test-output", "utf-8")
        tool = Grype(path="test-path", profile=profile, db_identity="oss")
        tool.capture(image="test-image", tool_input=None)
        assert check_output.call_args.args[0] == ["test-path/grype", "-o", "json", "test-image", "-c", "test-config-path"]


def test_grype_no_profile():
    with mock.patch("subprocess.check_output") as check_output:
        check_output.return_value = bytes("test-output", "utf-8")
        tool = Grype(path="test-path", db_identity="oss")
        tool.capture(image="test-image", tool_input=None)
        assert check_output.call_args.args[0] == ["test-path/grype", "-o", "json", "test-image"]


def test_install_from_path():
    with mock.patch("subprocess.check_call") as check_call, mock.patch("git.Repo") as repo, mock.patch(
        "os.path.exists"
    ) as exists, mock.patch("os.makedirs") as makedirs, mock.patch("os.chmod") as chmod:
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
        expected_grype_path = (
            f".yardstick/tools/grype/{normalized_version_str}/{git_describe_val}-{hash_of_git_diff}/local_install"
        )
        tool = Grype.install(version=version_str, path=".yardstick/tools/grype/path:_where_grype_is_cloned", update_db=False)
        assert tool.path == expected_grype_path
