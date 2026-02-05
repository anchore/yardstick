import os
from unittest import mock

from yardstick.tool.syft import Syft


def test_install_from_path():
    """Test that path: prefix works for local installation."""
    with (
        mock.patch("subprocess.check_call") as check_call,
        mock.patch("git.Repo") as repo,
        mock.patch("os.path.exists") as exists,
        mock.patch("os.makedirs"),
        mock.patch("os.chmod"),
    ):
        check_call.return_value = bytes("test-output", "utf-8")
        exists.return_value = True
        fake_repo = mock.Mock()
        fake_repo.git = mock.Mock()
        fake_repo.untracked_files = []
        git_describe_val = "v1.0.0-1-gabcdef0-dirty"
        hash_of_git_diff = "a29864cf5600b481056b6fa30a21cdbabc15287d"[:8]
        fake_repo.git.describe.return_value = git_describe_val
        fake_repo.git.diff.return_value = "test-diff"
        repo.return_value = fake_repo

        version_str = "path:/where/syft/is/cloned"
        normalized_version_str = version_str.replace("/", "_").removeprefix("path:")
        expected_syft_path = f".yardstick/tools/syft/{normalized_version_str}/{git_describe_val}-{hash_of_git_diff}/local_install"

        tool = Syft.install(
            version=version_str,
            path=".yardstick/tools/syft/path:_where_syft_is_cloned",
        )
        assert tool.path == expected_syft_path


def test_install_from_file_uri():
    """Test that file:// URI scheme works the same as path: prefix."""
    with (
        mock.patch("subprocess.check_call") as check_call,
        mock.patch("git.Repo") as repo,
        mock.patch("os.path.exists") as exists,
        mock.patch("os.makedirs"),
        mock.patch("os.chmod"),
    ):
        check_call.return_value = bytes("test-output", "utf-8")
        exists.return_value = True
        fake_repo = mock.Mock()
        fake_repo.git = mock.Mock()
        fake_repo.untracked_files = []
        git_describe_val = "v1.0.0-1-gabcdef0-dirty"
        hash_of_git_diff = "a29864cf5600b481056b6fa30a21cdbabc15287d"[:8]
        fake_repo.git.describe.return_value = git_describe_val
        fake_repo.git.diff.return_value = "test-diff"
        repo.return_value = fake_repo

        # Use file:// URI instead of path: prefix
        version_str = "file:///where/syft/is/cloned"
        # The path argument has slashes replaced with underscores (done by tool store)
        path_arg = ".yardstick/tools/syft/file:___where_syft_is_cloned"
        # strip_local_path_prefix removes "file:" leaving ___where_syft_is_cloned
        expected_syft_path = f".yardstick/tools/syft/___where_syft_is_cloned/{git_describe_val}-{hash_of_git_diff}/local_install"

        tool = Syft.install(
            version=version_str,
            path=path_arg,
        )
        assert tool.path == expected_syft_path
