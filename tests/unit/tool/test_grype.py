from unittest import mock

import pytest

from yardstick.tool.grype import Grype, GrypeProfile


def test_grype_profiles():
    profile_arg = {"name": "test-profile", "config_path": "test-config-path"}
    profile = GrypeProfile(**profile_arg)
    with mock.patch("subprocess.check_output") as check_output:
        check_output.return_value = bytes("test-output", "utf-8")
        tool = Grype(path="test-path", profile=profile)
        tool.capture(image="test-image", tool_input=None)
        assert check_output.call_args.args[0] == ["test-path/grype", "-o", "json", "test-image", "-c", "test-config-path"]


def test_grype_no_profile():
    with mock.patch("subprocess.check_output") as check_output:
        check_output.return_value = bytes("test-output", "utf-8")
        tool = Grype(path="test-path")
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
        fake_repo.git.describe.return_value = "test-version"
        repo.return_value = fake_repo
        tool = Grype.install(
            version="path:/where/grype/is/cloned", path=".yardstick/tools/grype/path:_where_grype_is_cloned", update_db=False
        )
        assert tool.path == ".yardstick/tools/grype/_where_grype_is_cloned/local_install"
