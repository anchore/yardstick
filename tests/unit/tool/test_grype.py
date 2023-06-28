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
