import pytest

from yardstick import utils
from yardstick.utils import (
    is_local_path_version,
    parse_local_path,
    strip_local_path_prefix,
)


@pytest.mark.parametrize(
    ("input", "expected_year"),
    [
        ("CVE-2016-2781", 2016),
        ("CVE-1989-18276", None),
        ("CVE-20222-18276", None),
        ("ALAS-2019-1234", 2019),
        ("ALASRUBY2.6-2023-006", 2023),
        ("ALASSELINUX-NG-2023-001", 2023),
        ("ALASKERNEL-5.4-2023-043", 2023),
        ("ELSA-2023-6162", 2023),
    ],
)
def test_parse_year_from_id(input, expected_year):
    assert utils.parse_year_from_id(input) == expected_year


class TestLocalPathParsing:
    """Tests for local path prefix parsing utilities."""

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            # path: prefix
            ("path:/where/grype/is/cloned", True),
            ("path:relative/path", True),
            ("path:.", True),
            # file:// URI scheme
            ("file:///where/grype/is/cloned", True),
            ("file:///home/user/grype", True),
            ("file://relative/path", True),
            # not local paths
            ("v0.65.1", False),
            ("main", False),
            ("github.com/anchore/grype@main", False),
            ("latest", False),
            ("", False),
        ],
    )
    def test_is_local_path_version(self, version, expected):
        assert is_local_path_version(version) == expected

    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            # path: prefix
            ("path:/where/grype/is/cloned", "/where/grype/is/cloned"),
            ("path:relative/path", "relative/path"),
            ("path:.", "."),
            ("path:~/grype", "~/grype"),
            # file:// URI scheme with absolute path (triple slash)
            ("file:///where/grype/is/cloned", "/where/grype/is/cloned"),
            ("file:///home/user/grype", "/home/user/grype"),
            # file:// with localhost
            ("file://localhost/home/user/grype", "/home/user/grype"),
            # file:// with relative-looking path (netloc becomes first segment)
            ("file://relative/path", "relative/path"),
            # not local paths - should return None
            ("v0.65.1", None),
            ("main", None),
            ("github.com/anchore/grype@main", None),
            ("latest", None),
        ],
    )
    def test_parse_local_path(self, version, expected):
        assert parse_local_path(version) == expected

    @pytest.mark.parametrize(
        ("input_str", "expected"),
        [
            # path: prefix (as used in actual path arguments derived from version strings)
            (".yardstick/tools/grype/path:_where_grype_is_cloned", ".yardstick/tools/grype/_where_grype_is_cloned"),
            ("path:/some/path", "/some/path"),
            # file:// prefix
            (".yardstick/tools/grype/file://_where_grype_is_cloned", ".yardstick/tools/grype/_where_grype_is_cloned"),
            ("file:///some/path", "/some/path"),
            # file: prefix (normalized form when slashes become underscores: file:///path -> file:___path)
            (".yardstick/tools/grype/file:___where_grype_is_cloned", ".yardstick/tools/grype/___where_grype_is_cloned"),
            # both prefixes
            ("path:foo/file://bar", "foo/bar"),
            # no prefix - unchanged
            ("just/a/path", "just/a/path"),
            ("/absolute/path", "/absolute/path"),
            ("some:other:colons", "some:other:colons"),  # colons that aren't path: prefix
        ],
    )
    def test_strip_local_path_prefix(self, input_str, expected):
        assert strip_local_path_prefix(input_str) == expected
