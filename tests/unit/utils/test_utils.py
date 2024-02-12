import pytest

from yardstick import utils


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
