from unittest.mock import patch

import pytest
from yardstick import artifact as art
from yardstick import store


class TestFilterByYear:
    @pytest.fixture()
    def matches(self) -> list[art.Match]:
        matches: list[art.Match] = []
        pkg = art.Package("busybox", "1.34.1-r5")
        for i in range(3):
            vuln = art.Vulnerability(f"CVE-200{i}-1")
            matches.append(art.Match(vulnerability=vuln, package=pkg))

        matches.append(
            art.Match(
                vulnerability=art.Vulnerability("GHSA-52rh-5rpj-c3w6"),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "GHSA-52rh-5rpj-abc7",
                    cve_id="CVE-2000-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(vulnerability=art.Vulnerability("ELSA-1998-0098"), package=pkg),
        )
        matches.append(
            art.Match(vulnerability=art.Vulnerability("ELSA-2023-0003"), package=pkg),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ELSA-2022-0002",
                    cve_id="CVE-2022-2222",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ELSA-2021-0001",
                    cve_id="CVE-2000-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ELSA-1999-1234",
                    cve_id="CVE-2021-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(vulnerability=art.Vulnerability("ALAS-1998-0098"), package=pkg),
        )
        matches.append(
            art.Match(vulnerability=art.Vulnerability("ALAS-2023-0003"), package=pkg),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALAS-2022-0002",
                    cve_id="CVE-2022-2222",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALAS-2021-0001",
                    cve_id="CVE-2000-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALAS-1999-1234",
                    cve_id="CVE-2021-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability("ALASKERNEL-1998-0098"),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability("ALASKERNEL-5.1-2023-0003"),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALASKERNEL-5.1-2022-0002",
                    cve_id="CVE-2022-2222",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALASKERNEL-5.1-2021-0001",
                    cve_id="CVE-2000-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALASKERNEL-5.1-1999-1234",
                    cve_id="CVE-2021-1234567",
                ),
                package=pkg,
            ),
        )
        matches.append(
            art.Match(
                vulnerability=art.Vulnerability(
                    "ALASKERNEL-1999-1234",
                    cve_id="CVE-2021-1234567",
                ),
                package=pkg,
            ),
        )
        return matches

    @pytest.fixture()
    def results(self, matches) -> list[art.ScanResult]:
        results: list[art.ScanResults] = []

        for i in range(1):
            cfg = art.ScanConfiguration(
                image_repo="ubuntu",
                image_digest="123456",
                tool_name="grype",
                tool_version=f"v{i}.0",
            )
            results.append(art.ScanResult(cfg, matches=matches))
        return results

    @pytest.mark.parametrize(
        ("expected", "year_limit", "year_from_cve_only"),
        [
            # below cases can only look at the CVE for year indications
            (
                [
                    # CVE below year limit
                    "CVE-2000-1",
                    "CVE-2001-1",
                    "CVE-2002-1",
                    "GHSA-52rh-5rpj-c3w6",
                    "GHSA-52rh-5rpj-abc7",
                    # above the year limit, but under this configuration we should only look at the CVE for this determination
                    # (which in this case is missing)
                    "ALASKERNEL-5.1-2023-0003",  # note: no cve
                    "ALAS-2023-0003",  # note: no cve
                    "ELSA-2023-0003",  # note: no cve
                    # no CVE found
                    "ELSA-1998-0098",  # note: no cve
                    "ALAS-1998-0098",  # note: no cve
                    "ALASKERNEL-1998-0098",  # note: no cve
                    # CVE below year limit
                    "ELSA-2021-0001",  # note: cve 2000
                    "ALAS-2021-0001",  # note: cve 2000
                    "ALASKERNEL-5.1-2021-0001",  # note: cve 2000
                    # CVE above year limit
                    # "ELSA-1999-1234", # note: cve 2021
                    # "ALAS-1999-1234", # note: cve 2021
                    # "ALASKERNEL-5.1-1999-1234", # note: cve 2021
                    # "ALASKERNEL-1999-1234", # note: cve 2021
                ],
                2002,
                True,
            ),
            (
                [
                    # CVE below year limit
                    "CVE-2000-1",
                    "GHSA-52rh-5rpj-c3w6",
                    "GHSA-52rh-5rpj-abc7",
                    # above the year limit, but under this configuration we should only look at the CVE for this determination
                    # (which in this case is missing)
                    "ALASKERNEL-5.1-2023-0003",  # note: no cve
                    "ALAS-2023-0003",  # note: no cve
                    "ELSA-2023-0003",  # note: no cve
                    # no CVE found
                    "ELSA-1998-0098",  # note: no cve
                    "ALAS-1998-0098",  # note: no cve
                    "ALASKERNEL-1998-0098",  # note: no cve
                    # CVE below year limit
                    "ELSA-2021-0001",  # note: cve 2000
                    "ALAS-2021-0001",  # note: cve 2000
                    "ALASKERNEL-5.1-2021-0001",  # note: cve 2000
                    # CVE above year limit
                    # "CVE-2001-1",
                    # "CVE-2002-1",
                    # "ELSA-1999-1234", # note: cve 2021
                    # "ALAS-1999-1234", # note: cve 2021
                    # "ALASKERNEL-5.1-1999-1234", # note: cve 2021
                    # "ALASKERNEL-1999-1234", # note: cve 2021
                ],
                2000,
                True,
            ),
            (
                [
                    # CVE below year limit
                    "GHSA-52rh-5rpj-c3w6",
                    # above the year limit, but under this configuration we should only look at the CVE for this determination
                    # (which in this case is missing)
                    "ALASKERNEL-5.1-2023-0003",  # note: no cve
                    "ALAS-2023-0003",  # note: no cve
                    "ELSA-2023-0003",  # note: no cve
                    # no CVE found
                    "ELSA-1998-0098",  # note: no cve
                    "ALAS-1998-0098",  # note: no cve
                    "ALASKERNEL-1998-0098",  # note: no cve
                    # CVE above year limit
                    # "CVE-2000-1",
                    # "CVE-2001-1",
                    # "CVE-2002-1",
                    # "ELSA-1999-1234",  # note: cve 2021
                    # "ALAS-1999-1234",  # note: cve 2021
                    # "ALASKERNEL-5.1-1999-1234", # note: cve 2021
                    # "ALASKERNEL-1999-1234", # note: cve 2021
                ],
                1999,
                True,
            ),
            # below cases can look at the primary ID for year indication
            (
                [
                    # ID below year limit
                    "CVE-2000-1",
                    "CVE-2001-1",
                    "CVE-2002-1",
                    "GHSA-52rh-5rpj-c3w6",
                    "GHSA-52rh-5rpj-abc7",
                    # ID below year limit
                    "ELSA-1999-1234",  # note: cve 2021
                    "ALAS-1999-1234",  # note: cve 2021
                    "ALASKERNEL-5.1-1999-1234",  # note: cve 2021
                    "ALASKERNEL-1999-1234",  # note: cve 2021
                    "ELSA-1998-0098",  # note: no cve
                    "ALAS-1998-0098",  # note: no cve
                    "ALASKERNEL-1998-0098",  # note: cve 2021
                    # ID above year limit
                    # "ELSA-2021-0001",  # note: cve 2000
                    # "ALAS-2021-0001",  # note: cve 2000
                    # "ALASKERNEL-5.1-2021-0001",  # note: cve 2000
                    # "ALASKERNEL-5.1-2023-0003",  # note: no cve
                    # "ALAS-2023-0003",  # note: no cve
                    # "ELSA-2023-0003",  # note: no cve
                ],
                2002,
                False,
            ),
            (
                [
                    # ID below year limit
                    "CVE-2000-1",
                    "GHSA-52rh-5rpj-c3w6",
                    "GHSA-52rh-5rpj-abc7",
                    # ID below year limit
                    "ELSA-1999-1234",  # note: cve 2021
                    "ALAS-1999-1234",  # note: cve 2021
                    "ALASKERNEL-5.1-1999-1234",  # note: cve 2021
                    "ALASKERNEL-1999-1234",  # note: cve 2021
                    "ELSA-1998-0098",  # note: no cve
                    "ALAS-1998-0098",  # note: no cve
                    # Invalid ID, but since we don't know how to get the year it's included
                    "ALASKERNEL-1998-0098",  # note: no cve
                    # ID above year limit
                    # "CVE-2001-1",
                    # "CVE-2002-1",
                    # "ALASKERNEL-5.1-2023-0003",  # note: no cve
                    # "ALAS-2023-0003",  # note: no cve
                    # "ELSA-2023-0003",  # note: no cve
                    # "ELSA-2021-0001",  # note: cve 2000
                    # "ALAS-2021-0001",  # note: cve 2000
                    # "ALASKERNEL-5.1-2021-0001",  # note: cve 2000
                ],
                2000,
                False,
            ),
            (
                [
                    # ID below year limit
                    "GHSA-52rh-5rpj-c3w6",
                    "ELSA-1998-0098",  # note: no cve
                    "ALAS-1998-0098",  # note: no cve
                    "ELSA-1999-1234",  # note: cve 2021
                    "ALAS-1999-1234",  # note: cve 2021
                    "ALASKERNEL-5.1-1999-1234",  # note: cve 2021
                    "ALASKERNEL-1999-1234",  # note: cve 2021
                    "ALASKERNEL-1998-0098",  # note: no cve
                    # ID above year limit
                    # "CVE-2000-1",
                    # "CVE-2001-1",
                    # "CVE-2002-1",
                    # "ALASKERNEL-5.1-2023-0003",  # note: no cve
                    # "ALAS-2023-0003",  # note: no cve
                    # "ELSA-2023-0003",  # note: no cve
                ],
                1999,
                False,
            ),
        ],
    )
    def test_filter_by_year(self, expected, year_limit, results, year_from_cve_only):
        assert len(results) == 1

        with patch("yardstick.utils.grype_db.normalize_to_cve", lambda _: None):
            filtered = store.scan_result.filter_by_year(
                results,
                year_limit,
                year_from_cve_only=year_from_cve_only,
            )

        for r in filtered:
            ids = [m.vulnerability.id for m in r.matches]
            assert set(expected) == set(ids)
            assert len(expected) == len(ids)  # duplicate matches must be honored
