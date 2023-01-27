import pytest

from yardstick import artifact as art
from yardstick import store, utils


class TestFilterByYear:
    def make_matches(self) -> list[art.Match]:
        matches: list[art.Match] = []
        pkg = art.Package("busybox", "1.34.1-r5")
        for i in range(3):
            vuln = art.Vulnerability("CVE-200{}-1".format(i))
            matches.append(art.Match(vulnerability=vuln, package=pkg))

        matches.append(art.Match(vulnerability=art.Vulnerability("GHSA-52rh-5rpj-c3w6"), package=pkg))
        matches.append(art.Match(vulnerability=art.Vulnerability("GHSA-52rh-5rpj-abc7", cve_id="CVE-2000-1234567"), package=pkg))
        matches.append(art.Match(vulnerability=art.Vulnerability("ELSA-2021-0001", cve_id="CVE-2000-1234567"), package=pkg))
        matches.append(art.Match(vulnerability=art.Vulnerability("ELSA-1999-1234", cve_id="CVE-2021-1234567"), package=pkg))
        matches.append(art.Match(vulnerability=art.Vulnerability("ALAS-2021-0001", cve_id="CVE-2000-1234567"), package=pkg))
        matches.append(art.Match(vulnerability=art.Vulnerability("ALAS-1999-1234", cve_id="CVE-2021-1234567"), package=pkg))
        matches.append(
            art.Match(vulnerability=art.Vulnerability("ALASKERNEL-5.1-2021-0001", cve_id="CVE-2000-1234567"), package=pkg)
        )
        matches.append(
            art.Match(vulnerability=art.Vulnerability("ALASKERNEL-5.1-1999-1234", cve_id="CVE-2021-1234567"), package=pkg)
        )
        matches.append(art.Match(vulnerability=art.Vulnerability("ALASKERNEL-1999-1234", cve_id="CVE-2021-1234567"), package=pkg))
        return matches

    def make_results(self) -> list[art.ScanResult]:
        results: list[art.ScanResults] = []
        matches = self.make_matches()

        for i in range(1):
            cfg = art.ScanConfiguration(
                image_repo="ubuntu",
                image_digest="123456",
                tool_name="grype",
                tool_version="v{}.0".format(i),
            )
            results.append(art.ScanResult(cfg, matches=matches))
        return results

    @pytest.mark.parametrize(
        "expected, year_limit",
        [
            (
                [
                    "CVE-2000-1",
                    "CVE-2001-1",
                    "CVE-2002-1",
                    "GHSA-52rh-5rpj-c3w6",
                    "GHSA-52rh-5rpj-abc7",
                    "ELSA-1999-1234",
                    "ALAS-1999-1234",
                    "ALASKERNEL-1999-5.1-1234",
                ],
                2002,
            ),
            (
                [
                    "CVE-2000-1",
                    "GHSA-52rh-5rpj-c3w6",
                    "GHSA-52rh-5rpj-abc7",
                    "ELSA-1999-1234",
                    "ALAS-1999-1234",
                    "ALASKERNEL-5.1-1999-1234",
                ],
                2000,
            ),
            (["GHSA-52rh-5rpj-c3w6", "ELSA-1999-1234", "ALAS-1999-1234", "ALASKERNEL-5.1-1999-1234"], 1999),
        ],
    )
    def test_filter_by_year(self, expected, year_limit):
        results = self.make_results()
        assert len(results) == 1

        utils.grype_db.raise_on_failure(False)
        filtered = store.scan_result.filter_by_year(results, year_limit)

        for r in filtered:
            ids = [m.vulnerability.id for m in r.matches]
            assert expected == ids
