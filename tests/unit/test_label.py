import pytest
from yardstick import artifact
from yardstick.label import (
    _contains_as_value,
    find_labels_for_match,
    has_overlapping_vulnerability_id,
    merge_label_entries,
)


class TestContainsAsValue:
    @pytest.fixture()
    def nested_dict(self):
        return {
            "temparature": "50",
            "treatment": {
                "second": 5,
                "last": "data",
            },
        }

    @pytest.mark.parametrize(
        ("value", "expected_path"),
        [
            ("data", True),
            (5, True),
            ("ata", False),
            ("dat", False),
            ("DATA", False),
            ("anotherdata", False),
            (10, False),
            ("temparature", False),
        ],
    )
    def test_nested_dict(self, nested_dict, value, expected_path):
        assert expected_path == _contains_as_value(nested_dict, value)

    @pytest.fixture()
    def list_of_dicts(self):
        return [{"treatment_plan": [[4, 5, 4], [4, "data", 4], [5, 5, 5]]}]

    @pytest.mark.parametrize(
        ("value", "expected_path"),
        [
            ("data", True),
            (5, True),
            (4, True),
            ("ata", False),
            ("dat", False),
            ("DATA", False),
            ("anotherdata", False),
            (10, False),
            ("treatment_plan", False),
        ],
    )
    def test_list_of_dicts(self, list_of_dicts, value, expected_path):
        assert expected_path == _contains_as_value(list_of_dicts, value)


class TestFindLabelsForMatch:
    @pytest.fixture()
    def label_entries(self):
        return [
            ##############################################################
            # CVE CVE-2020-0001
            # vat import
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0001",
                source="vat-import",
                user="somebody",
                package=artifact.Package(name="package", version="1.0"),
                ID="1",
            ),
            # manual entry
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                image=artifact.ImageSpecifier(exact="my/image:latest"),
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="package", version="1.0"),
                source="manual",
                user="somebody",
                ID="2",
            ),
            # manual entry, image pattern missing
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="package", version="1.0"),
                source="manual",
                user="somebody",
                ID="3",
            ),
            #################################################################
            # CVE CVE-2020-0002
            # manual entry, with image + extra match fields
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                image=artifact.ImageSpecifier(exact="my/image:latest"),
                vulnerability_id="CVE-2020-0002",
                package=artifact.Package(name="package", version="1.0"),
                source="manual",
                user="somebody",
                fullentry_fields=[
                    "4-best-match-4",
                ],
                ID="4",
            ),
            # manual entry, extra match fields
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0002",
                package=artifact.Package(name="package", version="1.0"),
                source="manual",
                user="somebody",
                fullentry_fields=[
                    "5-best-match-5",
                    "5-another-match-5",
                ],
                ID="5",
            ),
            #################################################################
            # never match against these
            # mismatch package name
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="never-match", version="1.0"),
                source="manual",
                user="somebody",
                fullentry_fields=[
                    "never-match",
                    "never-match",
                ],
                ID="1000",
            ),
            # different CVE
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-11111",
                source="vat-import",
                user="somebody",
                ID="1001",
            ),
        ]

    @pytest.mark.parametrize(
        ("image", "match", "expected_label_ids"),
        [
            # case: match on all
            (
                "my/image:latest",
                artifact.Match(
                    vulnerability=artifact.Vulnerability(id="CVE-2020-0001"),
                    package=artifact.Package(name="package", version="1.0"),
                ),
                ["1", "2", "3"],
            ),
            # case: match with different image
            (
                "another-mismatched/image:latest",
                artifact.Match(
                    vulnerability=artifact.Vulnerability(id="CVE-2020-0001"),
                    package=artifact.Package(name="package", version="1.0"),
                ),
                ["1", "3"],
            ),
            # case: match with extra info
            (
                "my/image:latest",
                artifact.Match(
                    vulnerability=artifact.Vulnerability(id="CVE-2020-0002"),
                    package=artifact.Package(name="package", version="1.0"),
                    fullentry={"something": "4-best-match-4"},
                ),
                ["4"],
            ),
            # case: match with multiple extra info
            (
                "my/image:latest",
                artifact.Match(
                    vulnerability=artifact.Vulnerability(id="CVE-2020-0002"),
                    package=artifact.Package(name="package", version="1.0"),
                    fullentry={
                        "something": "5-best-match-5",
                        "another": [
                            1,
                            {
                                "weird": "5-another-match-5",
                            },
                        ],
                    },
                ),
                ["5"],
            ),
            # case: match on a non-CVE vuln id (e.g. GHSA) must not pull in labels
            # for *different* non-CVE vuln ids on the same package just because
            # both sides have no effective_cve / cve_id
            (
                "my/image:latest",
                artifact.Match(
                    vulnerability=artifact.Vulnerability(id="GHSA-xxxx-yyyy-zzzz"),
                    package=artifact.Package(name="package", version="1.0"),
                ),
                [],
            ),
        ],
    )
    def test_find_labels_for_match(
        self,
        label_entries,
        image,
        match,
        expected_label_ids,
    ):
        ids = [m.ID for m in find_labels_for_match(image, match, label_entries)]
        assert expected_label_ids == ids


class TestHasOverlappingVulnerabilityID:
    @pytest.mark.parametrize(
        ("label_vuln_id", "label_effective_cve", "match_vuln_id", "match_cve_id", "expected"),
        [
            # same CVE on both sides
            ("CVE-2020-0001", None, "CVE-2020-0001", "CVE-2020-0001", True),
            # same GHSA on both sides (no CVEs known)
            ("GHSA-aaaa-bbbb-cccc", None, "GHSA-aaaa-bbbb-cccc", None, True),
            # GHSA on the label aliases to a CVE that the match also carries
            ("GHSA-aaaa-bbbb-cccc", "CVE-2020-0001", "CVE-2020-0001", "CVE-2020-0001", True),
            # GHSA on the match aliases to a CVE that the label also carries
            ("CVE-2020-0001", None, "GHSA-aaaa-bbbb-cccc", "CVE-2020-0001", True),
            # different non-CVE ids with no CVE aliases on either side must NOT overlap
            # (regression: previously both sides carried None and set-intersected on it)
            ("GHSA-aaaa-bbbb-cccc", None, "GHSA-xxxx-yyyy-zzzz", None, False),
            # same guard, but with empty strings instead of None
            ("GHSA-aaaa-bbbb-cccc", "", "GHSA-xxxx-yyyy-zzzz", "", False),
            # completely disjoint CVE ids
            ("CVE-2020-0001", None, "CVE-2020-0002", "CVE-2020-0002", False),
        ],
    )
    def test_overlap(self, label_vuln_id, label_effective_cve, match_vuln_id, match_cve_id, expected):
        label_entry = artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id=label_vuln_id,
            effective_cve=label_effective_cve,
            package=artifact.Package(name="package", version="1.0"),
            source="manual",
            user="somebody",
            ID="x",
        )
        match = artifact.Match(
            vulnerability=artifact.Vulnerability(id=match_vuln_id, cve_id=match_cve_id),
            package=artifact.Package(name="package", version="1.0"),
        )
        assert has_overlapping_vulnerability_id(label_entry, match) is expected


class TestMergeLabelEntries:
    @pytest.fixture()
    def existing_label_entries(self):
        return [
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                image="dontcare",
                vulnerability_id="CVE-2020-0001",
                source="vat-import",
                user="somebody",
                package=artifact.Package(name="package", version="1.0"),
                ID="1",
            ),
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                image=artifact.ImageSpecifier(exact="my/image:latest"),
                vulnerability_id="CVE-2020-0001",
                package=artifact.Package(name="package", version="1.0"),
                source="manual",
                user="somebody",
                ID="2",
            ),
            artifact.LabelEntry(
                label=artifact.Label.FalsePositive,
                vulnerability_id="CVE-2020-0001",
                image="dontcare",
                package=artifact.Package(name="package", version="1.0"),
                source="manual",
                user="somebody",
                ID="3",
            ),
        ]

    @pytest.mark.parametrize(
        ("new_label_entries", "deleted_label_ids", "expected_label_ids"),
        [
            # case: add a new label
            (
                [
                    artifact.LabelEntry(
                        label=artifact.Label.FalsePositive,
                        image="dontcare",
                        vulnerability_id="CVE-2020-0001",
                        package=artifact.Package(name="package", version="1.0"),
                        source="manual",
                        user="somebody",
                        ID="4",
                    ),
                ],
                [],
                ["1", "2", "3", "4"],
            ),
            # case: delete a new label
            (
                [],
                ["2"],
                ["1", "3"],
            ),
            # case: modify a label
            (
                [
                    artifact.LabelEntry(
                        label=artifact.Label.FalsePositive,
                        vulnerability_id="CVE-1995-DIFFERENT",
                        image="dontcare",
                        package=artifact.Package(name="WOOT", version="42.0"),
                        source="AUTOMATIC",
                        user="ANYBODY",
                        ID="3",
                    ),
                ],
                [],
                ["1", "2", "3"],
            ),
            # case: mix!
            (
                [
                    # modification of 3...
                    artifact.LabelEntry(
                        label=artifact.Label.FalsePositive,
                        image="dontcare",
                        vulnerability_id="CVE-1995-DIFFERENT",
                        package=artifact.Package(name="WOOT", version="42.0"),
                        source="AUTOMATIC",
                        user="ANYBODY",
                        ID="3",
                    ),
                    # addition of 4...
                    artifact.LabelEntry(
                        label=artifact.Label.FalsePositive,
                        vulnerability_id="CVE-2020-0001",
                        image="dontcare",
                        package=artifact.Package(name="package", version="1.0"),
                        source="manual",
                        user="somebody",
                        ID="4",
                    ),
                ],
                ["1"],
                ["2", "3", "4"],
            ),
        ],
    )
    def test_merge_label_entries(
        self,
        existing_label_entries,
        new_label_entries,
        deleted_label_ids,
        expected_label_ids,
    ):
        merged_entries = merge_label_entries(
            existing_label_entries,
            new_label_entries,
            deleted_label_ids,
        )

        # technically the second assertion includes this, but this is easier to see when debugging
        ids = [m.ID for m in merged_entries]
        assert expected_label_ids == ids

        # check that we persisted mutated data for all elements
        for entry in new_label_entries:
            assert entry in merged_entries
