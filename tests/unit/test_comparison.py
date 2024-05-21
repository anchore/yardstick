from yardstick import artifact, comparison

# TODO: include test with lineage


def test_comparison_against_labels():
    config = artifact.ScanConfiguration(
        image_repo="myimage",
        image_digest="123456",
        tool_name="grype",
        tool_version="main",
    )

    package_bash_5 = artifact.Package(name="bash", version="5.0-6ubuntu1.1")
    package_coreutils_8 = artifact.Package(name="coreutils", version="8.30-3ubuntu2")
    package_libc_2 = artifact.Package(name="libc-bin", version="2.31-0ubuntu9.2")
    package_libsystemd_245 = artifact.Package(
        name="libsystemd0",
        version="245.4-4ubuntu3.2",
    )
    package_libsystemd_25 = artifact.Package(name="libsystemd0", version="25")

    expected_tp_matches = [
        artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2019-18276"),
            package=package_bash_5,
            config=config,
        ),
        artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2016-2781"),
            package=package_coreutils_8,
            config=config,
        ),
    ]

    expected_fp_matches = [
        artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2016-10228"),
            package=package_libc_2,
            config=config,
        ),
        artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2018-20839"),
            package=package_libsystemd_245,
            config=config,
        ),
        artifact.Match(
            vulnerability=artifact.Vulnerability(id="CVE-2018-29999"),
            package=package_libsystemd_25,
            config=config,
        ),
    ]

    matches = [
        *expected_tp_matches,
        *expected_fp_matches,
    ]

    result = artifact.ScanResult(
        config=config,
        matches=matches,
    )

    common_label_options = {
        "image": artifact.ImageSpecifier(exact=config.image),
        "source": "manual",
    }

    false_negative_label_entries = [
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2016-NM111",
            package=package_libc_2,
            **common_label_options,
        ),
        # do not have matches and already are covered with effective CVE... but the package mismatches
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="ELSA-2020-123567",
            effective_cve="CVE-2019-18276",
            package=package_libsystemd_25,
            **common_label_options,
        ),
    ]

    label_entries = [
        # have matches
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2019-18276",
            package=package_bash_5,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2016-2781",
            package=package_coreutils_8,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id="CVE-2016-10228",
            package=package_libc_2,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id="CVE-2018-20839",
            package=package_libsystemd_245,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id="CVE-2018-29999",
            package=package_libsystemd_25,
            **common_label_options,
        ),
        # do not have matches
        *false_negative_label_entries,
        artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id="CVE-2016-NM222",
            package=package_libc_2,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id="CVE-2016-NM333",
            package=package_libsystemd_25,
            **common_label_options,
        ),
        # do not have matches and already are covered with effective CVE
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="ELSA-2020-123567",
            effective_cve="CVE-2019-18276",
            package=package_bash_5,
            **common_label_options,
        ),
    ]

    actual = comparison.AgainstLabels(
        result=result,
        label_entries=label_entries,
        lineage=[],
    )

    assert actual.summary.true_positives == len(expected_tp_matches)
    assert actual.summary.false_positives == len(expected_fp_matches)
    assert actual.summary.false_negatives == len(false_negative_label_entries)
    assert actual.summary.f1_score == 0.4444444444444444

    assert set(actual.true_positive_matches) == set(expected_tp_matches)
    assert set(actual.false_positive_matches) == set(expected_fp_matches)
    assert set(actual.false_negative_label_entries) == set(false_negative_label_entries)


def test_comparison_against_labels_indeterminate():
    config = artifact.ScanConfiguration(
        image_repo="myimage",
        image_digest="123456",
        tool_name="grype",
        tool_version="main",
    )

    package_bash_5 = artifact.Package(name="bash", version="5.0-6ubuntu1.1")

    m1 = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2019-18276"),
        package=package_bash_5,
        config=config,
    )
    m2 = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2020-12000"),
        package=package_bash_5,
        config=config,
    )
    m3 = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2020-2222"),
        package=package_bash_5,
        config=config,
    )

    matches = [m1, m2, m3]

    result = artifact.ScanResult(
        config=config,
        matches=matches,
    )

    common_label_options = {
        "image": artifact.ImageSpecifier(exact=config.image),
        "source": "manual",
    }

    m2_indeterminate = [
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2020-12000",
            package=package_bash_5,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.FalsePositive,
            vulnerability_id="CVE-2020-12000",
            package=package_bash_5,
            **common_label_options,
        ),
    ]

    m3_indeterminate = [
        artifact.LabelEntry(
            label=artifact.Label.Unclear,
            vulnerability_id="CVE-2020-2222",
            package=package_bash_5,
            **common_label_options,
        ),
    ]

    label_entries = [
        # not indeterminate
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2019-18276",
            package=package_bash_5,
            **common_label_options,
        ),
        artifact.LabelEntry(
            label=artifact.Label.TruePositive,
            vulnerability_id="CVE-2019-18276",
            package=package_bash_5,
            **common_label_options,
        ),
        # indeterminate
        *m2_indeterminate,
        *m3_indeterminate,
    ]

    actual = comparison.AgainstLabels(
        result=result,
        label_entries=label_entries,
        lineage=[],
    )

    assert actual.summary.indeterminate == 1
    assert set(actual.matches_with_indeterminate_labels) == {m2}
    assert actual.summary.f1_score == 1
    assert actual.summary.f1_score_lower_confidence == 0.6666666666666666
    assert actual.summary.f1_score_upper_confidence == 1
