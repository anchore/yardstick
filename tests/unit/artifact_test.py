from datetime import datetime

import pytest

from yardstick import artifact


def test_sort_matches():

    a = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2019-18276"),
        package=artifact.Package(name="bash", version="5.0-6ubuntu1.1"),
    )

    b = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2016-2781"),
        package=artifact.Package(name="coreutils", version="8.30-3ubuntu2"),
        config=artifact.ScanConfiguration(image_repo="fff", image_digest="fff", tool_name="fff", tool_version="fff"),
    )

    c = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2016-10228"),
        package=artifact.Package(name="libc-bin", version="2.31-0ubuntu9.2"),
        config=artifact.ScanConfiguration(image_repo="ddd", image_digest="ddd", tool_name="ddd", tool_version="ddd"),
    )

    d = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2018-20839"),
        package=artifact.Package(name="libsystemd0", version="245.4-4ubuntu3.2"),
    )

    e = artifact.Match(
        vulnerability=artifact.Vulnerability(id="CVE-2018-299999999"),
        package=artifact.Package(name="libsystemd0", version="25"),
        config=artifact.ScanConfiguration(image_repo="a", image_digest="a", tool_name="a", tool_version="a"),
    )

    assert sorted([d, e, c, b, a]) == [a, b, c, d, e]


def test_sort_packages():

    a = artifact.Package(name="bash", version="5.0-6ubuntu1.1")

    b = artifact.Package(name="coreutils", version="8.30-3ubuntu2")

    c = artifact.Package(name="libc-bin", version="2.31-0ubuntu9.2")

    d = artifact.Package(name="libsystemd0", version="245.4-4ubuntu3.2")

    e = artifact.Package(name="libsystemd0", version="25")

    assert sorted([d, c, e, b, a]) == [a, b, c, d, e]


class TestImageSpecifier:
    @pytest.mark.parametrize(
        "specifier, image, expected",
        [
            # exact match
            (
                artifact.ImageSpecifier(
                    exact="something/exact:latest",
                ),
                "something/exact:latest",
                True,
            ),
            # missing tail
            (
                artifact.ImageSpecifier(
                    exact="something/exact:lates",
                ),
                "something/exact:latest",
                False,
            ),
            # matches prefix
            (
                artifact.ImageSpecifier(
                    prefix="something/exact:lates",
                ),
                "something/exact:latest",
                True,
            ),
            # matches regex
            (
                artifact.ImageSpecifier(
                    regex="^.*/exact:latest$",
                ),
                "something/exact:latest",
                True,
            ),
        ],
    )
    def test_matches(self, specifier, image, expected):
        assert expected == specifier.matches_image(image)


def test_tool():

    t = artifact.Tool("grype@main")

    assert t.name == "grype"
    assert t.version == "main"


def test_image():

    i = artifact.Image("docker.io/place/ubuntu:thing@sha256:123")

    assert i.repository == "docker.io/place/ubuntu"
    assert i.tag == "thing"
    assert i.digest == "sha256:123"
    assert i.repository_encoded == "docker.io+place+ubuntu"
    assert i.encoded == "docker.io+place+ubuntu@sha256:123"

    assert i.is_like(other="docker.io/place/ubuntu@sha256:123")
    assert not i.is_like(other="docker.io/place/ubuntu:SOMETHINGELSE@sha256:123")
    assert not i.is_like(other="docker.io/SOMETHINGELSE/ubuntu@sha256:123")
    assert not i.is_like(other="docker.io/place/ubuntu@sha256:SOMETHINGELSE")


def test_scan_configuration():

    ts_rfc3339 = "2022-09-06T16:07:01+00:00"
    ts = datetime.fromisoformat(ts_rfc3339)

    s = artifact.ScanConfiguration(
        image_repo="docker.io+place+ubuntu",
        image_digest="sha256:123",
        image_tag="stuff",
        tool_name="grype",
        tool_version="main",
        timestamp=ts,
    )

    assert s.image_repo == "docker.io/place/ubuntu"
    assert s.image_digest == "sha256:123"
    assert s.image_tag == "stuff"
    assert s.tool_name == "grype"
    assert s.tool_version == "main"
    assert s.tool_input == "docker.io/place/ubuntu@sha256:123"
    assert s.timestamp == datetime.fromisoformat(ts_rfc3339)
    assert s.timestamp_rfc3339 == ts_rfc3339
    assert s.tool == "grype@main"
    assert s.image == "docker.io/place/ubuntu@sha256:123"
    assert s.image_encoded == "docker.io+place+ubuntu@sha256:123"
    assert s.image_repo_encoded == "docker.io+place+ubuntu"
    assert s.path == "docker.io/place/ubuntu@sha256:123/grype@main/2022-09-06T16:07:01+00:00"
    assert s.encoded_path == "docker.io+place+ubuntu@sha256:123/grype@main/2022-09-06T16:07:01+00:00"


def test_dt_encoder():
    ts = datetime.fromisoformat("2022-09-06T16:07:01+00:00")
    assert artifact.DTEncoder().default(ts) == "2022-09-06T16:07:01+00:00"
