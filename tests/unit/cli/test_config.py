import pytest

from yardstick.cli import config


def test_config(tmp_path):
    profile_file = tmp_path / ".yardstick.profiles.yaml"
    subject = f"""
store_root: .
profile_path: {profile_file}
default-max-year: 2021

x-ref:
  full-label-set-images: &full-label-set-images
    - docker.io/cloudbees/cloudbees-core-agent:2.289.2.2@sha256:d48f0546b4cf5ef4626136242ce302f94a42751156b7be42f4b1b75a66608880
    - docker.io/cloudbees/cloudbees-core-mm:2.277.3.1@sha256:4c564f473d38f23da1caa48c4ef53b958ef03d279232007ad3319b1f38584bdb
    - docker.io/cloudbees/cloudbees-core-oc:2.289.2.2@sha256:9cd85ee84e401dc27e3a8268aae67b594a651b2f4c7fc056ca14c7b0a0a6b82d
    - docker.io/anchore/test_images:grype-quality-node-d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4

  partial-label-set-images: &partial-label-set-images
    - docker.io/vulhub/cve-2017-1000353:latest@sha256:da2a59314b9ccfb428a313a7f163adcef77a74a393b8ebadeca8223b8cea9797

result-sets:

  sboms:

    description: "SBOMs for images that should be fully labeled"
    matrix:
      images:
        - *full-label-set-images
        - *partial-label-set-images

      tools:

        - name: syft
          # note: we want to use a fixed version of syft for capturing all results (NOT "latest")
          version: v0.68.1
          # once we have results captured, don't re-capture them
          refresh: false
"""
    file = tmp_path / "config.yaml"
    file.write_text(subject)

    profile_text = """
test_profile:
  something:
    name: jim
    config_path: .abc/xyx.conf
    refresh: false
"""
    profile_file.write_text(profile_text)

    cfg = config.load(str(file))

    assert cfg.result_sets["sboms"].matrix.images == [
        "docker.io/cloudbees/cloudbees-core-agent:2.289.2.2@sha256:d48f0546b4cf5ef4626136242ce302f94a42751156b7be42f4b1b75a66608880",
        "docker.io/cloudbees/cloudbees-core-mm:2.277.3.1@sha256:4c564f473d38f23da1caa48c4ef53b958ef03d279232007ad3319b1f38584bdb",
        "docker.io/cloudbees/cloudbees-core-oc:2.289.2.2@sha256:9cd85ee84e401dc27e3a8268aae67b594a651b2f4c7fc056ca14c7b0a0a6b82d",
        "docker.io/anchore/test_images:grype-quality-node-d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4",
        "docker.io/vulhub/cve-2017-1000353:latest@sha256:da2a59314b9ccfb428a313a7f163adcef77a74a393b8ebadeca8223b8cea9797",
    ]

    assert cfg.profiles == config.Profiles(
        {
            "test_profile": {
                "something": {
                    "name": "jim",
                    "config_path": ".abc/xyx.conf",
                    "refresh": False,
                },
            },
        },
    )


@pytest.mark.parametrize(
    "name, image, expected_valid",
    [
        # valid: everything present
        (
            "valid",
            "registry.example.com/repo/image:latest@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            True,
        ),
        (
            "valid: vulhub",
            "docker.io/vulhub/cve-2017-1000353:latest@sha256:da2a59314b9ccfb428a313a7f163adcef77a74a393b8ebadeca8223b8cea9797",
            True,
        ),
        (
            "valid: alpine",
            "docker.io/alpine:3.2@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9",
            True,
        ),
        # valid: localhost with port as repo host
        (
            "valid: localhost with port as repo host",
            "localhost:5555/repo/image:latest@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            True,
        ),
        (
            "valid: missing tag is allowed but discouraged",
            "registry.access.redhat.com/ubi8@sha256:68fecea0d255ee253acbf0c860eaebb7017ef5ef007c25bee9eeffd29ce85b29",
            True,
        ),
        (
            "invalid: missing host",
            "repo/image:latest@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            False,
        ),
        ("invalid: missing digest", "registry.example.com/repo/image:latest", False),
        ("invalid: missing everything", "repo/image", False),
        ("invalid: empty string", "", False),
        (
            "invalid: missing repo",
            "registry.example.com/:latest@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            False,
        ),
        ("invalid: missing repo and tag", "registry.example.com/", False),
        ("invalid: missing digest", "registry.example.com/repo/image:stable", False),
        (
            "invalid: digest does not look like sha256",
            "registry.example.com/repo/image:latest@sha256:invaliddigest",
            False,
        ),
        (
            "invalid: bad sha256 (too short)",
            "docker.io/alpine:3.2@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc27697",
            False,
        ),
    ],
)
def test_is_valid_oci_reference(name, image, expected_valid):
    result = config.ScanMatrix.is_valid_oci_reference(image)
    assert (
        result == expected_valid
    ), f"Test case {name}: Expected {expected_valid} but got {result} for image '{image}'"


@pytest.mark.parametrize(
    "image, expected_output",
    [
        (
            "docker.io/anchore/test_images:some-tag@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            (
                "docker.io",
                "anchore",
                "test_images",
                "some-tag",
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
        ),
        # Localhost reference with path, repository, tag, and digest
        (
            "localhost/anchore/test_images:some-tag@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            (
                "localhost",
                "anchore",
                "test_images",
                "some-tag",
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
        ),
        # Localhost with port, path, repository, tag, and digest
        (
            "localhost:5000/anchore/test_images:some-tag@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            (
                "localhost:5000",
                "anchore",
                "test_images",
                "some-tag",
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
        ),
        # Missing digest
        (
            "docker.io/anchore/test_images:some-tag",
            ("docker.io", "anchore", "test_images", "some-tag", ""),
        ),
        # Missing tag
        (
            "docker.io/anchore/test_images@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            (
                "docker.io",
                "anchore",
                "test_images",
                "",
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ),
        ),
        # Only repository
        ("test_images", ("", "", "test_images", "", "")),
    ],
)
def test_parse_oci_reference(image, expected_output):
    result = config.ScanMatrix.parse_oci_reference(image)
    assert (
        result == expected_output
    ), f"Expected {expected_output} but got {result} for image '{image}'"
