from yardstick.cli import config


def test_config(tmp_path):
    subject = """
store_root: .

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

    cfg = config.load(str(file))

    assert cfg.result_sets["sboms"].matrix.images == [
        "docker.io/cloudbees/cloudbees-core-agent:2.289.2.2@sha256:d48f0546b4cf5ef4626136242ce302f94a42751156b7be42f4b1b75a66608880",
        "docker.io/cloudbees/cloudbees-core-mm:2.277.3.1@sha256:4c564f473d38f23da1caa48c4ef53b958ef03d279232007ad3319b1f38584bdb",
        "docker.io/cloudbees/cloudbees-core-oc:2.289.2.2@sha256:9cd85ee84e401dc27e3a8268aae67b594a651b2f4c7fc056ca14c7b0a0a6b82d",
        "docker.io/anchore/test_images:grype-quality-node-d89207b@sha256:f56164678054e5eb59ab838367373a49df723b324617b1ba6de775749d7f91d4",
        "docker.io/vulhub/cve-2017-1000353:latest@sha256:da2a59314b9ccfb428a313a7f163adcef77a74a393b8ebadeca8223b8cea9797",
    ]
