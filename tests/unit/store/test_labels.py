from __future__ import annotations

import os

from yardstick import store

FIXTURE_ROOT = os.path.join(os.path.dirname(__file__), "..", "test-fixtures")
DIGEST = "sha256:2d761ba36575ddd4e07d446f4f2a05448298c20e5bdcd3dedfbbc00f9865240d"
DOCKERHUB = f"docker.io/anchore/test_images@{DIGEST}"
GHCR = f"ghcr.io/anchore/test-images/golang@{DIGEST}"


def load(images):
    return store.labels.load_for_image(images, store_root=FIXTURE_ROOT)


def test_load_for_image_by_registry_address():
    assert len(load(DOCKERHUB)) == 1


def test_load_for_image_by_other_registry_address_with_same_digest():
    assert [e.ID for e in load(GHCR)] == [e.ID for e in load(DOCKERHUB)]


def test_load_for_image_does_not_double_count_same_digest():
    assert len(load([DOCKERHUB, GHCR])) == 1


def test_load_for_image_different_digest_finds_nothing():
    assert load(GHCR.replace("2d761", "3d761")) == []
