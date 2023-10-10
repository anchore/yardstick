import pytest
from yardstick import store


class TestNamingImage:
    @pytest.mark.parametrize(
        ("image", "expected"),
        [
            ("ubuntu:20.04", "ubuntu:20.04"),
            ("anchore/anchore-engine:latest", "anchore+anchore-engine:latest"),
            ("something/nested/image:latest", "something+nested+image:latest"),
        ],
    )
    def test_encode_decode(self, image, expected):
        assert expected == store.naming.image.encode(image)
        assert image == store.naming.image.decode(expected)
