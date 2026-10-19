package ref

import (
	"strings"
	"testing"
)

const d = "sha256:f0f8e8ee94f8b5d9364f21ceffd50b7db7e19b1938271295eff8229b3cf56db2"

func TestParse(t *testing.T) {
	tests := []struct {
		in                       string
		registry, repo, tag, img string
	}{
		{"oci:docker.io/anchore/test_images@" + d, "docker.io", "anchore/test_images", "", "docker.io/anchore/test_images@" + d},
		{"oci:ubuntu:22.04@" + d, "docker.io", "library/ubuntu", "22.04", "docker.io/library/ubuntu:22.04@" + d},
		{"oci:index.docker.io/cloudbees/cloudbees-core-mm@" + d, "docker.io", "cloudbees/cloudbees-core-mm", "", "docker.io/cloudbees/cloudbees-core-mm@" + d},
		{"oci:localhost:5000/team/app:v1@" + d, "localhost:5000", "team/app", "v1", "localhost:5000/team/app:v1@" + d},
		{"oci:ghcr.io/anchore/vml-sbom/x@" + d, "ghcr.io", "anchore/vml-sbom/x", "", "ghcr.io/anchore/vml-sbom/x@" + d},
	}
	for _, tt := range tests {
		r, err := Parse(tt.in)
		if err != nil {
			t.Fatalf("%s: %v", tt.in, err)
		}
		if r.Kind != Image || r.Registry != tt.registry || r.Repository != tt.repo || r.Tag != tt.tag || r.Digest != d || r.Image() != tt.img {
			t.Errorf("%s: got %+v", tt.in, r)
		}
		if again, _ := Parse(r.String()); again != r {
			t.Errorf("%s: expected String to parse back to the same ref, got %+v", tt.in, again)
		}
	}

	r, err := Parse("sbom:subjects/vendor.cdx.json")
	if err != nil || r.Kind != SBOM || r.Path != "subjects/vendor.cdx.json" {
		t.Errorf("expected an SBOM subject, got %+v %v", r, err)
	}

	for in, want := range map[string]string{
		"oci:docker.io/library/ubuntu:22.04":  "pinned by digest",
		"oci:ubuntu@sha256:abc":               "not a sha256 digest",
		"pkg:deb/debian/libxml2@2.7.8.dfsg-2": "oci:<image>@sha256:<digest> or sbom:<path>",
		"docker.io/library/ubuntu@" + d:       "oci:<image>@sha256:<digest> or sbom:<path>",
		"sbom:":                               "names no SBOM file",
	} {
		if _, err := Parse(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected an error with %q, got %v", in, want, err)
		}
	}
}
