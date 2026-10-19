package claims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/cache"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
)

func sbomBytes(t *testing.T, image string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixture.SBOM(image, "syft"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func seen(l claimsv1.Label, sbom []byte) claimsv1.Label {
	l.SeenIn = &claimsv1.SeenIn{SBOM: sbomDigest(sbom)}
	return l
}

func writeAt(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// promote-into-a-claims-checkout
func TestPromote(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	deb, npm := sbomBytes(t, "deb"), sbomBytes(t, "npm")

	// the checkout: fp on a key, and the first image's SBOM
	target := corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)))
	writeAt(t, filepath.Join(target, dir, claimsv1.ImageSBOMFile), deb)
	// the local labels: tp on that key, and a label on the other image, whose SBOM only the local
	// directory holds
	local := corpus(t,
		at(claimsv1.TypeFile(dir, "deb"), seen(label(libudv, "CVE-2020-13776", claimsv1.TP), npm)),
		at(claimsv1.TypeFile(otherDir, "deb"), seen(label(libudv, "CVE-2021-33910", claimsv1.TP), npm)),
	)
	writeAt(t, filepath.Join(local, otherDir, claimsv1.ImageSBOMFile), npm)

	out, err := Promote(local, target)
	if err != nil {
		t.Fatal(err)
	}
	f, err := claimsv1.Parse("deb.json", must(os.ReadFile(filepath.Join(target, claimsv1.TypeFile(dir, "deb")))))
	if err != nil || len(f.Labels) != 1 || f.Labels[0].Verdict != claimsv1.TP {
		t.Errorf("expected the target's fp replaced by tp, got %+v %v", f, err)
	}
	if out.Labels != 2 || len(out.SBOMs) != 1 || out.SBOMs[0] != otherDir+"/"+claimsv1.ImageSBOMFile {
		t.Errorf("expected two labels and the one SBOM the target lacked copied, got %+v", out)
	}
	if got := must(os.ReadFile(filepath.Join(target, otherDir, claimsv1.ImageSBOMFile))); sbomDigest(got) != sbomDigest(npm) {
		t.Error("expected the copied SBOM's bytes")
	}
	// the target held the first image's SBOM already; promote leaves it
	if got := must(os.ReadFile(filepath.Join(target, dir, claimsv1.ImageSBOMFile))); sbomDigest(got) != sbomDigest(deb) {
		t.Error("promote replaced an SBOM the target held")
	}
}

func TestPromoteFromTheCache(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	npm := sbomBytes(t, "npm")
	// a run read the SBOM from a claims source: the cache keeps it by digest
	writeAt(t, cache.Dir("sboms-read", strings.ReplaceAll(sbomDigest(npm), ":", "-")+".syft.json"), npm)
	target := corpus(t)
	local := corpus(t, at(claimsv1.TypeFile(otherDir, "deb"), seen(label(libudv, "CVE-2021-33910", claimsv1.TP), npm)))
	if _, err := Promote(local, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, otherDir, claimsv1.ImageSBOMFile)); err != nil {
		t.Errorf("expected the SBOM copied from the cache: %v", err)
	}
}

func TestPromoteRefuses(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	npm := sbomBytes(t, "npm")
	for _, tc := range []struct {
		name  string
		local func(t *testing.T) string
		want  string
	}{
		{"an SBOM missing from both", func(t *testing.T) string {
			return corpus(t, at(claimsv1.TypeFile(otherDir, "deb"), seen(label(libudv, "CVE-2021-33910", claimsv1.TP), npm)))
		}, sbomDigest(npm)},
		{"an invalid label", func(t *testing.T) string {
			src := corpus(t, at(claimsv1.TypeFile(otherDir, "deb"), label(libudv, "CVE-2021-33910", claimsv1.TP)))
			p := filepath.Join(src, claimsv1.TypeFile(otherDir, "deb"))
			// an fp with no justification, as a hand edit leaves it
			edited := strings.Replace(string(must(os.ReadFile(p))), `"verdict": "tp",`, `"verdict": "fp",`, 1)
			edited = strings.Replace(edited, `"justification": "fix-newer",`, "", 1)
			writeAt(t, p, []byte(edited))
			return src
		}, "fp needs a justification"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := corpus(t, at(claimsv1.TypeFile(dir, "deb"), label(libudv, "CVE-2020-13776", claimsv1.FP)))
			before := must(os.ReadFile(filepath.Join(target, claimsv1.TypeFile(dir, "deb"))))
			_, err := Promote(tc.local(t), target)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "CVE-2021-33910") {
				t.Errorf("expected a refusal naming the label and %q, got %v", tc.want, err)
			}
			entries, _ := os.ReadDir(target)
			if after := must(os.ReadFile(filepath.Join(target, claimsv1.TypeFile(dir, "deb")))); string(after) != string(before) || len(entries) != 2 {
				t.Errorf("expected nothing written, got %v", entries)
			}
		})
	}
	if _, err := Promote(filepath.Join(t.TempDir(), "nope"), corpus(t)); err == nil || !strings.Contains(err.Error(), "not a local claims directory") {
		t.Errorf("expected a missing source refused, got %v", err)
	}
}

func must(data []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return data
}

// a target corpus is a contributor's clone that may hold someone else's pull request: promote
// writes nothing through a symlinked subject directory
func TestPromoteStaysInsideTheTarget(t *testing.T) {
	t.Setenv("YARDSTICK_CACHE_DIR", t.TempDir())
	npm := sbomBytes(t, "npm")
	target := corpus(t)
	outside := t.TempDir()
	link := filepath.Join(target, filepath.FromSlash(otherDir))
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	local := corpus(t, at(claimsv1.TypeFile(otherDir, "deb"), seen(label(libudv, "CVE-2021-33910", claimsv1.TP), npm)))
	writeAt(t, filepath.Join(local, otherDir, claimsv1.ImageSBOMFile), npm)
	if _, err := Promote(local, target); err == nil {
		t.Error("expected promote through a symlinked subject directory refused")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("promote wrote outside the target: %v", entries)
	}
}
