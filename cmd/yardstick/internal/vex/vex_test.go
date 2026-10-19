package vex

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/anchore/yardstick/cmd/yardstick/internal/fixture"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// the corpus's own data: categories people write, not tool output
const vocabYAML = `justifications:
  fp:
    fix-installed: Installed version has the fix
    vulnerable_code_not_present: Vulnerable code is not in this package
    different-product: CVE is about a different product with this name
    vendor-not-affected: Vendor marks it not affected without saying why
  tp:
    fix-newer: Fix is in a newer version than installed
  unclear:
    not-assessed: Nobody has assessed this version
fact-sources: [openvex, osv, sbom]
advisory-ids: [RHSA]
vulnerability-namespaces: [CVE, GHSA, PYSEC]
`

const debDigest = "sha256:617d48dd2601779266746a9a382bfb9f3fee2744fba698733b320366f41718b0"

var (
	now         = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	debImage, _ = ref.Parse("oci:docker.io/anchore/yardstick-fixture-deb@" + debDigest)
	debDir      = labels.ImageDir(debImage)
)

func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func corpusDir(t *testing.T) (string, labels.Writer) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, labels.VocabularyFile), []byte(vocabYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := labels.LoadVocabulary(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	return dir, labels.Writer{Dir: dir, Vocab: v}
}

func find(placed []labels.Placed, vuln string) []labels.Placed {
	var out []labels.Placed
	for _, p := range placed {
		if p.Label.Vulnerability == vuln {
			out = append(out, p)
		}
	}
	return out
}

// import-vendor-statements, OpenVEX: a document vexctl made
func TestImportOpenVEX(t *testing.T) {
	path := fixture.Path("vex", "vendor.openvex.json")
	got, err := Import(path, read(t, path), Options{Author: "Alex Goodman", Now: now})
	if err != nil {
		t.Fatal(err)
	}

	// an image product with a subcomponent: an fp in the image's deb file, citing the statement
	np := find(got.Placed, "CVE-2023-45853")
	if len(np) != 1 || np[0].File != labels.TypeFile(debDir, "deb") || np[0].Label.Verdict != labels.FP ||
		np[0].Label.Justification != "vulnerable_code_not_present" || np[0].Label.Package != "pkg:deb/debian/zlib1g@1:1.2.13.dfsg-1?arch=arm64&distro=debian-12" {
		t.Fatalf("expected an fp on zlib1g in the deb file, got %+v", np)
	}
	ev := np[0].Label.Evidence
	if len(ev) != 1 || ev[0].Facts[0].Source != "openvex" || ev[0].Facts[0].About["statement"] != "0" || !strings.HasPrefix(ev[0].Facts[0].About["document"], "https://openvex.dev/docs/") ||
		ev[0].Facts[0].Value != "not_affected (vulnerable_code_not_present)" || ev[0].Interpretation == "" {
		t.Errorf("expected one evidence entry citing the document, statement and status, got %+v", ev)
	}

	// a package product is a global label; fixed is an fp with the fix installed
	fixed := find(got.Placed, "CVE-2024-0727")
	if len(fixed) != 1 || fixed[0].File != "global/rpm.json" || fixed[0].Subject != nil || fixed[0].Label.Justification != "fix-installed" {
		t.Errorf("expected a global fp in global/rpm.json, got %+v", fixed)
	}
	// an image with no subcomponent is about the image: image.json, tp, the action as its note
	aff := find(got.Placed, "CVE-2023-4911")
	if len(aff) != 1 || aff[0].File != debDir+"/image.json" || aff[0].Label.Verdict != labels.TP || aff[0].Label.Package != "" || len(aff[0].Label.Notes) != 1 || aff[0].Label.Notes[0].Text != "upgrade libc6" {
		t.Errorf("expected a tp in image.json, got %+v", aff)
	}
	ui := find(got.Placed, "CVE-2023-50495")
	if len(ui) != 1 || ui[0].Label.Verdict != labels.Unclear || ui[0].Label.Justification != "not-assessed" {
		t.Errorf("expected under_investigation as unclear, got %+v", ui)
	}
	// a product that is no package URL is skipped, and listed
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0], "statement 4") || !strings.Contains(got.Skipped[0], "https://example.com/products/appliance") {
		t.Errorf("expected the appliance statement listed as skipped, got %v", got.Skipped)
	}

	// and the writer takes every one
	dir, w := corpusDir(t)
	if err := w.Write(got.Placed); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(labels.TypeFile(debDir, "deb")))); err != nil {
		t.Error(err)
	}
}

// import-vendor-statements, OSV: records as api.osv.dev serves them
func TestImportOSV(t *testing.T) {
	ghsa := fixture.Path("osv", "GHSA-67hx-6x53-jw92.json")
	got, err := Import(ghsa, read(t, ghsa), Options{Author: "Alex Goodman", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// only fixed events state a version: each is an fp with the fix installed, named by the CVE
	if len(got.Placed) != 2 {
		t.Fatalf("expected the two fixed versions, got %+v", got.Placed)
	}
	for _, p := range got.Placed {
		if p.File != "global/npm.json" || p.Label.Vulnerability != "CVE-2023-45133" || p.Label.Verdict != labels.FP || p.Label.Justification != "fix-installed" {
			t.Errorf("unexpected label %+v", p)
		}
	}
	if got.Placed[0].Label.Package != "pkg:npm/%40babel/traverse@7.23.2" {
		t.Errorf("expected the fixed version on the record's purl, got %s", got.Placed[0].Label.Package)
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0], "babel-traverse") || !strings.Contains(got.Skipped[0], "only a range") {
		t.Errorf("expected the range-only entry skipped, got %v", got.Skipped)
	}

	pysec := fixture.Path("osv", "PYSEC-2021-108.json")
	got, err = Import(pysec, read(t, pysec), Options{Author: "Alex Goodman", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	var tps, fps int
	for _, p := range got.Placed {
		switch {
		case p.Label.Verdict == labels.TP:
			tps++
		case p.Label.Verdict == labels.FP && p.Label.Package == "pkg:pypi/urllib3@1.26.5":
			fps++
		}
		if p.Label.Evidence[0].Facts[0].Source != "osv" || p.Label.Evidence[0].Facts[0].About["record"] != "PYSEC-2021-108" {
			t.Errorf("expected evidence citing the record, got %+v", p.Label.Evidence)
		}
	}
	if tps != 13 || fps != 1 {
		t.Errorf("expected 13 listed versions as tp and the fix as fp, got %d and %d", tps, fps)
	}
	_, w := corpusDir(t)
	if err := w.Write(got.Placed); err != nil {
		t.Fatal(err)
	}
}

// export-to-openvex
func TestExport(t *testing.T) {
	dir, w := corpusDir(t)
	label := func(pkg, vuln string, v labels.Verdict, just, note string) labels.Label {
		return labels.Label{Package: pkg, Vulnerability: vuln, Verdict: v, Justification: just, Notes: labels.NotesOf(note, "Alex Goodman", "2026-10-14T10:00:00Z"), Author: "Alex Goodman",
			FirstIssued: "2026-10-14T10:00:00Z", LastUpdated: "2026-10-14T11:00:00Z",
			SeenIn: &labels.SeenIn{SBOM: debDigest, Tools: []labels.Tool{{Name: labels.ToolSyft, Version: "v1.54.1"}}},
			Evidence: []labels.Evidence{{Facts: []labels.Fact{{Source: "sbom", About: map[string]string{"package": "x"}, Field: "name", Value: "x", ObservedAt: "2026-10-14T10:00:00Z"}},
				Interpretation: "a reason"}}}
	}
	subject := &labels.Subject{Image: debImage.Image(), Platform: "linux/arm64"}
	doc := labels.DocumentDir(debDigest)
	err := w.Write([]labels.Placed{
		{File: labels.TypeFile(debDir, "deb"), Subject: subject, Label: label("pkg:deb/debian/libc6@2.36-9?arch=arm64&distro=debian-12", "CVE-2023-4911", labels.TP, "fix-newer", "")},
		{File: labels.TypeFile(debDir, "deb"), Subject: subject, Label: label("pkg:deb/debian/zlib1g@1.2.13?distro=debian-12", "CVE-2022-37434", labels.FP, "fix-installed", "")},
		{File: labels.TypeFile(debDir, "deb"), Subject: subject, Label: label("pkg:deb/debian/tar@1.34?distro=debian-12", "CVE-2005-2541", labels.FP, "vulnerable_code_not_present", "")},
		{File: labels.TypeFile(debDir, "deb"), Subject: subject, Label: label("pkg:deb/debian/bash@5.2?distro=debian-12", "CVE-2019-18276", labels.FP, "different-product", "it is about GNU bash on Windows")},
		{File: debDir + "/image.json", Subject: subject, Label: label("", "CVE-2023-50495", labels.Unclear, "not-assessed", "")},
		{File: labels.TypeFile(doc, "npm"), Subject: &labels.Subject{SBOM: debDigest}, Label: label("pkg:npm/%40babel/traverse@7.22.0", "GHSA-67hx-6x53-jw92", labels.TP, "", "")},
		{File: labels.GlobalFile("rpm"), Label: label("pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8?epoch=1", "CVE-2024-0727", labels.FP, "fix-installed", "")},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Export(os.DirFS(dir), "anchore claims corpus")
	if err != nil {
		t.Fatal(err)
	}

	// the export validates against the OpenVEX 0.2.0 schema, formats asserted
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	schemaDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(read(t, fixture.Path("openvex", "openvex_json_schema_0.2.0.json"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("openvex.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("openvex.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("expected the export to validate against the OpenVEX schema: %v\n%s", err, out)
	}

	var got struct {
		Statements []struct {
			Vulnerability   struct{ Name string } `json:"vulnerability"`
			Status          string                `json:"status"`
			Justification   string                `json:"justification"`
			ImpactStatement string                `json:"impact_statement"`
			Products        []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	byVuln := map[string]int{}
	for i, s := range got.Statements {
		byVuln[s.Vulnerability.Name] = i
	}
	for vuln, want := range map[string]string{
		"CVE-2023-4911":       "affected",
		"CVE-2022-37434":      "fixed",
		"CVE-2005-2541":       "not_affected vulnerable_code_not_present",
		"CVE-2019-18276":      "not_affected vulnerable_code_not_present different-product: it is about GNU bash on Windows",
		"CVE-2023-50495":      "under_investigation",
		"GHSA-67hx-6x53-jw92": "affected",
		"CVE-2024-0727":       "fixed",
	} {
		s := got.Statements[byVuln[vuln]]
		if g := strings.TrimSpace(strings.Join([]string{s.Status, s.Justification, s.ImpactStatement}, " ")); g != want {
			t.Errorf("%s: expected %q, got %q", vuln, want, g)
		}
	}
	img := got.Statements[byVuln["CVE-2023-4911"]].Products[0]
	if !strings.HasPrefix(img.ID, "pkg:oci/yardstick-fixture-deb@sha256%3A617d48") || !strings.Contains(img.ID, "repository_url=docker.io%2Fanchore%2Fyardstick-fixture-deb") ||
		len(img.Subcomponents) != 1 || img.Subcomponents[0].ID != "pkg:deb/debian/libc6@2.36-9?arch=arm64&distro=debian-12" {
		t.Errorf("expected the image as product with the package as subcomponent, got %+v", img)
	}
	if p := got.Statements[byVuln["CVE-2024-0727"]].Products[0]; p.ID != "pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8?epoch=1" || len(p.Subcomponents) != 0 {
		t.Errorf("expected a global label's product to be its package, got %+v", p)
	}
	for _, leaked := range []string{"evidence", "seenIn", "interpretation", "Alex Goodman"} {
		if bytes.Contains(out, []byte(leaked)) {
			t.Errorf("expected no %s in the export", leaked)
		}
	}

	// what export writes, import reads back into the same files
	back, err := Import("export.json", out, Options{Author: "Alex Goodman", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if libc := find(back.Placed, "CVE-2023-4911"); len(libc) != 1 || libc[0].File != labels.TypeFile(debDir, "deb") {
		t.Errorf("expected the exported image label to import into %s, got %+v", labels.TypeFile(debDir, "deb"), libc)
	}

	again, _ := Export(os.DirFS(dir), "anchore claims corpus")
	if !bytes.Equal(out, again) {
		t.Error("expected the same corpus to export the same bytes")
	}
}
