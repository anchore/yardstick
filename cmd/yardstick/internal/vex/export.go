package vex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
)

// vexJustifications are OpenVEX's five; a label justification of the same name exports as itself.
var vexJustifications = []vex.Justification{
	vex.ComponentNotPresent, vex.VulnerableCodeNotPresent, vex.VulnerableCodeNotInExecutePath,
	vex.VulnerableCodeCannotBeControlledByAdversary, vex.InlineMitigationsAlreadyExist,
}

// Export writes every label in a corpus as one OpenVEX document: tp is affected, fp with the fix
// installed is fixed, any other fp is not_affected, and unclear is under_investigation. Evidence
// and seenIn stay behind. The same corpus gives the same bytes.
func Export(corpus fs.FS, author string) ([]byte, error) {
	log.Infof("exporting the corpus to OpenVEX")
	defer log.Timed("exporting the corpus to OpenVEX")()
	var statements []vex.Statement
	newest := time.Time{}
	err := fs.WalkDir(corpus, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		loc, ok := labels.Locate(p)
		if !ok || !loc.IsLabelFile() {
			return nil
		}
		data, err := fs.ReadFile(corpus, p)
		if err != nil {
			return err
		}
		f, err := labels.Parse(p, data)
		if err != nil {
			return err
		}
		for _, l := range f.Labels {
			st, err := statement(loc, f.Subject, l)
			if err != nil {
				return fmt.Errorf("%s: label %s: %w", p, l.Key(), err)
			}
			if st.Timestamp.After(newest) {
				newest = *st.Timestamp
			}
			statements = append(statements, st)
		}
		log.Debugf("exported %s: %d labels", p, len(f.Labels))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(statements) == 0 {
		return nil, fmt.Errorf("the corpus holds no labels to export")
	}
	body, err := encode(statements)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	doc := vex.VEX{
		Metadata: vex.Metadata{
			Context:   vex.ContextLocator(),
			ID:        "https://openvex.dev/docs/public/vex-" + hex.EncodeToString(sum[:]),
			Author:    author,
			Timestamp: &newest,
			Version:   1,
			Tooling:   "yardstick claims export",
		},
		Statements: statements,
	}
	log.Infof("exported %d statements", len(statements))
	return encode(doc)
}

func statement(loc labels.Location, subject *labels.Subject, l labels.Label) (vex.Statement, error) {
	issued, err := time.Parse(time.RFC3339, l.LastUpdated)
	if err != nil {
		return vex.Statement{}, err
	}
	issued = issued.UTC()
	product := productOf(loc, subject, l)
	st := vex.Statement{
		Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(l.Vulnerability)},
		Timestamp:     &issued,
		Products:      []vex.Product{product},
	}
	switch {
	case l.Verdict == labels.TP:
		st.Status = vex.StatusAffected
		st.ActionStatement = "no action recorded: the label says the match is right, not how to remediate it"
	case l.Verdict == labels.FP && l.Justification == fixInstalled:
		st.Status = vex.StatusFixed
	case l.Verdict == labels.FP && slices.Contains(vexJustifications, vex.Justification(l.Justification)):
		st.Status, st.Justification = vex.StatusNotAffected, vex.Justification(l.Justification)
	case l.Verdict == labels.FP:
		// a justification with no VEX name travels in the impact statement
		st.Status, st.Justification = vex.StatusNotAffected, vex.VulnerableCodeNotPresent
		st.ImpactStatement = strings.TrimSpace(l.Justification + ": " + strings.Join(l.NoteTexts(), "; "))
	default:
		st.Status = vex.StatusUnderInvestigation
	}
	return st, nil
}

// productOf is what a label is about: the image (with the package as a subcomponent), the SBOM
// document by its digest, or the package itself for a global label.
func productOf(loc labels.Location, subject *labels.Subject, l labels.Label) vex.Product {
	var p vex.Product
	switch loc.Kind {
	case labels.Global:
		p.ID = l.Package
		return p
	case labels.ImageSubject:
		qualifiers := packageurl.QualifiersFromMap(map[string]string{"repository_url": loc.Registry + "/" + loc.Repository})
		if subject != nil && subject.Platform != "" {
			os, arch, _ := strings.Cut(subject.Platform, "/")
			qualifiers = packageurl.QualifiersFromMap(map[string]string{"repository_url": loc.Registry + "/" + loc.Repository, "os": os, "arch": arch})
		}
		purl := packageurl.NewPackageURL("oci", "", path.Base(loc.Repository), loc.Digest, qualifiers, "")
		p.ID = purl.ToString()
	case labels.DocumentSubject:
		hex := strings.TrimPrefix(loc.Digest, "sha256:")
		p.ID = "urn:sha256:" + hex
		p.Hashes = map[vex.Algorithm]vex.Hash{vex.SHA256: vex.Hash(hex)}
	}
	if l.Package != "" {
		p.Subcomponents = []vex.Subcomponent{{Component: vex.Component{ID: l.Package}}}
	}
	return p
}

// encode is indented JSON without HTML escaping, so a purl's & stays an &.
func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(v)
	return buf.Bytes(), err
}
