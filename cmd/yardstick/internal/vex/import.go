// Package vex moves labels across the corpus's edges: vendor OpenVEX documents and OSV records
// in, as labels citing the statement they came from, and the corpus out as OpenVEX. OpenVEX is
// an exchange format here, never the store: it answers whether a product is exploitable, and a
// label answers whether a match is right.
package vex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// fixInstalled is the justification a fixed status maps to, both ways.
const fixInstalled = "fix-installed"

// Options say who is importing and what the evidence cites.
type Options struct {
	Author string // the person making the labels theirs
	// Source is the fact source the evidence names; it must be in the corpus's vocabulary.
	Source string
	Now    time.Time
}

// Imported is what one document became: labels placed in corpus files, and every statement
// that names nothing a label can be about.
type Imported struct {
	Placed  []corpus.Placed
	Skipped []string
}

// Import reads an OpenVEX document or an OSV record, by its shape.
func Import(name string, data []byte, opts Options) (*Imported, error) {
	log.Infof("importing %s", name)
	defer log.Timed("importing %s", name)()
	var probe struct {
		Context  string          `json:"@context"`
		ID       string          `json:"id"`
		Affected json.RawMessage `json:"affected"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	switch {
	case strings.Contains(probe.Context, "openvex"):
		log.Debugf("%s is an OpenVEX document", name)
		return logImported(name)(ImportOpenVEX(name, data, opts))
	case probe.ID != "" && probe.Affected != nil:
		log.Debugf("%s is an OSV record", name)
		return logImported(name)(ImportOSV(name, data, opts))
	}
	return nil, fmt.Errorf("%s is neither an OpenVEX document nor an OSV record", name)
}

// logImported passes an import's result through, reporting its totals.
func logImported(name string) func(*Imported, error) (*Imported, error) {
	return func(got *Imported, err error) (*Imported, error) {
		if err == nil {
			log.Infof("%s gave %d labels, and %d statements skipped", name, len(got.Placed), len(got.Skipped))
			for _, s := range got.Skipped {
				log.Debugf("skipped %s", s)
			}
		}
		return got, err
	}
}

// ImportOpenVEX turns each statement's products into labels: an image product's subcomponents
// into labels in that image's type files, an image product alone into its image.json, and a
// package product into global/. A product that is neither is skipped and listed.
func ImportOpenVEX(name string, data []byte, opts Options) (*Imported, error) {
	doc, err := vex.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if opts.Source == "" {
		opts.Source = "openvex"
	}
	out := &Imported{}
	for i, st := range doc.Statements {
		verdict, justification := fromStatus(st)
		vuln := string(st.Vulnerability.Name)
		observed := stamp(st.Timestamp, doc.Timestamp, opts.Now)
		for _, p := range st.Products {
			fact := claimsv1.Fact{
				Source:     opts.Source,
				About:      map[string]string{"document": doc.ID, "statement": fmt.Sprint(i), "vulnerability": vuln, "product": p.ID},
				Field:      "status",
				Value:      statusValue(st),
				ObservedAt: observed,
			}
			l := claimsv1.Label{
				Vulnerability: vuln,
				Verdict:       verdict,
				Justification: justification,
				Author:        opts.Author,
				Notes:         claimsv1.NotesOf(firstOf(st.ImpactStatement, st.ActionStatement, st.StatusNotes), opts.Author, opts.Now.UTC().Format(time.RFC3339)),
				FirstIssued:   opts.Now.UTC().Format(time.RFC3339),
				LastUpdated:   opts.Now.UTC().Format(time.RFC3339),
				Evidence: []claimsv1.Evidence{{Facts: []claimsv1.Fact{fact}, Interpretation: fmt.Sprintf(
					"%s's VEX statement %d in %s says %s for this product", doc.Author, i, name, statusValue(st))}},
			}
			placed, why := place(p, l)
			if why != "" {
				out.Skipped = append(out.Skipped, fmt.Sprintf("%s statement %d (%s, %s): %s", name, i, vuln, p.ID, why))
				continue
			}
			out.Placed = append(out.Placed, placed...)
		}
	}
	return out, nil
}

// fromStatus maps a VEX status to a verdict on the match: not affected and fixed mean the match
// is wrong, affected means it is right, under investigation decides nothing.
func fromStatus(st vex.Statement) (claimsv1.Verdict, string) {
	switch st.Status {
	case vex.StatusNotAffected:
		if st.Justification != "" {
			return claimsv1.FP, string(st.Justification)
		}
		return claimsv1.FP, "vendor-not-affected"
	case vex.StatusFixed:
		return claimsv1.FP, fixInstalled
	case vex.StatusAffected:
		return claimsv1.TP, ""
	}
	return claimsv1.Unclear, "not-assessed"
}

func statusValue(st vex.Statement) string {
	if st.Justification != "" {
		return string(st.Status) + " (" + string(st.Justification) + ")"
	}
	return string(st.Status)
}

// place puts a label about a product where the corpus keeps it, or says why it can't.
func place(p vex.Product, l claimsv1.Label) ([]corpus.Placed, string) {
	purl, err := packageurl.FromString(p.ID)
	if err != nil {
		return nil, "the product is not a package URL, so it names no image and no package"
	}
	if purl.Type != "oci" {
		t := pkg.TypeFromPURL(p.ID)
		if t == pkg.UnknownPkg || !corpus.ValidType(string(t)) {
			return nil, "no package type for the product"
		}
		l.Package = p.ID
		return []corpus.Placed{{File: corpus.GlobalFile(string(t)), Label: l}}, ""
	}
	image, err := ociImage(purl)
	if err != nil {
		return nil, err.Error()
	}
	dir, subject := corpus.ImageDir(image), &claimsv1.Subject{Image: image.Image()}
	if len(p.Subcomponents) == 0 {
		return []corpus.Placed{{File: dir + "/" + corpus.NoPackageFile, Subject: subject, Label: l}}, ""
	}
	var out []corpus.Placed
	for _, sc := range p.Subcomponents {
		t := pkg.TypeFromPURL(sc.ID)
		if t == pkg.UnknownPkg || !corpus.ValidType(string(t)) {
			return nil, fmt.Sprintf("subcomponent %s is not a package URL with a known type", sc.ID)
		}
		withPkg := l
		withPkg.Package = sc.ID
		out = append(out, corpus.Placed{File: corpus.TypeFile(dir, string(t)), Subject: subject, Label: withPkg})
	}
	return out, ""
}

// ociImage reads pkg:oci/<name>@<digest>?repository_url=<registry>/<repository> as an image.
func ociImage(purl packageurl.PackageURL) (ref.Ref, error) {
	repo := purl.Qualifiers.Map()["repository_url"]
	if repo == "" {
		repo = purl.Name
	}
	r, err := ref.Parse("oci:" + repo + "@" + purl.Version)
	if err != nil {
		return ref.Ref{}, fmt.Errorf("the image product is not pinned by a sha256 digest: %w", err)
	}
	return r, nil
}

func stamp(times ...any) string {
	for _, t := range times {
		switch v := t.(type) {
		case *time.Time:
			if v != nil {
				return v.UTC().Format(time.RFC3339)
			}
		case time.Time:
			return v.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

func firstOf(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
