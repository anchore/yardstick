// Package labelwrite is the one path a label about a run's subject takes into the corpus: claims
// add, accepting a proposal, and the label server all write through it.
package labelwrite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/collect"
	"github.com/anchore/yardstick/cmd/yardstick/internal/corpus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// SeenIn is what a run's scan of the subject used, for a label about it: the unfiltered SBOM's
// digest, the syft that built it, and the grype and DB of the setup that reported the match (the
// candidate's when both or neither did). dir is the run's directory, holding the scans.
func SeenIn(rec *runrecord.Record, dir string, sub *runrecord.Subject, l claimsv1.Label, vocab *claimsv1.Vocabulary) (*claimsv1.SeenIn, error) {
	setup, err := reportedBy(rec, dir, sub, l, vocab)
	if err != nil {
		return nil, err
	}
	return SeenInFor(rec, sub, setup), nil
}

// SeenInFor is SeenIn when the caller already knows which setup reported the match, as the label
// server does from its paired rows.
func SeenInFor(rec *runrecord.Record, sub *runrecord.Subject, setup string) *claimsv1.SeenIn {
	seen := rec.Setups[setup]
	out := &claimsv1.SeenIn{SBOM: sub.UnfilteredDigest}
	add := func(name, version string) {
		if version != "" {
			out.Tools = append(out.Tools, claimsv1.Tool{Name: name, Version: version})
		}
	}
	add(claimsv1.ToolSyft, sub.Syft)
	// a grype run from a local binary has no version but its path
	grype := seen.Grype.Spec.Version
	if grype == "" {
		grype = seen.Grype.Spec.Path
	}
	add(claimsv1.ToolGrype, grype)
	add(claimsv1.ToolGrypeDB, seen.DB.Checksum)
	return out
}

// Write places a label about a subject (or, when global, in global/<type>.json, dropping its
// seenIn) and writes it into the set's writable source. It returns the path written.
func Write(set *claims.Set, sub *runrecord.Subject, l claimsv1.Label, global bool) (string, error) {
	placed, err := Place(sub, l, global)
	if err != nil {
		return "", err
	}
	w, err := set.Writer()
	if err != nil {
		return "", err
	}
	if _, err := w.Write([]corpus.Placed{placed}); err != nil {
		return "", err
	}
	return filepath.Join(w.Dir, filepath.FromSlash(placed.File)), nil
}

// reportedBy is the setup whose grype and DB a label's seenIn records, reading the scans in dir: the
// reference when only it reports a match the label pairs, else the candidate. Aliases come from
// every subject's scans, as scoring builds them, so a link only another subject carries still
// pairs the label here.
func reportedBy(rec *runrecord.Record, dir string, sub *runrecord.Subject, l claimsv1.Label, vocab *claimsv1.Vocabulary) (string, error) {
	aliases := pairing.NewAliases(vocab.IsAdvisory)
	var scans map[string]*models.Document
	for i := range rec.Subjects {
		s := &rec.Subjects[i]
		docs := map[string]*models.Document{}
		for setup, rel := range s.Scans {
			data, err := os.ReadFile(filepath.Join(dir, rel))
			if err != nil {
				return "", err
			}
			doc, err := collect.Decode(data)
			if err != nil {
				return "", fmt.Errorf("subject %s, %s scan: %w", s.Name, setup, err)
			}
			docs[setup] = &doc
			aliases.AddScan(&doc)
		}
		if s.Name == sub.Name {
			scans = docs
		}
	}
	ls := []claims.Label{{Label: l}}
	aliases.AddLabels(ls)
	r := pairing.Pair(aliases, pairing.Subject{Name: sub.Name, Packages: sub.Packages, Filtered: len(sub.KeepTypes) > 0, Labels: ls, Scans: scans})
	if len(r.Labels) == 1 && !r.Labels[0].PairedIn(gatefile.Candidate) && r.Labels[0].PairedIn(gatefile.Reference) {
		return gatefile.Reference, nil
	}
	return gatefile.Candidate, nil
}

// Place puts a label in its subject's file for the package's type, its image.json when it names
// no package, or global/<type>.json.
func Place(sub *runrecord.Subject, l claimsv1.Label, global bool) (corpus.Placed, error) {
	t := ""
	if l.Package != "" {
		t = string(pkg.TypeFromPURL(l.Package))
		if t == string(pkg.UnknownPkg) || !corpus.ValidType(t) {
			return corpus.Placed{}, fmt.Errorf("package %s names no package type a label file can be named for", l.Package)
		}
	}
	if global {
		if t == "" {
			return corpus.Placed{}, errors.New("a global label names a package")
		}
		l.SeenIn = nil
		return corpus.Placed{File: corpus.GlobalFile(t), Label: l}, nil
	}
	s, err := SubjectOf(sub)
	if err != nil {
		return corpus.Placed{}, err
	}
	file := sub.Dir + "/" + corpus.NoPackageFile
	if t != "" {
		file = corpus.TypeFile(sub.Dir, t)
	}
	return corpus.Placed{File: file, Subject: &s, Label: l}, nil
}

// SubjectOf is the label subject a run's subject is addressed by in the corpus: its image, else
// its SBOM document's digest.
func SubjectOf(sub *runrecord.Subject) (claimsv1.Subject, error) {
	// the record keeps the subject's reference as written
	r, err := ref.Parse(sub.Written)
	if err != nil {
		return claimsv1.Subject{}, err
	}
	s := claimsv1.Subject{Platform: sub.Platform}
	if r.Kind == ref.Image {
		s.Image = r.Image()
	} else {
		// a document is addressed by its own bytes, before any filter
		s.SBOM = sub.UnfilteredDigest
	}
	return s, nil
}

// Accept writes the label accepting a proposal says, by the person accepting it: its verdict,
// justification, note and evidence, with seenIn from the run (SeenIn gives it). The proposal's
// confidence stays on the proposal.
func Accept(set *claims.Set, sub *runrecord.Subject, p agentstore.Proposal, author string, seen *claimsv1.SeenIn, now time.Time) (string, error) {
	l := p.Label(author, now)
	l.SeenIn = seen
	return Write(set, sub, l, false)
}
