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
	"github.com/anchore/yardstick/cmd/yardstick/internal/collect"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labels"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// SeenIn is what a run's scan of the subject used, for a label about it: the unfiltered SBOM's
// digest, the syft that built it, and the grype and DB of the setup that reported the match (the
// candidate's when both or neither did). dir is the run's directory, holding the scans.
func SeenIn(rec *runrecord.Record, dir string, sub *runrecord.Subject, l labels.Label, vocab *labels.Vocabulary) (*labels.SeenIn, error) {
	setup, err := reportedBy(dir, sub, l, vocab)
	if err != nil {
		return nil, err
	}
	return SeenInFor(rec, sub, setup), nil
}

// SeenInFor is SeenIn when the caller already knows which setup reported the match, as the label
// server does from its paired rows.
func SeenInFor(rec *runrecord.Record, sub *runrecord.Subject, setup string) *labels.SeenIn {
	seen := rec.Setups[setup]
	out := &labels.SeenIn{SBOM: sub.UnfilteredDigest}
	add := func(name, version string) {
		if version != "" {
			out.Tools = append(out.Tools, labels.Tool{Name: name, Version: version})
		}
	}
	add(labels.ToolSyft, sub.Syft)
	// a grype run from a local binary has no version but its path
	grype := seen.Grype.Spec.Version
	if grype == "" {
		grype = seen.Grype.Spec.Path
	}
	add(labels.ToolGrype, grype)
	add(labels.ToolGrypeDB, seen.DB.Checksum)
	return out
}

// Write places a label about a subject (or, when global, in global/<type>.json, dropping its
// seenIn) and writes it into the set's writable source. It returns the path written.
func Write(set *claims.Set, sub *runrecord.Subject, l labels.Label, global bool) (string, error) {
	placed, err := Place(sub, l, global)
	if err != nil {
		return "", err
	}
	w, err := set.Writer()
	if err != nil {
		return "", err
	}
	if err := w.Write([]labels.Placed{placed}); err != nil {
		return "", err
	}
	return w.Dir + "/" + placed.File, nil
}

// reportedBy is the setup whose grype and DB a label's seenIn records, reading the scans in dir: the
// reference when only it reports a match the label pairs, else the candidate.
func reportedBy(dir string, sub *runrecord.Subject, l labels.Label, vocab *labels.Vocabulary) (string, error) {
	isAdvisory := func(string) bool { return false }
	if vocab != nil {
		isAdvisory = vocab.IsAdvisory
	}
	aliases := pairing.NewAliases(isAdvisory)
	scans := map[string]*models.Document{}
	for setup, rel := range sub.Scans {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return "", err
		}
		doc, err := collect.Decode(data)
		if err != nil {
			return "", fmt.Errorf("subject %s, %s scan: %w", sub.Name, setup, err)
		}
		scans[setup] = &doc
		aliases.AddScan(&doc)
	}
	ls := []claims.Label{{Label: l}}
	aliases.AddLabels(ls)
	r := pairing.Pair(aliases, pairing.Subject{Name: sub.Name, Packages: sub.Packages, Filtered: len(sub.KeepTypes) > 0, Labels: ls, Scans: scans})
	if len(r.Labels) == 1 && !r.Labels[0].PairedIn(pairing.Candidate) && r.Labels[0].PairedIn(pairing.Reference) {
		return pairing.Reference, nil
	}
	return pairing.Candidate, nil
}

// Place puts a label in its subject's file for the package's type, its image.json when it names
// no package, or global/<type>.json.
func Place(sub *runrecord.Subject, l labels.Label, global bool) (labels.Placed, error) {
	t := ""
	if l.Package != "" {
		t = string(pkg.TypeFromPURL(l.Package))
		if t == string(pkg.UnknownPkg) || !labels.ValidType(t) {
			return labels.Placed{}, fmt.Errorf("package %s names no package type a label file can be named for", l.Package)
		}
	}
	if global {
		if t == "" {
			return labels.Placed{}, errors.New("a global label names a package")
		}
		l.SeenIn = nil
		return labels.Placed{File: labels.GlobalFile(t), Label: l}, nil
	}
	// the record keeps the subject's reference as written
	r, err := ref.Parse(sub.Written)
	if err != nil {
		return labels.Placed{}, err
	}
	s := &labels.Subject{Platform: sub.Platform}
	if r.Kind == ref.Image {
		s.Image = r.Image()
	} else {
		// a document is addressed by its own bytes, before any filter
		s.SBOM = sub.UnfilteredDigest
	}
	file := sub.Dir + "/" + labels.NoPackageFile
	if t != "" {
		file = labels.TypeFile(sub.Dir, t)
	}
	return labels.Placed{File: file, Subject: s, Label: l}, nil
}

// Accept writes the label accepting a proposal says, by the person accepting it: its verdict,
// justification, note and evidence, with seenIn from the run (SeenIn gives it). The proposal's
// confidence stays on the proposal.
func Accept(set *claims.Set, sub *runrecord.Subject, p agentstore.Proposal, author string, seen *labels.SeenIn, now time.Time) (string, error) {
	l := p.Label(author, now)
	l.SeenIn = seen
	return Write(set, sub, l, false)
}
