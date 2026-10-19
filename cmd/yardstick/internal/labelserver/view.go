package labelserver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelwrite"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
	"github.com/anchore/yardstick/cmd/yardstick/internal/report"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/score"
)

// entry is one gate's last scans under the run, reloaded when its record or gate file changes,
// with its view cached until a label, claims file or agent record changes.
type entry struct {
	name    string
	rec     *runrecord.Record
	gate    *gatefile.Gate
	recAt   time.Time
	gateAt  time.Time
	created time.Time

	mu    sync.Mutex
	view  *view
	stamp string
}

// entries finds every gate scanned under the run, scanned last first. Gates scanned since the
// server started show up without a restart, and a re-scanned gate is reloaded.
func (s *Server) entries() ([]*entry, error) {
	s.gatesMu.Lock()
	defer s.gatesMu.Unlock()
	dir := filepath.Join(runrecord.RunsDir, s.opts.Run)
	dirs, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	var out []*entry
	for _, d := range dirs {
		name := d.Name()
		if !d.IsDir() || strings.HasPrefix(name, ".") {
			continue // .partial- and .old- sets mid-run
		}
		recInfo, err := os.Stat(filepath.Join(dir, name, runrecord.File))
		if err != nil {
			continue
		}
		e := s.gates[name]
		if e == nil || !e.recAt.Equal(recInfo.ModTime()) || gateChanged(e) {
			if e, err = s.load(name, recInfo.ModTime()); err != nil {
				log.Warnf("skipping gate %s under run %s: %v", name, s.opts.Run, err)
				continue
			}
			s.gates[name] = e
		}
		out = append(out, e)
	}
	slices.SortStableFunc(out, func(a, b *entry) int {
		if c := b.created.Compare(a.created); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	return out, nil
}

func gateChanged(e *entry) bool {
	info, err := os.Stat(e.gate.Path)
	return err != nil || !info.ModTime().Equal(e.gateAt)
}

func (s *Server) load(name string, at time.Time) (*entry, error) {
	rec, err := runrecord.Load(s.opts.Run, name)
	if err != nil {
		return nil, err
	}
	g, err := s.opts.Load(rec.Gate.Path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(g.Path)
	if err != nil {
		return nil, err
	}
	created, _ := time.Parse(time.RFC3339, rec.Created)
	return &entry{name: name, rec: rec, gate: g, recAt: at, gateAt: info.ModTime(), created: created}, nil
}

// gateFor is the gate a request names by its {gate} segment, by name only: request input never
// becomes a path. It writes the error response when there is none.
func (s *Server) gateFor(w http.ResponseWriter, req *http.Request) *entry {
	all, err := s.entries()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	for _, e := range all {
		if e.name == req.PathValue("gate") {
			return e
		}
	}
	http.Error(w, "no gate "+req.PathValue("gate")+" has been scanned under run "+s.opts.Run, http.StatusNotFound)
	return nil
}

// viewFor is gateFor's gate scored as things are now, writing the error response on failure.
func (s *Server) viewFor(w http.ResponseWriter, req *http.Request) (*entry, *view) {
	e := s.gateFor(w, req)
	if e == nil {
		return nil, nil
	}
	v, err := s.view(e)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil
	}
	return e, v
}

// view is a gate's scans scored against the labels as they are now, with the agent's records
// attached to its rows.
type view struct {
	paired  *score.Paired
	verdict report.Gate
	stale   string // why the scans no longer apply; empty when they do
	set     *claims.Set
	vocab   *claimsv1.Vocabulary

	rows    map[string]*rowRef // by row id
	effects map[string]analysis.Effect

	hints          map[string]*hint
	causes         map[string]*causeView
	causeOrder     []*causeView
	rowCauses      map[string][]*causeView
	explanations   []*explanationView
	rowExplanation map[string]*explanationView
}

// rowRef is one row: its subject's index in the run and the verdict, and the match both ways.
type rowRef struct {
	si    int
	match *report.Match
	pm    *pairing.Match
}

func (r *rowRef) open() bool {
	return verdictOf(r) == unlabeled || verdictOf(r) == string(claimsv1.Unclear)
}

func (s *Server) view(e *entry) (*view, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	stamp, err := s.stampOf(e)
	if err != nil {
		return nil, err
	}
	if e.view != nil && e.stamp == stamp {
		return e.view, nil
	}
	v, err := s.compute(e)
	if err != nil {
		return nil, err
	}
	e.view, e.stamp = v, stamp
	return v, nil
}

// stampOf changes whenever anything the view reads does: the run record and gate file (by
// modification time), any file in a local claims source, and the agent store.
func (s *Server) stampOf(e *entry) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s\n", e.recAt, e.gateAt)
	// ponytail: walks every local claims source per request; a corpus of thousands of files
	// would want fsnotify instead
	for _, src := range e.gate.Claims {
		if src.Remote != nil {
			continue
		}
		err := filepath.WalkDir(src.Locator, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%s|%d|%s\n", p, info.Size(), info.ModTime())
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	st := s.opts.Store
	for _, snap := range []func() (string, error){st.Proposals.Snapshot, st.Causes.Snapshot, st.Explanations.Snapshot} {
		v, err := snap()
		if err != nil {
			return "", err
		}
		fmt.Fprintln(h, v)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Server) compute(e *entry) (*view, error) {
	set, err := claims.OpenSet(e.gate.Claims)
	if err != nil {
		return nil, err
	}
	v := &view{set: set, vocab: set.Vocabulary(), rows: map[string]*rowRef{}, effects: map[string]analysis.Effect{}}
	if st := score.Stale(s.ctx, s.opts.Run, e.gate, e.rec, set); st != nil {
		v.stale = st.Message
	}
	if v.paired, err = score.Pair(s.opts.Run, e.gate, e.rec, set); err != nil {
		return nil, err
	}
	v.verdict = v.paired.Verdict(nil)
	// the verdict's rows are built from the pairing's matches in order, unnarrowed
	for si, sub := range v.verdict.Subjects {
		pms := v.paired.Inputs[si].Result.Matches
		for j := range sub.Matches {
			m := &sub.Matches[j]
			v.rows[m.Row] = &rowRef{si: si, match: m, pm: pms[j]}
		}
	}
	for _, eff := range v.verdict.Effects {
		v.effects[pairing.RowID(eff.Subject, eff.Match)] = eff
	}
	if err := s.attachHints(e, v); err != nil {
		return nil, err
	}
	if err := s.attachCauses(e, v); err != nil {
		return nil, err
	}
	return v, s.attachExplanations(e, v)
}

// subjectKey is how a label file names a run's subject: its image, else its SBOM's digest.
func subjectKey(sub *runrecord.Subject) string {
	p, err := labelwrite.Place(sub, claimsv1.Label{}, false)
	if err != nil || p.Subject == nil {
		return sub.Name
	}
	return p.Subject.Image + p.Subject.SBOM
}

// orderedRows are the gate's rows in report order, for anything listing members.
func (v *view) orderedRows() []*rowRef {
	var out []*rowRef
	for _, sub := range v.verdict.Subjects {
		for j := range sub.Matches {
			out = append(out, v.rows[sub.Matches[j].Row])
		}
	}
	return out
}

// hint is the newest proposal on a row and where it stands against the row's label and the policy.
type hint struct {
	Proposal agentstore.Proposal `json:"proposal"`
	Policy   policyCheck         `json:"policy"`
	// Status is pending (the row is open), agrees or disagrees (someone labeled it).
	Status string `json:"status"`
}

type policyCheck struct {
	Rule     *namedRule `json:"rule,omitempty"`
	Problems []string   `json:"problems"`
}

// namedRule is a vocabulary rule with its name, as delta's policy rule was served.
type namedRule struct {
	Name string `json:"rule"`
	claimsv1.Rule
}

// ruleOf is the first rule a call's evidence cites, from the vocabulary.
func ruleOf(vocab *claimsv1.Vocabulary, evidence []claimsv1.Evidence) *namedRule {
	for _, e := range evidence {
		if e.Rule == "" {
			continue
		}
		r := &namedRule{Name: e.Rule}
		if vocab != nil {
			r.Rule = vocab.Rules[e.Rule]
		}
		return r
	}
	return nil
}

// attachHints puts the newest proposal about each row's subject, package and vulnerability on it.
func (s *Server) attachHints(e *entry, v *view) error {
	proposals, err := s.opts.Store.Proposals.Current()
	if err != nil {
		return err
	}
	// ponytail: a proposal pairs a row by its exact package purl, as claims propose resolves it
	// from the row; a hand-written proposal stating fewer purl fields shows no hint
	byKey := map[string]agentstore.Proposal{}
	for _, p := range proposals {
		byKey[p.Subject.Image+p.Subject.SBOM+"|"+p.Package+"|"+p.Vulnerability] = p
	}
	subjects := make([]string, len(e.rec.Subjects))
	for i := range e.rec.Subjects {
		subjects[i] = subjectKey(&e.rec.Subjects[i])
	}
	v.hints = map[string]*hint{}
	for id, r := range v.rows {
		var found *agentstore.Proposal
		for _, vuln := range append([]string{r.match.Vulnerability, r.match.Group}, r.match.Aliases...) {
			if p, ok := byKey[subjects[r.si]+"|"+r.match.Package+"|"+vuln]; ok && (found == nil || p.Timestamp.After(found.Timestamp)) {
				found = &p
			}
		}
		if found == nil {
			continue
		}
		h := &hint{Proposal: *found, Policy: policyCheck{Rule: ruleOf(v.vocab, found.Evidence), Problems: found.Problems(v.vocab)}, Status: "pending"}
		switch {
		case r.open():
		case verdictOf(r) == string(found.Verdict):
			h.Status = "agrees"
		default:
			h.Status = "disagrees"
		}
		v.hints[id] = h
	}
	return nil
}
