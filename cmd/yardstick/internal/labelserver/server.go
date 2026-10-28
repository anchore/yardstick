// Package labelserver is yardstick claims serve: a local web UI over a run's gates, ported from
// delta's label server, that shows the matches the setups disagree on and writes labels through
// the same path as yardstick claims add. The UI is one page under /ui/gates/, routed in the
// browser; / opens it and the old /ui/map/ URLs redirect into it.
//
// The wire contract started as delta's: /state, /rows/{id} and /api/gates* keep delta's response
// shapes wherever yardstick has the data.
//
// The machine-checked record of the contract is the Go types this package serializes, exported
// so tygo can see them, with web/tygo.yaml turning them into web/src/gen/wire.ts for the UI to
// type its calls against. Add a field there and the UI sees it; the table below only says where
// each field comes from. Embedded structs carry a tstype:",extends" tag so the TypeScript
// extends them, and a field the JSON can hold null in says so with a tstype tag.
//
// The mapping, delta field ← yardstick source:
//
//	row.id                    ← report.Match.Row (pairing.RowID: 16 hex of subject + match id)
//	row.match                 ← report.Match.ID (<pkgID>/<alias group>), new
//	row.package.ref           ← report.Match.Package (a purl; delta's claim.Subject is kept as {ref})
//	row.verdict               ← report.Match.Verdict; "unclear" when the deciding label is unclear,
//	                            else "unlabeled" (yardstick reads unclear as unlabeled)
//	row.candidate/reference, candidate/referenceStatus, candidate/referenceRecords, why,
//	row.sourcePackage, aliases, group, inCandidate/inReference
//	                          ← the report.Match fields of the same names (E1, E2, E4)
//	row.label                 ← report.Match.Label (file, sources), replacing delta's row.claims ids
//	row.conflict              ← dropped: the last source holding a key decides its verdict
//	row.gate                  ← analysis.Effect: bears = Narrows, couldFlip = checks whose state a
//	                            tp or fp label changes, ifTP/ifFP.outcome = Outcome[tp]/Outcome[fp];
//	                            set only for an open delta whose label bears on a check
//	row.hint                  ← the newest agentstore.Proposal on the row's subject, package purl and
//	                            vulnerability (or an alias): verdict, confidence, justification (in
//	                            place of delta's why{kind,line}), rule and its decision and title
//	                            from vocabulary.yaml's rules; status is pending, agrees or disagrees
//	                            (no basedOn in a label, so no accepted)
//	row.causes                ← agentstore.Cause ids listing the row as a member
//	row.explanation           ← the agentstore.Explanation of this gate and run listing the row
//	state.gate                ← report.Gate: outcome, ci from passed, checks from analysis.Check with
//	                            valueMeans, counts and direction from this package (checkWords);
//	                            failsOn the row ids deciding it (a failing subject's FailsOn, a failing
//	                            per-gate check's unmet rows); no result while the scans are stale
//	state.candidate/reference ← runrecord.Record.Setups (grype.spec.version, db, config)
//	state.vocabulary          ← the claims vocabulary's justifications, for the justification picker
//	rows/{id}.label           ← the full label deciding the row, from the pairing (delta's history)
//	rows/{id}.hint.proposal   ← agentstore.Proposal; evidence[].facts replaces delta's basis.facts
//	rows/{id}.hint.policy     ← {rule: vocabulary rule + name, problems: Proposal.Problems}
//	rows/{id}/matches         ← each setup's grype matches the pairing put on the row, verbatim, and
//	                            the SBOM artifact by package id
//	POST labels               ← labelwrite.Place into the writable source, one batch; fp and unclear
//	                            need a justification. A verdict against a pending hint or cause
//	                            appends an agentstore.Override
//	POST preview              ← analysis.EvaluateAs over the cached pairing, nothing re-read
//
// The /ui/gates/ tables, new and not delta's:
//
//	state…rows[].effect       ← the row's strongest effect over every check's findings (below), the
//	                            gate's Findings tab's Effect column
//	state.subjects[].changes  ← Tally over the subject's rows only one setup reports: verdictOf, and
//	                            hinted for an unlabeled row with a pending proposal or pending cause member;
//	                            gates[].changes in GET /api/gates is the same, per subject
//	checks/{c}/findings       ← analysis.Check of the gate: per subject its FailsOn (effect decides when
//	                            that subject fails the check, else counted) and Rows, plus any open row
//	                            whose analysis.Effect narrows or could flip it (could-move when a tp or
//	                            fp label alone changes the check's state, else counted); a per-gate
//	                            check's Unmet expectations, on a row only when a match pairs the label.
//	                            check is this package's CheckResult; images tallies findings by slug
//	labels                    ← pairing.Result.Labels of every subject, a global label once: source is
//	                            claims.Label.Source (the last source holding it), decides the checks
//	                            failing on a row it is the deciding label of (or an unmet expectation
//	                            it is), row the first changed such row. Newest lastUpdated first; counts skip the verdict
//	                            filter and perImage the image filter
//
//	queue                     ← the cross-gate join (shared.go) keyed by row id, every open change kept:
//	                            per entry the strongest in-scope effect (decides: a tp or fp label
//	                            alone changes a gate's outcome, from analysis.Effect; could-move,
//	                            counted, none), per gate in[].outcome and decides; gates[].rows every
//	                            open change, settled from analysis.EvaluateAs over the open changes all
//	                            labeled for the candidate and all against it
//	hints                     ← pending agentstore.Proposal (on a changed row) and agentstore.Cause
//	                            (pending members) of every gate; gates[].after is analysis.EvaluateAs
//	                            with only the hint's rows labeled its verdict; group from those
//	                            (decides, needed, none); replaces when a row holds a claims label
//	POST hints/accept         ← Proposal.Label and Cause.Label per row as the single accepts, placed by
//	                            labelwrite.Place and written once per writable source, file and key
//	history                   ← every label file in each gate's writable source (claims.Set.Writer,
//	                            the last source), rows from the pairing's labels held by that source;
//	                            since= on lastUpdated, started the server's start
//	POST history/revert       ← corpus.Writer.Revert in a writable source; a write's labels are
//	                            the keys it wrote with the label each replaced, for undoing it
//
//	row.research, researchLevel, researched, researchedBy, hint.origin
//	                          ← research.Job records under .yardstick/research/jobs/, as in delta;
//	                            researchedBy reads only the newest proposal (no history kept)
//	state.research            ← research.Availability: whether the yardstick plugin is installed at
//	                            this binary's version, and the command to copy when not.
//	                            researchConcurrency is set only while research can start
//	state.researchEstimate    ← research.Estimate over every job, on the configured model
//	row.researchShares        ← research.Siblings: the other rows a research job on the row covers
//	POST research             ← the queue's join (queue.go), rows with no research level and no
//	                            active job, grouped change (decides, could-move) or none, one
//	                            research.Requests job per row not already covered; estimate is
//	                            research.Estimate times the jobs; a start shares one batch id.
//	                            check narrows to the check findings' rows, grouped by their effect
//	                            on it; rows to those rows, each under the gate the plan picks
//	research/batch            ← the research.Job records of a batch, spent from each Job.Usage, hints
//	                            the proposals whose author.researchJob is one of its jobs
//	research/jobs             ← every research.Job record, newest first; position from the order
//	                            this runner queued the ones it holds; summary is research/batch's
//	                            math over the active jobs and the batches they are in
//	POST research (both)      ← refused with an UnlistedNamespace (code unlisted-namespace) when a
//	                            job's vulnerability is in a namespace its gate's vocabulary lacks:
//	                            Vocabulary.CheckScanned over the gate's rows
//	state.unlisted            ← the same, for each namespace of the gate's open rows
//	POST vocabulary/namespace ← claimsv1.AddToList on the writable source's vocabulary.yaml
package labelserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
)

// assets/dist/ is the built UI (make generate), gitignored, so a go install binary has none.
//
//go:embed assets
var assets embed.FS

// a dev build (dev.go) sets these: ui to the source tree on disk, dev to add live reload
var (
	ui  fs.FS = assets
	dev func(ctx context.Context, mux *http.ServeMux) http.Handler
)

// HasUI says whether this binary was built with the UI in assets/dist/.
func HasUI() bool {
	_, err := fs.Stat(ui, "assets/dist")
	return err == nil || dev != nil
}

// TokenHeader carries the per-start write token on every POST.
const TokenHeader = "X-Yardstick-Token" //nolint:gosec // a header name, not a credential

// Options are what a server serves.
type Options struct {
	Run    string // the run name whose gates are served, .yardstick/runs/<run>/
	Open   string // the gate "/" opens, by name; empty for the list of gates
	Author string // who the labels written are by
	// Load loads a gate file as the CLI does, with its --claims.
	Load  func(path string) (*gatefile.Gate, error)
	Store *agentstore.Store
	// Research runs research jobs; nil serves no research. ResearchAvailability says whether jobs
	// may start: the routes refuse and the UI disables its buttons when they may not.
	Research             *research.Runner
	ResearchAvailability research.Availability
}

type Server struct {
	ctx     context.Context
	opts    Options
	token   string
	started time.Time  // to the second, as labels stamp lastUpdated
	mu      sync.Mutex // serializes writes

	gatesMu sync.Mutex
	gates   map[string]*entry // by gate name, loaded on first use
}

// New serves a run's gates. ctx bounds what scoring resolves.
func New(ctx context.Context, opts Options) (*Server, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{ctx: ctx, opts: opts, token: hex.EncodeToString(b), started: time.Now().UTC().Truncate(time.Second), gates: map[string]*entry{}}, nil
}

// Token is the write token pages carry.
func (s *Server) Token() string { return s.token }

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(ui, "assets")
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServerFS(static)))
	mux.HandleFunc("GET /{$}", s.handleRoot)
	// the old map UI's pages, bookmarked and in links people pasted, go to their new screens
	mux.HandleFunc("GET /ui/map/gates/{$}", redirectOldMap)
	mux.HandleFunc("GET /ui/map/gates/{gate}/{rest...}", redirectOldMap)

	// the new UI: one page, routed client side. _kit is the component kit, not a gate
	app := func(w http.ResponseWriter, _ *http.Request) { s.servePage(w, "assets/app/index.html") }
	mux.HandleFunc("GET /ui/gates/{$}", app)
	mux.HandleFunc("GET /ui/gates/_kit", app)
	mux.HandleFunc("GET /ui/gates/{gate}/{rest...}", func(w http.ResponseWriter, req *http.Request) {
		if e := s.gateFor(w, req); e != nil {
			s.servePage(w, "assets/app/index.html")
		}
	})
	// the labeling flow's screens, the same page: hint review, the queue, what was written, research and its jobs
	for _, p := range []string{"/ui/hints", "/ui/queue", "/ui/queue/{row}", "/ui/history", "/ui/research", "/ui/research/jobs"} {
		mux.HandleFunc("GET "+p, app)
	}

	mux.HandleFunc("GET /api/gates", s.handleGateList)
	mux.HandleFunc("GET /api/gates/shared", s.handleShared)
	mux.HandleFunc("GET /api/queue", s.handleQueue)
	mux.HandleFunc("GET /api/hints", s.handleHints)
	mux.HandleFunc("POST /api/hints/accept", s.authorized(s.handleAcceptHints))
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("POST /api/history/revert", s.authorized(s.handleRevert))
	const g = "/api/gates/{gate}"
	mux.HandleFunc("GET "+g+"/state", s.handleState)
	mux.HandleFunc("GET "+g+"/checks/{check}/findings", s.handleCheckFindings)
	mux.HandleFunc("GET "+g+"/labels", s.handleGateLabels)
	mux.HandleFunc("GET "+g+"/rows/{id}", s.handleRow)
	mux.HandleFunc("GET "+g+"/rows/{id}/matches", s.handleMatches)
	mux.HandleFunc("GET "+g+"/package-hints/{id}", s.handleCause)
	mux.HandleFunc("POST "+g+"/labels", s.authorized(s.handleLabels))
	mux.HandleFunc("POST "+g+"/accept", s.authorized(s.handleAccept))
	mux.HandleFunc("POST "+g+"/package-hints/{id}/accept", s.authorized(s.handleAcceptCause))
	mux.HandleFunc("POST "+g+"/preview", s.handlePreview)
	mux.HandleFunc("POST "+g+"/research", s.authorized(s.handleResearch))
	mux.HandleFunc("POST "+g+"/research/cancel", s.authorized(s.handleCancelResearch))
	mux.HandleFunc("POST "+g+"/vocabulary/namespace", s.authorized(s.handleAddNamespace))
	mux.HandleFunc("POST /api/research", s.authorized(s.handleResearchQueue))
	mux.HandleFunc("GET /api/research/batch", s.handleResearchBatch)
	mux.HandleFunc("GET /api/research/jobs", s.handleResearchJobs)
	mux.HandleFunc("POST /api/research/batch/cancel", s.authorized(s.handleCancelBatch))
	mux.HandleFunc("GET /api/research/{id}/log", s.handleResearchLog)
	if dev != nil {
		return dev(s.ctx, mux)
	}
	return mux
}

// handleRoot opens the gate given on the command line, else the list of gates.
func (s *Server) handleRoot(w http.ResponseWriter, req *http.Request) {
	to := "/ui/gates/"
	if s.opts.Open != "" {
		to += url.PathEscape(s.opts.Open) + "/"
	}
	http.Redirect(w, req, to, http.StatusFound)
}

// redirectOldMap sends a /ui/map/ URL to the screen that took its place, keeping the image filter:
// the every-gate page (?gate= names a gate) to the gates list or that gate, a gate's board to the
// gate, its delta map to the Scan map tab (a package block to the Findings tab filtered to it), and
// a check's cards to the check. The #row= a card carried never reaches the server.
func redirectOldMap(w http.ResponseWriter, req *http.Request) {
	q, keep := req.URL.Query(), url.Values{}
	if v := q.Get("image"); v != "" {
		keep.Set("image", v)
	}
	// segments split before unescaping, since a package name can hold an escaped slash
	var p []string
	for _, seg := range strings.Split(strings.TrimPrefix(req.URL.EscapedPath(), "/ui/map/gates/"), "/") {
		v, _ := url.PathUnescape(seg)
		p = append(p, v)
	}
	gate := p[0]
	if gate == "" {
		gate = q.Get("gate")
	}
	to := "/ui/gates/"
	if gate != "" {
		to += url.PathEscape(gate) + "/"
		p = append(p[1:], "")
		switch {
		case p[0] == "delta" && len(p) >= 4 && p[3] != "all" && p[3] != "":
			keep.Set("pkg", p[3])
			to += "findings"
		case p[0] == "delta":
			to += "map"
		case p[0] == "check" && len(p) >= 2 && p[1] != "":
			to += "checks/" + url.PathEscape(p[1])
		}
	}
	if len(keep) > 0 {
		to += "?" + keep.Encode()
	}
	http.Redirect(w, req, to, http.StatusFound)
}

// servePage serves a page with the write token filled in.
func (s *Server) servePage(w http.ResponseWriter, path string) {
	page, err := fs.ReadFile(ui, path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
	_, _ = w.Write(bytes.ReplaceAll(page, []byte("{{TOKEN}}"), []byte(s.token)))
}

// LocalOnly refuses a request from anywhere but this machine, whose Host is not this server's
// loopback address on port, or a POST whose Origin, when present, is not one of those: a page on
// another site that rebinds its name to 127.0.0.1 reaches the server under its own Host, the token
// alone does not stop a rebound page from reading it out of a served page, and a client elsewhere
// can send any Host it likes.
func LocalOnly(port int, h http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
		allowed[fmt.Sprintf("%s:%d", host, port)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "only this machine may use the label server", http.StatusForbidden)
			return
		}
		if !allowed[req.Host] {
			http.Error(w, "unexpected host "+req.Host, http.StatusForbidden)
			return
		}
		if o := req.Header.Get("Origin"); req.Method == http.MethodPost && o != "" && !allowed[strings.TrimPrefix(o, "http://")] {
			http.Error(w, "unexpected origin "+o, http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, req)
	})
}

// authorized refuses a write without the token this server started with.
func (s *Server) authorized(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if subtle.ConstantTimeCompare([]byte(req.Header.Get(TokenHeader)), []byte(s.token)) != 1 {
			http.Error(w, "missing or bad token", http.StatusForbidden)
			return
		}
		h(w, req)
	}
}

func decode(w http.ResponseWriter, req *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Warnf("unable to write response: %v", err)
	}
}
