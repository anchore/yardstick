package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelwrite"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// served is a scanned deb gate whose candidate drops the tar match, served from its workspace.
type served struct {
	t     *testing.T
	w     *workspace
	srv   *labelserver.Server
	h     http.Handler
	store *agentstore.Store
	whole string
}

func newServed(t *testing.T) *served {
	t.Helper()
	return newServedWith(t, nil)
}

// newServedWith is newServed with the server's options adjusted first.
func newServedWith(t *testing.T, adjust func(*labelserver.Options)) *served {
	t.Helper()
	w := newWorkspace(t)
	whole := w.DebGate()
	if _, stderr, code := yardstick(t, w.dir, "gates/deb.yaml"); code == 2 {
		t.Fatalf("scan failed: %s", stderr)
	}
	t.Chdir(w.dir)
	store := agentstore.Open(agentstore.Dir)
	opts := labelserver.Options{Run: runrecord.DefaultName, Author: "tester", Store: store,
		Load: func(p string) (*gatefile.Gate, error) {
			return gatefile.Load(p, gatefile.Options{Checks: analysis.Definitions()})
		}}
	if adjust != nil {
		adjust(&opts)
	}
	srv, err := labelserver.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return &served{t: t, w: w, srv: srv, h: srv.Handler(), store: store, whole: whole}
}

type row struct {
	ID            string               `json:"id"`
	Vulnerability string               `json:"vulnerability"`
	Package       struct{ Ref string } `json:"package"`
	Verdict       string               `json:"verdict"`
	InReference   bool                 `json:"inReference"`
	Gate          *struct {
		Bears []string `json:"bears"`
	} `json:"gate"`
	Hint *struct {
		ID, Status string
	} `json:"hint"`
	Causes      []string `json:"causes"`
	Explanation string   `json:"explanation"`
}

type stateDoc struct {
	Subjects []struct {
		Rows []row `json:"rows"`
	} `json:"subjects"`
	Gate struct {
		Result *struct {
			Outcome string `json:"outcome"`
		} `json:"result"`
	} `json:"gate"`
	Causes []struct {
		ID      string   `json:"id"`
		Pending []string `json:"pending"`
	} `json:"causes"`
	Explanations []struct{ ID, Title string } `json:"explanations"`
	Vocabulary   *struct {
		Justifications map[string]map[string]string `json:"justifications"`
	} `json:"vocabulary"`
}

func (s *served) do(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set(labelserver.TokenHeader, token)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

func (s *served) get(path string, into any) {
	s.t.Helper()
	rec := s.do(http.MethodGet, path, "", "")
	if rec.Code != http.StatusOK {
		s.t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		s.t.Fatal(err)
	}
}

func (s *served) post(path, body string) *httptest.ResponseRecorder {
	return s.do(http.MethodPost, "/api/gates/deb"+path, s.srv.Token(), body)
}

// tarRow is the match only the reference reports.
func (s *served) tarRow() row {
	s.t.Helper()
	var st stateDoc
	s.get("/api/gates/deb/state", &st)
	for _, r := range st.Subjects[0].Rows {
		if r.Vulnerability == "CVE-2005-2541" && strings.Contains(r.Package.Ref, "/tar@") {
			return r
		}
	}
	s.t.Fatal("no tar row")
	return row{}
}

// debLabels are the labels written into the deb image's deb.json.
func (s *served) debLabels() []claimsv1.Label {
	s.t.Helper()
	r, _ := ref.Parse(debImage)
	data, err := os.ReadFile(filepath.Join(s.w.dir, "claims", claimsv1.ImageDir(r), "deb.json"))
	if err != nil {
		s.t.Fatal(err)
	}
	f, err := claimsv1.Parse("deb.json", data)
	if err != nil {
		s.t.Fatal(err)
	}
	return f.Labels
}

func (s *served) labelOf(vuln string) *claimsv1.Label {
	for _, l := range s.debLabels() {
		if l.Vulnerability == vuln {
			return &l
		}
	}
	return nil
}

func (s *served) subject() claimsv1.Subject {
	rec, err := runrecord.Load(runrecord.DefaultName, "deb")
	if err != nil {
		s.t.Fatal(err)
	}
	p, err := labelwrite.Place(&rec.Subjects[0], claimsv1.Label{}, false)
	if err != nil {
		s.t.Fatal(err)
	}
	return *p.Subject
}

func TestServePages(t *testing.T) {
	s := newServed(t)
	for _, tc := range []struct {
		path, location string
		code           int
	}{
		{"/", "/ui/gates/", http.StatusFound},
		{"/ui/gates/", "", http.StatusOK},
		{"/ui/gates/deb/", "", http.StatusOK},
		{"/ui/gates/deb/checks/unjudgedChangesAtMost/0123456789abcdef", "", http.StatusOK},
		{"/ui/gates/nope/labels", "", http.StatusNotFound},
	} {
		rec := s.do(http.MethodGet, tc.path, "", "")
		if rec.Code != tc.code || rec.Header().Get("Location") != tc.location {
			t.Errorf("GET %s: got %d %q, want %d %q", tc.path, rec.Code, rec.Header().Get("Location"), tc.code, tc.location)
		}
		if rec.Code == http.StatusOK && (!strings.Contains(rec.Body.String(), `content="`+s.srv.Token()+`"`) || rec.Header().Get("Content-Security-Policy") == "") {
			t.Errorf("GET %s: expected the page with its token and a content security policy", tc.path)
		}
	}
	// every asset the pages load; the built ones only when make generate has run
	for _, page := range []string{"/ui/gates/"} {
		for _, m := range assetRef.FindAllStringSubmatch(s.do(http.MethodGet, page, "", "").Body.String(), -1) {
			p := m[1]
			if strings.HasPrefix(p, "/assets/dist/") && !labelserver.HasUI() {
				t.Logf("GET %s: skipped, no assets/dist (run make generate)", p)
				continue
			}
			if rec := s.do(http.MethodGet, p, "", ""); rec.Code != http.StatusOK || rec.Body.Len() == 0 {
				t.Errorf("GET %s (from %s): %d, %d bytes", p, page, rec.Code, rec.Body.Len())
			}
		}
	}
}

func TestServeRedirectsTheOldMapURLs(t *testing.T) {
	s := newServed(t)
	for _, tc := range []struct{ path, location string }{
		{"/ui/map/gates/", "/ui/gates/"},
		{"/ui/map/gates/?gate=deb&group=c:x", "/ui/gates/deb/"},
		{"/ui/map/gates/deb/", "/ui/gates/deb/"},
		{"/ui/map/gates/deb/?image=debian-12", "/ui/gates/deb/?image=debian-12"},
		{"/ui/map/gates/deb/delta", "/ui/gates/deb/map"},
		{"/ui/map/gates/deb/delta/added/unexplained%7C%7C", "/ui/gates/deb/map"},
		{"/ui/map/gates/deb/delta/added/unexplained%7C%7C/all", "/ui/gates/deb/map"},
		{"/ui/map/gates/deb/delta/dropped/unexplained%7C%7C/%40babel%2Ftraverse?image=n", "/ui/gates/deb/findings?image=n&pkg=%40babel%2Ftraverse"},
		{"/ui/map/gates/deb/check/f1NotWorse/fails/CVE-1/tar?image=d", "/ui/gates/deb/checks/f1NotWorse?image=d"},
		{"/ui/map/gates/deb/check/no%20new%20FNs/cause/c-1", "/ui/gates/deb/checks/no%20new%20FNs"},
		{"/ui/map/gates/deb/check", "/ui/gates/deb/"},
		{"/ui/map/gates/a%20gate/", "/ui/gates/a%20gate/"},
	} {
		rec := s.do(http.MethodGet, tc.path, "", "")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != tc.location {
			t.Errorf("GET %s: got %d %q, want 302 %q", tc.path, rec.Code, rec.Header().Get("Location"), tc.location)
		}
	}

	// a gate named on the command line is what / opens
	named := newServedWith(t, func(o *labelserver.Options) { o.Open = "deb" })
	if rec := named.do(http.MethodGet, "/", "", ""); rec.Header().Get("Location") != "/ui/gates/deb/" {
		t.Errorf("expected / to open the gate named, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

var assetRef = regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)

func TestServeLabelingWritesAndRescores(t *testing.T) {
	s := newServed(t)
	tar := s.tarRow()
	if tar.Verdict != "unlabeled" || !tar.InReference || tar.Gate == nil || len(tar.Gate.Bears) == 0 {
		t.Fatalf("expected the dropped tar row open and bearing on the gate, got %+v", tar)
	}
	var detail struct {
		Row struct {
			Reference *struct{ Namespace string } `json:"reference"`
		} `json:"row"`
		Links []labelserver.Link `json:"links"`
	}
	s.get("/api/gates/deb/rows/"+tar.ID, &detail)
	if detail.Row.Reference == nil || len(detail.Links) == 0 {
		t.Errorf("expected the reference's record and links, got %+v", detail)
	}
	var matches struct {
		Candidate, Reference []json.RawMessage
		Artifact             json.RawMessage
	}
	s.get("/api/gates/deb/rows/"+tar.ID+"/matches", &matches)
	if len(matches.Candidate) != 0 || len(matches.Reference) != 1 || !strings.Contains(string(matches.Reference[0]), "CVE-2005-2541") || matches.Artifact == nil {
		t.Errorf("expected the reference's raw tar match and the SBOM artifact, got %d %d %s", len(matches.Candidate), len(matches.Reference), matches.Artifact)
	}

	fp := `{"rows":["` + tar.ID + `"],"verdict":"fp","justification":"fix-installed","note":"fixed in the image"}`
	if rec := s.do(http.MethodPost, "/api/gates/deb/labels", "", fp); rec.Code != http.StatusForbidden {
		t.Fatalf("expected a write without the token refused, got %d", rec.Code)
	}
	if rec := s.do(http.MethodPost, "/api/gates/deb/labels", "wrong", fp); rec.Code != http.StatusForbidden {
		t.Fatalf("expected a write with a bad token refused, got %d", rec.Code)
	}
	// fp needs a justification, which delta's UI never sent
	if rec := s.post("/labels", `{"rows":["`+tar.ID+`"],"verdict":"fp"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "fp needs a justification") {
		t.Fatalf("expected an fp without a justification refused, got %d %s", rec.Code, rec.Body)
	}
	if rec := s.post("/labels", fp); rec.Code != http.StatusOK {
		t.Fatalf("expected the label written, got %d %s", rec.Code, rec.Body)
	}
	l := s.labelOf("CVE-2005-2541")
	// only the reference reported it, so seenIn names the reference's grype
	if l == nil || l.Verdict != claimsv1.FP || l.Justification != "fix-installed" || l.Author != "tester" || len(l.Notes) != 1 || l.Notes[0].Text != "fixed in the image" || l.SeenIn.Tool(claimsv1.ToolGrype) != s.whole {
		t.Fatalf("unexpected label: %+v", l)
	}
	if got := s.tarRow(); got.Verdict != "fp" || got.Gate != nil {
		t.Errorf("expected the label scored at once, got %+v", got)
	}
}

func TestServeRefusesBadInput(t *testing.T) {
	s := newServed(t)
	tar := s.tarRow()
	for name, body := range map[string]string{
		"bad verdict":  `{"rows":["` + tar.ID + `"],"verdict":"maybe"}`,
		"unknown row":  `{"rows":["nope"],"verdict":"tp"}`,
		"no rows":      `{"rows":[],"verdict":"tp"}`,
		"bad scope":    `{"rows":["` + tar.ID + `"],"verdict":"tp","scope":"galaxy"}`,
		"bad reason":   `{"rows":["` + tar.ID + `"],"verdict":"tp","overrideReason":{"kind":"vibes"}}`,
		"invalid json": `{`,
	} {
		if rec := s.post("/labels", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := s.do(http.MethodPost, "/api/gates/nope/labels", s.srv.Token(), `{"rows":["x"],"verdict":"tp"}`); rec.Code != http.StatusNotFound {
		t.Errorf("expected a write to an unknown gate refused, got %d", rec.Code)
	}
	if s.labelOf("CVE-2005-2541") != nil {
		t.Error("a refused write wrote a label")
	}
}

func TestServeHintsPreviewAndAccept(t *testing.T) {
	s := newServed(t)
	tar := s.tarRow()
	p := agentstore.Proposal{Schema: agentstore.Schema, ID: "p1", Gate: "deb", Subject: s.subject(), Package: tar.Package.Ref, Vulnerability: "CVE-2005-2541",
		Verdict: claimsv1.FP, Justification: "fix-installed", Confidence: "medium", Author: agentstore.Author{Kind: agentstore.Agent, Skill: "triage-deltas"},
		Evidence:  []claimsv1.Evidence{{Rule: "nvd/fixed", Facts: []claimsv1.Fact{{Source: "nvd", About: map[string]string{"vulnerability": "CVE-2005-2541"}, Field: "status", Value: "fixed", ObservedAt: "2026-10-16T00:00:00Z"}}}},
		Timestamp: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)}
	if err := s.store.Proposals.Add(p); err != nil {
		t.Fatal(err)
	}
	if got := s.tarRow(); got.Hint == nil || got.Hint.ID != "p1" || got.Hint.Status != "pending" || got.Verdict != "unlabeled" {
		t.Fatalf("expected a pending hint that does not count, got %+v", got)
	}
	var detail struct {
		Hint struct {
			Policy struct {
				Rule *struct {
					Rule, Title string
				}
				Problems []string
			}
		}
	}
	s.get("/api/gates/deb/rows/"+tar.ID, &detail)
	if r := detail.Hint.Policy.Rule; r == nil || r.Rule != "nvd/fixed" || r.Title != "Fixed per NVD" || len(detail.Hint.Policy.Problems) != 0 {
		t.Errorf("expected the hint's rule from the vocabulary, got %+v", detail.Hint.Policy)
	}

	// previewing the hint moves the gate without writing anything
	rec := s.post("/preview", `{"labels":{"`+tar.ID+`":"fp"}}`)
	var preview struct {
		Outcome string
		Checks  []struct{ Name, State string }
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &preview) != nil || preview.Outcome != "pass" {
		t.Fatalf("expected the preview to pass the gate, got %d %s", rec.Code, rec.Body)
	}
	if rec := s.post("/preview", `{"labels":{"`+tar.ID+`":"unclear"}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("expected a preview label other than tp or fp refused, got %d", rec.Code)
	}
	if s.labelOf("CVE-2005-2541") != nil {
		t.Fatal("previewing wrote a label")
	}

	if rec := s.do(http.MethodPost, "/api/gates/deb/accept", "", `{"rows":["`+tar.ID+`"]}`); rec.Code != http.StatusForbidden {
		t.Fatalf("expected an accept without the token refused, got %d", rec.Code)
	}
	if rec := s.post("/accept", `{"rows":["`+tar.ID+`"]}`); rec.Code != http.StatusOK {
		t.Fatalf("expected the accept written, got %d %s", rec.Code, rec.Body)
	}
	l := s.labelOf("CVE-2005-2541")
	if l == nil || l.Verdict != claimsv1.FP || l.Author != "tester" || len(l.Evidence) != 1 || l.SeenIn == nil {
		t.Fatalf("expected the proposal's label by the acceptor, got %+v", l)
	}
	if got := s.tarRow(); got.Verdict != "fp" || got.Hint == nil || got.Hint.Status != "agrees" {
		t.Errorf("expected the accepted hint to agree with the label, got %+v", got)
	}
}

func TestServeOverridingAHintIsRecorded(t *testing.T) {
	s := newServed(t)
	tar := s.tarRow()
	p := agentstore.Proposal{Schema: agentstore.Schema, ID: "p1", Gate: "deb", Subject: s.subject(), Package: tar.Package.Ref, Vulnerability: "CVE-2005-2541",
		Verdict: claimsv1.FP, Justification: "fix-installed", Author: agentstore.Author{Kind: agentstore.Agent}, Timestamp: time.Now()}
	if err := s.store.Proposals.Add(p); err != nil {
		t.Fatal(err)
	}
	rec := s.post("/labels", `{"rows":["`+tar.ID+`"],"verdict":"tp","overrideReason":{"kind":"stale-fact","text":"the fix was reverted"}}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tar.ID) {
		t.Fatalf("expected the label written overriding the hint, got %d %s", rec.Code, rec.Body)
	}
	overrides, err := s.store.Overrides.Current()
	if err != nil {
		t.Fatal(err)
	}
	if len(overrides) != 1 || overrides[0].Proposal != "p1" || overrides[0].Verdict != claimsv1.TP || overrides[0].Reason.Kind != "stale-fact" {
		t.Errorf("expected one override record, got %+v", overrides)
	}
	if l := s.labelOf("CVE-2005-2541"); l == nil || len(l.Extra) != 0 {
		t.Errorf("expected a clean tp label, got %+v", l)
	}
}

func TestServeCausesAndExplanations(t *testing.T) {
	s := newServed(t)
	tar := s.tarRow()
	member := agentstore.Member{Row: tar.ID, Vulnerability: "CVE-2005-2541", Package: tar.Package.Ref}
	c := agentstore.Cause{Schema: agentstore.Schema, ID: "c1", Gate: "deb", Title: "tar fixed in the image", SourcePackage: "tar", Direction: "dropped",
		Members: []agentstore.Member{member}, Verdict: claimsv1.FP, Justification: "fix-installed", Author: agentstore.Author{Kind: agentstore.Agent}, Timestamp: time.Now()}
	if err := s.store.Causes.Add(c); err != nil {
		t.Fatal(err)
	}
	x := agentstore.Explanation{Schema: agentstore.Schema, ID: "e1", Gate: "deb", Run: runrecord.DefaultName, Title: "the candidate's DB dropped tar",
		Members: []agentstore.Member{member}, Author: agentstore.Author{Kind: agentstore.Agent}, Timestamp: time.Now()}
	if err := s.store.Explanations.Add(x); err != nil {
		t.Fatal(err)
	}
	var st stateDoc
	s.get("/api/gates/deb/state", &st)
	if len(st.Causes) != 1 || len(st.Causes[0].Pending) != 1 || len(st.Explanations) != 1 || st.Explanations[0].Title != x.Title {
		t.Fatalf("expected the cause and the explanation, got %+v %+v", st.Causes, st.Explanations)
	}
	if st.Vocabulary == nil || st.Vocabulary.Justifications["fp"]["fix-installed"] == "" {
		t.Error("expected the vocabulary's justifications, for the picker")
	}
	if got := s.tarRow(); len(got.Causes) != 1 || got.Explanation != "e1" {
		t.Errorf("expected the row to name its cause and explanation, got %+v", got)
	}
	if rec := s.post("/package-hints/c1/accept", `{"rows":["`+tar.ID+`"]}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"written":1`) {
		t.Fatalf("expected the cause accepted, got %d %s", rec.Code, rec.Body)
	}
	if l := s.labelOf("CVE-2005-2541"); l == nil || l.Verdict != claimsv1.FP || len(l.Notes) > 0 && l.Notes[0].Text != c.Note {
		t.Fatalf("expected the cause's label, got %+v", l)
	}
	// accepting again skips the labeled member
	if rec := s.post("/package-hints/c1/accept", `{"rows":["`+tar.ID+`"]}`); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "already labeled fp") {
		t.Errorf("expected the labeled member skipped, got %d %s", rec.Code, rec.Body)
	}
}

func TestServeSharedJoinsGates(t *testing.T) {
	s := newServed(t)
	var shared struct {
		Gates []struct {
			Name string
			Open int
		}
		Findings []struct {
			Vulnerability string
			In            []struct{ Gate, Row string }
		}
	}
	s.get("/api/gates/shared", &shared)
	if len(shared.Gates) != 1 || shared.Gates[0].Open != 1 || len(shared.Findings) != 1 || shared.Findings[0].Vulnerability != "CVE-2005-2541" {
		t.Errorf("expected the one open finding of the one gate, got %+v", shared)
	}
	var list struct {
		Open  string
		Gates []struct{ ID, GateOutcome string }
	}
	s.get("/api/gates", &list)
	if list.Open != "deb" || len(list.Gates) != 1 || list.Gates[0].GateOutcome != "undecided" {
		t.Errorf("expected the deb gate listed, got %+v", list)
	}
}

// a gate scanned later that cannot be scored (a remote claims source whose host is unreachable) is
// skipped for the default gate and leaves the others' routes working
func TestServeSkipsAGateThatCannotBeScored(t *testing.T) {
	// nothing listens on port 1, so the pointer read fails without leaving the machine
	t.Setenv("YARDSTICK_CLAIMS_URL", "http://127.0.0.1:1")
	s := newServed(t)
	s.w.gate("aaa", s.whole, s.whole, "", "  - name: noNewFalseNegatives\n")
	if _, stderr, code := yardstick(t, s.w.dir, "gates/aaa.yaml"); code == 2 {
		t.Fatalf("scan failed: %s", stderr)
	}
	gate := filepath.Join(s.w.dir, "gates", "aaa.yaml")
	data, err := os.ReadFile(gate)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, gate, strings.Replace(string(data), "claims: [../claims]", "claims: [github.com/anchore/delta-prototype@main]", 1))

	var list struct {
		Open  string
		Gates []struct{ ID, Error string }
	}
	s.get("/api/gates", &list)
	if list.Open != "deb" || len(list.Gates) != 2 || list.Gates[0].ID != "aaa" || list.Gates[0].Error == "" {
		t.Errorf("expected aaa listed with its error and deb opened, got %+v", list)
	}
	if rec := s.do(http.MethodGet, "/api/gates/aaa/state", "", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("expected aaa's state to fail, got %d", rec.Code)
	}
	var st stateDoc
	s.get("/api/gates/deb/state", &st)
	var shared struct{ Gates []struct{ Name, Note string } }
	s.get("/api/gates/shared", &shared)
	if len(shared.Gates) != 2 {
		t.Errorf("expected both gates in the shared view, got %+v", shared)
	}
}
