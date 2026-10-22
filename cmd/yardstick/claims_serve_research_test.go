package main

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// stubClaude puts a claude on PATH that lists the yardstick plugin at version and, run as an
// agent, prints its arguments and the job's environment. It returns a stand-in yardstick binary.
func stubClaude(t *testing.T, version string) string {
	t.Helper()
	bin, ys := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(bin, "claude"), `#!/bin/sh
if [ "$1" = plugin ]; then echo '[{"id":"yardstick@delta-prototype","version":"`+version+`","enabled":true}]'; exit 0; fi
echo "args: $*"
echo "gate=$YARDSTICK_GATE name=$YARDSTICK_NAME job=$YARDSTICK_RESEARCH_JOB vuln=$YARDSTICK_RESEARCH_VULNERABILITY yardstick=$(command -v yardstick)"
`)
	writeFile(t, filepath.Join(ys, "yardstick"), "#!/bin/sh\n")
	for _, f := range []string{filepath.Join(bin, "claude"), filepath.Join(ys, "yardstick")} {
		if err := os.Chmod(f, 0o755); err != nil { //nolint:gosec // a test stub must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return filepath.Join(ys, "yardstick")
}

type researchState struct {
	ResearchConcurrency int                    `json:"researchConcurrency"`
	Research            *research.Availability `json:"research"`
	Subjects            []struct {
		Rows []struct {
			ID            string `json:"id"`
			Researched    bool   `json:"researched"`
			ResearchLevel string `json:"researchLevel"`
			Research      *struct {
				Job, Status, Source string
			} `json:"research"`
			Hint *struct{ Origin, ResearchJob string } `json:"hint"`
		} `json:"rows"`
	} `json:"subjects"`
}

func servedWithResearch(t *testing.T, binVersion string) (*served, *research.Runner, string) {
	t.Helper()
	ys := stubClaude(t, "0.17.0")
	var runner *research.Runner
	s := newServedWith(t, func(o *labelserver.Options) {
		dir, _ := os.Getwd()
		runner = research.NewRunner(research.Config{Dir: dir, Run: o.Run, Concurrency: 1, Timeout: time.Minute, Bin: ys})
		o.Research, o.ResearchAvailability = runner, research.CheckPlugin(context.Background(), binVersion)
	})
	return s, runner, ys
}

func (s *served) research(body string, into any) {
	s.t.Helper()
	rec := s.post("/research", body)
	if rec.Code != http.StatusOK {
		s.t.Fatalf("POST research %s: %d %s", body, rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		s.t.Fatal(err)
	}
}

func TestServeResearchRunsThePluginSkill(t *testing.T) {
	s, runner, ys := servedWithResearch(t, "v0.17.0")
	tar := s.tarRow()
	var st researchState
	s.get("/api/gates/deb/state", &st)
	if st.ResearchConcurrency != 1 || st.Research == nil || !st.Research.Available {
		t.Fatalf("expected research available, got %d %+v", st.ResearchConcurrency, st.Research)
	}

	type counts struct {
		Jobs            []string
		Matches, Queued int
	}
	var c counts
	s.research(`{"select":"could-move-check","dryRun":true}`, &c)
	if c.Matches != 1 || c.Queued != 1 || len(c.Jobs) != 0 {
		t.Errorf("expected a dry run to count the open tar row and start nothing, got %+v", c)
	}
	for _, bad := range []string{`{}`, `{"select":"all"}`, `{"select":"no-hint","rows":["x"]}`, `{"rows":["nope"]}`} {
		if rec := s.post("/research", bad); rec.Code != http.StatusBadRequest {
			t.Errorf("POST research %s: expected 400, got %d", bad, rec.Code)
		}
	}
	if rec := s.post("/research", `{"select":"no-hint","subject":"nope"}`); rec.Code != http.StatusNotFound {
		t.Errorf("expected an unknown subject refused, got %d", rec.Code)
	}
	if rec := s.do(http.MethodPost, "/api/gates/deb/research", "", `{"rows":["`+tar.ID+`"]}`); rec.Code != http.StatusForbidden {
		t.Errorf("expected research without the token refused, got %d", rec.Code)
	}

	s.research(`{"select":"no-hint","dryRun":true}`, &c)
	noHint := c.Matches
	s.research(`{"rows":["`+tar.ID+`"]}`, &c)
	if len(c.Jobs) != 1 || c.Jobs[0] != tar.ID {
		t.Fatalf("expected one job named by the row, got %+v", c)
	}
	runner.Wait()
	rec := s.do(http.MethodGet, "/api/research/"+tar.ID+"/log", "", "")
	log := rec.Body.String()
	dir, _ := os.Getwd()
	for _, want := range []string{"args: -p /yardstick:research-vuln row:" + tar.ID + " " + dir + " --model sonnet",
		"gate=deb name=" + runrecord.DefaultName + " job=" + tar.ID + " vuln=CVE-2005-2541 yardstick=" + ys} {
		if !strings.Contains(log, want) {
			t.Errorf("expected the log to hold %q, got %q", want, log)
		}
	}
	if rec := s.do(http.MethodGet, "/api/research/nope/log", "", ""); rec.Code != http.StatusNotFound {
		t.Errorf("expected an unknown job's log refused, got %d", rec.Code)
	}

	// finished research counts, and a proposal the job recorded names it
	p := agentstore.Proposal{Schema: agentstore.Schema, ID: "p1", Subject: s.subject(), Package: tar.Package.Ref, Vulnerability: "CVE-2005-2541",
		Verdict: claimsv1.FP, Justification: "fix-installed", Confidence: "high",
		Author: agentstore.Author{Name: "agent", Kind: agentstore.Agent, Skill: "yardstick:research-vuln", ResearchJob: tar.ID}, Timestamp: time.Now(), Gate: "deb"}
	if err := s.store.Proposals.Add(p); err != nil {
		t.Fatal(err)
	}
	s.get("/api/gates/deb/state", &st)
	r := st.Subjects[0].Rows[0]
	for _, x := range st.Subjects[0].Rows {
		if x.ID == tar.ID {
			r = x
		}
	}
	if !r.Researched || r.ResearchLevel != "researched" || r.Research == nil || r.Research.Status != "done" || r.Research.Source != research.FromLabelUI ||
		r.Hint == nil || r.Hint.Origin != labelserver.OriginLabelUI || r.Hint.ResearchJob != tar.ID {
		t.Errorf("expected the row researched from the UI, got %+v %+v %+v", r, r.Research, r.Hint)
	}
	s.research(`{"select":"no-hint","dryRun":true}`, &c)
	if c.Matches != noHint-1 {
		t.Errorf("expected the researched row left out of %d, got %+v", noHint, c)
	}
	var cancel struct {
		Cancelled    []string
		NotCancelled []struct{ Job, Why string }
	}
	if rec := s.post("/research/cancel", `{"rows":["`+tar.ID+`"]}`); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &cancel) != nil ||
		len(cancel.Cancelled) != 0 || len(cancel.NotCancelled) != 1 || !strings.Contains(cancel.NotCancelled[0].Why, "not running") {
		t.Errorf("expected a finished job not cancelled, got %d %+v", rec.Code, cancel)
	}
}

func TestServeResearchLogRendersClaudesJSON(t *testing.T) {
	fixtures, _ := filepath.Abs(filepath.Join("internal", "research", "testdata")) // before serving moves to its workspace
	s, runner, _ := servedWithResearch(t, "v0.17.0")
	tar := s.tarRow()
	var c struct{ Jobs []string }
	s.research(`{"rows":["`+tar.ID+`"]}`, &c)
	runner.Wait()
	url := "/api/research/" + tar.ID + "/log"
	for _, tt := range []struct{ name, fixture, query, want string }{
		{"plain text as it is", "", "", "args: -p /yardstick:research-vuln"}, // the stub claude's own log
		{"a stream as text", "claude-stream-tool.jsonl", "", "> Bash: seq 1 8\n    1\n"},
		{"json mode's result and cost", "claude-result.json", "", "ok\n\n-- success: $0.00, 1 turns, 2s\n"},
		{"raw untouched", "claude-stream.jsonl", "?raw=1", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.fixture != "" {
				data, err := os.ReadFile(filepath.Join(fixtures, tt.fixture))
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, runner.LogPath(tar.ID), string(data))
				if tt.want == "" {
					tt.want = string(data)
				}
			}
			rec := s.do(http.MethodGet, url+tt.query, "", "")
			got := rec.Body.String()
			ok := strings.Contains(got, tt.want)
			if tt.query != "" {
				ok = got == tt.want
			}
			if rec.Code != http.StatusOK || !ok {
				t.Errorf("expected %q, got %d %q", tt.want, rec.Code, got)
			}
		})
	}
}

func TestServeResearchDisabledWithoutTheRightPlugin(t *testing.T) {
	s, _, _ := servedWithResearch(t, "0.18.0")
	var st researchState
	s.get("/api/gates/deb/state", &st)
	if st.ResearchConcurrency != 0 || st.Research == nil || st.Research.Available || !strings.Contains(st.Research.Command, "claude plugin update yardstick@delta-prototype") {
		t.Fatalf("expected research disabled with the update command, got %d %+v", st.ResearchConcurrency, st.Research)
	}
	if rec := s.post("/research", `{"rows":["`+s.tarRow().ID+`"]}`); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "claude plugin update") {
		t.Errorf("expected research refused with the command, got %d %s", rec.Code, rec.Body)
	}
}

func TestServeLocalOnly(t *testing.T) {
	h := labelserver.LocalOnly(7655, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	for _, tc := range []struct {
		method, host, origin string
		code                 int
		remote               string
	}{
		{http.MethodGet, "127.0.0.1:7655", "", http.StatusOK, ""},
		{http.MethodGet, "localhost:7655", "", http.StatusOK, ""},
		{http.MethodPost, "[::1]:7655", "http://localhost:7655", http.StatusOK, "[::1]:50000"},
		{http.MethodGet, "evil.example:7655", "", http.StatusForbidden, ""},
		{http.MethodGet, "127.0.0.1:8000", "", http.StatusForbidden, ""},
		{http.MethodPost, "127.0.0.1:7655", "http://evil.example", http.StatusForbidden, ""},
		{http.MethodPost, "127.0.0.1:7655", "https://127.0.0.1:7655", http.StatusForbidden, ""},
		// a client on the network sending a loopback Host
		{http.MethodGet, "127.0.0.1:7655", "", http.StatusForbidden, "192.168.1.20:50000"},
	} {
		req := httptest.NewRequest(tc.method, "/", nil)
		req.Host = tc.host
		req.RemoteAddr = cmp.Or(tc.remote, "127.0.0.1:50000")
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.code {
			t.Errorf("%s host %s origin %q: got %d, want %d", tc.method, tc.host, tc.origin, rec.Code, tc.code)
		}
	}
}

func TestServeCauseMembersMustBeTheirRows(t *testing.T) {
	s := newServed(t)
	tar := s.tarRow()
	add := func(id, gate string, m agentstore.Member) {
		c := agentstore.Cause{Schema: agentstore.Schema, ID: id, Gate: gate, Title: "t", SourcePackage: "tar", Members: []agentstore.Member{m},
			Verdict: claimsv1.FP, Justification: "fix-installed", Author: agentstore.Author{Kind: agentstore.Agent}, Timestamp: time.Now()}
		if err := s.store.Causes.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	add("other-pkg", "deb", agentstore.Member{Row: tar.ID, Vulnerability: "CVE-2005-2541", Package: "pkg:deb/debian/bash@5.0"})
	add("other-vuln", "deb", agentstore.Member{Row: tar.ID, Vulnerability: "CVE-2099-0001", Package: tar.Package.Ref})
	add("other-gate", "elsewhere", agentstore.Member{Row: tar.ID, Vulnerability: "CVE-2005-2541", Package: tar.Package.Ref})
	var st stateDoc
	s.get("/api/gates/deb/state", &st)
	if len(st.Causes) != 0 || len(s.tarRow().Causes) != 0 {
		t.Fatalf("expected no mismatched cause on the row, got %+v", st.Causes)
	}
	for _, id := range []string{"other-pkg", "other-vuln", "other-gate"} {
		if rec := s.post("/package-hints/"+id+"/accept", `{"rows":["`+tar.ID+`"]}`); rec.Code == http.StatusOK {
			t.Errorf("cause %s: expected the accept refused, got %d %s", id, rec.Code, rec.Body)
		}
	}
	for _, l := range s.debLabels() {
		if l.Vulnerability == "CVE-2099-0001" || strings.Contains(l.Package, "bash") || l.Vulnerability == "CVE-2005-2541" {
			t.Errorf("expected no label written, got %+v", l)
		}
	}
}

func TestServeCancelABatch(t *testing.T) {
	var runner *research.Runner
	s := newServedWith(t, func(o *labelserver.Options) {
		dir, _ := os.Getwd()
		runner = research.NewRunner(research.Config{Command: "sleep 30", Dir: dir, Run: o.Run, Concurrency: 1, Timeout: time.Minute})
		o.Research, o.ResearchAvailability = runner, research.Availability{Available: true}
	})
	var started labelserver.ResearchQueueResponse
	rec := s.do(http.MethodPost, "/api/research", s.srv.Token(), `{"groups":["change","none"]}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &started) != nil || started.Batch == "" || len(started.Jobs) == 0 {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	if rec := s.do(http.MethodPost, "/api/research/batch/cancel", "", `{"id":"`+started.Batch+`"}`); rec.Code != http.StatusForbidden {
		t.Errorf("expected a cancel without the token refused, got %d", rec.Code)
	}
	var cancel labelserver.CancelResponse
	rec = s.do(http.MethodPost, "/api/research/batch/cancel", s.srv.Token(), `{"id":"`+started.Batch+`"}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &cancel) != nil || len(cancel.Cancelled) != len(started.Jobs) || len(cancel.NotCancelled) != 0 {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body)
	}
	runner.Wait()
	var b labelserver.ResearchBatch
	s.get("/api/research/batch", &b)
	if b.ID != started.Batch || b.Total != len(started.Jobs) || b.Cancelled != b.Total || b.Spent != 0 {
		t.Errorf("cancelled batch: %+v", b)
	}
}
