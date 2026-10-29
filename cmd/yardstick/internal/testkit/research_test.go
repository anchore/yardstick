package testkit

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	claimsv1 "github.com/anchore/yardstick/cmd/yardstick/internal/claims/v1"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
)

// researchCost is what one stand-in research job reports it cost, in USD (researchCommand).
const researchCost = 0.25

// planLines are a research plan's jobs as "<group> <gate> <rows...>", in order.
func planLines(r labelserver.ResearchQueueResponse) []string {
	var out []string
	for _, g := range r.Groups {
		for _, j := range g.Jobs {
			out = append(out, g.Group+" "+j.Gate+" "+strings.Join(j.Rows, " "))
		}
	}
	return out
}

// batch is GET /api/research/batch once every job of the newest batch has finished.
func batch(t *testing.T, h http.Handler) labelserver.ResearchBatch {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		var b labelserver.ResearchBatch
		get(t, h, "/api/research/batch", &b)
		if b.Running+b.Queued == 0 {
			return b
		}
		if time.Now().After(deadline) {
			t.Fatalf("the batch did not finish: %+v", b)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// research across gates over the seed: what qualifies, the plan's groups and dedup, a batch's
// progress and cost, and the hints it left
func TestE2EResearchQueue(t *testing.T) {
	srv, dir, _, _ := e2eServer(t)
	h, token := srv.Handler(), srv.Token()
	plan := func(body any) labelserver.ResearchQueueResponse {
		t.Helper()
		var out labelserver.ResearchQueueResponse
		if code := post(t, h, token, "/api/research", body, &out); code != http.StatusOK {
			t.Fatalf("POST /api/research %+v: %d", body, code)
		}
		return out
	}
	both := []string{"change", "none"}

	// on the seed only the two rows with no hint or cause qualify, and neither can change a gate
	p := plan(map[string]any{"groups": both, "dryRun": true})
	if got, want := planLines(p), []string{"none deb-npm 24160b879ac36bf5", "none deb-java e3bfd3b0b0c30ee6"}; !slices.Equal(got, want) {
		t.Errorf("seed plan:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// the tar row is in both gates and counted once
	if p.Skipped != (labelserver.ResearchSkipped{Hinted: 10}) || p.Concurrency != 2 || p.Batch != "" || len(p.Jobs) != 0 {
		t.Errorf("seed skipped: %+v", p)
	}
	// no history yet: the built-in sonnet numbers, times the jobs
	if e := p.Estimate; e.Jobs != 2 || e.Rows != 2 || !e.Basis.Measured || e.Basis.Source == "workspace" || e.Basis.Model != "sonnet" || e.Mean != 2*e.Basis.Mean || e.Seconds != e.Basis.Seconds {
		t.Errorf("seed estimate: %+v", e)
	}
	// change alone is the default, and on the seed it has nothing
	if p := plan(map[string]any{"dryRun": true}); p.Estimate.Jobs != 0 || p.Groups[0].Group != "change" || !p.Groups[0].Selected || p.Groups[1].Selected || len(p.Groups[1].Jobs) != 2 {
		t.Errorf("default groups: %+v", p)
	}
	for _, bad := range []map[string]any{{"model": "sonnet; id"}, {"model": "Opus"}, {"groups": []string{"all"}}, {"scope": "nope"}} {
		if code := post(t, h, token, "/api/research", bad, nil); code != http.StatusBadRequest {
			t.Errorf("POST /api/research %v: expected 400, got %d", bad, code)
		}
	}
	if code := post(t, h, "", "/api/research", map[string]any{"dryRun": true}, nil); code != http.StatusForbidden {
		t.Errorf("expected research without the token refused, got %d", code)
	}

	// with the proposals gone the hinted rows qualify: the rows that decide a gate first, in the
	// queue's order, each log4j pair one job, and the tar row once, under deb-npm where it decides
	if err := os.Remove(filepath.Join(dir, agentstore.Dir, "proposals.jsonl")); err != nil {
		t.Fatal(err)
	}
	p = plan(map[string]any{"groups": both, "dryRun": true})
	want := []string{
		"change deb-npm 5e50fe5b2007001a",
		"change deb-npm 0fe9fc814bcd060a",
		"change deb-java e1af7851f0e60bb4 783bbb63489d81a6",
		"change deb-java 42c45bf99e4f741b a88b3bd584c62516",
		"none deb-npm 24160b879ac36bf5",
		"none deb-java e3bfd3b0b0c30ee6",
	}
	if got := planLines(p); !slices.Equal(got, want) || p.Groups[0].Rows != 6 || p.Skipped != (labelserver.ResearchSkipped{Hinted: 4}) {
		t.Errorf("plan without proposals:\n%s\nwant:\n%s\n%+v", strings.Join(got, "\n"), strings.Join(want, "\n"), p.Skipped)
	}
	if j := p.Groups[0].Jobs[0]; j.Vulnerability != "CVE-2026-41992" || j.Package.Name != "gzip" || j.Package.Version != "1.12-1" || j.Image != "vulnerabilities-debian-12-tar-util-linux:617d48d" {
		t.Errorf("the gzip job: %+v", j)
	}
	// each open row is one match of one job, the research page's rows: a log4j pair is one job of two
	for _, g := range p.Groups {
		n := 0
		for _, j := range g.Jobs {
			n += len(j.Matches)
		}
		if n != g.Rows {
			t.Errorf("%s lists %d matches for %d rows", g.Group, n, g.Rows)
		}
	}
	if j := p.Groups[0].Jobs[2]; len(j.Matches) != 2 || j.Matches[0].Row != "e1af7851f0e60bb4" || j.Matches[1].Row != "783bbb63489d81a6" || j.ImageSlug == "" {
		t.Errorf("a log4j pair's job: %+v", j)
	}
	if p := plan(map[string]any{"scope": "gate:deb-java", "dryRun": true}); len(p.Groups[0].Jobs) != 2 || p.Groups[0].Jobs[0].Rows[0] != "e1af7851f0e60bb4" {
		t.Errorf("deb-java's plan: %v", planLines(p))
	}
	// a check takes only the rows bearing on it, grouped by what they do to it: the dropped tar row
	// can't move noNewFalsePositives, the log4j pairs (added) can
	p = plan(map[string]any{"scope": "gate:deb-java", "check": "noNewFalsePositives", "groups": both, "dryRun": true})
	if got, want := planLines(p), []string{"change deb-java e1af7851f0e60bb4 783bbb63489d81a6", "change deb-java 42c45bf99e4f741b a88b3bd584c62516"}; !slices.Equal(got, want) {
		t.Errorf("noNewFalsePositives plan:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for body, code := range map[string]int{
		`{"check": "noNewFalsePositives"}`:                       http.StatusBadRequest,
		`{"scope": "image:deb", "check": "noNewFalsePositives"}`: http.StatusBadRequest,
		`{"scope": "gate:deb-java", "check": "nope"}`:            http.StatusNotFound,
		`{"rows": ["e3bfd3b0b0c30ee6"], "groups": ["change"]}`:   http.StatusBadRequest,
		`{"rows": ["e3bfd3b0b0c30ee6"], "check": "f1NotWorse"}`:  http.StatusBadRequest,
	} {
		if got := post(t, h, token, "/api/research", json.RawMessage(body), nil); got != code {
			t.Errorf("POST /api/research %s: expected %d, got %d", body, code, got)
		}
	}

	// the limit counts jobs in that order
	if p := plan(map[string]any{"limit": 3, "dryRun": true}); p.Estimate.Jobs != 3 || p.Estimate.Rows != 4 || len(p.Groups[0].Jobs) != 4 {
		t.Errorf("limit 3: %+v", p.Estimate)
	}

	// a start is one batch on the model asked for, and the stand-in's result lines are its cost
	var none labelserver.ResearchBatch
	get(t, h, "/api/research/batch", &none)
	if none.ID != "" {
		t.Errorf("expected no batch before one starts, got %+v", none)
	}
	started := plan(map[string]any{"limit": 3, "model": "haiku"})
	if started.Batch == "" || !slices.Equal(started.Jobs, []string{"5e50fe5b2007001a", "0fe9fc814bcd060a", "e1af7851f0e60bb4"}) {
		t.Fatalf("start: %+v", started)
	}
	b := batch(t, h)
	if b.ID != started.Batch || b.Model != "haiku" || b.Total != 3 || b.Done != 3 || b.Failed+b.Cancelled != 0 || b.Spent != 3*researchCost ||
		b.Estimate != b.Spent || b.SecondsLeft != 0 || b.Hints != (labelserver.ResearchHints{TP: 3}) || b.Started.IsZero() {
		t.Errorf("finished batch: %+v", b)
	}
	var byID labelserver.ResearchBatch
	get(t, h, "/api/research/batch?id="+b.ID, &byID)
	if byID.ID != b.ID {
		t.Errorf("the batch by id: %+v", byID)
	}
	if code := post(t, h, token, "/api/research/batch/cancel", map[string]string{"id": b.ID}, nil); code != http.StatusOK {
		t.Errorf("cancelling a finished batch: %d", code)
	}
	if code := post(t, h, token, "/api/research/batch/cancel", map[string]string{"id": "nope"}, nil); code != http.StatusNotFound {
		t.Errorf("cancelling an unknown batch: expected 404, got %d", code)
	}

	// the jobs list has each job's hint and where it was started; with nothing active the summary is empty
	var jl labelserver.ResearchJobs
	get(t, h, "/api/research/jobs", &jl)
	if len(jl.Jobs) != 3 || jl.Summary != (labelserver.ResearchJobsSummary{Concurrency: 2}) {
		t.Errorf("jobs after the batch: %+v", jl)
	}
	for _, j := range jl.Jobs {
		if j.Batch != b.ID || j.From != labelserver.FromResearchPage || j.Position != 0 || j.Cancellable || len(j.Hints) != 1 || j.Hints[0].Verdict != "tp" || j.Hints[0].Confidence != "medium" {
			t.Errorf("finished job: %+v", j)
		}
	}

	// what it researched is skipped from now on, sibling included, and haiku is now measured here
	p = plan(map[string]any{"groups": both, "model": "haiku", "dryRun": true})
	if p.Skipped != (labelserver.ResearchSkipped{Researched: 4, Hinted: 4}) || p.Estimate.Jobs != 3 {
		t.Errorf("after the batch: %+v %v", p.Skipped, planLines(p))
	}
	if e := p.Estimate.Basis; !e.Measured || e.Source != "workspace" || e.N != 3 || e.Mean != researchCost || e.TokensIn != 10030 || e.TokensOut != 400 || e.Seconds != 2 {
		t.Errorf("haiku's basis: %+v", e)
	}

	// a finding's research: the per-job estimate on the configured model, and who shares the job
	var st struct {
		ResearchEstimate *struct{ Model, Source string }
		Subjects         []struct {
			Rows []struct {
				ID             string
				ResearchShares []string
			}
		}
	}
	get(t, h, "/api/gates/deb-java/state", &st)
	if st.ResearchEstimate == nil || st.ResearchEstimate.Model != "sonnet" || st.ResearchEstimate.Source == "workspace" {
		t.Errorf("state research estimate: %+v", st.ResearchEstimate)
	}
	shares := map[string][]string{}
	for _, s := range st.Subjects {
		for _, r := range s.Rows {
			if len(r.ResearchShares) > 0 {
				shares[r.ID] = r.ResearchShares
			}
		}
	}
	if !slices.Equal(shares["e1af7851f0e60bb4"], []string{"783bbb63489d81a6"}) || !slices.Equal(shares["783bbb63489d81a6"], []string{"e1af7851f0e60bb4"}) || shares["e3bfd3b0b0c30ee6"] != nil {
		t.Errorf("research shares: %v", shares)
	}
}

// research on a vulnerability whose namespace the vocabulary lacks is refused before any job is
// queued, since proposing its call would be refused after the whole run; the refusal and the
// gate's state say which list to add it to, and adding it there lets the same request start
func TestE2EUnlistedNamespace(t *testing.T) {
	srv, dir, tools, bin := e2eServer(t)
	h, token := srv.Handler(), srv.Token()
	const babel = "24160b879ac36bf5" // GHSA-67hx-6x53-jw92, open in deb-npm
	vocab := filepath.Join(dir, "claims", claimsv1.VocabularyFile)
	b, err := os.ReadFile(vocab)
	if err != nil {
		t.Fatal(err)
	}
	// a comment, to see an add keep it
	edited := "# the e2e corpus's categories\n" + strings.Replace(string(b), "vulnerability-namespaces: [CVE, GHSA]", "vulnerability-namespaces: [CVE]", 1)
	if err := os.WriteFile(vocab, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	send := func(path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		data, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		req.Header.Set(labelserver.TokenHeader, token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	// the GHSA names one CVE, so the scan suggests a disclosure namespace, in the writable
	// source's vocabulary.yaml, named relative to the workspace
	want := labelserver.UnlistedNamespace{Gate: "deb-npm", ID: "GHSA-67hx-6x53-jw92", Namespace: "GHSA", Suggest: claimsv1.ListDisclosure, Checked: 1,
		Example: &labelserver.NamespaceExample{ID: "GHSA-67hx-6x53-jw92", Names: []string{"CVE-2023-45133"}}, File: filepath.Join("claims", claimsv1.VocabularyFile)}
	text := "This gate's scan has 1 GHSA id; each names exactly 1 vulnerability (e.g. GHSA-67hx-6x53-jw92 → CVE-2023-45133), so add it to vulnerability-namespaces in claims/vocabulary.yaml."
	var st labelserver.State
	get(t, h, "/api/gates/deb-npm/state", &st)
	if len(st.Unlisted) != 1 || !reflect.DeepEqual(st.Unlisted[0], want) {
		t.Errorf("deb-npm's unlisted namespaces: %+v", st.Unlisted)
	}
	// both ways to start research refuse it with that, as JSON the UI recognizes
	for _, path := range []string{"/api/research", "/api/gates/deb-npm/research"} {
		rec := send(path, map[string]any{"rows": []string{babel}})
		var got labelserver.UnlistedNamespace
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusBadRequest || got.Code != "unlisted-namespace" || !strings.Contains(got.Error, text) {
			t.Errorf("POST %s on an unlisted namespace: %d %s", path, rec.Code, rec.Body)
		}
		got.Code, got.Error = "", ""
		if !reflect.DeepEqual(got, want) {
			t.Errorf("POST %s's refusal: %+v", path, got)
		}
	}
	var jl labelserver.ResearchJobs
	get(t, h, "/api/research/jobs", &jl)
	if len(jl.Jobs) != 0 {
		t.Errorf("a refused request queued jobs: %+v", jl.Jobs)
	}
	// propose refuses the call the same way, naming the file as the set resolved it
	real, err := filepath.EvalSymlinks(vocab)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "claims", "agent", "propose", "--gate", "deb-npm")
	cmd.Dir, cmd.Env = dir, append(os.Environ(), "YARDSTICK_CACHE_DIR="+filepath.Join(tools, "cache"))
	cmd.Stdin = strings.NewReader(`{"row":"24160b879ac36bf5","verdict":"unclear","justification":"not-assessed","author":{"skill":"triage-deltas","model":"e2e"}}`)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), strings.Replace(text, "claims/vocabulary.yaml", real, 1)) {
		t.Errorf("propose on an unlisted namespace: %v\n%s", err, out)
	}

	// a namespace listed as both kinds is refused, and so is a name no id could have
	add := "/api/gates/deb-npm/vocabulary/namespace"
	for _, bad := range []struct{ ns, list, want string }{
		{"ELSA", claimsv1.ListDisclosure, `advisory-ids "ELSA" already covers it`},
		{"CVE", claimsv1.ListAdvisory, "it is in vulnerability-namespaces"},
		{"GH-SA", claimsv1.ListDisclosure, "namespace must be"},
		{"GHSA", "rules", "list must be"},
	} {
		if rec := send(add, map[string]string{"namespace": bad.ns, "list": bad.list}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), bad.want) {
			t.Errorf("adding %s to %s: %d %s", bad.ns, bad.list, rec.Code, rec.Body)
		}
	}
	noToken := httptest.NewRecorder()
	h.ServeHTTP(noToken, httptest.NewRequest(http.MethodPost, add, strings.NewReader(`{"namespace":"GHSA","list":"vulnerability-namespaces"}`)))
	if noToken.Code != http.StatusForbidden {
		t.Errorf("expected an add without the token refused, got %d", noToken.Code)
	}

	// adding it edits the file in place, its comment and order kept; again is no change
	added := func(rec *httptest.ResponseRecorder) labelserver.AddNamespaceResponse {
		t.Helper()
		var out labelserver.AddNamespaceResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("add: %d %s", rec.Code, rec.Body)
		}
		return out
	}
	if got := added(send(add, map[string]string{"namespace": "GHSA", "list": claimsv1.ListDisclosure})); got != (labelserver.AddNamespaceResponse{File: want.File, Added: true}) {
		t.Errorf("adding GHSA: %+v", got)
	}
	after, err := os.ReadFile(vocab)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != strings.Replace(edited, "vulnerability-namespaces: [CVE]", "vulnerability-namespaces: [CVE, GHSA]", 1) {
		t.Errorf("vocabulary.yaml after the add:\n%s", after)
	}
	if got := added(send(add, map[string]string{"namespace": "GHSA", "list": claimsv1.ListDisclosure})); got.Added || got.Created {
		t.Errorf("adding GHSA again: %+v", got)
	}
	// the very next requests read it: nothing unlisted, and the refused request starts
	st = labelserver.State{}
	get(t, h, "/api/gates/deb-npm/state", &st)
	if len(st.Unlisted) != 0 {
		t.Errorf("unlisted after the add: %+v", st.Unlisted)
	}
	var started labelserver.ResearchQueueResponse
	if code := post(t, h, token, "/api/research", map[string]any{"rows": []string{babel}}, &started); code != http.StatusOK || len(started.Jobs) != 1 {
		t.Errorf("research after the add: %d %+v", code, started)
	}
	batch(t, h)

	// a writable source with no vocabulary.yaml gets one, holding only what was added
	gate := filepath.Join(dir, "gates", "deb-java.yaml")
	g, err := os.ReadFile(gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "overlay"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gate, []byte(strings.Replace(string(g), "claims: [../claims]", "claims: [../claims, ../overlay]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := added(send("/api/gates/deb-java/vocabulary/namespace", map[string]string{"namespace": "CLEANSTART", "list": claimsv1.ListDisclosure})); got != (labelserver.AddNamespaceResponse{File: filepath.Join("overlay", claimsv1.VocabularyFile), Created: true, Added: true}) {
		t.Errorf("adding to the overlay: %+v", got)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "overlay", claimsv1.VocabularyFile)); string(data) != "vulnerability-namespaces: [CLEANSTART]\n" {
		t.Errorf("the overlay's vocabulary.yaml:\n%s", data)
	}
}

// jobs is GET /api/research/jobs once want jobs are running.
func jobs(t *testing.T, h http.Handler, want int) labelserver.ResearchJobs {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		var out labelserver.ResearchJobs
		get(t, h, "/api/research/jobs", &out)
		if out.Summary.Running == want {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d running: %+v", want, out.Summary)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// research in flight, on a runner whose jobs wait to be cancelled and run one at a time: starts
// from a table batch and skip the rows a job is on, the jobs list's order and queue positions,
// the summary across batches, and the research rows carry
func TestE2EResearchInFlight(t *testing.T) {
	_, dir, _, bin := e2eServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := research.NewRunner(research.Config{Command: "sleep 600", Dir: dir, Run: runrecord.DefaultName, Concurrency: 1, Timeout: 10 * time.Minute, Bin: bin})
	t.Cleanup(func() { cancel(); r.Wait() })
	srv, err := newServer(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	h, token := srv.Handler(), srv.Token()
	start := func(gate string, body any) labelserver.ResearchResponse {
		t.Helper()
		var out labelserver.ResearchResponse
		if code := post(t, h, token, "/api/gates/"+gate+"/research", body, &out); code != http.StatusOK {
			t.Fatalf("POST %s research %+v: %d", gate, body, code)
		}
		return out
	}

	// two rows from a table are one batch, one job per log4j pair
	first := start("deb-java", map[string]any{"rows": []string{"e1af7851f0e60bb4", "42c45bf99e4f741b"}, "from": "table"})
	if first.Batch == "" || first.Skipped != 0 || !slices.Equal(first.Jobs, []string{"e1af7851f0e60bb4", "42c45bf99e4f741b"}) || first.Matches != 2 {
		t.Fatalf("first start: %+v", first)
	}
	// a row a job is on is skipped, not restarted: the sibling of the first
	second := start("deb-java", map[string]any{"rows": []string{"783bbb63489d81a6", "e3bfd3b0b0c30ee6"}, "from": "table"})
	if second.Batch == "" || second.Batch == first.Batch || second.Skipped != 1 || !slices.Equal(second.Jobs, []string{"e3bfd3b0b0c30ee6"}) {
		t.Fatalf("second start: %+v", second)
	}
	// one row from a finding is no batch, and a row with a job on it starts nothing
	if one := start("deb-npm", map[string]any{"rows": []string{"5e50fe5b2007001a"}, "from": "finding"}); one.Batch != "" || len(one.Jobs) != 1 {
		t.Errorf("one row: %+v", one)
	}
	if again := start("deb-npm", map[string]any{"rows": []string{"5e50fe5b2007001a"}}); again.Skipped != 1 || len(again.Jobs) != 0 || again.Batch != "" {
		t.Errorf("a row already queued: %+v", again)
	}
	if code := post(t, h, token, "/api/gates/deb-npm/research", map[string]any{"rows": []string{"24160b879ac36bf5"}, "from": "nope"}, nil); code != http.StatusBadRequest {
		t.Errorf("an unknown from: expected 400, got %d", code)
	}

	// across gates, rows researches exactly those not hinted, researched or in flight: the tar row
	// has a job, gzip a hint, so only babel, under its one gate
	var p labelserver.ResearchQueueResponse
	if code := post(t, h, token, "/api/research", map[string]any{"rows": []string{"e3bfd3b0b0c30ee6", "24160b879ac36bf5", "0fe9fc814bcd060a"}}, &p); code != http.StatusOK {
		t.Fatalf("POST /api/research rows: %d", code)
	}
	if got := planLines(p); !slices.Equal(got, []string{"none deb-npm 24160b879ac36bf5"}) || p.Skipped != (labelserver.ResearchSkipped{Active: 1, Hinted: 1}) ||
		p.Batch == "" || !slices.Equal(p.Jobs, []string{"24160b879ac36bf5"}) {
		t.Errorf("rows start: %v %+v", got, p)
	}

	// newest first; one running, the rest numbered in the order they were queued
	jl := jobs(t, h, 1)
	if len(jl.Jobs) != 5 || !slices.IsSortedFunc(jl.Jobs, func(a, b labelserver.ResearchJob) int { return b.Queued.Compare(a.Queued) }) {
		t.Fatalf("jobs: %+v", jl.Jobs)
	}
	var waiting []string
	for i := len(jl.Jobs) - 1; i >= 0; i-- {
		j := jl.Jobs[i]
		switch {
		case j.Status == research.Running:
			if j.Position != 0 || !j.Cancellable {
				t.Errorf("running job: %+v", j)
			}
		case j.Position != len(waiting)+1 || !j.Cancellable:
			t.Errorf("queued job %s: position %d, expected %d", j.ID, j.Position, len(waiting)+1)
		default:
			waiting = append(waiting, j.ID)
		}
	}
	froms := map[string]string{}
	for _, j := range jl.Jobs {
		froms[j.ID] = j.From
	}
	if !maps.Equal(froms, map[string]string{"e1af7851f0e60bb4": "table", "42c45bf99e4f741b": "table", "e3bfd3b0b0c30ee6": "table",
		"5e50fe5b2007001a": "finding", "24160b879ac36bf5": "research"}) {
		t.Errorf("froms: %v", froms)
	}
	// the summary spans the three batches and the lone job, priced on sonnet's built-in numbers
	sum := jl.Summary
	basis := research.Estimate(nil, research.DefaultModel)
	if sum.Total != 5 || sum.Running != 1 || sum.Queued != 4 || sum.Concurrency != 1 || sum.Spent != 0 || math.Abs(sum.Estimate-5*basis.Mean) > 1e-9 || sum.SecondsLeft <= 0 {
		t.Errorf("summary: %+v", sum)
	}

	// a queued row's research says its place in line, in the queue and in the Unlabeled list
	var q labelserver.Queue
	get(t, h, "/api/queue", &q)
	if i := slices.IndexFunc(q.Entries, func(e labelserver.QueueEntry) bool { return e.Row == waiting[0] }); i < 0 {
		t.Errorf("no queue entry for %s", waiting[0])
	} else if rs := q.Entries[i].Research; rs == nil || rs.Status != research.Queued || rs.Position != 1 || rs.QueueLength != 4 {
		t.Errorf("queue entry research: %+v", rs)
	}
	var shared labelserver.SharedState
	get(t, h, "/api/gates/shared", &shared)
	i := slices.IndexFunc(shared.Findings, func(f labelserver.CrossFinding) bool { return f.In[0].Row == "e1af7851f0e60bb4" })
	if i < 0 || shared.Findings[i].Research == nil || shared.Findings[i].Research.Job != "e1af7851f0e60bb4" {
		t.Errorf("shared finding research: %+v", shared.Findings)
	}

	// a cancelled job of a batch still running stays in the summary; a batch with none left drops out
	var c labelserver.CancelResponse
	if code := post(t, h, token, "/api/gates/deb-java/research/cancel", map[string]any{"rows": []string{"42c45bf99e4f741b", "e3bfd3b0b0c30ee6"}}, &c); code != http.StatusOK || len(c.Cancelled) != 2 {
		t.Fatalf("cancel: %d %+v", code, c)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		jl = jobs(t, h, 1)
		if jl.Summary.Queued == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s := jl.Summary; s.Total != 4 || s.Cancelled != 1 || s.Queued != 2 || s.Running != 1 {
		t.Errorf("summary after a cancel: %+v", s)
	}
}

// notRecordedCommand stands in for research whose propose call was denied, as headless claude's
// were in the CleanStart turnup: it writes its report and proposal where the skill does, and never
// proposes
const notRecordedCommand = `d=.yardstick/research/$YARDSTICK_RESEARCH_VULNERABILITY/tar && mkdir -p "$d" && printf '# %s on tar\n\ntp, medium confidence\n' "$YARDSTICK_RESEARCH_VULNERABILITY" > "$d/REPORT.md" && ` +
	`printf '{"row":"%s","verdict":"tp","justification":"no-fix","confidence":"medium","note":"e2e","openQuestions":["Was the fix backported?"],"author":{"skill":"research-vuln","model":"e2e"}}\n' "$YARDSTICK_ROW" > "$d/proposal.json" && ` +
	`echo '{"type":"result","subtype":"success","result":"Verdict I would propose: tp, no-fix, medium.","total_cost_usd":0.27,"num_turns":18,"permission_denials":[{"tool_name":"Bash","tool_use_id":"t1","tool_input":{"command":"yardstick claims agent propose --gate deb-java proposal.json"}}]}'`

// research that ran but recorded nothing says so and why, shows what it wrote, and records it as
// a hint on request without researching again
func TestE2EResearchNotRecorded(t *testing.T) {
	_, dir, _, bin := e2eServer(t)
	runner := research.NewRunner(research.Config{
		Command: notRecordedCommand, Dir: dir, Run: runrecord.DefaultName, Concurrency: 2, Timeout: time.Minute, Bin: bin,
		Recorded: agentstore.Open(filepath.Join(dir, agentstore.Dir)).RecordedJobs,
	})
	srv, err := newServer(context.Background(), runner)
	if err != nil {
		t.Fatal(err)
	}
	h, token := srv.Handler(), srv.Token()
	const tar = "e3bfd3b0b0c30ee6" // CVE-2026-18508 on tar, open in deb-java with no hint
	if code := post(t, h, token, "/api/gates/deb-java/research", map[string]any{"rows": []string{tar}, "from": "finding"}, nil); code != http.StatusOK {
		t.Fatalf("research: %d", code)
	}
	// one row's research is no batch: wait for the runner
	runner.Wait()
	row := func() labelserver.RowResponse {
		t.Helper()
		var d labelserver.RowResponse
		get(t, h, "/api/gates/deb-java/rows/"+tar, &d)
		return d
	}
	d := row()
	if j := d.Row.Research; j == nil || j.Status != research.NotRecorded || j.Error != "the agent was refused 1 tool use: Bash yardstick claims agent propose --gate deb-java proposal.json" || j.CostUSD != 0.27 {
		t.Fatalf("the row's research: %+v", j)
	}
	r := d.Research
	if r == nil || !r.Recordable || r.Summary != "Verdict I would propose: tp, no-fix, medium." || r.Output == nil ||
		r.Output.Dir != filepath.Join(".yardstick", "research", "CVE-2026-18508", "tar") || !slices.Equal(r.Output.Files, []string{"REPORT.md", "proposal.json"}) ||
		!strings.Contains(r.Output.Report, "tp, medium confidence") || r.Output.Proposal == nil || r.Output.Proposal.Verdict != "tp" ||
		!slices.Equal(r.Output.Proposal.OpenQuestions, []string{"Was the fix backported?"}) {
		t.Fatalf("what the research wrote: %+v %+v", r, r.Output)
	}
	if d.Hint != nil || d.Row.Researched {
		t.Fatalf("expected no hint and not researched before recording, got %+v %v", d.Hint, d.Row.Researched)
	}
	// not researched, so batch research plans it again
	var plan labelserver.ResearchQueueResponse
	if code := post(t, h, token, "/api/research", map[string]any{"groups": []string{"change", "none"}, "dryRun": true}, &plan); code != http.StatusOK || !slices.Contains(planLines(plan), "none deb-java "+tar) {
		t.Errorf("expected the batch plan to research it again: %d %v", code, planLines(plan))
	}

	// recording it is propose on what it wrote, as the job: the hint arrives, and the job is done.
	// It's asked from deb-npm, which scans the same image, so its finding page shows the same row
	// and job: the job proposes under its own gate, deb-java
	var rec map[string]string
	if code := post(t, h, token, "/api/gates/deb-npm/research/record", map[string]string{"row": tar}, &rec); code != http.StatusOK || rec["status"] != "done" {
		t.Fatalf("record: %d %v", code, rec)
	}
	d = row()
	if d.Hint == nil || d.Hint.Proposal.Verdict != "tp" || d.Hint.Proposal.Author.ResearchJob != tar || d.Row.Research.Status != research.Done || d.Research.Recordable {
		t.Errorf("after recording: hint %+v, research %+v %+v", d.Hint, d.Row.Research, d.Research)
	}
	if code := post(t, h, token, "/api/gates/deb-java/research/record", map[string]string{"row": tar}, nil); code != http.StatusBadRequest {
		t.Errorf("recording twice: expected 400, got %d", code)
	}

	// propose run in a job leaves its refusal in the job's directory, and a success clears it
	// (a job's own directory: propose writes nowhere else)
	jobDir := filepath.Join(t.TempDir(), ".yardstick", "research", "jobs", "j1")
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	propose := func(in string) error {
		cmd := exec.Command(bin, "claims", "agent", "propose", "--gate", "deb-java")
		cmd.Dir, cmd.Env, cmd.Stdin = dir, append(os.Environ(), research.JobDirEnv+"="+jobDir), strings.NewReader(in)
		return cmd.Run()
	}
	refusal := filepath.Join(jobDir, research.ProposeErrorFile)
	if err := propose(`{"row":"` + tar + `","verdict":"tp","justification":"not-a-justification","author":{"skill":"e2e"}}`); err == nil {
		t.Fatal("expected propose to refuse an unlisted justification")
	}
	if b, err := os.ReadFile(refusal); err != nil || !strings.Contains(string(b), `justification "not-a-justification"`) {
		t.Errorf("expected the refusal in the job's directory: %q %v", b, err)
	}
	if err := propose(`{"row":"` + tar + `","verdict":"tp","justification":"no-fix","author":{"skill":"e2e"}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(refusal); !os.IsNotExist(err) {
		t.Errorf("expected a success to clear the refusal: %v", err)
	}
}
