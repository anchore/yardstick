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
	"path/filepath"
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
// queued, since proposing its call would be refused after the whole run
func TestE2EResearchRefusesUnlistedNamespace(t *testing.T) {
	srv, dir, _, _ := e2eServer(t)
	h, token := srv.Handler(), srv.Token()
	vocab := filepath.Join(dir, "claims", claimsv1.VocabularyFile)
	b, err := os.ReadFile(vocab)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vocab, []byte(strings.Replace(string(b), "vulnerability-namespaces: [CVE, GHSA]", "vulnerability-namespaces: [OSV]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"rows": []string{"24160b879ac36bf5"}})
	req := httptest.NewRequest(http.MethodPost, "/api/research", bytes.NewReader(body))
	req.Header.Set(labelserver.TokenHeader, token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "add it to advisory-ids if its ids are advisories that alias CVEs, else to vulnerability-namespaces") {
		t.Errorf("POST /api/research on an unlisted namespace: %d %s", rec.Code, rec.Body)
	}
	var jl labelserver.ResearchJobs
	get(t, h, "/api/research/jobs", &jl)
	if len(jl.Jobs) != 0 {
		t.Errorf("a refused request queued jobs: %+v", jl.Jobs)
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
