package testkit

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
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
	if p := plan(map[string]any{"scope": "gate:deb-java", "dryRun": true}); len(p.Groups[0].Jobs) != 2 || p.Groups[0].Jobs[0].Rows[0] != "e1af7851f0e60bb4" {
		t.Errorf("deb-java's plan: %v", planLines(p))
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
