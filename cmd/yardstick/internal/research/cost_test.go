package research

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testdata/claude-result.json is the real output of `claude -p "say ok" --model haiku --output-format json`
func TestUsageIsReadFromTheResultLine(t *testing.T) {
	result, err := os.ReadFile("testdata/claude-result.json")
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "log.txt")
	// stderr shares the log, and a stray JSON line that is not the result is passed over
	content := "warming up\n{\"type\":\"system\",\"total_cost_usd\":9}\n" + string(result) + "\n"
	if err := os.WriteFile(log, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	u := readUsage(log)
	want := Usage{CostUSD: 0.004815970000000001, InputTokens: 2, CacheReadTokens: 11697, CacheCreationTokens: 23484, OutputTokens: 4, Turns: 1, DurationMs: 1708}
	if u == nil || *u != want {
		t.Fatalf("expected %+v, got %+v", want, u)
	}
	if u.TokensIn() != 35183 {
		t.Errorf("expected every input token counted, got %d", u.TokensIn())
	}
}

func TestNoResultLineRecordsNoUsage(t *testing.T) {
	r, _ := newRunner(t, `echo "plain text, no result"`, time.Minute)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ := r.Jobs()
	if j := jobs[0]; j.Status != Done || j.Usage != nil {
		t.Errorf("expected a finished job with no usage, got %+v", j)
	}
	if readUsage(filepath.Join(t.TempDir(), "missing.txt")) != nil {
		t.Error("expected no usage from a missing log")
	}
}

func TestUsageAndBatchAreRecordedOnTheJob(t *testing.T) {
	r, _ := newRunner(t, `echo '{"type":"result","total_cost_usd":0.25,"num_turns":3,"duration_ms":1500,"usage":{"input_tokens":10,"cache_read_input_tokens":200,"output_tokens":7}}'; exit 1`, time.Minute)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}, Model: "haiku", Batch: "b1"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	jobs, _ := r.Jobs()
	j := jobs[0]
	// usage is read whatever the job's status
	if j.Status != Failed || j.Model != "haiku" || j.Batch != "b1" || j.Usage == nil || j.Usage.CostUSD != 0.25 || j.Usage.TokensIn() != 210 || j.Usage.Turns != 3 {
		t.Errorf("expected the failed job's usage, model and batch recorded, got %+v %+v", j, j.Usage)
	}
}

func TestModelValuesAreChecked(t *testing.T) {
	for _, ok := range []string{"sonnet", "claude-opus-5-5", "claude-3.5-haiku"} {
		if err := CheckModel(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Sonnet", "-x", "sonnet; rm -rf /", "$(id)", "opus[1m]", "a b"} {
		if CheckModel(bad) == nil {
			t.Errorf("expected %q refused", bad)
		}
	}
	r, _ := newRunner(t, `true`, time.Minute)
	if _, err := r.Start(context.Background(), Request{Rows: []string{"aaa"}, Model: "x;y"}); err == nil {
		t.Error("expected a request with a bad model refused")
	}
}

func TestEstimate(t *testing.T) {
	job := func(model string, cost float64, secs int) Job {
		return Job{Model: model, Status: Done, Usage: &Usage{CostUSD: cost, InputTokens: 100, CacheReadTokens: 900, OutputTokens: 50, DurationMs: secs * 1000}}
	}
	measured := []Job{job("opus", 1, 30), job("opus", 2, 60), job("opus", 3, 90), job("sonnet", 0.1, 10), {Model: "opus", Status: Failed}}
	got := Estimate(measured, "opus")
	want := Basis{Model: "opus", Measured: true, Source: SourceWorkspace, N: 3, Min: 1, Mean: 2, Max: 3, TokensIn: 1000, TokensOut: 50, Seconds: 60}
	if got != want {
		t.Errorf("opus: expected %+v, got %+v", want, got)
	}
	// too few on sonnet: the built-in measurement
	if got := Estimate(measured, "sonnet"); got != sonnetMeasured {
		t.Errorf("sonnet: expected the built-in numbers, got %+v", got)
	}
	// too few on anything else: not measured, with how many there are
	if got := Estimate(measured[:2], "opus"); got != (Basis{Model: "opus", N: 2}) {
		t.Errorf("opus with two jobs: expected not measured, got %+v", got)
	}
	if got := Estimate(nil, "haiku"); got.Measured || got.Mean != 0 {
		t.Errorf("haiku: expected not measured, got %+v", got)
	}
}
