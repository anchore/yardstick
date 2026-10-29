package research

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Usage is what one job's run cost, as claude's JSON result line reports it.
type Usage struct {
	CostUSD             float64 `json:"costUSD"`
	InputTokens         int     `json:"inputTokens"`
	CacheReadTokens     int     `json:"cacheReadTokens"`
	CacheCreationTokens int     `json:"cacheCreationTokens"`
	OutputTokens        int     `json:"outputTokens"`
	Turns               int     `json:"turns"`
	DurationMs          int     `json:"durationMs"`
}

// TokensIn is every input token, cached or not.
// resultType is the type of the line stream-json ends with: the result, what the run cost and the
// agent's last message
const resultType = "result"

func (u Usage) TokensIn() int {
	return u.InputTokens + u.CacheReadTokens + u.CacheCreationTokens
}

// result is the part of claude's result object (the last line of `--output-format stream-json`, or all
// of `--output-format json`) a job keeps.
type result struct {
	Type         string  `json:"type"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	NumTurns     int     `json:"num_turns"`
	DurationMs   int     `json:"duration_ms"`
	Usage        struct {
		InputTokens              int `json:"input_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		OutputTokens             int `json:"output_tokens"`
	} `json:"usage"`
}

// readUsage is the usage of the last line of a job's log that is a JSON object of type result; nil
// when there is none (another command, or a run stopped before claude printed it).
func readUsage(path string) *Usage {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out *Usage
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		var r result
		if !bytes.HasPrefix(line, []byte("{")) || json.Unmarshal(line, &r) != nil || r.Type != resultType {
			continue
		}
		out = &Usage{CostUSD: r.TotalCostUSD, InputTokens: r.Usage.InputTokens, CacheReadTokens: r.Usage.CacheReadInputTokens,
			CacheCreationTokens: r.Usage.CacheCreationInputTokens, OutputTokens: r.Usage.OutputTokens, Turns: r.NumTurns, DurationMs: r.DurationMs}
	}
	return out
}

// a model reaches the command only through YARDSTICK_MODEL, but it is still a name, never shell
var modelName = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]*$`)

// CheckModel refuses a model value that isn't a plain name or alias (sonnet, claude-opus-5-5).
func CheckModel(m string) error {
	if !modelName.MatchString(m) {
		return fmt.Errorf("model %q is not a model name", m)
	}
	return nil
}

// Basis is what one job costs on a model, from this workspace's finished jobs or the built-in
// measurement: cost in USD, mean tokens, mean seconds. Measured is false when neither applies.
type Basis struct {
	Model     string  `json:"model"`
	Measured  bool    `json:"measured"`
	Source    string  `json:"source,omitempty"` // "workspace", or the built-in measurement's date
	N         int     `json:"n"`
	Min       float64 `json:"min"`
	Mean      float64 `json:"mean"`
	Max       float64 `json:"max"`
	TokensIn  int     `json:"tokensIn"`
	TokensOut int     `json:"tokensOut"`
	Seconds   float64 `json:"seconds"`
}

// SourceWorkspace is Basis.Source when the numbers come from this workspace's own jobs.
const SourceWorkspace = "workspace"

// minMeasured is how many finished jobs on a model the estimate needs before it trusts them
const minMeasured = 3

// sonnetMeasured is 23 real research-vuln jobs on Sonnet 5.5, from Claude Code's per-session cost
// records (2026-10-19): the estimate on sonnet until this workspace has its own.
var sonnetMeasured = Basis{Model: DefaultModel, Measured: true, Source: "measured 2026-10-19", N: 23,
	Min: 0.18, Mean: 0.23, Max: 0.28, TokensIn: 310_000, TokensOut: 4_700, Seconds: 55}

// Estimate is what a job on model costs, from the jobs given that recorded usage on it.
func Estimate(jobs []Job, model string) Basis {
	b := Basis{Model: model, Source: SourceWorkspace}
	var cost, sec float64
	var in, out int
	for _, j := range jobs {
		u := j.Usage
		if u == nil || j.Model != model {
			continue
		}
		if b.N == 0 || u.CostUSD < b.Min {
			b.Min = u.CostUSD
		}
		b.Max = max(b.Max, u.CostUSD)
		b.N++
		cost += u.CostUSD
		in += u.TokensIn()
		out += u.OutputTokens
		sec += float64(u.DurationMs) / 1000
	}
	switch {
	case b.N >= minMeasured:
		b.Measured = true
		b.Mean, b.TokensIn, b.TokensOut, b.Seconds = cost/float64(b.N), in/b.N, out/b.N, sec/float64(b.N)
	case model == DefaultModel:
		b = sonnetMeasured
	default:
		b = Basis{Model: model, N: b.N}
	}
	return b
}
