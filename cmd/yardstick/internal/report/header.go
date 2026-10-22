package report

import (
	"sort"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// Header is what a gate's run compared and read, stated before any verdict.
type Header struct {
	Scanned string `json:"scanned"`
	// OneSetup is set for a gate with no reference: one setup was scanned and nothing varied.
	OneSetup bool `json:"oneSetup,omitempty"`
	// Setups describe each setup's inputs as resolved.
	Setups map[string]Inputs `json:"setups"`
	// Varied are the inputs that differ between the setups; Held are the ones that do not.
	Varied []Varied `json:"varied,omitempty"`
	Held   []string `json:"held,omitempty"`
	// Attribution says what can be concluded from what varied.
	Attribution string `json:"attribution,omitempty"`
	// Claims are the sources scored against, each with the snapshot read.
	Claims []Source `json:"claims"`
	// Built are subjects whose SBOM this gate's scan built, with the syft that built it.
	Built []Built `json:"built,omitempty"`
	// Bypassed says the claims sources' SBOMs were skipped (--rebuild-sboms).
	Bypassed bool     `json:"bypassed,omitempty"`
	Frozen   []string `json:"frozen,omitempty"`
	// InheritedEnv names the GRYPE_* and SYFT_* variables passed on from the environment.
	InheritedEnv []string `json:"inheritedEnv,omitempty"`
}

// Inputs are what one setup resolved to, as the header compares them.
type Inputs struct {
	Grype  string `json:"grype"`
	DB     string `json:"db"`
	Config string `json:"config"`
	Env    string `json:"env"`
}

// Varied is one input that differs between the setups.
type Varied struct {
	Input     string `json:"input"`
	Candidate string `json:"candidate"`
	Reference string `json:"reference"`
}

// Source is a claims source and the snapshot a gate was scored against.
type Source struct {
	Locator  string `json:"locator"`
	Snapshot string `json:"snapshot"`
	Commit   string `json:"commit,omitempty"`
}

// Built is a subject whose SBOM was built rather than read.
type Built struct {
	Subject string `json:"subject"`
	Syft    string `json:"syft"`
}

// Attribution statements.
const (
	NothingVaried   = "nothing varied between the setups"
	NotAttributable = "more than one input varied, so no delta can be attributed to one of them"
)

// NewHeader states what the scans resolved to and the claims snapshots a gate is scored against.
func NewHeader(rec *runrecord.Record, sources []*claims.Source) Header {
	h := Header{Scanned: rec.Created, Setups: map[string]Inputs{}, Bypassed: rec.RebuildSBOMs, InheritedEnv: rec.InheritedEnv}
	for name, p := range rec.Setups {
		h.Setups[name] = inputs(p)
	}
	cand, okC := h.Setups["candidate"]
	ref, okR := h.Setups["reference"]
	switch {
	case okC && !okR:
		h.OneSetup = true
	case okC && okR:
		for _, in := range []struct{ name, c, r string }{
			{"grype", cand.Grype, ref.Grype}, {"DB", cand.DB, ref.DB}, {"config", cand.Config, ref.Config}, {"env", cand.Env, ref.Env},
		} {
			if in.c == in.r {
				h.Held = append(h.Held, in.name)
			} else {
				h.Varied = append(h.Varied, Varied{Input: in.name, Candidate: in.c, Reference: in.r})
			}
		}
		switch len(h.Varied) {
		case 0:
			h.Attribution = NothingVaried
		case 1:
		default:
			h.Attribution = NotAttributable
		}
	}
	for _, s := range sources {
		h.Claims = append(h.Claims, Source{Locator: s.Locator, Snapshot: s.Snapshot(), Commit: s.Commit})
	}
	for _, s := range rec.Subjects {
		if s.From == subject.FromBuilt {
			h.Built = append(h.Built, Built{Subject: s.Name, Syft: s.Syft})
		}
		if s.Frozen {
			h.Frozen = append(h.Frozen, s.Name)
		}
	}
	return h
}

func inputs(p setup.Prepared) Inputs {
	in := Inputs{Grype: p.Grype.Spec.String(), DB: p.DB.Checksum, Config: "none", Env: "none"}
	if p.Grype.Spec.Path != "" {
		in.Grype += " (sha256:" + p.Grype.SHA256 + ")"
	}
	if in.DB == "" {
		in.DB = p.DB.Source
	}
	if p.Config != nil {
		in.Config = p.Config.Path + " (sha256:" + p.Config.SHA256 + ")"
	}
	if len(p.Env) > 0 {
		var kv []string
		for k, v := range execute.MaskEnv(p.Env) {
			kv = append(kv, k+"="+v)
		}
		sort.Strings(kv)
		in.Env = strings.Join(kv, " ")
	}
	return in
}
