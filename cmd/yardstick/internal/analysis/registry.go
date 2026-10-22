// Package analysis holds the check registry and evaluates a gate's checks over paired matches
// and labels, per subject for the F1 family and summed across the gate for expectations.
package analysis

import (
	"sort"

	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
)

// Check names, as a gate file lists them.
const (
	F1NotWorse             = "f1NotWorse"
	NoNewFalseNegatives    = "noNewFalseNegatives"
	NoNewFalsePositives    = "noNewFalsePositives"
	UnjudgedChangesAtMost  = "unjudgedChangesAtMost"
	UnlabeledPercentAtMost = "unlabeledPercentAtMost"
	ExpectationsMetAtLeast = "expectationsMetAtLeast"
	NoNewMisses            = "noNewMisses"
	MatchesAtLeast         = "matchesAtLeast"
)

// Scope is what a check is evaluated over.
type Scope string

const (
	PerSubject Scope = "subject" // each subject alone; the gate takes the worst
	PerGate    Scope = "gate"    // summed across every subject
)

// CheckType is one entry of the registry: what a CLI or a labeling surface needs to show a check
// without a list of its own.
type CheckType struct {
	gatefile.CheckDef
	Description string
	Scope       Scope
}

const (
	paramMax       = "max"
	paramMin       = "min"
	paramTolerance = "tolerance"
)

func zero() *float64         { v := 0.0; return &v }
func ptr(v float64) *float64 { return &v }

// Registry is every check a gate can list.
var Registry = map[string]CheckType{
	F1NotWorse: {
		CheckDef: gatefile.CheckDef{Name: F1NotWorse, ReadsReference: true, Params: []gatefile.Param{
			{Name: paramTolerance, Description: "how far below the reference's F1 the candidate's may be", Min: 0, Default: zero()},
		}},
		Description: "fails when the candidate's F1 is lower than the reference's by more than tolerance",
		Scope:       PerSubject,
	},
	NoNewFalseNegatives: {
		CheckDef: gatefile.CheckDef{Name: NoNewFalseNegatives, ReadsReference: true, Params: []gatefile.Param{
			{Name: paramMax, Description: "how many tp labels the reference satisfied may go unsatisfied", Integer: true, Default: zero()},
		}},
		Description: "fails when more than max tp labels the reference satisfied are unsatisfied in the candidate",
		Scope:       PerSubject,
	},
	NoNewFalsePositives: {
		CheckDef: gatefile.CheckDef{Name: NoNewFalsePositives, ReadsReference: true, Params: []gatefile.Param{
			{Name: paramMax, Description: "how many new matches an fp label pairs are allowed", Integer: true, Default: zero()},
		}},
		Description: "fails when more than max candidate matches paired by an fp label were not reported by the reference",
		Scope:       PerSubject,
	},
	UnjudgedChangesAtMost: {
		CheckDef: gatefile.CheckDef{Name: UnjudgedChangesAtMost, ReadsReference: true, Params: []gatefile.Param{
			{Name: paramMax, Description: "how many matches only one setup reports may stay unlabeled", Integer: true},
		}},
		Description: "fails when more than max unlabeled matches appear in only one setup; labeling them lowers the count",
		Scope:       PerSubject,
	},
	UnlabeledPercentAtMost: {
		CheckDef: gatefile.CheckDef{Name: UnlabeledPercentAtMost, Params: []gatefile.Param{
			{Name: paramMax, Description: "the percent of the candidate's matches that may be unlabeled", Max: ptr(100)},
		}},
		Description: "fails when more than max percent of the candidate's matches are unlabeled",
		Scope:       PerSubject,
	},
	ExpectationsMetAtLeast: {
		CheckDef: gatefile.CheckDef{Name: ExpectationsMetAtLeast, Params: []gatefile.Param{
			{Name: paramMin, Description: "how many expectations must be met: a count when at least 1, a fraction of all of them when below 1"},
		}},
		Description: "fails when fewer expectations are met than min",
		Scope:       PerGate,
	},
	MatchesAtLeast: {
		CheckDef: gatefile.CheckDef{Name: MatchesAtLeast, Params: []gatefile.Param{
			{Name: paramMin, Description: "how many matches the candidate and the reference must report between them on each subject", Integer: true},
		}},
		Description: "fails when the candidate and the reference together report fewer than min matches on a subject, after the gate's vulnerabilities filter",
		Scope:       PerSubject,
	},
	NoNewMisses: {
		CheckDef: gatefile.CheckDef{Name: NoNewMisses, ReadsReference: true, Params: []gatefile.Param{
			{Name: paramMax, Description: "how many expectations the reference met the candidate may miss", Integer: true, Default: zero()},
		}},
		Description: "fails when more than max expectations met by the reference are not met by the candidate",
		Scope:       PerGate,
	},
}

// Definitions is the registry as gate loading reads it.
func Definitions() map[string]gatefile.CheckDef {
	out := make(map[string]gatefile.CheckDef, len(Registry))
	for n, t := range Registry {
		out[n] = t.CheckDef
	}
	return out
}

// Names lists the registry's checks, sorted.
func Names() []string {
	names := make([]string, 0, len(Registry))
	for n := range Registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
