package v1

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// VocabularyFile is where a corpus keeps its vocabulary, at its root.
const VocabularyFile = "vocabulary.yaml"

// Vocabulary is the corpus's categories, as data in vocabulary.yaml: justification values by
// verdict, fact sources, and which vulnerability id namespaces a label may name. A new value is
// one corpus pull request and no yardstick release.
type Vocabulary struct {
	// Justifications are the values allowed under each verdict, with a one-line description.
	Justifications map[Verdict]map[string]string `yaml:"justifications"`
	FactSources    []string                      `yaml:"fact-sources"`
	// AdvisoryIDs are namespace patterns (path.Match, so ALAS* covers ALAS2 and ALAS2023) of ids
	// that are advisories rather than disclosures. A label may name one: it pairs only a match grype
	// reported under exactly that id, and the id never joins an alias group.
	AdvisoryIDs []string `yaml:"advisory-ids"`
	// Namespaces are the disclosure namespaces a label's vulnerability may use. An id in neither
	// list is refused, so a new vendor prefix fails closed.
	Namespaces []string `yaml:"vulnerability-namespaces"`
	// Rules are the labeling policy's rules, by the name evidence[].rule cites.
	Rules map[string]Rule `yaml:"rules"`
}

// Rule is one row of the labeling policy: what a kind of evidence supports, and how strongly.
type Rule struct {
	Verdict string `yaml:"verdict" json:"verdict"` // tp, fp, unclear, or any
	// Justification is what labels citing the rule carry: RulePerLabel when it depends on the
	// vendor's stated reason, empty when the rule supports either verdict.
	Justification string `yaml:"justification" json:"justification,omitempty"`
	Ceiling       string `yaml:"ceiling" json:"ceiling"` // the strongest confidence a proposal citing it may carry
	Decision      string `yaml:"decision" json:"decision"`
	Basis         string `yaml:"basis" json:"basis"`
	Title         string `yaml:"title" json:"title,omitempty"`
}

const (
	// AnyVerdict is a rule's verdict when it supports either call.
	AnyVerdict = "any"
	// RulePerLabel is a rule's justification when each label citing it states its own.
	RulePerLabel = "*"
)

// confidenceRank orders the confidences a proposal may carry.
var confidenceRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// LoadVocabulary reads vocabulary.yaml from a claims source; nil when it has none.
func LoadVocabulary(fsys fs.FS) (*Vocabulary, error) {
	data, err := fs.ReadFile(fsys, VocabularyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// unknown keys are allowed, so a corpus can add one without breaking an older yardstick
	var v Vocabulary
	if err := yaml.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", VocabularyFile, err)
	}
	return &v, nil
}

// FindVocabulary is the vocabulary labels are written against: the writable source's, else that
// of the first source that has one.
func FindVocabulary(writable fs.FS, sources ...fs.FS) (*Vocabulary, error) {
	for _, fsys := range append([]fs.FS{writable}, sources...) {
		v, err := LoadVocabulary(fsys)
		if err != nil || v != nil {
			return v, err
		}
	}
	return nil, errors.New("no claims source has a " + VocabularyFile + ", so no justification or fact source can be checked")
}

// Namespace is a vulnerability id's namespace: what comes before the first '-'.
func Namespace(id string) string {
	ns, _, _ := strings.Cut(id, "-")
	return ns
}

// IsAdvisory says whether an id is in an advisory-only namespace; with no vocabulary, none is.
func (v *Vocabulary) IsAdvisory(id string) bool {
	if v == nil {
		return false
	}
	ns := Namespace(id)
	for _, p := range v.AdvisoryIDs {
		if ok, _ := path.Match(p, ns); ok {
			return true
		}
	}
	return false
}

// CheckVulnerability refuses an id whose namespace is on neither list.
func (v *Vocabulary) CheckVulnerability(id string) error {
	if !v.IsAdvisory(id) && !slices.Contains(v.Namespaces, Namespace(id)) {
		return fmt.Errorf("vulnerability %s: namespace %q is in neither advisory-ids nor vulnerability-namespaces in %s", id, Namespace(id), VocabularyFile)
	}
	return nil
}

// CheckAliases refuses aliases on a label that is not on an advisory, and an alias that is not a
// disclosure id: an alias is what grype reports the advisory's match under, such as its CVE.
func (v *Vocabulary) CheckAliases(l Label) error {
	if len(l.Aliases) == 0 {
		return nil
	}
	if !v.IsAdvisory(l.Vulnerability) {
		return fmt.Errorf("aliases: only a label on an advisory carries them, and %s is not one", l.Vulnerability)
	}
	for _, a := range l.Aliases {
		if v.IsAdvisory(a) || !slices.Contains(v.Namespaces, Namespace(a)) {
			return fmt.Errorf("alias %s: namespace %q is not in vulnerability-namespaces in %s", a, Namespace(a), VocabularyFile)
		}
	}
	return nil
}

// CheckLabel refuses a label with any of Problems, naming the first.
func (v *Vocabulary) CheckLabel(l Label) error {
	if problems := v.Problems(l, ""); len(problems) > 0 {
		return errors.New(problems[0])
	}
	return nil
}

// Problems is how a call sits with the vocabulary and the policy: a justification not listed under
// its verdict, a fact source not listed at all, a rule not listed or of the other verdict, and,
// for a proposal's confidence (empty for a label, which has none), one above its rule's ceiling.
func (v *Vocabulary) Problems(l Label, confidence string) []string {
	var problems []string
	if l.Justification != "" {
		if _, ok := v.Justifications[l.Verdict][l.Justification]; !ok {
			problems = append(problems, fmt.Sprintf("justification %q is not listed under %s in %s (allowed: %s)", l.Justification, l.Verdict, VocabularyFile, strings.Join(v.Allowed(l.Verdict), ", ")))
		}
	}
	for i, e := range l.Evidence {
		for j, f := range e.Facts {
			if !slices.Contains(v.FactSources, f.Source) {
				problems = append(problems, fmt.Sprintf("evidence[%d].facts[%d].source %q is not listed under fact-sources in %s", i, j, f.Source, VocabularyFile))
			}
		}
		if e.Rule == "" {
			continue
		}
		r, ok := v.Rules[e.Rule]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("evidence[%d]: rule %q is not listed under rules in %s", i, e.Rule, VocabularyFile))
			continue
		case r.Verdict != AnyVerdict && r.Verdict != string(l.Verdict):
			problems = append(problems, fmt.Sprintf("evidence[%d]: rule %s supports %s, not %s", i, e.Rule, r.Verdict, l.Verdict))
		}
		if confidence != "" && confidenceRank[confidence] > confidenceRank[r.Ceiling] {
			problems = append(problems, fmt.Sprintf("%s confidence is above the %s ceiling for %s (%s)", confidence, r.Ceiling, e.Rule, r.Decision))
		}
	}
	return problems
}

// CheckRules is the vocabulary's own consistency, for corpus CI: each rule's verdict and ceiling
// are known values, and its justification is listed under its verdict.
func (v *Vocabulary) CheckRules() []string {
	var problems []string
	for _, name := range slices.Sorted(maps.Keys(v.Rules)) {
		r := v.Rules[name]
		switch {
		case r.Verdict != AnyVerdict && !slices.Contains(Verdicts(), Verdict(r.Verdict)):
			problems = append(problems, fmt.Sprintf("rule %s: verdict %q is not tp, fp, unclear or any", name, r.Verdict))
		case confidenceRank[r.Ceiling] == 0:
			problems = append(problems, fmt.Sprintf("rule %s: ceiling %q is not low, medium or high", name, r.Ceiling))
		case r.Justification == "" || r.Justification == RulePerLabel:
		case r.Verdict == AnyVerdict:
			problems = append(problems, fmt.Sprintf("rule %s supports either verdict, so its justification must be empty or %q", name, RulePerLabel))
		default:
			if _, ok := v.Justifications[Verdict(r.Verdict)][r.Justification]; !ok {
				problems = append(problems, fmt.Sprintf("rule %s: justification %q is not listed under %s", name, r.Justification, r.Verdict))
			}
		}
	}
	return problems
}

// Allowed lists the justifications of a verdict, sorted.
func (v *Vocabulary) Allowed(verdict Verdict) []string {
	out := make([]string, 0, len(v.Justifications[verdict]))
	for j := range v.Justifications[verdict] {
		out = append(out, j)
	}
	sort.Strings(out)
	return out
}
