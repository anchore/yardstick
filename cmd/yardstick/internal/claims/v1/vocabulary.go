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

// NamedFS is a claims source's files, and the name a vocabulary merge error gives it.
type NamedFS struct {
	Name string
	FS   fs.FS
}

// FindVocabulary is the vocabulary labels are written against: every source's vocabulary.yaml
// merged (MergeVocabularies), an error when none has one.
func FindVocabulary(sources ...NamedFS) (*Vocabulary, error) {
	v, err := MergeVocabularies(sources...)
	if err == nil && v == nil {
		err = errors.New("no claims source has a " + VocabularyFile + ", so no justification or fact source can be checked")
	}
	return v, err
}

// MergeVocabularies merges the vocabulary.yaml of each source that has one, in order; nil when none
// has one. A source adds to the lists and to the justifications and rules, so a provider's own
// claims can list its namespace before the published corpus does. A justification or rule two
// sources define differently is an error naming both, as is a namespace listed as both kinds.
func MergeVocabularies(sources ...NamedFS) (*Vocabulary, error) {
	var out *Vocabulary
	// from is the source that first listed each list entry or map key, for the errors
	from := map[string]string{}
	for _, s := range sources {
		v, err := LoadVocabulary(s.FS)
		if err != nil {
			return nil, fmt.Errorf("claims source %s: %w", s.Name, err)
		}
		if v == nil {
			continue
		}
		if out == nil {
			out = &Vocabulary{Justifications: map[Verdict]map[string]string{}, Rules: map[string]Rule{}}
		}
		if err := out.merge(s.Name, v, from); err != nil {
			return nil, err
		}
	}
	if out == nil {
		return nil, nil
	}
	// a disclosure namespace an advisory pattern covers would pair as both kinds
	for _, ns := range out.Namespaces {
		for _, p := range out.AdvisoryIDs {
			if ok, _ := path.Match(p, ns); ok {
				return nil, fmt.Errorf("namespace %q is in vulnerability-namespaces (%s) and matches advisory-ids %q (%s) in %s; list it as one kind",
					ns, from["namespace "+ns], p, from["advisory "+p], VocabularyFile)
			}
		}
	}
	return out, nil
}

// merge adds o, from the named source, to v.
func (v *Vocabulary) merge(source string, o *Vocabulary, from map[string]string) error {
	union := func(list []string, add []string, kind string) []string {
		for _, x := range add {
			if !slices.Contains(list, x) {
				list = append(list, x)
				from[kind+" "+x] = source
			}
		}
		return list
	}
	v.FactSources = union(v.FactSources, o.FactSources, "fact-source")
	v.AdvisoryIDs = union(v.AdvisoryIDs, o.AdvisoryIDs, "advisory")
	v.Namespaces = union(v.Namespaces, o.Namespaces, "namespace")
	for _, verdict := range slices.Sorted(maps.Keys(o.Justifications)) {
		if v.Justifications[verdict] == nil {
			v.Justifications[verdict] = map[string]string{}
		}
		for _, j := range slices.Sorted(maps.Keys(o.Justifications[verdict])) {
			desc, key := o.Justifications[verdict][j], fmt.Sprintf("justification %s/%s", verdict, j)
			if had, ok := v.Justifications[verdict][j]; ok && had != desc {
				return fmt.Errorf("justification %q under %s is %q in %s and %q in %s, each in its %s", j, verdict, had, from[key], desc, source, VocabularyFile)
			}
			if _, ok := v.Justifications[verdict][j]; !ok {
				v.Justifications[verdict][j], from[key] = desc, source
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(o.Rules)) {
		r, key := o.Rules[name], "rule "+name
		if had, ok := v.Rules[name]; ok && had != r {
			return fmt.Errorf("rule %q is defined differently in %s and %s, each in its %s", name, from[key], source, VocabularyFile)
		}
		if _, ok := v.Rules[name]; !ok {
			v.Rules[name], from[key] = r, source
		}
	}
	return nil
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

// CheckVulnerability refuses an id whose namespace is on neither list, naming both and the file to
// add it in. CheckScanned says which list, when a scan is at hand.
func (v *Vocabulary) CheckVulnerability(id string) error {
	return v.CheckScanned(id, "", nil)
}

// CheckScanned is CheckVulnerability, its refusal judging which list the namespace belongs on from a
// scan's ids in it: an id naming at most one vulnerability is a disclosure, one naming several is
// an advisory. related is each id the scan reported, with the ids reported beside it; file is the
// vocabulary.yaml to add the namespace in, empty for an additional-claims one.
func (v *Vocabulary) CheckScanned(id, file string, related map[string][]string) error {
	ns := Namespace(id)
	if v.IsAdvisory(id) || slices.Contains(v.Namespaces, ns) {
		return nil
	}
	if file == "" {
		file = "an additional-claims " + VocabularyFile
	}
	head := fmt.Sprintf("vulnerability %s: namespace %q is not in any claims source's %s", id, ns, VocabularyFile)
	var ids, several []string
	for _, x := range slices.Sorted(maps.Keys(related)) {
		if Namespace(x) == ns {
			ids = append(ids, x)
			if len(names(x, related[x])) > 1 {
				several = append(several, x)
			}
		}
	}
	if len(ids) == 0 {
		return fmt.Errorf("%s; add it to vulnerability-namespaces in %s if each of its ids names one vulnerability, "+
			"or to advisory-ids if an id can name several (as an ELSA names several CVEs)", head, file)
	}
	example := func(x string) string {
		if n := names(x, related[x]); len(n) > 0 {
			return x + " → " + strings.Join(n, ", ")
		}
		return x + " names none"
	}
	count := fmt.Sprintf("This gate's scan has %d %s id", len(ids), ns)
	if len(ids) > 1 {
		count += "s"
	}
	if len(several) > 0 {
		verb := "name"
		if len(several) == 1 {
			verb = "names"
		}
		return fmt.Errorf("%s. %s; %d %s several vulnerabilities (e.g. %s), so add it to advisory-ids in %s. "+
			"(An id naming exactly one vulnerability would belong in vulnerability-namespaces.)", head, count, len(several), verb, example(several[0]), file)
	}
	each, ex := "none names more than 1 vulnerability", ids[0]
	if !slices.ContainsFunc(ids, func(x string) bool { return len(names(x, related[x])) == 0 }) {
		each = "each names exactly 1 vulnerability"
	}
	if i := slices.IndexFunc(ids, func(x string) bool { return len(names(x, related[x])) == 1 }); i >= 0 {
		ex = ids[i]
	}
	return fmt.Errorf("%s. %s; %s (e.g. %s), so add it to vulnerability-namespaces in %s. "+
		"(An id naming several CVEs would belong in advisory-ids.)", head, count, each, example(ex), file)
}

// names is the distinct vulnerabilities an id's related ids name. Ids in its own namespace are its
// siblings (CleanStart's related advisories), not names. Its CVEs count when it has any: a GHSA
// or other id beside a CVE is most often that CVE's alias, and a scan's related ids don't say
// which pair up, so counting them too would call a CVE and its GHSA two vulnerabilities. With no
// CVE, its ids in other namespaces count.
func names(id string, related []string) []string {
	var cves, other []string
	for _, r := range related {
		switch ns := Namespace(r); {
		case ns == Namespace(id) || slices.Contains(cves, r) || slices.Contains(other, r):
		case ns == "CVE":
			cves = append(cves, r)
		default:
			other = append(other, r)
		}
	}
	if len(cves) > 0 {
		return cves
	}
	return other
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
