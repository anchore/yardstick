package v1

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
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
// merged (MergeVocabularies), an error when none has one or each is a fragment (CheckWritable).
func FindVocabulary(sources ...NamedFS) (*Vocabulary, error) {
	v, err := MergeVocabularies(sources...)
	if err == nil {
		err = v.CheckWritable()
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Fragment says the vocabulary lists no justifications, as one holding only a namespace doesn't:
// it adds to another claims source's vocabulary.yaml, and is only whole merged onto one.
func (v *Vocabulary) Fragment() bool {
	return len(v.Justifications) == 0
}

// CheckWritable says why labels can't be checked against a merged vocabulary: no claims source
// has a vocabulary.yaml (v is nil), or each one there is a fragment.
func (v *Vocabulary) CheckWritable() error {
	const none = "no claims source has a " + VocabularyFile + ", so no justification or fact source can be checked"
	switch {
	case v == nil:
		return errors.New(none)
	case v.Fragment():
		return errors.New(none + "; the ones there list no justifications, so they only add to a full " + VocabularyFile +
			" from another source, such as github.com/anchore/claims@main")
	}
	return nil
}

// MergeVocabularies merges the vocabulary.yaml of each source that has one, in order; nil when none
// has one. A source adds to the lists and to the justifications and rules, so a provider's own
// claims can list its namespace before the published corpus does: a vocabulary.yaml holding only
// that is a fragment, meant to be merged onto a source with the rest. Where two sources word a
// justification or a rule differently, the later one's words win, with a warning, so a checkout a
// commit behind the published corpus still opens. A rule two sources give a different verdict,
// justification or ceiling is an error naming both, as is a namespace listed as both kinds.
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
			had, ok := v.Justifications[verdict][j]
			if ok && had == desc {
				continue
			}
			if ok {
				log.Warnf("justification %q under %s is %q in %s and %q in %s; using %s's", j, verdict, had, from[key], desc, source, source)
			}
			v.Justifications[verdict][j], from[key] = desc, source
		}
	}
	for _, name := range slices.Sorted(maps.Keys(o.Rules)) {
		r, key := o.Rules[name], "rule "+name
		had, ok := v.Rules[name]
		if ok && had == r {
			continue
		}
		// what a rule allows a call citing it must agree; only its prose may differ
		if ok && (had.Verdict != r.Verdict || had.Justification != r.Justification || had.Ceiling != r.Ceiling) {
			return fmt.Errorf("rule %q has verdict %s, justification %q and ceiling %s in %s but %s, %q and %s in %s, each in its %s",
				name, had.Verdict, had.Justification, had.Ceiling, from[key], r.Verdict, r.Justification, r.Ceiling, source, VocabularyFile)
		}
		if ok {
			log.Warnf("rule %q is worded differently in %s and %s; using %s's", name, from[key], source, source)
		}
		v.Rules[name], from[key] = r, source
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

// CheckVulnerability refuses an id whose namespace is on neither list, naming both and file, the
// vocabulary.yaml to add it in. CheckScanned says which list, when a scan is at hand.
func (v *Vocabulary) CheckVulnerability(id, file string) error {
	return v.CheckScanned(id, file, nil)
}

// The two lists a namespace may be on.
const (
	ListDisclosure = "vulnerability-namespaces"
	ListAdvisory   = "advisory-ids"
)

// Unlisted is the refusal of an id whose namespace is on neither list, with which list a scan's ids
// in the namespace suggest: an id naming at most one vulnerability is a disclosure, one naming
// several is an advisory.
type Unlisted struct {
	ID, Namespace string
	// File is the vocabulary.yaml to add the namespace in; empty when the caller can't say which
	// claims source's it is.
	File string
	// Suggest is ListDisclosure or ListAdvisory, empty when the scan had no id in the namespace.
	Suggest string
	// Checked counts the scan's ids in the namespace, Several those naming more than one
	// vulnerability and Unnamed those naming none.
	Checked, Several, Unnamed int
	// Example is one id that shows the suggestion, and Names the vulnerabilities it names.
	Example string
	Names   []string
}

func (u *Unlisted) Error() string {
	file := cmp.Or(u.File, "a claims source's "+VocabularyFile)
	head := fmt.Sprintf("vulnerability %s: namespace %q is not in any claims source's %s", u.ID, u.Namespace, VocabularyFile)
	if u.Suggest == "" {
		return fmt.Sprintf("%s; add it to %s in %s if each of its ids names one vulnerability, "+
			"or to %s if an id can name several (as an ELSA names several CVEs)", head, ListDisclosure, file, ListAdvisory)
	}
	count := fmt.Sprintf("This gate's scan has %d %s id", u.Checked, u.Namespace)
	if u.Checked > 1 {
		count += "s"
	}
	example := u.Example + " names none"
	if len(u.Names) > 0 {
		example = u.Example + " → " + strings.Join(u.Names, ", ")
	}
	if u.Suggest == ListAdvisory {
		verb := "name"
		if u.Several == 1 {
			verb = "names"
		}
		return fmt.Sprintf("%s. %s; %d %s several vulnerabilities (e.g. %s), so add it to %s in %s. "+
			"(An id naming exactly one vulnerability would belong in %s.)", head, count, u.Several, verb, example, ListAdvisory, file, ListDisclosure)
	}
	each := "each names exactly 1 vulnerability"
	if u.Unnamed > 0 {
		each = "none names more than 1 vulnerability"
	}
	return fmt.Sprintf("%s. %s; %s (e.g. %s), so add it to %s in %s. "+
		"(An id naming several CVEs would belong in %s.)", head, count, each, example, ListDisclosure, file, ListAdvisory)
}

// CheckScanned is CheckVulnerability, refusing with an *Unlisted that judges which list the
// namespace belongs on from a scan's ids in it. related is each id the scan reported, with the ids
// reported beside it; file is the vocabulary.yaml to add the namespace in (Unlisted.File).
func (v *Vocabulary) CheckScanned(id, file string, related map[string][]string) error {
	ns := Namespace(id)
	if v.IsAdvisory(id) || slices.Contains(v.Namespaces, ns) {
		return nil
	}
	u := &Unlisted{ID: id, Namespace: ns, File: file}
	var one, several []string
	for _, x := range slices.Sorted(maps.Keys(related)) {
		if Namespace(x) != ns {
			continue
		}
		u.Checked++
		switch n := len(names(x, related[x])); {
		case n > 1:
			several = append(several, x)
		case n == 1:
			one = append(one, x)
		default:
			u.Unnamed++
		}
		if u.Example == "" {
			u.Example = x
		}
	}
	u.Several = len(several)
	switch {
	case u.Checked == 0:
	case len(several) > 0:
		u.Suggest, u.Example = ListAdvisory, several[0]
	default:
		u.Suggest = ListDisclosure
		if len(one) > 0 {
			u.Example = one[0]
		}
	}
	if u.Example != "" {
		u.Names = names(u.Example, related[u.Example])
	}
	return u
}

// CheckAdd says whether adding a namespace to a list keeps the vocabulary sound: already when it
// is on that list, an error when it would be listed as both kinds.
func (v *Vocabulary) CheckAdd(ns, list string) (already bool, err error) {
	switch list {
	case ListDisclosure:
		if slices.Contains(v.Namespaces, ns) {
			return true, nil
		}
		for _, p := range v.AdvisoryIDs {
			if ok, _ := path.Match(p, ns); ok {
				return false, fmt.Errorf("namespace %q can't be added to %s: %s %q already covers it", ns, ListDisclosure, ListAdvisory, p)
			}
		}
	case ListAdvisory:
		if slices.Contains(v.AdvisoryIDs, ns) {
			return true, nil
		}
		if slices.Contains(v.Namespaces, ns) {
			return false, fmt.Errorf("namespace %q can't be added to %s: it is in %s", ns, ListAdvisory, ListDisclosure)
		}
	default:
		return false, fmt.Errorf("list must be %s or %s, got %q", ListDisclosure, ListAdvisory, list)
	}
	return false, nil
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

// AddToList is a vocabulary.yaml with a namespace appended to one of its lists, the list added when
// the file has none; data may be empty, for a file not yet written. The namespace is spliced into
// the file's text after the list's last item, and a missing list goes at the end, so every other
// byte stays as it was; a file laid out otherwise (an empty list key, an inline mapping) is edited
// as a YAML tree, which keeps comments, key order and styles but may drop blank lines.
func AddToList(data []byte, ns, list string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", VocabularyFile, err)
	}
	// no file, only comments (which yaml.v3 doesn't keep for a document with no node), or an empty
	// document ("---", which loading reads as an empty vocabulary): the list goes after the text
	if doc.Kind == 0 || doc.Content[0].Kind == yaml.ScalarNode && doc.Content[0].Tag == "!!null" {
		return appendList(data, ns, list)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s is not a mapping", VocabularyFile)
	}
	var seq *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == list {
			seq = root.Content[i+1]
		}
	}
	switch {
	case seq == nil && root.Style&yaml.FlowStyle == 0:
		return appendList(data, ns, list)
	case seq == nil:
		root.Content = append(root.Content, str(list), flowList(ns))
	case seq.Kind == yaml.SequenceNode:
		if slices.ContainsFunc(seq.Content, func(n *yaml.Node) bool { return n.Value == ns }) {
			return data, nil
		}
		if out, ok := splice(data, seq, ns); ok && listIs(out, list, seq, ns) {
			return out, nil
		}
		seq.Content = append(seq.Content, str(ns))
	case seq.Tag == "!!null":
		*seq = *flowList(ns)
	default:
		return nil, fmt.Errorf("%s in %s is not a list", list, VocabularyFile)
	}
	return encode(&doc)
}

// appendList is data with a list holding ns after it.
func appendList(data []byte, ns, list string) ([]byte, error) {
	text, err := encode(&yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{str(list), flowList(ns)}})
	if err != nil {
		return nil, err
	}
	out := slices.Clone(data)
	if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, '\n')
	}
	return append(out, text...), nil
}

// splice is data with ns written after seq's last item, in seq's style: ", ns" inline, or a line
// of its own indented as the item above it. ok is false when the text isn't where the nodes say.
func splice(data []byte, seq *yaml.Node, ns string) (out []byte, ok bool) {
	item, err := encode(str(ns))
	if err != nil {
		return nil, false
	}
	item = bytes.TrimSuffix(item, []byte("\n"))
	lines := bytes.SplitAfter(data, []byte("\n"))
	// at is the byte offset of a node, whose line and column yaml.v3 counts from 1, in runes
	at := func(n *yaml.Node) int {
		if n.Line < 1 || n.Line > len(lines) || n.Column < 1 {
			return -1
		}
		off := 0
		for _, l := range lines[:n.Line-1] {
			off += len(l)
		}
		line := []rune(string(lines[n.Line-1]))
		if n.Column > len(line) {
			return -1
		}
		return off + len(string(line[:n.Column-1]))
	}
	insert := func(i int, parts ...[]byte) []byte {
		return slices.Concat(data[:i], bytes.Join(parts, nil), data[i:])
	}
	if seq.Style&yaml.FlowStyle != 0 {
		if len(seq.Content) == 0 {
			i := at(seq)
			return insert(i+1, item), i >= 0 && data[i] == '['
		}
		last := seq.Content[len(seq.Content)-1]
		i := at(last)
		if i < 0 {
			return nil, false
		}
		// a plain item is its value as written; a quoted one is checked again by the caller
		end := i + len(last.Value)
		if last.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 {
			end += 2
		}
		if end > len(data) {
			return nil, false
		}
		return insert(end, []byte(", "), item), true
	}
	last := seq.Content[len(seq.Content)-1]
	i := at(last)
	if i < 0 {
		return nil, false
	}
	// the item's line up to it, such as "  - ", is the new line's too
	start := bytes.LastIndexByte(data[:i], '\n') + 1
	prefix := data[start:i]
	if len(bytes.TrimSpace(prefix)) != 1 || bytes.TrimSpace(prefix)[0] != '-' {
		return nil, false
	}
	end := bytes.IndexByte(data[i:], '\n')
	if end < 0 {
		return insert(len(data), []byte("\n"), prefix, item, []byte("\n")), true
	}
	return insert(i+end+1, prefix, item, []byte("\n")), true
}

// listIs says whether data's list is seq's items and then ns, as splice meant it to be.
func listIs(data []byte, list string, seq *yaml.Node, ns string) bool {
	var m map[string]yaml.Node
	var got []string
	if yaml.Unmarshal(data, &m) != nil {
		return false
	}
	n := m[list]
	if n.Decode(&got) != nil {
		return false
	}
	want := make([]string, 0, len(seq.Content)+1)
	for _, c := range seq.Content {
		want = append(want, c.Value)
	}
	return slices.Equal(got, append(want, ns))
}

// str is a string node; flowList a one-item list written inline, [ns].
func str(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

func flowList(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle, Content: []*yaml.Node{str(v)}}
}

// encode is a YAML tree as vocabulary.yaml is written, indented by 2.
func encode(n *yaml.Node) ([]byte, error) {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	return out.Bytes(), enc.Close()
}
