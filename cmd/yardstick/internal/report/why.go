package report

import (
	"slices"
	"strings"

	"github.com/anchore/yardstick/cmd/yardstick/internal/lookup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/pairing"
)

// Why is the computed reason the setups disagree about a row only one reported: a key, and for a
// change the reference's value (From) and the candidate's (To). It is computed from the row's two
// sides and the DB lookups, never from labels. Ported from delta's internal/assay/why.go, keys
// and order included, since the map UI and the skills read them.
type Why struct {
	Key       string   `json:"key"`
	From      string   `json:"from,omitempty"`
	To        string   `json:"to,omitempty"`
	Secondary []Reason `json:"secondary,omitempty"`
}

// Reason is one reason that applies to a row.
type Reason struct {
	Key  string `json:"key"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// The reason keys, in the order they are tried: the first that applies is the row's primary
// reason, the rest are secondary. Add keys, never rename them.
const (
	WhyRejectedInCandidate = "record/rejected-in-candidate"
	WhyRejectedInReference = "record/rejected-in-reference"
	WhyAbsentInReference   = "record/absent-in-reference"
	WhyAbsentInCandidate   = "record/absent-in-candidate"
	WhyPackageAbsentInRef  = "package/absent-in-reference"
	WhyPackageAbsentInCand = "package/absent-in-candidate"
	WhyNamespaceChanged    = "namespace/changed"
	WhyFixStateChanged     = "fix-state/changed"
	WhyConstraintChanged   = "constraint/changed"
	WhyDistroNotAffected   = "record/distro-not-affected" // the other DB's record in the package's distro says fixed in 0 (a NAK)
	WhySameButUnmatched    = "record/same-but-unmatched"
	WhyCPEOnly             = "match-type/cpe-only"
	WhyMatcherChanged      = "matcher/changed" // reserved: a one-sided row has no second matcher to compare
	WhyUnexplained         = "unexplained"
)

// WhyKeys are every reason key, in the order they are tried.
var WhyKeys = []string{WhyRejectedInCandidate, WhyRejectedInReference, WhyAbsentInReference, WhyAbsentInCandidate,
	WhyPackageAbsentInRef, WhyPackageAbsentInCand, WhyNamespaceChanged, WhyFixStateChanged, WhyConstraintChanged,
	WhyDistroNotAffected, WhySameButUnmatched, WhyCPEOnly, WhyMatcherChanged, WhyUnexplained}

const (
	rejected = "rejected"
	// noConstraint is how grype reports a match on a record with no version constraint
	noConstraint = "none"
)

// explain sets what the DB lookups say about a row only one setup reported, and its reason.
// lookups are by the setup whose DB was searched; a run made before lookups has none.
func explain(row *Match, m *pairing.Match, lookups map[string]*lookup.File) {
	foundIn, otherDB := pairing.Candidate, pairing.Reference
	if row.InReference {
		foundIn, otherDB = pairing.Reference, pairing.Candidate
	}
	ids := lookup.IDs(m)
	if f := lookups[pairing.Candidate]; f != nil {
		row.CandidateStatus = f.Statuses[m.Vulnerability]
	}
	if f := lookups[pairing.Reference]; f != nil {
		row.ReferenceStatus = f.Statuses[m.Vulnerability]
	}
	absent := notInDB(lookups[otherDB], ids)
	row.NewInCandidate = absent && row.InCandidate
	found := m.Details[foundIn]
	looked := lookups[otherDB].Looked(row.Row)
	dist := lookup.PackageOS(m)
	var records []lookup.Affected
	if looked {
		records = related(lookups[otherDB].Records, found, ids, lookup.Names(m), dist)
		if otherDB == pairing.Candidate {
			row.CandidateRecords = records
		} else {
			row.ReferenceRecords = records
		}
	}

	// from is the reference's value and to the candidate's, whichever setup found the row
	change := func(key, foundValue, otherValue string) Reason {
		if row.InCandidate {
			return Reason{Key: key, From: otherValue, To: foundValue}
		}
		return Reason{Key: key, From: foundValue, To: otherValue}
	}
	lacksAbsent, lacksPackage := WhyAbsentInReference, WhyPackageAbsentInRef
	if row.InReference {
		lacksAbsent, lacksPackage = WhyAbsentInCandidate, WhyPackageAbsentInCand
	}
	var reasons []Reason
	if row.CandidateStatus == rejected {
		reasons = append(reasons, Reason{Key: WhyRejectedInCandidate})
	}
	if row.ReferenceStatus == rejected {
		reasons = append(reasons, Reason{Key: WhyRejectedInReference})
	}
	// an absence carries the finding setup's namespace, so new NVD records and new GHSAs group apart
	namespace := ""
	if found != nil {
		namespace = found.Namespace
	}
	if absent {
		reasons = append(reasons, change(lacksAbsent, namespace, ""))
	}
	if looked && found != nil && !absent {
		reasons = append(reasons, notAffected(compareRecords(found, records, lacksPackage, change), records, dist, change)...)
	}
	if found != nil && found.CPEOnly() {
		reasons = append(reasons, Reason{Key: WhyCPEOnly})
	}
	if len(reasons) == 0 {
		reasons = append(reasons, Reason{Key: WhyUnexplained})
	}
	row.Why = &Why{Key: reasons[0].Key, From: reasons[0].From, To: reasons[0].To}
	if len(reasons) > 1 {
		row.Why.Secondary = reasons[1:]
	}
}

// notInDB is true when a DB's lookups say it has no record of the row under any of its ids; false
// when it was not looked up.
func notInDB(f *lookup.File, ids []string) bool {
	if f == nil {
		return false
	}
	for _, id := range ids {
		if s, ok := f.Statuses[id]; !ok || s != lookup.NotInDB {
			return false
		}
	}
	return true
}

// related are the records a DB search returned that are about the row: one of its ids, its
// package (or CPE product), in its namespace's family or scope, or in its package's distro and
// release.
func related(recs []lookup.Affected, found *pairing.Detail, ids, names []string, dist lookup.OS) []lookup.Affected {
	var products []string
	if found != nil {
		for _, c := range found.CPEs {
			products = appendUnique(products, cpeProduct(c))
		}
	}
	var out []lookup.Affected
	for _, rec := range recs {
		// records for other distros or ecosystems say nothing about this row
		near := found == nil || namespaceFamily(rec.Namespace) == namespaceFamily(found.Namespace) || namespaceScope(rec.Namespace) == namespaceScope(found.Namespace) || dist.Has(rec.Namespace)
		forPackage := slices.Contains(names, rec.Package)
		if rec.CPE != "" {
			forPackage = slices.Contains(products, cpeProduct(rec.CPE))
		}
		if near && slices.Contains(ids, rec.Vulnerability) && forPackage {
			out = append(out, rec)
		}
	}
	return out
}

// compareRecords compares what the finding setup matched with the other DB's records for the row.
func compareRecords(found *pairing.Detail, other []lookup.Affected, packageAbsent string, change func(key, foundValue, otherValue string) Reason) []Reason {
	var same, scope []lookup.Affected
	for _, a := range other {
		switch {
		case a.Namespace == found.Namespace:
			same = append(same, a)
		case namespaceScope(a.Namespace) == namespaceScope(found.Namespace):
			scope = append(scope, a)
		}
	}
	if len(same) == 0 {
		if len(scope) == 0 {
			return []Reason{change(packageAbsent, found.Namespace, "")}
		}
		var ns []string
		for _, a := range scope {
			ns = appendUnique(ns, a.Namespace)
		}
		return []Reason{change(WhyNamespaceChanged, found.Namespace, strings.Join(ns, ", "))}
	}

	var states, constraints []string
	for _, a := range same {
		states = appendUnique(states, a.FixStates...)
		constraints = appendUnique(constraints, a.Constraints...)
	}
	var out []Reason
	// no fix state on either side (most CPE records) is no change
	if !slices.Contains(states, found.FixState) && (found.FixState != "" || len(states) > 0) {
		out = append(out, change(WhyFixStateChanged, found.FixState, joinSorted(states)))
	}
	var matched []string
	for _, c := range found.Constraints {
		// grype joins a record's ranges with "||"; the DB lists them apart
		for _, part := range strings.Split(matchedConstraint(c), "||") {
			if part = strings.TrimSpace(part); part != "" {
				matched = append(matched, part)
			}
		}
	}
	if !sameSet(matched, constraints) {
		out = append(out, change(WhyConstraintChanged, joinSorted(matched), joinSorted(constraints)))
	}
	if len(out) == 0 {
		out = append(out, Reason{Key: WhySameButUnmatched})
	}
	return out
}

// notAffected adds to the reasons from compareRecords the other DB's record in the package's distro
// saying it was never affected, if it has one: after every change to the found record, before the
// same record unmatched.
func notAffected(reasons []Reason, other []lookup.Affected, dist lookup.OS, change func(key, foundValue, otherValue string) Reason) []Reason {
	i := slices.IndexFunc(other, func(a lookup.Affected) bool { return dist.Has(a.Namespace) && a.NotAffected() })
	if i < 0 {
		return reasons
	}
	at := slices.IndexFunc(reasons, func(r Reason) bool { return r.Key == WhySameButUnmatched })
	if at < 0 {
		at = len(reasons)
	}
	return slices.Insert(reasons, at, change(WhyDistroNotAffected, "", other[i].Namespace))
}

// matchedConstraint is a constraint as grype reports a match ("< 1.2-3 (deb)", "none (unknown)") in
// the DB record's terms ("< 1.2-3", or none).
func matchedConstraint(c string) string {
	if i := strings.LastIndex(c, " ("); i >= 0 && strings.HasSuffix(c, ")") {
		c = c[:i]
	}
	if c == noConstraint {
		return ""
	}
	return strings.TrimSpace(c)
}

// namespaceFamily is a distro namespace without its release ("ubuntu:distro:ubuntu" for every
// Ubuntu release); other namespaces are their own family.
func namespaceFamily(ns string) string {
	if i := strings.LastIndex(ns, ":"); i >= 0 && strings.Contains(ns, ":distro:") {
		return ns[:i]
	}
	return ns
}

// namespaceScope is what a namespace covers without its provider ("distro:ubuntu:20.04" for
// "ubuntu:distro:ubuntu:20.04"), so a record moving between providers reads as a namespace change.
func namespaceScope(ns string) string {
	_, rest, _ := strings.Cut(ns, ":")
	return rest
}

// cpeProduct is a CPE's part, vendor and product ("a:minio:minio"): what a CPE search matches on.
func cpeProduct(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return cpe
	}
	return strings.Join(parts[2:5], ":")
}

func joinSorted(vs []string) string {
	vs = slices.Clone(vs)
	slices.Sort(vs)
	return strings.Join(vs, ", ")
}

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Compact(slices.Sorted(slices.Values(a))), slices.Compact(slices.Sorted(slices.Values(b))))
}

func appendUnique(list []string, vs ...string) []string {
	for _, v := range vs {
		if v != "" && !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}
