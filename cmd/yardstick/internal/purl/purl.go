// Package purl compares the fields of package URLs the way a label pairs a package: a field a
// label's purl does not state matches anything, and the version is the one grype reports.
package purl

import (
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
)

// Fields are the fields of a purl, as pairing compares them. An empty field is one the purl does
// not state, and matches anything.
type Fields struct {
	Type, Namespace, Name, Version string
	Qualifiers                     map[string]string
}

// Label reads the fields a label's package purl states.
func Label(s string) (Fields, error) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return Fields{}, err
	}
	return fields(p), nil
}

// Package is a package's fields, from its purl. A package with no purl has only its version.
func Package(s, version string) Fields {
	p, err := packageurl.FromString(s)
	if err != nil {
		return Fields{Version: version}
	}
	f := fields(p)
	if f.Version == "" {
		f.Version = version
	}
	return f
}

// fields reads a purl's fields. An epoch the purl states as a qualifier is put in front of its
// version, on a label and a package alike, so a label that leaves the epoch out does not pair a
// package that has one.
func fields(p packageurl.PackageURL) Fields {
	f := Fields{Type: p.Type, Namespace: p.Namespace, Name: p.Name, Version: p.Version, Qualifiers: p.Qualifiers.Map()}
	if e := f.Qualifiers["epoch"]; e != "" && f.Version != "" && !strings.Contains(f.Version, ":") {
		f.Version = e + ":" + f.Version
	}
	return f
}

// Matches says whether every field f states equals the package's.
func (f Fields) Matches(pkg Fields) bool {
	if !eq(f.Type, pkg.Type) || !eq(f.Namespace, pkg.Namespace) || !eq(f.Name, pkg.Name) || !eq(f.Version, pkg.Version) {
		return false
	}
	for k, v := range f.Qualifiers {
		if pkg.Qualifiers[k] != v {
			return false
		}
	}
	return true
}

func eq(stated, got string) bool {
	return stated == "" || stated == got
}

// Stated names the fields f states, in a fixed order: type, namespace, name, version, then each
// qualifier as qualifier:<key>.
func (f Fields) Stated() []string {
	var out []string
	for _, kv := range [][2]string{{"type", f.Type}, {"namespace", f.Namespace}, {"name", f.Name}, {"version", f.Version}} {
		if kv[1] != "" {
			out = append(out, kv[0])
		}
	}
	keys := make([]string, 0, len(f.Qualifiers))
	for k := range f.Qualifiers {
		keys = append(keys, "qualifier:"+k)
	}
	sort.Strings(keys)
	return append(out, keys...)
}

// Without is f with one stated field dropped, by its name in Stated.
func (f Fields) Without(field string) Fields {
	out := f
	out.Qualifiers = map[string]string{}
	for k, v := range f.Qualifiers {
		if "qualifier:"+k != field {
			out.Qualifiers[k] = v
		}
	}
	switch field {
	case "type":
		out.Type = ""
	case "namespace":
		out.Namespace = ""
	case "name":
		out.Name = ""
	case "version":
		out.Version = ""
	}
	return out
}
