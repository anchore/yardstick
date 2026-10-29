package research

import (
	"path/filepath"
	"testing"
)

// a job's output directory is the one the plugin's yardstick-vuln-sources.py writes: safe_part of
// the vulnerability, then of parse_purl's name (yardstick_common.py). Each want is what the plugin
// gives for the purl.
func TestOutputDirMatchesThePlugin(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:apk/cleanstart/binutils@2.45.1-r0?arch=x86_64&distro=cleanstart-3.20.3", "binutils"},
		{"pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12", "libc6"},
		// a scoped npm package: the scope is the namespace, decoded or not
		{"pkg:npm/%40babel/traverse@7.22.0", "traverse"},
		{"pkg:npm/%40scope%2Fodd/name@1", "name"},
		{"pkg:npm/lodash@4.17.21", "lodash"},
		// maven's group is the namespace, qualifiers or not
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j-core"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", "log4j-core"},
		// a Go module keeps its path past the first segment, a subpath dropped
		{"pkg:golang/github.com/gin-gonic/gin@v1.9.0", "gin-gonic_gin"},
		{"pkg:golang/golang.org/x/net@v0.17.0#http2", "x_net"},
		{"pkg:golang/stdlib@go1.21.0", "stdlib"},
		// with no namespace, a subpath with a '/' is read as the namespace's end, as the plugin's regexp does
		{"pkg:generic/openssl@3.0.2#crypto/evp", "evp"},
		{"pkg:github/actions/checkout@v4", "checkout"},
		{"pkg:pypi/Django@4.2", "Django"},
		{"pkg:nuget/Newtonsoft.Json", "Newtonsoft.Json"},
		// a decoded character outside [A-Za-z0-9._+-] is "_", one per character
		{"pkg:cargo/r%C3%A9sum%C3%A9@1", "r_sum_"},
		{"not-a-purl", "not-a-purl"},
		{"", "all"},
	} {
		got := OutputDir(Job{Vulnerability: "CVE-2025-11082", Package: tc.purl})
		if want := filepath.Join(".yardstick", "research", "CVE-2025-11082", tc.want); got != want {
			t.Errorf("%q: got %s, want %s", tc.purl, got, want)
		}
	}
	// the plugin refuses a name of only '.' or '..', and so writes nowhere
	for _, j := range []Job{{Vulnerability: "..", Package: "pkg:npm/a@1"}, {Vulnerability: "CVE-1", Package: "pkg:npm/..@1"}} {
		if got := OutputDir(j); got != "" {
			t.Errorf("%+v: expected no directory, got %s", j, got)
		}
	}
}

// %XX decodes as Python's unquote: a malformed escape stays
func TestUnquote(t *testing.T) {
	for in, want := range map[string]string{"%40babel": "@babel", "a%2Fb": "a/b", "100%": "100%", "%zz": "%zz", "%4": "%4", "plain": "plain", "r%C3%A9": "ré"} {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}
