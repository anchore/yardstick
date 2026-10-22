package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// tygo writes a Go string type and its typed constants as `export type T = string;` and the
	// constants right after it
	stringEnum = regexp.MustCompile(`(?m)^export type (\w+) = string;\n((?:export const \w+: (\w+) = "[^"]*";.*\n)+)`)
	enumValue  = regexp.MustCompile(`= ("[^"]*");`)
)

// unionEnums makes each Go string enum in the generated wire types a union of its constants'
// values, so the UI's checks see every value the server can send: tygo's own union style needs
// constants named after their type (VerdictTP), which these are not. A map keyed by one becomes a
// mapped type, since an index signature cannot take a union of literals.
func unionEnums(dir string) {
	files, err := filepath.Glob(filepath.Join(dir, "*.ts"))
	if err != nil {
		panic(err)
	}
	src := map[string]string{}
	var unions []string // T in its own file, ns.T everywhere else
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		ns := strings.ReplaceAll(strings.TrimSuffix(filepath.Base(f), ".ts"), "-", "")
		src[f] = stringEnum.ReplaceAllStringFunc(string(data), func(m string) string {
			sub := stringEnum.FindStringSubmatch(m)
			name, consts := sub[1], sub[2]
			var values []string
			for _, line := range strings.SplitAfter(strings.TrimSuffix(consts, "\n"), "\n") {
				// only a group whose constants are all of the type is the type's enumeration
				if !strings.Contains(line, ": "+name+" = ") {
					return m
				}
				values = append(values, enumValue.FindStringSubmatch(line)[1])
			}
			unions = append(unions, ns+"."+name)
			return "export type " + name + " = " + strings.Join(values, " | ") + ";\n" + consts
		})
	}
	for f, s := range src {
		ns := strings.ReplaceAll(strings.TrimSuffix(filepath.Base(f), ".ts"), "-", "")
		for _, u := range unions {
			s = strings.ReplaceAll(s, "[key: "+u+"]:", "[key in "+u+"]?:")
			if local, ok := strings.CutPrefix(u, ns+"."); ok {
				s = strings.ReplaceAll(s, "[key: "+local+"]:", "[key in "+local+"]?:")
			}
		}
		if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
			panic(err)
		}
	}
}
