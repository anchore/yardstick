package main

import (
	"os"
	"path/filepath"
	"testing"
)

// a string type and its constants become a union, and a map keyed by it a mapped type, in its own
// file and through its namespace in another; a group that is not all the type's is left alone
func TestUnionEnums(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("claims-v1.ts", `export type Verdict = string;
export const TP: Verdict = "tp";
export const FP: Verdict = "fp"; // a comment
export type Open = string;
export const Some: Open = "x";
export const Other = "y";
export interface Vocabulary {
  justifications: { [key: Verdict]: string};
}
`)
	write("wire.ts", `export interface Effect {
  outcome: { [key: claimsv1.Verdict]: string};
}
`)
	unionEnums(dir)
	got, _ := os.ReadFile(filepath.Join(dir, "claims-v1.ts"))
	want := `export type Verdict = "tp" | "fp";
export const TP: Verdict = "tp";
export const FP: Verdict = "fp"; // a comment
export type Open = "x";
export const Some: Open = "x";
export const Other = "y";
export interface Vocabulary {
  justifications: { [key in Verdict]?: string};
}
`
	if string(got) != want {
		t.Errorf("claims-v1.ts:\n%s\nwant:\n%s", got, want)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "wire.ts")); string(got) != "export interface Effect {\n  outcome: { [key in claimsv1.Verdict]?: string};\n}\n" {
		t.Errorf("wire.ts:\n%s", got)
	}
}
