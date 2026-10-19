package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEverySliceValueValidates(t *testing.T) {
	if Formats[0] != "cause" {
		t.Errorf("expected cause the default format, got %s", Formats[0])
	}
	for _, f := range Formats {
		if err := CheckFormat(f); err != nil {
			t.Errorf("format %q: %v", f, err)
		}
		if _, err := ParseOutputs([]string{f}); err != nil {
			t.Errorf("output %q: %v", f, err)
		}
	}
	for _, d := range DetailsLevels {
		if err := CheckDetails(d); err != nil {
			t.Errorf("details %q: %v", d, err)
		}
	}
	for _, err := range []error{CheckFormat("tree"), CheckDetails("lots")} {
		if err == nil {
			t.Fatal("expected a refusal")
		}
	}
	if err := CheckDetails("lots"); !strings.Contains(err.Error(), strings.Join(DetailsLevels, ", ")) {
		t.Errorf("expected the refusal to name every level, got %v", err)
	}
}

func TestParseOutputs(t *testing.T) {
	outs, err := ParseOutputs([]string{"check", "json=./r.json", "table=/tmp/t"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Output{{"check", ""}, {"json", "./r.json"}, {"table", "/tmp/t"}}
	for i := range want {
		if outs[i] != want[i] {
			t.Errorf("output %d: got %v, want %v", i, outs[i], want[i])
		}
	}
	if _, err := ParseOutputs([]string{"yaml=./x"}); err == nil || !strings.Contains(err.Error(), strings.Join(Formats, ", ")) {
		t.Errorf("expected an unknown format refused naming the valid ones, got %v", err)
	}
	if _, err := ParseOutputs([]string{"check", "json"}); err == nil || !strings.Contains(err.Error(), "only one output can go to stdout") {
		t.Errorf("expected two stdout outputs refused, got %v", err)
	}
	if _, err := ParseOutputs([]string{"json="}); err == nil {
		t.Error("expected an empty path refused")
	}
}

type countingWriter struct {
	bytes.Buffer
	writes int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.Buffer.Write(p)
}

func TestWriteOutputs(t *testing.T) {
	set := Summarize([]Gate{passing(t)})
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	var stdout countingWriter
	outs, err := ParseOutputs([]string{"check", "json=" + path, "table=" + filepath.Join(dir, "t.txt")})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteOutputs(&stdout, set, outs, Options{}); err != nil {
		t.Fatal(err)
	}
	if want := render(t, set, Options{Format: "check"}); stdout.String() != want {
		t.Errorf("stdout is not the details render:\n%s", stdout.String())
	}
	if stdout.writes < 2 {
		t.Error("expected an empty write to stdout ahead of the report, so the UI settles first")
	}
	if got, _ := os.ReadFile(path); string(got) != render(t, set, Options{Format: "json"}) {
		t.Errorf("json file is not the json render: %s", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "t.txt")); string(got) != render(t, set, Options{Format: "table"}) {
		t.Errorf("table file is not the table render: %s", got)
	}
	// the temp files were renamed away
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("expected only the two reports in the directory, got %d entries", len(entries))
	}
}

func TestWriteOutputsFilesOnly(t *testing.T) {
	var stdout countingWriter
	path := filepath.Join(t.TempDir(), "r.json")
	if err := WriteOutputs(&stdout, Summarize([]Gate{passing(t)}), []Output{{"json", path}}, Options{}); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || stdout.writes == 0 {
		t.Errorf("expected only the settling empty write to stdout, got %d bytes in %d writes", stdout.Len(), stdout.writes)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
}
