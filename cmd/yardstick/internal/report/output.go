package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Output is one -o: a format, and the file it is written to. An empty Path is stdout.
type Output struct {
	Format string
	Path   string
}

// ParseOutputs reads every -o value, FORMAT or FORMAT=path. It refuses an unknown format, an
// empty path, and more than one output on stdout, so a bad request fails before any scan.
func ParseOutputs(specs []string) ([]Output, error) {
	var outs []Output
	stdout := 0
	for _, spec := range specs {
		format, path, hasPath := strings.Cut(spec, "=")
		if err := CheckFormat(format); err != nil {
			return nil, err
		}
		if hasPath && path == "" {
			return nil, fmt.Errorf("output %q has no path after the =", spec)
		}
		if !hasPath {
			stdout++
		}
		outs = append(outs, Output{Format: format, Path: path})
	}
	if stdout > 1 {
		return nil, fmt.Errorf("only one output can go to stdout, give the others a path as FORMAT=path (formats: %s)", strings.Join(Formats, ", "))
	}
	return outs, nil
}

// WriteOutputs renders the set once per output. Every render happens before anything is written,
// so a failure leaves no partial files. An empty write to stdout comes first: it is what lets the
// live UI settle before a file is written, whether or not any output goes to stdout. A file is
// never colored.
func WriteOutputs(stdout io.Writer, s Set, outs []Output, o Options) error {
	rendered := make([]bytes.Buffer, len(outs))
	for i, out := range outs {
		ro := o
		ro.Format = out.Format
		ro.Color = o.Color && out.Path == ""
		if err := Render(&rendered[i], s, ro); err != nil {
			return err
		}
	}
	if _, err := stdout.Write(nil); err != nil {
		return err
	}
	var errs []error
	for i, out := range outs {
		if out.Path == "" {
			_, err := stdout.Write(rendered[i].Bytes())
			errs = append(errs, err)
			continue
		}
		errs = append(errs, writeFile(out.Path, rendered[i].Bytes()))
	}
	return errors.Join(errs...)
}

// writeFile writes through a temp file beside the target and renames it, so a reader never sees
// half a report.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
