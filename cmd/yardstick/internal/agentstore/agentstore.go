// Package agentstore is the agent state a labeling session keeps beside the runs: proposals,
// causes, explanations and override records, as JSON lines under .yardstick/. None of it is in
// the corpus and none of it counts for scoring until a person accepts a proposal, which writes an
// ordinary label (labeling policy P-7).
package agentstore

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Schema is written on every line.
const Schema = "v1"

// Dir is where the store lives, relative to the working directory, beside runrecord.RunsDir.
var Dir = ".yardstick"

const (
	proposalsFile    = "proposals.jsonl"
	causesFile       = "causes.jsonl"
	explanationsFile = "explanations.jsonl"
	overridesFile    = "overrides.jsonl"
)

// record is a line one of the store's logs holds.
type record interface {
	key() string // lines with the same key supersede one another, the newest winning
	schema() string
	Validate() error
}

// Store is the agent state in one directory.
type Store struct {
	Proposals    *Log[Proposal]
	Causes       *Log[Cause]
	Explanations *Log[Explanation]
	Overrides    *Log[Override]
}

// Open is the store in dir; nothing is created until something is added.
func Open(dir string) *Store {
	return &Store{
		Proposals:    &Log[Proposal]{path: filepath.Join(dir, proposalsFile)},
		Causes:       &Log[Cause]{path: filepath.Join(dir, causesFile)},
		Explanations: &Log[Explanation]{path: filepath.Join(dir, explanationsFile)},
		Overrides:    &Log[Override]{path: filepath.Join(dir, overridesFile)},
	}
}

// Log is one JSON lines file, append-only: nothing is edited, a newer line with the same key
// supersedes an older one.
type Log[T record] struct {
	path string
}

// Add appends the records, after every one of them was checked, in one write.
func (l *Log[T]) Add(values ...T) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep purls like ?arch=amd64&distro=... readable
	for _, v := range values {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("%s: %w", v.key(), err)
		}
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// Current is the newest record per key, in the order each key first appeared.
func (l *Log[T]) Current() ([]T, error) {
	data, err := l.read()
	if err != nil {
		return nil, err
	}
	var order []string
	byKey := map[string]T{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for n := 1; scanner.Scan(); n++ {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(scanner.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", l.path, n, err)
		}
		if v.schema() != Schema {
			return nil, fmt.Errorf("%s line %d: schema %q; this yardstick reads %s", l.path, n, v.schema(), Schema)
		}
		if n, ok := any(&v).(interface{ normalize() }); ok {
			n.normalize()
		}
		if _, ok := byKey[v.key()]; !ok {
			order = append(order, v.key())
		}
		byKey[v.key()] = v
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	out := make([]T, 0, len(order))
	for _, k := range order {
		out = append(out, byKey[k])
	}
	return out, nil
}

// Snapshot is a hash of the file's content: lines are only ever appended, so it changes exactly
// when something is added.
func (l *Log[T]) Snapshot() (string, error) {
	data, err := l.read()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "jsonl:" + hex.EncodeToString(sum[:]), nil
}

// read is the file's content; nil when nothing was added yet.
func (l *Log[T]) read() ([]byte, error) {
	data, err := os.ReadFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}
