// Package event names what a run publishes on the bus for a UI to draw: a gate starting, the work
// that prepares it, and each scan. Nothing in a run reads them back.
package event

import (
	"fmt"
	"strings"

	"github.com/wagoodman/go-partybus"
)

const (
	prefix = "yardstick-"

	// GateStarted carries a Gate: its setups as the gate file wrote them, and its subjects.
	GateStarted partybus.EventType = prefix + "gate-started"
	// SetupPrepared carries a Setup with its grype version and DB resolved.
	SetupPrepared partybus.EventType = prefix + "setup-prepared"
	// TaskStarted and TaskFinished carry a Task: an install, a DB resolved or imported, an SBOM built,
	// a claims snapshot resolved or downloaded.
	TaskStarted  partybus.EventType = prefix + "task-started"
	TaskFinished partybus.EventType = prefix + "task-finished"
	// SBOMResolved carries an SBOM: where a subject's SBOM came from.
	SBOMResolved partybus.EventType = prefix + "sbom-resolved"
	// ScanStarted and ScanFinished carry a Scan: one setup's grype over one subject.
	ScanStarted  partybus.EventType = prefix + "scan-started"
	ScanFinished partybus.EventType = prefix + "scan-finished"
	// Settle carries a chan struct{} the UI closes once it has drawn its last frame, so what follows
	// on stdout is never drawn over.
	Settle partybus.EventType = prefix + "settle"
)

// Ours reports whether an event is one of yardstick's.
func Ours(t partybus.EventType) bool {
	return strings.HasPrefix(string(t), prefix)
}

type Gate struct {
	Name     string
	Setups   []Setup
	Subjects []string
}

// Setup is one side of a gate. Before it is prepared Grype and DB are as written (grype@latest,
// latest); once prepared Grype is the version installed and DB the checksum of the DB imported.
type Setup struct {
	Name   string
	Grype  string
	DB     string
	Config string
	Env    string // the declared env as sorted K=V pairs
}

type TaskKind string

const (
	Install   TaskKind = "install"
	ResolveDB TaskKind = "resolve DB"
	ImportDB  TaskKind = "import DB"
	BuildSBOM TaskKind = "build SBOM"
	// ResolveClaims and DownloadClaims are a published claims source's network reads.
	ResolveClaims  TaskKind = "resolve claims"
	DownloadClaims TaskKind = "download claims"
)

var done = map[TaskKind]string{
	Install:        "installed",
	ResolveDB:      "resolved DB",
	ImportDB:       "imported DB",
	BuildSBOM:      "built SBOM",
	ResolveClaims:  "resolved claims",
	DownloadClaims: "downloaded claims",
}

// Done is the kind as a finished task's line says it.
func (k TaskKind) Done() string {
	if d, ok := done[k]; ok {
		return d
	}
	return string(k)
}

// Task is one piece of preparation. ID pairs a finish with its start; Err is set on a failed finish.
// Details, set on the start, are lines drawn under the task while it runs and once it is done, and
// are never shortened to the task column the way Name is.
type Task struct {
	ID      uint64
	Kind    TaskKind
	Name    string
	Details []string
	Err     error
}

type SBOM struct {
	Subject string
	From    string // source, cache, built or file
}

// Scan is one setup over one subject. Matches and Err are set when it finishes; Cancelled marks a
// scan stopped because another one failed.
type Scan struct {
	Subject   string
	Setup     string
	Matches   int
	Err       error
	Cancelled bool
	// Cached marks a scan whose stored output was reused: it finishes without having started.
	Cached bool
}

// Parse returns an event's value as the type its event type carries.
func Parse[T any](e partybus.Event) (T, error) {
	v, ok := e.Value.(T)
	if !ok {
		return v, fmt.Errorf("event %s: expected a %T value, got %T", e.Type, v, e.Value)
	}
	return v, nil
}
