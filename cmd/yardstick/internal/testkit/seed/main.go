// Command seed builds a workspace with a scanned deb gate (testkit's, as claims serve's tests use)
// and serves it for the label UI's end to end tests. Research runs a stand-in that records a
// proposal, never claude. It is also the yardstick CLI, as `seed yardstick ...`, so the scan and
// the stand-in call back into it and the seed is the one binary a test container needs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/cli"
	"github.com/anchore/yardstick/cmd/yardstick/internal/agentstore"
	"github.com/anchore/yardstick/cmd/yardstick/internal/analysis"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/testkit"
)

// researchCommand stands in for the research-vuln skill: it proposes tp for the row it was given,
// through the CLI the way the skill does.
const researchCommand = `printf '{"row":"%s","verdict":"tp","justification":"no-fix","confidence":"medium","note":"e2e research stand-in","author":{"skill":"research-vuln","model":"e2e"}}\n' "$YARDSTICK_ROW" | yardstick claims agent propose`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "yardstick" {
		os.Args = os.Args[1:]
		app, exit := cli.New(clio.Identification{Name: "yardstick", Version: "e2e"})
		app.Run()
		os.Exit(*exit)
	}
	dir := flag.String("dir", "", "workspace to build; replaced if it exists")
	addr := flag.String("addr", "127.0.0.1:7656", "address to serve on")
	flag.Parse()
	if *dir == "" {
		log.Fatal("seed: -dir is required")
	}
	if err := run(*dir, *addr); err != nil {
		log.Fatal("seed: ", err)
	}
}

// fatal is testkit.TB outside a test.
type fatal struct{}

func (fatal) Helper()           {}
func (fatal) Fatal(args ...any) { log.Fatal(append([]any{"seed: "}, args...)...) }

func run(dir, addr string) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	tools, err := os.MkdirTemp("", "yardstick-seed-")
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	w := testkit.NewWorkspace(fatal{}, dir, tools)
	w.DebGate()
	bin := testkit.StubTool(fatal{}, filepath.Join(tools, "bin"), "yardstick", "#!/bin/sh\nexec '"+self+"' yardstick \"$@\"\n")

	scan := exec.Command(bin, "gates/deb.yaml", "-q")
	scan.Dir, scan.Stdout, scan.Stderr = dir, os.Stderr, os.Stderr
	scan.Env = append(os.Environ(), "YARDSTICK_CACHE_DIR="+filepath.Join(tools, "cache"))
	// 1 is a failed gate, which is what a gate with unlabeled changes is
	var exit *exec.ExitError
	if err := scan.Run(); err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		return fmt.Errorf("scan: %w", err)
	}

	if err := os.Chdir(dir); err != nil {
		return err
	}
	srv, err := labelserver.New(context.Background(), labelserver.Options{
		Run: runrecord.DefaultName, Author: "e2e", Store: agentstore.Open(agentstore.Dir),
		Research: research.NewRunner(research.Config{
			Command: researchCommand, Dir: dir, Run: runrecord.DefaultName, Concurrency: 2, Timeout: time.Minute, Bin: bin,
		}),
		ResearchAvailability: research.Availability{Available: true},
		Load: func(p string) (*gatefile.Gate, error) {
			return gatefile.Load(p, gatefile.Options{Checks: analysis.Definitions()})
		},
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("seeded %s, serving http://%s/\n", dir, ln.Addr())
	server := &http.Server{Handler: labelserver.LocalOnly(ln.Addr().(*net.TCPAddr).Port, srv.Handler()), ReadHeaderTimeout: 10 * time.Second}
	return server.Serve(ln)
}
