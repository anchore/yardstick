// Command seed builds the label UI's end to end workspace (testkit.E2E: two scanned gates, labels
// and agent material from testkit/testdata/e2e) and serves it. Research runs a stand-in that records a
// proposal, never claude. It is also the yardstick CLI, as `seed yardstick ...`, so the scan and
// the stand-in call back into it and the seed is the one binary the tests need.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/cli"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
	"github.com/anchore/yardstick/cmd/yardstick/internal/research"
	"github.com/anchore/yardstick/cmd/yardstick/internal/testkit"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "yardstick" {
		os.Args = os.Args[1:]
		app, exit := cli.New(clio.Identification{Name: "yardstick", Version: "e2e"})
		app.Run()
		os.Exit(*exit)
	}
	dir := flag.String("dir", "", "workspace to build; replaced if it exists")
	addr := flag.String("addr", "127.0.0.1:7656", "address to serve on")
	serve := flag.Bool("serve", true, "serve the workspace; false builds it and exits")
	flag.Parse()
	if *dir == "" {
		log.Fatal("seed: -dir is required")
	}
	if err := run(*dir, *addr, *serve); err != nil {
		log.Fatal("seed: ", err)
	}
}

// fatal is testkit.TB outside a test.
type fatal struct{}

func (fatal) Helper()           {}
func (fatal) Fatal(args ...any) { log.Fatal(append([]any{"seed: "}, args...)...) }

func run(dir, addr string, serve bool) error {
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
	bin := testkit.StubTool(fatal{}, filepath.Join(tools, "bin"), "yardstick", "#!/bin/sh\nexec '"+self+"' yardstick \"$@\"\n")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	testkit.E2E(fatal{}, dir, tools, bin)
	if !serve {
		fmt.Printf("seeded %s\n", dir)
		return nil
	}
	h := &swap{dir: dir, bin: bin, pristine: dir + ".pristine"}
	// the seeded workspace is kept aside so a test can put it back (POST /__e2e/reset). An earlier
	// seed's snapshot goes first: cp would copy into it, and a reset would bring back that seed's
	// workspace, whose run records name SBOMs in its own temporary cache, long gone
	if err := os.RemoveAll(h.pristine); err != nil {
		return err
	}
	if out, err := exec.Command("cp", "-a", dir, h.pristine).CombinedOutput(); err != nil {
		return fmt.Errorf("snapshot workspace: %w\n%s", err, out)
	}
	if err := h.start(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("seeded %s, serving http://%s/\n", dir, ln.Addr())
	server := &http.Server{Handler: labelserver.LocalOnly(ln.Addr().(*net.TCPAddr).Port, h), ReadHeaderTimeout: 10 * time.Second}
	return server.Serve(ln)
}

// swap serves the label server and, for the tests only, resets it: POST /__e2e/reset puts the
// seeded workspace back and starts a fresh server over it. The real `claims serve` has no such route.
type swap struct {
	dir, bin, pristine string

	mu     sync.RWMutex
	cancel context.CancelFunc
	runner *research.Runner
	next   http.Handler
}

func (s *swap) start() error {
	ctx, cancel := context.WithCancel(context.Background())
	srv, runner, err := testkit.NewServer(ctx, s.dir, s.bin)
	if err != nil {
		cancel()
		return err
	}
	s.cancel, s.runner, s.next = cancel, runner, srv.Handler()
	return nil
}

// stop ends the current server and waits for its research jobs, which write into the workspace
// (a test that started research can end while its job is still recording)
func (s *swap) stop() {
	if s.cancel != nil {
		s.cancel()
		s.runner.Wait()
	}
}

func (s *swap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == "/__e2e/reset" {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.stop()
		// contents only: the seed's working directory is dir itself
		cmd := exec.Command("sh", "-c", `find . -mindepth 1 -delete && cp -a "$1"/. .`, "sh", s.pristine) //nolint:gosec // the seed's own snapshot
		cmd.Dir = s.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			http.Error(w, fmt.Sprintf("restore workspace: %v\n%s", err, out), http.StatusInternalServerError)
			return
		}
		if err := s.start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.mu.RLock()
	h := s.next
	s.mu.RUnlock()
	h.ServeHTTP(w, r)
}
