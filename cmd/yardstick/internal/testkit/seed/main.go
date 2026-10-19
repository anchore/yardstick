// Command seed builds the label UI's end to end workspace (testkit.E2E: two scanned gates, labels
// and agent material from testkit/testdata/e2e) and serves it. Research runs a stand-in that records a
// proposal, never claude. It is also the yardstick CLI, as `seed yardstick ...`, so the scan and
// the stand-in call back into it and the seed is the one binary a test container needs.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/yardstick/cmd/yardstick/cli"
	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
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
	srv, err := testkit.NewServer(context.Background(), dir, bin)
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
