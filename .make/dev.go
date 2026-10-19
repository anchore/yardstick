package main

import (
	"os"

	. "github.com/anchore/go-make"
	"github.com/anchore/go-make/lang"
	"github.com/anchore/go-make/run"
	"github.com/anchore/go-make/shell"
	"github.com/anchore/go-make/template"
)

// dev builds yardstick with the dev tag and runs claims serve in YARDSTICK_DEV_DIR (default the
// repo root, which needs a run under .yardstick/runs/) with ARGS appended, beside tsc --watch.
// It is built first rather than go run so it can run outside the module. It skips generate's tsc
// so a type error never stops the server from starting: the dev build bundles on startup and
// tsc --watch reports the errors beside it.
func dev() {
	webDeps()
	bin := template.Render("{{RootDir}}/.tmp/yardstick-dev")
	Run("go build -tags dev -o", run.Args(bin, "./cmd/yardstick"))
	dir := os.Getenv("YARDSTICK_DEV_DIR")
	if dir == "" {
		dir = template.Render("{{RootDir}}")
	}
	parallel(
		func() error {
			args := append([]string{"claims", "serve"}, shell.Split(os.Getenv("ARGS"))...)
			_, err := run.Command(bin, run.Args(args...), run.InDir(dir), run.Stdout(os.Stdout))
			return err
		},
		func() error {
			_, err := run.Command(tsc(), run.Args("--noEmit", "--watch", "--preserveWatchOutput", "-p", web), run.Stdout(os.Stdout))
			return err
		},
	)
}

// parallel runs fns at once until the first returns, then stops the rest through go-make's
// context, the same way ctrl-c stops them, and throws the first one's error unless it was ctrl-c.
func parallel(fns ...func() error) {
	ctx := run.Context()
	errs := make(chan error, len(fns))
	for _, fn := range fns {
		go func() { errs <- fn() }()
	}
	err := <-errs
	interrupted := ctx.Err() != nil
	run.Cancel()
	for range len(fns) - 1 {
		<-errs
	}
	if !interrupted {
		lang.Throw(err)
	}
}
