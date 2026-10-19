//go:build dev

// a dev build (go run -tags dev, make dev) serves the UI from the source tree, rebuilding it with
// esbuild as web/src changes and telling open pages to reload. Only this build links esbuild.

package labelserver

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/evanw/esbuild/pkg/api"

	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver/web/buildopts"
)

//go:embed devreload.js
var reloadJS []byte

func init() {
	// the package's own directory in the source tree, which is where go run builds from
	_, file, _, _ := runtime.Caller(0) //nolint:dogsled // only the file is wanted
	dir := filepath.Dir(file)
	ui = pageFS{os.DirFS(dir)}
	dev = func(ctx context.Context, mux *http.ServeMux) http.Handler { return watch(ctx, dir, mux) }
}

// pageFS is the source tree, with the reload script added to every page servePage reads.
type pageFS struct{ fs.FS }

func (p pageFS) ReadFile(name string) ([]byte, error) {
	b, err := fs.ReadFile(p.FS, name)
	if err != nil || !strings.HasSuffix(name, ".html") {
		return b, err
	}
	return bytes.Replace(b, []byte("</head>"), []byte(`<script src="/dev/reload.js"></script></head>`), 1), nil
}

// watch builds the UI into assets/dist/ once, then on every change under web/, and adds the
// reload routes to mux. Every response is no-store, so a reload always reads from disk.
func watch(ctx context.Context, dir string, mux *http.ServeMux) http.Handler {
	h := &hub{subs: map[chan []byte]bool{}}
	opts := buildopts.Options(filepath.Join(dir, "web"))
	hashes := map[string]string{} // by URL path, from the last build that succeeded
	opts.Plugins = []api.Plugin{{Name: "reload", Setup: func(b api.PluginBuild) {
		b.OnEnd(func(r *api.BuildResult) (api.OnEndResult, error) {
			h.send(rebuilt(r, dir, hashes))
			return api.OnEndResult{}, nil
		})
	}}}
	bc, cerr := api.Context(opts)
	if cerr != nil {
		panic(fmt.Sprintf("esbuild: %v", cerr.Errors))
	}
	bc.Rebuild() // so assets/dist/ is there before the first page; esbuild prints any errors
	if err := bc.Watch(api.WatchOptions{}); err != nil {
		panic(fmt.Sprintf("esbuild watch: %v", err))
	}
	go func() {
		<-ctx.Done()
		bc.Dispose()
	}()
	fmt.Fprintf(os.Stderr, "dev: serving the UI from %s, rebuilding on changes under web/\n", dir)

	mux.HandleFunc("GET /dev/reload", h.serve(ctx))
	mux.HandleFunc("GET /dev/reload.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(reloadJS)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, req)
	})
}

// event is what /dev/reload sends after each build: the outputs whose contents changed, by URL
// path, and the build's errors.
type event struct {
	Changed []string `json:"changed"`
	Errors  []string `json:"errors"`
}

func rebuilt(r *api.BuildResult, dir string, hashes map[string]string) event {
	ev := event{Changed: []string{}, Errors: []string{}}
	for _, m := range r.Errors {
		msg := m.Text
		if l := m.Location; l != nil {
			msg = fmt.Sprintf("%s:%d:%d: %s", l.File, l.Line, l.Column, m.Text)
		}
		ev.Errors = append(ev.Errors, msg)
	}
	for _, f := range r.OutputFiles {
		rel, err := filepath.Rel(dir, f.Path)
		if err != nil || strings.HasSuffix(rel, ".map") {
			continue
		}
		path := "/" + filepath.ToSlash(rel)
		if hashes[path] != f.Hash {
			ev.Changed = append(ev.Changed, path)
			hashes[path] = f.Hash
		}
	}
	return ev
}

// hub fans each build's event out to every open /dev/reload.
type hub struct {
	mu   sync.Mutex
	subs map[chan []byte]bool
	last []byte // the last build's event when it failed, for a page opened after it
}

func (h *hub) send(ev event) {
	b, _ := json.Marshal(ev)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = nil
	if len(ev.Errors) > 0 {
		h.last = b
	}
	for c := range h.subs {
		select {
		case c <- b:
		default: // a page too slow to keep up misses a build
		}
	}
}

// serve streams build events as server-sent events until the page goes or the server stops.
func (h *hub) serve(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		c := make(chan []byte, 8)
		h.mu.Lock()
		h.subs[c] = true
		last := h.last
		h.mu.Unlock()
		defer func() {
			h.mu.Lock()
			delete(h.subs, c)
			h.mu.Unlock()
		}()

		w.Header().Set("Content-Type", "text/event-stream")
		rc := http.NewResponseController(w)
		write := func(s string) bool {
			_, err := fmt.Fprint(w, s)
			return err == nil && rc.Flush() == nil
		}
		if !write(": connected\n\n") || (last != nil && !write("data: "+string(last)+"\n\n")) {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-req.Context().Done():
				return
			case b := <-c:
				if !write("data: " + string(b) + "\n\n") {
					return
				}
			}
		}
	}
}
