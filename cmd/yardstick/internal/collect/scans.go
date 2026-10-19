package collect

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gosync "github.com/anchore/go-sync"
	"github.com/anchore/yardstick/cmd/yardstick/internal/bus"
	"github.com/anchore/yardstick/cmd/yardstick/internal/claims"
	"github.com/anchore/yardstick/cmd/yardstick/internal/execute"
	"github.com/anchore/yardstick/cmd/yardstick/internal/gatefile"
	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/runrecord"
	"github.com/anchore/yardstick/cmd/yardstick/internal/setup"
	"github.com/anchore/yardstick/cmd/yardstick/internal/subject"
)

// Setup names, in the order a gate scans them.
const (
	Candidate = "candidate"
	Reference = "reference"
)

// Scan runs a prepared setup's grype over one SBOM and checks that its output decodes, returning
// the output, its log with credentials redacted, and how many matches it holds. grype logs at
// trace unless the setup declares GRYPE_LOG_LEVEL: trace says why grype dropped each record it
// considered, which is what explains a difference.
func Scan(ctx context.Context, run execute.Runner, p setup.Prepared, sbom string) (out, stderr []byte, matches int, err error) {
	cfg, err := configPath(p.Config)
	if err != nil {
		return nil, nil, 0, err
	}
	args := []string{"-c", cfg, "sbom:" + sbom, "-o", "json"}
	env := map[string]string{"GRYPE_LOG_LEVEL": "trace"}
	maps.Copy(env, p.Env)
	out, stderr, err = run.Run(ctx, execute.Cmd{Bin: p.Grype.Bin, Args: args, DBDir: p.DB.Dir, Env: env})
	if err != nil {
		return nil, nil, 0, err
	}
	doc, err := Decode(out)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("grype %s wrote JSON grype's own models do not read: %w", p.Grype.Spec, err)
	}
	// redact against what the child actually saw: the inherited environment plus the setup's own
	environ := os.Environ()
	for k, v := range p.Env {
		environ = append(environ, k+"="+v)
	}
	return out, redact(stderr, environ), len(doc.Matches), nil
}

// credentialVar is a variable that may hold a registry credential.
var credentialVar = regexp.MustCompile(`^(GRYPE|SYFT)_REGISTRY_AUTH.*_(USERNAME|PASSWORD|TOKEN)$`)

// urlUserinfo is the userinfo part of a URL, which can carry a credential (a proxy, a DB mirror).
var urlUserinfo = regexp.MustCompile(`://[^/\s]*@`)

// redact masks credentials in a tool log, which is kept in the run and the scan cache: the values
// of credential variables in the environment, and userinfo in any URL. grype masks them in its own
// config dump; this catches anything else.
func redact(log []byte, environ []string) []byte {
	var secrets []string
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if (credentialVar.MatchString(k) || slices.Contains(execute.SecretEnv, k)) && len(v) >= 3 {
			secrets = append(secrets, v)
		}
	}
	// longest first, so a secret that contains another is masked whole
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	for _, v := range secrets {
		log = bytes.ReplaceAll(log, []byte(v), []byte("*******"))
	}
	return urlUserinfo.ReplaceAll(log, []byte("://*******@"))
}

// gzipLog compresses a tool log, returning it with the sha256 of its text.
func gzipLog(text []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(text); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(text)
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// configPath is the config file a tool runs with: the declared one, else an empty file, so no
// config outside the gate file applies.
func configPath(declared *setup.File) (string, error) {
	if declared != nil {
		return declared.Path, nil
	}
	return execute.EmptyConfig()
}

// Scans is what scanning a gate needs besides the gate file.
type Scans struct {
	Run      execute.Runner
	Preparer *setup.Preparer
	Build    subject.Builder
	// Rebuild skips the claims sources' SBOMs (--rebuild-sboms).
	Rebuild bool
	// Rescan runs every scan and replaces what is stored, instead of reusing it (--rescan).
	Rescan bool
	// Parallelism is how many grype processes run at once; zero means GOMAXPROCS.
	Parallelism int
	// RunName picks the run directory the scans go to, .yardstick/runs/<RunName>/<gate>/ (--name).
	RunName string
}

// ExecutorGrype names the go-sync executor that bounds grype processes, carried in the context.
const ExecutorGrype = "grype"

// CheckParallelism rejects a limit that could not run a scan.
func CheckParallelism(n int) error {
	if n < 1 {
		return fmt.Errorf("--parallelism must be at least 1, got %d", n)
	}
	return nil
}

// Gate prepares a gate's setups, resolves each subject's SBOM, and scans every subject with
// each setup, up to Parallelism grype processes at a time. The scans replace the gate's last ones
// only when all of them succeed. The claims set is the one the caller opened, so a run opens each source once.
func (m Scans) Gate(ctx context.Context, g *gatefile.Gate, set *claims.Set) (*runrecord.Record, error) {
	if m.Parallelism != 0 {
		if err := CheckParallelism(m.Parallelism); err != nil {
			return nil, err
		}
	}
	log.Infof("scanning gate %s", g.Name)
	rec := &runrecord.Record{
		Gate:         runrecord.Gate{Name: g.Name, Path: g.Path, SHA256: g.SHA256, Fingerprint: g.Fingerprint()},
		Created:      time.Now().UTC().Format(time.RFC3339),
		Setups:       map[string]setup.Prepared{},
		RebuildSBOMs: m.Rebuild,
	}
	if m.Run.InheritEnv {
		// names only: a value may be a credential, and the record is uploaded with a CI run's
		// scans. Both setups run in this one process, so inherited env never differs between them.
		for k := range execute.Inherited() {
			rec.InheritedEnv = append(rec.InheritedEnv, k)
		}
		sort.Strings(rec.InheritedEnv)
	}
	setups := []string{Candidate}
	if g.Reference != nil {
		setups = append(setups, Reference)
	}
	bus.GateStarted(g)
	for _, name := range setups {
		s := g.Candidate
		if name == Reference {
			s = g.Reference
		}
		p, err := m.Preparer.Prepare(ctx, name, s)
		if err != nil {
			return nil, err
		}
		rec.Setups[name] = p
		bus.SetupPrepared(name, p.Grype.Spec.String(), p.DB.Checksum)
	}

	resolved, err := m.Resolve(ctx, g, set)
	if err != nil {
		return nil, err
	}
	for _, res := range resolved {
		rec.Warnings = append(rec.Warnings, res.Warnings...)
		rec.Subjects = append(rec.Subjects, runrecord.Subject{Resolved: *res, Scans: map[string]string{}, ScanKeys: map[string]string{}, Logs: map[string]runrecord.Log{}})
	}

	partial, err := runrecord.Start(m.RunName, g.Name)
	if err != nil {
		return nil, err
	}
	if err := m.scanAll(ctx, partial, rec, setups); err != nil {
		partial.Discard()
		return nil, err
	}
	if g.Reference != nil {
		isAdvisory := func(string) bool { return false }
		if v := set.Vocabulary(); v != nil {
			isAdvisory = v.IsAdvisory
		}
		if err := m.lookups(ctx, partial, rec, isAdvisory); err != nil {
			partial.Discard()
			return nil, err
		}
	}
	for _, src := range set.Sources {
		rec.Claims = append(rec.Claims, runrecord.Source{Locator: src.Locator, Kind: src.Kind, Snapshot: src.Snapshot(), Commit: src.Commit})
	}
	return rec, partial.Replace(rec)
}

// Resolve finds or builds each subject's SBOM, in the order a gate run finds them: the first
// claims source holding it, the cache, then a build with the effective catalog. It runs no grype,
// so it is all of collect sboms --gate and the first step of Gate.
func (m Scans) Resolve(ctx context.Context, g *gatefile.Gate, set *claims.Set) ([]*subject.Resolved, error) {
	resolver := &subject.Resolver{Sources: set.Sources, Catalog: g.Catalog, Rebuild: m.Rebuild, Build: m.Build}
	var out []*subject.Resolved
	for _, s := range g.Subjects {
		log.Infof("finding the SBOM of %s", s.Name)
		res, err := resolver.Resolve(ctx, s)
		if err != nil {
			return nil, err
		}
		bus.SBOMResolved(s.Name, string(res.From))
		out = append(out, res)
	}
	return out, nil
}

// scanAll runs every subject's scans, each setup over the subject's one SBOM, on a go-sync
// executor bounded by Parallelism. The first failure cancels the scans not yet started and kills
// the running ones.
func (m Scans) scanAll(ctx context.Context, partial *runrecord.Partial, rec *runrecord.Record, setups []string) error {
	n := m.Parallelism
	if n == 0 {
		n = runtime.GOMAXPROCS(0)
	}
	// the executor is carried in the context, as syft does, so the limit is not threaded by hand
	ctx = gosync.SetContextExecutor(ctx, ExecutorGrype, gosync.NewExecutor(n))
	// Collect gets the uncancelled ctx so it waits for every scan to finish before the caller
	// discards the partial; the scans themselves run on the cancellable one.
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type job struct {
		sub  *runrecord.Subject
		name string
		rel  string
	}
	var jobs []job
	for i := range rec.Subjects {
		for _, name := range setups {
			jobs = append(jobs, job{&rec.Subjects[i], name, fmt.Sprintf("%s/%02d.json", name, i)})
		}
	}
	var mu sync.Mutex
	var reused, ran atomic.Int64
	err := gosync.Collect(&ctx, ExecutorGrype, slices.Values(jobs), func(j job) (struct{}, error) {
		if scanCtx.Err() != nil {
			return struct{}{}, nil
		}
		p := rec.Setups[j.name]
		res, err := m.scanOrReuse(scanCtx, p, j.sub, j.name)
		if res.Reused {
			bus.ScanReused(j.sub.Name, j.name, res.Matches)
		} else {
			bus.ScanFinished(scanCtx, j.sub.Name, j.name, res.Matches, err)
		}
		var logged *runrecord.Log
		switch {
		case err != nil:
			err = fmt.Errorf("subject %s, %s setup (grype %s): %w", j.sub.Name, j.name, p.Grype.Spec, err)
		case res.Log != nil:
			logged = &runrecord.Log{Path: strings.TrimSuffix(j.rel, ".json") + ".log.gz", SHA256: res.LogSHA256}
			err = partial.Write(logged.Path, res.Log)
		}
		if err == nil {
			err = partial.Write(j.rel, res.Out)
		}
		if err != nil {
			cancel()
			return struct{}{}, err
		}
		log.Debugf("%s setup scan of %s written to %s", j.name, j.sub.Name, j.rel)
		mu.Lock()
		j.sub.Scans[j.name] = j.rel
		if res.Key != "" {
			j.sub.ScanKeys[j.name] = res.Key
		}
		if logged != nil {
			j.sub.Logs[j.name] = *logged
		}
		mu.Unlock()
		if res.Reused {
			reused.Add(1)
		} else {
			ran.Add(1)
		}
		return struct{}{}, nil
	}, nil)
	if err == nil {
		log.Infof("scans of %s: %d reused, %d ran", rec.Gate.Name, reused.Load(), ran.Load())
	}
	return err
}
