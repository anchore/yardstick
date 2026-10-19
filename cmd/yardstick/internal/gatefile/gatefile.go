// Package gatefile loads one gate from one YAML file: the candidate and optional reference setups,
// the catalog, the claims sources, the subjects and the checks. Every rule that can be checked
// without running a tool or fetching anything is checked here, so a bad gate fails before any
// scan.
package gatefile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/yardstick/cmd/yardstick/internal/log"
	"github.com/anchore/yardstick/cmd/yardstick/internal/ref"
)

// SchemaVersion is the gate file format this yardstick reads.
const SchemaVersion = "v1"

// Undecided policies: what CI does with an undecided gate.
const (
	UndecidedFail = "fail"
	UndecidedPass = "pass"
)

// Gate is one gate file, loaded, validated, and with every relative path resolved against the
// file's directory.
type Gate struct {
	Schema      string    `yaml:"schema" json:"-"`
	Name        string    `yaml:"name" json:"name"`
	Description string    `yaml:"description" json:"description,omitempty"`
	Candidate   *Setup    `yaml:"candidate" json:"candidate"`
	Reference   *Setup    `yaml:"reference" json:"reference,omitempty"`
	Catalog     *Catalog  `yaml:"catalog" json:"catalog,omitempty"`
	Claims      []Source  `yaml:"-" json:"claims"`
	Subjects    []Subject `yaml:"-" json:"subjects"`
	Checks      []Check   `yaml:"-" json:"checks"`
	Undecided   string    `yaml:"undecided" json:"undecided"`

	Path   string `yaml:"-" json:"path"`   // the file, absolute
	SHA256 string `yaml:"-" json:"sha256"` // of the file's bytes
}

// Setup is how one side scans.
type Setup struct {
	Grype  string            `yaml:"grype" json:"grype"`
	DB     string            `yaml:"db" json:"db"`
	Config string            `yaml:"config" json:"config,omitempty"`
	Env    map[string]string `yaml:"env" json:"env,omitempty"`
}

// Catalog is how a missing image SBOM is built: syft pinned, its config, platform and env.
type Catalog struct {
	Syft     string            `yaml:"syft" json:"syft"`
	Config   string            `yaml:"config" json:"config,omitempty"`
	Platform string            `yaml:"platform" json:"platform,omitempty"`
	Env      map[string]string `yaml:"env" json:"env,omitempty"`
}

// Source is one claims source: a local directory or a published reference.
type Source struct {
	Locator string `json:"locator"`
	// Remote is set for <host>/<owner>/<repo>@<ref>; the locator is then the reference as written.
	Remote *Remote `json:"remote,omitempty"`
}

// Remote is a published claims reference, <host>/<owner>/<repo>@<ref>.
type Remote struct {
	Repository string `json:"repository"` // <host>/<owner>/<repo>
	Ref        string `json:"ref"`        // main, or a commit or snapshot digest
}

// Subject is one subject entry: a reference, its name, and an optional package filter.
type Subject struct {
	Ref      ref.Ref `json:"-"`
	Written  string  `json:"ref"` // the reference as the file wrote it, sbom: paths resolved
	Name     string  `json:"name"`
	Platform string  `json:"platform,omitempty"`
	// KeepTypes, when set, filters the SBOM to these package types before either setup scans it.
	KeepTypes []string `json:"keepTypes,omitempty"`
}

// Check is one check the gate runs, resolved against the registry: every param set, defaults
// filled in.
type Check struct {
	Name   string             `json:"name"`
	Params map[string]float64 `json:"params,omitempty"`
}

// Param is one numeric parameter a check takes.
type Param struct {
	Name        string
	Description string
	Integer     bool
	Min         float64
	Max         *float64 // nil: unbounded
	Default     *float64 // nil: required
}

// CheckDef is what loading needs to know about a check: its params, and whether it reads the
// reference setup. The check registry provides one per check.
type CheckDef struct {
	Name           string
	Params         []Param
	ReadsReference bool
}

// Options are what loading takes besides the file.
type Options struct {
	// Checks is the check registry, by name.
	Checks map[string]CheckDef
	// App is the app config, nil when there is none. Its claims apply when the file lists none.
	App *AppConfig
	// Claims are local sources appended after the file's own or the app config's (the CLI's --claims).
	Claims []string
	// Writes is set when the invocation writes labels, which needs a local last claims source.
	Writes bool
}

// DB keys a gate may not declare: yardstick pins the DB and the update checks itself.
var pinnedEnv = []string{"GRYPE_DB_AUTO_UPDATE", "GRYPE_DB_VALIDATE_AGE", "GRYPE_DB_CACHE_DIR", "SYFT_CHECK_FOR_APP_UPDATE"}

var (
	validName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	remotePattern  = regexp.MustCompile(`^([a-z0-9.-]+\.[a-z]{2,}/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([A-Za-z0-9._:-]+)$`)
	platformFormat = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)
)

// LoadError is everything wrong with one gate file.
type LoadError struct {
	Path     string
	Problems []string
}

func (e *LoadError) Error() string {
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = e.Path + ": " + p
	}
	return strings.Join(lines, "\n")
}

// problems collects what is wrong with a file, so one load reports all of it.
type problems []string

func (p *problems) addf(format string, args ...any) {
	*p = append(*p, fmt.Sprintf(format, args...))
}

// Load reads and validates one gate file.
func Load(path string, opts Options) (*Gate, error) {
	abs, err := canonical(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, &LoadError{Path: path, Problems: []string{err.Error()}}
	}
	defer log.Timed("loading gate file %s", abs)()
	var errs problems
	g := parse(data, filepath.Dir(abs), opts, &errs)
	if len(errs) > 0 {
		return nil, &LoadError{Path: path, Problems: errs}
	}
	g.Path = abs
	sum := sha256.Sum256(data)
	g.SHA256 = hex.EncodeToString(sum[:])
	if g.Name == "" {
		g.Name = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(abs), ".yaml"), ".yml")
	}
	if !validName.MatchString(g.Name) {
		return nil, &LoadError{Path: path, Problems: []string{fmt.Sprintf("name %q must be letters, digits, '.', '-' and '_', since it names the gate's scans directory", g.Name)}}
	}
	claimsLocs := make([]string, len(g.Claims))
	for i, c := range g.Claims {
		claimsLocs[i] = c.Locator
	}
	log.Debugf("loaded gate %s from %s: %d subjects, claims sources %v", g.Name, abs, len(g.Subjects), claimsLocs)
	return g, nil
}

// UniqueNames fails when two gates of one invocation resolve to the same name, since they would
// share a scans directory and a line in the report.
func UniqueNames(gates []*Gate) error {
	seen := map[string]string{}
	for _, g := range gates {
		if other, ok := seen[g.Name]; ok {
			return fmt.Errorf("gates %s and %s both resolve to the name %q; set name: in one of them", other, g.Path, g.Name)
		}
		seen[g.Name] = g.Path
	}
	return nil
}

const keyName = "name"

// the raw file: keys are checked against these before decoding, so an unknown key is named
// with where it is, rather than with a Go type name
var (
	topKeys     = []string{"schema", keyName, "description", "candidate", "reference", "catalog", "claims", "subjects", "checks", "undecided"}
	setupKeys   = []string{"grype", "db", "config", "env"}
	catalogKeys = []string{"syft", "config", "platform", "env"}
	subjectKeys = []string{"ref", keyName, "platform", "packages"}
	packageKeys = []string{"keepTypes"}
	checkKeys   = []string{keyName, "params"}
)

type rawGate struct {
	Gate     `yaml:",inline"`
	Claims   []string    `yaml:"claims"`
	Subjects []yaml.Node `yaml:"subjects"`
	Checks   []yaml.Node `yaml:"checks"`
}

type rawCheck struct {
	Name   string         `yaml:"name"`
	Params map[string]any `yaml:"params"`
}

type rawSubject struct {
	Ref      string `yaml:"ref"`
	Name     string `yaml:"name"`
	Platform string `yaml:"platform"`
	Packages *struct {
		KeepTypes []string `yaml:"keepTypes"`
	} `yaml:"packages"`
}

func parse(data []byte, dir string, opts Options, errs *problems) *Gate {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		errs.addf("%v", err)
		return nil
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		errs.addf("a gate file is a YAML mapping")
		return nil
	}
	if !checkKeysIn(doc.Content[0], "", topKeys, errs) {
		return nil
	}
	var raw rawGate
	if err := doc.Content[0].Decode(&raw); err != nil {
		errs.addf("%v", err)
		return nil
	}
	g := raw.Gate

	if g.Schema != SchemaVersion {
		errs.addf("schema must be %s, got %q", SchemaVersion, g.Schema)
	}
	if g.Undecided == "" {
		g.Undecided = UndecidedFail
	}
	if g.Undecided != UndecidedFail && g.Undecided != UndecidedPass {
		errs.addf("undecided must be %s or %s, got %q", UndecidedFail, UndecidedPass, g.Undecided)
	}

	g.Candidate = setup("candidate", doc.Content[0], g.Candidate, dir, errs)
	g.Reference = setup("reference", doc.Content[0], g.Reference, dir, errs)
	if g.Candidate == nil {
		errs.addf("candidate is required")
	}
	g.Catalog = catalog(doc.Content[0], g.Catalog, dir, errs)
	g.Claims = claims(raw.Claims, opts, dir, errs)
	g.Subjects = subjects(raw.Subjects, g.Catalog, dir, errs)
	g.Checks = checks(raw.Checks, opts.Checks, g.Reference != nil, errs)
	return &g
}

// checkKeysIn reports keys of a mapping that are not in known.
func checkKeysIn(n *yaml.Node, where string, known []string, errs *problems) bool {
	if n.Kind != yaml.MappingNode {
		if where == "" {
			where = "the file"
		}
		errs.addf("%s must be a mapping", where)
		return false
	}
	ok := true
	for i := 0; i < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if !slices.Contains(known, k) {
			at := k
			if where != "" {
				at = where + "." + k
			}
			errs.addf("unknown key %q (line %d); %s takes: %s", at, n.Content[i].Line, orFile(where), strings.Join(known, ", "))
			ok = false
		}
	}
	return ok
}

func orFile(where string) string {
	if where == "" {
		return "a gate file"
	}
	return where
}

// child is the value under key in a mapping.
func child(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func setup(name string, top *yaml.Node, s *Setup, dir string, errs *problems) *Setup {
	n := child(top, name)
	if n == nil || s == nil {
		return nil
	}
	checkKeysIn(n, name, setupKeys, errs)
	if s.Grype == "" {
		errs.addf("%s.grype is required (grype@<version>, grype@latest, or a path to a binary)", name)
	} else if isPath(s.Grype) {
		s.Grype = resolve(dir, s.Grype)
	} else if tool, v, _ := strings.Cut(s.Grype, "@"); tool != "grype" || v == "" {
		errs.addf("%s.grype must be grype@<version>, grype@latest, or a path to a binary, got %q", name, s.Grype)
	}
	switch {
	case s.DB == "":
		errs.addf("%s.db is required (latest, an archive path or URL, or dir:<path>); it has no default", name)
	case s.DB == "latest", strings.HasPrefix(s.DB, "https://"), strings.HasPrefix(s.DB, "http://"):
	case strings.HasPrefix(s.DB, "dir:"):
		s.DB = "dir:" + resolve(dir, strings.TrimPrefix(s.DB, "dir:"))
	default:
		s.DB = resolve(dir, s.DB)
	}
	if s.Config != "" {
		s.Config = resolve(dir, s.Config)
	}
	env(name, s.Env, errs)
	return s
}

func catalog(top *yaml.Node, c *Catalog, dir string, errs *problems) *Catalog {
	n := child(top, "catalog")
	if n == nil || c == nil {
		return nil
	}
	checkCatalog("catalog", n, c, dir, errs)
	return c
}

// ParseCatalog reads a corpus's catalog.yaml: the keys a gate's catalog: takes, with paths
// relative to dir, the corpus root.
func ParseCatalog(data []byte, dir string) (*Catalog, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		return nil, err
	}
	if len(n.Content) == 0 {
		return nil, errors.New("catalog.yaml is empty")
	}
	var c Catalog
	if err := n.Content[0].Decode(&c); err != nil {
		return nil, err
	}
	var errs problems
	checkCatalog("catalog.yaml", n.Content[0], &c, dir, &errs)
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return &c, nil
}

func checkCatalog(where string, n *yaml.Node, c *Catalog, dir string, errs *problems) {
	checkKeysIn(n, where, catalogKeys, errs)
	switch tool, v, _ := strings.Cut(c.Syft, "@"); {
	case c.Syft == "":
		errs.addf("%s: syft is required (syft@<version> or a path to a binary)", where)
	case isPath(c.Syft):
		c.Syft = resolve(dir, c.Syft)
	case tool != "syft" || v == "":
		errs.addf("%s: syft must be syft@<version> or a path to a binary, got %q", where, c.Syft)
	case v == "latest":
		errs.addf("%s: syft must be pinned (syft@<version>), not syft@latest, so every SBOM it builds is built the same way", where)
	}
	if c.Config != "" {
		c.Config = resolve(dir, c.Config)
	}
	if c.Platform != "" && !platformFormat.MatchString(c.Platform) {
		errs.addf("%s: platform must be os/arch[/variant], got %q", where, c.Platform)
	}
	env(where, c.Env, errs)
}

// CheckData refuses what a catalog read from a claims source may not set. A claims source is
// data, possibly someone else's: it may not choose a binary to run or set variables other than
// syft's own. A gate file's catalog: is the user's config and is not held to this.
func (c *Catalog) CheckData() error {
	if c.SyftVersion() == "" {
		return fmt.Errorf("syft must be pinned as syft@<version>, not a path to a binary, got %q", c.Syft)
	}
	keys := make([]string, 0, len(c.Env))
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !strings.HasPrefix(k, "SYFT_") {
			return fmt.Errorf("env may set only SYFT_* variables, got %s", k)
		}
	}
	return nil
}

// SyftVersion is the version a catalog pins, without its v; empty for a binary by path.
func (c *Catalog) SyftVersion() string {
	if isPath(c.Syft) {
		return ""
	}
	_, v, _ := strings.Cut(c.Syft, "@")
	return strings.TrimPrefix(v, "v")
}

// env refuses the keys that pin the DB and the update checks, which yardstick sets itself.
func env(where string, e map[string]string, errs *problems) {
	keys := make([]string, 0, len(e))
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if slices.Contains(pinnedEnv, k) {
			errs.addf("%s.env may not set %s: yardstick pins the DB and update checks itself", where, k)
		}
	}
}

func claims(listed []string, opts Options, dir string, errs *problems) []Source {
	var out []Source
	add := func(s, base, from string) {
		if m := remotePattern.FindStringSubmatch(s); m != nil {
			out = append(out, Source{Locator: s, Remote: &Remote{Repository: m[1], Ref: m[2]}})
			return
		}
		p, err := canonical(resolve(base, s))
		if info, statErr := os.Stat(p); err != nil || statErr != nil || !info.IsDir() {
			errs.addf("claims source %q%s is neither an existing directory nor a reference like github.com/<owner>/<repo>@main", s, from)
			return
		}
		out = append(out, Source{Locator: p})
	}
	// a gate's own claims: replaces the app config's
	from := ""
	if len(listed) == 0 && opts.App != nil {
		listed, dir, from = opts.App.Claims, filepath.Dir(opts.App.Path), " (from "+opts.App.Path+")"
	}
	for _, s := range listed {
		add(s, dir, from)
	}
	cwd, _ := os.Getwd()
	for _, s := range opts.Claims {
		add(s, cwd, "")
	}
	if len(listed)+len(opts.Claims) == 0 {
		errs.addf("a gate needs at least one claims source (claims: in the file, in %s, or --claims)", strings.Join(AppConfigPaths, " or "))
	}
	if opts.Writes && len(out) > 0 && out[len(out)-1].Remote != nil {
		errs.addf("the last claims source must be a local path when labels are written, got %s; add one with --claims <path>", out[len(out)-1].Locator)
	}
	return out
}

func subjects(nodes []yaml.Node, cat *Catalog, dir string, errs *problems) []Subject {
	if len(nodes) == 0 {
		errs.addf("a gate needs at least one subject")
	}
	var out []Subject
	seen := map[string]bool{}
	for i := range nodes {
		s, ok := subject(&nodes[i], fmt.Sprintf("subjects[%d]", i), cat, dir, errs)
		if !ok {
			continue
		}
		if seen[s.Name] {
			errs.addf("two subjects are named %q; give one a different name:", s.Name)
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out
}

// subject reads one entry: a reference, or a mapping with ref, name, platform and packages.
func subject(n *yaml.Node, where string, cat *Catalog, dir string, errs *problems) (Subject, bool) {
	var raw rawSubject
	switch n.Kind {
	case yaml.ScalarNode:
		raw.Ref = n.Value
	case yaml.MappingNode:
		if !checkKeysIn(n, where, subjectKeys, errs) {
			return Subject{}, false
		}
		if p := child(n, "packages"); p != nil && !checkKeysIn(p, where+".packages", packageKeys, errs) {
			return Subject{}, false
		}
		if err := n.Decode(&raw); err != nil {
			errs.addf("%s: %v", where, err)
			return Subject{}, false
		}
	default:
		errs.addf("%s must be a reference or a mapping with ref:", where)
		return Subject{}, false
	}
	if raw.Ref == "" {
		errs.addf("%s needs a ref", where)
		return Subject{}, false
	}
	r, err := ref.Parse(raw.Ref)
	if err != nil {
		errs.addf("%v", err)
		return Subject{}, false
	}
	s := Subject{Ref: r, Written: raw.Ref, Name: raw.Name, Platform: raw.Platform}
	if r.Kind == ref.SBOM {
		s.Ref.Path = resolve(dir, r.Path)
		s.Written = s.Ref.String()
	}
	if s.Platform == "" && cat != nil && r.Kind == ref.Image {
		s.Platform = cat.Platform
	}
	if s.Platform != "" && !platformFormat.MatchString(s.Platform) {
		errs.addf("%s: platform must be os/arch[/variant], got %q", where, s.Platform)
	}
	if raw.Packages != nil {
		if raw.Name == "" {
			errs.addf("%s (%s) sets packages: and so needs a name:, since one image can be listed with several filters", where, raw.Ref)
		}
		if len(raw.Packages.KeepTypes) == 0 {
			errs.addf("%s: packages.keepTypes must list at least one package type", where)
		}
		s.KeepTypes = slices.Sorted(slices.Values(raw.Packages.KeepTypes))
	}
	if s.Name == "" {
		s.Name = raw.Ref
	}
	return s, true
}

func checks(nodes []yaml.Node, registry map[string]CheckDef, hasReference bool, errs *problems) []Check {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	var raw []rawCheck
	for i := range nodes {
		where := fmt.Sprintf("checks[%d]", i)
		var rc rawCheck
		if !checkKeysIn(&nodes[i], where, checkKeys, errs) {
			continue
		}
		if err := nodes[i].Decode(&rc); err != nil {
			errs.addf("%s: %v", where, err)
			continue
		}
		raw = append(raw, rc)
	}
	if len(nodes) == 0 {
		errs.addf("a gate needs at least one check (checks: [{name: ...}]); known checks: %s", strings.Join(names, ", "))
		return nil
	}
	var out []Check
	seen := map[string]bool{}
	var needRef []string
	for _, rc := range raw {
		def, ok := registry[rc.Name]
		if !ok {
			errs.addf("unknown check %q (known: %s)", rc.Name, strings.Join(names, ", "))
			continue
		}
		if seen[rc.Name] {
			errs.addf("check %s is listed twice", rc.Name)
			continue
		}
		seen[rc.Name] = true
		if def.ReadsReference && !hasReference {
			needRef = append(needRef, rc.Name)
		}
		if c, ok := resolveCheck(rc, def, errs); ok {
			out = append(out, c)
		}
	}
	for _, n := range needRef {
		errs.addf("check %s reads the reference setup, and the gate has no reference:", n)
	}
	return out
}

// resolveCheck checks params against the check's definition: known names, numbers, whole where
// they must be, in range, every required one given.
func resolveCheck(rc rawCheck, def CheckDef, errs *problems) (Check, bool) {
	c := Check{Name: rc.Name, Params: map[string]float64{}}
	known := map[string]Param{}
	for _, p := range def.Params {
		known[p.Name] = p
	}
	ok := true
	keys := make([]string, 0, len(rc.Params))
	for k := range rc.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p, found := known[k]
		if !found {
			errs.addf("check %s has no param %q", rc.Name, k)
			ok = false
			continue
		}
		v, isNum := number(rc.Params[k])
		switch {
		case !isNum:
			errs.addf("check %s: %s must be a number, got %v", rc.Name, k, rc.Params[k])
		case p.Integer && v != math.Trunc(v):
			errs.addf("check %s: %s must be a whole number, got %v", rc.Name, k, v)
		case v < p.Min:
			errs.addf("check %s: %s must be at least %v, got %v", rc.Name, k, p.Min, v)
		case p.Max != nil && v > *p.Max:
			errs.addf("check %s: %s must be at most %v, got %v", rc.Name, k, *p.Max, v)
		default:
			c.Params[k] = v
			continue
		}
		ok = false
	}
	for _, p := range def.Params {
		if _, set := c.Params[p.Name]; set || rc.Params[p.Name] != nil {
			continue
		}
		if p.Default == nil {
			errs.addf("check %s needs %s (%s)", rc.Name, p.Name, p.Description)
			ok = false
			continue
		}
		c.Params[p.Name] = *p.Default
	}
	if len(c.Params) == 0 {
		c.Params = nil
	}
	return c, ok
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// isPath says whether a tool spec is a path to a binary rather than name@version.
func isPath(s string) bool {
	return strings.ContainsRune(s, filepath.Separator) || strings.HasPrefix(s, ".")
}

// canonical is a path absolute and with symlinks resolved, so the same file is spelled one way
// whatever directory yardstick runs from (on macOS, /var and /private/var), and a gate's
// fingerprint does not change with the spelling.
func canonical(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	return abs, nil
}

func resolve(dir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// HasReference says whether the gate compares two setups.
func (g *Gate) HasReference() bool {
	return g.Reference != nil
}

// Fingerprint identifies the gate's setups and subjects, but not its checks, undecided policy,
// catalog or claims sources. The last two only decide which SBOM a subject resolves to, and score
// checks that per subject against the recorded digest, so another claims source rescores the
// same scans.
func (g *Gate) Fingerprint() string {
	data, _ := json.Marshal(struct {
		Candidate *Setup    `json:"candidate"`
		Reference *Setup    `json:"reference"`
		Subjects  []Subject `json:"subjects"`
	}{g.Candidate, g.Reference, g.Subjects})
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
