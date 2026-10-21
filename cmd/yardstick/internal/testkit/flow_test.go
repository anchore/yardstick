package testkit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/anchore/yardstick/cmd/yardstick/internal/labelserver"
)

func post(t *testing.T, h http.Handler, token, path string, body, v any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set(labelserver.TokenHeader, token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && v != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code
}

// queue is GET /api/queue with the query given.
func queue(t *testing.T, h http.Handler, query string) labelserver.Queue {
	t.Helper()
	var q labelserver.Queue
	get(t, h, "/api/queue"+query, &q)
	return q
}

// hints is GET /api/hints with the query given.
func hints(t *testing.T, h http.Handler, query string) labelserver.HintsResponse {
	t.Helper()
	var out labelserver.HintsResponse
	get(t, h, "/api/hints"+query, &out)
	return out
}

// queueLines are a queue's entries as "<row> <effect>", in order.
func queueLines(q labelserver.Queue) []string {
	var out []string
	for _, e := range q.Entries {
		out = append(out, e.Row+" "+e.Effect)
	}
	return out
}

// hintLine is a hint as "<kind> <first vulnerability> <verdict> <group>[ replaces] <gate>:<rows>:<outcome>><after>...".
func hintLine(h labelserver.HintEntry) string {
	line := h.Kind + " " + h.Rows[0].Vulnerability + " " + string(h.Verdict) + " " + h.Group
	if h.Replaces {
		line += " replaces"
	}
	gates := slices.Clone(h.Gates)
	slices.SortFunc(gates, func(a, b labelserver.HintGate) int { return strings.Compare(a.Gate, b.Gate) })
	for _, g := range gates {
		line += " " + g.Gate + ":" + strconv.Itoa(len(g.Rows)) + ":" + string(g.Outcome) + ">" + string(g.After)
	}
	return line
}

// the labeling flow's endpoints over the seed: the queue, hint review, accepting every hint, and the
// history of what was written
func TestE2ELabelingFlow(t *testing.T) {
	srv, dir, tools, bin := e2eServer(t)
	h := srv.Handler()

	// every open change once, the tar row shared by both gates included: the rows that decide a gate
	// first (gzip and tar each pass deb-npm; no one label passes deb-java, whose unlabeled count
	// fails until the last), then the rest closest gate to done first, by image and in report order
	q := queue(t, h, "")
	want := []string{
		"5e50fe5b2007001a decides",
		"0fe9fc814bcd060a decides",
		"24160b879ac36bf5 counted",
		"d2572e8f87a44f74 counted",
		"781d813b74ed9e10 counted",
		"12fab8dbf4fcf9e8 counted",
		"e3bfd3b0b0c30ee6 counted",
		"9f5eb52729c83cc1 counted",
		"e1af7851f0e60bb4 could-move",
		"783bbb63489d81a6 could-move",
		"42c45bf99e4f741b could-move",
		"a88b3bd584c62516 could-move",
	}
	if got := queueLines(q); !slices.Equal(got, want) {
		t.Errorf("queue:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rows := map[string]int{}
	for _, g := range q.Gates {
		rows[g.Name] = g.Rows
		if g.Settled {
			t.Errorf("gate %s settled before anything is labeled", g.Name)
		}
	}
	if q.Settled || rows["deb-java"] != 10 || rows["deb-npm"] != 3 {
		t.Errorf("queue gates: settled %v, rows %v", q.Settled, rows)
	}
	tar := q.Entries[1]
	decides := map[string]bool{}
	for _, a := range tar.In {
		decides[a.Gate] = a.Decides
	}
	if len(tar.In) != 2 || !decides["deb-npm"] || decides["deb-java"] || tar.Hint == nil || tar.Hint.Confidence != "medium" || tar.Label != nil {
		t.Errorf("the shared tar entry: %+v", tar)
	}
	if vc5p := q.Entries[10]; vc5p.Label == nil || vc5p.Label.Verdict != "unclear" {
		t.Errorf("the vc5p entry's unclear label: %+v", vc5p.Label)
	}
	// scoped to deb-java, no row decides it, so they are in image and report order
	q = queue(t, h, "?scope=gate:deb-java")
	if got := queueLines(q); len(got) != 10 || got[0] != "d2572e8f87a44f74 counted" || !slices.Contains(got, "0fe9fc814bcd060a counted") || !slices.Contains(got, "e1af7851f0e60bb4 could-move") {
		t.Errorf("deb-java queue: %v", got)
	}
	q = queue(t, h, "?scope=image:"+npmSlug)
	if got := queueLines(q); !slices.Equal(got, []string{"24160b879ac36bf5 counted"}) {
		t.Errorf("npm image queue: %v", got)
	}

	// every pending hint, by what accepting it alone does: deciding ones first. Within a group they
	// are in gate list order, which two scans across a minute boundary swap, so compare sorted
	all := hints(t, h, "")
	var lines []string
	for _, x := range all.Hints {
		lines = append(lines, hintLine(x))
	}
	if g := all.Hints[len(all.Hints)-1].Group; g != "needed" {
		t.Errorf("the last hint's group: %s", g)
	}
	slices.Sort(lines)
	want = []string{
		"cause CVE-2026-3184 tp needed deb-java:4:fail>fail",
		"proposal CVE-2005-2541 fp decides deb-java:1:fail>fail deb-npm:1:fail>pass",
		"proposal CVE-2026-41992 fp decides deb-npm:1:fail>pass",
		"proposal GHSA-jfh8-c2jp-5v3q tp needed deb-java:2:fail>fail",
		"proposal GHSA-vc5p-v9hr-52mj tp needed replaces deb-java:2:fail>fail",
	}
	if !slices.Equal(lines, want) || all.Low != 0 {
		t.Errorf("hints (low %d):\n%s\nwant:\n%s", all.Low, strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	// the vc5p hint replaces a person's unclear label, whose note review shows as the reason
	if i := slices.IndexFunc(all.Hints, func(x labelserver.HintEntry) bool { return x.Replaces }); i < 0 || all.Hints[i].Rows[0].Label == nil ||
		all.Hints[i].Rows[0].Label.Note != "needs a look at the JNDI lookup config" {
		t.Errorf("the replacing hint's label: %+v", all.Hints)
	}
	if java := hints(t, h, "?image="+javaSlug); len(java.Hints) != 2 {
		t.Errorf("java hints: %d", len(java.Hints))
	}

	// preview every hint, as review does before accepting: deb-npm passes, deb-java still fails on the
	// one tar row no hint covers
	preview := map[string]map[string]string{}
	var ids []string
	for _, x := range all.Hints {
		ids = append(ids, x.ID)
		for _, g := range x.Gates {
			if preview[g.Gate] == nil {
				preview[g.Gate] = map[string]string{}
			}
			for _, r := range g.Rows {
				preview[g.Gate][r] = string(x.Verdict)
			}
		}
	}
	for gate, wantOutcome := range map[string]string{"deb-npm": "pass", "deb-java": "fail"} {
		var res labelserver.GateResult
		if code := post(t, h, srv.Token(), "/api/gates/"+gate+"/preview", map[string]any{"labels": preview[gate]}, &res); code != http.StatusOK || string(res.Outcome) != wantOutcome {
			t.Errorf("preview %s with every hint: %d %s", gate, code, res.Outcome)
		}
	}

	if code := post(t, h, "", "/api/hints/accept", labelserver.HintsAcceptRequest{Hints: ids}, nil); code != http.StatusForbidden {
		t.Errorf("accept without the token: %d", code)
	}
	if code := post(t, h, srv.Token(), "/api/hints/accept", labelserver.HintsAcceptRequest{Hints: []string{"nope"}}, nil); code != http.StatusBadRequest {
		t.Errorf("accept of no such hint: %d", code)
	}
	// one label per image match: the tar row in both gates once, log4j's two jars once per hint
	var acc labelserver.HintsAcceptResponse
	if code := post(t, h, srv.Token(), "/api/hints/accept", labelserver.HintsAcceptRequest{Hints: ids}, &acc); code != http.StatusOK {
		t.Fatalf("accept: %d", code)
	}
	lines = nil
	for _, a := range acc.Written {
		gates := slices.Sorted(slices.Values(a.Gates))
		name := strings.SplitN(strings.TrimPrefix(a.Label.Package, "pkg:"), "@", 2)[0]
		lines = append(lines, string(a.Label.Verdict)+" "+a.Label.Vulnerability+" "+name[strings.LastIndex(name, "/")+1:]+" "+strings.Join(a.Rows, ",")+" "+strings.Join(gates, ","))
		if a.Label.Author != "e2e" {
			t.Errorf("label %s by %q", a.Label.Vulnerability, a.Label.Author)
		}
	}
	slices.Sort(lines)
	want = []string{
		"fp CVE-2005-2541 tar 0fe9fc814bcd060a deb-java,deb-npm",
		"fp CVE-2026-41992 gzip 5e50fe5b2007001a deb-java,deb-npm",
		"tp CVE-2026-3184 libblkid1 d2572e8f87a44f74 deb-java,deb-npm",
		"tp CVE-2026-3184 libmount1 781d813b74ed9e10 deb-java,deb-npm",
		"tp CVE-2026-3184 mount 12fab8dbf4fcf9e8 deb-java,deb-npm",
		"tp CVE-2026-3184 util-linux 9f5eb52729c83cc1 deb-java,deb-npm",
		"tp GHSA-jfh8-c2jp-5v3q log4j-core e1af7851f0e60bb4,783bbb63489d81a6 deb-java",
		"tp GHSA-vc5p-v9hr-52mj log4j-core 42c45bf99e4f741b,a88b3bd584c62516 deb-java",
	}
	if !slices.Equal(lines, want) || len(acc.Skipped) != 0 {
		t.Errorf("accepted (skipped %v):\n%s\nwant:\n%s", acc.Skipped, strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	// the labels are the single accept's: the proposal's note carried over, in the image's file once
	tarLabel := acc.Written[slices.IndexFunc(acc.Written, func(a labelserver.AcceptedLabel) bool { return a.Label.Vulnerability == "CVE-2005-2541" })]
	if n := tarLabel.Label.NoteTexts(); len(n) != 1 || n[0] != "debian's tar 1.34+dfsg-1.2+deb12u1 carries the fix" {
		t.Errorf("tar label notes: %v", n)
	}
	debFile, err := os.ReadFile(filepath.Join(dir, "claims", tarLabel.File))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(debFile), `"CVE-2005-2541"`); n != 1 {
		t.Errorf("%s holds CVE-2005-2541 %d times", tarLabel.File, n)
	}
	// nothing is pending now, so a second accept writes nothing
	acc = labelserver.HintsAcceptResponse{}
	if code := post(t, h, srv.Token(), "/api/hints/accept", labelserver.HintsAcceptRequest{Hints: ids}, &acc); code != http.StatusOK || len(acc.Written) != 0 {
		t.Errorf("second accept: %d %+v", code, acc.Written)
	}

	// and the queue agrees with the preview: deb-npm passes, deb-java waits on the tar row with no hint
	q = queue(t, h, "")
	outcomes := map[string]string{}
	for _, g := range q.Gates {
		outcomes[g.Name] = string(g.Outcome)
	}
	if got := queueLines(q); !slices.Equal(got, []string{"e3bfd3b0b0c30ee6 decides", "24160b879ac36bf5 none"}) || outcomes["deb-java"] != "fail" || outcomes["deb-npm"] != "pass" || q.Settled {
		t.Errorf("queue after accepting every hint: %v %v settled %v", got, outcomes, q.Settled)
	}
	// tar CVE-2026-18508 is deb-java's last open row: fp passes it, tp fails the check on new false negatives
	if eff := q.Entries[0].In[0].Effect; eff == nil || eff.IfFP.Outcome != "pass" || len(eff.IfFP.Fails) != 0 || !slices.Equal(eff.IfTP.Fails, []string{"noNewFalseNegatives"}) {
		t.Errorf("the last deb-java row's effect: %+v", eff)
	}
	if left := hints(t, h, ""); len(left.Hints) != 0 {
		t.Errorf("hints after accepting all: %d", len(left.Hints))
	}
	// the stopping point: with tar CVE-2026-18508 fp, deb-java passes, and the babel row moves nothing
	if code := post(t, h, srv.Token(), "/api/gates/deb-java/labels", labelserver.LabelsRequest{Rows: []string{"e3bfd3b0b0c30ee6"}, Verdict: "fp", Justification: "fix-installed"}, nil); code != http.StatusOK {
		t.Fatalf("label tar CVE-2026-18508: %d", code)
	}
	if q = queue(t, h, ""); !q.Settled || !slices.Equal(queueLines(q), []string{"24160b879ac36bf5 none"}) {
		t.Errorf("queue when every gate is decided: settled %v %v", q.Settled, queueLines(q))
	}

	// history: the seeded four and the nine just written, newest first
	var hist labelserver.History
	get(t, h, "/api/history", &hist)
	if hist.Total != 13 || len(hist.Labels) != 13 || len(hist.Sources) != 1 {
		t.Fatalf("history: %d labels, sources %v", hist.Total, hist.Sources)
	}
	written := map[string]bool{}
	for _, l := range hist.Labels[:9] {
		written[l.Label.Vulnerability+" "+l.Package.Name] = true
	}
	for _, k := range []string{"CVE-2026-41992 gzip", "CVE-2005-2541 tar", "CVE-2026-18508 tar", "GHSA-jfh8-c2jp-5v3q log4j-core", "CVE-2026-3184 mount"} {
		if !written[k] {
			t.Errorf("history's newest nine lack %s: %v", k, written)
		}
	}
	i := slices.IndexFunc(hist.Labels, func(l labelserver.HistoryLabel) bool { return l.Label.Vulnerability == "CVE-2005-2541" })
	tarRows := hist.Labels[i].Rows
	slices.SortFunc(tarRows, func(a, b labelserver.GateRow) int { return strings.Compare(a.Gate, b.Gate) })
	if hl := hist.Labels[i]; hl.ImageName != "vulnerabilities-debian-12-tar-util-linux:617d48d" ||
		!slices.Equal(tarRows, []labelserver.GateRow{{Gate: "deb-java", Row: "0fe9fc814bcd060a"}, {Gate: "deb-npm", Row: "0fe9fc814bcd060a"}}) {
		t.Errorf("the tar label in history: %+v", hl)
	}
	hist = labelserver.History{}
	get(t, h, "/api/history?offset=10&limit=5", &hist)
	if hist.Total != 13 || len(hist.Labels) != 3 {
		t.Errorf("history's last page: %d of %d", len(hist.Labels), hist.Total)
	}
	// filtered by verdict and by text, as the history page asks
	hist = labelserver.History{}
	get(t, h, "/api/history?verdict=unclear", &hist)
	if hist.Total != 1 || hist.Labels[0].Label.Vulnerability != "GHSA-vc5p-v9hr-52mj" {
		t.Errorf("history's unclear labels: %+v", hist.Labels)
	}
	hist = labelserver.History{}
	get(t, h, "/api/history?q=GZIP", &hist)
	if hist.Total != 1 || hist.Labels[0].Package.Name != "gzip" {
		t.Errorf("history matching gzip: %+v", hist.Labels)
	}

	// an unclear hint stays out of review unless asked for, and out of the queue's entries
	cmd := exec.Command(bin, "claims", "agent", "propose", "--gate", "deb-npm")
	cmd.Dir, cmd.Env = dir, append(os.Environ(), "YARDSTICK_CACHE_DIR="+filepath.Join(tools, "cache"))
	cmd.Stdin = strings.NewReader(`{"row":"24160b879ac36bf5","verdict":"unclear","justification":"not-assessed","author":{"skill":"triage-deltas","model":"e2e"}}`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("propose: %v\n%s", err, out)
	}
	if without := hints(t, h, ""); len(without.Hints) != 0 || without.Low != 1 {
		t.Errorf("hints without low: %d, low %d", len(without.Hints), without.Low)
	}
	if with := hints(t, h, "?low=1"); len(with.Hints) != 1 || hintLine(with.Hints[0]) != "proposal GHSA-67hx-6x53-jw92 unclear none deb-npm:1:pass>pass" {
		t.Errorf("hints with low: %+v", with.Hints)
	}
	if q = queue(t, h, "?scope=image:"+npmSlug); len(q.Entries) != 1 || q.Entries[0].Hint != nil {
		t.Errorf("the babel entry keeps its unclear hint: %+v", q.Entries)
	}
	if q = queue(t, h, "?scope=image:"+npmSlug+"&low=1"); len(q.Entries) != 1 || q.Entries[0].Hint == nil {
		t.Errorf("the babel entry with low: %+v", q.Entries)
	}
}

// rowVerdict is a row's verdict in a gate's state.
func rowVerdict(t *testing.T, h http.Handler, gate, row string) string {
	t.Helper()
	var st state
	get(t, h, "/api/gates/"+gate+"/state", &st)
	for _, s := range st.Subjects {
		for _, r := range s.Rows {
			if r.Row == row {
				return r.Verdict
			}
		}
	}
	t.Fatalf("no row %s in %s", row, gate)
	return ""
}

// undo through history: a write's keys revert it, since= reads lastUpdated, and once the writable
// source's label is gone the label an earlier source holds decides the row again
func TestE2EHistoryUndo(t *testing.T) {
	srv, dir, _, _ := e2eServer(t)
	h := srv.Handler()
	const gzip = "5e50fe5b2007001a"
	history := func(query string) labelserver.History {
		t.Helper()
		var out labelserver.History
		get(t, h, "/api/history"+query, &out)
		return out
	}

	// the seeded labels predate the server, so since=start shows none of them
	if hist := history("?since=start"); hist.Total != 0 || hist.Started == "" {
		t.Errorf("history since start: %d labels, started %q", hist.Total, hist.Started)
	}
	if code := post(t, h, srv.Token(), "/api/gates/deb-npm/labels", labelserver.LabelsRequest{Rows: []string{gzip}, Verdict: "fp", Justification: "fix-installed"}, nil); code != http.StatusOK {
		t.Fatalf("label gzip fp: %d", code)
	}
	// the gzip fp, old, in a corpus read before ./claims as well: deb-npm's sources are now two
	var hist labelserver.History
	if hist = history("?since=start"); hist.Total != 1 {
		t.Fatalf("history after the fp: %d", hist.Total)
	}
	file, written := hist.Labels[0].File, hist.Labels[0].Label.LastUpdated
	claimsFile := filepath.Join(dir, "claims", filepath.FromSlash(file))
	data, err := os.ReadFile(claimsFile)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), written, "2026-01-01T00:00:00Z"))
	for _, p := range []string{claimsFile, filepath.Join(dir, "corpus", filepath.FromSlash(file))} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gateFile := filepath.Join(dir, "gates", "deb-npm.yaml")
	gate, err := os.ReadFile(gateFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateFile, []byte(strings.Replace(string(gate), "claims: [../claims]", "claims: [../corpus, ../claims]", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if hist = history("?since=start"); hist.Total != 0 || history("").Total != 5 {
		t.Errorf("history once the fp is old: %d since start, %d in all", hist.Total, history("").Total)
	}
	if v := rowVerdict(t, h, "deb-npm", gzip); v != "fp" {
		t.Fatalf("gzip with both sources fp: %s", v)
	}

	// a tp in ./claims replaces the fp there, keeping its firstIssued, and outweighs the corpus's fp
	var res labelserver.LabelsResponse
	if code := post(t, h, srv.Token(), "/api/gates/deb-npm/labels", labelserver.LabelsRequest{Rows: []string{gzip}, Verdict: "tp"}, &res); code != http.StatusOK || len(res.Labels) != 1 {
		t.Fatalf("label gzip tp: %d %+v", code, res.Labels)
	}
	if k := res.Labels[0]; k.File != file || k.Vulnerability != "CVE-2026-41992" || !strings.HasPrefix(k.Package, "pkg:deb/debian/gzip@") {
		t.Errorf("the tp's key: %+v", k)
	}
	if hist = history("?since=start"); hist.Total != 1 || hist.Labels[0].Label.FirstIssued != "2026-01-01T00:00:00Z" || hist.Labels[0].Label.Verdict != "tp" {
		t.Errorf("history since start after the replace: %+v", hist.Labels)
	}
	if hist = history("?since=2099-01-01T00:00:00Z"); hist.Total != 0 {
		t.Errorf("history since a later time: %d", hist.Total)
	}
	if v := rowVerdict(t, h, "deb-npm", gzip); v != "tp" {
		t.Errorf("gzip with the last source's tp: %s", v)
	}

	revert := func(token string, keys []labelserver.LabelKey) int {
		t.Helper()
		return post(t, h, token, "/api/history/revert", labelserver.RevertRequest{Labels: keys}, nil)
	}
	if code := revert("", res.Labels); code != http.StatusForbidden {
		t.Errorf("revert without the token: %d", code)
	}
	other := res.Labels[0]
	other.Source = filepath.Join(dir, "corpus")
	if code := revert(srv.Token(), []labelserver.LabelKey{other}); code != http.StatusBadRequest {
		t.Errorf("revert from a source that is not writable: %d", code)
	}
	var rev labelserver.RevertResponse
	if code := post(t, h, srv.Token(), "/api/history/revert", labelserver.RevertRequest{Labels: res.Labels}, &rev); code != http.StatusOK || rev.Removed != 1 {
		t.Fatalf("revert the tp: %d %+v", code, rev)
	}
	// the corpus's fp decides again, and ./claims no longer holds the key
	if v := rowVerdict(t, h, "deb-npm", gzip); v != "fp" {
		t.Errorf("gzip after the revert: %s", v)
	}
	if hist = history(""); hist.Total != 4 || slices.ContainsFunc(hist.Labels, func(l labelserver.HistoryLabel) bool { return l.Label.Vulnerability == "CVE-2026-41992" }) {
		t.Errorf("history after the revert: %d", hist.Total)
	}
	if code := revert(srv.Token(), res.Labels); code != http.StatusBadRequest {
		t.Errorf("revert of a label no longer in ./claims: %d", code)
	}
}
