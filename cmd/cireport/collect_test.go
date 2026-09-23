package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub serves the REST endpoints the reporter reads, from fixtures.
type fakeGitHub struct {
	t         *testing.T
	runs      map[int64]fixture
	artifacts map[int64][]apiArtifact // by run id
	zips      map[int64][]byte        // by artifact id
	named     map[string][]apiArtifact
	files     map[string][]byte // "path@ref"
	wfRuns    map[string][]apiRun
	mu        sync.Mutex
	fetched   []string
}

func newFake(t *testing.T) *fakeGitHub {
	return &fakeGitHub{t: t, runs: map[int64]fixture{}, artifacts: map[int64][]apiArtifact{}, zips: map[int64][]byte{},
		named: map[string][]apiArtifact{}, files: map[string][]byte{}, wfRuns: map[string][]apiRun{}}
}

func (f *fakeGitHub) addArtifact(runID, id int64, name string, zipData []byte) {
	a := apiArtifact{ID: id, Name: name, SizeInBytes: int64(len(zipData))}
	a.WorkflowRun.ID = runID
	f.artifacts[runID] = append(f.artifacts[runID], a)
	f.zips[id] = zipData
	f.named[name] = append(f.named[name], a)
}

var (
	reJobs      = regexp.MustCompile(`^actions/runs/(\d+)/attempts/(\d+)/jobs$`)
	reRunArts   = regexp.MustCompile(`^actions/runs/(\d+)/artifacts$`)
	reZip       = regexp.MustCompile(`^actions/artifacts/(\d+)/zip$`)
	reBlob      = regexp.MustCompile(`^/blob/(\d+)$`)
	reWfRuns    = regexp.MustCompile(`^actions/workflows/([^/]+)/runs$`)
	reRun       = regexp.MustCompile(`^actions/runs/(\d+)$`)
	reRunAttmpt = regexp.MustCompile(`^actions/runs/(\d+)/attempts/(\d+)$`)
)

func atoi(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.fetched = append(f.fetched, r.URL.Path)
	f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/repos/o/r/")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if m := reJobs.FindStringSubmatch(p); m != nil {
		jobs := f.runs[atoi(m[1])].Jobs
		write(map[string]any{"total_count": len(jobs), "jobs": jobs})
		return
	}
	if m := reRunArts.FindStringSubmatch(p); m != nil {
		write(map[string]any{"artifacts": f.artifacts[atoi(m[1])]})
		return
	}
	if m := reZip.FindStringSubmatch(p); m != nil {
		// #nosec G710 -- test double: the target is this server's own /blob path and m[1] matched \d+
		http.Redirect(w, r, "/blob/"+m[1], http.StatusFound)
		return
	}
	if m := reBlob.FindStringSubmatch(r.URL.Path); m != nil {
		_, _ = w.Write(f.zips[atoi(m[1])])
		return
	}
	if p == "actions/artifacts" {
		write(map[string]any{"artifacts": f.named[r.URL.Query().Get("name")]})
		return
	}
	if m := reWfRuns.FindStringSubmatch(p); m != nil {
		var out []apiRun
		for runI := range f.wfRuns[m[1]] {
			run := &f.wfRuns[m[1]][runI]
			if ev := r.URL.Query().Get("event"); ev == "" || ev == run.Event {
				out = append(out, *run)
			}
		}
		write(map[string]any{"workflow_runs": out})
		return
	}
	if strings.HasPrefix(p, "contents/") {
		b, ok := f.files[strings.TrimPrefix(p, "contents/")+"@"+r.URL.Query().Get("ref")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		write(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString(b)})
		return
	}
	m := reRun.FindStringSubmatch(p)
	if m == nil {
		m = reRunAttmpt.FindStringSubmatch(p)
	}
	if m != nil {
		fx, ok := f.runs[atoi(m[1])]
		if !ok {
			http.NotFound(w, r)
			return
		}
		write(fx.Run)
		return
	}
	f.t.Errorf("unexpected request %s", r.URL)
	http.NotFound(w, r)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCollectRun_EndToEnd(t *testing.T) {
	fx, ev := qaAuditRun(t)
	fake := newFake(t)
	fake.runs[fx.Run.ID] = fx
	id := int64(100)
	fake.addArtifact(fx.Run.ID, id, "qa-race-verdict", makeZip(t, map[string][]byte{
		"verdict.json": mustJSON(t, ev.Verdict), "results.json": mustJSON(t, ev.Results), "merged.cover.out": []byte("mode: atomic\n")}))
	for i := 0; i < 4; i++ {
		id++
		fake.addArtifact(fx.Run.ID, id, fmt.Sprintf("qa-race-shard-%d", i), makeZip(t, map[string][]byte{"meta.json": mustJSON(t, ev.ShardMetas[i])}))
	}
	id++
	fake.addArtifact(fx.Run.ID, id, "qa-audit-compare", makeZip(t, map[string][]byte{
		"comparison.json": mustJSON(t, ev.Comparison), "qa-root-shard-timings.json": ev.CandidateRaw}))
	id++
	buildID := id
	fake.addArtifact(fx.Run.ID, buildID, "qa-race-build", makeZip(t, map[string][]byte{"root.test": []byte("\x7fELF")}))
	fake.files[committedTimingsPath+"@"+fx.Run.HeadSHA] = []byte(`{"source":"qa-gate run 35866546559 @ a606f82","package":"p","tests":{"TestA":1}}`)

	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, err := newGHClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	committed := filepath.Join(dir, "committed.json")
	if err := os.WriteFile(committed, []byte(`{"source":"old","package":"p","tests":{"FuzzSanitizeLog":0.5,"TestGone":2}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	summary := filepath.Join(dir, "step-summary.md")
	rep, err := collectRun(context.Background(), c, runOpts{repo: "o/r", runID: fx.Run.ID, committedTimings: committed,
		outDir: filepath.Join(dir, "out"), summary: summary, collector: Collector{RunID: 9, SHA: "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Evidence.Audit.State != "passed" || rep.Evidence.Verdict != "ok" || rep.Toolchain == nil || len(rep.Problems) != 0 {
		t.Fatalf("report: audit=%s verdict=%s toolchain=%v problems=%v unknowns=%v", rep.Evidence.Audit.State, rep.Evidence.Verdict, rep.Toolchain, rep.Problems, rep.Unknowns)
	}
	if rep.Config.TimingFileSource != "qa-gate run 35866546559 @ a606f82" {
		t.Errorf("timing file source %q", rep.Config.TimingFileSource)
	}
	for _, p := range fake.fetched {
		if strings.HasSuffix(p, fmt.Sprintf("/artifacts/%d/zip", buildID)) {
			t.Fatal("the reporter downloaded qa-race-build — the artifact that carries the test binary")
		}
	}
	for _, f := range []string{"out/report.json", "out/summary.md", "out/timing-candidate/qa-root-shard-timings.json", "out/timing-candidate/diff.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing output %s: %v", f, err)
		}
	}
	var back RunReport
	b, _ := os.ReadFile(filepath.Join(dir, "out", "report.json"))
	if err := json.Unmarshal(b, &back); err != nil || back.Schema != runReportSchema || back.Collector.RunID != 9 {
		t.Errorf("report.json round trip: %v %+v", err, back.Collector)
	}
	var diff CandidateDiff
	b, _ = os.ReadFile(filepath.Join(dir, "out", "timing-candidate", "diff.json"))
	if err := json.Unmarshal(b, &diff); err != nil || diff.Removed != 1 || diff.Added != 39 || diff.CommittedEntries != 2 || diff.RemovedNames[0] != "TestGone" {
		t.Errorf("candidate diff %+v err %v, want TestGone removed and 39 of 40 added", diff, err)
	}
	s, _ := os.ReadFile(summary)
	if !strings.Contains(string(s), "not a bill") || !strings.Contains(string(s), "never auto-committed") {
		t.Errorf("step summary lacks the runner-minute caveat or the candidate notice:\n%s", s)
	}
}

// With no artifacts at all (expired, never uploaded) the report still
// completes, and says evidence is missing rather than reporting health.
func TestCollectRun_NoArtifactsIsUnknownNotHealthy(t *testing.T) {
	fx := loadFixture(t, "fast-pr-code")
	fake := newFake(t)
	fake.runs[fx.Run.ID] = fx
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, _ := newGHClient(srv.URL, "")
	rep, err := collectRun(context.Background(), c, runOpts{repo: "o/r", runID: fx.Run.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Evidence.Verdict != "missing" || rep.Race != nil {
		t.Errorf("verdict %s race %v, want missing/nil", rep.Evidence.Verdict, rep.Race)
	}
	joined := strings.Join(rep.Unknowns, "\n")
	for _, want := range []string{"verdict.json was not readable", "timing file at head_sha unreadable"} {
		if !strings.Contains(joined, want) {
			t.Errorf("unknowns lack %q: %v", want, rep.Unknowns)
		}
	}
}
