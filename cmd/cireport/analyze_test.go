package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures under testdata/runs are REAL GitHub API payloads (run + that
// attempt's jobs, trimmed to the fields read) captured from KidCarmi/Culvert,
// so classification and timing are tested against what GitHub actually emits:
// skipped jobs stamped complete-before-start, re-runs that carry earlier
// attempts' jobs, cancellations, dispatch titles, the pre-5C race job.

type fixture struct {
	Run  apiRun   `json:"run"`
	Jobs []apiJob `json:"jobs"`
}

func loadFixture(t *testing.T, name string) fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "runs", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var fx fixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return fx
}

func loadEvidenceFile(t *testing.T, name string, v any) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "evidence", name))
	if err != nil {
		t.Fatalf("evidence %s: %v", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("evidence %s: %v", name, err)
	}
	return b
}

func TestAnalyze_ClassifiesRealExecutions(t *testing.T) {
	for _, tc := range []struct {
		fixture, class, key, verdict, audit string
		rerun                               bool
	}{
		{"fast-pr-code", classPRCode, "race", "missing", "not-requested", false},
		{"fast-pr-docs", classPRDocsOnly, "minimal", "not-run", "not-requested", false},
		{"fast-pr-cancelled", classPRCode, "race", "missing", "not-requested", false},
		{"fast-pr-failure", classPRCode, "race", "missing", "not-requested", false},
		{"fast-dispatch-audit", classManualAudit, "race+audit+frontend+mcp+maint", "missing", "unknown", false},
		// Before run-name existed, the classifier-fails fault left no trace:
		// the reporter can only say "manual" — never invent a fault.
		{"fast-dispatch-a", classManualQualify, "minimal", "not-run", "not-requested", false},
		{"fast-dispatch-b", classFaultInjection, "race+frontend+mcp+maint", "missing", "not-requested", false},
		{"fast-rerun", classPRCode, "race-unsharded+frontend", "missing", "not-requested", true},
		{"qa-push", classMainQA, "race+qa-layers", "missing", "not-requested", false},
		{"qa-push-cancelled", classMainQA, "qa-layers", "missing", "not-requested", false},
		{"qa-dispatch-audit", classManualAudit, "race+audit+qa-layers", "missing", "unknown", false},
		{"qa-dispatch-cancelled", classManualAudit, "race+audit+qa-layers", "missing", "failed", false},
		{"qa-pr-passthrough", classPRPassThrough, "minimal", "not-run", "not-requested", false},
		{"qa-rerun", classManualAudit, "race+audit+qa-layers", "missing", "unknown", true},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			fx := loadFixture(t, tc.fixture)
			r := Analyze(fx.Run, fx.Jobs, runEvidence{})
			if r.Class != tc.class || r.JobSet.Key != tc.key || r.Evidence.Verdict != tc.verdict || r.Evidence.Audit.State != tc.audit || r.Run.Rerun != tc.rerun {
				t.Errorf("got class=%s key=%s verdict=%s audit=%s rerun=%v; want %s %s %s %s %v (reasons: %v)",
					r.Class, r.JobSet.Key, r.Evidence.Verdict, r.Evidence.Audit.State, r.Run.Rerun,
					tc.class, tc.key, tc.verdict, tc.audit, tc.rerun, r.Reasons)
			}
			if r.Schema != runReportSchema || r.Timing.RunnerMinutesNote == "" {
				t.Error("every report carries its schema and the runner-minutes caveat")
			}
		})
	}
}

func ts(base time.Time, s int) string {
	return base.Add(time.Duration(s) * time.Second).Format(time.RFC3339)
}

func synthJob(base time.Time, name, concl string, created, start, end int) apiJob {
	return apiJob{Name: name, Status: "completed", Conclusion: concl, CreatedAt: ts(base, created),
		StartedAt: ts(base, start), CompletedAt: ts(base, end), RunAttempt: 1,
		Steps: []apiStep{
			{Name: "Set up job", Conclusion: "success", StartedAt: ts(base, start), CompletedAt: ts(base, start+2)},
			{Name: "Run actions/checkout@x", Conclusion: "success", StartedAt: ts(base, start+2), CompletedAt: ts(base, start+5)},
			{Name: "do the work", Conclusion: concl, StartedAt: ts(base, start+5), CompletedAt: ts(base, end-1)},
			{Name: "Complete job", Conclusion: "success", StartedAt: ts(base, end-1), CompletedAt: ts(base, end)},
		}}
}

// Four 400-second shards in parallel must read as ~400 s of elapsed time and
// ~1,600 s of runner time. Summing parallel durations as wall time is the
// error this report exists to avoid.
func TestAnalyze_ParallelJobsDoNotInflateElapsed(t *testing.T) {
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	run := apiRun{ID: 1, Path: fastWorkflowPath, Event: "pull_request", RunAttempt: 1, Status: "completed", Conclusion: "success",
		CreatedAt: ts(base, 0), RunStartedAt: ts(base, 0)}
	jobs := []apiJob{synthJob(base, "Gate · go test -race (sharded) / Race · compile root once + partition", "success", 0, 3, 100)}
	for i := 0; i < 4; i++ {
		jobs = append(jobs, synthJob(base, fmt.Sprintf("Gate · go test -race (sharded) / Race · root shard %d", i), "success", 100, 102, 502))
	}
	jobs = append(jobs, synthJob(base, "Gate · go test -race (sharded) / "+raceVerdictJobSuffix, "success", 502, 504, 540),
		synthJob(base, "✅ Fast PR Gate — APPROVED", "success", 540, 541, 545))
	r := Analyze(run, jobs, runEvidence{})

	if r.Timing.ElapsedToAggregate == nil || *r.Timing.ElapsedToAggregate != 545 {
		t.Fatalf("elapsed to aggregate = %v, want 545 (the aggregate's completion, not a sum)", fmtSecs(r.Timing.ElapsedToAggregate))
	}
	if *r.Timing.ElapsedToRaceVerdict != 540 {
		t.Errorf("elapsed to race verdict = %v, want 540", *r.Timing.ElapsedToRaceVerdict)
	}
	sum := 97.0 + 4*400 + 36 + 4 // every job's duration, parallel ones in full
	if got := r.Timing.RunnerMinutes; got != float64(int(sum/60*10+0.5))/10 {
		t.Errorf("runner-minutes = %v, want %.1f (summed job time)", got, sum/60)
	}
	if r.Timing.Busy >= sum || r.Timing.Busy > 545 {
		t.Errorf("busy = %v: the union of intervals must count overlapping shards once", r.Timing.Busy)
	}
	if r.Timing.WallSpan != 545 {
		t.Errorf("wall span = %v, want 545", r.Timing.WallSpan)
	}
	if r.Timing.Queue.Max != 3 || r.Timing.Setup.Median != 5 {
		t.Errorf("queue max %v / setup median %v, want 3 / 5 (created→started; Set up job + checkout)", r.Timing.Queue.Max, r.Timing.Setup.Median)
	}

	// The same property on a real execution: runner time far exceeds wall
	// time, and elapsed never exceeds the span.
	fx := loadFixture(t, "fast-pr-code")
	live := Analyze(fx.Run, fx.Jobs, runEvidence{})
	if live.Timing.RunnerMinutes*60 < 2*live.Timing.WallSpan || *live.Timing.ElapsedToAggregate > live.Timing.WallSpan {
		t.Errorf("real run: runner %.1f min vs wall %.0f s vs elapsed %v — parallel time leaked into elapsed", live.Timing.RunnerMinutes, live.Timing.WallSpan, *live.Timing.ElapsedToAggregate)
	}
}

// A re-run attempt carries the earlier attempt's jobs with timestamps from
// before the attempt started. They must not count toward this attempt.
func TestAnalyze_RerunExcludesCarriedOverJobs(t *testing.T) {
	fx := loadFixture(t, "fast-rerun")
	r := Analyze(fx.Run, fx.Jobs, runEvidence{})
	if len(r.JobSet.CarriedOver) != 9 {
		t.Fatalf("carried over = %v, want the 9 attempt-1 jobs", r.JobSet.CarriedOver)
	}
	var names []string
	for _, j := range r.JobSet.Executed {
		names = append(names, j.Name)
	}
	if len(names) != 2 || r.Timing.RunnerMinutes > 4 {
		t.Errorf("attempt 2 executed %v (%.1f runner-min); want only the re-run perf job and the aggregate", names, r.Timing.RunnerMinutes)
	}
	if !strings.Contains(strings.Join(r.Unknowns, "\n"), "re-run attempt") {
		t.Errorf("a re-run must say its evidence may belong to an earlier attempt: %v", r.Unknowns)
	}
}

func TestAnalyze_CancelledAndFailedStayVisible(t *testing.T) {
	for _, name := range []string{"fast-pr-cancelled", "qa-push-cancelled", "qa-dispatch-cancelled", "fast-pr-failure"} {
		fx := loadFixture(t, name)
		r := Analyze(fx.Run, fx.Jobs, runEvidence{})
		if r.Run.Conclusion != fx.Run.Conclusion || r.Run.Conclusion == "success" {
			t.Errorf("%s: conclusion %q must be carried through unchanged", name, r.Run.Conclusion)
		}
		if r.Evidence.Audit.State == "passed" || r.Evidence.Verdict == "ok" {
			t.Errorf("%s: a %s run with no evidence reported audit=%s verdict=%s", name, r.Run.Conclusion, r.Evidence.Audit.State, r.Evidence.Verdict)
		}
	}
}

// qaAuditRun is the real audit dispatch paired with its OWN published evidence
// (the verdict and comparison of run 35874102885 at fef1fd0).
func qaAuditRun(t *testing.T) (fixture, runEvidence) {
	fx := loadFixture(t, "qa-dispatch-audit")
	var ev runEvidence
	var v evVerdict
	loadEvidenceFile(t, "verdict.json", &v)
	ev.Verdict = &v
	var c evComparison
	loadEvidenceFile(t, "comparison.json", &c)
	ev.Comparison = &c
	var cand evTimings
	ev.CandidateRaw = loadEvidenceFile(t, "qa-root-shard-timings.json", &cand)
	ev.Candidate = &cand
	ev.ShardMetas = map[int]*evShardMeta{}
	for i := 0; i < 4; i++ {
		ev.ShardMetas[i] = &evShardMeta{Shard: i, Commit: v.Commit, GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64"}
	}
	ev.Results = map[string]*evPkgResult{v.Package: {Status: "pass", Tests: map[string]*evTestResult{
		"TestA": {Status: "pass", Seconds: 3}, "TestB": {Status: "pass", Seconds: 48.4}, "TestC": {Status: "pass", Seconds: 0.1}}}}
	return fx, ev
}

func TestAnalyze_RealAuditEvidence(t *testing.T) {
	fx, ev := qaAuditRun(t)
	r := Analyze(fx.Run, fx.Jobs, ev)
	if len(r.Problems) != 0 {
		t.Fatalf("consistent evidence reported problems: %v", r.Problems)
	}
	if r.Evidence.Verdict != "ok" || r.Evidence.Audit.State != "passed" || !r.Evidence.Audit.TimingCandidate {
		t.Fatalf("verdict=%s audit=%s candidate=%v, want ok/passed/true", r.Evidence.Verdict, r.Evidence.Audit.State, r.Evidence.Audit.TimingCandidate)
	}
	// The same passing evidence on a re-run attempt publishes no candidate.
	rerun := fx.Run
	rerun.RunAttempt = 2
	if rr := Analyze(rerun, fx.Jobs, ev); rr.Evidence.Audit.TimingCandidate {
		t.Error("a re-run attempt published a timing candidate built from per-run, possibly mixed-attempt artifacts")
	}
	if r.Run.TestedSHA != fx.Run.HeadSHA || r.Toolchain == nil || r.Toolchain.Go != "go1.26.6" || r.Config.Shards != 4 {
		t.Errorf("tested=%s toolchain=%v shards=%d", r.Run.TestedSHA, r.Toolchain, r.Config.Shards)
	}
	rs := r.Race
	if rs == nil || len(rs.Shards) != 4 || rs.Inventory.RootEntries != 6381 || rs.Lane.Packages != 111 {
		t.Fatalf("race stats %+v, want 4 shards / 6381 root entries / 111 lane packages", rs)
	}
	for _, s := range rs.Shards {
		if s.Job == nil || *s.Job < s.Test {
			t.Errorf("shard %d: job %v s is shorter than its test time %.0f s", s.Index, fmtSecs(s.Job), s.Test)
		}
	}
	if rs.Imbalance.MaxOverMean < 1 || rs.Imbalance.SpreadSeconds <= 0 || len(rs.Lane.Slowest) != 5 {
		t.Errorf("imbalance %+v slowest packages %v", rs.Imbalance, rs.Lane.Slowest)
	}
	if len(rs.SlowestRootTests) == 0 || rs.SlowestRootTests[0].Name != "TestB" {
		t.Errorf("slowest root tests %v", rs.SlowestRootTests)
	}
	if r.Evidence.Audit.BlocksLost != 0 || r.Evidence.Audit.BlocksGained != 1 {
		t.Errorf("audit lost/gained = %d/%d, want 0/1 (the run's own comparison)", r.Evidence.Audit.BlocksLost, r.Evidence.Audit.BlocksGained)
	}
}

func TestAnalyze_MismatchedIdentitiesAreProblems(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(fx *fixture, ev *runEvidence)
		want string
	}{
		{"verdict for another commit", func(_ *fixture, ev *runEvidence) {
			v := *ev.Verdict
			v.Commit = "0000000000000000000000000000000000000000"
			ev.Verdict = &v
		}, "is not the run's head_sha"},
		{"shard ran another commit", func(_ *fixture, ev *runEvidence) {
			ev.ShardMetas[2] = &evShardMeta{Shard: 2, Commit: "ffffffff", GoVersion: "go1.26.6", GOOS: "linux", GOARCH: "amd64"}
		}, "shard 2 ran commit"},
		{"shards disagree on the toolchain", func(_ *fixture, ev *runEvidence) {
			ev.ShardMetas[3] = &evShardMeta{Shard: 3, Commit: ev.Verdict.Commit, GoVersion: "go1.25.0", GOOS: "linux", GOARCH: "amd64"}
		}, "reports toolchain"},
		{"candidate from another run", func(_ *fixture, ev *runEvidence) {
			c := *ev.Candidate
			c.Source = "qa-gate run 1 @ " + ev.Verdict.Commit
			ev.Candidate = &c
		}, "timing candidate source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx, ev := qaAuditRun(t)
			tc.mut(&fx, &ev)
			r := Analyze(fx.Run, fx.Jobs, ev)
			if !strings.Contains(strings.Join(r.Problems, "\n"), tc.want) {
				t.Errorf("problems %v do not mention %q", r.Problems, tc.want)
			}
			if tc.name == "candidate from another run" && r.Evidence.Audit.TimingCandidate {
				t.Error("a candidate whose provenance names another run must not be published")
			}
		})
	}
}

func auditJobs(base time.Time, refConcl, cmpConcl string) []apiJob {
	mk := func(name, concl string) apiJob {
		if concl == "skipped" {
			return apiJob{Name: name, Status: "completed", Conclusion: "skipped", CreatedAt: ts(base, 10), StartedAt: ts(base, 10), CompletedAt: ts(base, 9)}
		}
		return synthJob(base, name, concl, 10, 11, 900)
	}
	return []apiJob{mk(auditReferenceJob, refConcl), mk(auditCompareJob, cmpConcl), synthJob(base, "✅ QA Gate — APPROVED", "success", 901, 902, 905)}
}

// A requested audit that did not execute is "missing" and one whose comparison
// could not be read is "unknown": neither is ever "passed".
func TestAnalyze_UnexecutedOrUnreadableAuditNeverPasses(t *testing.T) {
	base := time.Date(2026, 9, 7, 4, 0, 0, 0, time.UTC)
	run := apiRun{ID: 7, Path: qaWorkflowPath, Event: "schedule", RunAttempt: 1, Status: "completed", Conclusion: "success",
		HeadBranch: "main", CreatedAt: ts(base, 0), RunStartedAt: ts(base, 0), DisplayTitle: "QA Gate · scheduled equivalence audit"}
	okCmp := &evComparison{OK: true}
	for _, tc := range []struct {
		name     string
		ref, cmp string
		ev       runEvidence
		want     string
	}{
		{"both skipped", "skipped", "skipped", runEvidence{}, "missing"},
		{"compare skipped", "success", "skipped", runEvidence{Comparison: okCmp}, "missing"},
		{"no comparison artifact", "success", "success", runEvidence{}, "unknown"},
		{"comparison refused", "success", "failure", runEvidence{Comparison: &evComparison{OK: false, Lost: []string{"x.go:1.1,2.2"}}}, "failed"},
		{"reference failed", "failure", "success", runEvidence{Comparison: okCmp}, "failed"},
		{"everything passed", "success", "success", runEvidence{Comparison: okCmp}, "passed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(run, auditJobs(base, tc.ref, tc.cmp), tc.ev)
			if r.Class != classScheduledAudit || !r.Evidence.Audit.Requested {
				t.Fatalf("class %s requested %v", r.Class, r.Evidence.Audit.Requested)
			}
			if r.Evidence.Audit.State != tc.want {
				t.Errorf("audit state %q, want %q", r.Evidence.Audit.State, tc.want)
			}
		})
	}
}

// The workflows' run-name publishes the dispatch inputs; the fault class also
// follows an executed fault step even with no title.
func TestAnalyze_FaultAndAuditFromRunName(t *testing.T) {
	fx := loadFixture(t, "fast-dispatch-a")
	fx.Run.DisplayTitle = "Fast PR Gate · dispatch · audit=false · fault=classifier-fails"
	if r := Analyze(fx.Run, fx.Jobs, runEvidence{}); r.Class != classFaultInjection || r.Config.Fault != "classifier-fails" {
		t.Errorf("class %s fault %q, want fault-injection/classifier-fails", r.Class, r.Config.Fault)
	}
	fx.Run.DisplayTitle = "Fast PR Gate · dispatch · audit=true · fault=none"
	if r := Analyze(fx.Run, fx.Jobs, runEvidence{}); r.Class != classManualAudit || r.Evidence.Audit.State != "missing" {
		t.Errorf("audit=true with no audit jobs: class %s audit %s, want manual-audit/missing", r.Class, r.Evidence.Audit.State)
	}
	// A pull request's display title is its author's text, not a run-name: it
	// must not be able to reclassify the run or claim an audit.
	pr := loadFixture(t, "fast-pr-code")
	pr.Run.DisplayTitle = "tidy: audit=true fault=classifier-fails"
	if r := Analyze(pr.Run, pr.Jobs, runEvidence{}); r.Class != classPRCode || r.Config.Fault != "" || r.Evidence.Audit.State != "not-requested" {
		t.Errorf("a PR title was trusted as a run-name: class %s fault %q audit %s", r.Class, r.Config.Fault, r.Evidence.Audit.State)
	}
}
