package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testBaseline(status string) Baseline {
	var b Baseline
	b.Schema, b.Status, b.MinSamples, b.MaxSamples = baselineSchema, status, 10, 20
	b.Regression.Ratio, b.Regression.Consecutive = 1.25, 3
	b.Audit.Workflow, b.Audit.Introduced, b.Audit.MaxAgeDays = "qa-gate.yml", "2026-09-01", 8
	return b
}

func f64(v float64) *float64 { return &v }

// sample builds a report in one group with the given outcome and timing.
func sample(id int64, day int, concl string, attempt int, elapsed float64, class, key string) Sample {
	r := RunReport{Schema: runReportSchema, Class: class}
	r.Run = RunIdentity{RunID: id, Attempt: attempt, Rerun: attempt > 1, Status: "completed", Conclusion: concl,
		WorkflowPath: fastWorkflowPath, Event: "pull_request",
		CreatedAt: time.Date(2026, 9, day, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)}
	r.JobSet.Key = key
	r.Timing.ElapsedToAggregate = f64(elapsed)
	r.Timing.RunnerMinutes = elapsed / 10
	r.Evidence.Verdict = "ok"
	return Sample{Report: r, Source: "per-run-report"}
}

func findGroup(t *testing.T, tr TrendReport, class, key string) GroupStats {
	t.Helper()
	for _, g := range tr.Groups {
		if g.Class == class && g.JobSet == key {
			return g
		}
	}
	t.Fatalf("no group %s/%s in %+v", class, key, tr.Groups)
	return GroupStats{}
}

// Mixed events, conclusions, re-runs and job sets: only like executions are
// pooled, only counted ones enter the statistics, and nothing is dropped.
func TestBuildTrend_GroupsCountsAndKeepsEverythingVisible(t *testing.T) {
	var ss []Sample
	for i := 0; i < 6; i++ {
		ss = append(ss, sample(int64(100+i), 10+i, "success", 1, 700+float64(i)*10, classPRCode, "race"))
	}
	ss = append(ss,
		sample(200, 17, "failure", 1, 900, classPRCode, "race"),
		sample(201, 18, "cancelled", 1, 300, classPRCode, "race"),
		sample(202, 19, "success", 2, 220, classPRCode, "race"),           // re-run attempt
		sample(203, 19, "success", 1, 1500, classPRCode, "race+frontend"), // different job set
		sample(204, 19, "success", 1, 60, classPRDocsOnly, "minimal"),
	)
	bad := sample(205, 20, "success", 1, 5000, classPRCode, "race")
	bad.Report.Problems = []string{"verdict commit mismatch"}
	ss = append(ss, bad)
	meta := sample(206, 20, "success", 1, 710, classPRCode, "race")
	meta.Source = "metadata-only"
	ss = append(ss, meta)

	tr := buildTrend(ss, testBaseline("provisional"), AuditFreshness{State: "passed"}, time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))
	g := findGroup(t, tr, classPRCode, "race")
	if g.Total != 11 || g.Eligible != 7 || g.Reruns != 1 || g.ByConclusion["failure"] != 1 || g.ByConclusion["cancelled"] != 1 || g.UnknownEv != 1 {
		t.Fatalf("group %+v: want total 11, counted 7 (6 + the metadata-only success), 1 re-run, 1 failure, 1 cancel, 1 evidence-unknown", g)
	}
	e := g.Metrics["elapsedToAggregateSeconds"]
	if e.N != 7 || !e.Provisional || e.Max != 750 || e.Min != 700 {
		t.Errorf("elapsed stat %+v: the failure, cancellation, re-run and contradictory run must not enter it; 7 < 10 is provisional", e)
	}
	if g := findGroup(t, tr, classPRCode, "race+frontend"); g.Total != 1 {
		t.Errorf("a different job set must be its own group")
	}
	if len(tr.Samples) != len(ss) {
		t.Errorf("%d sample rows for %d executions: nothing may be dropped", len(tr.Samples), len(ss))
	}
	whys := map[int64]string{}
	for _, s := range tr.Samples {
		whys[s.RunID] = s.Why
	}
	for id, want := range map[int64]string{200: "failure", 201: "cancelled", 202: "re-run", 205: "contradictory"} {
		if !strings.Contains(whys[id], want) {
			t.Errorf("run %d not-counted reason %q, want it to mention %q", id, whys[id], want)
		}
	}
	if len(tr.Indicators) != 0 || !strings.Contains(strings.Join(tr.Unknowns, " "), "provisional") {
		t.Errorf("a provisional baseline asserts no regression and says so: indicators %v unknowns %v", tr.Indicators, tr.Unknowns)
	}
	md := renderTrend(tr)
	for _, want := range []string{"Not counted", "not a bill", "provisional"} {
		if !strings.Contains(md, want) {
			t.Errorf("trend summary lacks %q", want)
		}
	}
}

func TestBuildTrend_WindowIsTheNewestMaxSamples(t *testing.T) {
	var ss []Sample
	for i := 0; i < 25; i++ {
		ss = append(ss, sample(int64(i), 1+i, "success", 1, float64(100+i), classMainQA, "race+qa-layers"))
	}
	tr := buildTrend(ss, testBaseline("provisional"), AuditFreshness{}, time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	e := findGroup(t, tr, classMainQA, "race+qa-layers").Metrics["elapsedToAggregateSeconds"]
	if e.N != 20 || e.Min != 105 || e.Provisional {
		t.Errorf("stat %+v: want the 20 newest samples (min 105) and no longer provisional", e)
	}
}

func TestRegressions_AdvisoryAndSustainedOnly(t *testing.T) {
	b := testBaseline("reviewed")
	b.ReviewedBy, b.ReviewedAt = "someone", "2026-10-01"
	key := fastWorkflowPath + "|" + classPRCode + "|race"
	b.Groups = map[string]map[string]struct {
		Median float64 `json:"median"`
	}{key: {"elapsedToAggregateSeconds": {Median: 700}}}
	mk := func(vals ...float64) []Sample {
		var ss []Sample
		for i, v := range vals { // vals newest first → later day
			ss = append(ss, sample(int64(i), 28-i, "success", 1, v, classPRCode, "race"))
		}
		return ss
	}
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	if tr := buildTrend(mk(900, 901, 902, 600), b, AuditFreshness{}, now); len(tr.Indicators) != 1 {
		t.Errorf("three newest all > 700×1.25: want one advisory indicator, got %v", tr.Indicators)
	}
	if tr := buildTrend(mk(900, 600, 902, 903), b, AuditFreshness{}, now); len(tr.Indicators) != 0 {
		t.Errorf("one normal sample among the newest three breaks 'sustained': got %v", tr.Indicators)
	}
	if tr := buildTrend(mk(900, 901), b, AuditFreshness{}, now); len(tr.Indicators) != 0 {
		t.Errorf("fewer samples than the rule needs: got %v", tr.Indicators)
	}
}

func auditSample(id int64, day int, concl, ref, cmp, state, source string) Sample {
	r := RunReport{Schema: runReportSchema, Class: classScheduledAudit}
	r.Run = RunIdentity{RunID: id, Attempt: 1, Status: "completed", Conclusion: concl, Event: "schedule",
		CreatedAt: time.Date(2026, 9, day, 4, 0, 0, 0, time.UTC).Format(time.RFC3339)}
	r.Evidence.Audit = Audit{State: state, Requested: true, ReferenceJob: ref, CompareJob: cmp}
	return Sample{Report: r, Source: source}
}

// The scheduled audit is judged fail-closed: failed, skipped, stale and
// never-run audits fail the trend; a pass needs the gate's success AND both
// audit jobs' success AND (when read) a passed comparison.
func TestAuditFreshness_States(t *testing.T) {
	b := testBaseline("provisional") // introduced 2026-09-01, 8-day limit
	at := func(day int) time.Time { return time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC) }
	pass := func(id int64, day int) Sample {
		return auditSample(id, day, "success", "success", "success", "passed", "per-run-report")
	}
	for _, tc := range []struct {
		name string
		runs []Sample
		now  time.Time
		want string
	}{
		{"none yet, within grace", nil, at(5), "pending-first"},
		{"none after the grace", nil, at(12), "missing"},
		{"passed this week", []Sample{pass(2, 14)}, at(15), "passed"},
		{"last pass too old", []Sample{pass(2, 14)}, at(24), "stale"},
		{"latest failed although an older one passed", []Sample{auditSample(3, 21, "failure", "success", "failure", "failed", "per-run-report"), pass(2, 14)}, at(21), "failed"},
		{"audit jobs skipped, gate green", []Sample{auditSample(3, 21, "success", "skipped", "skipped", "missing", "per-run-report")}, at(21), "failed"},
		{"comparison unreadable in the report", []Sample{auditSample(3, 21, "success", "success", "success", "unknown", "per-run-report")}, at(21), "failed"},
		{"report shows contradictory identities", func() []Sample {
			s := pass(3, 21)
			s.Report.Problems = []string{"verdict commit mismatch"}
			return []Sample{s}
		}(), at(21), "failed"},
		{"metadata-only pass rests on the gate's verdict", []Sample{auditSample(3, 21, "success", "success", "success", "unknown", "metadata-only")}, at(21), "passed"},
		{"cancelled audit", []Sample{auditSample(3, 21, "cancelled", "cancelled", "skipped", "failed", "metadata-only")}, at(21), "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			af := auditFreshness(tc.runs, b, tc.now)
			if af.State != tc.want {
				t.Errorf("state %q (%s), want %q", af.State, af.Detail, tc.want)
			}
			if wantFail := tc.want == "failed" || tc.want == "stale" || tc.want == "missing"; af.failing() != wantFail {
				t.Errorf("failing()=%v for %s", af.failing(), af.State)
			}
		})
	}
}

func TestLoadBaseline_Validates(t *testing.T) {
	b, err := loadBaseline("../../.github/ci-perf-baseline.json")
	if err != nil || b.Status != "provisional" || len(b.Groups) != 0 {
		t.Fatalf("the committed baseline must load and start provisional with no targets: %+v %v", b, err)
	}
	dir := t.TempDir()
	for name, body := range map[string]string{
		"wrong schema":           `{"schema":"x","status":"provisional","minSamples":10,"maxSamples":20,"sustainedRegression":{"ratio":1.25,"consecutive":3},"audit":{"workflow":"qa-gate.yml","introduced":"2026-09-01","maxAgeDays":8},"groups":{}}`,
		"unreviewed reviewed":    `{"schema":"culvert.ci-perf-baseline/v1","status":"reviewed","minSamples":10,"maxSamples":20,"sustainedRegression":{"ratio":1.25,"consecutive":3},"audit":{"workflow":"qa-gate.yml","introduced":"2026-09-01","maxAgeDays":8},"groups":{}}`,
		"too few samples":        `{"schema":"culvert.ci-perf-baseline/v1","status":"provisional","minSamples":3,"maxSamples":20,"sustainedRegression":{"ratio":1.25,"consecutive":3},"audit":{"workflow":"qa-gate.yml","introduced":"2026-09-01","maxAgeDays":8},"groups":{}}`,
		"unknown field":          `{"schema":"culvert.ci-perf-baseline/v1","status":"provisional","target":1,"minSamples":10,"maxSamples":20,"sustainedRegression":{"ratio":1.25,"consecutive":3},"audit":{"workflow":"qa-gate.yml","introduced":"2026-09-01","maxAgeDays":8},"groups":{}}`,
		"audit age below a week": `{"schema":"culvert.ci-perf-baseline/v1","status":"provisional","minSamples":10,"maxSamples":20,"sustainedRegression":{"ratio":1.25,"consecutive":3},"audit":{"workflow":"qa-gate.yml","introduced":"2026-09-01","maxAgeDays":3},"groups":{}}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBaseline(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// End to end through the fake API: per-run reports are preferred, a run
// without one is measured from metadata and marked so, and the audit verdict
// comes from the scheduled runs.
func TestCollectTrend_EndToEnd(t *testing.T) {
	fake := newFake(t)
	code := loadFixture(t, "fast-pr-code")
	docs := loadFixture(t, "fast-pr-docs")
	fake.runs[code.Run.ID], fake.runs[docs.Run.ID] = code, docs
	fake.wfRuns["pr-fast-gate.yml"] = []apiRun{code.Run, docs.Run}
	rep := Analyze(code.Run, code.Jobs, runEvidence{})
	fake.runs[999] = fixture{Run: reporterRun(999, "workflow_run", "main")}
	fake.addArtifact(999, 1, reportArtifactName(code.Run.ID, code.Run.RunAttempt), makeZip(t, map[string][]byte{"report.json": mustJSON(t, rep)}))

	audit := loadFixture(t, "qa-dispatch-audit")
	audit.Run.Event = "schedule"
	fake.runs[audit.Run.ID] = audit
	// Thirty newer pull-request pass-throughs ahead of one main push: listed
	// workflow-wide, "newest 10" would contain no push at all.
	push := loadFixture(t, "qa-push")
	fake.runs[push.Run.ID] = push
	var qaRuns []apiRun
	pt := loadFixture(t, "qa-pr-passthrough")
	for i := int64(0); i < 30; i++ {
		f := pt
		f.Run.ID = 5_000_000 + i
		fake.runs[f.Run.ID] = f
		qaRuns = append(qaRuns, f.Run)
	}
	fake.wfRuns["qa-gate.yml"] = append(append(qaRuns, push.Run), audit.Run)

	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, _ := newGHClient(srv.URL, "")
	b := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(b, []byte(`{"schema":"culvert.ci-perf-baseline/v1","status":"provisional","reviewedBy":"","reviewedAt":"","minSamples":10,"maxSamples":20,"sustainedRegression":{"ratio":1.25,"consecutive":3},"audit":{"workflow":"qa-gate.yml","introduced":"2026-09-20","maxAgeDays":8},"groups":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "trend")
	tr, err := collectTrend(context.Background(), c, trendOpts{repo: "o/r", workflows: []string{"pr-fast-gate.yml", "qa-gate.yml"},
		perEvent: 10, defaultBranch: "main", baselinePath: b, outDir: out, now: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	sources := map[int64]string{}
	for _, s := range tr.Samples {
		sources[s.RunID] = s.Source
	}
	if sources[code.Run.ID] != "per-run-report" || sources[docs.Run.ID] != "metadata-only" {
		t.Errorf("sources %v: the retained report must be preferred, and its absence marked", sources)
	}
	seen := map[int64]int{}
	for _, row := range tr.Samples {
		seen[row.RunID]++
	}
	if seen[push.Run.ID] != 1 {
		t.Errorf("the main push was crowded out by pull-request runs (seen %d times) — runs must be listed per event", seen[push.Run.ID])
	}
	if seen[audit.Run.ID] != 1 {
		t.Errorf("the scheduled audit must be one trend sample, not %d", seen[audit.Run.ID])
	}
	if tr.Audit.State != "passed" || tr.Audit.LastPassed == nil || tr.Audit.LastPassed.RunID != audit.Run.ID {
		t.Errorf("audit freshness %+v", tr.Audit)
	}
	if _, err := os.Stat(filepath.Join(out, "trend.json")); err != nil {
		t.Error(err)
	}
}

// reporterRun is a run of the reporter workflow in repository o/r.
func reporterRun(id int64, event, branch string) apiRun {
	r := apiRun{ID: id, Path: reporterWorkflowPath, Event: event, HeadBranch: branch, Status: "completed", Conclusion: "success"}
	r.Repository.FullName, r.HeadRepository.FullName = "o/r", "o/r"
	return r
}

// A retained report is trusted only when a default-branch reporter run
// produced it AND it agrees with the API about its own run. Artifact names
// are not access-controlled: a pull request can upload one named for the
// scheduled audit and claim that a FAILED audit passed.
func TestCollectTrend_ForgedReportCannotPassAFailedAudit(t *testing.T) {
	failed := loadFixture(t, "qa-dispatch-audit")
	failed.Run.Event = "schedule"
	failed.Run.Conclusion = "failure"
	for i := range failed.Jobs {
		if failed.Jobs[i].Name == auditCompareJob {
			failed.Jobs[i].Conclusion = "failure"
		}
	}
	// The forgery: a report for the same run, claiming success and a passed audit.
	forged := Analyze(failed.Run, failed.Jobs, runEvidence{})
	forged.Run.Conclusion = "success"
	forged.Evidence.Audit.State, forged.Evidence.Audit.ReferenceJob, forged.Evidence.Audit.CompareJob = "passed", "success", "success"
	honest := forged
	honest.Run.Conclusion = "failure" // agrees with the API, but the producer below is untrusted anyway

	for _, tc := range []struct {
		name     string
		producer apiRun
		report   RunReport
	}{
		{"pull-request run of an edited reporter", reporterRun(801, "pull_request", "attacker-branch"), forged},
		{"push to a non-default branch", reporterRun(802, "push", "attacker-branch"), forged},
		{"dispatch on a non-default branch", reporterRun(803, "workflow_dispatch", "attacker-branch"), forged},
		{"another workflow on main", func() apiRun {
			r := reporterRun(804, "push", "main")
			r.Path = ".github/workflows/pr-fast-gate.yml"
			return r
		}(), forged},
		{"a fork's head repository", func() apiRun {
			r := reporterRun(805, "workflow_run", "main")
			r.HeadRepository.FullName = "fork/r"
			return r
		}(), forged},
		{"trusted producer, identity disagrees with the API", reporterRun(806, "schedule", "main"), forged},
		{"untrusted producer, identity agrees", reporterRun(807, "pull_request", "main"), honest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFake(t)
			fake.runs[failed.Run.ID] = failed
			fake.wfRuns["qa-gate.yml"] = []apiRun{failed.Run}
			fake.runs[tc.producer.ID] = fixture{Run: tc.producer}
			fake.addArtifact(tc.producer.ID, 1, reportArtifactName(failed.Run.ID, failed.Run.RunAttempt),
				makeZip(t, map[string][]byte{"report.json": mustJSON(t, tc.report)}))
			srv := httptest.NewServer(fake)
			defer srv.Close()
			c, _ := newGHClient(srv.URL, "")
			tr, err := collectTrend(context.Background(), c, trendOpts{repo: "o/r", workflows: []string{"qa-gate.yml"}, perEvent: 5,
				defaultBranch: "main", baselinePath: "../../.github/ci-perf-baseline.json", outDir: t.TempDir(),
				now: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)})
			if err != nil {
				t.Fatal(err)
			}
			if tr.Audit.State != "failed" {
				t.Fatalf("audit state %q (%s): a report the trend must not trust decided the audit", tr.Audit.State, tr.Audit.Detail)
			}
			for _, row := range tr.Samples {
				if row.RunID == failed.Run.ID && row.Source != "metadata-only" {
					t.Errorf("run %d taken from an untrusted report (source %s)", row.RunID, row.Source)
				}
			}
		})
	}
}
