package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hosted puts every job of a real fixture on one runner platform, as GitHub
// reports it (labels + runner group), which the trimmed fixtures omit.
func hosted(jobs []apiJob, label, group string) []apiJob {
	out := make([]apiJob, len(jobs))
	for i := range jobs {
		out[i] = jobs[i]
		out[i].Labels = []string{label}
		out[i].RunnerGroupName = group
	}
	return out
}

func withGo(ev runEvidence, version string) runEvidence {
	metas := map[int]*evShardMeta{}
	for i, m := range ev.ShardMetas {
		c := *m
		c.GoVersion = version
		metas[i] = &c
	}
	ev.ShardMetas = metas
	return ev
}

// withImage sets the runner image every shard reported; image "" leaves one
// shard on a different image (mixed).
func withImage(ev runEvidence, image, version string) runEvidence {
	metas := map[int]*evShardMeta{}
	for i, m := range ev.ShardMetas {
		c := *m
		c.RunnerImage, c.RunnerImageVersion = image, version
		metas[i] = &c
	}
	ev.ShardMetas = metas
	return ev
}

// dropShard removes one root-shard job, as a 3-shard engine would schedule.
func dropShard(jobs []apiJob) []apiJob {
	var out []apiJob
	for jI := range jobs {
		if !strings.HasSuffix(jobs[jI].Name, "Race · root shard 3") {
			out = append(out, jobs[jI])
		}
	}
	return out
}

// Materially different configurations never share a cohort, and a
// configuration that was not observed is its own, unverified cohort.
func TestCohort_SeparatesMaterialConfigurations(t *testing.T) {
	fx, ev := qaAuditRun(t)
	ev = withImage(ev, "ubuntu24", "20260915.1")
	gh := "GitHub Actions"
	base := Analyze(fx.Run, hosted(fx.Jobs, "ubuntu-latest", gh), ev)
	if !base.Cohort.Verified || base.Cohort.Key != "platform=ubuntu-latest@GitHub Actions;image=ubuntu24;shards=4;toolchain=go1.26 linux/amd64" {
		t.Fatalf("base cohort %+v", base.Cohort)
	}
	mixedImages := func(e runEvidence) runEvidence {
		e = withImage(e, "ubuntu24", "20260915.1")
		e.ShardMetas[2].RunnerImage = "ubuntu26"
		return e
	}
	arm := ev
	arm.ShardMetas = map[int]*evShardMeta{}
	for i, m := range ev.ShardMetas {
		c := *m
		c.GOARCH = "arm64"
		arm.ShardMetas[i] = &c
	}
	for _, tc := range []struct {
		name  string
		jobs  []apiJob
		ev    runEvidence
		wantV bool
	}{
		{"another runner label", hosted(fx.Jobs, "ubuntu-24.04-arm", gh), arm, true},
		{"self-hosted runner group", hosted(fx.Jobs, "ubuntu-latest", "culvert-self-hosted"), ev, true},
		{"another shard count", dropShard(hosted(fx.Jobs, "ubuntu-latest", gh)), ev, true},
		{"another Go release line", hosted(fx.Jobs, "ubuntu-latest", gh), withGo(ev, "go1.27.0"), true},
		{"another GOARCH", hosted(fx.Jobs, "ubuntu-latest", gh), arm, true},
		// The label ubuntu-latest moves to a new image under one name.
		{"same label, another runner image", hosted(fx.Jobs, "ubuntu-latest", gh), withImage(ev, "ubuntu26", "20261020.1"), true},
		{"shards on different images", hosted(fx.Jobs, "ubuntu-latest", gh), mixedImages(ev), false},
		{"image not recorded (artifacts from before it was)", hosted(fx.Jobs, "ubuntu-latest", gh), withImage(ev, "", ""), false},
		{"toolchain not observed (metadata only)", hosted(fx.Jobs, "ubuntu-latest", gh), runEvidence{}, false},
		{"platform not observed", fx.Jobs, ev, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Analyze(fx.Run, tc.jobs, tc.ev)
			if groupKeyOf(r) == groupKeyOf(base) {
				t.Errorf("cohort %q shares the verified base's group", r.Cohort.Key)
			}
			if r.Cohort.Verified != tc.wantV {
				t.Errorf("cohort %+v verified=%v, want %v", r.Cohort, r.Cohort.Verified, tc.wantV)
			}
			if !tc.wantV && !strings.Contains(r.Cohort.Key, "=unknown") && !strings.Contains(r.Cohort.Key, "=mixed:") {
				t.Errorf("an unobserved component must read unknown, never a guessed value: %q", r.Cohort.Key)
			}
		})
	}
}

// Ordinary change stays comparable: a different commit, different durations
// and a Go patch release land in the same cohort as the base.
func TestCohort_ComparableRunsStayGrouped(t *testing.T) {
	fx, ev := qaAuditRun(t)
	ev = withImage(ev, "ubuntu24", "20260915.1")
	jobs := hosted(fx.Jobs, "ubuntu-latest", "GitHub Actions")
	base := Analyze(fx.Run, jobs, ev)

	other := fx.Run
	other.ID, other.HeadSHA = fx.Run.ID+1, strings.Repeat("a", 40)
	oev := withImage(withGo(ev, "go1.26.7"), "ubuntu24", "20260922.1") // next week's image build
	v := *ev.Verdict
	v.Commit = other.HeadSHA
	oev.Verdict = &v
	oev.Candidate, oev.CandidateRaw = nil, nil // the timing candidate names its own run
	for i := range oev.ShardMetas {
		oev.ShardMetas[i].Commit = other.HeadSHA
	}
	slower := make([]apiJob, len(jobs))
	copy(slower, jobs)
	for i := range slower {
		if end, ok := parseTime(slower[i].CompletedAt); ok && slower[i].Conclusion != "skipped" {
			slower[i].CompletedAt = end.Add(90 * time.Second).Format(time.RFC3339)
		}
	}
	r := Analyze(other, slower, oev)
	if len(r.Problems) != 0 {
		t.Fatalf("problems %v", r.Problems)
	}
	if groupKeyOf(r) != groupKeyOf(base) {
		t.Fatalf("comparable runs split:\n %s\n %s", groupKeyOf(base), groupKeyOf(r))
	}
	if r.Toolchain.Go != "go1.26.7" || base.Toolchain.Go != "go1.26.6" || r.Toolchain.RunnerImageVersion != "20260922.1" {
		t.Error("the exact Go and image versions stay in the report even though the cohort keeps only the release line and image OS")
	}

	// And the trend pools them: one group, two counted samples, with the
	// exact toolchain visible per sample.
	tr := buildTrend([]Sample{{Report: base, Source: "per-run-report"}, {Report: r, Source: "per-run-report"}},
		testBaseline("provisional"), AuditFreshness{}, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC))
	if len(tr.Groups) != 1 || tr.Groups[0].Eligible != 2 || !tr.Groups[0].Verified {
		t.Fatalf("groups %+v: want one verified cohort with both samples", tr.Groups)
	}
	if tr.Samples[0].Toolchain == "" || tr.Samples[1].Toolchain == "" {
		t.Error("sample rows must carry the exact toolchain")
	}
}

// Metadata-only samples of the same workflow/class/job set never enter a
// verified cohort's statistics — they are pooled separately and labelled.
func TestCohort_TrendKeepsUnknownApart(t *testing.T) {
	fx, ev := qaAuditRun(t)
	ev = withImage(ev, "ubuntu24", "20260915.1")
	jobs := hosted(fx.Jobs, "ubuntu-latest", "GitHub Actions")
	verified := Analyze(fx.Run, jobs, ev)
	meta := Analyze(fx.Run, jobs, runEvidence{})
	tr := buildTrend([]Sample{{Report: verified, Source: "per-run-report"}, {Report: meta, Source: "metadata-only"}},
		testBaseline("provisional"), AuditFreshness{}, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC))
	if len(tr.Groups) != 2 {
		t.Fatalf("groups %+v: verified and unknown cohorts must not pool", tr.Groups)
	}
	for gI := range tr.Groups {
		g := &tr.Groups[gI]
		if g.Eligible != 1 || g.Verified == strings.Contains(g.Cohort, "=unknown") {
			t.Errorf("group %s eligible=%d verified=%v", g.Cohort, g.Eligible, g.Verified)
		}
	}
	if md := renderTrend(tr); !strings.Contains(md, "unverified") {
		t.Error("the summary must label an unverified cohort")
	}
}

// A reviewed median may only describe one fully observed configuration in
// the current key shape.
func TestBaseline_ReviewedGroupsMustBeVerifiedCohorts(t *testing.T) {
	fx, ev := qaAuditRun(t)
	ev = withImage(ev, "ubuntu24", "20260915.1")
	jobs := hosted(fx.Jobs, "ubuntu-latest", "GitHub Actions")
	good := groupKeyOf(Analyze(fx.Run, jobs, ev))
	for _, tc := range []struct {
		key string
		ok  bool
	}{
		{good, true},
		{groupKeyOf(Analyze(fx.Run, jobs, runEvidence{})), false},         // toolchain unknown
		{groupKeyOf(Analyze(fx.Run, jobs, withImage(ev, "", ""))), false}, // image unknown
		{qaWorkflowPath + "|" + classManualAudit + "|race+audit", false},  // pre-cohort key shape
	} {
		b := testBaseline("reviewed")
		b.ReviewedBy, b.ReviewedAt = "someone", "2026-10-01"
		b.Groups = map[string]map[string]struct {
			Median float64 `json:"median"`
		}{tc.key: {"elapsedToAggregateSeconds": {Median: 700}}}
		if err := validateBaseline(b); (err == nil) != tc.ok {
			t.Errorf("key %q: err %v, want ok=%v", tc.key, err, tc.ok)
		}
	}
}

// rerunRun mirrors real run 35034671115: attempt 1 enqueued 23:13:20, the
// re-run requested 34 minutes later (attempt 2 enqueued 23:47:37, run_started_at
// reset to 23:47:35), and nine jobs carried over from attempt 1.
func rerunRun() (apiRun, []apiJob) {
	base := time.Date(2026, 9, 15, 23, 13, 20, 0, time.UTC)
	run := apiRun{ID: 35034671115, Path: fastWorkflowPath, Event: "pull_request", RunAttempt: 2, Status: "completed",
		Conclusion: "success", CreatedAt: ts(base, 0), RunStartedAt: ts(base, 2055)}
	var jobs []apiJob
	for i := 0; i < 9; i++ { // attempt 1's jobs, reused
		jobs = append(jobs, synthJob(base, "carried "+string(rune('a'+i)), "success", 33, 35, 2000))
	}
	jobs = append(jobs,
		synthJob(base, "Gate · perf-regression (allocs/op)", "success", 2057, 2090, 2270),
		synthJob(base, "✅ Fast PR Gate — APPROVED", "success", 2270, 2272, 2277))
	return run, jobs
}

func TestAnalyze_RerunQueueIsAttemptScoped(t *testing.T) {
	run, jobs := rerunRun()
	base, _ := parseTime(run.CreatedAt)

	// Read through the attempt endpoint: the attempt's own enqueue time.
	scoped := run
	scoped.attemptCreatedAt = ts(base, 2057)
	r := Analyze(scoped, jobs, runEvidence{})
	if r.Timing.AttemptQueue == nil || *r.Timing.AttemptQueue != 33 {
		t.Fatalf("attempt queue = %v, want 33 s (enqueue 23:47:37 → first attempt-2 job 23:48:10), not the %d s between attempts",
			fmtSecs(r.Timing.AttemptQueue), 2090)
	}
	if r.Run.AttemptCreatedAt != ts(base, 2057) || r.Run.CreatedAt != run.CreatedAt {
		t.Errorf("identity: createdAt %s attemptCreatedAt %s", r.Run.CreatedAt, r.Run.AttemptCreatedAt)
	}

	// Read through the runs list: created_at is attempt 1's. Unknown, not
	// 2,090 s and not zero — and elapsed and runner-minutes are unchanged.
	listed := Analyze(run, jobs, runEvidence{})
	if listed.Timing.AttemptQueue != nil {
		t.Errorf("attempt queue = %v from attempt 1's created_at; want unknown", *listed.Timing.AttemptQueue)
	}
	if !strings.Contains(strings.Join(listed.Unknowns, "\n"), "attempt queue is unknown") {
		t.Errorf("the unknown queue must be stated: %v", listed.Unknowns)
	}
	for _, x := range []RunReport{r, listed} {
		if x.Timing.ElapsedToAggregate == nil || *x.Timing.ElapsedToAggregate != 222 {
			t.Errorf("elapsed to aggregate = %v, want 222 (attempt start 23:47:35 → aggregate done)", fmtSecs(x.Timing.ElapsedToAggregate))
		}
		if x.Timing.RunnerMinutes != 3.1 || len(x.JobSet.CarriedOver) != 9 {
			t.Errorf("runner-minutes %.1f carried %d: want 3.1 (180 s + 5 s, carried jobs excluded) and 9 carried", x.Timing.RunnerMinutes, len(x.JobSet.CarriedOver))
		}
	}

	// Attempt 1: created_at IS the attempt's enqueue time.
	first := run
	first.RunAttempt, first.RunStartedAt = 1, run.CreatedAt
	one := Analyze(first, []apiJob{synthJob(base, "a", "success", 1, 40, 90), synthJob(base, "✅ Fast PR Gate — APPROVED", "success", 90, 95, 99)}, runEvidence{})
	if one.Timing.AttemptQueue == nil || *one.Timing.AttemptQueue != 40 {
		t.Errorf("attempt 1 queue = %v, want 40", fmtSecs(one.Timing.AttemptQueue))
	}

	// The real pre-5C re-run fixture came from the runs endpoint.
	fx := loadFixture(t, "fast-rerun")
	if q := Analyze(fx.Run, fx.Jobs, runEvidence{}).Timing.AttemptQueue; q != nil {
		t.Errorf("real re-run via the runs endpoint: attempt queue %v, want unknown", *q)
	}
}

// The collector reads through the attempt endpoint, keeps the run's own
// created_at as identity (what the trend compares) and the attempt's enqueue
// time separately.
func TestCollectRun_ReadsTheAttemptEnqueueTime(t *testing.T) {
	run, jobs := rerunRun()
	base, _ := parseTime(run.CreatedAt)
	fake := newFake(t)
	fake.runs[run.ID] = fixture{Run: run, Jobs: jobs}
	att := run
	att.CreatedAt = ts(base, 2057)
	fake.attempts["35034671115/2"] = att
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, err := newGHClient(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := collectRun(context.Background(), c, runOpts{repo: "o/r", runID: run.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.CreatedAt != run.CreatedAt || rep.Run.AttemptCreatedAt != att.CreatedAt {
		t.Errorf("createdAt %s attemptCreatedAt %s", rep.Run.CreatedAt, rep.Run.AttemptCreatedAt)
	}
	if rep.Timing.AttemptQueue == nil || *rep.Timing.AttemptQueue != 33 {
		t.Errorf("attempt queue %v, want 33", fmtSecs(rep.Timing.AttemptQueue))
	}
	if why := identityMismatch(rep.Run, run); why != "" {
		t.Errorf("a retained re-run report must still match the runs list: %s", why)
	}
}
