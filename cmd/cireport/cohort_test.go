package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	img24   = "ubuntu-24.04"
	build24 = "20260907.300.1"
)

// hosted puts every job of a real fixture on one runner platform, as GitHub
// reports it (labels + runner group + job id), which the trimmed fixtures omit.
func hosted(jobs []apiJob, label, group string) []apiJob {
	out := make([]apiJob, len(jobs))
	for i := range jobs {
		out[i] = jobs[i]
		out[i].ID = int64(i + 1)
		out[i].Labels = []string{label}
		out[i].RunnerGroupName = group
	}
	return out
}

// imaged records that every job's log reported this runner image and build.
func imaged(ev runEvidence, jobs []apiJob, image, build string) runEvidence {
	ev.JobImages = map[int64]runnerImage{}
	for jI := range jobs {
		ev.JobImages[jobs[jI].ID] = runnerImage{Image: image, Version: build}
	}
	return ev
}

// setJobImage changes (or, with image "", removes) one job's observed image.
func setJobImage(ev runEvidence, jobs []apiJob, suffix, image, build string) runEvidence {
	m := map[int64]runnerImage{}
	for k, v := range ev.JobImages {
		m[k] = v
	}
	for jI := range jobs {
		if strings.HasSuffix(jobs[jI].Name, suffix) {
			if image == "" {
				delete(m, jobs[jI].ID)
			} else {
				m[jobs[jI].ID] = runnerImage{Image: image, Version: build}
			}
		}
	}
	ev.JobImages = m
	return ev
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

func dropMeta(ev runEvidence, idx int) runEvidence {
	metas := map[int]*evShardMeta{}
	for i, m := range ev.ShardMetas {
		if i != idx {
			metas[i] = m
		}
	}
	ev.ShardMetas = metas
	return ev
}

// renumberMeta moves shard from's metadata to artifact index to, with the
// document's own shard field set to named.
func renumberMeta(ev runEvidence, from, to, named int) runEvidence {
	metas := map[int]*evShardMeta{}
	for i, m := range ev.ShardMetas {
		if i != from {
			metas[i] = m
		}
	}
	c := *ev.ShardMetas[from]
	c.Shard = named
	metas[to] = &c
	ev.ShardMetas = metas
	return ev
}

// threeShards is the same evidence from a 3-shard engine: shard 3's metadata
// and verdict entry are gone too.
func threeShards(ev runEvidence) runEvidence {
	ev = dropMeta(ev, 3)
	v := *ev.Verdict
	v.Shards = v.Shards[:3]
	ev.Verdict = &v
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

// hostedAudit is the real audit run on one platform, every job observed on
// one image.
func hostedAudit(t *testing.T, label, group string) (fixture, []apiJob, runEvidence) {
	fx, ev := qaAuditRun(t)
	jobs := hosted(fx.Jobs, label, group)
	return fx, jobs, imaged(ev, jobs, img24, build24)
}

const laneJob = "Race · non-root packages"

// Materially different configurations never share a cohort, and a
// configuration that was not observed is its own, unverified cohort.
func TestCohort_SeparatesMaterialConfigurations(t *testing.T) {
	gh := "GitHub Actions"
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", gh)
	base := Analyze(fx.Run, jobs, ev)
	if !base.Cohort.Verified || base.Cohort.Key != "platform=ubuntu-latest@GitHub Actions;image=ubuntu-24.04;shards=4;toolchain=go1.26 linux/amd64" {
		t.Fatalf("base cohort %+v", base.Cohort)
	}
	arm := ev
	arm.ShardMetas = map[int]*evShardMeta{}
	for i, m := range ev.ShardMetas {
		c := *m
		c.GOARCH = "arm64"
		arm.ShardMetas[i] = &c
	}
	armJobs := hosted(fx.Jobs, "ubuntu-24.04-arm", gh)
	for _, tc := range []struct {
		name  string
		jobs  []apiJob
		ev    runEvidence
		wantV bool
	}{
		{"another runner label", armJobs, imaged(arm, armJobs, "ubuntu-24.04-arm", build24), true},
		{"self-hosted runner group", hosted(fx.Jobs, "ubuntu-latest", "culvert-self-hosted"), ev, true},
		{"another shard count", dropShard(jobs), threeShards(ev), true},
		{"another Go release line", jobs, withGo(ev, "go1.27.0"), true},
		{"another GOARCH", jobs, arm, true},
		// The label ubuntu-latest moves to a new image under one name.
		{"same label, another runner image", jobs, imaged(ev, jobs, "ubuntu-26.04", "20261020.1"), true},
		// A rollout moves one job and not another: every root shard on
		// 24.04 while the non-root lane — whose time is a trend metric —
		// ran on 26.04. The run measured a mixed configuration.
		{"a non-shard job on another image", jobs, setJobImage(ev, jobs, laneJob, "ubuntu-26.04", "20261020.1"), false},
		{"one measured job's log not read", jobs, setJobImage(ev, jobs, laneJob, "", ""), false},
		// Four shards scheduled, one shard's metadata never read: that shard
		// may have run another toolchain.
		{"one shard's metadata not read", jobs, dropMeta(ev, 2), false},
		// Four documents for four scheduled shards, but not the same four:
		// shard 3 was never observed.
		{"metadata for an unscheduled shard in place of one scheduled", jobs, renumberMeta(ev, 3, 4, 4), false},
		// Shard 3's artifact carries a document naming shard 2: it says
		// nothing about what shard 3 ran.
		{"a shard's meta.json names another shard", jobs, renumberMeta(ev, 3, 3, 2), false},
		{"nothing read (metadata only)", jobs, runEvidence{}, false},
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

// One measured job whose log was not read leaves the run's image unobserved:
// the other jobs do not speak for it, and it is not a second image either.
func TestCohort_OneUnobservedJobMakesTheImageUnknown(t *testing.T) {
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	r := Analyze(fx.Run, jobs, setJobImage(ev, jobs, "✅ QA Gate — APPROVED", "", ""))
	if r.Cohort.Image != cohortUnknown || r.Cohort.Verified || r.RunnerImage.JobsObserved != r.RunnerImage.JobsMeasured-1 {
		t.Errorf("image %q verified=%v observed %d/%d, want unknown, unverified, one short",
			r.Cohort.Image, r.Cohort.Verified, r.RunnerImage.JobsObserved, r.RunnerImage.JobsMeasured)
	}
}

// A run with no race engine has no toolchain, but every job's image is still
// observed: its cohort is complete and can be verified.
func TestCohort_RunWithoutEngineIsVerifiedFromJobImages(t *testing.T) {
	fx := loadFixture(t, "fast-pr-docs")
	jobs := hosted(fx.Jobs, "ubuntu-latest", "GitHub Actions")
	r := Analyze(fx.Run, jobs, imaged(runEvidence{}, jobs, img24, build24))
	if !r.Cohort.Verified || r.Cohort.Toolchain != "n/a" || r.Cohort.Image != img24 {
		t.Errorf("docs-only cohort %+v, want verified with toolchain n/a", r.Cohort)
	}
}

// During an image rollout jobs can share an image but not a build. The build
// is stated only when every job agrees; the cohort (keyed on the image) is
// unaffected.
func TestCohort_ImageBuildStatedOnlyWhenJobsAgree(t *testing.T) {
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	if r := Analyze(fx.Run, jobs, ev); r.RunnerImage.Build != build24 || r.RunnerImage.Image != img24 {
		t.Fatalf("agreeing jobs: %+v", r.RunnerImage)
	}
	for name, e := range map[string]runEvidence{
		"one job on the next build": setJobImage(ev, jobs, laneJob, img24, "20260914.1"),
		"one job's build missing":   setJobImage(ev, jobs, laneJob, img24, ""),
	} {
		r := Analyze(fx.Run, jobs, e)
		if r.RunnerImage.Build != "" || !strings.Contains(strings.Join(r.Unknowns, "\n"), "image build is unknown") {
			t.Errorf("%s: build %q unknowns %v, want unstated and noted", name, r.RunnerImage.Build, r.Unknowns)
		}
		if r.Cohort.Image != img24 || !r.Cohort.Verified {
			t.Errorf("%s: the cohort is keyed on the image and must stay %q verified, got %+v", name, img24, r.Cohort)
		}
	}
}

// Every shard's metadata read, but one shard on another release line or
// architecture: the run is a mixed configuration and never verified, even
// though the contradiction already keeps it out of the statistics.
func TestCohort_ShardsDisagreeingOnToolchainAreMixed(t *testing.T) {
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	for name, mut := range map[string]func(m *evShardMeta){
		"another release line": func(m *evShardMeta) { m.GoVersion = "go1.27.0" },
		"another GOARCH":       func(m *evShardMeta) { m.GOARCH = "arm64" },
	} {
		e := withGo(ev, "go1.26.6") // a private copy of the metas
		mut(e.ShardMetas[3])
		r := Analyze(fx.Run, jobs, e)
		if !strings.HasPrefix(r.Cohort.Toolchain, "mixed:") || r.Cohort.Verified {
			t.Errorf("%s: cohort %+v, want a mixed, unverified toolchain", name, r.Cohort)
		}
		if strings.Contains(reportLogLine(r), "verified=true") {
			t.Errorf("%s: the log line claims a verified cohort", name)
		}
		b := testBaseline("reviewed")
		b.ReviewedBy, b.ReviewedAt = "someone", "2026-10-01"
		b.Groups = map[string]map[string]struct {
			Median float64 `json:"median"`
		}{groupKeyOf(r): {"elapsedToAggregateSeconds": {Median: 700}}}
		if validateBaseline(b) == nil {
			t.Errorf("%s: a reviewed baseline accepted the mixed cohort %q", name, groupKeyOf(r))
		}
	}
	// A patch-only difference is the same release line: comparable, though
	// the exact-toolchain contradiction is still recorded as a problem.
	e := withGo(ev, "go1.26.6")
	e.ShardMetas[3].GoVersion = "go1.26.7"
	r := Analyze(fx.Run, jobs, e)
	if strings.HasPrefix(r.Cohort.Toolchain, "mixed:") || r.Cohort.Toolchain != "go1.26 linux/amd64" || len(r.Problems) == 0 {
		t.Errorf("patch-only difference: cohort %+v problems %v", r.Cohort, r.Problems)
	}
	// No one shard's exact version is presented as the run's.
	if r.Toolchain != nil {
		t.Errorf("patch-only difference: run toolchain %+v, want unstated", *r.Toolchain)
	}
	row := sampleRow("g", "success", &Sample{Report: r})
	if row.Toolchain != "" {
		t.Errorf("patch-only difference: trend row toolchain %q, want empty", row.Toolchain)
	}
	// The image build is what separates two samples of one cohort.
	if row.Image != img24 || row.ImageBuild != build24 {
		t.Errorf("trend row image %q build %q, want %q %q", row.Image, row.ImageBuild, img24, build24)
	}
}

// Label sets that differ only in where a separator falls must not share a
// platform: joined raw, "a+b","c" and "a","b","c" both read "a+b+c".
func TestCohort_PlatformEncodingIsUnambiguous(t *testing.T) {
	fx, _, _ := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	withLabels := func(group string, labels ...string) string {
		jobs := hosted(fx.Jobs, "x", group)
		for jI := range jobs {
			jobs[jI].Labels = labels
		}
		return observedPlatform(viewJobs(jobs, time.Time{}))
	}
	for _, pair := range [][2]string{
		{withLabels("g", "a+b", "c", "self-hosted"), withLabels("g", "a", "b", "c", "self-hosted")},
		{withLabels("g", "a@b"), withLabels("b", "a")},
		{withLabels("g", "a,b"), withLabels("g", "a")},
		{withLabels("g", "a%2Bb"), withLabels("g", "a+b")},
	} {
		if pair[0] == cohortUnknown || pair[1] == cohortUnknown {
			t.Fatalf("fixture platform not observed: %q / %q", pair[0], pair[1])
		}
		if pair[0] == pair[1] {
			t.Errorf("distinct platforms serialise to the same string %q", pair[0])
		}
	}
	if got := withLabels("GitHub Actions", "ubuntu-latest"); got != "ubuntu-latest@GitHub Actions" {
		t.Errorf("an ordinary platform reads %q, want it unchanged", got)
	}
	// Separators never reach the cohort key raw, so its fields still parse.
	if p := withLabels("g;x=y|z", "a;b|c"); strings.ContainsAny(p, ";=|") {
		t.Errorf("platform %q carries a cohort key separator", p)
	}
	// A verified run on a label carrying "|" still forms a group key a
	// reviewed baseline can hold: the separator does not split it.
	_, jobs, ev := hostedAudit(t, "self|hosted", "g|1")
	r := Analyze(fx.Run, jobs, ev)
	if !r.Cohort.Verified {
		t.Fatalf("cohort %+v, want verified", r.Cohort)
	}
	b := testBaseline("reviewed")
	b.ReviewedBy, b.ReviewedAt = "someone", "2026-10-01"
	b.Groups = map[string]map[string]struct {
		Median float64 `json:"median"`
	}{groupKeyOf(r): {"elapsedToAggregateSeconds": {Median: 700}}}
	if err := validateBaseline(b); err != nil {
		t.Errorf("a verified cohort on a label with \"|\" was refused: %v", err)
	}
}

// Ordinary change stays comparable: a different commit, different durations,
// a Go patch release and next week's image build land in the same cohort.
func TestCohort_ComparableRunsStayGrouped(t *testing.T) {
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	base := Analyze(fx.Run, jobs, ev)

	other := fx.Run
	other.ID, other.HeadSHA = fx.Run.ID+1, strings.Repeat("a", 40)
	oev := imaged(withGo(ev, "go1.26.7"), jobs, img24, "20260914.1") // next week's image build
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
	if r.Toolchain.Go != "go1.26.7" || base.Toolchain.Go != "go1.26.6" || r.RunnerImage.Build != "20260914.1" {
		t.Error("the exact Go version and image build stay in the report even though the cohort keeps only the release line and image")
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
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
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
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	good := groupKeyOf(Analyze(fx.Run, jobs, ev))
	mixed := setJobImage(ev, jobs, laneJob, "ubuntu-26.04", "20261020.1")
	pre := qaWorkflowPath + "|" + classManualAudit + "|race+audit|"
	for _, tc := range []struct {
		key string
		ok  bool
	}{
		{good, true},
		{groupKeyOf(Analyze(fx.Run, jobs, runEvidence{})), false},                            // nothing observed
		{groupKeyOf(Analyze(fx.Run, jobs, setJobImage(ev, jobs, laneJob, "", ""))), false},   // image unknown
		{qaWorkflowPath + "|" + classManualAudit + "|race+audit", false},                     // pre-cohort key shape
		{groupKeyOf(Analyze(fx.Run, jobs, mixed)), false},                                    // jobs on different images
		{pre + "platform=ubuntu-latest@GitHub Actions", false},                               // incomplete cohort
		{pre + "platform=x;shards=4;image=ubuntu-24.04;toolchain=go1.26 linux/amd64", false}, // fields out of order
		{pre + "platform=x;image=;shards=4;toolchain=go1.26 linux/amd64", false},             // empty field
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

// realLogHead is the start of a real job log (job 107340167293), verbatim.
const realLogHead = "\ufeff2026-09-23T19:14:04.3565260Z Current runner version: '2.337.0'\n" +
	"2026-09-23T19:14:04.3589178Z ##[group]Runner Image Provisioner\n" +
	"2026-09-23T19:14:04.3590176Z Hosted Compute Agent\n" +
	"2026-09-23T19:14:04.3590798Z Version: 20260828.587\n" +
	"2026-09-23T19:14:04.3594690Z ##[endgroup]\n" +
	"2026-09-23T19:14:04.3596391Z ##[group]Operating System\n" +
	"2026-09-23T19:14:04.3597056Z Ubuntu\n" +
	"2026-09-23T19:14:04.3597575Z 24.04.5\n" +
	"2026-09-23T19:14:04.3598702Z ##[endgroup]\n" +
	"2026-09-23T19:14:04.3599233Z ##[group]Runner Image\n" +
	"2026-09-23T19:14:04.3599878Z Image: ubuntu-24.04\n" +
	"2026-09-23T19:14:04.3600441Z Version: 20260907.300.1\n" +
	"2026-09-23T19:14:04.3601765Z Included Software: https://github.com/actions/runner-images/blob/ubuntu24/20260907.300/images/ubuntu/Ubuntu2404-Readme.md\n" +
	"2026-09-23T19:14:04.3604785Z ##[endgroup]\n" +
	"2026-09-23T19:14:04.3605954Z ##[group]GITHUB_TOKEN Permissions\n"

// The parser reads only the "Runner Image" group — not the provisioner's
// Version line before it — and refuses values outside a safe character set.
func TestParseRunnerImage(t *testing.T) {
	ri, ok := parseRunnerImage([]byte(realLogHead))
	if !ok || ri.Image != img24 || ri.Version != build24 {
		t.Fatalf("real log head: %+v ok=%v", ri, ok)
	}
	for name, head := range map[string]string{
		"no image group":     "2026-09-23T19:14:04Z ##[group]Operating System\n2026-09-23T19:14:04Z Image: ubuntu-24.04\n2026-09-23T19:14:04Z ##[endgroup]\n",
		"group never closed": "2026-09-23T19:14:04Z ##[group]Runner Image\n2026-09-23T19:14:04Z Image: ubuntu-24.04\n",
		"hostile value":      "2026-09-23T19:14:04Z ##[group]Runner Image\n2026-09-23T19:14:04Z Image: ubuntu;$(id)\n2026-09-23T19:14:04Z ##[endgroup]\n",
		"empty":              "",
	} {
		if ri, ok := parseRunnerImage([]byte(head)); ok {
			t.Errorf("%s: parsed %+v, want unobserved", name, ri)
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

// A run reported while still in progress: the earliest start of this
// attempt's jobs counts whether or not that job has completed yet.
func TestAnalyze_AttemptQueueCountsRunningJobs(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	run := apiRun{ID: 9, Path: fastWorkflowPath, Event: "pull_request", RunAttempt: 1, Status: "in_progress",
		CreatedAt: ts(base, 0), RunStartedAt: ts(base, 0)}
	running := apiJob{Name: "Gate · go test -race (sharded) / Race · non-root packages", Status: "in_progress",
		CreatedAt: ts(base, 2), StartedAt: ts(base, 7), RunAttempt: 1}
	later := synthJob(base, "Gate · gitleaks", "success", 2, 30, 60)
	r := Analyze(run, []apiJob{running, later}, runEvidence{})
	if r.Timing.AttemptQueue == nil || *r.Timing.AttemptQueue != 7 {
		t.Errorf("attempt queue %v, want 7 s (the running job started first), not 30 s", fmtSecs(r.Timing.AttemptQueue))
	}
	if r := Analyze(run, []apiJob{running}, runEvidence{}); r.Timing.AttemptQueue == nil || *r.Timing.AttemptQueue != 7 {
		t.Errorf("no job completed yet: attempt queue %v, want 7 s (a start is observed)", fmtSecs(r.Timing.AttemptQueue))
	}
	skipped := apiJob{Name: "x", Status: "completed", Conclusion: "skipped", StartedAt: ts(base, 1), CompletedAt: ts(base, 0)}
	if r := Analyze(run, []apiJob{skipped, later}, runEvidence{}); r.Timing.AttemptQueue == nil || *r.Timing.AttemptQueue != 30 {
		t.Errorf("a skipped job's stamp must not count: %v", fmtSecs(r.Timing.AttemptQueue))
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

// The collector reads the head of every measured job's log — through the
// storage redirect, cutting a log that ignores the byte range — and derives
// the image from all of them. A job whose log is missing leaves the image
// unknown and is noted.
func TestCollectRun_ReadsEveryMeasuredJobsImage(t *testing.T) {
	fx, jobs, _ := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	fake := newFake(t)
	fake.runs[fx.Run.ID] = fixture{Run: fx.Run, Jobs: jobs}
	start, _ := parseTime(fx.Run.RunStartedAt)
	measured := 0
	var lane int64
	for _, v := range viewJobs(jobs, start) {
		if !v.inAttempt() {
			continue
		}
		measured++
		fake.jobLogs[v.api.ID] = realLogHead
		if strings.HasSuffix(v.api.Name, laneJob) {
			lane = v.api.ID
			fake.jobLogs[v.api.ID] = realLogHead + strings.Repeat("2026-09-23T19:14:05Z test output line\n", 30000) // ~1 MB
		}
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	c, err := newGHClient(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := collectRun(context.Background(), c, runOpts{repo: "o/r", runID: fx.Run.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rep.RunnerImage.JobsObserved != measured || rep.RunnerImage.JobsMeasured != measured || rep.Cohort.Image != img24 || rep.RunnerImage.Build != build24 {
		t.Fatalf("runner image %+v cohort image %q, want all %d jobs on %s", rep.RunnerImage, rep.Cohort.Image, measured, img24)
	}

	delete(fake.jobLogs, lane)
	rep, err = collectRun(context.Background(), c, runOpts{repo: "o/r", runID: fx.Run.ID})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cohort.Image != cohortUnknown || rep.RunnerImage.JobsObserved != measured-1 ||
		!strings.Contains(strings.Join(rep.Unknowns, "\n"), "1 job logs unreadable") {
		t.Errorf("one log missing: image %q observed %d/%d unknowns %v", rep.Cohort.Image, rep.RunnerImage.JobsObserved, measured, rep.Unknowns)
	}
}

// Toolchain values come from artifacts. One carrying a key separator is not
// an observed toolchain: it would split the cohort or group key.
func TestCohort_UnsafeToolchainValueIsUnknown(t *testing.T) {
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	for _, v := range []string{"go1.26.6|x", "go1.26.6;toolchain=go1.26", "go1.26 6"} {
		r := Analyze(fx.Run, jobs, withGo(ev, v))
		if r.Cohort.Toolchain != cohortUnknown || r.Cohort.Verified {
			t.Errorf("Go version %q: cohort %+v, want an unknown, unverified toolchain", v, r.Cohort)
		}
		if strings.Count(groupKeyOf(r), "|") != 3 {
			t.Errorf("Go version %q split the group key: %q", v, groupKeyOf(r))
		}
	}
}

// The run-level exact toolchain is stated under the same completeness rule as
// the cohort: shards whose metadata was not read may have run another one.
func TestCohort_ExactToolchainNeedsEveryScheduledShard(t *testing.T) {
	fx, jobs, ev := hostedAudit(t, "ubuntu-latest", "GitHub Actions")
	if r := Analyze(fx.Run, jobs, ev); r.Toolchain == nil {
		t.Fatal("control: a complete run must state its exact toolchain")
	}
	for name, e := range map[string]runEvidence{
		"one shard's metadata not read":         dropMeta(ev, 2),
		"metadata for an unscheduled shard":     renumberMeta(ev, 3, 4, 4),
		"a shard's meta.json names another one": renumberMeta(ev, 3, 3, 2),
	} {
		r := Analyze(fx.Run, jobs, e)
		if r.Toolchain != nil {
			t.Errorf("%s: run toolchain %+v stated from a partial read", name, *r.Toolchain)
		}
		if row := sampleRow("g", "success", &Sample{Report: r}); row.Toolchain != "" {
			t.Errorf("%s: trend row toolchain %q, want empty", name, row.Toolchain)
		}
	}
}
