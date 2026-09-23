package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Baseline is the REVIEWED reference the trend is compared with. It starts
// provisional with no targets; targets are written by a person after 10–20
// representative executions of a group have been observed, never generated.
type Baseline struct {
	Schema     string `json:"schema"`
	Status     string `json:"status"` // provisional | reviewed
	ReviewedBy string `json:"reviewedBy"`
	ReviewedAt string `json:"reviewedAt"`
	MinSamples int    `json:"minSamples"`
	MaxSamples int    `json:"maxSamples"`
	Regression struct {
		Ratio       float64 `json:"ratio"`
		Consecutive int     `json:"consecutive"`
	} `json:"sustainedRegression"`
	Audit AuditPolicy `json:"audit"`
	// Groups: "<workflowPath>|<class>|<jobSetKey>" → metric → reviewed median.
	Groups map[string]map[string]struct {
		Median float64 `json:"median"`
	} `json:"groups"`
}

// AuditPolicy is the baseline's rule for the recurring equivalence audit.
type AuditPolicy struct {
	Workflow   string `json:"workflow"`
	Introduced string `json:"introduced"`
	MaxAgeDays int    `json:"maxAgeDays"`
	// Cron is the audit workflow's schedule ("M H * * D", UTC), pinned
	// equal to qa-gate.yml by ci_perf_report_test.go. SlotGraceHours is
	// how long after a slot its audit may still be queued or running.
	Cron           string `json:"cron"`
	SlotGraceHours int    `json:"slotGraceHours"`
}

func loadBaseline(path string) (Baseline, error) {
	var b Baseline
	raw, err := os.ReadFile(path)
	if err != nil {
		return b, fmt.Errorf("read baseline: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return b, fmt.Errorf("decode baseline %s: %w", path, err)
	}
	return b, validateBaseline(b)
}

// validateBaseline rejects a baseline whose rules could not be applied as
// written: an unreviewed "reviewed" file, sample bounds outside 10..20, a
// regression rule that fires on noise, or an audit block that cannot expire.
func validateBaseline(b Baseline) error {
	switch {
	case b.Schema != baselineSchema:
		return fmt.Errorf("baseline schema %q, want %q", b.Schema, baselineSchema)
	case b.Status != "provisional" && b.Status != "reviewed":
		return fmt.Errorf("baseline status %q, want provisional|reviewed", b.Status)
	case b.Status == "reviewed" && (b.ReviewedBy == "" || b.ReviewedAt == ""):
		return fmt.Errorf("a reviewed baseline must name its reviewer and date")
	case b.MinSamples < 10 || b.MaxSamples < b.MinSamples || b.MaxSamples > 20:
		return fmt.Errorf("baseline sample bounds %d..%d must lie within 10..20", b.MinSamples, b.MaxSamples)
	case b.Regression.Ratio <= 1 || b.Regression.Consecutive < 2:
		return fmt.Errorf("sustained-regression rule needs ratio > 1 and at least 2 consecutive samples")
	}
	if err := validateReviewedGroups(b); err != nil {
		return err
	}
	return validateAuditBlock(b.Audit)
}

// validateReviewedGroups refuses a reviewed median for a cohort that is not
// fully observed or not in the current key shape: a baseline must describe one
// verified configuration, never a mix of unknown ones.
func validateReviewedGroups(b Baseline) error {
	for k := range b.Groups {
		parts := strings.Split(k, "|")
		if len(parts) != 4 || !strings.HasPrefix(parts[3], "platform=") {
			return fmt.Errorf("baseline group %q is not workflow|class|jobSet|cohort", k)
		}
		if strings.Contains(parts[3], "="+cohortUnknown) {
			return fmt.Errorf("baseline group %q has an unobserved cohort component; enrich natural runs with on-demand reports first", k)
		}
	}
	return nil
}

// validateAuditBlock rejects an audit block that cannot expire or whose
// weekly slot cannot be computed.
func validateAuditBlock(a AuditPolicy) error {
	if a.Workflow == "" || a.MaxAgeDays < 7 {
		return fmt.Errorf("baseline audit block needs a workflow and maxAgeDays >= 7")
	}
	if _, err := time.Parse("2006-01-02", a.Introduced); err != nil {
		return fmt.Errorf("baseline audit.introduced: %w", err)
	}
	if _, err := parseWeeklyCron(a.Cron); err != nil {
		return fmt.Errorf("baseline audit.cron: %w", err)
	}
	if a.SlotGraceHours < 1 || a.SlotGraceHours > 48 {
		return fmt.Errorf("baseline audit.slotGraceHours %d must lie within 1..48", a.SlotGraceHours)
	}
	return nil
}

// weeklySlot is a once-a-week schedule: weekday and time of day, UTC.
type weeklySlot struct {
	weekday      time.Weekday
	hour, minute int
}

// parseWeeklyCron accepts exactly the "M H * * D" shape the audit uses.
func parseWeeklyCron(expr string) (weeklySlot, error) {
	f := strings.Fields(expr)
	if len(f) != 5 || f[2] != "*" || f[3] != "*" {
		return weeklySlot{}, fmt.Errorf("%q is not a weekly \"M H * * D\" schedule", expr)
	}
	m, errM := strconv.Atoi(f[0])
	h, errH := strconv.Atoi(f[1])
	d, errD := strconv.Atoi(f[4])
	if errM != nil || errH != nil || errD != nil || m < 0 || m > 59 || h < 0 || h > 23 || d < 0 || d > 6 {
		return weeklySlot{}, fmt.Errorf("%q has an out-of-range or non-numeric field", expr)
	}
	return weeklySlot{weekday: time.Weekday(d), hour: h, minute: m}, nil
}

// lastDueSlot is the most recent scheduled audit time whose grace period has
// ended by now: the slot whose audit must already have completed.
func lastDueSlot(ws weeklySlot, grace time.Duration, now time.Time) time.Time {
	now = now.UTC()
	t := time.Date(now.Year(), now.Month(), now.Day(), ws.hour, ws.minute, 0, 0, time.UTC)
	t = t.AddDate(0, 0, -((int(t.Weekday()) - int(ws.weekday) + 7) % 7))
	for t.Add(grace).After(now) {
		t = t.AddDate(0, 0, -7)
	}
	return t
}

// Sample is one observed execution and where its report came from.
type Sample struct {
	Report RunReport `json:"report"`
	// Source: per-run-report (the collector's artifact) or metadata-only (no
	// report; evidence not read, so evidence-derived values are unknown).
	Source string `json:"source"`
}

// Stat is a provisional or baseline-eligible summary of one metric.
type Stat struct {
	N           int     `json:"n"`
	Median      float64 `json:"median"`
	P90         float64 `json:"p90"`
	Min         float64 `json:"min"`
	Max         float64 `json:"max"`
	Provisional bool    `json:"provisional"`
}

// Indicator is an ADVISORY sustained-regression signal.
type Indicator struct {
	Group    string    `json:"group"`
	Metric   string    `json:"metric"`
	Baseline float64   `json:"baselineMedian"`
	Recent   []float64 `json:"recent"`
	Ratio    float64   `json:"ratio"`
}

// GroupStats summarises one class of equivalent executions.
type GroupStats struct {
	Key          string          `json:"key"`
	Workflow     string          `json:"workflow"`
	Class        string          `json:"class"`
	JobSet       string          `json:"jobSet"`
	Cohort       string          `json:"cohort"`
	Verified     bool            `json:"cohortVerified"`
	Total        int             `json:"total"`
	ByConclusion map[string]int  `json:"byConclusion"`
	Reruns       int             `json:"reruns"`
	Eligible     int             `json:"eligible"`
	UnknownEv    int             `json:"evidenceUnknown"`
	Metrics      map[string]Stat `json:"metrics"`
}

// AuditRun is one scheduled audit execution.
type AuditRun struct {
	RunID      int64  `json:"runId"`
	Attempt    int    `json:"attempt"`
	CreatedAt  string `json:"createdAt"`
	Conclusion string `json:"conclusion"`
	Audit      string `json:"audit"`
	Reference  string `json:"referenceJob"`
	Compare    string `json:"compareJob"`
	Unreadable bool   `json:"unreadable,omitempty"`
}

// AuditFreshness says whether the recurring equivalence audit is current.
type AuditFreshness struct {
	Workflow   string     `json:"workflow"`
	Introduced string     `json:"introduced"`
	MaxAgeDays int        `json:"maxAgeDays"`
	State      string     `json:"state"` // passed | pending-first | failed | stale | missing
	Detail     string     `json:"detail"`
	LastPassed *AuditRun  `json:"lastPassed"`
	AgeDays    float64    `json:"ageDays"`
	DueSlot    string     `json:"dueSlot"`
	Expected   int        `json:"expectedSinceIntroduced"`
	Observed   int        `json:"observedSinceIntroduced"`
	Runs       []AuditRun `json:"runs"`
}

// failing reports the audit states that fail the trend: an equivalence check
// that failed, went stale, or never ran is a correctness signal, not advice.
func (a AuditFreshness) failing() bool {
	return a.State == "failed" || a.State == "stale" || a.State == "missing"
}

// TrendReport is the periodic summary.
type TrendReport struct {
	Schema      string         `json:"schema"`
	GeneratedAt string         `json:"generatedAt"`
	Collector   Collector      `json:"collector"`
	Baseline    string         `json:"baselineStatus"`
	Groups      []GroupStats   `json:"groups"`
	Indicators  []Indicator    `json:"sustainedRegressions"`
	Audit       AuditFreshness `json:"audit"`
	Samples     []SampleRow    `json:"samples"`
	Unknowns    []string       `json:"unknowns"`
}

// SampleRow keeps every observed execution visible, including the ones not
// counted: failures, cancellations and re-runs are listed, never dropped.
type SampleRow struct {
	Group      string   `json:"group"`
	RunID      int64    `json:"runId"`
	Attempt    int      `json:"attempt"`
	Event      string   `json:"event"`
	Conclusion string   `json:"conclusion"`
	CreatedAt  string   `json:"createdAt"`
	Counted    bool     `json:"counted"`
	Why        string   `json:"whyNotCounted,omitempty"`
	Source     string   `json:"source"`
	Elapsed    *float64 `json:"elapsedToAggregateSeconds"`
	Runner     float64  `json:"runnerMinutes"`
	// Toolchain is the exact Go version the shards reported, when read; the
	// cohort keeps only the release line.
	Toolchain string `json:"toolchain,omitempty"`
}

// metricValues extracts the compared metrics; absent values are simply absent.
func metricValues(r RunReport) map[string]float64 {
	m := map[string]float64{"runnerMinutes": r.Timing.RunnerMinutes}
	if r.Timing.ElapsedToAggregate != nil {
		m["elapsedToAggregateSeconds"] = *r.Timing.ElapsedToAggregate
	}
	if r.Timing.ElapsedToRaceVerdict != nil {
		m["elapsedToRaceVerdictSeconds"] = *r.Timing.ElapsedToRaceVerdict
	}
	if r.Race != nil && len(r.Race.Shards) > 0 {
		var hi float64
		for _, s := range r.Race.Shards {
			hi = math.Max(hi, s.Test)
		}
		m["maxShardTestSeconds"] = hi
		m["laneSeconds"] = r.Race.Lane.Seconds
		m["shardMaxOverMean"] = r.Race.Imbalance.MaxOverMean
	}
	return m
}

// groupKeyOf is the comparison cohort: workflow, execution class, the job
// families that ran, and the observed configuration (runner platform, shard
// count, Go release line). The source commit is deliberately not part of it —
// ordinary code changes stay comparable. A run whose configuration was not
// observed carries "unknown" and so forms its own cohort, separate from every
// verified one.
func groupKeyOf(r RunReport) string {
	return r.Run.WorkflowPath + "|" + r.Class + "|" + r.JobSet.Key + "|" + cohortKeyOf(r)
}

// cohortKeyOf tolerates a report without a derived cohort (never produced by
// this collector) by calling it unknown rather than guessing.
func cohortKeyOf(r RunReport) string {
	if r.Cohort.Key == "" {
		return "platform=unknown;shards=unknown;toolchain=unknown"
	}
	return r.Cohort.Key
}

// countedWhy returns "" when a sample may enter statistics, else the reason.
func countedWhy(s Sample) string {
	r := s.Report
	switch {
	case s.Source == "unreadable":
		return "run data unreadable"
	case r.Run.Status != "completed":
		return "not completed"
	case r.Run.Rerun:
		return "re-run attempt (partial job set)"
	case r.Run.Conclusion != "success":
		return "conclusion " + r.Run.Conclusion
	case len(r.Problems) > 0:
		return "contradictory evidence"
	}
	return ""
}

func stat(vals []float64, minSamples int) Stat {
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	st := Stat{N: len(s), Provisional: len(s) < minSamples}
	if len(s) == 0 {
		return st
	}
	st.Median, st.Min, st.Max = median(s), s[0], s[len(s)-1]
	rank := int(math.Ceil(0.9*float64(len(s)))) - 1
	st.P90 = s[rank]
	return st
}

// sampleRow is one execution's visible row, counted or not.
func sampleRow(group, concl string, s *Sample) SampleRow {
	r := &s.Report
	why := countedWhy(*s)
	row := SampleRow{Group: group, RunID: r.Run.RunID, Attempt: r.Run.Attempt, Event: r.Run.Event, Conclusion: concl,
		CreatedAt: r.Run.CreatedAt, Counted: why == "", Why: why, Source: s.Source,
		Elapsed: r.Timing.ElapsedToAggregate, Runner: r.Timing.RunnerMinutes}
	if r.Toolchain != nil {
		row.Toolchain = r.Toolchain.Go
	}
	return row
}

// buildTrend is pure: samples + baseline + audit in, report out.
func buildTrend(samples []Sample, b Baseline, audit AuditFreshness, now time.Time) TrendReport {
	tr := TrendReport{Schema: trendReportSchema, GeneratedAt: now.UTC().Format(time.RFC3339), Baseline: b.Status, Audit: audit, Unknowns: []string{}}
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].Report.Run.CreatedAt > samples[j].Report.Run.CreatedAt })
	groups := map[string]*GroupStats{}
	eligible := map[string][]RunReport{}
	for sI := range samples {
		s := &samples[sI]
		r := s.Report
		k := groupKeyOf(r)
		g := groups[k]
		if g == nil {
			g = &GroupStats{Key: k, Workflow: r.Run.WorkflowPath, Class: r.Class, JobSet: r.JobSet.Key,
				Cohort: cohortKeyOf(r), Verified: r.Cohort.Verified, ByConclusion: map[string]int{}, Metrics: map[string]Stat{}}
			groups[k] = g
		}
		g.Total++
		concl := r.Run.Conclusion
		if concl == "" {
			concl = r.Run.Status
		}
		g.ByConclusion[concl]++
		if r.Run.Rerun {
			g.Reruns++
		}
		if s.Source != "per-run-report" || r.Evidence.Verdict == "missing" {
			g.UnknownEv++
		}
		row := sampleRow(k, concl, s)
		tr.Samples = append(tr.Samples, row)
		if row.Counted && len(eligible[k]) < b.MaxSamples {
			eligible[k] = append(eligible[k], r)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		g.Eligible = len(eligible[k])
		perMetric := map[string][]float64{}
		for rI := range eligible[k] { // newest first
			r := &eligible[k][rI]
			for m, v := range metricValues(*r) {
				perMetric[m] = append(perMetric[m], v)
			}
		}
		for m, vals := range perMetric {
			g.Metrics[m] = stat(vals, b.MinSamples)
		}
		tr.Indicators = append(tr.Indicators, regressions(k, perMetric, b)...)
		tr.Groups = append(tr.Groups, *g)
	}
	if b.Status != "reviewed" {
		tr.Unknowns = append(tr.Unknowns, "baseline is provisional: no performance targets exist yet, so no regression can be asserted; statistics below are provisional until each group has "+fmt.Sprint(b.MinSamples)+" counted samples and a person reviews them")
	}
	return tr
}

// regressions: a metric regresses when the `consecutive` newest counted
// samples ALL exceed the reviewed median by the ratio. Advisory only.
func regressions(key string, perMetric map[string][]float64, b Baseline) []Indicator {
	if b.Status != "reviewed" {
		return nil
	}
	ref, ok := b.Groups[key]
	if !ok {
		return nil
	}
	var out []Indicator
	metrics := make([]string, 0, len(ref))
	for m := range ref {
		metrics = append(metrics, m)
	}
	sort.Strings(metrics)
	for _, m := range metrics {
		vals, base := perMetric[m], ref[m].Median
		if base <= 0 || len(vals) < b.Regression.Consecutive {
			continue
		}
		recent := vals[:b.Regression.Consecutive]
		all := true
		for _, v := range recent {
			if v <= base*b.Regression.Ratio {
				all = false
				break
			}
		}
		if all {
			out = append(out, Indicator{Group: key, Metric: m, Baseline: base, Recent: append([]float64(nil), recent...), Ratio: b.Regression.Ratio})
		}
	}
	return out
}

// auditFreshness judges the recurring audit from its scheduled runs (newest
// first). A run passes only when the gate concluded success AND both audit jobs
// executed and succeeded AND, when the collector's report exists, the report
// read the comparison as passed with consistent identities.
func auditFreshness(runs []Sample, b Baseline, now time.Time) AuditFreshness {
	af := AuditFreshness{Workflow: b.Audit.Workflow, Introduced: b.Audit.Introduced, MaxAgeDays: b.Audit.MaxAgeDays}
	intro, _ := time.Parse("2006-01-02", b.Audit.Introduced)
	af.Expected = int(now.Sub(intro).Hours() / (24 * 7))
	var latestCompleted *AuditRun
	for sI := range runs {
		s := &runs[sI]
		r := s.Report
		ar := AuditRun{RunID: r.Run.RunID, Attempt: r.Run.Attempt, CreatedAt: r.Run.CreatedAt, Conclusion: r.Run.Conclusion,
			Audit: r.Evidence.Audit.State, Reference: r.Evidence.Audit.ReferenceJob, Compare: r.Evidence.Audit.CompareJob, Unreadable: s.Source == "unreadable"}
		af.Runs = append(af.Runs, ar)
		if created, ok := parseTime(r.Run.CreatedAt); ok && !created.Before(intro) {
			af.Observed++
		}
		if r.Run.Status != "completed" {
			continue
		}
		if latestCompleted == nil {
			latestCompleted = &af.Runs[len(af.Runs)-1]
		}
		if af.LastPassed == nil && auditRunPassed(*s) {
			af.LastPassed = &af.Runs[len(af.Runs)-1]
		}
	}
	// Every weekly slot must have its own completed audit. An age limit alone
	// cannot say this: a backstop run a few hours after the slot still sees
	// last week's audit as "7 days old" and would pass a week with no audit.
	ws, _ := parseWeeklyCron(b.Audit.Cron) // validated by loadBaseline
	slot := lastDueSlot(ws, time.Duration(b.Audit.SlotGraceHours)*time.Hour, now)
	af.DueSlot = slot.Format(time.RFC3339)
	judgeAudit(&af, latestCompleted, slot, intro, now)
	return af
}

// judgeAudit sets the verdict from the latest completed scheduled run and the
// last passing one: pending-first, missing, failed, stale or passed.
func judgeAudit(af *AuditFreshness, latestCompleted *AuditRun, slot, intro, now time.Time) {
	var latestCreated time.Time
	if latestCompleted != nil {
		latestCreated, _ = parseTime(latestCompleted.CreatedAt)
	}
	switch {
	case slot.Before(intro) && latestCompleted == nil:
		af.State, af.Detail = "pending-first", "no scheduled audit slot has come due since introduction"
	case latestCompleted == nil:
		af.State, af.Detail = "missing", fmt.Sprintf("no scheduled audit has completed since introduction; the slot due %s has none", af.DueSlot)
	case !slot.Before(intro) && latestCreated.Before(slot):
		af.State = "missing"
		af.Detail = fmt.Sprintf("no scheduled audit completed for the slot due %s; the latest completed one is run %d from %s",
			af.DueSlot, latestCompleted.RunID, latestCompleted.CreatedAt)
	case af.LastPassed == nil || af.LastPassed.RunID != latestCompleted.RunID:
		af.State = "failed"
		af.Detail = failedAuditDetail(latestCompleted)
	default:
		created, _ := parseTime(af.LastPassed.CreatedAt)
		af.AgeDays = math.Round(now.Sub(created).Hours()/24*10) / 10
		af.State, af.Detail = "passed", fmt.Sprintf("run %d passed %.1f days ago", af.LastPassed.RunID, af.AgeDays)
		if af.AgeDays > float64(af.MaxAgeDays) {
			af.State = "stale"
			af.Detail = fmt.Sprintf("the last passing scheduled audit (run %d) is %.1f days old, over the %d-day limit", af.LastPassed.RunID, af.AgeDays, af.MaxAgeDays)
		}
	}
}

// failedAuditDetail names why the latest completed scheduled audit failed.
func failedAuditDetail(r *AuditRun) string {
	d := fmt.Sprintf("the latest scheduled audit (run %d, attempt %d) did not pass: conclusion %s, audit %s, reference %s, compare %s",
		r.RunID, r.Attempt, r.Conclusion, r.Audit, r.Reference, r.Compare)
	if r.Attempt > 1 {
		d += " — a re-run attempt cannot establish a passing audit"
	}
	if r.Unreadable {
		d += " — its jobs could not be read, and unknown evidence never passes"
	}
	return d
}

func auditRunPassed(s Sample) bool {
	r := s.Report
	a := r.Evidence.Audit
	// A re-run attempt never establishes a passing audit. The runs API
	// reports only a run's LATEST attempt, so a failed audit re-run to green
	// would otherwise read as passed, and a "re-run failed jobs" attempt mixes
	// a fresh comparison with jobs carried over from the attempt that failed.
	// A red audit is investigated, never re-run away (§17.7); the next
	// scheduled audit must pass on its first attempt.
	if r.Run.Rerun || r.Run.Attempt > 1 || s.Source == "unreadable" {
		return false
	}
	if r.Run.Conclusion != "success" || a.ReferenceJob != "success" || a.CompareJob != "success" {
		return false
	}
	if s.Source == "per-run-report" {
		return a.State == "passed" && len(r.Problems) == 0
	}
	// Metadata-only: the comparison was not read by this reporter, so the
	// pass rests on the gate's own verdict, which requires both audit jobs.
	return true
}

type trendOpts struct {
	repo      string
	workflows []string
	perEvent  int
	// defaultBranch is the only branch a trusted reporter run may be on.
	defaultBranch string
	baselinePath  string
	outDir        string
	summary       string
	now           time.Time
	collector     Collector
}

const reportArtifactPrefix = "ci-run-report-"

func reportArtifactName(runID int64, attempt int) string {
	return fmt.Sprintf("%s%d-%d", reportArtifactPrefix, runID, attempt)
}

// loadSample prefers the collector's retained per-run report; without one it
// measures the run from metadata alone and says so.
func loadSample(ctx context.Context, c *ghClient, o trendOpts, run apiRun) (Sample, error) {
	var rejected []string
	arts, err := c.artifactsNamed(ctx, o.repo, reportArtifactName(run.ID, run.RunAttempt))
	if err == nil {
		for _, a := range arts {
			if a.Expired {
				continue
			}
			rep, why := trustedReport(ctx, c, o, run, a)
			if why == "" {
				return Sample{Report: rep, Source: "per-run-report"}, nil
			}
			rejected = append(rejected, fmt.Sprintf("retained report artifact %d rejected: %s", a.ID, why))
		}
	}
	jobs, err := c.jobs(ctx, o.repo, run.ID, run.RunAttempt)
	if err != nil {
		return Sample{}, err
	}
	rep := Analyze(run, jobs, runEvidence{Notes: append(rejected, "no retained per-run report: evidence artifacts were not read")})
	return Sample{Report: rep, Source: "metadata-only"}, nil
}

// reporterWorkflowPath is the only workflow whose report artifacts the trend
// trusts.
const reporterWorkflowPath = ".github/workflows/ci-perf-report.yml"

// trustedReport accepts a retained report only when BOTH hold, and otherwise
// says why not:
//
//  1. It was produced by a trusted run: the reporter workflow, on the
//     default branch of this repository, from an event that runs
//     default-branch code (workflow_run, schedule, or a dispatch on the
//     default branch). Artifact names are not access-controlled — any run in
//     the repository, including a pull request that edits or adds a workflow,
//     can upload an artifact with this name — so the name proves nothing.
//  2. Its run identity matches the API's run field for field. A report that
//     disagrees with GitHub about its own run (a different workflow, event,
//     commit or conclusion) is not about this run.
//
// Without both, a pull request could make a failed equivalence audit read as
// passed by uploading a report named for the scheduled run.
func trustedReport(ctx context.Context, c *ghClient, o trendOpts, run apiRun, a apiArtifact) (rep RunReport, rejected string) {
	producer, err := c.run(ctx, o.repo, a.WorkflowRun.ID)
	if err != nil {
		return RunReport{}, fmt.Sprintf("producing run %d unreadable: %v", a.WorkflowRun.ID, err)
	}
	if why := untrustedProducer(producer, o); why != "" {
		return RunReport{}, why
	}
	members, err := c.artifactMembers(ctx, o.repo, a, map[string]bool{"report.json": true})
	if err != nil {
		return RunReport{}, fmt.Sprintf("unreadable: %v", err)
	}
	if err := decodeStrict("report.json", members["report.json"], &rep); err != nil {
		return RunReport{}, fmt.Sprintf("undecodable: %v", err)
	}
	if rep.Schema != runReportSchema {
		return RunReport{}, fmt.Sprintf("schema %q", rep.Schema)
	}
	if why := identityMismatch(rep.Run, run); why != "" {
		return RunReport{}, why
	}
	return rep, ""
}

// untrustedProducer returns why a producing run is not the trusted reporter,
// or "" when it is.
func untrustedProducer(p apiRun, o trendOpts) string {
	switch {
	case p.Path != reporterWorkflowPath:
		return fmt.Sprintf("produced by %s, not the reporter workflow", p.Path)
	case p.Event != "workflow_run" && p.Event != "schedule" && p.Event != "workflow_dispatch":
		return fmt.Sprintf("produced by a %s run, which may execute unreviewed workflow code", p.Event)
	case p.HeadBranch != o.defaultBranch:
		return fmt.Sprintf("produced on branch %q, not %q", p.HeadBranch, o.defaultBranch)
	case p.Repository.FullName != o.repo || p.HeadRepository.FullName != o.repo:
		return fmt.Sprintf("produced in %s (head %s), not %s", p.Repository.FullName, p.HeadRepository.FullName, o.repo)
	}
	return ""
}

// identityMismatch compares a report's immutable run identity with the API.
func identityMismatch(got RunIdentity, run apiRun) string {
	for _, f := range []struct{ name, report, api string }{
		{"workflowPath", got.WorkflowPath, run.Path},
		{"event", got.Event, run.Event},
		{"headSha", got.HeadSHA, run.HeadSHA},
		{"headBranch", got.HeadBranch, run.HeadBranch},
		{"status", got.Status, run.Status},
		{"conclusion", got.Conclusion, run.Conclusion},
		{"createdAt", got.CreatedAt, run.CreatedAt},
	} {
		if f.report != f.api {
			return fmt.Sprintf("%s %q disagrees with the API's %q", f.name, f.report, f.api)
		}
	}
	if got.RunID != run.ID || got.Attempt != run.RunAttempt {
		return fmt.Sprintf("names run %d attempt %d, not %d attempt %d", got.RunID, got.Attempt, run.ID, run.RunAttempt)
	}
	return ""
}

// trendEvents are listed separately for every workflow; the scheduled audit
// is listed on its own (it also decides audit freshness).
var trendEvents = []string{"pull_request", "push", "workflow_dispatch"}

// loadRuns lists the newest runs of one workflow for one event and reads each
// as a sample; a run that cannot be read is noted, never silently dropped.
func loadRuns(ctx context.Context, c *ghClient, o trendOpts, wf, event string, limit int) ([]Sample, []string, error) {
	runs, err := c.workflowRuns(ctx, o.repo, wf, event, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("list %s %s runs: %w", wf, event, err)
	}
	var out []Sample
	var notes []string
	for runI := range runs {
		run := &runs[runI]
		s, err := loadSample(ctx, c, o, *run)
		if err != nil {
			// Kept, not dropped: dropping the newest scheduled run would let an
			// older passing one stand in for it. An unreadable run never counts
			// in statistics and never passes an audit.
			notes = append(notes, fmt.Sprintf("%s run %d unreadable: %v", event, run.ID, err))
			s = Sample{Report: Analyze(*run, nil, runEvidence{Notes: []string{"run jobs unreadable: " + err.Error()}}), Source: "unreadable"}
		}
		out = append(out, s)
	}
	return out, notes, nil
}

func collectTrend(ctx context.Context, c *ghClient, o trendOpts) (TrendReport, error) {
	b, err := loadBaseline(o.baselinePath)
	if err != nil {
		return TrendReport{}, err
	}
	var samples []Sample
	var unknowns []string
	// Listed PER EVENT: a workflow-wide "newest N" is dominated by whichever
	// event is most frequent, so ~240 pull-request runs a week would push the
	// main-push and dispatch executions out of the window entirely.
	for _, wf := range o.workflows {
		for _, ev := range trendEvents {
			got, notes, err := loadRuns(ctx, c, o, wf, ev, o.perEvent)
			if err != nil {
				return TrendReport{}, err
			}
			samples, unknowns = append(samples, got...), append(unknowns, notes...)
		}
	}
	auditSamples, notes, err := loadRuns(ctx, c, o, b.Audit.Workflow, "schedule", 30)
	if err != nil {
		return TrendReport{}, err
	}
	unknowns = append(unknowns, notes...)
	// Scheduled audits are also executions of their workflow: they get a trend
	// group of their own, besides deciding the audit's freshness.
	samples = append(samples, auditSamples...)
	tr := buildTrend(samples, b, auditFreshness(auditSamples, b, o.now), o.now)
	tr.Collector = o.collector
	tr.Unknowns = append(tr.Unknowns, unknowns...)
	return tr, writeTrendOutputs(tr, o)
}

func writeTrendOutputs(tr TrendReport, o trendOpts) error {
	if o.outDir == "" {
		return nil
	}
	if err := os.MkdirAll(o.outDir, 0o750); err != nil {
		return fmt.Errorf("out dir: %w", err)
	}
	md := renderTrend(tr)
	if err := writeJSON(o.outDir+"/trend.json", tr); err != nil {
		return err
	}
	if err := os.WriteFile(o.outDir+"/summary.md", []byte(md), 0o600); err != nil {
		return fmt.Errorf("write summary.md: %w", err)
	}
	return appendSummary(o.summary, md)
}

func shortWorkflow(p string) string {
	return strings.TrimSuffix(strings.TrimPrefix(p, ".github/workflows/"), ".yml")
}

func fmtStat(s Stat, ok bool) string {
	if !ok || s.N == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f / %.0f", s.Median, s.P90)
}

func renderTrend(tr TrendReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## CI performance and evidence trend — %s\n\n", tr.GeneratedAt)
	fmt.Fprintf(&b, "Baseline: **%s**. Statistics are over counted executions only (completed, first attempt, success, consistent evidence); every other execution is listed below with the reason. Elapsed is wall clock; runner-minutes are summed job time, not a bill.\n\n", tr.Baseline)
	b.WriteString("| workflow | class | job set | cohort | executions (by conclusion) | re-runs | counted | evidence unknown | elapsed to aggregate s, median / p90 | race verdict s, median / p90 | runner-min median | status |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for gI := range tr.Groups {
		g := &tr.Groups[gI]
		conc := make([]string, 0, len(g.ByConclusion))
		for k, v := range g.ByConclusion {
			conc = append(conc, fmt.Sprintf("%s %d", k, v))
		}
		sort.Strings(conc)
		e, ok1 := g.Metrics["elapsedToAggregateSeconds"]
		rv, ok2 := g.Metrics["elapsedToRaceVerdictSeconds"]
		rm, ok3 := g.Metrics["runnerMinutes"]
		runner := "—"
		if ok3 && rm.N > 0 {
			runner = fmt.Sprintf("%.1f", rm.Median)
		}
		status := "provisional"
		switch {
		case !g.Verified:
			status = "unverified cohort: never reviewed"
		case e.N >= 10 && !e.Provisional:
			status = "enough samples to review"
		}
		cohort := strings.ReplaceAll(g.Cohort, ";", "; ")
		if !g.Verified {
			cohort += " (unverified)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d (%s) | %d | %d | %d | %s | %s | %s | %s |\n",
			shortWorkflow(g.Workflow), g.Class, g.JobSet, cohort, g.Total, strings.Join(conc, ", "), g.Reruns, g.Eligible, g.UnknownEv,
			fmtStat(e, ok1), fmtStat(rv, ok2), runner, status)
	}
	a := tr.Audit
	fmt.Fprintf(&b, "\n### Weekly same-SHA equivalence audit: **%s**\n\n%s. Scheduled audits observed since %s: %d of %d expected.\n",
		a.State, a.Detail, a.Introduced, a.Observed, a.Expected)
	if len(tr.Indicators) > 0 {
		b.WriteString("\n### Sustained regressions (advisory)\n\n")
		for _, in := range tr.Indicators {
			fmt.Fprintf(&b, "- `%s` %s: the %d newest counted samples %v all exceed the reviewed median %.0f × %.2f\n", in.Group, in.Metric, len(in.Recent), in.Recent, in.Baseline, in.Ratio)
		}
	}
	var excluded []string
	for sI := range tr.Samples {
		s := &tr.Samples[sI]
		if !s.Counted {
			excluded = append(excluded, fmt.Sprintf("run %d attempt %d (%s, %s): %s", s.RunID, s.Attempt, shortWorkflow(strings.SplitN(s.Group, "|", 2)[0]), s.Event, s.Why))
		}
	}
	writeList(&b, "Not counted (visible, never dropped)", excluded)
	writeList(&b, "Unknown", tr.Unknowns)
	return b.String()
}
