package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Execution classes. Stats are only ever computed within one class and one job
// set, so a docs-only PR is never averaged with a code PR, and a qualification
// run is never averaged with ordinary traffic.
const (
	classPRCode          = "pr-code"
	classPRDocsOnly      = "pr-docs-only"
	classPRPassThrough   = "pr-pass-through"
	classMainQA          = "main-qa"
	classScheduledAudit  = "scheduled-audit"
	classManualAudit     = "manual-audit"
	classManualQualify   = "manual-qualification"
	classFaultInjection  = "fault-injection"
	classOther           = "other"
	fastWorkflowPath     = ".github/workflows/pr-fast-gate.yml"
	qaWorkflowPath       = ".github/workflows/qa-gate.yml"
	aggregateJobPattern  = " — APPROVED"
	raceVerdictJobSuffix = "Race · verdict + coverage evidence"
	legacyRaceJobPrefix  = "Gate · go test -race + "
	auditReferenceJob    = "Audit · unsharded race reference"
	auditCompareJob      = "Audit · sharded vs unsharded"
)

var (
	titleAuditRE = regexp.MustCompile(`\baudit=(true|false)\b`)
	titleFaultRE = regexp.MustCompile(`\bfault=([a-z-]+)\b`)
	shardJobRE   = regexp.MustCompile(`Race · root shard (\d+)$`)
)

// jobView is one job with parsed times and its place in the attempt.
type jobView struct {
	api      apiJob
	start    time.Time
	end      time.Time
	created  time.Time
	executed bool // ran steps in some attempt (not skipped, has a completed interval)
	carried  bool // executed in an EARLIER attempt and reused by this one
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func secs(d time.Duration) float64 { return math.Round(d.Seconds()*10) / 10 }

// viewJobs classifies each job relative to the attempt's start. A skipped job
// is never executed (GitHub stamps it with a completion before its start). A
// job that started before this attempt started was carried over by a re-run.
func viewJobs(jobs []apiJob, attemptStart time.Time) []jobView {
	out := make([]jobView, 0, len(jobs))
	for jI := range jobs {
		j := &jobs[jI]
		v := jobView{api: *j}
		v.start, _ = parseTime(j.StartedAt)
		v.end, _ = parseTime(j.CompletedAt)
		v.created, _ = parseTime(j.CreatedAt)
		v.executed = j.Conclusion != "skipped" && j.Status == "completed" &&
			!v.start.IsZero() && !v.end.IsZero() && !v.end.Before(v.start) && len(j.Steps) > 0
		v.carried = v.executed && !attemptStart.IsZero() && v.start.Before(attemptStart)
		out = append(out, v)
	}
	return out
}

func (v jobView) inAttempt() bool { return v.executed && !v.carried }

// stepPhase maps a step name to setup | work | teardown. The names are GitHub's
// own ("Set up job", "Post …", "Complete job") plus the repository's shared
// setup steps; anything unrecognised is work, so the split can only
// under-report setup, never invent it.
func stepPhase(name string) string {
	switch {
	case name == "Set up job", strings.HasPrefix(name, "Pre "),
		strings.Contains(name, "Harden runner"), strings.HasPrefix(name, "Run actions/checkout"),
		strings.Contains(name, "setup-go"), name == "Download dependencies":
		return "setup"
	case strings.HasPrefix(name, "Post "), name == "Complete job":
		return "teardown"
	default:
		return "work"
	}
}

func jobTiming(v jobView) JobTiming {
	jt := JobTiming{Name: v.api.Name, Conclusion: v.api.Conclusion, Seconds: secs(v.end.Sub(v.start))}
	if !v.created.IsZero() && v.start.After(v.created) {
		jt.Queue = secs(v.start.Sub(v.created))
	}
	for _, s := range v.api.Steps {
		st, ok1 := parseTime(s.StartedAt)
		en, ok2 := parseTime(s.CompletedAt)
		if !ok1 || !ok2 || en.Before(st) || s.Conclusion == "skipped" {
			continue
		}
		d := secs(en.Sub(st))
		switch stepPhase(s.Name) {
		case "setup":
			jt.Setup += d
		case "teardown":
			jt.Teardown += d
		default:
			jt.Work += d
		}
	}
	return jt
}

// jobGroups names the optional job families that executed, in a stable order.
func jobGroups(views []jobView) []string {
	has := map[string]bool{}
	for vI := range views {
		v := &views[vI]
		if !v.executed {
			continue
		}
		n := v.api.Name
		switch {
		case shardJobRE.MatchString(n):
			has["race"] = true
		case strings.HasPrefix(n, legacyRaceJobPrefix):
			// The pre-stage-5C single-process race job: a different engine
			// with a different duration, so a different comparison group.
			has["race-unsharded"] = true
		case n == auditReferenceJob:
			has["audit"] = true
		case strings.Contains(n, "Frontend ·"):
			has["frontend"] = true
		case strings.Contains(n, "MCP design predicates"):
			has["mcp"] = true
		case strings.Contains(n, "maint-agent"):
			has["maint"] = true
		case strings.HasPrefix(n, "QA · Application logic"):
			has["qa-layers"] = true
		}
	}
	order := []string{"race", "race-unsharded", "audit", "qa-layers", "frontend", "mcp", "maint"}
	var out []string
	for _, g := range order {
		if has[g] {
			out = append(out, g)
		}
	}
	return out
}

func groupKey(groups []string) string {
	if len(groups) == 0 {
		return "minimal"
	}
	return strings.Join(groups, "+")
}

// titleFacts reads the dispatch inputs the workflows' run-name publishes.
func titleFacts(title string) (audit *bool, fault string) {
	if m := titleAuditRE.FindStringSubmatch(title); m != nil {
		b := m[1] == "true"
		audit = &b
	}
	if m := titleFaultRE.FindStringSubmatch(title); m != nil {
		fault = m[1]
	}
	return audit, fault
}

// executedFaultStep reports a qualification-fault step that actually ran.
func executedFaultStep(views []jobView) string {
	for vI := range views {
		v := &views[vI]
		for _, s := range v.api.Steps {
			if strings.HasPrefix(s.Name, "Qualification fault") && s.Conclusion != "" && s.Conclusion != "skipped" {
				return s.Name
			}
		}
	}
	return ""
}

// isRaceJob matches the sharded engine's jobs ("… / Race · …") and the
// pre-5C single race job ("Gate · go test -race + coverage floors"), so
// executions from before the engine are still classified by what they ran.
func isRaceJob(name string) bool {
	return strings.Contains(name, "/ Race · ") || strings.HasPrefix(name, legacyRaceJobPrefix)
}

// raceScheduled reports whether the diff classifier sent the run down the race
// path: an engine job ("… / Race · …") exists and was not skipped. It is read
// from scheduling, not execution, so a code PR whose shards were cancelled
// before starting is still a code PR.
func raceScheduled(views []jobView) bool {
	for vI := range views {
		v := &views[vI]
		if isRaceJob(v.api.Name) && v.api.Conclusion != "skipped" {
			return true
		}
	}
	return false
}

func hasGroup(groups []string, g string) bool {
	for _, x := range groups {
		if x == g {
			return true
		}
	}
	return false
}

// classify decides the execution class from the workflow, the event and what
// ran. Every decision records its reason.
func classify(run apiRun, views []jobView, groups []string) (class string, fault string, auditRequested bool, reasons []string) {
	fault, auditRequested, reasons = declaredFacts(run, views, groups)
	if c, why := qualificationClass(run, fault, auditRequested); c != "" {
		if why != "" {
			reasons = append(reasons, why)
		}
		return c, fault, auditRequested, reasons
	}
	c, why := gateClass(run, views)
	return c, fault, auditRequested, append(reasons, why)
}

// declaredFacts gathers what the run says about itself: the run-name's audit
// and fault inputs, an executed qualification-fault step, and the audit jobs.
func declaredFacts(run apiRun, views []jobView, groups []string) (fault string, auditRequested bool, reasons []string) {
	// Only a dispatch's title is the workflow's run-name. On a pull request
	// display_title is the PR's own title, written by its author, and a push
	// shows the commit subject — so neither may declare an audit or a fault.
	var titleAudit *bool
	var titleFault string
	if run.Event == "workflow_dispatch" {
		titleAudit, titleFault = titleFacts(run.DisplayTitle)
	}
	stepFault := executedFaultStep(views)
	fault = titleFault
	if fault == "" && stepFault != "" {
		fault = "step:" + stepFault
	}
	auditRequested = run.Event == "schedule" || (titleAudit != nil && *titleAudit) || hasGroup(groups, "audit")
	if titleAudit != nil {
		reasons = append(reasons, fmt.Sprintf("run-name declares audit=%v", *titleAudit))
	}
	if titleFault != "" {
		reasons = append(reasons, "run-name declares fault="+titleFault)
	}
	if stepFault != "" {
		reasons = append(reasons, "a qualification fault step executed: "+stepFault)
	}
	return fault, auditRequested, reasons
}

// qualificationClass classifies the runs that are not ordinary gate
// executions: fault injection, the scheduled audit and manual dispatches.
func qualificationClass(run apiRun, fault string, auditRequested bool) (class, why string) {
	switch {
	case fault != "" && fault != "none":
		return classFaultInjection, ""
	case run.Event == "schedule":
		return classScheduledAudit, "event=schedule"
	case run.Event == "workflow_dispatch" && auditRequested:
		return classManualAudit, "dispatch with the unsharded audit"
	case run.Event == "workflow_dispatch":
		return classManualQualify, "dispatch without the audit"
	}
	return "", ""
}

// gateClass classifies an ordinary pull-request or main-push execution.
func gateClass(run apiRun, views []jobView) (class, why string) {
	switch run.Path {
	case qaWorkflowPath:
		if run.Event == "pull_request" {
			return classPRPassThrough, "QA is a pass-through shell on pull requests"
		}
		if run.Event == "push" && run.HeadBranch == "main" {
			return classMainQA, "push to main"
		}
	case fastWorkflowPath:
		if run.Event == "pull_request" && raceScheduled(views) {
			return classPRCode, "the race engine was scheduled (code diff)"
		}
		if run.Event == "pull_request" {
			return classPRDocsOnly, "the race engine was skipped (docs-only diff)"
		}
	}
	return classOther, fmt.Sprintf("no class for %s on %s", run.Path, run.Event)
}

func phaseStats(vals []float64) PhaseStats {
	ps := PhaseStats{Jobs: len(vals)}
	if len(vals) == 0 {
		return ps
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	for _, v := range s {
		ps.Sum += v
	}
	ps.Sum = math.Round(ps.Sum*10) / 10
	ps.Median = median(s)
	ps.Max = s[len(s)-1]
	return ps
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return math.Round((sorted[n/2-1]+sorted[n/2])/2*10) / 10
}

// unionSeconds is the length of the union of intervals: wall time during which
// at least one job was running. Overlapping (parallel) jobs count once.
func unionSeconds(iv [][2]time.Time) float64 {
	if len(iv) == 0 {
		return 0
	}
	sort.Slice(iv, func(i, j int) bool { return iv[i][0].Before(iv[j][0]) })
	var total time.Duration
	cur := iv[0]
	for _, x := range iv[1:] {
		if x[0].After(cur[1]) {
			total += cur[1].Sub(cur[0])
			cur = x
			continue
		}
		if x[1].After(cur[1]) {
			cur[1] = x[1]
		}
	}
	total += cur[1].Sub(cur[0])
	return secs(total)
}

// measureTiming computes elapsed and summed time for THIS attempt only.
func measureTiming(run apiRun, views []jobView, rep *RunReport) {
	start, ok := parseTime(run.RunStartedAt)
	t := &rep.Timing
	t.RunnerMinutesNote = runnerMinutesNote
	var iv [][2]time.Time
	var runner float64
	var queue, setup, work []float64
	var last time.Time
	for vI := range views {
		v := &views[vI]
		if !v.inAttempt() {
			continue
		}
		jt := jobTiming(*v)
		rep.JobSet.Executed = append(rep.JobSet.Executed, jt)
		iv = append(iv, [2]time.Time{v.start, v.end})
		runner += jt.Seconds
		queue = append(queue, jt.Queue)
		setup = append(setup, jt.Setup)
		work = append(work, jt.Work)
		if v.end.After(last) {
			last = v.end
		}
		if !ok {
			continue
		}
		switch {
		case strings.Contains(v.api.Name, aggregateJobPattern):
			e := secs(v.end.Sub(start))
			t.ElapsedToAggregate = &e
		case strings.HasSuffix(v.api.Name, raceVerdictJobSuffix):
			e := secs(v.end.Sub(start))
			t.ElapsedToRaceVerdict = &e
		}
	}
	t.RunnerMinutes = math.Round(runner/60*10) / 10
	t.Busy = unionSeconds(iv)
	if ok && !last.IsZero() {
		t.WallSpan = secs(last.Sub(start))
	}
	t.Queue, t.Setup, t.Work = phaseStats(queue), phaseStats(setup), phaseStats(work)
	t.AttemptQueue = attemptQueue(run, views, start, rep)
	if !ok {
		rep.Unknowns = append(rep.Unknowns, "run_started_at missing: elapsed time is not observable")
	}
	if t.ElapsedToAggregate == nil {
		rep.Unknowns = append(rep.Unknowns, "the aggregate job did not complete in this attempt: elapsed-to-aggregate is unknown")
	}
}

// attemptEnqueue is when this attempt was queued, when that is observable:
// the attempt endpoint's created_at, or the run's created_at on attempt 1.
// A re-run read through the runs endpoint or list carries attempt 1's
// created_at, and using it would add the interval between attempts.
func attemptEnqueue(run apiRun) (time.Time, bool) {
	if run.attemptCreatedAt != "" {
		return parseTime(run.attemptCreatedAt)
	}
	if run.RunAttempt <= 1 {
		return parseTime(run.CreatedAt)
	}
	return time.Time{}, false
}

// attemptQueue is the attempt's wait for its first runner: enqueue to the
// earliest start among this attempt's own jobs. Every job of the attempt
// that has started counts, completed or not — a run reported while still in
// progress has running jobs whose start is observed. Skipped jobs and jobs
// carried over from an earlier attempt (started before this one) do not.
// Unknown — nil, never zero — when the enqueue time was not observed.
func attemptQueue(run apiRun, views []jobView, attemptStart time.Time, rep *RunReport) *float64 {
	enq, ok := attemptEnqueue(run)
	if !ok {
		rep.Unknowns = append(rep.Unknowns, fmt.Sprintf("attempt %d's enqueue time was not observed (only the attempt endpoint carries it): attempt queue is unknown", run.RunAttempt))
		return nil
	}
	var first time.Time
	for vI := range views {
		v := &views[vI]
		switch {
		case v.api.Conclusion == "skipped", v.start.IsZero():
			continue
		case !attemptStart.IsZero() && v.start.Before(attemptStart):
			continue // carried over from an earlier attempt
		}
		if first.IsZero() || v.start.Before(first) {
			first = v.start
		}
	}
	if first.IsZero() || first.Before(enq) {
		rep.Unknowns = append(rep.Unknowns, "no job of this attempt started after its enqueue time: attempt queue is unknown")
		return nil
	}
	q := secs(first.Sub(enq))
	return &q
}

// Analyze builds a RunReport from GitHub metadata and whatever evidence was
// readable. It never fetches anything; every input is data.
func Analyze(run apiRun, jobs []apiJob, ev runEvidence) RunReport {
	start, _ := parseTime(run.RunStartedAt)
	views := viewJobs(jobs, start)
	rep := RunReport{
		Schema: runReportSchema,
		Run: RunIdentity{
			Workflow: run.Name, WorkflowPath: run.Path, Event: run.Event, RunID: run.ID,
			Attempt: run.RunAttempt, Rerun: run.RunAttempt > 1, HeadSHA: run.HeadSHA,
			HeadBranch: run.HeadBranch, DisplayTitle: run.DisplayTitle, Status: run.Status,
			Conclusion: run.Conclusion, CreatedAt: run.CreatedAt, AttemptCreatedAt: run.attemptCreatedAt,
			StartedAt: run.RunStartedAt,
		},
		Unknowns: []string{},
		Problems: []string{},
	}
	for vI := range views {
		v := &views[vI]
		switch {
		case v.carried:
			rep.JobSet.CarriedOver = append(rep.JobSet.CarriedOver, v.api.Name)
		case v.api.Conclusion == "skipped":
			rep.JobSet.Skipped = append(rep.JobSet.Skipped, v.api.Name)
		case !v.executed:
			rep.JobSet.Incomplete = append(rep.JobSet.Incomplete, v.api.Name)
		}
	}
	groups := jobGroups(views)
	rep.JobSet.Groups = groups
	rep.JobSet.Key = groupKey(groups)
	class, fault, auditReq, reasons := classify(run, views, groups)
	rep.Class, rep.Reasons = class, reasons
	rep.Config.Fault, rep.Config.AuditRequested = fault, auditReq
	rep.Config.TimingFileSource = ev.TimingFileSource
	if run.RunAttempt > 1 {
		rep.Unknowns = append(rep.Unknowns, "re-run attempt: artifacts are per run, not per attempt, so evidence may come from an earlier attempt")
	}
	if run.Status != "completed" {
		rep.Unknowns = append(rep.Unknowns, "run not completed when observed (status "+run.Status+")")
	}
	measureTiming(run, views, &rep)
	raceEvidence(run, views, groups, ev, &rep)
	auditEvidence(views, auditReq, ev, &rep)
	rep.Cohort = cohortOf(views, &rep)
	rep.Evidence.Read = append([]string{}, ev.Read...)
	sort.Strings(rep.Evidence.Read)
	rep.Evidence.Source = "metadata-only"
	if len(rep.Evidence.Read) > 0 {
		rep.Evidence.Source = "artifacts"
	}
	rep.Unknowns = append(rep.Unknowns, ev.Notes...)
	return rep
}

const cohortUnknown = "unknown"

var goReleaseLineRE = regexp.MustCompile(`^(go\d+\.\d+)(?:\.\d+)?$`)

// cohortOf derives the observed configuration the run executed under. Each
// component is read from something observed — job metadata for the platform
// and shard count, the shards' own meta.json for the toolchain — and is
// "unknown" when it was not. Nothing is filled in from what the workflow
// files say should have happened.
func cohortOf(views []jobView, rep *RunReport) Cohort {
	c := Cohort{Platform: observedPlatform(views), Image: rep.cohortImage, Shards: scheduledShards(views, rep), Toolchain: cohortUnknown}
	if c.Image == "" {
		c.Image = cohortUnknown
	}
	// Every scheduled shard's metadata must have been read: a shard that was
	// not may have run on another image or toolchain.
	complete := true
	if n, err := strconv.Atoi(c.Shards); err == nil && rep.cohortMetas != n {
		complete = false
		c.Image = cohortUnknown
		rep.Unknowns = append(rep.Unknowns, fmt.Sprintf("shard metadata read from %d of %d scheduled shards: an unread shard may have run another image or toolchain", rep.cohortMetas, n))
	}
	if complete {
		c.Toolchain = toolchainLine(rep.Toolchain)
	}
	switch {
	case c.Shards == "none":
		// No race engine ran: there is no toolchain to observe and none to
		// compare. "n/a", not "unknown" — unknown always means unobserved.
		c.Toolchain = "n/a"
	case c.Toolchain == cohortUnknown:
		rep.Unknowns = append(rep.Unknowns, "toolchain not observed (no shard meta.json read): this run's cohort is unverified")
	}
	if c.Image == cohortUnknown {
		rep.Unknowns = append(rep.Unknowns, "runner image not observed (no shard reported ImageOS): this run's cohort is unverified")
	}
	c.Verified = c.Platform != cohortUnknown && c.Toolchain != cohortUnknown &&
		c.Image != cohortUnknown && !strings.HasPrefix(c.Image, "mixed:")
	c.Key = "platform=" + c.Platform + ";image=" + c.Image + ";shards=" + c.Shards + ";toolchain=" + c.Toolchain
	return c
}

// toolchainLine is the Go release line and GOOS/GOARCH, or unknown.
func toolchainLine(tc *Toolchain) string {
	if tc == nil || tc.Go == "" || tc.GOOS == "" || tc.GOARCH == "" {
		return cohortUnknown
	}
	line := tc.Go
	if m := goReleaseLineRE.FindStringSubmatch(tc.Go); m != nil {
		line = m[1]
	}
	return line + " " + tc.GOOS + "/" + tc.GOARCH
}

// observedPlatform is the distinct runner label sets and runner groups of the
// executed jobs, sorted. Any executed job without them makes it unknown.
func observedPlatform(views []jobView) string {
	seen := map[string]bool{}
	for vI := range views {
		v := &views[vI]
		if !v.executed {
			continue
		}
		if len(v.api.Labels) == 0 || v.api.RunnerGroupName == "" {
			return cohortUnknown
		}
		labels := append([]string(nil), v.api.Labels...)
		sort.Strings(labels)
		seen[strings.Join(labels, "+")+"@"+v.api.RunnerGroupName] = true
	}
	if len(seen) == 0 {
		return cohortUnknown
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// scheduledShards counts the root-shard jobs GitHub scheduled (not skipped),
// which is the engine's shard count even when a shard failed or was
// cancelled. "none" when no shard job was scheduled. The verdict's own count,
// when read, must agree.
func scheduledShards(views []jobView, rep *RunReport) string {
	idx := map[int]bool{}
	for vI := range views {
		v := &views[vI]
		if m := shardJobRE.FindStringSubmatch(v.api.Name); m != nil && v.api.Conclusion != "skipped" {
			if i, err := strconv.Atoi(m[1]); err == nil {
				idx[i] = true
			}
		}
	}
	if len(idx) == 0 {
		return "none"
	}
	if rep.Config.Shards > 0 && rep.Config.Shards != len(idx) {
		rep.Problems = append(rep.Problems, fmt.Sprintf("the verdict reports %d shards, GitHub scheduled %d shard jobs", rep.Config.Shards, len(idx)))
	}
	return strconv.Itoa(len(idx))
}

func jobByName(views []jobView, pred func(string) bool) *jobView {
	for i := range views {
		if pred(views[i].api.Name) {
			return &views[i]
		}
	}
	return nil
}

func jobSecondsIfInAttempt(v *jobView) *float64 {
	if v == nil || !v.inAttempt() {
		return nil
	}
	s := secs(v.end.Sub(v.start))
	return &s
}

// raceEvidence fills the race statistics and the verdict state, and checks the
// identities the evidence claims against the run.
func raceEvidence(run apiRun, views []jobView, groups []string, ev runEvidence, rep *RunReport) {
	verdictJob := jobByName(views, func(n string) bool { return strings.HasSuffix(n, raceVerdictJobSuffix) })
	switch {
	case hasGroup(groups, "race-unsharded"):
		rep.Evidence.Verdict = "missing"
		rep.Unknowns = append(rep.Unknowns, "the pre-sharding race job publishes no verdict: completeness is unknown")
		return
	case !hasGroup(groups, "race") && (verdictJob == nil || !verdictJob.executed):
		rep.Evidence.Verdict = "not-run"
		return
	case ev.Verdict == nil:
		rep.Evidence.Verdict = "missing"
		rep.Unknowns = append(rep.Unknowns, "the race ran but its verdict.json was not readable: completeness is unknown")
		return
	}
	v := ev.Verdict
	rep.Run.TestedSHA = v.Commit
	rep.Evidence.VerdictProblems = v.Problems
	rep.Evidence.Verdict = "ok"
	if !v.OK || (verdictJob != nil && verdictJob.api.Conclusion != "success") {
		rep.Evidence.Verdict = "failed"
	}
	checkIdentity(run, ev, rep)

	rs := &RaceStats{
		BuildJobSeconds: jobSecondsIfInAttempt(jobByName(views, func(n string) bool { return strings.HasSuffix(n, "Race · compile root once + partition") })),
		VerdictSeconds:  jobSecondsIfInAttempt(verdictJob),
	}
	shardJobs := shardJobsByIndex(views)
	for _, s := range v.Shards {
		rs.Shards = append(rs.Shards, ShardStat{Index: s.Index, Entries: s.Entries, Skipped: s.Skipped,
			Test: s.TestSeconds, Estimated: s.Estimated, Job: jobSecondsIfInAttempt(shardJobs[s.Index])})
		rs.Inventory.RootEntries += s.Entries
		rs.Inventory.RootSkipped += s.Skipped
	}
	rs.Imbalance = imbalance(rs.Shards)
	rep.Config.Shards = len(v.Shards)
	rs.Lane = LaneStat{Packages: v.Lane.Packages, Seconds: v.Lane.Seconds,
		Job:     jobSecondsIfInAttempt(jobByName(views, func(n string) bool { return strings.HasSuffix(n, "Race · non-root packages") })),
		Slowest: topN(v.Lane.Elapsed, 5)}
	rs.Inventory.LanePackages = v.Lane.Packages
	rs.Inventory.LaneEntries = v.Completeness.LaneReportedEntries
	rs.Inventory.RootUniverseBlocks = v.Completeness.RootUniverseBlocks
	rs.Inventory.LaneUniverseBlocks = v.Completeness.LaneUniverseBlocks
	if v.Merged.Blocks > 0 {
		rs.Coverage = &CoverageFraction{Blocks: v.Merged.Blocks, Covered: v.Merged.Covered, Percent: v.Merged.Percent}
	}
	if slowest, ok := slowestRootTests(ev, v.Package); ok {
		rs.SlowestRootTests = slowest
	} else {
		rep.Unknowns = append(rep.Unknowns, "results.json not readable: slowest root tests are unknown")
	}
	rep.Race = rs
}

// shardJobsByIndex maps each root-shard job to the shard index in its name.
func shardJobsByIndex(views []jobView) map[int]*jobView {
	out := map[int]*jobView{}
	for i := range views {
		if m := shardJobRE.FindStringSubmatch(views[i].api.Name); m != nil {
			if idx, err := strconv.Atoi(m[1]); err == nil {
				out[idx] = &views[i]
			}
		}
	}
	return out
}

// slowestRootTests ranks the root package's tests by results.json, or reports
// that the document was not readable.
func slowestRootTests(ev runEvidence, pkg string) ([]NamedSeconds, bool) {
	if ev.Results == nil || pkg == "" || ev.Results[pkg] == nil {
		return nil, false
	}
	tests := map[string]float64{}
	for name, r := range ev.Results[pkg].Tests {
		if r != nil {
			tests[name] = r.Seconds
		}
	}
	return topN(tests, 10), true
}

// checkIdentity: every piece of evidence must describe the same checkout, and
// that checkout must be the run's own for every event except pull_request
// (where the engine tests the PR merge commit, which the run API does not
// expose).
func checkIdentity(run apiRun, ev runEvidence, rep *RunReport) {
	v := ev.Verdict
	if run.Event != "pull_request" && v.Commit != run.HeadSHA {
		rep.Problems = append(rep.Problems, fmt.Sprintf("verdict commit %s is not the run's head_sha %s", short(v.Commit), short(run.HeadSHA)))
	}
	if len(ev.ShardMetas) == 0 {
		rep.Unknowns = append(rep.Unknowns, "no shard meta.json readable: toolchain is unknown")
		return
	}
	var tc *Toolchain
	idx := make([]int, 0, len(ev.ShardMetas))
	for i := range ev.ShardMetas {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		m := ev.ShardMetas[i]
		if m.Commit != v.Commit {
			rep.Problems = append(rep.Problems, fmt.Sprintf("shard %d ran commit %s, the verdict judged %s", i, short(m.Commit), short(v.Commit)))
		}
		cur := Toolchain{Go: m.GoVersion, GOOS: m.GOOS, GOARCH: m.GOARCH}
		if tc == nil {
			tc = &cur
		} else if *tc != cur {
			rep.Problems = append(rep.Problems, fmt.Sprintf("shard %d reports toolchain %v, shard %d reports %v", i, cur, idx[0], *tc))
		}
	}
	rep.cohortMetas = len(idx)
	shardImage(ev, idx, tc, rep)
	rep.Toolchain = tc
	if len(ev.ShardMetas) != len(v.Shards) {
		rep.Unknowns = append(rep.Unknowns, fmt.Sprintf("toolchain read from %d of %d shards", len(ev.ShardMetas), len(v.Shards)))
	}
}

// shardImage records the runner image the shards ran on. Any shard that did
// not report its image leaves the run's image unobserved; shards on different
// images are "mixed:"; the image build is stated only when all shards agree.
func shardImage(ev runEvidence, idx []int, tc *Toolchain, rep *RunReport) {
	images, versions := map[string]bool{}, map[string]bool{}
	for _, i := range idx {
		images[ev.ShardMetas[i].RunnerImage] = true
		versions[ev.ShardMetas[i].RunnerImageVersion] = true
	}
	switch names := sortedKeys(images); {
	case images[""]:
	case len(names) == 1:
		rep.cohortImage = names[0]
		tc.RunnerImage = names[0]
		// The image build is stated only when every shard reports the same
		// one: during a rollout shards share an image OS but not a build.
		if vs := sortedKeys(versions); len(vs) == 1 && vs[0] != "" {
			tc.RunnerImageVersion = vs[0]
		} else {
			rep.Unknowns = append(rep.Unknowns, "shards reported different or missing runner image builds: the run's image build is unknown")
		}
	case len(names) > 1:
		rep.cohortImage = "mixed:" + strings.Join(names, "+")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	if sha == "" {
		return "<none>"
	}
	return sha
}

func imbalance(shards []ShardStat) Imbalance {
	if len(shards) == 0 {
		return Imbalance{}
	}
	var sum, lo, hi, estErr float64
	lo = math.Inf(1)
	for _, s := range shards {
		sum += s.Test
		lo = math.Min(lo, s.Test)
		hi = math.Max(hi, s.Test)
		if s.Estimated > 0 {
			estErr = math.Max(estErr, math.Abs(s.Test-s.Estimated)/s.Estimated)
		}
	}
	mean := sum / float64(len(shards))
	im := Imbalance{SpreadSeconds: math.Round((hi-lo)*10) / 10, EstimateError: math.Round(estErr*1000) / 1000}
	if mean > 0 {
		im.MaxOverMean = math.Round(hi/mean*1000) / 1000
	}
	return im
}

func topN(m map[string]float64, n int) []NamedSeconds {
	out := make([]NamedSeconds, 0, len(m))
	for k, v := range m {
		out = append(out, NamedSeconds{Name: k, Seconds: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seconds != out[j].Seconds {
			return out[i].Seconds > out[j].Seconds
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// auditEvidence decides the audit state. A requested audit whose jobs did not
// execute is "missing" — never "passed" — and one that executed but left no
// readable comparison is "unknown".
func auditEvidence(views []jobView, requested bool, ev runEvidence, rep *RunReport) {
	a := &rep.Evidence.Audit
	a.Requested = requested
	a.Problems = []string{}
	ref := jobByName(views, func(n string) bool { return n == auditReferenceJob })
	cmp := jobByName(views, func(n string) bool { return n == auditCompareJob })
	a.ReferenceJob, a.CompareJob = conclusionOf(ref), conclusionOf(cmp)
	if !requested {
		a.State = "not-requested"
		return
	}
	switch {
	case ref == nil || cmp == nil || !ref.executed || !cmp.executed:
		a.State = "missing"
		a.Problems = append(a.Problems, "an audit was requested but its reference or comparison job did not execute")
		return
	case ev.Comparison == nil:
		a.State = "unknown"
		if cmp.api.Conclusion != "success" || ref.api.Conclusion != "success" {
			a.State = "failed"
		}
		rep.Unknowns = append(rep.Unknowns, "the audit ran but comparison.json was not readable")
		return
	}
	c := ev.Comparison
	a.BlocksLost, a.BlocksGained, a.BlocksExcepted = len(c.Lost), len(c.Gained), len(c.Excepted)
	a.Problems = append(a.Problems, c.Problems...)
	a.State = "passed"
	if !c.OK || cmp.api.Conclusion != "success" || ref.api.Conclusion != "success" {
		a.State = "failed"
	}
	candidateIdentity(ev, rep)
}

// candidateIdentity accepts the audit's refreshed timing file as a candidate
// only when its provenance names this run and the tested checkout.
func candidateIdentity(ev runEvidence, rep *RunReport) {
	if ev.Candidate == nil {
		return
	}
	want := fmt.Sprintf("run %d @ %s", rep.Run.RunID, rep.Run.TestedSHA)
	if rep.Run.TestedSHA == "" || !strings.Contains(ev.Candidate.Source, want) {
		rep.Problems = append(rep.Problems, fmt.Sprintf("timing candidate source %q does not name %q", ev.Candidate.Source, want))
		return
	}
	// A re-run attempt never publishes a candidate: the audit artifacts are
	// per RUN, not per attempt, so a re-run can pair a fresh comparison with
	// evidence carried over from the attempt that failed — the same reason a
	// re-run never establishes a passing audit (auditRunPassed).
	if rep.Run.Rerun || rep.Run.Attempt > 1 {
		rep.Unknowns = append(rep.Unknowns, "timing candidate withheld: a re-run attempt's audit artifacts may mix attempts")
		return
	}
	rep.Evidence.Audit.TimingCandidate = rep.Evidence.Audit.State == "passed"
}

func conclusionOf(v *jobView) string {
	switch {
	case v == nil:
		return "absent"
	case v.api.Conclusion == "":
		return v.api.Status
	default:
		return v.api.Conclusion
	}
}
