package main

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// CI-REDESIGN stage 6B wall: the weekly same-SHA equivalence audit and the
// performance reporter (roadmap/CI-REDESIGN.md §17).
//
// Four properties, each with a way to break it silently:
//
//  1. ONE audit predicate. qa-gate.yml writes it in five places (the
//     concurrency group, its cancel flag, both audit jobs' `if:`, and the
//     aggregate's require-success) because none of those can read `env`. If
//     the copies drift, an audit runs unrequired — so a skip passes — or the
//     gate demands jobs that never start.
//  2. An audit CANNOT pass without its evidence. needs-verdict reads a skipped
//     job as a pass; on an audit run the aggregate therefore requires the race,
//     coverage and both audit jobs to be exactly `success`. Driven here through
//     the REAL action shell, not a re-implementation.
//  3. Audits and main pushes never cancel each other: separate concurrency
//     groups, and audit runs never cancel in progress.
//  4. The reporter is isolated: read-only token, trusted code, no cache, no
//     artifact written to disk by the runner, and not release evidence — which
//     still comes only from event=push runs of main.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// qaAuditPredicate is the canonical "this QA run is an audit" condition.
	qaAuditPredicate = "github.event_name == 'schedule' || " +
		"(github.event_name == 'workflow_dispatch' && inputs.unsharded_audit)"
	ciPerfReportPath    = ".github/workflows/ci-perf-report.yml"
	releaseEvidencePath = ".github/release-evidence.txt"
	requireGatePath     = ".github/scripts/require-gate.sh"
	cireportAnalyzePath = "cmd/cireport/analyze.go"
)

// qaAuditRequired is the set an audit run must see as exactly `success`: the
// two audit jobs, and the sharded evidence and floors they are judged against.
var qaAuditRequired = []string{"qa-race", "qa-coverage", "qa-unsharded-audit", "qa-unsharded-audit-compare"}

// qaPushPredicate is the "this QA run is release evidence" condition. The
// workflow's push trigger is `branches: [main]`, and require-gate.sh reads
// only event=push runs of main, so the two describe the same set of runs.
const qaPushPredicate = "github.event_name == 'push'"

// qaRequireSuccessExpr is the ONE expression the aggregate passes to
// needs-verdict, in evaluation order: the audit arm, then the main-push arm,
// then ” for a pull request or an ordinary dispatch. Pinned whole rather
// than decomposed — a nested ternary is exactly where an arm can be added,
// reordered or silently emptied.
func qaRequireSuccessExpr() string {
	return "${{ (" + qaAuditPredicate + ") && '" + strings.Join(qaAuditRequired, ",") + "'" +
		" || " + qaPushPredicate + " && '" + strings.Join(qaSubstantiveJobs, ",") + "'" +
		" || '' }}"
}

// auditIs evaluates qaAuditPredicate's workflow copy for one (event, input).
func auditIs(t *testing.T, cond, event string, input bool) bool {
	t.Helper()
	return evalRaceOwnership(t, strings.ReplaceAll(cond, "inputs.unsharded_audit", boolLit(input)), event, "refs/heads/main")
}

func qaAggregateRequireSuccess(t *testing.T) string {
	t.Helper()
	agg := asMap(asMap(genericWorkflow(t, qaGateWorkflowPath)["jobs"])[qaGateAggregateJob])
	for _, st := range agg["steps"].([]interface{}) {
		step := asMap(st)
		if strings.Contains(toStr(step["uses"]), needsVerdictActionRef) {
			return normaliseExpr(toStr(asMap(step["with"])["require-success"]))
		}
	}
	t.Fatalf("the QA aggregate does not use %s — the selector is stale", needsVerdictActionRef)
	return ""
}

// ─── 1. One predicate ────────────────────────────────────────────────────────

func TestCIPerf_AuditPredicateIsSingleSourced(t *testing.T) {
	wf := loadWorkflow(t, qaGateWorkflowPath)
	if got := normaliseExpr(qaGateJob(t, wf, qaAuditJob).If); got != qaAuditPredicate {
		t.Errorf("%s `if:` drifted from the audit predicate.\n got: %s\nwant: %s", qaAuditJob, got, qaAuditPredicate)
	}
	if got, want := normaliseExpr(qaGateJob(t, wf, qaAuditCompareJob).If), "always() && ("+qaAuditPredicate+")"; got != want {
		t.Errorf("%s `if:` drifted.\n got: %s\nwant: %s", qaAuditCompareJob, got, want)
	}

	conc := asMap(genericWorkflow(t, qaGateWorkflowPath)["concurrency"])
	if got, want := normaliseExpr(toStr(conc["group"])),
		"${{ ("+qaAuditPredicate+") && 'qa-audit' || 'qa-gate' }}-${{ github.ref }}"; got != want {
		t.Errorf("concurrency group drifted.\n got: %s\nwant: %s", got, want)
	}
	if got, want := normaliseExpr(toStr(conc["cancel-in-progress"])), "${{ !("+qaAuditPredicate+") }}"; got != want {
		t.Errorf("cancel-in-progress drifted.\n got: %s\nwant: %s", got, want)
	}

	req := qaAggregateRequireSuccess(t)
	if want := qaRequireSuccessExpr(); req != want {
		t.Errorf("the aggregate's require-success drifted.\n got: %s\nwant: %s", req, want)
	}
	// Restated from the expression itself, so a future rewrite that keeps the
	// shape but empties an arm still fails here.
	if got := requiredList(t, req); !slices.Equal(got, qaAuditRequired) {
		t.Errorf("an audit run must require exactly %v to be `success`; require-success lists %v", qaAuditRequired, got)
	}
	if !strings.HasSuffix(req, "|| '' }}") {
		t.Errorf("a PULL REQUEST or an ordinary dispatch must require nothing (the pass-through shape depends on it); require-success = %s", req)
	}
}

func requiredList(t *testing.T, req string) []string {
	t.Helper()
	return requireArms(t, req)[0]
}

// requireArms returns every `&& '<list>'` arm of the require-success
// expression, in evaluation order: [0] the audit arm, [1] the main-push arm.
// Reading the arms OUT of the workflow (rather than restating them) is what
// makes the behavioural gates below real: empty an arm in qa-gate.yml and the
// gate for that arm fails, because it is driven with the workflow's own value.
func requireArms(t *testing.T, req string) [][]string {
	t.Helper()
	ms := regexp.MustCompile(`&& '([^']*)'`).FindAllStringSubmatch(req, -1)
	if len(ms) != 2 {
		t.Fatalf("require-success must carry exactly two required-job arms (audit, push); got %d in %q", len(ms), req)
	}
	out := make([][]string, 0, 2)
	for _, m := range ms {
		if m[1] == "" {
			t.Fatalf("an arm of require-success is empty — that arm requires nothing: %q", req)
		}
		out = append(out, strings.Split(m[1], ","))
	}
	return out
}

// qaPushRequired is the job list the aggregate requires on a main push, read
// from the workflow.
func qaPushRequired(t *testing.T) []string {
	t.Helper()
	return requireArms(t, qaAggregateRequireSuccess(t))[1]
}

// The predicate itself: an audit on the schedule and on an opted-in dispatch,
// never on a push, a pull request or a default dispatch.
func TestCIPerf_AuditPredicateMatrix(t *testing.T) {
	for _, tc := range []struct {
		event string
		input bool
		want  bool
	}{
		{"push", false, false},
		{"pull_request", false, false},
		{"workflow_dispatch", false, false},
		{"workflow_dispatch", true, true},
		{"schedule", false, true},
	} {
		if got := auditIs(t, qaAuditPredicate, tc.event, tc.input); got != tc.want {
			t.Errorf("event=%s unsharded_audit=%v: audit=%v, want %v", tc.event, tc.input, got, tc.want)
		}
	}
}

// ─── 2. An audit cannot pass without its evidence ────────────────────────────

// TestCIPerf_ScheduledAuditRefusesMissingOrFailedEvidence drives the real
// needs-verdict shell with the require-success value the QA aggregate passes
// on an audit run. Skipped, failed and cancelled evidence all refuse; only a
// run in which every job executed successfully approves.
func TestCIPerf_ScheduledAuditRefusesMissingOrFailedEvidence(t *testing.T) {
	for _, bin := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s unavailable — the shared action's verdict needs it", bin)
		}
	}
	script := needsVerdictScript(t)
	require := strings.Join(requiredList(t, qaAggregateRequireSuccess(t)), ",")
	audit := func() map[string]string {
		m := allQAResults("success")
		for _, n := range qaAuditJobs {
			m[n] = "success"
		}
		return m
	}

	if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(audit()), require); !ok {
		t.Fatalf("an audit whose every job succeeded must approve; output:\n%s", out)
	}
	for _, name := range qaAuditRequired {
		for _, bad := range []string{"skipped", "failure", "cancelled"} {
			t.Run(name+"="+bad, func(t *testing.T) {
				r := audit()
				r[name] = bad
				out, ok := runNeedsVerdictRequiring(t, script, needsJSON(r), require)
				if ok {
					t.Fatalf("an audit approved with %s=%s — omitted or failed evidence must refuse; output:\n%s", name, bad, out)
				}
				if !strings.Contains(out, name) {
					t.Errorf("refusal does not name %q; output:\n%s", name, out)
				}
			})
		}
	}
	// The job an audit needs but never reports on (the needs map omits it).
	r := audit()
	delete(r, "qa-unsharded-audit-compare")
	if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(r), require); ok {
		t.Fatalf("an audit approved with the comparison absent from needs; output:\n%s", out)
	}
	// Control: the SAME skipped audit jobs on an ordinary main push (no
	// require-success) still approve — the audit requirement is scoped to
	// audit runs and does not change the main-push verdict.
	if out, ok := runNeedsVerdict(t, script, needsJSON(allQAResults("success"))); !ok {
		t.Fatalf("an ordinary main push with the audit jobs skipped must still approve; output:\n%s", out)
	}
}

// TestCIPerf_MainPushRefusesJobsThatNeverRan drives the REAL needs-verdict
// shell with the require-success value the QA aggregate passes on a main
// push — the runs .github/release-evidence.txt names `mandatory` and
// require-gate.sh reads.
//
// The fail-open it closes: needs-verdict reads a `skipped` need as a pass, so
// without require-success a main push in which every substantive job skipped
// left the aggregate (`if: always()`) as the only job that ran. It reported
// APPROVED, the WORKFLOW therefore concluded `success` rather than `skipped`,
// and require-gate.sh — which refuses a workflow-level `skipped` — had nothing
// to refuse. Release promotion could proceed on a commit no test had run
// against. Each sub-case below fails against the pre-fix expression.
func TestCIPerf_MainPushRefusesJobsThatNeverRan(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq unavailable — the shared action's verdict is jq-based")
	}
	script := needsVerdictScript(t)
	// Read from qa-gate.yml, not restated: emptying the push arm there must
	// fail this gate, which is the defect being closed.
	pushRequired := qaPushRequired(t)
	if !slices.Equal(pushRequired, qaSubstantiveJobs) {
		t.Fatalf("a main push must require every substantive job to be `success`.\n got: %v\nwant: %v", pushRequired, qaSubstantiveJobs)
	}
	require := strings.Join(pushRequired, ",")

	// The healthy shape: nine substantive jobs green, both audit jobs skipped
	// because this is not an audit run. Must still approve — the requirement
	// must not make an ordinary green push refuse.
	if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(allQAResults("success")), require); !ok {
		t.Fatalf("a green main push must approve; output:\n%s", out)
	}

	// The defect itself: nothing ran.
	if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(allQAResults("skipped")), require); ok {
		t.Fatalf("a main push in which EVERY job skipped approved — nothing ran is not approval; output:\n%s", out)
	}

	// One job at a time, both ways it can fail to produce evidence: skipped,
	// and absent from the needs map entirely.
	for _, name := range qaSubstantiveJobs {
		t.Run("skipped/"+name, func(t *testing.T) {
			results := allQAResults("success")
			results[name] = "skipped"
			out, ok := runNeedsVerdictRequiring(t, script, needsJSON(results), require)
			if ok {
				t.Fatalf("a main push approved with %q skipped; output:\n%s", name, out)
			}
			if !strings.Contains(out, name) {
				t.Errorf("the refusal does not name %q; output:\n%s", name, out)
			}
		})
		t.Run("absent/"+name, func(t *testing.T) {
			results := allQAResults("success")
			delete(results, name)
			if out, ok := runNeedsVerdictRequiring(t, script, needsJSON(results), require); ok {
				t.Fatalf("a main push approved with %q absent from needs; output:\n%s", name, out)
			}
		})
	}

	// CONTROL: the requirement is scoped to the push arm. A pull request
	// passes require-success='' and every job skips on its own `if:`, so the
	// required check must still report success or branch protection wedges
	// every PR at "Expected". The cheapest wrong fix — tightening the shared
	// action's default instead of one caller — fails here.
	if out, ok := runNeedsVerdict(t, script, needsJSON(allQAResults("skipped"))); !ok {
		t.Fatalf("the PR pass-through shape must still approve; output:\n%s", out)
	}
}

// TestCIPerf_RequiredJobsAreAllNeeded pins the invariant that makes a
// require-success list safe: needs-verdict reads its verdicts out of the
// `needs` context, so a job named in require-success but absent from the
// aggregate's `needs:` is not missing evidence — it is evidence that can never
// arrive, and the gate refuses EVERY run. The Security gate's `sbom` job is
// the live example of a job that runs on the same events but is deliberately
// not a need; see TestSecurityRace_RequiredJobsAreAllNeeded.
func TestCIPerf_RequiredJobsAreAllNeeded(t *testing.T) {
	needed := jobNeeds(loadWorkflow(t, qaGateWorkflowPath).Jobs[qaGateAggregateJob])
	if len(needed) == 0 {
		t.Fatalf("aggregate %q lists no needs — the selector is stale", qaGateAggregateJob)
	}
	for i, arm := range requireArms(t, qaAggregateRequireSuccess(t)) {
		for _, job := range arm {
			if !needed[job] {
				t.Errorf("require-success arm %d names %q, which is NOT in the aggregate's `needs:` — the gate would refuse every run", i, job)
			}
		}
	}
}

// TestCIPerf_RequireSuccessArmsAreDisjoint pins that the audit arm and the
// push arm can never both claim a run: an audit is a schedule or a dispatch,
// never a push, so the first arm winning never hides the second.
func TestCIPerf_RequireSuccessArmsAreDisjoint(t *testing.T) {
	for _, ev := range []string{"push", "pull_request", "workflow_dispatch", "schedule"} {
		for _, input := range []bool{false, true} {
			isAudit := auditIs(t, qaAuditPredicate, ev, input)
			isPush := ev == "push"
			if isAudit && isPush {
				t.Errorf("event=%s unsharded_audit=%v matches BOTH require-success arms", ev, input)
			}
		}
	}
}

// ─── 3. Audits and main pushes do not cancel each other ──────────────────────

func TestCIPerf_AuditConcurrencyIsSeparate(t *testing.T) {
	conc := asMap(genericWorkflow(t, qaGateWorkflowPath)["concurrency"])
	group := normaliseExpr(toStr(conc["group"]))
	cancel := normaliseExpr(toStr(conc["cancel-in-progress"]))
	for _, tc := range []struct {
		event string
		input bool
	}{{"push", false}, {"workflow_dispatch", false}, {"workflow_dispatch", true}, {"schedule", false}} {
		isAudit := auditIs(t, qaAuditPredicate, tc.event, tc.input)
		prefix := map[bool]string{true: "qa-audit", false: "qa-gate"}[isAudit]
		// The group's value is `<prefix>-<ref>` and cancellation is its
		// negation — evaluated from the workflow's own strings.
		inner := strings.TrimSuffix(strings.TrimPrefix(cancel, "${{ !("), ") }}")
		cancels := !auditIs(t, inner, tc.event, tc.input)
		if !strings.Contains(group, "'"+prefix+"'") || cancels == isAudit {
			t.Errorf("event=%s audit=%v: group prefix %s cancel=%v — an audit must have its own group and never cancel; an ordinary run keeps cancelling superseded runs",
				tc.event, tc.input, prefix, cancels)
		}
	}
	if strings.Contains(group, "github.sha") || strings.Contains(group, "run_id") {
		t.Errorf("the group must stay per-ref (%s): a per-SHA or per-run group would stop superseded main pushes being cancelled", group)
	}
}

// ─── 4. The reporter is isolated and is not evidence ─────────────────────────

func TestCIPerf_ReporterIsReadOnlyAndTrusted(t *testing.T) {
	doc := genericWorkflow(t, ciPerfReportPath)
	raw := string(mustRead(t, ciPerfReportPath))

	perms := asMap(doc["permissions"])
	if len(perms) != 2 || perms["actions"] != "read" || perms["contents"] != "read" {
		t.Errorf("the reporter's token must be exactly actions:read + contents:read; got %v", doc["permissions"])
	}
	on := asMap(doc["on"])
	for k := range on {
		if !slices.Contains([]string{"workflow_run", "schedule", "workflow_dispatch"}, k) {
			t.Errorf("unexpected trigger %q — pull_request/pull_request_target/push would run the reporter on, or as, the PR", k)
		}
	}
	var gates []string
	for _, w := range asMap(on["workflow_run"])["workflows"].([]interface{}) {
		gates = append(gates, toStr(w))
	}
	for _, pair := range [][2]string{{"Fast PR Gate", ".github/workflows/pr-fast-gate.yml"}, {"QA Gate", qaGateWorkflowPath}} {
		if !slices.Contains(gates, pair[0]) {
			t.Errorf("workflow_run must follow %q; follows %v", pair[0], gates)
		}
		if toStr(genericWorkflow(t, pair[1])["name"]) != pair[0] {
			t.Errorf("%s is no longer named %q — the reporter's workflow_run trigger would silently stop firing", pair[1], pair[0])
		}
	}
	if strings.Contains(raw, "secrets.") {
		t.Error("the reporter must use only the read-only GITHUB_TOKEN")
	}

	for name, j := range asMap(doc["jobs"]) {
		job := asMap(j)
		if job["permissions"] != nil {
			t.Errorf("job %s widens permissions (%v)", name, job["permissions"])
		}
		for _, st := range job["steps"].([]interface{}) {
			checkReporterStep(t, name, asMap(st))
		}
	}
}

// checkReporterStep pins one reporter step to the isolation contract.
func checkReporterStep(t *testing.T, name string, step map[string]interface{}) {
	t.Helper()
	uses, with := toStr(step["uses"]), asMap(step["with"])
	switch {
	case strings.HasPrefix(uses, "actions/checkout@"):
		if with["persist-credentials"] != false {
			t.Errorf("%s: checkout must set persist-credentials: false", name)
		}
		// Pinned explicitly: without `ref`, checkout follows the triggering
		// ref, and a dispatch with --ref <branch> would build that branch's
		// unreviewed collector.
		if toStr(with["ref"]) != "${{ github.event.repository.default_branch }}" || with["repository"] != nil {
			t.Errorf("%s: checkout must pin ref to the default branch — never a PR head, a dispatched branch or another repository (got %v)", name, with)
		}
	case strings.HasPrefix(uses, "actions/setup-go@"):
		if with["cache"] != false {
			t.Errorf("%s: setup-go must set cache: false — a cache restored here may have been written by a PR run", name)
		}
	case strings.Contains(uses, "cache"), strings.Contains(uses, "download-artifact"), strings.HasPrefix(uses, "./"):
		t.Errorf("%s: step uses %q — the reporter restores no cache, downloads no artifact to disk and runs no repository action", name, uses)
	}
	if run := shellCodeOnly(toStr(step["run"])); run != "" {
		if strings.Contains(run, "${{") {
			t.Errorf("%s: a run body interpolates an expression; pass event data through env so it is never parsed as shell:\n%s", name, run)
		}
		if strings.Contains(run, "go run") && toStr(asMap(step["env"])["GOPROXY"]) != "off" {
			t.Errorf("%s: `go run` must build with GOPROXY=off — the collector is stdlib-only and must fetch nothing", name)
		}
	}
}

// The reporter's own collector must stay standard-library only; GOPROXY=off in
// the workflow depends on it.
func TestCIPerf_CollectorImportsOnlyTheStandardLibrary(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./cmd/cireport").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if p != "github.com/KidCarmi/Culvert/cmd/cireport" {
			t.Errorf("cmd/cireport depends on %s — the reporter workflow builds offline (GOPROXY=off)", p)
		}
	}
}

// Neither the reporter nor a scheduled/dispatched audit can become release
// evidence: the manifest does not name the reporter, and the release predicate
// still reads only event=push runs of main.
func TestCIPerf_NotReleaseEvidence(t *testing.T) {
	manifest := string(mustRead(t, releaseEvidencePath))
	if strings.Contains(manifest, "ci-perf-report") {
		t.Errorf("%s names the reporter — it is advisory and must never gate a release", releaseEvidencePath)
	}
	if !regexp.MustCompile(`(?m)^qa-gate\.yml\s+mandatory\s*$`).MatchString(manifest) {
		t.Errorf("qa-gate.yml must stay mandatory release evidence in %s", releaseEvidencePath)
	}
	gate := string(mustRead(t, requireGatePath))
	if !strings.Contains(gate, "&event=push&") || !strings.Contains(gate, `select(.head_branch == "main")`) {
		t.Errorf("%s no longer restricts evidence to event=push runs of main — a scheduled or dispatched audit could then satisfy release gating", requireGatePath)
	}
	for _, f := range mustGlob(t, ".github/workflows/*.yml") {
		if f == ciPerfReportPath {
			continue
		}
		if strings.Contains(string(mustRead(t, f)), "CI Performance Report") {
			t.Errorf("%s refers to the reporter — nothing may wait on or chain from it", f)
		}
	}
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil || len(m) == 0 {
		t.Fatalf("glob %s: %v (%d matches)", pattern, err, len(m))
	}
	return m
}

// The run-names publish the dispatch inputs in exactly the form the reporter
// parses, so classification never has to guess an audit or a fault.
func TestCIPerf_RunNamesMatchTheReporter(t *testing.T) {
	analyze := string(mustRead(t, cireportAnalyzePath))
	for _, re := range []string{"`\\baudit=(true|false)\\b`", "`\\bfault=([a-z-]+)\\b`"} {
		if !strings.Contains(analyze, re) {
			t.Fatalf("%s no longer parses run-names with %s — update this wall and the workflows' run-name together", cireportAnalyzePath, re)
		}
	}
	for path, wants := range map[string][]string{
		qaGateWorkflowPath:                   {"'QA Gate · scheduled equivalence audit'", "format('QA Gate · dispatch · audit={0}', inputs.unsharded_audit)"},
		".github/workflows/pr-fast-gate.yml": {"format('Fast PR Gate · dispatch · audit={0} · fault={1}', inputs.unsharded_audit, inputs.fault)"},
	} {
		rn := toStr(genericWorkflow(t, path)["run-name"])
		for _, w := range wants {
			if !strings.Contains(rn, w) {
				t.Errorf("%s run-name %q lacks %s", path, rn, w)
			}
		}
		if !strings.HasSuffix(strings.TrimSpace(rn), "|| '' }}") {
			t.Errorf("%s run-name must fall back to '' (GitHub's default title) on pushes and pull requests: %q", path, rn)
		}
	}
}

// The reporter's own cost stays bounded: no automatic job per pull-request or
// cancelled run (hundreds a week — more runner time than the audit), and the
// trend runs weekly or after a scheduled audit, never per gate run.
func TestCIPerf_ReporterCostIsBounded(t *testing.T) {
	jobs := asMap(genericWorkflow(t, ciPerfReportPath)["jobs"])
	report := normaliseExpr(toStr(asMap(jobs["run-report"])["if"]))
	for _, want := range []string{"github.event.workflow_run.event != 'pull_request'", "github.event.workflow_run.conclusion != 'cancelled'"} {
		if !strings.Contains(report, want) {
			t.Errorf("run-report must not fire automatically for every gate run; its `if:` lacks %q: %s", want, report)
		}
	}
	trend := normaliseExpr(toStr(asMap(jobs["trend"])["if"]))
	if !strings.Contains(trend, "(github.event_name == 'workflow_run' && github.event.workflow_run.event == 'schedule')") {
		t.Errorf("the trend may follow a gate run only when that run was the scheduled audit: %s", trend)
	}
}

// The freshness check's idea of WHEN the weekly audit is due must be the
// schedule qa-gate.yml actually uses, and the reporter's backstop must run
// only after that slot's grace period has ended: otherwise the same-day
// backstop judges an audit that is still allowed to be running, or looks for
// one at a time the workflow never schedules.
func TestCIPerf_AuditSlotMatchesTheSchedules(t *testing.T) {
	var b struct {
		Audit struct {
			Cron           string `json:"cron"`
			SlotGraceHours int    `json:"slotGraceHours"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(mustRead(t, ".github/ci-perf-baseline.json"), &b); err != nil {
		t.Fatal(err)
	}
	cronOf := func(path string) string {
		sched, _ := asMap(genericWorkflow(t, path)["on"])["schedule"].([]interface{})
		if len(sched) != 1 {
			t.Fatalf("%s must carry exactly one schedule, has %v", path, sched)
		}
		return toStr(asMap(sched[0])["cron"])
	}
	audit, backstop := cronOf(qaGateWorkflowPath), cronOf(ciPerfReportPath)
	if b.Audit.Cron != audit {
		t.Fatalf("baseline audit.cron %q differs from qa-gate.yml's schedule %q — freshness would look for the audit in the wrong slot", b.Audit.Cron, audit)
	}
	minutesOf := func(expr string) (day, mins int) {
		f := strings.Fields(expr)
		if len(f) != 5 {
			t.Fatalf("cron %q", expr)
		}
		m, _ := strconv.Atoi(f[0])
		h, _ := strconv.Atoi(f[1])
		d, _ := strconv.Atoi(f[4])
		return d, h*60 + m
	}
	ad, am := minutesOf(audit)
	bd, bm := minutesOf(backstop)
	if bd != ad || bm < am+b.Audit.SlotGraceHours*60 {
		t.Errorf("the backstop (%s) must run on the audit's day, after the slot (%s) plus its %d h grace", backstop, audit, b.Audit.SlotGraceHours)
	}
}
