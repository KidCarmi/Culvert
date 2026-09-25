package main

import (
	"regexp"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// CI-REDESIGN stage 6B wall: which ci-perf-report.yml jobs run for which event
// (roadmap/CI-REDESIGN.md §18.3.1).
//
// The reporter has two jobs with two costs. run-report reads ONE run; trend
// reads the recent history of every measured workflow. A dispatch with a
// run_id used to run both, so enriching N runs cost N full trends against the
// repository's shared API budget — 28 dispatches exhausted it and failed an
// unrelated automatic report on main. A targeted dispatch now reports its run
// only, and an empty dispatch is the trend.
//
// The matrix EVALUATES the workflow's own `if:` strings, including GitHub's
// job-skipping rule (an `if:` without a status function is implicitly
// `success() && …`, so a skipped or failed `needs` job skips it), so an
// equivalent rewrite passes and a wrong one fails. Two controls prove the
// matrix can fail: the pre-fix condition and the fixed condition without
// always() must each be rejected.
// ─────────────────────────────────────────────────────────────────────────────

// perfEvent is one triggering event as the reporter's conditions see it.
type perfEvent struct {
	name        string // github.event_name
	runID       string // inputs.run_id ("" when absent)
	wrEvent     string // github.event.workflow_run.event
	wrConcluded string // github.event.workflow_run.conclusion
}

// ciPerfTrendIfPreFix is the trend condition #1478 shipped, verbatim: it ran
// on EVERY workflow_dispatch.
const ciPerfTrendIfPreFix = "always() && ( github.event_name == 'schedule' || " +
	"github.event_name == 'workflow_dispatch' || " +
	"(github.event_name == 'workflow_run' && github.event.workflow_run.event == 'schedule'))"

// evalJobIf reports whether GitHub would run a job with condition expr and
// the given needs results for ev. It follows the documented rule: without a
// status-check function the condition is `success() && (expr)`, and success()
// holds only when every needed job succeeded. The workflow is never cancelled
// in this model, so cancelled() is false and always() is true.
func evalJobIf(t *testing.T, expr string, ev perfEvent, needs map[string]string) bool {
	t.Helper()
	work := normaliseExpr(expr)
	if work == "" {
		work = "success()"
	}
	status := regexp.MustCompile(`\b(always|success|failure|cancelled)\(\)`)
	if !status.MatchString(work) {
		work = "success() && (" + work + ")"
	}
	allOK, anyFailed := true, false
	for _, r := range needs {
		allOK = allOK && r == "success"
		anyFailed = anyFailed || r == "failure"
	}
	work = status.ReplaceAllStringFunc(work, func(m string) string {
		switch m {
		case "always()":
			return "true"
		case "success()":
			return boolLit(allOK)
		case "failure()":
			return boolLit(anyFailed)
		default:
			return "false"
		}
	})
	values := map[string]string{
		"github.event.workflow_run.conclusion": ev.wrConcluded,
		"github.event.workflow_run.event":      ev.wrEvent,
		"github.event_name":                    ev.name,
		"inputs.run_id":                        ev.runID,
	}
	cmp := regexp.MustCompile(`(github\.event\.workflow_run\.conclusion|github\.event\.workflow_run\.event|github\.event_name|inputs\.run_id)\s*(==|!=)\s*'([^']*)'`)
	work = cmp.ReplaceAllStringFunc(work, func(m string) string {
		g := cmp.FindStringSubmatch(m)
		eq := values[g[1]] == g[3]
		if g[2] == "!=" {
			eq = !eq
		}
		return boolLit(eq)
	})
	if strings.ContainsAny(work, ".'=!") {
		t.Fatalf("the reporter's condition uses a context this test cannot evaluate; extend evalJobIf.\ncondition: %s\nreduced:   %s", expr, work)
	}
	v, err := evalBool(work)
	if err != nil {
		t.Fatalf("cannot evaluate %q (reduced to %q): %v", expr, work, err)
	}
	return v
}

// perfJobs runs the two-job graph for ev with the given trend condition and
// run-report outcome (used only when run-report actually runs), and returns
// whether each job ran.
func perfJobs(t *testing.T, reportIf, trendIf string, ev perfEvent, reportOutcome string) (report, trend bool) {
	t.Helper()
	report = evalJobIf(t, reportIf, ev, nil)
	result := "skipped"
	if report {
		result = reportOutcome
	}
	trend = evalJobIf(t, trendIf, ev, map[string]string{"run-report": result})
	return report, trend
}

func ciPerfJobIfs(t *testing.T) (reportIf, trendIf string) {
	t.Helper()
	jobs := asMap(genericWorkflow(t, ciPerfReportPath)["jobs"])
	trend := asMap(jobs["trend"])
	if needs := toStr(trend["needs"]); needs != "run-report" {
		t.Fatalf("trend must keep `needs: run-report` so an audit's own report is readable before the trend; got %v", trend["needs"])
	}
	reportIf, trendIf = toStr(asMap(jobs["run-report"])["if"]), toStr(trend["if"])
	if !strings.HasPrefix(normaliseExpr(trendIf), "always() && (") {
		t.Fatalf("trend must stay `always() && (…)`: run-report is skipped on the schedule and may fail, and neither may hide the audit-freshness verdict; got %s", trendIf)
	}
	return reportIf, trendIf
}

var ciPerfDispatchMatrix = []struct {
	name          string
	ev            perfEvent
	reportOutcome string
	wantReport    bool
	wantTrend     bool
	why           string
}{
	{"targeted dispatch", perfEvent{name: "workflow_dispatch", runID: "35989051459"}, "success", true, false,
		"a dispatch with run_id reports that run only; the trend costs a full history read"},
	{"targeted dispatch whose report failed", perfEvent{name: "workflow_dispatch", runID: "35989051459"}, "failure", true, false,
		"a failed targeted report must not start a trend either"},
	{"empty dispatch", perfEvent{name: "workflow_dispatch"}, "success", false, true,
		"an empty dispatch is the deliberate trend run; run-report is skipped and always() keeps the trend"},
	{"weekly backstop", perfEvent{name: "schedule"}, "success", false, true,
		"the Sunday backstop notices an audit that never ran"},
	{"scheduled QA audit completed", perfEvent{name: "workflow_run", wrEvent: "schedule", wrConcluded: "success"}, "success", true, true,
		"the audit's completion reports it and refreshes the trend"},
	{"scheduled QA audit completed, its report failed", perfEvent{name: "workflow_run", wrEvent: "schedule", wrConcluded: "failure"}, "failure", true, true,
		"a failed report must not hide the audit-freshness verdict"},
	{"scheduled QA audit cancelled", perfEvent{name: "workflow_run", wrEvent: "schedule", wrConcluded: "cancelled"}, "success", false, true,
		"a cancelled audit is not reported, but the trend must still judge its freshness"},
	{"main push completed", perfEvent{name: "workflow_run", wrEvent: "push", wrConcluded: "success"}, "success", true, false,
		"ordinary main runs get a per-run report and no trend"},
	{"main push failed", perfEvent{name: "workflow_run", wrEvent: "push", wrConcluded: "failure"}, "success", true, false,
		"failed runs are reported too; only cancelled ones are skipped"},
	{"main push cancelled", perfEvent{name: "workflow_run", wrEvent: "push", wrConcluded: "cancelled"}, "success", false, false,
		"cancelled runs are measured by the trend from metadata, not reported one by one"},
	{"pull-request run", perfEvent{name: "workflow_run", wrEvent: "pull_request", wrConcluded: "success"}, "success", false, false,
		"PR runs are reported only on demand"},
	{"gate dispatch completed", perfEvent{name: "workflow_run", wrEvent: "workflow_dispatch", wrConcluded: "success"}, "success", true, false,
		"a dispatched gate run (e.g. a manual audit) is reported; the trend is the schedule's"},
}

func TestCIPerf_DispatchMatrix(t *testing.T) {
	reportIf, trendIf := ciPerfJobIfs(t)
	for _, tc := range ciPerfDispatchMatrix {
		t.Run(tc.name, func(t *testing.T) {
			report, trend := perfJobs(t, reportIf, trendIf, tc.ev, tc.reportOutcome)
			if report != tc.wantReport || trend != tc.wantTrend {
				t.Errorf("run-report=%v trend=%v, want run-report=%v trend=%v: %s",
					report, trend, tc.wantReport, tc.wantTrend, tc.why)
			}
		})
	}
}

// The matrix must be able to fail. The pre-fix condition runs a trend on a
// targeted dispatch, and dropping always() lets a skipped or failed run-report
// hide the trend: each must disagree with the matrix somewhere.
func TestCIPerf_DispatchMatrixRejectsKnownWrongConditions(t *testing.T) {
	reportIf, trendIf := ciPerfJobIfs(t)
	withoutAlways := strings.Replace(normaliseExpr(trendIf), "always() && ", "", 1)
	for name, wrong := range map[string]string{
		"pre-fix condition (trend on every dispatch)": ciPerfTrendIfPreFix,
		"fixed condition without always()":            withoutAlways,
	} {
		t.Run(name, func(t *testing.T) {
			if normaliseExpr(wrong) == normaliseExpr(trendIf) {
				t.Fatalf("the control is identical to the workflow's condition — it proves nothing")
			}
			for _, tc := range ciPerfDispatchMatrix {
				report, trend := perfJobs(t, reportIf, wrong, tc.ev, tc.reportOutcome)
				if report != tc.wantReport || trend != tc.wantTrend {
					return
				}
			}
			t.Errorf("the matrix accepts a known-wrong trend condition: %s", wrong)
		})
	}
}
