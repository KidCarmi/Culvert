package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// ─────────────────────────────────────────────────────────────────────────────
// QA Gate scheduling wall (CI-REDESIGN stages 1 and 2A).
//
// STAGE 1. Six of the eight substantive QA jobs carried `needs: qa-logic` while
// reading no output and no artifact from it — the edge bought nothing but
// serialised ~14 minutes of the longest job in front of every one of them on
// main pushes and manual dispatches. Stage 1 removed those edges and stated the
// PR-time skip on each job explicitly, because the skip used to arrive by
// CASCADE from qa-logic's own `if:` — dropping the edge without restoring the
// condition would have started running the whole QA suite on every pull
// request.
//
// STAGE 2A gave exactly ONE of them the edge back, for the opposite reason:
// qa-coverage used to run the entire suite a SECOND time purely to instrument
// it, and now consumes the coverage profile qa-logic's race run publishes. That
// edge carries DATA, so it is justified where the six were not — and the
// distinction is the invariant this file pins (`qaAllowedJobEdges`), rather
// than a blanket "no edges" rule that would have to be deleted to ship 2A.
//
// This file is the anti-drift wall for that change. It parses the real
// workflow (never a substring scan of the whole file) and drives the REAL
// aggregate verdict implementation — the composite action the aggregate job
// actually `uses:` — rather than a re-implementation of its jq logic.
//
// KNOWN LIMITATION, deliberately NOT changed here and NOT asserted away:
// .github/actions/needs-verdict treats a `skipped` need as a pass on EVERY
// event, not only on pull requests, unless the caller passes `require-success`.
// The QA aggregate passes no `require-success`, so an all-skipped main-push run
// would report APPROVED. That is pre-existing behaviour shared by every gate
// aggregate in the repository; tightening it is a policy change to a shared
// action and belongs in its own reviewed diff (recorded as a follow-up in
// roadmap/CI-REDESIGN.md §8). TestQAGateVerdict_RealActionBehaviour pins the
// behaviour as it IS, including that gap, so a future fix is a visible diff.
// Live validation of this stage must therefore confirm that all eight jobs
// EXECUTED successfully, not merely that the aggregate went green.
// ─────────────────────────────────────────────────────────────────────────────

const (
	qaGateWorkflowPath    = ".github/workflows/qa-gate.yml"
	needsVerdictActionYM  = ".github/actions/needs-verdict/action.yml"
	qaGateAggregateJob    = "qa-gate-approved"
	qaGateAggregateName   = "✅ QA Gate — APPROVED"
	needsVerdictActionRef = "./.github/actions/needs-verdict"
	qaPRSkipCondition     = "github.event_name != 'pull_request'"
)

// qaSubstantiveJobs are the eight jobs the aggregate must wait for. Order is
// the workflow's own layer order (A–H) so a failure message reads like the file.
var qaSubstantiveJobs = []string{
	"qa-logic",
	"qa-determinism",
	"qa-coverage",
	"qa-infra-compose",
	"qa-os",
	"qa-contract",
	"qa-agent",
	"qa-bench",
}

// qaFreedJobs are the jobs that must NOT depend on qa-logic. Named explicitly
// (rather than derived as "everything else") so re-adding an edge to any one of
// them is a named failure.
//
// Stage 1 detached six. Stage 2A gave ONE of them — qa-coverage — a real
// dependency back, because qa-logic now publishes the coverage profile
// qa-coverage enforces the floors on, so it is deliberately absent here and
// pinned by TestQAGateCoverage_* instead. The other five stay listed: nothing
// has ever justified an edge for them.
var qaFreedJobs = []string{
	"qa-determinism",
	"qa-infra-compose",
	"qa-os",
	"qa-contract",
	"qa-bench",
}

// qaAllowedJobEdges is the COMPLETE set of dependencies permitted between
// substantive jobs, as "job -> the one job it may need". Anything outside this
// map is a scheduling regression; anything inside it must be justified by data
// crossing the edge, never by ordering preference.
var qaAllowedJobEdges = map[string]string{
	"qa-coverage": "qa-logic", // the coverage profile artifact (stage 2A)
}

func qaGateJob(t *testing.T, doc wfDoc, name string) wfJob {
	t.Helper()
	j, ok := doc.Jobs[name]
	if !ok {
		t.Fatalf("%s must carry the %q job", qaGateWorkflowPath, name)
	}
	return j
}

// ─── 1. The six freed jobs are detached and skip PRs on their own ────────────

// TestQAGateScheduling_FreedJobsAreIndependent pins the stage-1 change itself:
// the six jobs no longer depend on qa-logic, and each states the PR exclusion
// explicitly instead of inheriting it by cascade.
func TestQAGateScheduling_FreedJobsAreIndependent(t *testing.T) {
	doc := loadWorkflow(t, qaGateWorkflowPath)

	for _, name := range qaFreedJobs {
		j := qaGateJob(t, doc, name)

		if needs := jobNeeds(j); needs["qa-logic"] {
			t.Errorf("job %q declares `needs: qa-logic` again — it consumes no output or artifact from it, "+
				"so the edge only serialises the longest job in front of it (CI-REDESIGN stage 1)", name)
		}

		// `always()` would ALSO detach the job, and would additionally run it on
		// pull requests and after a cancellation. The condition must be the plain
		// event test.
		if strings.TrimSpace(j.If) != qaPRSkipCondition {
			t.Errorf("job %q must carry exactly `if: %s` (got %q). Without it the job no longer cascade-skips "+
				"from qa-logic and the full QA suite would start running on every pull request; "+
				"an always()/success() form would additionally defeat the aggregate.",
				name, qaPRSkipCondition, j.If)
		}
	}
}

// TestQAGateScheduling_SubstantiveGraphHasOnlyJustifiedEdges pins the property
// both stages depend on: the only dependency between substantive jobs is one
// that carries DATA. Stage 1 removed six edges that carried none; stage 2A
// added one that does (qa-coverage consumes qa-logic's coverage artifact).
//
// The assertion is on the whole edge SET, not on "no edges" and not on "these
// edges exist", so both regressions fail here: a re-added ordering edge, and a
// silently dropped artifact edge.
func TestQAGateScheduling_SubstantiveGraphHasOnlyJustifiedEdges(t *testing.T) {
	doc := loadWorkflow(t, qaGateWorkflowPath)

	substantive := map[string]bool{}
	for _, n := range qaSubstantiveJobs {
		substantive[n] = true
	}

	for _, name := range qaSubstantiveJobs {
		j := qaGateJob(t, doc, name)
		allowed, hasAllowed := qaAllowedJobEdges[name]
		edges := 0
		for dep := range jobNeeds(j) {
			if !substantive[dep] {
				continue
			}
			edges++
			if !hasAllowed || dep != allowed {
				t.Errorf("job %q waits for %q, which is not a justified edge. The QA layers stay independent "+
					"unless DATA crosses the edge; add it to qaAllowedJobEdges with the reason, or remove the `needs:`.", name, dep)
			}
		}
		if hasAllowed && edges == 0 {
			t.Errorf("job %q must keep `needs: %s` — it consumes that job's artifact, so dropping the edge "+
				"would let it run against a missing or stale profile", name, allowed)
		}
		if strings.TrimSpace(j.If) != qaPRSkipCondition {
			t.Errorf("job %q must carry `if: %s` so it skips on pull requests on its own (got %q)", name, qaPRSkipCondition, j.If)
		}
	}

	// Control: only the aggregate and the justified consumers may join. A wall
	// that passed because every job had been deleted would fail here.
	wantJoiners := map[string]bool{qaGateAggregateJob: true}
	for consumer := range qaAllowedJobEdges {
		wantJoiners[consumer] = true
	}
	for name := range doc.Jobs {
		if len(jobNeeds(doc.Jobs[name])) > 0 && !wantJoiners[name] {
			t.Errorf("job %q declares `needs:` but is neither the aggregate nor a justified consumer of another job's output", name)
		}
	}
	for name := range wantJoiners {
		if len(jobNeeds(qaGateJob(t, doc, name))) == 0 {
			t.Errorf("job %q must declare `needs:`", name)
		}
	}
}

// ─── 2. The trigger matrix is unchanged ──────────────────────────────────────

// TestQAGateScheduling_TriggerMatrixPreserved pins the event surface stage 1
// must not move: push to main, pull_request against main, manual dispatch —
// and NO schedule and NO tag push. Manual dispatch is deliberately unrestricted
// (any branch or tag), which is what makes this stage verifiable on a candidate
// branch without touching main.
func TestQAGateScheduling_TriggerMatrixPreserved(t *testing.T) {
	raw, err := os.ReadFile(qaGateWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", qaGateWorkflowPath, err)
	}

	var typed struct {
		Name string `yaml:"name"`
		On   struct {
			Push struct {
				Branches []string `yaml:"branches"`
				Tags     []string `yaml:"tags"`
			} `yaml:"push"`
			PullRequest struct {
				Branches []string `yaml:"branches"`
			} `yaml:"pull_request"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal(raw, &typed); err != nil {
		t.Fatalf("parse %s: %v", qaGateWorkflowPath, err)
	}

	// The workflow NAME is a branch-protection and release-evidence identity
	// (.github/release-evidence.txt matches by file path, require-gate.sh by
	// file path; the check name is what a human reads in the PR list).
	if typed.Name != "QA Gate" {
		t.Errorf("workflow name changed to %q — branch protection and the release evidence manifest are keyed on this gate", typed.Name)
	}

	if got := typed.On.Push.Branches; len(got) != 1 || got[0] != "main" {
		t.Errorf("push trigger must be exactly [main]; got %v", got)
	}
	if got := typed.On.Push.Tags; len(got) != 0 {
		t.Errorf("push.tags must stay ABSENT (CI review P0-3 removed it: auto-tag only tags SHAs already green on the main push); got %v", got)
	}
	if got := typed.On.PullRequest.Branches; len(got) != 1 || got[0] != "main" {
		t.Errorf("pull_request trigger must be exactly [main]; got %v", got)
	}

	// `on:` keys are checked generically as well, because a struct decode
	// cannot tell "workflow_dispatch: null" from "key absent", and cannot see
	// a newly-added `schedule:`.
	var keyed struct {
		On map[string]interface{} `yaml:"on"`
	}
	if err := yaml.Unmarshal(raw, &keyed); err != nil {
		t.Fatalf("parse %s (keys): %v", qaGateWorkflowPath, err)
	}
	if _, ok := keyed.On["workflow_dispatch"]; !ok {
		t.Error("workflow_dispatch must stay — it is the only way to exercise the full graph off main")
	}
	if wd, ok := keyed.On["workflow_dispatch"]; ok && wd != nil {
		// A `branches:` filter on workflow_dispatch would prevent validating this
		// change on a candidate branch.
		if m, isMap := wd.(map[string]interface{}); isMap {
			if _, restricted := m["branches"]; restricted {
				t.Error("workflow_dispatch must not be restricted to particular branches — manual dispatch is how the changed graph is validated off main")
			}
		}
	}
	if _, ok := keyed.On["schedule"]; ok {
		t.Error("qa-gate.yml has no scheduled trigger and stage 1 does not add one")
	}
	want := map[string]bool{"push": true, "pull_request": true, "workflow_dispatch": true}
	for k := range keyed.On {
		if !want[k] {
			t.Errorf("unexpected trigger %q — the stage-1 change must not widen the event matrix", k)
		}
	}
}

// ─── 3. The aggregate still joins all eight and stays fail-closed ────────────

// TestQAGateScheduling_AggregateStillJoinsEveryJob pins that detaching the six
// jobs did not detach them from the VERDICT. This is the half that keeps a
// qa-logic failure fatal: the freed jobs now run anyway, but the approval must
// still refuse.
func TestQAGateScheduling_AggregateStillJoinsEveryJob(t *testing.T) {
	doc := loadWorkflow(t, qaGateWorkflowPath)
	agg := qaGateJob(t, doc, qaGateAggregateJob)

	if agg.Name != qaGateAggregateName {
		t.Errorf("aggregate display name is %q, want %q — it is a required status check; renaming it wedges branch protection at \"Expected\"", agg.Name, qaGateAggregateName)
	}
	if strings.TrimSpace(agg.If) != "always()" {
		t.Errorf("aggregate `if:` must stay `always()` so the required check keeps reporting when the QA jobs skip on PRs; got %q", agg.If)
	}

	needs := jobNeeds(agg)
	for _, name := range qaSubstantiveJobs {
		if !needs[name] {
			t.Errorf("aggregate no longer needs %q — its failure would stop blocking the gate", name)
		}
	}
	if len(needs) != len(qaSubstantiveJobs) {
		t.Errorf("aggregate needs %d jobs, want exactly the %d substantive jobs (%v); got %v",
			len(needs), len(qaSubstantiveJobs), qaSubstantiveJobs, needs)
	}

	// The verdict must be delegated to the SHARED action, not hand-rolled: a
	// per-workflow jq copy is how four aggregates drifted apart before. Read the
	// aggregate's OWN steps — a whole-file substring scan would be satisfied by
	// the string appearing anywhere, including in a comment.
	usesShared, passesNeeds := false, false
	for _, st := range aggregateSteps(t) {
		if !strings.Contains(toStr(st["uses"]), needsVerdictActionRef) {
			continue
		}
		usesShared = true
		with, _ := st["with"].(map[string]interface{})
		if strings.Contains(toStr(with["needs-json"]), "toJSON(needs)") {
			passesNeeds = true
		}
	}
	if !usesShared {
		t.Errorf("aggregate must evaluate its needs through %s", needsVerdictActionRef)
	}
	if !passesNeeds {
		t.Errorf("aggregate must pass `needs-json: ${{ toJSON(needs) }}` to %s — otherwise the shared action judges nothing", needsVerdictActionRef)
	}
}

// aggregateSteps returns the aggregate job's steps as generic maps, so a step's
// `with:` can be inspected without adding QA-only fields to the wfStepWith
// struct that the release-workflow tests share.
func aggregateSteps(t *testing.T) []map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(qaGateWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", qaGateWorkflowPath, err)
	}
	var generic struct {
		Jobs map[string]struct {
			Steps []map[string]interface{} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("parse %s (generic): %v", qaGateWorkflowPath, err)
	}
	steps := generic.Jobs[qaGateAggregateJob].Steps
	if len(steps) == 0 {
		t.Fatalf("aggregate job %q has no steps — the selector is stale", qaGateAggregateJob)
	}
	return steps
}

// ─── 4. The REAL shared verdict implementation, exercised ────────────────────

// needsVerdictScript extracts the shell body the composite action actually
// runs. Exercising the real script (not a Go re-implementation of its jq) is
// the point: a re-implementation can agree with a test and disagree with CI.
func needsVerdictScript(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(needsVerdictActionYM)
	if err != nil {
		t.Fatalf("read %s: %v", needsVerdictActionYM, err)
	}
	var act struct {
		Runs struct {
			Using string `yaml:"using"`
			Steps []struct {
				Name  string `yaml:"name"`
				Shell string `yaml:"shell"`
				Run   string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &act); err != nil {
		t.Fatalf("parse %s: %v", needsVerdictActionYM, err)
	}
	if act.Runs.Using != "composite" {
		t.Fatalf("%s is no longer a composite action (using=%q) — this harness runs its shell directly", needsVerdictActionYM, act.Runs.Using)
	}
	body := ""
	for _, st := range act.Runs.Steps {
		if st.Shell == "bash" && strings.TrimSpace(st.Run) != "" {
			body += st.Run + "\n"
		}
	}
	if strings.TrimSpace(body) == "" {
		t.Fatalf("%s exposes no bash body — the selector is stale and this harness would prove nothing", needsVerdictActionYM)
	}
	return body
}

// needsJSON builds the shape `toJSON(needs)` produces for the QA aggregate.
func needsJSON(results map[string]string) string {
	var b strings.Builder
	b.WriteString("{")
	for i, name := range qaSubstantiveJobs {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:{\"result\":%q,\"outputs\":{}}", name, results[name])
	}
	b.WriteString("}")
	return b.String()
}

func allQAResults(result string) map[string]string {
	m := map[string]string{}
	for _, n := range qaSubstantiveJobs {
		m[n] = result
	}
	return m
}

// runNeedsVerdict executes the real action body against a needs payload and
// returns (combined output, exit-was-zero).
func runNeedsVerdict(t *testing.T, script, payload string) (string, bool) {
	t.Helper()
	dir := t.TempDir()
	sh := filepath.Join(dir, "verdict.sh")
	if err := os.WriteFile(sh, []byte(script), 0o700); err != nil { //nolint:gosec // test harness script, temp dir
		t.Fatalf("write harness script: %v", err)
	}
	summary := filepath.Join(dir, "step-summary.md")
	if err := os.WriteFile(summary, nil, 0o600); err != nil {
		t.Fatalf("seed step summary: %v", err)
	}
	// CommandContext, not Command: the harness must die with the test (noctx).
	// #nosec G204 -- the only variable is a path under this test's own t.TempDir();
	// the program is the literal "bash" and no caller supplies either.
	cmd := exec.CommandContext(t.Context(), "bash", sh)
	cmd.Env = append(os.Environ(),
		"NEEDS_JSON="+payload,
		"REQUIRE=", // the QA aggregate passes no require-success
		"TITLE="+qaGateAggregateName,
		"EXTRA=",
		"GITHUB_STEP_SUMMARY="+summary,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// TestQAGateVerdict_RealActionBehaviour drives the shared verdict action
// through the result shapes this stage can now produce, using the action's own
// shell. Nothing here re-implements its jq.
func TestQAGateVerdict_RealActionBehaviour(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq unavailable — the shared action's verdict is jq-based")
	}
	script := needsVerdictScript(t)

	t.Run("all success approves", func(t *testing.T) {
		out, ok := runNeedsVerdict(t, script, needsJSON(allQAResults("success")))
		if !ok {
			t.Fatalf("all-success needs must approve; output:\n%s", out)
		}
	})

	// The PR shape. Every substantive job skips on its own `if:` now that the
	// cascade is gone, and the required check must still report success.
	t.Run("pull-request all-skipped still approves", func(t *testing.T) {
		out, ok := runNeedsVerdict(t, script, needsJSON(allQAResults("skipped")))
		if !ok {
			t.Fatalf("all-skipped needs (the PR shape) must still approve or branch protection wedges at \"Expected\"; output:\n%s", out)
		}
		// Honest record of the KNOWN LIMITATION described in this file's header:
		// the action cannot tell a PR skip from a main-push skip, because the
		// event is not part of its input. Non-PR validation must therefore check
		// that the jobs RAN, not just that this verdict was green.
		t.Log("known limitation (follow-up, CI-REDESIGN §8): needs-verdict accepts `skipped` on every event unless the caller passes require-success; the QA aggregate passes none")
	})

	// Failure and cancellation must refuse, for EVERY substantive job — the
	// freed jobs included, which is exactly what "the approval must still fail"
	// means once a qa-logic failure no longer suppresses them.
	for _, bad := range []string{"failure", "cancelled"} {
		for _, name := range qaSubstantiveJobs {
			t.Run(bad+"/"+name, func(t *testing.T) {
				results := allQAResults("success")
				results[name] = bad
				out, ok := runNeedsVerdict(t, script, needsJSON(results))
				if ok {
					t.Fatalf("needs-verdict approved with %s=%s — the gate must refuse; output:\n%s", name, bad, out)
				}
				if !strings.Contains(out, name) {
					t.Errorf("refusal does not name the offending job %q; output:\n%s", name, out)
				}
			})
		}
	}
}
