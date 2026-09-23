package main

import (
	"regexp"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Where the production-size restore aggregate bound runs (CI-REDESIGN 6A).
//
// TestReadTarball_ProductionAggregateBound_Integration skips in the ordinary
// suite (it reads 256 MiB; tens of seconds under -race). This wall pins the one
// place it executes so the proof cannot silently become dead code:
//
//   - qa-gate.yml's qa-contract job ("QA · On-disk contract") runs it with
//     CULVERT_RESTORE_PRODUCTION_SIZE=1, selects exactly that test, and fails
//     unless the log carries its PASS line (a skip or a missing test fails);
//   - qa-contract runs on every event the QA gate runs substantively (not
//     pull_request, like every other QA job), and the QA aggregate needs it;
//   - the QA gate is a mandatory row of .github/release-evidence.txt, so a
//     failure refuses release promotion;
//   - the test still exists, and skips only on that env var.
// ─────────────────────────────────────────────────────────────────────────────

const (
	restoreLimitsJob  = "qa-contract"
	restoreLimitsTest = "TestReadTarball_ProductionAggregateBound_Integration"
)

func TestRestoreLimitsLane_ProductionSizeCaseRunsInQAContract(t *testing.T) {
	doc := genericWorkflow(t, qaGateWorkflowPath)
	job := asMap(asMap(doc["jobs"])[restoreLimitsJob])
	if job == nil {
		t.Fatalf("%s has no %s job", qaGateWorkflowPath, restoreLimitsJob)
	}
	var step map[string]interface{}
	for _, st := range jobSteps(job) {
		s := asMap(st)
		if strings.Contains(toStr(s["run"]), restoreLimitsTest) {
			step = s
		}
	}
	if step == nil {
		t.Fatalf("%s no longer runs %s — the production-size aggregate proof would never execute", restoreLimitsJob, restoreLimitsTest)
	}
	if got := toScalar(asMap(step["env"])[restoreProductionSizeEnv]); got != "1" {
		t.Errorf("the step must set %s=1 (got %q) — without it the test skips", restoreProductionSizeEnv, got)
	}
	run := shellCodeOnly(toStr(step["run"]))
	for _, want := range []string{
		"-run '^" + restoreLimitsTest + "$'",
		"--- PASS: " + restoreLimitsTest,
		"set -o pipefail",
	} {
		if !strings.Contains(run, want) {
			t.Errorf("the step must contain %q so only a PASS satisfies it", want)
		}
	}
	if strings.Contains(run, "-race") {
		t.Error("the production-size case runs WITHOUT -race here; under -race it costs ~40 s for no extra evidence")
	}

	// It runs whenever QA runs substantively, and the aggregate needs it.
	cond := normaliseExpr(toStr(job["if"]))
	for _, ev := range []string{"push", "workflow_dispatch"} {
		if !evalRaceOwnership(t, cond, ev, "refs/heads/main") {
			t.Errorf("%s must run on %s (if: %q)", restoreLimitsJob, ev, job["if"])
		}
	}
	wf := loadWorkflow(t, qaGateWorkflowPath)
	if !jobNeeds(qaGateJob(t, wf, qaGateAggregateJob))[restoreLimitsJob] {
		t.Errorf("the QA aggregate must need %s", restoreLimitsJob)
	}
	// And the QA gate gates releases.
	if !regexp.MustCompile(`(?m)^qa-gate\.yml\s+mandatory\s*$`).Match(mustRead(t, ".github/release-evidence.txt")) {
		t.Error(".github/release-evidence.txt must keep qa-gate.yml mandatory — it is what makes this proof block a release")
	}
}

func TestRestoreLimitsLane_TestExistsAndSkipsOnlyOnTheEnv(t *testing.T) {
	src := string(mustRead(t, "restore_decompression_bomb_test.go"))
	i := strings.Index(src, "func "+restoreLimitsTest+"(t *testing.T) {")
	if i < 0 {
		t.Fatalf("%s no longer declares %s", "restore_decompression_bomb_test.go", restoreLimitsTest)
	}
	body := src[i:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatalf("could not find the end of %s", restoreLimitsTest)
	}
	body = body[:end]
	if strings.Count(body, "t.Skip") != 1 || !strings.Contains(body, `os.Getenv(restoreProductionSizeEnv) != "1"`) {
		t.Errorf("%s must skip on exactly one condition — %s unset", restoreLimitsTest, restoreProductionSizeEnv)
	}
	for _, want := range []string{"readTarball(path, \"\")", "maxRestoreEntryBytes", "maxRestoreTotalBytes", "requireLimitError(t, err, tarballLimitTotal"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s must drive the production path with the production constants (missing %q)", restoreLimitsTest, want)
		}
	}
}
