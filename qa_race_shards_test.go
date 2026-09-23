package main

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// ─────────────────────────────────────────────────────────────────────────────
// Sharded race + coverage wall (CI-REDESIGN stage 5B; stage 5A was the pilot).
//
// qa-gate.yml's `qa-race` runs the full race + coverage suite as 4 isolated
// root-package shards plus every other package (.github/workflows/
// qa-race-shards.yml) and publishes the authoritative `qa-coverage` profile.
// An ordinary run has NO unsharded reference, so this file pins what makes it
// trustworthy on its own:
//
//  1. IT ALWAYS RUNS. qa-race runs on every event qa-logic runs on, calls the
//     reusable workflow with 4 shards, and the aggregate needs it.
//  2. FAIL-CLOSED, COMPLETE VERDICT. The verdict runs even when a producer
//     fails, judges every producer's result, judges the evidence against BOTH
//     independent block universes and the source inventory, guards the
//     profile, and is the ONLY producer of `qa-coverage`.
//  3. THE AUDIT IS OPT-IN AND JUDGED. The unsharded comparison runs only on a
//     dispatch with unsharded_audit=true, and when it runs the aggregate
//     waits for it; a lost covered block fails unless the checked-in
//     exceptions file justifies it (and that file is empty).
//  4. PARITY with the unsharded command: the same TEST_SEED and per-binary
//     -timeout.
//  5. Timing data only balances; its file stays usable.
//
// The tool's own behaviour (partition, selection, merge, completeness,
// comparison) is tested in cmd/rootshard, which `go test ./...` runs.
// ─────────────────────────────────────────────────────────────────────────────

const (
	qaRaceShardsWorkflowPath = ".github/workflows/qa-race-shards.yml"
	qaRaceJob                = "qa-race"
	qaAuditJob               = "qa-unsharded-audit"
	qaAuditCompareJob        = "qa-unsharded-audit-compare"
	qaAuditInput             = "unsharded_audit"
	qaRaceArtifactPfx        = "qa-race-"
	qaAuditArtifactPfx       = "qa-audit-"
	qaRaceTimingsPath        = ".github/qa-root-shard-timings.json"
	qaCoverageExceptionsPath = ".github/qa-root-shard-coverage-exceptions.json"
	qaRaceShardCount         = "4"
)

// genericWorkflow parses a workflow without the shared typed structs, so
// `uses:` on a job and `with:` on a step are visible.
func genericWorkflow(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return doc
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func TestQARaceShards_RunOnEveryQAExecution(t *testing.T) {
	doc := genericWorkflow(t, qaGateWorkflowPath)
	job := asMap(asMap(doc["jobs"])[qaRaceJob])
	if job == nil {
		t.Fatalf("qa-gate.yml must carry the %q job — it owns the race + coverage suite", qaRaceJob)
	}
	if got := toStr(job["uses"]); got != "./"+qaRaceShardsWorkflowPath {
		t.Errorf("%q must call the local reusable workflow %s (got uses: %q)", qaRaceJob, qaRaceShardsWorkflowPath, got)
	}
	if got := toScalar(asMap(job["with"])["shards"]); got != qaRaceShardCount {
		t.Errorf("%q must run %s shards (got %q) — the count is a measured decision, see roadmap/CI-REDESIGN.md §14", qaRaceJob, qaRaceShardCount, got)
	}
	if got := strings.TrimSpace(toStr(job["if"])); got != qaPRSkipCondition {
		t.Errorf("%q must run on every non-PR event exactly like the job it replaced (if: %s); got %q", qaRaceJob, qaPRSkipCondition, got)
	}
	agg := jobNeeds(qaGateJob(t, loadWorkflow(t, qaGateWorkflowPath), qaGateAggregateJob))
	if !agg[qaRaceJob] {
		t.Errorf("the QA aggregate must need %q — its failure is the application-logic failure", qaRaceJob)
	}
}

func TestQARaceShards_ReusableWorkflowHasNoTriggerOfItsOwn(t *testing.T) {
	doc := genericWorkflow(t, qaRaceShardsWorkflowPath)
	on := asMap(doc["on"])
	keys := make([]string, 0, len(on))
	for k := range on {
		keys = append(keys, k)
	}
	if _, ok := on["workflow_call"]; !ok || len(on) != 1 {
		t.Fatalf("%s must be triggered ONLY by workflow_call (got %v)", qaRaceShardsWorkflowPath, keys)
	}
	if p := doc["permissions"]; toStr(asMap(p)["contents"]) != "read" || len(asMap(p)) != 1 {
		t.Errorf("%s must stay read-only (permissions: contents: read); got %v", qaRaceShardsWorkflowPath, p)
	}
}

// uploadedArtifacts lists the artifact names a workflow's upload steps use.
func uploadedArtifacts(t *testing.T, path string, jobs ...string) []string {
	t.Helper()
	doc := genericWorkflow(t, path)
	var out []string
	for name, j := range asMap(doc["jobs"]) {
		if len(jobs) > 0 && !slices.Contains(jobs, name) {
			continue
		}
		steps, _ := asMap(j)["steps"].([]interface{})
		for _, st := range steps {
			s := asMap(st)
			if strings.Contains(toStr(s["uses"]), "actions/upload-artifact@") {
				out = append(out, resolveEngineName(t, path, toStr(asMap(s["with"])["name"])))
			}
		}
	}
	sort.Strings(out)
	return out
}

// engineInputRe matches a value the engine takes wholly from one of its
// workflow_call inputs (stage 5C parameterized the coverage artifact name).
var engineInputRe = regexp.MustCompile(`^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$`)

// engineInputDefault returns the declared default of one of the engine's
// workflow_call inputs, as text.
func engineInputDefault(t *testing.T, input string) string {
	t.Helper()
	doc := genericWorkflow(t, qaRaceShardsWorkflowPath)
	in := asMap(asMap(asMap(asMap(doc["on"])["workflow_call"])["inputs"])[input])
	if in == nil {
		t.Fatalf("%s declares no workflow_call input %q", qaRaceShardsWorkflowPath, input)
	}
	return toScalar(in["default"])
}

// resolveEngineName maps an engine value of the form `${{ inputs.X }}` to X's
// default — the value it takes for the QA gate, which passes nothing but
// `shards` (pinned by TestQARaceShards_QAKeepsEveryEngineDefault). Any other
// value, or any other workflow's value, is returned unchanged.
func resolveEngineName(t *testing.T, path, v string) string {
	t.Helper()
	if path != qaRaceShardsWorkflowPath {
		return v
	}
	if m := engineInputRe.FindStringSubmatch(strings.TrimSpace(v)); m != nil {
		return engineInputDefault(t, m[1])
	}
	return v
}

// TestQARaceShards_QAKeepsEveryEngineDefault pins that parameterizing the
// shared engine for the Fast gate (stage 5C) changed nothing for QA: qa-race
// passes `shards: 4` and nothing else, so the coverage artifact stays
// `qa-coverage`, no hardening step, no privileged job and no fault — and the
// defaults themselves are those values.
func TestQARaceShards_QAKeepsEveryEngineDefault(t *testing.T) {
	gate := genericWorkflow(t, qaGateWorkflowPath)
	with := asMap(asMap(asMap(gate["jobs"])[qaRaceJob])["with"])
	if len(with) != 1 || toScalar(with["shards"]) != qaRaceShardCount {
		t.Errorf("qa-gate.yml %s must pass exactly `shards: %s` to the engine (got %v) — every other input keeps its QA default",
			qaRaceJob, qaRaceShardCount, with)
	}
	for input, want := range map[string]string{
		"coverage-artifact": qaCoverageArtifact,
		"harden-runner":     "false",
		"privileged-test":   "",
		"fault":             "none",
	} {
		if got := engineInputDefault(t, input); got != want {
			t.Errorf("engine input %q defaults to %q, want %q (the QA gate relies on the default)", input, got, want)
		}
	}
}

func TestQARaceShards_ArtifactNamesAreDistinct(t *testing.T) {
	names := uploadedArtifacts(t, qaRaceShardsWorkflowPath)
	if len(names) < 6 {
		t.Fatalf("expected the build, shard, lane, universe, verdict and coverage uploads; found %v — the selector is stale", names)
	}
	for _, n := range names {
		if n != qaCoverageArtifact && !strings.HasPrefix(n, qaRaceArtifactPfx) {
			t.Errorf("sharded-run artifact %q lacks the %q prefix — it could collide with, or be consumed as, another artifact", n, qaRaceArtifactPfx)
		}
	}
	for _, n := range uploadedArtifacts(t, qaGateWorkflowPath, qaAuditJob, qaAuditCompareJob) {
		if !strings.HasPrefix(n, qaAuditArtifactPfx) {
			t.Errorf("audit artifact %q lacks the %q prefix", n, qaAuditArtifactPfx)
		}
	}
	ev, err := os.ReadFile(".github/release-evidence.txt")
	if err != nil {
		t.Fatalf("read release evidence manifest: %v", err)
	}
	for _, s := range []string{"qa-race", "qa-audit", "root-shard"} {
		if strings.Contains(string(ev), s) {
			t.Errorf(".github/release-evidence.txt references %q — release evidence is the QA gate's main-push result, not a job artifact", s)
		}
	}
}

func TestQARaceShards_VerdictFailsClosedAndIsComplete(t *testing.T) {
	doc := genericWorkflow(t, qaRaceShardsWorkflowPath)
	jobs := asMap(doc["jobs"])
	verdict := asMap(jobs["race-verdict"])
	if strings.TrimSpace(toStr(verdict["if"])) != "always()" {
		t.Errorf("race-verdict must run `if: always()` so a failed or cancelled producer yields a verdict that names it; got %v", verdict["if"])
	}
	needs, _ := verdict["needs"].([]interface{})
	got := map[string]bool{}
	for _, n := range needs {
		got[toStr(n)] = true
	}
	producers := []string{"race-build", "race-shard", "race-lane", "race-universe", "race-privileged"}
	for _, want := range producers {
		if !got[want] {
			t.Errorf("race-verdict must need %q", want)
		}
		if !strings.Contains(stepBodies(verdict), "needs."+want+".result") {
			t.Errorf("race-verdict no longer judges %q's job result", want)
		}
	}
	body := shellCodeOnly(stepBodies(verdict))
	for _, want := range []string{
		"rootshard verdict",
		"-universe-dir race-universe", // the lane's independent block universe
		"-commit \"$GITHUB_SHA\"",     // expectations enumerated from THIS checkout
		"cp race-verdict/merged.cover.out coverage.out",
		"test -s coverage.out",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("race-verdict no longer runs %q", want)
		}
	}
	universe := shellCodeOnly(stepBodies(asMap(jobs["race-universe"])))
	if !strings.Contains(universe, "rootshard universe") {
		t.Error("race-universe no longer produces the lane's expected block set")
	}
	if strategy := asMap(asMap(jobs["race-shard"])["strategy"]); strategy["fail-fast"] != false {
		t.Errorf("race-shard must set fail-fast: false — one red shard must not cancel the evidence of the others (got %v)", strategy["fail-fast"])
	}
	var code strings.Builder
	for _, j := range jobs {
		code.WriteString(shellCodeOnly(stepBodies(asMap(j))))
	}
	if strings.Contains(code.String(), "-trimpath") {
		t.Error("the sharded run must not add -trimpath: pkgSourceDir() and the source-reading tests resolve absolute compiled-in paths")
	}
	// qa-coverage is uploaded by the verdict ONLY (and only after it passed —
	// the upload step carries no always()).
	if got := uploadedArtifacts(t, qaRaceShardsWorkflowPath, "race-verdict"); !slices.Contains(got, qaCoverageArtifact) {
		t.Errorf("race-verdict must publish %q; uploads %v", qaCoverageArtifact, got)
	}
}

func TestQARaceShards_AuditIsOptInAndJudged(t *testing.T) {
	doc := genericWorkflow(t, qaGateWorkflowPath)
	input := asMap(asMap(asMap(asMap(doc["on"])["workflow_dispatch"])["inputs"])[qaAuditInput])
	if input == nil {
		t.Fatalf("qa-gate.yml workflow_dispatch must declare the %q input", qaAuditInput)
	}
	if toStr(input["type"]) != "boolean" || input["default"] != false {
		t.Errorf("%q must be a boolean defaulting to false (got type %v, default %v) — an ordinary run must not pay for the unsharded reference",
			qaAuditInput, input["type"], input["default"])
	}
	if in := asMap(asMap(asMap(doc["on"])["workflow_dispatch"])["inputs"]); len(in) != 1 {
		t.Errorf("workflow_dispatch inputs = %v; only %q is expected (the 5A pilot input is retired)", in, qaAuditInput)
	}

	wf := loadWorkflow(t, qaGateWorkflowPath)
	agg := jobNeeds(qaGateJob(t, wf, qaGateAggregateJob))
	for _, name := range []string{qaAuditJob, qaAuditCompareJob} {
		j := qaGateJob(t, wf, name)
		cond := normaliseExpr(j.If)
		if !strings.Contains(cond, "github.event_name == 'workflow_dispatch'") || !strings.Contains(cond, "inputs."+qaAuditInput) {
			t.Errorf("job %q must be gated on a dispatch with %s=true; got if: %q", name, qaAuditInput, j.If)
		}
		for _, ev := range []string{"push", "pull_request", "workflow_dispatch"} {
			if evalRaceOwnership(t, cond, ev, "refs/heads/main") {
				t.Errorf("job %q would run on %s with the input at its default — the audit must be opt-in", name, ev)
			}
		}
		if !agg[name] {
			t.Errorf("the QA aggregate must need %q — a requested audit that fails must refuse the gate", name)
		}
	}
	cmp := jobNeeds(qaGateJob(t, wf, qaAuditCompareJob))
	if !cmp[qaRaceJob] || !cmp[qaAuditJob] || len(cmp) != 2 {
		t.Errorf("%q must need exactly %q (the sharded evidence) and %q (the reference); got %v", qaAuditCompareJob, qaRaceJob, qaAuditJob, cmp)
	}
	body := shellCodeOnly(stepBodies(asMap(asMap(doc["jobs"])[qaAuditCompareJob])))
	if !strings.Contains(body, "rootshard compare") || !strings.Contains(body, "-coverage-exceptions "+qaCoverageExceptionsPath) {
		t.Errorf("%q must compare against the checked-in coverage exceptions file %s", qaAuditCompareJob, qaCoverageExceptionsPath)
	}
}

// TestQARaceShards_NoCoverageExceptions pins the exceptions file EMPTY. Stage
// 5B pinned every block that differed between the sharded and unsharded runs
// with an isolated fixture (coverage_isolation*_test.go). Adding an exception
// is allowed by the tool — narrow, explicit, current — but it is a reviewed
// decision, so it must also change this test, with the evidence in the diff.
func TestQARaceShards_NoCoverageExceptions(t *testing.T) {
	var ex struct {
		Schema     int               `json:"schema"`
		Exceptions []json.RawMessage `json:"exceptions"`
	}
	if err := json.Unmarshal(mustRead(t, qaCoverageExceptionsPath), &ex); err != nil {
		t.Fatalf("%s: %v", qaCoverageExceptionsPath, err)
	}
	if ex.Schema != 1 {
		t.Errorf("%s schema = %d, want 1", qaCoverageExceptionsPath, ex.Schema)
	}
	if len(ex.Exceptions) != 0 {
		t.Errorf("%s lists %d coverage exception(s); each is a covered path the sharded run gives up — justify it in review and update this test",
			qaCoverageExceptionsPath, len(ex.Exceptions))
	}
}

func stepBodies(job map[string]interface{}) string {
	var b strings.Builder
	steps, _ := job["steps"].([]interface{})
	for _, st := range steps {
		b.WriteString(toStr(asMap(st)["run"]))
		b.WriteByte('\n')
	}
	return b.String()
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

var timeoutFlagRe = regexp.MustCompile(`-timeout[= ](\S+)`)

// TestQARaceShards_MatchesTheUnshardedCommand pins parity with the
// single-process command the audit job runs (qa-logic's until stage 5B): the
// same TEST_SEED and the same per-binary -timeout, read from that job's own
// step so the two cannot drift silently.
func TestQARaceShards_MatchesTheUnshardedCommand(t *testing.T) {
	gate := genericWorkflow(t, qaGateWorkflowPath)
	var refSeed, refTimeout string
	steps, _ := asMap(asMap(gate["jobs"])[qaAuditJob])["steps"].([]interface{})
	for _, st := range steps {
		s := asMap(st)
		if run := toStr(s["run"]); strings.Contains(run, "go test -race") {
			refSeed = toStr(asMap(s["env"])["TEST_SEED"])
			if m := timeoutFlagRe.FindStringSubmatch(shellCodeOnly(run)); m != nil {
				refTimeout = m[1]
			}
		}
	}
	if refSeed == "" || refTimeout == "" {
		t.Fatalf("could not read the unsharded command's TEST_SEED (%q) or -timeout (%q) — the selector is stale", refSeed, refTimeout)
	}
	shards := genericWorkflow(t, qaRaceShardsWorkflowPath)
	if got := toStr(asMap(shards["env"])["TEST_SEED"]); got != refSeed {
		t.Errorf("sharded TEST_SEED %q != the unsharded command's %q", got, refSeed)
	}
	for _, job := range []string{"race-shard", "race-lane", "race-universe"} {
		body := shellCodeOnly(stepBodies(asMap(asMap(shards["jobs"])[job])))
		m := timeoutFlagRe.FindStringSubmatch(body)
		if len(m) < 2 || m[1] != refTimeout {
			t.Errorf("%s must pass the unsharded command's per-binary -timeout %s explicitly (got %v)", job, refTimeout, m)
		}
	}
}

func TestQARaceShards_TimingFileIsUsable(t *testing.T) {
	var tf struct {
		Source  string             `json:"source"`
		Package string             `json:"package"`
		Tests   map[string]float64 `json:"tests"`
	}
	if err := json.Unmarshal(mustRead(t, qaRaceTimingsPath), &tf); err != nil {
		t.Fatalf("%s: %v", qaRaceTimingsPath, err)
	}
	if tf.Package != "github.com/KidCarmi/Culvert" || tf.Source == "" || len(tf.Tests) < 1000 {
		t.Errorf("%s must carry provenance and the root package's measured entries (package %q, source %q, %d entries)",
			qaRaceTimingsPath, tf.Package, tf.Source, len(tf.Tests))
	}
	for name, sec := range tf.Tests {
		if sec < 0 || strings.Contains(name, "/") {
			t.Errorf("%s: %q = %v is not a top-level entry timing", qaRaceTimingsPath, name, sec)
		}
	}
}
