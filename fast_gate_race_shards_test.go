package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Fast PR Gate on the shared sharded engine (CI-REDESIGN stage 5C).
//
// pr-fast-gate.yml's race + coverage execution moved from one
// `go test -race -coverprofile ./...` process to the engine the QA gate runs
// (qa-race-shards.yml). This file pins what the migration must preserve:
//
//  1. ONE ENGINE. test-race calls the reusable workflow with 4 shards and only
//     the caller-specific inputs; no ordinary Fast job runs the unsharded
//     root-module race suite any more (only the dispatch-only audit does).
//  2. THE CONTRACTS. `fast-gate-coverage` (coverage.out, 30-day retention)
//     comes from the verdict; coverage-floors enforces the shared floor script
//     on THIS run's profile; runner hardening is on every job that replaced
//     the hardened race job; the privileged mount-point regression runs as
//     root and must PASS.
//  3. THE AGGREGATE. Same required check name; when the diff classified as
//     code the migrated path must be exactly `success`; a qualification
//     dispatch never approves.
//  4. THE CLASSIFIER. Driven for real below: the shipped script, real git
//     diffs, real outputs — docs-only still skips, code still runs, and the
//     dispatch-only qualification paths cannot be reached from a PR.
//  5. THE AUDIT. Opt-in, and the same reference command and comparison as the
//     QA gate's, so the two qualification paths cannot drift.
// ─────────────────────────────────────────────────────────────────────────────

const (
	fastGateWorkflowPath   = ".github/workflows/pr-fast-gate.yml"
	fastRaceJob            = "test-race"
	fastFloorsJob          = "coverage-floors"
	fastAuditJob           = "race-unsharded-audit"
	fastAuditCompareJob    = "race-unsharded-audit-compare"
	fastAggregateJob       = "fast-gate-approved"
	fastAggregateName      = "✅ Fast PR Gate — APPROVED"
	fastCoverageArtifact   = "fast-gate-coverage"
	fastPrivilegedTest     = "TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting"
	fastPrivilegedTestFile = "restore_mountpoint_test.go"
	hardenRunnerAction     = "step-security/harden-runner@"
)

// jobSteps returns a job's steps; a job that calls a reusable workflow has none.
func jobSteps(j map[string]interface{}) []interface{} {
	steps, _ := j["steps"].([]interface{})
	return steps
}

func fastJobs(t *testing.T) map[string]interface{} {
	t.Helper()
	return asMap(genericWorkflow(t, fastGateWorkflowPath)["jobs"])
}

func TestFastGateRace_CallsTheSharedEngine(t *testing.T) {
	j := asMap(fastJobs(t)[fastRaceJob])
	if got := toStr(j["uses"]); got != "./"+qaRaceShardsWorkflowPath {
		t.Fatalf("%s must call the shared engine ./%s (got uses %q) — the engine is reused, never copied", fastRaceJob, qaRaceShardsWorkflowPath, got)
	}
	if j["steps"] != nil {
		t.Errorf("%s calls a reusable workflow and must carry no steps of its own", fastRaceJob)
	}
	if got := normaliseExpr(toStr(j["if"])); got != "needs.changes.outputs.code == 'true'" {
		t.Errorf("%s must run exactly when the classifier says code (got if: %q)", fastRaceJob, got)
	}
	with := asMap(j["with"])
	want := map[string]string{
		"shards":            qaRaceShardCount,
		"coverage-artifact": fastCoverageArtifact,
		"harden-runner":     "true",
		"privileged-test":   fastPrivilegedTest,
		"fault":             "${{ inputs.fault || 'none' }}",
	}
	for k, v := range want {
		if got := toScalar(with[k]); got != v {
			t.Errorf("%s with.%s = %q, want %q", fastRaceJob, k, got, v)
		}
	}
	if len(with) != len(want) {
		t.Errorf("%s passes %v; only %v are caller-specific", fastRaceJob, with, want)
	}
}

// TestFastGateRace_NoOrdinaryUnshardedRun pins that the single-process
// root-module race run is gone from every ordinary Fast execution: the only
// job that still runs it is the audit, which a pull request cannot reach.
func TestFastGateRace_NoOrdinaryUnshardedRun(t *testing.T) {
	for name, jv := range fastJobs(t) {
		j := asMap(jv)
		if wd := toStr(asMap(asMap(j["defaults"])["run"])["working-directory"]); wd != "" {
			continue // a nested module (cmd/culvert-maint) is not the root suite
		}
		steps, _ := j["steps"].([]interface{})
		for _, st := range steps {
			run := shellCodeOnly(toStr(asMap(st)["run"]))
			if !strings.Contains(run, "go test") || !strings.Contains(run, "-race") || !strings.Contains(run, "./...") {
				continue
			}
			if name != fastAuditJob {
				t.Errorf("job %q runs the unsharded root-module race suite — the sharded engine owns it (stage 5C)", name)
				continue
			}
			cond := normaliseExpr(toStr(j["if"]))
			for _, ev := range []string{"pull_request", "workflow_dispatch"} {
				if evalRaceOwnership(t, cond, ev, "refs/heads/main") {
					t.Errorf("%s would run on %s with unsharded_audit at its default — the audit must be opt-in", name, ev)
				}
			}
		}
	}
}

func TestFastGateRace_CoverageFloorsOnThisRunsMergedProfile(t *testing.T) {
	jobs := fastJobs(t)
	j := asMap(jobs[fastFloorsJob])
	needs := map[string]bool{}
	for _, n := range j["needs"].([]interface{}) {
		needs[toStr(n)] = true
	}
	if !needs[fastRaceJob] || !needs["changes"] {
		t.Errorf("%s must need changes and %s (got %v)", fastFloorsJob, fastRaceJob, j["needs"])
	}
	var downloaded bool
	for _, st := range jobSteps(j) {
		s := asMap(st)
		if !strings.Contains(toStr(s["uses"]), "actions/download-artifact@") {
			continue
		}
		with := asMap(s["with"])
		if toStr(with["name"]) == fastCoverageArtifact {
			downloaded = true
		}
		// No run-id / github-token: the download is scoped to THIS run, so a
		// profile from main or another run can never be enforced against.
		if with["run-id"] != nil || with["github-token"] != nil {
			t.Errorf("%s must read the profile from this run only (found run-id/github-token)", fastFloorsJob)
		}
	}
	if !downloaded {
		t.Errorf("%s must download %q", fastFloorsJob, fastCoverageArtifact)
	}
	if body := shellCodeOnly(stepBodies(j)); !strings.Contains(body, coverageFloorSh+" coverage.out") {
		t.Errorf("%s must enforce %s on coverage.out (both floors, the shared script)", fastFloorsJob, coverageFloorSh)
	}
	// The artifact itself: the engine's verdict is its only producer, with the
	// pre-5C path and retention; no Fast job uploads it any more.
	if got := uploadedArtifacts(t, fastGateWorkflowPath); slices.Contains(got, fastCoverageArtifact) {
		t.Errorf("pr-fast-gate.yml uploads %q itself; the sharded verdict is its only producer", fastCoverageArtifact)
	}
	verdict := asMap(asMap(genericWorkflow(t, qaRaceShardsWorkflowPath)["jobs"])["race-verdict"])
	var found bool
	for _, st := range jobSteps(verdict) {
		s := asMap(st)
		with := asMap(s["with"])
		if !strings.Contains(toStr(s["uses"]), "actions/upload-artifact@") || normaliseExpr(toStr(with["name"])) != "${{ inputs.coverage-artifact }}" {
			continue
		}
		found = true
		if toScalar(with["path"]) != qaCoverageFile || toScalar(with["retention-days"]) != "30" || toScalar(with["if-no-files-found"]) != "error" {
			t.Errorf("the coverage upload must keep path %s, 30-day retention and if-no-files-found: error (got %v)", qaCoverageFile, with)
		}
		if s["if"] != nil {
			t.Errorf("the coverage upload must run only when every earlier verdict step passed (no if:, got %v)", s["if"])
		}
	}
	if !found {
		t.Error("race-verdict no longer uploads the caller-named coverage artifact")
	}
}

// TestFastGateRace_RunnerHardening pins the egress-audit step on every job
// that replaced the pre-5C hardened race job: all engine jobs (gated on the
// input the Fast gate sets) and the Fast-side floors and audit jobs.
func TestFastGateRace_RunnerHardening(t *testing.T) {
	check := func(where, job string, j map[string]interface{}, gated bool) {
		steps, _ := j["steps"].([]interface{})
		if len(steps) == 0 {
			t.Errorf("%s / %s has no steps", where, job)
			return
		}
		first := asMap(steps[0])
		if !strings.HasPrefix(toStr(first["uses"]), hardenRunnerAction) || toStr(asMap(first["with"])["egress-policy"]) != "audit" {
			t.Errorf("%s / %s: first step must be %s with egress-policy: audit (got %v)", where, job, hardenRunnerAction, first)
		}
		cond := normaliseExpr(toStr(first["if"]))
		if gated && cond != "inputs.harden-runner" {
			t.Errorf("%s / %s: the harden step must be gated on inputs.harden-runner (got if: %q)", where, job, cond)
		}
		if !gated && cond != "" {
			t.Errorf("%s / %s: the harden step must be unconditional (got if: %q)", where, job, cond)
		}
	}
	for name, j := range asMap(genericWorkflow(t, qaRaceShardsWorkflowPath)["jobs"]) {
		check(qaRaceShardsWorkflowPath, name, asMap(j), true)
	}
	jobs := fastJobs(t)
	for _, name := range []string{fastFloorsJob, fastAuditJob, fastAuditCompareJob} {
		check(fastGateWorkflowPath, name, asMap(jobs[name]), false)
	}
}

// TestFastGateRace_PrivilegedRegressionRunsAsRoot pins the mount-point
// regression's execution path: the engine runs the named test as root against
// the prebuilt binary, a SKIP or a missing PASS fails, and the verdict refuses
// a privileged job that was requested but did not succeed.
func TestFastGateRace_PrivilegedRegressionRunsAsRoot(t *testing.T) {
	src := string(mustRead(t, fastPrivilegedTestFile))
	if !strings.Contains(src, "func "+fastPrivilegedTest+"(t *testing.T)") {
		t.Fatalf("%s no longer declares %s — the Fast gate would run a test that does not exist", fastPrivilegedTestFile, fastPrivilegedTest)
	}
	jobs := asMap(genericWorkflow(t, qaRaceShardsWorkflowPath)["jobs"])
	priv := asMap(jobs["race-privileged"])
	if toStr(priv["needs"]) != "race-build" || normaliseExpr(toStr(priv["if"])) != "inputs.privileged-test != ''" {
		t.Errorf("race-privileged must need race-build and run exactly when a privileged test is named (needs %v, if %v)", priv["needs"], priv["if"])
	}
	body := shellCodeOnly(stepBodies(priv))
	for _, want := range []string{
		`sudo env "TEST_SEED=$TEST_SEED" "$b/root.test"`, // the SAME prebuilt binary, as root
		`-test.run "^${PRIV_TEST}\$"`,                    // exactly the named test
		`--- SKIP: ${PRIV_TEST} `,                        // a skip fails
		`--- PASS: ${PRIV_TEST} `,                        // only an explicit PASS passes
		`[ "$built" = "$GITHUB_SHA" ]`,                   // the binary is this run's
	} {
		if !strings.Contains(body, want) {
			t.Errorf("race-privileged no longer contains %q", want)
		}
	}
	verdict := asMap(jobs["race-verdict"])
	// Both directions: requested ⇒ exactly success; not requested (QA) ⇒
	// exactly skipped. Anything else — failed, cancelled, or a requested job
	// that never ran — refuses the verdict.
	vb := shellCodeOnly(stepBodies(verdict))
	for _, want := range []string{
		`want=skipped; [ -z "$PRIV_TEST" ] || want=success`,
		`[ "${{ needs.race-privileged.result }}" = "$want" ] ||`,
	} {
		if !strings.Contains(vb, want) {
			t.Errorf("race-verdict must judge race-privileged exactly (missing %q)", want)
		}
	}
}

func TestFastGateRace_AggregateRefusesAnIncompleteRacePath(t *testing.T) {
	agg := asMap(fastJobs(t)[fastAggregateJob])
	if toStr(agg["name"]) != fastAggregateName {
		t.Fatalf("the required check must stay named %q (got %q)", fastAggregateName, agg["name"])
	}
	if normaliseExpr(toStr(agg["if"])) != "always()" {
		t.Errorf("%s must run if: always()", fastAggregateJob)
	}
	needs := map[string]bool{}
	for _, n := range agg["needs"].([]interface{}) {
		needs[toStr(n)] = true
	}
	for _, want := range []string{"changes", "hygiene", "lint", fastRaceJob, fastFloorsJob, "benchgate", "security-fast",
		"gitleaks", "agent", "mcp-predicates", "frontend", fastAuditJob, fastAuditCompareJob} {
		if !needs[want] {
			t.Errorf("the aggregate must need %q", want)
		}
	}
	var verdict, guard map[string]interface{}
	for _, st := range jobSteps(agg) {
		s := asMap(st)
		if strings.HasSuffix(toStr(s["uses"]), "needs-verdict") {
			verdict = s
		}
		if strings.Contains(toStr(s["if"]), "inputs.fault") {
			guard = s
		}
	}
	if verdict == nil {
		t.Fatal("the aggregate must evaluate its needs through ./.github/actions/needs-verdict")
	}
	req := normaliseExpr(toStr(asMap(verdict["with"])["require-success"]))
	for _, want := range []string{
		"format('changes{0}{1}'",
		"needs.changes.outputs.code == 'true' && '," + fastRaceJob + "," + fastFloorsJob + "'",
		"inputs.unsharded_audit && '," + fastAuditJob + "," + fastAuditCompareJob + "'",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("require-success must contain %q — a skipped migrated race path must not read as green on a code diff (got %q)", want, req)
		}
	}
	if guard == nil {
		t.Fatal("the aggregate must refuse any qualification dispatch (a step gated on inputs.fault)")
	}
	if normaliseExpr(toStr(guard["if"])) != "github.event_name == 'workflow_dispatch' && inputs.fault != 'none'" ||
		!strings.Contains(shellCodeOnly(toStr(guard["run"])), "exit 1") {
		t.Errorf("the qualification guard must fail every dispatch with a fault set (got if %q)", guard["if"])
	}
}

// TestFastGateRace_FaultInputIsHandledAndDispatchOnly pins every fault option
// to a handler, and the input to workflow_dispatch (a pull request has no
// inputs, so `inputs.fault || 'none'` is always none there).
func TestFastGateRace_FaultInputIsHandledAndDispatchOnly(t *testing.T) {
	doc := genericWorkflow(t, fastGateWorkflowPath)
	on := asMap(doc["on"])
	if _, ok := asMap(on["pull_request"])["inputs"]; ok {
		t.Fatal("pull_request cannot carry inputs")
	}
	in := asMap(asMap(asMap(on["workflow_dispatch"])["inputs"])["fault"])
	if toStr(in["type"]) != "choice" || toStr(in["default"]) != "none" {
		t.Fatalf("fault must be a choice defaulting to none (got %v)", in)
	}
	fast := string(mustRead(t, fastGateWorkflowPath))
	engine := string(mustRead(t, qaRaceShardsWorkflowPath))
	handled := map[string]string{
		"classifier-fails":        fast,
		"docs-only":               fast,
		"coverage-floor-fails":    fast,
		"shard-evidence-missing":  engine,
		"shard-profile-truncated": engine,
		"producer-fails":          engine,
	}
	opts, _ := in["options"].([]interface{})
	if len(opts) != len(handled)+1 {
		t.Errorf("fault options %v: each must be handled below (plus none)", opts)
	}
	for _, o := range opts {
		name := toStr(o)
		if name == "none" {
			continue
		}
		where, ok := handled[name]
		if !ok {
			t.Errorf("fault %q has no known handler", name)
			continue
		}
		if !strings.Contains(where, "== '"+name+"'") && !strings.Contains(where, " "+name+")") {
			t.Errorf("fault %q is offered but nothing handles it", name)
		}
	}
}

// TestFastGateRace_AuditMatchesTheQAAudit pins the Fast audit's reference
// command and comparison to the QA gate's (and so to the engine's seed and
// -timeout, which TestQARaceShards_MatchesTheUnshardedCommand pins there).
func TestFastGateRace_AuditMatchesTheQAAudit(t *testing.T) {
	qa := asMap(genericWorkflow(t, qaGateWorkflowPath)["jobs"])
	fast := fastJobs(t)
	norm := func(s, prefix string) string {
		return normaliseExpr(strings.ReplaceAll(shellCodeOnly(s), prefix, "AUDIT"))
	}
	refRun := func(j map[string]interface{}, prefix string) (cmd, seed string) {
		for _, st := range jobSteps(j) {
			s := asMap(st)
			if run := toStr(s["run"]); strings.Contains(run, "go test -race") {
				return norm(run, prefix), toStr(asMap(s["env"])["TEST_SEED"])
			}
		}
		return "", ""
	}
	qc, qs := refRun(asMap(qa[qaAuditJob]), "qa-audit-reference")
	fc, fs := refRun(asMap(fast[fastAuditJob]), "fast-audit-reference")
	if qc == "" || fc == "" || qc != fc || qs != fs {
		t.Errorf("the Fast audit's reference command must equal the QA audit's:\n qa:   %q seed %q\n fast: %q seed %q", qc, qs, fc, fs)
	}
	compare := func(j map[string]interface{}) string {
		body := normaliseExpr(shellCodeOnly(stepBodies(j)))
		i := strings.Index(body, "go run ./cmd/rootshard compare")
		if i < 0 {
			return ""
		}
		return body[i : i+strings.Index(body[i:], "| tee")]
	}
	qcmp, fcmp := compare(asMap(qa[qaAuditCompareJob])), compare(asMap(fast[fastAuditCompareJob]))
	if qcmp == "" || qcmp != fcmp {
		t.Errorf("the Fast comparison must equal the QA comparison:\n qa:   %q\n fast: %q", qcmp, fcmp)
	}
	for _, n := range uploadedArtifacts(t, fastGateWorkflowPath, fastAuditJob, fastAuditCompareJob) {
		if !strings.HasPrefix(n, "fast-audit-") {
			t.Errorf("Fast audit artifact %q lacks the fast-audit- prefix", n)
		}
	}
}

// ─── The classifier, driven for real ────────────────────────────────────────

var ghEventExpr = regexp.MustCompile(`\$\{\{\s*github\.event_name\s*\}\}`)

// classifyScript returns the shipped `changes` classifier step.
func classifyScript(t *testing.T) string {
	t.Helper()
	for _, st := range jobSteps(asMap(fastJobs(t)["changes"])) {
		if s := asMap(st); toStr(s["id"]) == "classify" {
			return toStr(s["run"])
		}
	}
	t.Fatal("changes job has no step with id: classify")
	return ""
}

// runClassifier runs the classifier as GitHub Actions would for event, in a
// scratch repository whose HEAD^1..HEAD diff is the given change set.
func runClassifier(t *testing.T, event, fault string, change func(dir string)) (map[string]string, error) {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		// #nosec G204 -- test-only: the fixed git binary with arguments built in this test.
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-c", "user.email=ci@example.invalid", "-c", "user.name=ci",
			"-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write("README.md", "base\n")
	write("docs/design/mcp/DATA-FLOW-DIAGRAMS.md", "base\n")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	change(dir)
	git("add", "-A")
	git("commit", "-q", "--allow-empty", "-m", "change")

	out := filepath.Join(dir, "gh-output")
	script := ghEventExpr.ReplaceAllString(classifyScript(t), event)
	// #nosec G204 -- test-only: the classifier script shipped in this repo's own workflow, run in a scratch repository.
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+out, "FAULT="+fault)
	if b, err := cmd.CombinedOutput(); err != nil {
		return nil, &classifierErr{err: err, out: string(b)}
	}
	res := map[string]string{}
	raw, _ := os.ReadFile(out)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			res[k] = v
		}
	}
	return res, nil
}

type classifierErr struct {
	err error
	out string
}

func (e *classifierErr) Error() string { return e.err.Error() + "\n" + e.out }

func TestFastGateRace_ClassifierBehaviour(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	touch := func(files ...string) func(string) {
		return func(dir string) {
			for _, f := range files {
				p := filepath.Join(dir, f)
				_ = os.MkdirAll(filepath.Dir(p), 0o750)
				if err := os.WriteFile(p, []byte("changed\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	moveOut := func(dir string) {
		if err := os.MkdirAll(filepath.Join(dir, "archive"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(dir, "docs", "design", "mcp", "DATA-FLOW-DIAGRAMS.md"), filepath.Join(dir, "archive", "DATA-FLOW-DIAGRAMS.md")); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name, event, fault string
		change             func(string)
		want               map[string]string
	}{
		{"PR docs-only skips code", "pull_request", "none", touch("README.md", "docs/operator/x.md", "roadmap/y.md"),
			map[string]string{"code": "false", "agent": "false", "mcp_docs": "false", "frontend": "false"}},
		{"PR code change runs code", "pull_request", "none", touch("proxy.go"),
			map[string]string{"code": "true", "agent": "false", "mcp_docs": "false", "frontend": "false"}},
		{"PR load-bearing doc runs code", "pull_request", "none", touch("docs/saml-idp-configuration-reference.md"),
			map[string]string{"code": "true"}},
		{"PR agent change", "pull_request", "none", touch("cmd/culvert-maint/main.go"),
			map[string]string{"code": "true", "agent": "true"}},
		{"PR workflow change runs code, MCP and frontend gates", "pull_request", "none", touch(".github/workflows/pr-fast-gate.yml"),
			map[string]string{"code": "true", "mcp_docs": "true", "frontend": "true"}},
		{"PR move out of the MCP surface is still classified", "pull_request", "none", moveOut,
			map[string]string{"mcp_docs": "true"}},
		// A pull request never sees a fault (no inputs); even if the env
		// carried one, the PR branch of the script must ignore it.
		{"PR ignores a stray fault value", "pull_request", "docs-only", touch("proxy.go"),
			map[string]string{"code": "true"}},
		{"dispatch runs everything", "workflow_dispatch", "none", touch("README.md"),
			map[string]string{"code": "true", "agent": "true", "mcp_docs": "true", "frontend": "true"}},
		{"dispatch docs-only simulation", "workflow_dispatch", "docs-only", touch("proxy.go"),
			map[string]string{"code": "false", "agent": "false", "mcp_docs": "false", "frontend": "false"}},
		{"dispatch engine fault still runs everything", "workflow_dispatch", "shard-evidence-missing", touch("README.md"),
			map[string]string{"code": "true"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := runClassifier(t, c.event, c.fault, c.change)
			if err != nil {
				t.Fatalf("classifier failed: %v", err)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q (all outputs %v)", k, got[k], v, got)
				}
			}
		})
	}
	t.Run("dispatch classifier-fails leaves the diff unclassified", func(t *testing.T) {
		got, err := runClassifier(t, "workflow_dispatch", "classifier-fails", touch("proxy.go"))
		if err == nil {
			t.Fatalf("classifier-fails must exit non-zero; got outputs %v", got)
		}
	})
}
