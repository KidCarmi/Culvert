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
// QA coverage-provenance wall (CI-REDESIGN stage 2A).
//
// QA used to execute the whole `./...` suite TWICE per main push: once in
// qa-logic under `-race`, and once again in qa-coverage under `-coverprofile`,
// with the same TEST_SEED and the same package scope. The second run existed
// only to instrument what the first had already executed.
//
// Stage 2A adds `-coverprofile` to the race run and turns qa-coverage into a
// VERIFIER: it downloads the profile qa-logic published and enforces the
// existing floors on it. Nothing about the floor table, its arithmetic or its
// blast-radius scope moves — only where the profile comes from.
//
// That makes the coverage verdict depend on an artifact crossing a job
// boundary, which introduces failure modes a single job did not have: a
// producer that goes green without publishing a usable profile, and a transfer
// that arrives empty or truncated. Both must refuse, because a floor enforced
// against nothing is indistinguishable from a floor that passed. This file
// pins the provenance structurally AND drives the real shipped shell for both
// the guards and the floor script.
//
// It deliberately does NOT re-implement coverage-floor.sh's arithmetic: that
// script is shared with the Fast PR Gate and is exercised here as the binary
// CI actually runs.
// ─────────────────────────────────────────────────────────────────────────────

const (
	qaCoverageArtifact = "qa-coverage"
	qaCoverageFile     = "coverage.out"
	coverageFloorSh    = ".github/scripts/coverage-floor.sh"
	qaCoverageJob      = "qa-coverage"
	// qaCoverageProducer is the ONE job that publishes the profile: the
	// sharded race verdict (stage 5B; qa-logic's race run in stage 2A).
	qaCoverageProducer     = "race-verdict"
	qaCoverageProducerPath = ".github/workflows/qa-race-shards.yml"
	// qaReferenceJob runs the unsharded command qa-logic ran until stage 5B.
	qaReferenceJob = "qa-unsharded-audit"
)

// toScalar renders any YAML scalar as text. The shared toStr helper returns ""
// for non-strings, and `retention-days: 30` decodes as an int — comparing it
// through toStr silently compares "" to "30" and passes whatever is there.
func toScalar(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// qaJobSteps returns a job's steps as generic maps so a step's `with:` block
// can be inspected without adding QA-only fields to the wfStepWith struct the
// release-workflow tests share.
func qaJobSteps(t *testing.T, job string) []map[string]interface{} {
	t.Helper()
	return qaJobStepsIn(t, qaGateWorkflowPath, job)
}

func qaJobStepsIn(t *testing.T, path, job string) []map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var generic struct {
		Jobs map[string]struct {
			Steps []map[string]interface{} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	steps := generic.Jobs[job].Steps
	if len(steps) == 0 {
		t.Fatalf("job %q has no steps — the selector is stale", job)
	}
	return steps
}

// shellRunOnly concatenates a job's `run:` bodies with `#` comments stripped, so
// a comment ABOUT a command is never mistaken for the command (the
// shellCodeOnly discipline from release_publication_gating_test.go).
func shellRunOnly(steps []map[string]interface{}) string {
	var b strings.Builder
	for _, st := range steps {
		b.WriteString(shellCodeOnly(toStr(st["run"])))
		b.WriteByte('\n')
	}
	return b.String()
}

// ─── 1. One execution, and the profile comes out of it ───────────────────────

// TestQAGateCoverage_ProfileIsProducedByTheRaceRun pins the whole point of
// stage 2A — the race run also produces the profile — across stage 5B's move:
//
//   - the published profile is the sharded race verdict's merged profile
//     (qa-race-shards.yml race-verdict copies it to coverage.out), and
//   - the unsharded command that DEFINES what the sharded run must match is
//     still the exact pre-5B qa-logic command, now run by the audit job; its
//     flags are pinned here so the reference cannot drift either. The
//     sharded run's own flags are pinned against it by
//     TestQARaceShards_MatchesTheUnshardedCommand and, for the compiled
//     binary and the lane, by cmd/rootshard's TestRunConfig_* tests.
func TestQAGateCoverage_ProfileIsProducedByTheRaceRun(t *testing.T) {
	producer := shellRunOnly(qaJobStepsIn(t, qaCoverageProducerPath, qaCoverageProducer))
	if !strings.Contains(producer, "cp race-verdict/merged.cover.out "+qaCoverageFile) {
		t.Errorf("%s no longer publishes the verdict's merged profile as %s", qaCoverageProducer, qaCoverageFile)
	}
	run := shellRunOnly(qaJobSteps(t, qaReferenceJob))

	var cmd string
	for _, line := range strings.Split(run, "\n") {
		if strings.Contains(line, "go test ") && strings.Contains(line, "-race") {
			cmd = strings.TrimSpace(line)
		}
	}
	if cmd == "" {
		t.Fatal("the audit reference no longer runs a `go test -race` command — the selector is stale and this test proves nothing")
	}

	// Every flag the race run carried before stage 2A must survive: the seed is
	// an env var (checked separately), the rest are on the command line.
	for _, want := range []string{"-race", "-count=1", "-timeout=40m", "-v", "./...", "-coverprofile=qa-audit-reference/" + qaCoverageFile} {
		if !strings.Contains(cmd, want) {
			t.Errorf("the unsharded reference command lost %q — it must stay the exact pre-5B race run.\ngot: %s", want, cmd)
		}
	}

	// `go test` hands arguments AFTER the package list to the test binary, so a
	// trailing -coverprofile is silently passed to the tests and no profile is
	// written — a green run that publishes nothing.
	if iCov, iPkg := strings.Index(cmd, "-coverprofile="), strings.Index(cmd, "./..."); iCov > iPkg {
		t.Errorf("-coverprofile must precede the package list, or `go test` passes it to the test binary instead of the tool.\ngot: %s", cmd)
	}

	if !strings.Contains(run, "pipefail") {
		t.Error("the audit reference lost `set -o pipefail` — the run is piped into tee, whose exit status is always 0, so failing tests would go green")
	}
	if !strings.Contains(run, "tee ") {
		t.Error("the audit reference no longer tees its output to a log — the comparison parses that log")
	}
}

// TestQAGateCoverage_VerifierRunsNoTests is the half that proves the DUPLICATE
// execution is gone rather than merely joined by a third one.
func TestQAGateCoverage_VerifierRunsNoTests(t *testing.T) {
	run := shellRunOnly(qaJobSteps(t, qaCoverageJob))

	if strings.Contains(run, "go test") {
		t.Errorf("qa-coverage runs `go test` again — stage 2A exists to delete that second full-suite execution; "+
			"it must enforce floors on qa-logic's profile instead.\nrun bodies:\n%s", run)
	}
	if !strings.Contains(run, coverageFloorSh) {
		t.Errorf("qa-coverage no longer calls %s — the floors would stop being enforced anywhere on main", coverageFloorSh)
	}
	// TEST_SEED only ever existed here to keep a SECOND suite's percentages
	// stable against the first. With no suite left to run it is meaningless;
	// this is a control that the job really was gutted, not just edited.
	for _, st := range qaJobSteps(t, qaCoverageJob) {
		if env, ok := st["env"].(map[string]interface{}); ok {
			if _, seeded := env["TEST_SEED"]; seeded {
				t.Error("qa-coverage still sets TEST_SEED — nothing there runs tests any more, so a seed can only mislead")
			}
		}
	}
}

// ─── 2. Artifact provenance: one producer, current run only ──────────────────

// TestQAGateCoverage_ArtifactHasExactlyOneProducer pins the contract the
// stage-2A brief states directly: the immutable artifact name must not be
// uploaded from two jobs, and its name, path and retention must survive the
// move from consumer to producer.
func TestQAGateCoverage_ArtifactHasExactlyOneProducer(t *testing.T) {
	// Every workflow, not only the two QA files: an artifact name is scoped to
	// the RUN, and a reusable workflow's uploads land in its caller's run.
	producers := []string{}
	for _, wf := range workflowFiles(t) {
		raw, err := os.ReadFile(wf)
		if err != nil {
			t.Fatalf("read %s: %v", wf, err)
		}
		var generic struct {
			Jobs map[string]struct {
				Steps []map[string]interface{} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &generic); err != nil {
			t.Fatalf("parse %s: %v", wf, err)
		}
		producers = append(producers, coverageUploaders(t, wf, generic.Jobs)...)
	}

	if len(producers) != 1 {
		t.Fatalf("the %q artifact must have exactly ONE producer; got %v. Uploading an immutable artifact name from "+
			"two jobs is a race whose winner decides what the floors are enforced against.", qaCoverageArtifact, producers)
	}
	if want := qaCoverageProducerPath + " / " + qaCoverageProducer; producers[0] != want {
		t.Errorf("the %q artifact must be produced by %s (the sharded race verdict); got %q", qaCoverageArtifact, want, producers[0])
	}
}

// coverageUploaders returns "<workflow> / <job>" for every step uploading the
// coverage artifact, checking the upload contract on each.
func coverageUploaders(t *testing.T, wf string, jobs map[string]struct {
	Steps []map[string]interface{} `yaml:"steps"`
}) []string {
	t.Helper()
	var producers []string
	for job := range jobs {
		for _, st := range jobs[job].Steps {
			if !strings.Contains(toStr(st["uses"]), "actions/upload-artifact") {
				continue
			}
			with, _ := st["with"].(map[string]interface{})
			if resolveEngineName(t, wf, toStr(with["name"])) != qaCoverageArtifact {
				continue
			}
			producers = append(producers, wf+" / "+job)

			if got := toScalar(with["path"]); got != qaCoverageFile {
				t.Errorf("the %q artifact must stay at path %q (got %q)", qaCoverageArtifact, qaCoverageFile, got)
			}
			if got := toScalar(with["retention-days"]); got != "30" {
				t.Errorf("the %q artifact must keep 30-day retention (got %q)", qaCoverageArtifact, got)
			}
			// A missing profile must FAIL the producer. The default
			// (`warn`) publishes no artifact and leaves the job green, which
			// then fails downstream as a confusing download error.
			if got := toScalar(with["if-no-files-found"]); got != "error" {
				t.Errorf("the %q upload must set if-no-files-found: error so a vanished profile fails the producer (got %q)",
					qaCoverageArtifact, got)
			}
		}
	}

	return producers
}

// TestQAGateCoverage_VerifierConsumesOnlyThisRun pins that the floors are
// enforced against THIS run's profile. actions/download-artifact reaches into
// another workflow run only when handed `run-id` (with a token); without them
// it is scoped to the current run, so their ABSENCE is the control.
func TestQAGateCoverage_VerifierConsumesOnlyThisRun(t *testing.T) {
	downloads := 0
	for _, st := range qaJobSteps(t, qaCoverageJob) {
		if !strings.Contains(toStr(st["uses"]), "actions/download-artifact") {
			continue
		}
		downloads++
		with, _ := st["with"].(map[string]interface{})
		if got := toScalar(with["name"]); got != qaCoverageArtifact {
			t.Errorf("qa-coverage downloads %q, want %q", got, qaCoverageArtifact)
		}
		for _, escape := range []string{"run-id", "github-token", "repository"} {
			if v, present := with[escape]; present && toScalar(v) != "" {
				t.Errorf("qa-coverage passes %q=%q to download-artifact — that lets it read ANOTHER run's profile. "+
					"The floors must only ever be enforced against the profile this run produced.", escape, toScalar(v))
			}
		}
	}
	if downloads != 1 {
		t.Fatalf("qa-coverage must download the coverage artifact exactly once; got %d", downloads)
	}
}

// ─── 3. The floor contract itself did not move ───────────────────────────────

// TestQAGateCoverage_FloorTableUnchanged pins that stage 2A did not buy a
// passing instrumented result by lowering a threshold. The brief forbids
// filtering files, reducing thresholds or suppressing failures; this asserts
// the shipped values, so any of those is a named diff.
func TestQAGateCoverage_FloorTableUnchanged(t *testing.T) {
	raw, err := os.ReadFile(coverageFloorSh)
	if err != nil {
		t.Fatalf("read %s: %v", coverageFloorSh, err)
	}
	body := string(raw)

	if !strings.Contains(body, "GLOBAL_FLOOR=55") {
		t.Error("the global coverage floor is no longer 55 — stage 2A must not move a threshold to make an instrumented result pass")
	}
	for file, floor := range map[string]string{
		"totp.go":                "85",
		"security.go":            "70",
		"session.go":             "75",
		"lockout.go":             "80",
		"policy.go":              "60",
		"autoexclude.go":         "85",
		"autoexclude_resolve.go": "80",
		"controlplane_delta.go":  "80",
		"controlplane_client.go": "55",
	} {
		if !regexpFloorRow(body, file, floor) {
			t.Errorf("per-file floor for %s is no longer %s%% — stage 2A changes where the profile comes from, never what it must clear", file, floor)
		}
	}
}

// regexpFloorRow reports whether the floors table still carries "<file> <floor>"
// on one line, tolerating the column alignment the table uses.
func regexpFloorRow(body, file, floor string) bool {
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == file && f[1] == floor {
			return true
		}
	}
	return false
}

// ─── 4. The REAL guard shell, against real failure shapes ────────────────────

// qaGuardScript extracts the shipped body of a named guard step so the test
// drives what CI runs rather than a copy that could agree with the test and
// disagree with CI.
func qaGuardScript(t *testing.T, path, job, stepNameSubstr string) string {
	t.Helper()
	for _, st := range qaJobStepsIn(t, path, job) {
		if strings.Contains(toStr(st["name"]), stepNameSubstr) {
			if body := toStr(st["run"]); strings.TrimSpace(body) != "" {
				return body
			}
		}
	}
	t.Fatalf("job %q has no step named like %q with a run body — the selector is stale", job, stepNameSubstr)
	return ""
}

func runShell(t *testing.T, script, dir string) (string, bool) {
	t.Helper()
	sh := filepath.Join(t.TempDir(), "guard.sh")
	if err := os.WriteFile(sh, []byte(script), 0o700); err != nil { //nolint:gosec // test harness script in a temp dir
		t.Fatalf("write harness: %v", err)
	}
	// CommandContext, not Command: the harness must die with the test (noctx).
	// #nosec G204 -- program is the literal "bash"; the only variable is a path
	// under this test's own t.TempDir(), supplied by no caller.
	cmd := exec.CommandContext(t.Context(), "bash", sh)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// TestQAGateCoverage_GuardsRefuseUnusableEvidence drives BOTH shipped guards —
// the producer's and the verifier's — against the shapes that would otherwise
// let a floor be "enforced" against nothing.
func TestQAGateCoverage_GuardsRefuseUnusableEvidence(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	// Each guard reads the profile from where ITS job finds it: the producer
	// from the verdict's merged output, the verifier from the download.
	type guard struct{ script, seed string }
	guards := map[string]guard{
		"producer": {qaGuardScript(t, qaCoverageProducerPath, qaCoverageProducer, "coverage profile is usable"), "race-verdict/merged.cover.out"},
		"verifier": {qaGuardScript(t, qaGateWorkflowPath, qaCoverageJob, "downloaded profile is usable"), qaCoverageFile},
	}

	cases := []struct {
		name    string
		content *string // nil = do not create the file at all
		wantOK  bool
	}{
		{"absent", nil, false},
		{"empty", strptr(""), false},
		{"mode line only", strptr("mode: atomic\n"), false},
		{"not a profile", strptr("PASS\nok  github.com/KidCarmi/Culvert 12.3s\n"), false},
		{"usable", strptr("mode: atomic\ngithub.com/KidCarmi/Culvert/totp.go:1.1,2.2 1 1\n"), true},
	}

	for name, g := range guards {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				if tc.content != nil {
					seed := filepath.Join(dir, g.seed)
					if err := os.MkdirAll(filepath.Dir(seed), 0o750); err != nil {
						t.Fatalf("seed dir: %v", err)
					}
					if err := os.WriteFile(seed, []byte(*tc.content), 0o600); err != nil {
						t.Fatalf("seed profile: %v", err)
					}
				}
				out, ok := runShell(t, g.script, dir)
				if ok != tc.wantOK {
					t.Fatalf("%s guard on a %s profile: ok=%v want %v\noutput:\n%s", name, tc.name, ok, tc.wantOK, out)
				}
				if !tc.wantOK && !strings.Contains(out, "::error::") {
					t.Errorf("%s guard refused a %s profile without an ::error:: annotation — the operator cannot see why\noutput:\n%s", name, tc.name, out)
				}
			})
		}
	}
}

func strptr(s string) *string { return &s }

// ─── 5. The REAL floor script, against real profiles ─────────────────────────

// realCoverageProfile builds a genuinely valid coverage profile by compiling
// and running a throwaway one-file module, rather than hand-writing profile
// lines. `go tool cover -func` OPENS each file a profile names and maps its
// byte ranges onto real statements, so a synthesised line pointing at a path
// that does not exist — or at offsets that do not — fails to parse and the
// script errors for a reason that has nothing to do with the floors. Returning
// the module directory too lets the caller run the script with a cwd where
// those import paths resolve.
//
// covered=false rewrites every block's execution count to 0, which is exactly
// what an uncovered run produces and keeps the profile structurally valid.
func realCoverageProfile(t *testing.T, covered bool) (dir, profile string) {
	t.Helper()
	dir = t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("go.mod", "module culvert.test/covsample\n\ngo 1.21\n")
	write("sample.go", "package covsample\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n")
	write("sample_test.go", "package covsample\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n")

	out := filepath.Join(dir, "gen.out")
	// #nosec G204 -- fixed argv; the only variable is a path under t.TempDir().
	cmd := exec.CommandContext(t.Context(), "go", "test", "-covermode=atomic", "-coverprofile="+out, "./...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build a sample coverage profile in this environment: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read generated profile: %v", err)
	}

	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("generated profile has no statement blocks:\n%s", raw)
	}
	if !covered {
		for i := 1; i < len(lines); i++ {
			if idx := strings.LastIndex(lines[i], " "); idx > 0 {
				lines[i] = lines[i][:idx] + " 0"
			}
		}
	}
	return dir, strings.Join(lines, "\n") + "\n"
}

// TestQAGateCoverage_FloorScriptRefusesUnusableAndBreachedProfiles runs the
// SHIPPED coverage-floor.sh — the same file the Fast PR Gate runs — so a pass
// or a refusal here means what CI would mean by it.
func TestQAGateCoverage_FloorScriptRefusesUnusableAndBreachedProfiles(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	script := filepath.Join(pkgSourceDir(), coverageFloorSh)
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("%s is missing — the coverage contract this test reports is gone", coverageFloorSh)
	}

	runFloor := func(t *testing.T, dir, profile string) (string, bool) {
		t.Helper()
		if dir == "" {
			dir = t.TempDir()
		}
		path := filepath.Join(dir, qaCoverageFile)
		if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
			t.Fatalf("write profile: %v", err)
		}
		// #nosec G204 -- fixed in-repo script; the only variable is a t.TempDir() path.
		cmd := exec.CommandContext(t.Context(), "bash", script, path)
		cmd.Dir = dir // `go tool cover -func` resolves import paths relative to here
		cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off")
		out, err := cmd.CombinedOutput()
		return string(out), err == nil
	}

	// A structurally valid profile that covers nothing: the global floor is
	// breached and every per-file floor is missing, and the script must say so
	// per file rather than exiting quietly.
	t.Run("zero coverage breaches the floors", func(t *testing.T) {
		dir, profile := realCoverageProfile(t, false)
		out, ok := runFloor(t, dir, profile)
		if ok {
			t.Fatalf("coverage-floor.sh approved a zero-coverage profile\noutput:\n%s", out)
		}
		if !strings.Contains(out, "below the 55% floor") {
			t.Errorf("the global floor breach was not reported\noutput:\n%s", out)
		}
		if !strings.Contains(out, "::error file=") {
			t.Errorf("no per-file floor breach was annotated — the blast-radius table is not being enforced\noutput:\n%s", out)
		}
	})

	// An unusable profile must never be read as "nothing below the floor".
	// This is the failure the stage-2A guards exist for, re-checked at the last
	// layer: even with both guards removed, the script still refuses.
	for _, tc := range []struct{ name, profile string }{
		{"empty", ""},
		{"mode line only", "mode: atomic\n"},
	} {
		t.Run("unusable/"+tc.name, func(t *testing.T) {
			out, ok := runFloor(t, "", tc.profile)
			if ok {
				t.Fatalf("coverage-floor.sh approved a %s profile — a floor enforced against no evidence is not a floor\noutput:\n%s", tc.name, out)
			}
		})
	}

	// CONTROL. The cheapest way to pass every assertion above is a script that
	// always fails. A fully covered profile must CLEAR the global floor,
	// proving that check is live and independent of the per-file table (which
	// still breaches, since none of the nine files appears in this profile).
	t.Run("control: the global check can pass", func(t *testing.T) {
		dir, profile := realCoverageProfile(t, true)
		out, ok := runFloor(t, dir, profile)
		if ok {
			t.Fatal("expected the per-file table to still breach on a profile containing none of the nine files")
		}
		if strings.Contains(out, "below the 55% floor") {
			t.Errorf("a fully covered profile was reported as below the GLOBAL floor — the global check is not computing what it claims\noutput:\n%s", out)
		}
		if !strings.Contains(out, "total ... 100.0%") {
			t.Errorf("expected the global line to report 100.0%%\noutput:\n%s", out)
		}
	})
}

// ─── 6. Effect on the FINAL verdict ──────────────────────────────────────────

// TestQAGateCoverage_VerdictRefusesMissingCoverageEvidence closes the loop the
// brief asks for: a coverage failure, and the skip that a failed producer
// causes, must each end in a refused QA verdict. It drives the REAL
// needs-verdict action, so this is the aggregate CI actually evaluates.
//
// The second case is the one worth having: stage 2A makes a failed qa-logic
// SKIP qa-coverage, and needs-verdict reads a skip as a pass. The gate is
// still correct only because qa-logic's own `failure` is in the same needs set.
// If qa-logic were ever dropped from the aggregate, a coverage-less run would
// report APPROVED — so that combination is pinned here explicitly.
func TestQAGateCoverage_VerdictRefusesMissingCoverageEvidence(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq unavailable — the shared action's verdict is jq-based")
	}
	script := needsVerdictScript(t)

	for _, tc := range []struct {
		name    string
		mutate  func(map[string]string)
		wantRef string // a job name the refusal must mention
	}{
		{
			name:    "floor enforcement failed",
			mutate:  func(r map[string]string) { r[qaCoverageJob] = "failure" },
			wantRef: qaCoverageJob,
		},
		{
			name: "producer failed, so coverage never ran",
			mutate: func(r map[string]string) {
				r[qaRaceJob] = "failure"
				r[qaCoverageJob] = "skipped" // what GitHub does to a needs-blocked job
			},
			wantRef: qaRaceJob,
		},
		{
			name: "producer cancelled, so coverage never ran",
			mutate: func(r map[string]string) {
				r[qaRaceJob] = "cancelled"
				r[qaCoverageJob] = "skipped"
			},
			wantRef: qaRaceJob,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := allQAResults("success")
			tc.mutate(results)
			out, ok := runNeedsVerdict(t, script, needsJSON(results))
			if ok {
				t.Fatalf("the QA verdict APPROVED a run with no usable coverage evidence (%s)\noutput:\n%s", tc.name, out)
			}
			if !strings.Contains(out, tc.wantRef) {
				t.Errorf("the refusal does not name %q, so an operator cannot tell what went wrong\noutput:\n%s", tc.wantRef, out)
			}
		})
	}

	// CONTROL: the PR shape still passes. Stage 2A must not wedge the required
	// check on pull requests, where every substantive job skips.
	t.Run("control: PR all-skipped still approves", func(t *testing.T) {
		out, ok := runNeedsVerdict(t, script, needsJSON(allQAResults("skipped")))
		if !ok {
			t.Fatalf("the PR shape must still approve or branch protection wedges at \"Expected\"\noutput:\n%s", out)
		}
	})

	// CONTROL: a fully green run still approves, so none of the above passes
	// merely because the verdict started refusing everything.
	t.Run("control: all success approves", func(t *testing.T) {
		out, ok := runNeedsVerdict(t, script, needsJSON(allQAResults("success")))
		if !ok {
			t.Fatalf("an all-success run must approve\noutput:\n%s", out)
		}
	})
}
