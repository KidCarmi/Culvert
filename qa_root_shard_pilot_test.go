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
// Root-suite sharding pilot wall (CI-REDESIGN stage 5A).
//
// The pilot is EVIDENCE for a decision, not a gate. This file pins the three
// properties that keep it that way, and the parity that makes its evidence
// comparable with the unsharded reference:
//
//  1. OPT-IN ONLY. It runs on a manual dispatch with root_shard_pilot=true and
//     on nothing else; the input defaults to false; the reusable workflow has
//     no trigger of its own.
//  2. NOT A GATE. The QA aggregate does not wait for it, and its artifacts all
//     carry a `qa-root-shard-pilot-` prefix no existing consumer or release
//     evidence row can match.
//  3. FAIL-CLOSED VERDICT. The verdict runs even when a shard fails or is
//     cancelled, judges every job's result, and enforces the UNCHANGED
//     coverage-floor.sh.
//  4. PARITY with qa-logic: the same TEST_SEED and per-binary -timeout.
//
// The tool's own behaviour (partition, selection, merge, verdict) is tested in
// cmd/rootshard, which the ordinary `go test ./...` runs.
// ─────────────────────────────────────────────────────────────────────────────

const (
	qaPilotWorkflowPath = ".github/workflows/qa-root-shard-pilot.yml"
	qaPilotCallJob      = "qa-root-shard-pilot"
	qaPilotCompareJob   = "qa-root-shard-pilot-compare"
	qaPilotInput        = "root_shard_pilot"
	qaPilotArtifactPfx  = "qa-root-shard-pilot-"
	qaPilotTimingsPath  = ".github/qa-root-shard-timings.json"
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

func TestQARootShardPilot_OptInOnly(t *testing.T) {
	doc := genericWorkflow(t, qaGateWorkflowPath)
	input := asMap(asMap(asMap(asMap(doc["on"])["workflow_dispatch"])["inputs"])[qaPilotInput])
	if input == nil {
		t.Fatalf("qa-gate.yml workflow_dispatch must declare the %q input", qaPilotInput)
	}
	if toStr(input["type"]) != "boolean" || input["default"] != false {
		t.Errorf("%q must be a boolean defaulting to false (got type %v, default %v) — an ordinary dispatch must run exactly the graph it always did",
			qaPilotInput, input["type"], input["default"])
	}

	wf := loadWorkflow(t, qaGateWorkflowPath)
	for _, name := range []string{qaPilotCallJob, qaPilotCompareJob} {
		j := qaGateJob(t, wf, name)
		cond := normaliseExpr(j.If)
		if !strings.Contains(cond, "github.event_name == 'workflow_dispatch'") || !strings.Contains(cond, "inputs."+qaPilotInput) {
			t.Errorf("job %q must be gated on a dispatch with %s=true; got if: %q", name, qaPilotInput, j.If)
		}
		for _, ev := range []string{"push", "pull_request", "workflow_dispatch"} {
			if evalRaceOwnership(t, cond, ev, "refs/heads/main") {
				t.Errorf("job %q would run on %s with the input at its default — the pilot must be opt-in only", name, ev)
			}
		}
	}

	agg := jobNeeds(qaGateJob(t, wf, qaGateAggregateJob))
	for _, name := range []string{qaPilotCallJob, qaPilotCompareJob} {
		if agg[name] {
			t.Errorf("the QA aggregate needs %q — pilot evidence must never approve or block the gate", name)
		}
	}
	call := asMap(asMap(doc["jobs"])[qaPilotCallJob])
	if toStr(call["uses"]) != "./"+qaPilotWorkflowPath {
		t.Errorf("job %q must call the local reusable workflow %s (got uses: %v)", qaPilotCallJob, qaPilotWorkflowPath, call["uses"])
	}
	cmp := jobNeeds(qaGateJob(t, wf, qaPilotCompareJob))
	if !cmp["qa-logic"] || !cmp[qaPilotCallJob] || len(cmp) != 2 {
		t.Errorf("%q must need exactly qa-logic (the unsharded reference) and %q; got %v", qaPilotCompareJob, qaPilotCallJob, cmp)
	}
}

func TestQARootShardPilot_ReusableWorkflowHasNoTriggerOfItsOwn(t *testing.T) {
	doc := genericWorkflow(t, qaPilotWorkflowPath)
	on := asMap(doc["on"])
	keys := make([]string, 0, len(on))
	for k := range on {
		keys = append(keys, k)
	}
	if _, ok := on["workflow_call"]; !ok || len(on) != 1 {
		t.Fatalf("%s must be triggered ONLY by workflow_call (got %v) — a push, PR, tag or schedule trigger would run the pilot outside the opt-in", qaPilotWorkflowPath, keys)
	}
	if p := doc["permissions"]; toStr(asMap(p)["contents"]) != "read" || len(asMap(p)) != 1 {
		t.Errorf("%s must stay read-only (permissions: contents: read); got %v", qaPilotWorkflowPath, p)
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
				out = append(out, toStr(asMap(s["with"])["name"]))
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestQARootShardPilot_ArtifactsAreDistinctAndNeverEvidence(t *testing.T) {
	names := append(uploadedArtifacts(t, qaPilotWorkflowPath), uploadedArtifacts(t, qaGateWorkflowPath, qaPilotCompareJob)...)
	if len(names) < 5 {
		t.Fatalf("expected the build, shard, lane, verdict and compare uploads; found %v — the selector is stale", names)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, qaPilotArtifactPfx) {
			t.Errorf("pilot artifact %q lacks the %q prefix — it could collide with, or be consumed as, a real artifact", n, qaPilotArtifactPfx)
		}
	}
	// No job outside the pilot may consume pilot artifacts.
	for _, wf := range workflowFiles(t) {
		if wf == qaPilotWorkflowPath {
			continue
		}
		doc := genericWorkflow(t, wf)
		for name, j := range asMap(doc["jobs"]) {
			if wf == qaGateWorkflowPath && name == qaPilotCompareJob {
				continue
			}
			steps, _ := asMap(j)["steps"].([]interface{})
			for _, st := range steps {
				s := asMap(st)
				w := asMap(s["with"])
				if strings.Contains(toStr(s["uses"]), "download-artifact@") &&
					(strings.Contains(toStr(w["name"]), "root-shard-pilot") || strings.Contains(toStr(w["pattern"]), "root-shard-pilot")) {
					t.Errorf("%s job %q downloads a pilot artifact — pilot output must not feed anything but its own comparison", wf, name)
				}
			}
		}
	}
	ev, err := os.ReadFile(".github/release-evidence.txt")
	if err != nil {
		t.Fatalf("read release evidence manifest: %v", err)
	}
	if strings.Contains(string(ev), "root-shard") {
		t.Error(".github/release-evidence.txt references the pilot — pilot success can never replace release evidence")
	}
}

func TestQARootShardPilot_VerdictFailsClosed(t *testing.T) {
	doc := genericWorkflow(t, qaPilotWorkflowPath)
	jobs := asMap(doc["jobs"])
	verdict := asMap(jobs["pilot-verdict"])
	if strings.TrimSpace(toStr(verdict["if"])) != "always()" {
		t.Errorf("pilot-verdict must run `if: always()` so a failed or cancelled shard produces a verdict that names it; got %v", verdict["if"])
	}
	needs, _ := verdict["needs"].([]interface{})
	got := map[string]bool{}
	for _, n := range needs {
		got[toStr(n)] = true
	}
	for _, want := range []string{"pilot-build", "pilot-shard", "pilot-lane"} {
		if !got[want] {
			t.Errorf("pilot-verdict must need %q", want)
		}
	}
	body := stepBodies(verdict)
	for _, want := range []string{
		"rootshard verdict",
		".github/scripts/coverage-floor.sh pilot-verdict/merged.cover.out",
		"needs.pilot-shard.result", "needs.pilot-lane.result", "needs.pilot-build.result",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("pilot-verdict no longer runs/judges %q", want)
		}
	}
	strategy := asMap(asMap(jobs["pilot-shard"])["strategy"])
	if strategy["fail-fast"] != false {
		t.Errorf("pilot-shard must set fail-fast: false — one red shard must not cancel the evidence of the others (got %v)", strategy["fail-fast"])
	}
	var code strings.Builder
	for _, j := range jobs {
		code.WriteString(shellCodeOnly(stepBodies(asMap(j))))
	}
	if strings.Contains(code.String(), "-trimpath") {
		t.Error("the pilot must not add -trimpath: pkgSourceDir() and the source-reading tests resolve absolute compiled-in paths")
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

// TestQARootShardPilot_MatchesTheReference pins what makes pilot and reference
// comparable: the same TEST_SEED and the same per-binary -timeout as qa-logic,
// derived from qa-logic's own step so the two cannot drift silently.
func TestQARootShardPilot_MatchesTheReference(t *testing.T) {
	gate := genericWorkflow(t, qaGateWorkflowPath)
	var refSeed, refTimeout string
	steps, _ := asMap(asMap(gate["jobs"])["qa-logic"])["steps"].([]interface{})
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
		t.Fatalf("could not read qa-logic's TEST_SEED (%q) or -timeout (%q) — the selector is stale", refSeed, refTimeout)
	}
	pilot := genericWorkflow(t, qaPilotWorkflowPath)
	if got := toStr(asMap(pilot["env"])["TEST_SEED"]); got != refSeed {
		t.Errorf("pilot TEST_SEED %q != qa-logic's %q", got, refSeed)
	}
	for _, job := range []string{"pilot-shard", "pilot-lane"} {
		body := shellCodeOnly(stepBodies(asMap(asMap(pilot["jobs"])[job])))
		m := timeoutFlagRe.FindStringSubmatch(body)
		if len(m) < 2 || m[1] != refTimeout {
			t.Errorf("%s must pass qa-logic's per-binary -timeout %s explicitly (got %v)", job, refTimeout, m)
		}
	}
}

func TestQARootShardPilot_TimingFileIsUsable(t *testing.T) {
	var tf struct {
		Source  string             `json:"source"`
		Package string             `json:"package"`
		Tests   map[string]float64 `json:"tests"`
	}
	if err := json.Unmarshal(mustRead(t, qaPilotTimingsPath), &tf); err != nil {
		t.Fatalf("%s: %v", qaPilotTimingsPath, err)
	}
	if tf.Package != "github.com/KidCarmi/Culvert" || tf.Source == "" || len(tf.Tests) < 1000 {
		t.Errorf("%s must carry provenance and the root package's measured entries (package %q, source %q, %d entries)",
			qaPilotTimingsPath, tf.Package, tf.Source, len(tf.Tests))
	}
	for name, sec := range tf.Tests {
		if sec < 0 || strings.Contains(name, "/") {
			t.Errorf("%s: %q = %v is not a top-level entry timing", qaPilotTimingsPath, name, sec)
		}
	}
}
