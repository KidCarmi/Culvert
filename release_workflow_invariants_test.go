package main

import (
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// TestWorkflowInvariants pins the load-bearing SECURITY invariants of the dormant
// R2 publisher (.github/workflows/publish-catalog-r2.yml, M0-PR3) by parsing the
// YAML structurally — NOT by fragile whole-file substring scans. The threat model
// for this test is a FUTURE EDIT that silently relaxes an invariant while keeping
// the file syntactically valid; every assertion is written so that an unsafe
// workflow FAILS (never vacuously passes):
//
//   - no `id-token: write` at any permission level — incl. the scalar `write-all`
//     form, which grants id-token implicitly (a literal-key scan would miss it);
//   - an explicit restrictive top-level `permissions` (absent ⇒ inherits a broad
//     default), `contents` never `write` at top level or in any job;
//   - the dormant gate keys on `vars.R2_PUBLISH_ENABLED`, and NO `if:` anywhere
//     references `secrets.` / `secrets[` (unavailable in `if:`; pinned robustly);
//   - stage (create-only) → verify → promote EXIST and are ordered, the verify step
//     proves a non-skip PASS and has no `continue-on-error`, and the promote step
//     has no status-override bypass — so verify genuinely gates promotion.

const r2WorkflowPath = ".github/workflows/publish-catalog-r2.yml"

type wfStep struct {
	Name            string      `yaml:"name"`
	Uses            string      `yaml:"uses"`
	Run             string      `yaml:"run"`
	If              string      `yaml:"if"`
	ContinueOnError interface{} `yaml:"continue-on-error"`
}

type wfJob struct {
	If          string      `yaml:"if"`
	Permissions interface{} `yaml:"permissions"` // string ("read-all"/"write-all") OR map
	Steps       []wfStep    `yaml:"steps"`
}

type wfDoc struct {
	Permissions interface{}      `yaml:"permissions"`
	Jobs        map[string]wfJob `yaml:"jobs"`
}

// permsGrantIDToken reports whether a `permissions:` node grants id-token. The
// scalar `write-all` grants EVERY scope (incl. id-token), so it must count as a
// grant even though no `id-token` key is present — this is the false-green vector
// a literal-key check misses.
func permsGrantIDToken(p interface{}) bool {
	switch v := p.(type) {
	case string:
		return v == "write-all"
	case map[string]interface{}:
		tok, ok := v["id-token"]
		if !ok {
			return false
		}
		return toStr(tok) != "none" && toStr(tok) != ""
	default:
		return false
	}
}

// permsContentsWritable reports whether a `permissions:` node grants contents:write
// (or write-all, which implies it).
func permsContentsWritable(p interface{}) bool {
	switch v := p.(type) {
	case string:
		return v == "write-all"
	case map[string]interface{}:
		return toStr(v["contents"]) == "write"
	default:
		return false
	}
}

func toStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// runScript returns a step's run body with full-line shell comments removed, so a
// `# … put-object … --if-none-match …` comment in an UNRELATED step cannot false-match
// a load-bearing step signature and misorder the stage/verify/promote indices.
func runScript(run string) string {
	var b strings.Builder
	for _, ln := range strings.Split(run, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return b.String()
}

func isTruthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	default:
		return false
	}
}

// runContainsAll reports whether run contains every substring (positive form,
// avoids a De-Morgan'able negated-OR chain).
func runContainsAll(run string, subs ...string) bool {
	for _, s := range subs {
		if !strings.Contains(run, s) {
			return false
		}
	}
	return true
}

func loadR2Workflow(t *testing.T) wfDoc {
	t.Helper()
	raw, err := os.ReadFile(r2WorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", r2WorkflowPath, err)
	}
	var doc wfDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", r2WorkflowPath, err)
	}
	if len(doc.Jobs) == 0 {
		t.Fatalf("%s has no jobs", r2WorkflowPath)
	}
	return doc
}

func TestWorkflowInvariants(t *testing.T) {
	doc := loadR2Workflow(t)
	assertNoElevatedPermissions(t, doc)
	assertNoSecretsInAnyIf(t, doc)
	assertStageVerifyPromote(t, requirePublishJob(t, doc))
}

// assertNoElevatedPermissions: an explicit restrictive top-level `permissions` (an
// absent block inherits a broad default) and no job grants id-token or contents:write.
func assertNoElevatedPermissions(t *testing.T, doc wfDoc) {
	t.Helper()
	if doc.Permissions == nil {
		t.Fatal("top-level permissions must be present and restrictive (absent inherits a broad default)")
	}
	if permsGrantIDToken(doc.Permissions) {
		t.Fatal("top-level permissions grants id-token; the R2 publisher must be verify-only (no id-token)")
	}
	if permsContentsWritable(doc.Permissions) {
		t.Fatal("top-level permissions grants contents:write; must be read-only")
	}
	for name, job := range doc.Jobs {
		if permsGrantIDToken(job.Permissions) {
			t.Fatalf("job %q grants id-token; must be verify-only", name)
		}
		if permsContentsWritable(job.Permissions) {
			t.Fatalf("job %q grants contents:write; must be read-only", name)
		}
	}
}

// assertNoSecretsInAnyIf: no `if:` (job- or step-level) references secrets.* — the
// dormant gate must key on vars (secrets.* is unavailable in if: anyway).
func assertNoSecretsInAnyIf(t *testing.T, doc wfDoc) {
	t.Helper()
	check := func(where, expr string) {
		if strings.Contains(expr, "secrets.") || strings.Contains(expr, "secrets[") {
			t.Fatalf("%s `if:` references secrets (unavailable in if:, and the dormant gate must key on vars): %q", where, expr)
		}
	}
	for name, job := range doc.Jobs {
		check("job "+name, job.If)
		for i := range job.Steps {
			check("job "+name+" step", job.Steps[i].If)
		}
	}
}

func requirePublishJob(t *testing.T, doc wfDoc) wfJob {
	t.Helper()
	job, ok := doc.Jobs["publish"]
	if !ok {
		t.Fatal("expected a `publish` job in the R2 workflow")
	}
	if !strings.Contains(job.If, "vars.R2_PUBLISH_ENABLED") {
		t.Fatalf("publish job gate must key on vars.R2_PUBLISH_ENABLED (dormant switch); got %q", job.If)
	}
	return job
}

// findLoadBearingSteps returns the stage/verify/promote step indices (or -1 each) by
// their run-body signatures. A missing step keeps its index at -1 so the caller's
// existence checks FAIL (no vacuous pass). First match wins.
func findLoadBearingSteps(job wfJob) (stageIdx, verifyIdx, promoteIdx int) {
	stageIdx, verifyIdx, promoteIdx = -1, -1, -1
	for i := range job.Steps {
		run := runScript(job.Steps[i].Run)
		switch {
		case stageIdx == -1 && strings.Contains(run, "put-object") && strings.Contains(run, "--if-none-match"):
			stageIdx = i
		case verifyIdx == -1 && strings.Contains(run, "TestServedVerify_BakedRootGate"):
			verifyIdx = i
		case promoteIdx == -1 && strings.Contains(run, "copy-object"):
			promoteIdx = i
		}
	}
	return stageIdx, verifyIdx, promoteIdx
}

// assertStageVerifyPromote: the three load-bearing steps EXIST and are ordered
// stage → verify → promote, and verify genuinely gates promotion.
func assertStageVerifyPromote(t *testing.T, job wfJob) {
	t.Helper()
	stageIdx, verifyIdx, promoteIdx := findLoadBearingSteps(job)
	if stageIdx == -1 {
		t.Fatal("no create-only staging step (put-object --if-none-match) found — immutable-history guard missing")
	}
	if verifyIdx == -1 {
		t.Fatal("no baked-root verify step (TestServedVerify_BakedRootGate) found — the trust boundary is missing")
	}
	if promoteIdx == -1 {
		t.Fatal("no promote step (copy-object) found")
	}
	if stageIdx >= verifyIdx || verifyIdx >= promoteIdx {
		t.Fatalf("steps must be ordered stage(%d) < verify(%d) < promote(%d)", stageIdx, verifyIdx, promoteIdx)
	}
	assertVerifyGates(t, job.Steps[verifyIdx])
	assertPromoteNotBypassable(t, job.Steps[promoteIdx])
}

// assertVerifyGates: the verify step has no continue-on-error and proves a non-skip
// PASS via an ENFORCING pipeline (`go test -json` + `jq -e`/`--exit-status` on an
// Action==pass record + `exit 1`) — not merely the right words (an `echo "… Action
// pass"` keeps the substrings while defeating the gate, the fail-open we guard).
func assertVerifyGates(t *testing.T, verify wfStep) {
	t.Helper()
	if isTruthy(verify.ContinueOnError) {
		t.Fatal("verify step has continue-on-error — a verify failure must HARD-STOP before promote")
	}
	enforcingJQ := strings.Contains(verify.Run, "jq -e") || strings.Contains(verify.Run, "--exit-status")
	enforcedPass := enforcingJQ && runContainsAll(verify.Run, "-json", "exit 1", "Action", "pass")
	if !enforcedPass {
		t.Fatal("verify step must ENFORCE a non-skip PASS: `go test -json` + `jq -e`/`--exit-status` on Action==pass + `exit 1` (else a skipped test fails OPEN)")
	}
	if !strings.Contains(verify.Run, "CULVERT_RELEASE_SERVED_URL") {
		t.Fatal("verify step must set/require CULVERT_RELEASE_SERVED_URL (else the gate silently skips)")
	}
}

// assertPromoteNotBypassable: promote runs ONLY on the implicit success() gate. Reject
// any status override that would run it after a FAILED verify — always(), !cancelled(),
// cancelled(), failure(), success() || failure() — not just always().
func assertPromoteNotBypassable(t *testing.T, promote wfStep) {
	t.Helper()
	for _, bad := range []string{"always", "cancelled", "failure"} {
		if strings.Contains(promote.If, bad) {
			t.Fatalf("promote step `if:` must not reference %q — it must run only after a successful verify; got %q", bad, promote.If)
		}
	}
}
