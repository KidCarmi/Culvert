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
//     has no `if: always()` bypass — so verify genuinely gates promotion.

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

	// ── permissions: no id-token anywhere; explicit restrictive top level ──────
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

	// ── every `if:` uses vars, never secrets.* (job- AND step-level) ───────────
	assertNoSecretsInIf := func(where, expr string) {
		if strings.Contains(expr, "secrets.") || strings.Contains(expr, "secrets[") {
			t.Fatalf("%s `if:` references secrets (unavailable in if:, and the dormant gate must key on vars): %q", where, expr)
		}
	}
	for name, job := range doc.Jobs {
		assertNoSecretsInIf("job "+name, job.If)
		for i := range job.Steps {
			assertNoSecretsInIf("job "+name+" step", job.Steps[i].If)
		}
	}

	// ── the publish job: dormant vars-gate + stage→verify→promote invariants ───
	job, ok := doc.Jobs["publish"]
	if !ok {
		t.Fatal("expected a `publish` job in the R2 workflow")
	}
	if !strings.Contains(job.If, "vars.R2_PUBLISH_ENABLED") {
		t.Fatalf("publish job gate must key on vars.R2_PUBLISH_ENABLED (dormant switch); got %q", job.If)
	}

	// Locate the load-bearing steps by their run-body signatures. Missing step ⇒
	// index stays -1 ⇒ the existence assertions below FAIL (no vacuous pass).
	stageIdx, verifyIdx, promoteIdx := -1, -1, -1
	for i := range job.Steps {
		run := runScript(job.Steps[i].Run)
		switch {
		case strings.Contains(run, "put-object") && strings.Contains(run, "--if-none-match"):
			if stageIdx == -1 {
				stageIdx = i
			}
		case strings.Contains(run, "TestServedVerify_BakedRootGate"):
			if verifyIdx == -1 {
				verifyIdx = i
			}
		case strings.Contains(run, "copy-object"):
			if promoteIdx == -1 {
				promoteIdx = i
			}
		}
	}
	if stageIdx == -1 {
		t.Fatal("no create-only staging step (put-object --if-none-match) found — immutable-history guard missing")
	}
	if verifyIdx == -1 {
		t.Fatal("no baked-root verify step (TestServedVerify_BakedRootGate) found — the trust boundary is missing")
	}
	if promoteIdx == -1 {
		t.Fatal("no promote step (copy-object) found")
	}

	// Ordering: stage before verify before promote (verify must gate promotion).
	if !(stageIdx < verifyIdx && verifyIdx < promoteIdx) {
		t.Fatalf("steps must be ordered stage(%d) < verify(%d) < promote(%d)", stageIdx, verifyIdx, promoteIdx)
	}

	// Verify step must actually gate: no continue-on-error, must prove a non-skip
	// PASS (go test -json + an "Action":"pass" assertion, not a bare `go test` that
	// exits 0 on a t.Skip when the served URL is unset — the fail-open hazard).
	verify := job.Steps[verifyIdx]
	if isTruthy(verify.ContinueOnError) {
		t.Fatal("verify step has continue-on-error — a verify failure must HARD-STOP before promote")
	}
	// The pass-proof must be an ENFORCING pipeline, not merely the right words: a real
	// `go test -json` piped into a `jq -e`/`--exit-status` check on an Action==pass
	// record AND an `exit 1` on the same step. (An `echo "... Action pass"` would keep
	// the substrings while defeating the gate — the fail-open this test exists to stop.)
	hasEnforcingJQ := strings.Contains(verify.Run, "jq -e") || strings.Contains(verify.Run, "--exit-status")
	if !strings.Contains(verify.Run, "-json") || !hasEnforcingJQ ||
		!strings.Contains(verify.Run, "exit 1") ||
		!strings.Contains(verify.Run, "Action") || !strings.Contains(verify.Run, "pass") {
		t.Fatal("verify step must ENFORCE a non-skip PASS: `go test -json` + `jq -e`/`--exit-status` on Action==pass + `exit 1` (else a skipped test fails OPEN)")
	}
	if !strings.Contains(verify.Run, "CULVERT_RELEASE_SERVED_URL") {
		t.Fatal("verify step must set/require CULVERT_RELEASE_SERVED_URL (else the gate silently skips)")
	}

	// Promote must be reachable ONLY on the implicit success() gate. Reject ANY status
	// override that would run it after a FAILED verify — always(), !cancelled(),
	// cancelled(), failure(), success() || failure() — not just always().
	promoteIf := job.Steps[promoteIdx].If
	for _, bad := range []string{"always", "cancelled", "failure"} {
		if strings.Contains(promoteIf, bad) {
			t.Fatalf("promote step `if:` must not reference %q — it must run only after a successful verify; got %q", bad, promoteIf)
		}
	}
}
