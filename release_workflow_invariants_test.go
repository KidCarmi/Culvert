package main

import (
	"os"
	"regexp"
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
	With            wfStepWith  `yaml:"with"`
}

type wfStepWith struct {
	AllowedEndpoints string `yaml:"allowed-endpoints"`
	EgressPolicy     string `yaml:"egress-policy"`
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
	job := requirePublishJob(t, doc)
	assertStageVerifyPromote(t, job)
	assertEgressAllowListWellFormed(t, job)
}

// assertEgressAllowListWellFormed pins the M0-activation outage class: inside a YAML
// block scalar, a quoted allow-list entry like "*.r2.cloudflarestorage.com:443" keeps
// its quotes as LITERAL characters, so harden-runner matches nothing and blocks the
// endpoint (the first live publish failed exactly this way). Every token must be bare
// host:port — no quote characters — and the endpoints the publisher's steps actually
// contact must be present.
func assertEgressAllowListWellFormed(t *testing.T, job wfJob) {
	t.Helper()
	var allowed string
	for i := range job.Steps {
		if strings.Contains(job.Steps[i].Uses, "harden-runner") {
			allowed = job.Steps[i].With.AllowedEndpoints
			if job.Steps[i].With.EgressPolicy != "block" {
				t.Fatalf("harden-runner egress-policy must be block; got %q", job.Steps[i].With.EgressPolicy)
			}
			break
		}
	}
	if strings.TrimSpace(allowed) == "" {
		t.Fatal("no harden-runner allowed-endpoints found in the publish job")
	}
	for _, tok := range strings.Fields(allowed) {
		if strings.ContainsAny(tok, `"'`) {
			t.Fatalf("allow-list token %q contains a quote character — inside a block scalar the quotes are LITERAL and harden-runner will block the endpoint", tok)
		}
		if !strings.Contains(tok, ":") {
			t.Fatalf("allow-list token %q is missing a :port", tok)
		}
	}
	for _, must := range []string{
		"*.r2.cloudflarestorage.com:443", // stage/promote (aws s3api)
		"api.cloudflare.com:443",         // cache purge
		"api.github.com:443",             // gh release download / tag resolve
	} {
		if !strings.Contains(allowed, must) {
			t.Fatalf("allow-list is missing required endpoint %q", must)
		}
	}
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

// ─── M1-1: secret-name contract + credential-free dual-publish verify ─────────

const dualVerifyWorkflowPath = ".github/workflows/verify-dual-publish.yml"

// wfExprRE extracts `${{ … }}` expression blocks (multi-line: folded `if: >-`
// gates span lines); wfRefRE finds every secrets./vars. reference INSIDE them.
// Scanning only real expressions — never raw file text — means a COMMENT naming
// `vars.R2_PUBLISH_ENABLED` cannot satisfy the contract (the vacuity the M1-1
// impl review flagged: the publisher's header comments already name the vars, so
// a raw-text scan would stay green after the real reference was deleted).
var (
	wfExprRE = regexp.MustCompile(`(?s)\$\{\{.*?\}\}`)
	wfRefRE  = regexp.MustCompile(`(secrets|vars)\.([A-Za-z0-9_]+)`)
)

// wfRefSets extracts the exact sets of `secrets.*` / `vars.*` names referenced in
// a workflow file's `${{ … }}` expressions (env:, if:, with: alike).
func wfRefSets(t *testing.T, path string) (secretSet, varSet map[string]bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	secretSet, varSet = map[string]bool{}, map[string]bool{}
	for _, expr := range wfExprRE.FindAllString(string(raw), -1) {
		for _, m := range wfRefRE.FindAllStringSubmatch(expr, -1) {
			if m[1] == "secrets" {
				secretSet[m[2]] = true
			} else {
				varSet[m[2]] = true
			}
		}
	}
	return secretSet, varSet
}

func assertSetEquals(t *testing.T, what string, got map[string]bool, want []string) {
	t.Helper()
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s: missing required reference %q (contract drift — update the workflow AND the runbook together)", what, w)
		}
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for g := range got {
		if !wantSet[g] {
			t.Errorf("%s: unexpected reference %q (contract drift — a rename/addition must update the documented contract)", what, g)
		}
	}
}

// TestPublisherSecretContract pins the R2 publisher's exact secret/var reference
// sets — the M0-activation "secret-name drift" regression guard (an operator
// configured R2_ACCOUNT_ID-style names while the workflow read R2_S3_*; the run
// failed closed but the mismatch was only caught by manual preflight). Drift in
// EITHER direction now fails CI, keeping workflow + runbook in lock-step.
func TestPublisherSecretContract(t *testing.T) {
	secretSet, varSet := wfRefSets(t, r2WorkflowPath)
	assertSetEquals(t, "publish-catalog-r2.yml secrets", secretSet, []string{
		"R2_S3_ENDPOINT", "R2_S3_ACCESS_KEY_ID", "R2_S3_SECRET_ACCESS_KEY",
		"R2_BUCKET", "CF_ZONE_ID", "CF_CACHE_PURGE_TOKEN",
	})
	assertSetEquals(t, "publish-catalog-r2.yml vars", varSet, []string{
		"R2_PUBLISH_ENABLED", "R2_PUBLIC_BASE",
	})
}

// TestDualVerifyWorkflowInvariants pins the M1-1 verify workflow's security
// contract: a VERIFY workflow must not be able to publish. Zero `secrets.*`
// references (the ambient github.token is not a secrets ref), no id-token at any
// permission level, contents at most read, EXACT-name asset selection (OPS-F2:
// a culvert-release-catalog-* glob pick is order-dependent once resign assets
// exist), and both served-verify steps carry the enforcing pass-proof.
func TestDualVerifyWorkflowInvariants(t *testing.T) {
	secretSet, _ := wfRefSets(t, dualVerifyWorkflowPath)
	if len(secretSet) != 0 {
		t.Fatalf("verify workflow must reference NO secrets; found %v", secretSet)
	}
	// The zero-secrets contract must also catch NON-dot access forms —
	// secrets['X'], secrets[format(...)], toJSON(secrets) — which the name-set
	// scanner cannot enumerate (Codex review): for this workflow ANY mention of
	// the secrets context inside an expression is a violation.
	rawExpr, err := os.ReadFile(dualVerifyWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", dualVerifyWorkflowPath, err)
	}
	for _, expr := range wfExprRE.FindAllString(string(rawExpr), -1) {
		if regexp.MustCompile(`\bsecrets\b`).MatchString(expr) {
			t.Fatalf("verify workflow expression mentions the secrets context (any access form is a violation): %q", expr)
		}
	}
	raw, err := os.ReadFile(dualVerifyWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", dualVerifyWorkflowPath, err)
	}
	var doc wfDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", dualVerifyWorkflowPath, err)
	}
	assertVerifyWorkflowCredentialFree(t, doc)
	assertExactAssetSelection(t, doc)
	assertServedVerifyPassProofs(t, doc, 2)
}

// assertVerifyWorkflowCredentialFree: contents:read only, no id-token anywhere.
func assertVerifyWorkflowCredentialFree(t *testing.T, doc wfDoc) {
	t.Helper()
	if doc.Permissions == nil {
		t.Fatal("verify workflow needs an explicit restrictive top-level permissions block")
	}
	if permsGrantIDToken(doc.Permissions) || permsContentsWritable(doc.Permissions) {
		t.Fatal("verify workflow must be contents:read only with NO id-token")
	}
	for name, job := range doc.Jobs {
		if permsGrantIDToken(job.Permissions) || permsContentsWritable(job.Permissions) {
			t.Fatalf("verify workflow job %q must be contents:read only with NO id-token", name)
		}
	}
}

// assertExactAssetSelection: every `--pattern` argument in run: bodies is
// wildcard-free, and the download uses an EXACT name — either the tag-derived
// literal, or (M1-4 amendment, declared in the design §10 plan) a `$ASSET`
// resolved from the release's ASSET LIST by the anchored resign-name regex
// with the exact original name as the fallback. A filesystem glob can never
// reappear (OPS-F2).
func assertExactAssetSelection(t *testing.T, doc wfDoc) {
	t.Helper()
	patternRE := regexp.MustCompile(`--pattern\s+("[^"]*"|'[^']*'|\S+)`)
	exactSeen := false
	for _, job := range doc.Jobs {
		for i := range job.Steps {
			run := runScript(job.Steps[i].Run)
			for _, m := range patternRE.FindAllStringSubmatch(run, -1) {
				arg := strings.Trim(m[1], `"'`)
				if strings.ContainsAny(arg, "*?[") {
					t.Fatalf("verify workflow must download assets by EXACT name, never a glob (OPS-F2); got --pattern %q", arg)
				}
				switch arg {
				case "culvert-release-catalog-${TAG}.tar.gz":
					exactSeen = true
				case "$ASSET":
					// The resolved form is exact ONLY if the same step derives
					// $ASSET from the asset list via the anchored resign regex
					// AND falls back to the exact original name.
					if runContainsAll(run,
						`-r[0-9]{8}\.tar\.gz$`,
						`ASSET="culvert-release-catalog-${TAG}.tar.gz"`) {
						exactSeen = true
					} else {
						t.Fatalf("--pattern \"$ASSET\" without the anchored resign-name resolution + exact fallback in the same step (OPS-F2)")
					}
				}
			}
		}
	}
	if !exactSeen {
		t.Fatal("verify workflow must select the release bundle by exact name (tag-derived literal or list-resolved $ASSET with exact fallback)")
	}
}

// assertServedVerifyPassProofs: exactly n baked-root served-verify steps, each
// carrying the enforcing pass-proof (M0 posture: -json + jq -e + exit 1).
func assertServedVerifyPassProofs(t *testing.T, doc wfDoc, n int) {
	t.Helper()
	passProof := 0
	for _, job := range doc.Jobs {
		for i := range job.Steps {
			run := job.Steps[i].Run
			if !strings.Contains(run, "TestServedVerify_BakedRootGate") {
				continue
			}
			enforcing := (strings.Contains(run, "jq -e") || strings.Contains(run, "--exit-status")) &&
				runContainsAll(run, "-json", "exit 1", "Action", "pass")
			if !enforcing {
				t.Fatalf("served-verify step lacks the enforcing pass-proof: %q", job.Steps[i].Name)
			}
			passProof++
		}
	}
	if passProof != n {
		t.Fatalf("expected exactly %d baked-root served-verify steps; found %d", n, passProof)
	}
}

// ─── M1-4: re-sign invariants (SEC-F1/F2a/F2b, OPS-F1/F2/F4) ──────────────────
//
// Every §10 row for the re-sign slice that names an "invariant" is pinned here,
// mutation-proven: each assertion locates its step by run-body SIGNATURE with a
// -1 sentinel, so deleting or reordering a guard fails the test rather than
// passing vacuously.

const (
	ciWorkflowPath      = ".github/workflows/ci.yml"
	resignSchedulerPath = ".github/workflows/resign-catalog.yml"
	pagesWorkflowPath   = ".github/workflows/publish-catalog-pages.yml"
)

func loadWorkflow(t *testing.T, path string) wfDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc wfDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Jobs) == 0 {
		t.Fatalf("%s has no jobs", path)
	}
	return doc
}

// TestResignCIInvariants pins ci.yml's re-sign surface.
func TestResignCIInvariants(t *testing.T) {
	doc := loadWorkflow(t, ciWorkflowPath)
	assertResignDispatchGuards(t, doc)

	// The dedicated resign job: dispatch+tag+resign-gated, NO docker dependency.
	resign, ok := doc.Jobs["catalog-resign"]
	if !ok {
		t.Fatal("ci.yml must carry the catalog-resign job")
	}
	if !runContainsAll(resign.If, "workflow_dispatch", "refs/tags/v", "inputs.resign") {
		t.Fatalf("catalog-resign must require a resign tag dispatch; got if: %q", resign.If)
	}
	assertResignStepOrder(t, resign)
	assertNoGlobPatterns(t, "catalog-resign", resign)
}

// assertResignDispatchGuards pins BOTH halves of OPS-F1: the loud fail-fast
// guard job AND docker's structural tag-dispatch skip (which skips the whole
// needs-chain, so a dispatched tag run can never overwrite release assets).
func assertResignDispatchGuards(t *testing.T, doc wfDoc) {
	t.Helper()
	guard, ok := doc.Jobs["resign-dispatch-guard"]
	if !ok {
		t.Fatal("OPS-F1: ci.yml must carry the resign-dispatch-guard job (bare tag dispatches must fail loudly)")
	}
	if !runContainsAll(guard.If, "workflow_dispatch", "refs/tags/") {
		t.Fatalf("guard job must be scoped to tag-ref dispatches; got if: %q", guard.If)
	}
	guardEnforces := false
	for i := range guard.Steps {
		if runContainsAll(runScript(guard.Steps[i].Run), `"$RESIGN" != "true"`, "exit 1") {
			guardEnforces = true
		}
	}
	if !guardEnforces {
		t.Fatal("OPS-F1: the guard step must exit 1 when resign != true")
	}
	docker, ok := doc.Jobs["docker"]
	if !ok {
		t.Fatal("ci.yml docker job missing")
	}
	if !runContainsAll(docker.If, "workflow_dispatch", "refs/tags/", "!(") {
		t.Fatalf("docker must exclude tag-ref dispatches (needs-chain skip); got if: %q", docker.If)
	}
}

// assertResignStepOrder pins the SEC-F1 + SEC-F2a + OPS-F2 step ordering inside
// catalog-resign, located by run-body signature (-1 sentinel ⇒ missing step
// FAILS, never vacuously passes). THE load-bearing order: the latest-tag assert
// and the verifying gate both run BEFORE cosign signs anything; the
// attach+prune step comes last.
func assertResignStepOrder(t *testing.T, resign wfJob) {
	t.Helper()
	latest, download, gate, sign, keyless, prune := -1, -1, -1, -1, -1, -1
	for i := range resign.Steps {
		run := runScript(resign.Steps[i].Run)
		switch {
		case latest == -1 && runContainsAll(run, "sort -V", "tail -n1", `"$REF_NAME" = "$LATEST"`):
			latest = i
		case download == -1 && strings.Contains(run, `culvert-release-catalog-${REF_NAME}.tar.gz`):
			download = i
		case gate == -1 && strings.Contains(run, "TestReleaseResignGate"):
			gate = i
		case sign == -1 && strings.Contains(run, "cosign sign-blob"):
			sign = i
		case keyless == -1 && strings.Contains(run, "TestReleaseCatalogKeylessVerify"):
			keyless = i
		case prune == -1 && strings.Contains(run, "delete-asset"):
			prune = i
		}
	}
	if latest == -1 {
		t.Fatal("SEC-F2a: the latest-tag assert step is missing from catalog-resign (old-tag re-sign = unbounded freshness extension)")
	}
	if download == -1 {
		t.Fatal("OPS-F2: the exact-name original-bundle download step is missing")
	}
	if gate == -1 {
		t.Fatal("SEC-F1: the TestReleaseResignGate step (verify-before-read) is missing")
	}
	if sign == -1 || keyless == -1 {
		t.Fatal("catalog-resign must keyless-sign and then end-to-end verify the resigned index")
	}
	if prune == -1 {
		t.Fatal("OPS-F2: the superseded-resign prune step is missing (multi-asset globs would mis-pick)")
	}
	ordered := latest < download && download < gate && gate < sign && sign < keyless && keyless < prune
	if !ordered {
		t.Fatalf("catalog-resign step order violated: latest(%d) < download(%d) < gate(%d) < sign(%d) < keyless(%d) < prune(%d) required (verify must precede sign — SEC-F1)",
			latest, download, gate, sign, keyless, prune)
	}
}

// assertNoGlobPatterns: no glob --pattern anywhere in the job (OPS-F2).
func assertNoGlobPatterns(t *testing.T, name string, job wfJob) {
	t.Helper()
	patternRE := regexp.MustCompile(`--pattern\s+("[^"]*"|'[^']*'|\S+)`)
	for i := range job.Steps {
		for _, m := range patternRE.FindAllStringSubmatch(runScript(job.Steps[i].Run), -1) {
			if arg := strings.Trim(m[1], `"'`); strings.ContainsAny(arg, "*?[") {
				t.Fatalf("%s must download by exact name, never a glob; got --pattern %q", name, arg)
			}
		}
	}
}

// TestResignR2PublisherInvariants pins the SEC-F2b monotonic live binding and
// the M1-4 exact-name extension on the R2 publisher.
func TestResignR2PublisherInvariants(t *testing.T) {
	doc := loadR2Workflow(t)
	job := requirePublishJob(t, doc)

	// Locate verify / monotonic-binding / promote by signature.
	verifyIdx, bindIdx, promoteIdx := -1, -1, -1
	for i := range job.Steps {
		run := runScript(job.Steps[i].Run)
		switch {
		case verifyIdx == -1 && strings.Contains(run, "TestServedVerify_BakedRootGate"):
			verifyIdx = i
		case bindIdx == -1 && runContainsAll(run, "catalog_version", "generated_at", "release-catalog/index.json"):
			bindIdx = i
		case promoteIdx == -1 && strings.Contains(run, "copy-object"):
			promoteIdx = i
		}
	}
	if bindIdx == -1 {
		t.Fatal("SEC-F2b: the monotonic live-binding step is missing from the R2 publisher (a resign could roll the live pointer backward)")
	}
	bindOrdered := verifyIdx != -1 && promoteIdx != -1 && verifyIdx < bindIdx && bindIdx < promoteIdx
	if !bindOrdered {
		t.Fatalf("SEC-F2b binding must sit between verify(%d) and promote(%d); got bind(%d)", verifyIdx, promoteIdx, bindIdx)
	}
	bind := job.Steps[bindIdx]
	if !strings.Contains(bind.If, "resign_asset") {
		t.Fatalf("the monotonic binding step must be gated on the resign_asset input; got if: %q", bind.If)
	}
	if !runContainsAll(bind.Run, "-lt", "exit 1", "sort") {
		t.Fatal("the monotonic binding must fail closed on version regression and non-newer generated_at")
	}
	// OPS-F2 (M1-4 extension): the publisher downloads by exact name — no glob
	// --pattern, and the resign asset name is validated by the anchored regex.
	assertNoGlobPatterns(t, "R2 publisher", job)
	anchored := false
	for i := range job.Steps {
		if strings.Contains(runScript(job.Steps[i].Run), `-r[0-9]{8}\.tar\.gz$`) {
			anchored = true
		}
	}
	if !anchored {
		t.Fatal("R2 publisher must validate resign_asset against the anchored resign-name regex before using it as an R2 key segment")
	}
}

// TestResignSchedulerInvariants: the scheduler sequences but must not be able
// to SIGN or PUBLISH — actions:write + contents:read only, no id-token, zero
// secrets-context mentions — and its dispatch chain is ordered ci → R2 → Pages
// → verify with fail-closed bounded polling.
func TestResignSchedulerInvariants(t *testing.T) {
	doc := loadWorkflow(t, resignSchedulerPath)
	if permsGrantIDToken(doc.Permissions) || permsContentsWritable(doc.Permissions) {
		t.Fatal("scheduler must have no id-token and contents at most read")
	}
	for name, job := range doc.Jobs {
		if permsGrantIDToken(job.Permissions) || permsContentsWritable(job.Permissions) {
			t.Fatalf("scheduler job %q must have no id-token and contents at most read", name)
		}
	}
	raw, err := os.ReadFile(resignSchedulerPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expr := range wfExprRE.FindAllString(string(raw), -1) {
		if regexp.MustCompile(`\bsecrets\b`).MatchString(expr) {
			t.Fatalf("scheduler expression mentions the secrets context: %q", expr)
		}
	}
	// Sequencing: one job whose combined run bodies dispatch ci.yml with
	// resign=true, then the R2 publisher with resign_asset, then Pages, then
	// the dual verify — in that order — with a fail-closed conclusion check.
	var all strings.Builder
	for _, job := range doc.Jobs {
		for i := range job.Steps {
			all.WriteString(runScript(job.Steps[i].Run))
			all.WriteByte('\n')
		}
	}
	seq := all.String()
	ci := strings.Index(seq, "dispatch_and_wait ci.yml")
	r2 := strings.Index(seq, "dispatch_and_wait publish-catalog-r2.yml")
	pg := strings.Index(seq, "dispatch_and_wait publish-catalog-pages.yml")
	vf := strings.Index(seq, "dispatch_and_wait verify-dual-publish.yml")
	if ci == -1 || r2 == -1 || pg == -1 || vf == -1 {
		t.Fatalf("scheduler must dispatch ci(%d), r2(%d), pages(%d), verify(%d) — one is missing", ci, r2, pg, vf)
	}
	if !(ci < r2 && r2 < pg && pg < vf) {
		t.Fatal("scheduler dispatch order must be ci → R2 → Pages → verify (OPS-F4)")
	}
	if !runContainsAll(seq, "resign=true", "resign_asset=", `"$conclusion" = "success"`, "fail-closed") {
		t.Fatal("scheduler must pass resign=true / resign_asset and poll each run to a fail-closed success conclusion")
	}
}

// TestResignPagesAndCanaryInvariants: the Pages newest-resign pick and the
// SEC-F5 weekly freshness canary on the dual verify.
func TestResignPagesAndCanaryInvariants(t *testing.T) {
	pages := loadWorkflow(t, pagesWorkflowPath)
	pick := false
	for _, job := range pages.Jobs {
		for i := range job.Steps {
			run := runScript(job.Steps[i].Run)
			if runContainsAll(run, `-r*.tar.gz`, "sort | tail -n1", `BUNDLE="dl/culvert-release-catalog-${TAG}.tar.gz"`) {
				pick = true
			}
		}
	}
	if !pick {
		t.Fatal("Pages publisher must prefer the newest resign bundle with an exact-original fallback (the old `ls | head -n1` picked the OLDEST resign)")
	}

	verify := loadWorkflow(t, dualVerifyWorkflowPath)
	canary := false
	for _, job := range verify.Jobs {
		for i := range job.Steps {
			st := job.Steps[i]
			if !strings.Contains(st.Run, "generated_at") || !strings.Contains(st.Run, "AGE") {
				continue
			}
			if !strings.Contains(st.If, "schedule") {
				t.Fatalf("the freshness canary must run on schedule events only; got if: %q", st.If)
			}
			if !runContainsAll(st.Run, "14", "exit 1") {
				t.Fatal("the freshness canary must fail when the live generated_at is older than 14 days (2× cadence)")
			}
			canary = true
		}
	}
	if !canary {
		t.Fatal("SEC-F5: verify-dual-publish must carry the weekly live-freshness canary step")
	}
}
