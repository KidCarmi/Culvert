package main

import (
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// Structural (not substring-scan) invariant tests for the DORMANT public-feed
// publisher (.github/workflows/publish-feeds.yml, F5). The threat model is a FUTURE
// EDIT that silently relaxes an invariant while keeping the YAML valid; every
// assertion is written so an unsafe workflow FAILS (never vacuously passes). The
// two-job privilege boundary (F0 §11.1) is the load-bearing property: Job A holds
// the OIDC signing identity but NO R2 credential; Job B holds the R2 credential but
// NO id-token — so neither job can both sign AND publish.
//
// Reuses the pure helpers from release_workflow_invariants_test.go (same package):
// permsGrantIDToken, permsContentsWritable, runScript, runContainsAll, isTruthy,
// wfStepWith, wfExprRE/wfRefRE via wfRefSets, assertSetEquals.

const feedsWorkflowPath = ".github/workflows/publish-feeds.yml"

type feedsWFStep struct {
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	If   string            `yaml:"if"`
	With wfStepWith        `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type feedsWFJob struct {
	Needs       interface{}   `yaml:"needs"`
	If          string        `yaml:"if"`
	Permissions interface{}   `yaml:"permissions"`
	Environment interface{}   `yaml:"environment"` // string OR {name: ...} map, or absent
	Steps       []feedsWFStep `yaml:"steps"`
}

// envName extracts the environment name from a job's `environment:` node, which may
// be a bare string or a `{name: ...}` map. Empty string ⇒ no environment binding.
func envName(env interface{}) string {
	switch v := env.(type) {
	case string:
		return v
	case map[string]interface{}:
		if s, ok := v["name"].(string); ok {
			return s
		}
	}
	return ""
}

type feedsWFDoc struct {
	Permissions interface{} `yaml:"permissions"`
	Concurrency struct {
		Group            string      `yaml:"group"`
		CancelInProgress interface{} `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]feedsWFJob `yaml:"jobs"`
}

func loadFeedsWorkflow(t *testing.T) feedsWFDoc {
	t.Helper()
	raw, err := os.ReadFile(feedsWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", feedsWorkflowPath, err)
	}
	var doc feedsWFDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", feedsWorkflowPath, err)
	}
	if len(doc.Jobs) == 0 {
		t.Fatalf("%s has no jobs", feedsWorkflowPath)
	}
	return doc
}

// jobSecretRefs returns the set of `secrets.NAME` referenced anywhere in a job
// (step env values, run bodies, ifs, and the job-level if). This is the mechanism
// behind the privilege-boundary assertion: Job A's set MUST be empty, Job B's set
// MUST equal the R2/CF contract.
func jobSecretRefs(job feedsWFJob) map[string]bool {
	set := map[string]bool{}
	add := func(s string) {
		for _, m := range wfRefRE.FindAllStringSubmatch(s, -1) {
			if m[1] == "secrets" {
				set[m[2]] = true
			}
		}
	}
	add(job.If)
	for i := range job.Steps {
		add(job.Steps[i].If)
		add(job.Steps[i].Run)
		for _, v := range job.Steps[i].Env {
			add(v)
		}
	}
	return set
}

func TestFeedsWorkflowInvariants(t *testing.T) {
	doc := loadFeedsWorkflow(t)
	assertFeedsTopLevel(t, doc)
	assertFeedsPrivilegeBoundary(t, doc)
	assertFeedsGenerateSigns(t, doc)
	assertFeedsMasterGateDominance(t, doc)
	assertFeedsSigningRefPinning(t, doc)
	pub := requireFeedsPublishJob(t, doc)
	assertFeedsNoSecretsInIf(t, doc)
	assertFeedsPublishSequence(t, pub)
	assertFeedsEgressAllowList(t, pub)
}

// feedsMasterGate is the exact expression that must dominate every signing step (Job
// A) and the publish job (Job B): the master switch AND the feeds-v* tag context.
const feedsMasterGate = "vars.FEEDS_PUBLISH_ENABLED == 'true'"

// assertFeedsMasterGateDominance: NO signing/publication path may run unless the master
// gate is exactly 'true'. Every Job A step that installs cosign, runs `cosign sign-blob`,
// or runs the keyless end-to-end verify must carry `vars.FEEDS_PUBLISH_ENABLED == 'true'`
// in its `if:`; the publish job's `if:` must too. So a feeds-v* tag push with the gate
// disabled signs and publishes nothing.
func assertFeedsMasterGateDominance(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	gen := doc.Jobs["generate"]
	guarded, total := 0, 0
	for i := range gen.Steps {
		run := runScript(gen.Steps[i].Run)
		uses := gen.Steps[i].Uses
		isSigningPath := strings.Contains(run, "cosign sign-blob") ||
			strings.Contains(uses, "cosign-installer") ||
			strings.Contains(run, "TestFeedGenKeylessVerify")
		if !isSigningPath {
			continue
		}
		total++
		if strings.Contains(gen.Steps[i].If, feedsMasterGate) {
			guarded++
		} else {
			t.Fatalf("MASTER GATE: generate-job signing step %q is not gated on `%s`; got if: %q",
				gen.Steps[i].Name, feedsMasterGate, gen.Steps[i].If)
		}
	}
	if total == 0 {
		t.Fatal("MASTER GATE: found no signing steps in the generate job to guard (detection broke)")
	}
	if guarded != total {
		t.Fatalf("MASTER GATE: %d/%d signing steps guarded", guarded, total)
	}
	// The publish job's own gate must also key on the master switch.
	if !strings.Contains(doc.Jobs["publish"].If, feedsMasterGate) {
		t.Fatalf("MASTER GATE: publish job `if:` must include `%s`; got %q", feedsMasterGate, doc.Jobs["publish"].If)
	}
}

// assertFeedsSigningRefPinning: before any cosign call, Job A must PROVE it is running
// at the operator-pinned tag/SHA — a step that (a) is gated on the master gate, (b)
// references both `vars.FEEDS_SIGNING_TAG` and `vars.FEEDS_SIGNING_TAG_SHA`, (c) checks
// the exact feeds-vX.Y.Z grammar and a 40-hex SHA, (d) compares to github.ref_name +
// github.sha, and (e) fails closed (`exit 1`) — and it must appear BEFORE the first
// `cosign sign-blob`. The publish job must re-assert the same pin.
func assertFeedsSigningRefPinning(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	pinIdx, signIdx := feedsPinAndSignIdx(doc.Jobs["generate"])
	if pinIdx == -1 {
		t.Fatal("SIGNING-REF PIN: generate job has no signing-ref pinning proof step")
	}
	if signIdx == -1 {
		t.Fatal("SIGNING-REF PIN: generate job has no cosign sign-blob step")
	}
	if pinIdx >= signIdx {
		t.Fatalf("SIGNING-REF PIN: the pinning proof (%d) must run BEFORE cosign sign-blob (%d)", pinIdx, signIdx)
	}
	assertPinStepShape(t, "generate", doc.Jobs["generate"].Steps[pinIdx])
	// Job B must re-assert the pin on the publication path.
	pubPin, _ := feedsPinAndSignIdx(doc.Jobs["publish"])
	if pubPin == -1 {
		t.Fatal("SIGNING-REF PIN: publish job must re-assert the tag/SHA pin on the publication path")
	}
	assertPinStepShape(t, "publish", doc.Jobs["publish"].Steps[pubPin])
}

// feedsPinAndSignIdx returns (pinning-proof index, first cosign-sign index) for a job.
// The pinning proof is identified by its run-body signature: the exact feeds-vX.Y.Z tag
// grammar, the 40-hex SHA grammar, and the REF_NAME/RUN_SHA equality checks together
// appear only in a signing-ref pin step.
func feedsPinAndSignIdx(job feedsWFJob) (pin, sign int) {
	pin, sign = -1, -1
	for i := range job.Steps {
		run := runScript(job.Steps[i].Run)
		if pin == -1 && runContainsAll(run,
			`^feeds-v[0-9]+\.[0-9]+\.[0-9]+$`, `^[0-9a-f]{40}$`, "REF_NAME", "RUN_SHA") {
			pin = i
		}
		if sign == -1 && strings.Contains(run, "cosign sign-blob") {
			sign = i
		}
	}
	return pin, sign
}

// assertPinStepShape proves a pinning step is fail-closed and checks all four facets:
// tag grammar, 40-hex SHA, ref-name equality, and commit-SHA equality.
func assertPinStepShape(t *testing.T, job string, step feedsWFStep) {
	t.Helper()
	// The pinned vars must be wired in via env (so `${{ vars.* }}` appears in env values).
	if step.Env["SIGNING_TAG"] == "" || step.Env["SIGNING_TAG_SHA"] == "" {
		t.Fatalf("SIGNING-REF PIN (%s): step must wire SIGNING_TAG + SIGNING_TAG_SHA from vars via env", job)
	}
	if !strings.Contains(step.Env["SIGNING_TAG"], "FEEDS_SIGNING_TAG") ||
		!strings.Contains(step.Env["SIGNING_TAG_SHA"], "FEEDS_SIGNING_TAG_SHA") {
		t.Fatalf("SIGNING-REF PIN (%s): env must reference vars.FEEDS_SIGNING_TAG / _SHA", job)
	}
	run := step.Run
	if !runContainsAll(run, `^feeds-v[0-9]+\.[0-9]+\.[0-9]+$`, `^[0-9a-f]{40}$`, "REF_NAME", "RUN_SHA", "exit 1") {
		t.Fatalf("SIGNING-REF PIN (%s): step must check feeds-vX.Y.Z grammar, 40-hex SHA, ref_name + sha equality, and fail closed (exit 1)", job)
	}
}

// assertFeedsTopLevel: explicit restrictive top-level permissions (absent inherits a
// broad default), no top-level id-token / contents:write, and a serialized
// non-cancelling concurrency group.
func assertFeedsTopLevel(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	if doc.Permissions == nil {
		t.Fatal("top-level permissions must be present and restrictive (absent inherits a broad default)")
	}
	if permsGrantIDToken(doc.Permissions) {
		t.Fatal("top-level permissions grants id-token; only Job A may elevate it")
	}
	if permsContentsWritable(doc.Permissions) {
		t.Fatal("top-level permissions grants contents:write; must be read-only")
	}
	if doc.Concurrency.Group != "feeds-publish" {
		t.Fatalf("concurrency group must be feeds-publish (serialize publications); got %q", doc.Concurrency.Group)
	}
	if isTruthy(doc.Concurrency.CancelInProgress) {
		t.Fatal("concurrency.cancel-in-progress must be false — never cancel an in-flight CAS promote")
	}
}

// assertFeedsPrivilegeBoundary is the core F0 §11.1 property: Job A `generate` grants
// id-token but references NO secret; Job B `publish` references the R2/CF secrets but
// grants NO id-token (at any level). No job may grant contents:write.
func assertFeedsPrivilegeBoundary(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	gen, ok := doc.Jobs["generate"]
	if !ok {
		t.Fatal("expected a `generate` (sign) job")
	}
	pub, ok := doc.Jobs["publish"]
	if !ok {
		t.Fatal("expected a `publish` job")
	}
	if !permsGrantIDToken(gen.Permissions) {
		t.Fatal("the generate job must grant id-token (keyless signing)")
	}
	if permsContentsWritable(gen.Permissions) {
		t.Fatal("the generate job must not grant contents:write")
	}
	if refs := jobSecretRefs(gen); len(refs) != 0 {
		t.Fatalf("PRIVILEGE BOUNDARY: the generate (sign) job must reference NO secrets; found %v", refs)
	}
	if permsGrantIDToken(pub.Permissions) || permsGrantIDToken(doc.Permissions) {
		t.Fatal("PRIVILEGE BOUNDARY: the publish job must grant NO id-token (it must not be able to sign)")
	}
	if permsContentsWritable(pub.Permissions) {
		t.Fatal("the publish job must not grant contents:write")
	}
	// B-1: ONLY the publish job binds the protected `feeds-production` environment
	// (required-reviewer approval + environment secrets). Job A must NOT bind it.
	if envName(pub.Environment) != "feeds-production" {
		t.Fatalf("PRIVILEGE BOUNDARY: the publish job must bind environment `feeds-production`; got %q", envName(pub.Environment))
	}
	if envName(gen.Environment) != "" {
		t.Fatalf("PRIVILEGE BOUNDARY: the generate (sign) job must NOT bind any environment; got %q", envName(gen.Environment))
	}
	// Job B must depend on Job A (it publishes A's signed artifact).
	if !needsContains(pub.Needs, "generate") {
		t.Fatalf("the publish job must `needs: generate`; got %v", pub.Needs)
	}
	// Job B's secret set must be EXACTLY the R2/CF contract (drift in either direction fails).
	assertSetEquals(t, "publish job secrets", jobSecretRefs(pub), []string{
		"FEEDS_R2_S3_ENDPOINT", "FEEDS_R2_S3_ACCESS_KEY_ID", "FEEDS_R2_S3_SECRET_ACCESS_KEY",
		"FEEDS_R2_BUCKET", "FEEDS_CF_ZONE_ID", "FEEDS_CF_CACHE_PURGE_TOKEN",
	})
}

func needsContains(needs interface{}, want string) bool {
	switch v := needs.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, n := range v {
			if s, ok := n.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// assertFeedsGenerateSigns: the generate job signs keyless on a feeds-v* tag and
// end-to-end verifies through the baked-root path with the enforcing pass-proof.
func assertFeedsGenerateSigns(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	gen := doc.Jobs["generate"]
	signIdx, kvIdx := -1, -1
	for i := range gen.Steps {
		run := runScript(gen.Steps[i].Run)
		switch {
		case signIdx == -1 && strings.Contains(run, "cosign sign-blob"):
			signIdx = i
		case kvIdx == -1 && strings.Contains(run, "TestFeedGenKeylessVerify"):
			kvIdx = i
		}
	}
	if signIdx == -1 {
		t.Fatal("the generate job must keyless-sign (cosign sign-blob) the artifact + manifest")
	}
	if !strings.Contains(gen.Steps[signIdx].If, "refs/tags/feeds-v") {
		t.Fatalf("the signing step must be gated on a feeds-v* tag ref (pinned identity); got if: %q", gen.Steps[signIdx].If)
	}
	if kvIdx == -1 {
		t.Fatal("the generate job must run the keyless end-to-end verify (TestFeedGenKeylessVerify)")
	}
	if !assertEnforcingPass(gen.Steps[kvIdx].Run, "TestFeedGenKeylessVerify") {
		t.Fatal("the keyless end-to-end verify step lacks the enforcing pass-proof (-json + jq -e + Action pass + exit 1)")
	}
}

func requireFeedsPublishJob(t *testing.T, doc feedsWFDoc) feedsWFJob {
	t.Helper()
	pub := doc.Jobs["publish"]
	if !strings.Contains(pub.If, "vars.FEEDS_PUBLISH_ENABLED") {
		t.Fatalf("publish job gate must key on vars.FEEDS_PUBLISH_ENABLED (dormant switch); got %q", pub.If)
	}
	if !strings.Contains(pub.If, "refs/tags/feeds-v") {
		t.Fatalf("publish job must require a feeds-v* tag context (a dry-run produced no signed envelope); got %q", pub.If)
	}
	return pub
}

// assertFeedsNoSecretsInIf: no `if:` (job- or step-level) references secrets.* — the
// dormant gate must key on vars (secrets.* is unavailable in if: anyway).
func assertFeedsNoSecretsInIf(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	check := func(where, expr string) {
		if strings.Contains(expr, "secrets.") || strings.Contains(expr, "secrets[") {
			t.Fatalf("%s `if:` references secrets (unavailable in if:; the gate must key on vars): %q", where, expr)
		}
	}
	for name, job := range doc.Jobs {
		check("job "+name, job.If)
		for i := range job.Steps {
			check("job "+name+" step", job.Steps[i].If)
		}
	}
}

// feedsPublishSteps locates the five load-bearing publish steps by run-body signature
// (-1 sentinel ⇒ a missing step FAILS the caller's checks, never vacuously passes).
func feedsPublishSteps(job feedsWFJob) (verifyDL, stage, pubArt, promote, pubEnv int) {
	verifyDL, stage, pubArt, promote, pubEnv = -1, -1, -1, -1, -1
	for i := range job.Steps {
		run := runScript(job.Steps[i].Run)
		switch {
		case verifyDL == -1 && strings.Contains(run, "TestFeedPublishVerifyGate") && strings.Contains(run, "verified.json"):
			verifyDL = i
		case stage == -1 && strings.Contains(run, "put_create_only") && strings.Contains(run, "--if-none-match"):
			stage = i
		case pubArt == -1 && strings.Contains(run, "TestFeedPublishVerifyGate") && strings.Contains(run, "cp dl/manifest.sigstore.json pub/manifest.sigstore.json"):
			pubArt = i
		case promote == -1 && strings.Contains(run, "manifest.sigstore.json") && strings.Contains(run, "--if-match"):
			promote = i
		case pubEnv == -1 && strings.Contains(run, "TestFeedPublishVerifyGate") && strings.Contains(run, "purge_cache"):
			pubEnv = i
		}
	}
	return verifyDL, stage, pubArt, promote, pubEnv
}

// assertFeedsPublishSequence: the §11.2 sequence EXISTS and is ordered
// re-verify(downloaded) → stage(create-only) → public-artifact re-verify → CAS
// promote(envelope, LAST) → public-envelope re-verify; each of the three re-verify
// steps carries the enforcing non-skip pass-proof; the CAS promote is strictly-greater
// + If-Match + reads the live version from the R2 origin.
func assertFeedsPublishSequence(t *testing.T, pub feedsWFJob) {
	t.Helper()
	verifyDL, stage, pubArt, promote, pubEnv := feedsPublishSteps(pub)
	if verifyDL == -1 {
		t.Fatal("missing downloaded-bundle re-verify step (TestFeedPublishVerifyGate + verified.json)")
	}
	if stage == -1 {
		t.Fatal("missing create-only staging step (put_create_only --if-none-match) — immutability guard absent")
	}
	if pubArt == -1 {
		t.Fatal("missing public-artifact re-verify step")
	}
	if promote == -1 {
		t.Fatal("missing CAS envelope-promote step (manifest.sigstore.json + --if-match)")
	}
	if pubEnv == -1 {
		t.Fatal("missing public-envelope re-verify step")
	}
	ordered := verifyDL < stage && stage < pubArt && pubArt < promote && promote < pubEnv
	if !ordered {
		t.Fatalf("publish steps must be ordered verify(%d) < stage(%d) < public-artifact(%d) < promote(%d) < public-envelope(%d) — the envelope must be promoted LAST",
			verifyDL, stage, pubArt, promote, pubEnv)
	}
	for _, idx := range []int{verifyDL, pubArt, pubEnv} {
		if !assertEnforcingPass(pub.Steps[idx].Run, "TestFeedPublishVerifyGate") {
			t.Fatalf("re-verify step %q lacks the enforcing pass-proof (-json + jq -e + Action pass + exit 1)", pub.Steps[idx].Name)
		}
	}
	// Exactly three re-verify invocations (downloaded, public artifact, public envelope).
	n := 0
	for i := range pub.Steps {
		if strings.Contains(pub.Steps[i].Run, "TestFeedPublishVerifyGate") {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("expected exactly 3 TestFeedPublishVerifyGate re-verify steps; found %d", n)
	}
	assertFeedsCAS(t, pub.Steps[promote])
}

// assertFeedsCAS: the envelope promote reads the LIVE feed_version from the R2 ORIGIN,
// requires the new one strictly greater, and writes conditionally (If-Match on a live
// envelope; If-None-Match '*' on first publish) — aborting on a 412.
func assertFeedsCAS(t *testing.T, promote feedsWFStep) {
	t.Helper()
	run := promote.Run
	if !runContainsAll(run, "get-object", "payload_b64", "feed_version") {
		t.Fatal("CAS promote must read the live envelope's embedded feed_version from the R2 origin (get-object + payload_b64 + feed_version)")
	}
	if !runContainsAll(run, "-le", "exit 1") {
		t.Fatal("CAS promote must fail closed unless the new feed_version is STRICTLY GREATER than live (`-le` guard + exit 1)")
	}
	if !strings.Contains(run, "--if-match") {
		t.Fatal("CAS promote must use --if-match on the live envelope ETag")
	}
	if !strings.Contains(run, "--if-none-match") {
		t.Fatal("CAS promote must use --if-none-match '*' for the first publish")
	}
	if !runContainsAll(run, "412", "exit 1") {
		t.Fatal("CAS promote must abort (exit 1) on a 412 precondition failure (concurrent/stale publisher)")
	}
}

// assertEnforcingPass reports whether a run body ENFORCES a non-skip PASS for the
// named test via `go test -json` + `jq -e` on an Action==pass record + `exit 1` (so a
// skipped test — which exits 0 — fails OPEN otherwise).
func assertEnforcingPass(run, testName string) bool {
	if !strings.Contains(run, testName) {
		return false
	}
	enforcingJQ := strings.Contains(run, "jq -e") || strings.Contains(run, "--exit-status")
	return enforcingJQ && runContainsAll(run, "-json", "exit 1", "Action", "pass")
}

// assertFeedsEgressAllowList: the publish job's harden-runner is egress:block with a
// well-formed allow-list (no literal quote chars inside the block scalar, every token
// carries a :port) covering the origin, CDN-purge, and public-verify hosts.
func assertFeedsEgressAllowList(t *testing.T, job feedsWFJob) {
	t.Helper()
	var allowed string
	for i := range job.Steps {
		if strings.Contains(job.Steps[i].Uses, "harden-runner") {
			allowed = job.Steps[i].With.AllowedEndpoints
			if job.Steps[i].With.EgressPolicy != "block" {
				t.Fatalf("publish harden-runner egress-policy must be block; got %q", job.Steps[i].With.EgressPolicy)
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
		"*.r2.cloudflarestorage.com:443", // stage/promote origin
		"api.cloudflare.com:443",         // envelope cache purge
		"feeds.culvertlabs.com:443",      // public re-verify
	} {
		if !strings.Contains(allowed, must) {
			t.Fatalf("allow-list is missing required endpoint %q", must)
		}
	}
}

// TestFeedsPublisherSecretContract pins the publisher's EXACT secret/var reference
// sets (the secret-name-drift regression guard — an operator configuring differently
// named secrets fails closed but only surfaces here). Drift in either direction fails
// CI, keeping workflow + runbook in lock-step.
func TestFeedsPublisherSecretContract(t *testing.T) {
	secretSet, varSet := wfRefSets(t, feedsWorkflowPath)
	assertSetEquals(t, "publish-feeds.yml secrets", secretSet, []string{
		"FEEDS_R2_S3_ENDPOINT", "FEEDS_R2_S3_ACCESS_KEY_ID", "FEEDS_R2_S3_SECRET_ACCESS_KEY",
		"FEEDS_R2_BUCKET", "FEEDS_CF_ZONE_ID", "FEEDS_CF_CACHE_PURGE_TOKEN",
	})
	assertSetEquals(t, "publish-feeds.yml vars", varSet, []string{
		"FEEDS_PUBLISH_ENABLED", "FEEDS_PUBLIC_BASE",
		"FEEDS_SIGNING_TAG", "FEEDS_SIGNING_TAG_SHA",
	})
}

// ─── resign-feeds.yml (renewal dispatcher) invariants ─────────────────────────

const resignFeedsWorkflowPath = ".github/workflows/resign-feeds.yml"

// TestResignFeedsWorkflowInvariants proves the weekly renewal dispatcher CANNOT sign
// or publish anything itself: it holds contents:read + actions:write ONLY, has no
// id-token / no environment / references no secrets and no cosign, validates the master
// gate + pinned tag/SHA, and dispatches publish-feeds.yml at the pinned protected tag.
func TestResignFeedsWorkflowInvariants(t *testing.T) {
	raw, err := os.ReadFile(resignFeedsWorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", resignFeedsWorkflowPath, err)
	}
	var doc feedsWFDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", resignFeedsWorkflowPath, err)
	}
	if len(doc.Jobs) == 0 {
		t.Fatalf("%s has no jobs", resignFeedsWorkflowPath)
	}
	assertResignNoPrivilege(t, doc)         // (1) no id-token/contents:write/env/secrets
	assertResignNoSecretsContext(t, raw)    // (2) no secrets context in any expression
	assertResignTriggers(t, raw)            // (3) weekly schedule + manual dispatch
	assertResignDispatchesPinnedTag(t, doc) // (4) dispatch-only, no cosign, validated
	assertResignPinnedVars(t)               // (5) references the pinned vars.*
	assertResignConcurrency(t, doc)         // (6) concurrency guard
}

// (1) No id-token anywhere; contents at most read; no environment; no secrets.
func assertResignNoPrivilege(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	if permsGrantIDToken(doc.Permissions) {
		t.Fatal("resign workflow top-level grants id-token — a renewal dispatcher must not be able to sign")
	}
	if permsContentsWritable(doc.Permissions) {
		t.Fatal("resign workflow top-level grants contents:write")
	}
	for name, job := range doc.Jobs {
		if permsGrantIDToken(job.Permissions) {
			t.Fatalf("resign job %q grants id-token", name)
		}
		if permsContentsWritable(job.Permissions) {
			t.Fatalf("resign job %q grants contents:write", name)
		}
		if envName(job.Environment) != "" {
			t.Fatalf("resign job %q must NOT bind any environment (no feeds-production access); got %q", name, envName(job.Environment))
		}
		if refs := jobSecretRefs(job); len(refs) != 0 {
			t.Fatalf("resign job %q must reference NO secrets; found %v", name, refs)
		}
	}
}

// (2) No secrets context in ANY expression (catches secrets['X'] / toJSON(secrets)).
func assertResignNoSecretsContext(t *testing.T, raw []byte) {
	t.Helper()
	for _, expr := range wfExprRE.FindAllString(string(raw), -1) {
		if strings.Contains(expr, "secrets") {
			t.Fatalf("resign workflow expression mentions the secrets context (any form is a violation): %q", expr)
		}
	}
}

// (3) Weekly schedule + manual dispatch triggers.
func assertResignTriggers(t *testing.T, raw []byte) {
	t.Helper()
	s := string(raw)
	if !strings.Contains(s, "schedule:") || !strings.Contains(s, "cron:") {
		t.Fatal("resign workflow must carry a weekly `schedule: cron:` trigger")
	}
	if !strings.Contains(s, "workflow_dispatch") {
		t.Fatal("resign workflow must also allow manual workflow_dispatch")
	}
}

// (4) Its ONLY side effect is to dispatch publish-feeds.yml at the pinned tag — it must
// NEVER sign locally, must grant actions:write, and must validate the gate + tag + SHA.
func assertResignDispatchesPinnedTag(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	var body strings.Builder
	sawActionsWrite := false
	for _, job := range doc.Jobs {
		if toStr(mapGet(job.Permissions, "actions")) == "write" {
			sawActionsWrite = true
		}
		for i := range job.Steps {
			// Strip shell comments first — a "never runs cosign" comment must not trip this.
			if strings.Contains(runScript(job.Steps[i].Run), "cosign") {
				t.Fatalf("resign workflow must NOT run cosign (no local signing); step %q", job.Steps[i].Name)
			}
			body.WriteString(job.Steps[i].Run)
			body.WriteByte('\n')
		}
	}
	if !sawActionsWrite {
		t.Fatal("resign job must grant actions:write to dispatch the publisher")
	}
	seq := body.String()
	if !strings.Contains(seq, "gh workflow run publish-feeds.yml") {
		t.Fatal("resign workflow must dispatch publish-feeds.yml (gh workflow run)")
	}
	if !runContainsAll(seq, `--ref "$SIGNING_TAG"`, "validity_hours=336") {
		t.Fatal("resign must dispatch at the PINNED tag ($SIGNING_TAG from vars.FEEDS_SIGNING_TAG) preserving 336h validity")
	}
	// gate + tag grammar + 40-hex SHA + lightweight-tag resolution, fail-closed. (The master-gate
	// VAR reference is asserted in assertResignPinnedVars; the body checks it via the $GATE env
	// alias with a `!= "true"` fail-closed guard.)
	if !runContainsAll(seq, `!= "true"`,
		`^feeds-v[0-9]+\.[0-9]+\.[0-9]+$`, `^[0-9a-f]{40}$`,
		"object.type", "commit", "exit 1") {
		t.Fatal("resign must validate the master gate, exact tag grammar, 40-hex SHA, and lightweight-tag resolution, failing closed")
	}
}

// (5) Pinned vars are referenced from vars.* (not hardcoded).
func assertResignPinnedVars(t *testing.T) {
	t.Helper()
	_, varSet := wfRefSets(t, resignFeedsWorkflowPath)
	for _, must := range []string{"FEEDS_PUBLISH_ENABLED", "FEEDS_SIGNING_TAG", "FEEDS_SIGNING_TAG_SHA"} {
		if !varSet[must] {
			t.Fatalf("resign workflow must reference vars.%s", must)
		}
	}
}

// (6) Concurrency so overlapping renewals cannot race.
func assertResignConcurrency(t *testing.T, doc feedsWFDoc) {
	t.Helper()
	if doc.Concurrency.Group == "" {
		t.Fatal("resign workflow must declare a concurrency group (no racing renewals)")
	}
	if isTruthy(doc.Concurrency.CancelInProgress) {
		t.Fatal("resign concurrency.cancel-in-progress must be false")
	}
}

// mapGet reads key from an interface{} that may be a map[string]interface{}.
func mapGet(m interface{}, key string) interface{} {
	if mm, ok := m.(map[string]interface{}); ok {
		return mm[key]
	}
	return nil
}
