package mcpacceptance

// Machine-checkable guards for the Observe Acceptance operational-readiness
// documentation pack (docs/operator). These keep the operator-facing pack in
// lockstep with the code and enforce the pack's own safety invariants:
//
//   - the authoritative spec template still matches the current spec schema
//     (LoadSpec rejects unknown fields, so schema drift fails here);
//   - no secret-like literal material leaked into the example or the docs;
//   - the operator values in the template were NOT invented (placeholders remain);
//   - the runbook carries all sixteen required operator sections;
//   - the runbook's Final cleanup section states the QUAL-6.1 authoritative
//     preservation contract (operator-owned telemetry + KEK, preserved on cleanup,
//     reused across the authoritative restart) and no longer carries the stale QUAL-6
//     "harness-owned / no operator KEK / deleted on cleanup" claims;
//   - the runbook contains no call-form BeginWindow / rollout-transition invocation;
//   - the new docs contain no em-dash (repository operator-doc convention).
//
// No production runtime code and no external dependency are involved.

import (
	"os"
	"strings"
	"testing"
)

// docPaths are resolved relative to this package directory (repo-root/../..).
const (
	docExampleSpec   = "../../docs/operator/examples/mcp-observe-acceptance-authoritative.json"
	docExampleREADME = "../../docs/operator/examples/README.md"
	docRunbook       = "../../docs/operator/mcp-observe-acceptance-runbook.md"
	docDecisions     = "../../docs/operator/mcp-observe-acceptance-decisions.md"
)

func docNewDocs() []string {
	return []string{docExampleSpec, docExampleREADME, docRunbook, docDecisions}
}

// TestDocsPack_ExampleSpecMatchesSchema loads the authoritative template through the
// REAL LoadSpec. LoadSpec disallows unknown fields and runs Validate, so a schema
// change that is not mirrored in the template fails this test.
func TestDocsPack_ExampleSpecMatchesSchema(t *testing.T) {
	sp, err := LoadSpec(docExampleSpec)
	if err != nil {
		t.Fatalf("authoritative example spec does not load against the current schema: %v", err)
	}
	if sp.Mode != ModeAuthoritative {
		t.Fatalf("example spec mode = %q, want %q", sp.Mode, ModeAuthoritative)
	}
	if sp.Environment == nil {
		t.Fatal("authoritative example spec must carry an environment")
	}
	// Validate is already called by LoadSpec; re-assert for intent.
	if err := sp.Validate(); err != nil {
		t.Fatalf("example spec failed authoritative validation: %v", err)
	}
}

// TestDocsPack_NoInventedOperatorValues proves the template still carries obvious
// placeholders for every operator decision, i.e. no real host/issuer/tenant/digest
// was baked in.
func TestDocsPack_NoInventedOperatorValues(t *testing.T) {
	b, err := os.ReadFile(docExampleSpec)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	for _, ph := range []string{
		"<DECISION_REQUIRED_ARTIFACT_BINARY_PATH>",
		"<DECISION_REQUIRED_ARTIFACT_SHA256_DIGEST>",
		"<DECISION_REQUIRED_OAUTH_ISSUER>",
		"<DECISION_REQUIRED_TENANT_A>",
		"<DECISION_REQUIRED_TENANT_B>",
		"<DECISION_REQUIRED_SERVER_A_ID>",
		"<DECISION_REQUIRED_SERVER_B_ID>",
		"<DECISION_REQUIRED_SIGNING_KEY_FILE>",
		"<DECISION_REQUIRED_EVIDENCE_DIR>",
		// QUAL-6.1 authoritative controls must also remain operator decisions.
		"<DECISION_REQUIRED_QUALIFICATION_POLICY_FILE>",
		"<DECISION_REQUIRED_TELEMETRY_NODE_ID>",
		"<DECISION_REQUIRED_TELEMETRY_DATA_DIR>",
		"<DECISION_REQUIRED_TELEMETRY_KEK_FILE>",
		"<DECISION_REQUIRED_TELEMETRY_ARCHIVE_DIR>",
		"<DECISION_REQUIRED_ADMIN_PASSWORD_FILE>",
		"<DECISION_REQUIRED_METRICS_TOKEN_FILE>",
	} {
		if !strings.Contains(content, ph) {
			t.Errorf("example spec is missing placeholder %q (operator value must not be invented)", ph)
		}
	}
}

// TestDocsPack_NoEmbeddedSecrets applies the harness's own generic secret patterns
// (private-key PEM, bearer JWT) to the example and to every new doc. A match means a
// secret leaked into documentation.
func TestDocsPack_NoEmbeddedSecrets(t *testing.T) {
	for _, path := range docNewDocs() {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		content := string(b)
		for _, p := range secretPatterns {
			if p.re.MatchString(content) {
				t.Errorf("%s contains secret-like material classified %q", path, p.name)
			}
		}
	}
}

// TestDocsPack_RunbookHasAllSixteenSections asserts the runbook carries every
// required operator section heading.
func TestDocsPack_RunbookHasAllSixteenSections(t *testing.T) {
	b, err := os.ReadFile(docRunbook)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	sections := []string{
		"## Harness scope and current limitations (read before section 1)",
		"## 1. Prerequisites",
		"## 2. Artifact verification",
		"## 3. Environment inventory",
		"## 4. Startup configuration",
		"## 5. Startup validation",
		"## 6. Known-good request",
		"## 7. Tenant-isolation validation",
		"## 8. Authentication and hard-failure validation",
		"## 9. Durable evidence validation",
		"## 10. Monitoring supervision",
		"## 11. Emergency disable",
		"## 12. Restart / recovery",
		"## 13. Evidence collection",
		"## 14. Incident escalation",
		"## 15. Abort criteria",
		"## 16. Final cleanup",
	}
	for _, s := range sections {
		if !strings.Contains(content, s) {
			t.Errorf("runbook is missing required section heading %q", s)
		}
	}
}

// collapseWS normalizes all runs of whitespace (including newlines) to a single space
// so a stale-wording check is not defeated by a line wrap.
func collapseWS(s string) string { return strings.Join(strings.Fields(s), " ") }

// sectionBody returns the text of the runbook section starting at heading, up to the
// next "## " heading (or end of file). It lets the positive cleanup-contract checks be
// scoped to section 16 without matching a dev-mode mention elsewhere.
func sectionBody(content, heading string) string {
	i := strings.Index(content, heading)
	if i < 0 {
		return ""
	}
	rest := content[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestDocsPack_RunbookAuthoritativeCleanupContract pins the QUAL-6.1 Final cleanup
// truthfulness contract so the section can never drift back to the stale QUAL-6 claims.
// It asserts, on concepts rather than large exact prose blocks, that section 16 states
// the authoritative preservation model, and that the stale statements are absent from
// the whole runbook. Runtime behavior is already correct (fixture.go / authoritative.go
// and TestCleanup_PreservesOperatorOwnedTelemetry); this only keeps the doc honest.
func TestDocsPack_RunbookAuthoritativeCleanupContract(t *testing.T) {
	b, err := os.ReadFile(docRunbook)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)

	sec := sectionBody(content, "## 16. Final cleanup")
	if sec == "" {
		t.Fatal("runbook is missing the Final cleanup section body")
	}
	secWS := collapseWS(sec)
	secLower := strings.ToLower(secWS)

	// Positive: the authoritative preservation contract must be present (concept-level).
	for _, want := range []string{
		"authoritative kek is operator-owned",             // operator-owned KEK
		"does not generate a replacement kek",             // no harness KEK substitution in authoritative mode
		"cleanup must not delete the operator kek",        // preserved on cleanup
		"uses the same kek",                               // restart reuses the KEK
		"operator-owned and must survive harness cleanup", // telemetry preserved on cleanup
	} {
		if !strings.Contains(secLower, want) {
			t.Errorf("Final cleanup section is missing the authoritative-contract concept %q", want)
		}
	}
	// The operator telemetry data_dir and archive_dir must be named as preserved.
	for _, want := range []string{
		"environment.telemetry.data_dir",
		"environment.telemetry.kek_file",
		"environment.telemetry.archive_dir",
	} {
		if !strings.Contains(secWS, want) {
			t.Errorf("Final cleanup section must name the operator-owned telemetry field %q", want)
		}
	}
	// The reuse-across-restart concept must be stated.
	if !strings.Contains(secLower, "reused across") {
		t.Error("Final cleanup section must state that authoritative telemetry/KEK/archive are reused across the restart scenario")
	}
	// The dev-versus-authoritative distinction must be explicit in the section.
	for _, want := range []string{`mode: "authoritative"`, `mode: "dev"`} {
		if !strings.Contains(sec, want) {
			t.Errorf("Final cleanup section must distinguish %s", want)
		}
	}

	// Negative: the stale QUAL-6 claims must be absent from the WHOLE runbook.
	fullWS := collapseWS(content)
	fullLower := strings.ToLower(fullWS)
	for _, stale := range []string{
		"there is no operator kek to preserve",              // "no operator KEK exists"
		"harness-owned ephemeral state, not operator-owned", // authoritative telemetry mislabeled harness-owned
		"archive, and kek are created under the harness",    // telemetry always under the work root + deleted
	} {
		if strings.Contains(fullLower, stale) {
			t.Errorf("runbook still contains stale QUAL-6 cleanup wording: %q", stale)
		}
	}
}

// TestDocsPack_RunbookNoForbiddenInvocation asserts the runbook contains no call-form
// invocation of BeginWindow, a rollout transition, or a Catalog promotion. Prose that
// names these as prohibited (without a call paren) is expected and allowed.
func TestDocsPack_RunbookNoForbiddenInvocation(t *testing.T) {
	b, err := os.ReadFile(docRunbook)
	if err != nil {
		t.Fatal(err)
	}
	content := string(b)
	for _, callForm := range []string{
		"BeginWindow(",
		"SetRolloutMode(",
		"TransitionTo(",
		"Promote(",
		"MarkUsable(",
	} {
		if strings.Contains(content, callForm) {
			t.Errorf("runbook contains a forbidden call-form invocation %q", callForm)
		}
	}
}

// TestDocsPack_NoEmDash enforces the repository operator-doc convention that the new
// pack contains no em-dash.
func TestDocsPack_NoEmDash(t *testing.T) {
	for _, path := range docNewDocs() {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(b), string(rune(0x2014))) {
			t.Errorf("%s contains an em-dash (U+2014); operator docs must use none", path)
		}
	}
}
