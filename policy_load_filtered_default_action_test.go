package main

// policy_load_filtered_default_action_test.go — SEC-POLICYDROP-1.
//
// The defect: PolicyStore.Load applies a fail-closed gate
// (policyRulePersistable) that DROPS a rule it must not install. When every
// rule in the operator's policy file is dropped, the store ends up empty — and
// the startup default-action derivation keys off the rule count: empty rulebase
// + unset default_action => "allow" (passthrough), non-empty => "deny"
// (zero-trust). So a refusal meant to fail CLOSED on one scoped rule could flip
// the global default OPEN for every unmatched destination.
//
// The fix is to feed that derivation the CONFIGURED rulebase size
// (policyStore.ConfiguredRuleCount(): installed + refused), not the installed
// size. These tests pin both halves: the refusal accounting on the store, and
// the derivation's behaviour on top of it — including the negative control that
// a GENUINELY empty policy still allows, so the fix does not silently turn
// every zero-rule deployment into deny.
//
// Found by Codex review on PR #1651 against the SEC-POLICYACTION-1 load gate,
// confirmed against the startup ordering in main.go (initPolicy runs before
// initRewriteAndDefaultAction) before any code was changed. The hazard predates
// that gate — the SubjectMatch and invalid-auth refusals could empty a rulebase
// the same way — but the action gate made it reachable from a far more
// plausible file, so the tests below cover all three refusal reasons.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writePolicyFileForDropTest marshals rules to a temp policy file and returns
// its path. Raw JSON (not []PolicyRule) so a test can carry an action spelling
// no Go constant names — which is the whole point of the version-skew case.
func writePolicyFileForDropTest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	// Guard the fixture itself: a malformed body would make every assertion
	// below pass for the wrong reason (Load returns early on a parse error).
	if strings.HasPrefix(strings.TrimSpace(body), "[") {
		var probe []*PolicyRule
		if err := json.Unmarshal([]byte(body), &probe); err != nil {
			t.Fatalf("fixture is not valid policy JSON: %v", err)
		}
	}
	return path
}

// loadIntoFreshStore loads body into a store of its own. The global policyStore
// is deliberately untouched: these are store-level and derivation-level facts,
// and borrowing the global would couple them to whatever else is running.
func loadIntoFreshStore(t *testing.T, body string) *PolicyStore {
	t.Helper()
	ensureRewriteDefaultTestLogger(t)
	ps := &PolicyStore{}
	if err := ps.Load(writePolicyFileForDropTest(t, body)); err != nil {
		t.Fatalf("Load: unexpected error: %v", err)
	}
	return ps
}

// derivedDefaultAction runs the real startup derivation for an unset
// default_action at the given configured-rule count and reports what it chose.
func derivedDefaultAction(t *testing.T, rulesConfigured int) string {
	t.Helper()
	resetRewriteDefaultGlobals(t)
	ensureRewriteDefaultTestLogger(t)
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{}, rulesConfigured)
	return defaultPolicyAction()
}

// A rule the gate refuses because this build cannot dispatch its action. "Deny"
// is the spelling an operator reaches for (the real ones are Drop/Block_Page),
// and it is also the shape a binary downgrade produces.
const dropTestUnknownActionRules = `[
  {"name":"block-one","priority":10,"destFQDN":"blocked.example.com","action":"Deny"},
  {"name":"block-two","priority":20,"destFQDN":"also-blocked.example.com","action":"Deny"}
]`

// ── Positive: the defect case now fails closed ────────────────────────────────

func TestSECPOLICYDROP1_PolicyFilteredToEmptyStillDeniesByDefault(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestUnknownActionRules)

	if got := len(ps.List()); got != 0 {
		t.Fatalf("precondition: expected every rule refused, got %d installed", got)
	}
	if got := ps.DroppedOnLoad(); got != 2 {
		t.Fatalf("DroppedOnLoad: got %d, want 2", got)
	}
	if got := ps.ConfiguredRuleCount(); got != 2 {
		t.Fatalf("ConfiguredRuleCount: got %d, want 2 (0 installed + 2 refused)", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "deny" {
		t.Fatalf("a policy file that filtered down to nothing must still be a CONFIGURED policy: default action got %q, want %q", got, "deny")
	}
}

// TestSECPOLICYDROP1_PreFixCountWouldHaveSelectedAllow is the differential
// oracle: the same store, the two candidate inputs, opposite outcomes. If this
// ever reports the same action for both, the fix has stopped doing anything and
// the tests above would pass vacuously.
func TestSECPOLICYDROP1_PreFixCountWouldHaveSelectedAllow(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestUnknownActionRules)

	preFix := derivedDefaultAction(t, len(ps.List())) // what the shim used to pass
	postFix := derivedDefaultAction(t, ps.ConfiguredRuleCount())

	if preFix != "allow" {
		t.Fatalf("pre-fix input should reproduce the fail-open default: got %q, want %q", preFix, "allow")
	}
	if postFix != "deny" {
		t.Fatalf("post-fix input must fail closed: got %q, want %q", postFix, "deny")
	}
}

// Every refusal reason can empty a rulebase, not just the action gate the
// review was looking at. Each subtest asserts the file is fully refused AND the
// derivation still denies.
func TestSECPOLICYDROP1_EveryRefusalReasonKeepsTheDenyDefault(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown action",
			body: dropTestUnknownActionRules,
		},
		{
			name: "subjectMatch on an access rule",
			body: `[{"name":"scoped","priority":10,"destFQDN":"blocked.example.com","action":"Drop","subjectMatch":{}}]`,
		},
		{
			name: "invalid auth rule",
			body: `[{"name":"bad-auth","priority":10,"ruleType":"auth"}]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := loadIntoFreshStore(t, tc.body)
			if got := len(ps.List()); got != 0 {
				t.Fatalf("precondition: expected a fully refused file, got %d installed", got)
			}
			if got := ps.DroppedOnLoad(); got == 0 {
				t.Fatalf("DroppedOnLoad: got 0, want the refusals to be counted")
			}
			if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "deny" {
				t.Fatalf("default action: got %q, want %q", got, "deny")
			}
		})
	}
}

// ── Negative controls: nothing else changes direction ─────────────────────────

// A genuinely empty policy must keep allowing. This is the control that stops
// the fix from becoming "deny everywhere": the passthrough default for a
// deployment that configured no rules at all is documented behaviour, not a bug.
func TestSECPOLICYDROP1_GenuinelyEmptyPolicyStillAllows(t *testing.T) {
	ps := loadIntoFreshStore(t, `[]`)

	if got := ps.DroppedOnLoad(); got != 0 {
		t.Fatalf("DroppedOnLoad: got %d, want 0 — nothing was refused", got)
	}
	if got := ps.ConfiguredRuleCount(); got != 0 {
		t.Fatalf("ConfiguredRuleCount: got %d, want 0", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "allow" {
		t.Fatalf("an empty policy must still default to passthrough: got %q, want %q", got, "allow")
	}
}

// A configured path whose file does not exist yet is adopted, not refused: no
// rules, no refusals, and the passthrough default is unchanged.
func TestSECPOLICYDROP1_MissingPolicyFileStillAllows(t *testing.T) {
	ensureRewriteDefaultTestLogger(t)
	ps := &PolicyStore{}
	if err := ps.Load(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("Load of a missing file should adopt the path: %v", err)
	}
	if got := ps.ConfiguredRuleCount(); got != 0 {
		t.Fatalf("ConfiguredRuleCount: got %d, want 0", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "allow" {
		t.Fatalf("default action: got %q, want %q", got, "allow")
	}
}

// ── Boundaries ────────────────────────────────────────────────────────────────

// One survivor is enough for the pre-fix count to have said "deny" already, so
// this case must be byte-identical in outcome before and after the fix.
func TestSECPOLICYDROP1_PartiallyRefusedFileIsUnchanged(t *testing.T) {
	ps := loadIntoFreshStore(t, `[
  {"name":"survivor","priority":10,"destFQDN":"ok.example.com","action":"Drop"},
  {"name":"refused","priority":20,"destFQDN":"blocked.example.com","action":"Deny"}
]`)

	if got := len(ps.List()); got != 1 {
		t.Fatalf("installed: got %d, want 1", got)
	}
	if got := ps.DroppedOnLoad(); got != 1 {
		t.Fatalf("DroppedOnLoad: got %d, want 1", got)
	}
	if got := ps.ConfiguredRuleCount(); got != 2 {
		t.Fatalf("ConfiguredRuleCount: got %d, want 2", got)
	}
	if pre, post := derivedDefaultAction(t, len(ps.List())), derivedDefaultAction(t, ps.ConfiguredRuleCount()); pre != "deny" || post != "deny" {
		t.Fatalf("a partially refused file must deny both ways: pre=%q post=%q", pre, post)
	}
}

// An explicit default_action is the operator's decision and still wins — in
// BOTH directions. The errata contract ("explicit configuration wins") is not
// softened by the refusal accounting, which only feeds the unset case.
func TestSECPOLICYDROP1_ExplicitDefaultActionStillWins(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestUnknownActionRules)

	for _, explicit := range []string{"allow", "deny"} {
		t.Run(explicit, func(t *testing.T) {
			resetRewriteDefaultGlobals(t)
			ensureRewriteDefaultTestLogger(t)
			loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{DefaultAction: explicit}, ps.ConfiguredRuleCount())
			if got := defaultPolicyAction(); got != explicit {
				t.Fatalf("explicit default_action %q must win: got %q", explicit, got)
			}
		})
	}
}

// The refusal count describes the file as last loaded. A clean reload must
// clear it, or one bad file would pin the store at "configured" forever and the
// count would drift further from the truth on every reload.
func TestSECPOLICYDROP1_CleanReloadClearsTheRefusalCount(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestUnknownActionRules)
	if got := ps.DroppedOnLoad(); got != 2 {
		t.Fatalf("precondition: DroppedOnLoad got %d, want 2", got)
	}

	if err := ps.Load(writePolicyFileForDropTest(t, `[]`)); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := ps.DroppedOnLoad(); got != 0 {
		t.Fatalf("a clean reload must clear the count: DroppedOnLoad got %d, want 0", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "allow" {
		t.Fatalf("after the operator emptied the file: got %q, want %q", got, "allow")
	}
}

// ── Malformed input ───────────────────────────────────────────────────────────

// A file Load never managed to parse must leave BOTH the rules and the refusal
// count exactly as they were: reporting refusals from a load that did not
// happen would be the same confusion in the other direction.
func TestSECPOLICYDROP1_MalformedFileLeavesTheCountUntouched(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestUnknownActionRules)
	before := ps.ConfiguredRuleCount()

	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte(`{"not":"an array"`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := ps.Load(path); err == nil {
		t.Fatalf("Load of malformed JSON should have failed")
	}
	if got := ps.ConfiguredRuleCount(); got != before {
		t.Fatalf("ConfiguredRuleCount after a failed load: got %d, want %d (unchanged)", got, before)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "deny" {
		t.Fatalf("default action: got %q, want %q", got, "deny")
	}
}

// ── Concurrency ───────────────────────────────────────────────────────────────

// ConfiguredRuleCount reads an atomic and a mutex-guarded slice. Under -race
// this pins that it is safe to call while the store is being reloaded and
// listed, and that it never reports a count below the refusals already banked.
func TestSECPOLICYDROP1_ConfiguredRuleCountIsRaceFree(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestUnknownActionRules)
	reload := writePolicyFileForDropTest(t, dropTestUnknownActionRules)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				if got := ps.ConfiguredRuleCount(); got < 0 {
					t.Errorf("ConfiguredRuleCount: got %d", got)
				}
			case 1:
				_ = ps.List()
			default:
				if err := ps.Load(reload); err != nil {
					t.Errorf("concurrent Load: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	if got := ps.ConfiguredRuleCount(); got != 2 {
		t.Fatalf("ConfiguredRuleCount after the storm: got %d, want 2", got)
	}
}

// ── Wall: the shim must keep passing the configured count ─────────────────────

// TestSECPOLICYDROP1_ShimPassesTheConfiguredCount is a structural wall. The
// defect was a single wrong ARGUMENT at one call site, which no behavioural test
// of the loader can see — loadRewriteAndDefaultAction is correct either way, it
// just answers the question it was asked. This asserts the question.
func TestSECPOLICYDROP1_ShimPassesTheConfiguredCount(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	var body string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "initRewriteAndDefaultAction" || fn.Body == nil {
			return true
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		src, readErr := os.ReadFile("main.go")
		if readErr != nil {
			t.Fatalf("read main.go: %v", readErr)
		}
		body = string(src[start:end])
		return false
	})

	if body == "" {
		t.Fatalf("initRewriteAndDefaultAction not found in main.go — if it was renamed or moved, move this wall with it")
	}
	if !strings.Contains(body, "policyStore.ConfiguredRuleCount()") {
		t.Errorf("initRewriteAndDefaultAction must pass policyStore.ConfiguredRuleCount() so refused rules still count as a configured policy (SEC-POLICYDROP-1); body:\n%s", body)
	}
	if strings.Contains(body, "len(policyStore.List())") {
		t.Errorf("initRewriteAndDefaultAction must NOT derive the default action from the INSTALLED rule count: a fully refused policy file would select passthrough Allow (SEC-POLICYDROP-1); body:\n%s", body)
	}
}
