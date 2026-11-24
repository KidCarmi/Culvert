package main

// policy_load_filtered_default_action_test.go — SEC-POLICYDROP-1, as revised by
// POL-005.
//
// History: PolicyStore.Load used to apply a gate (policyRulePersistable) that
// DROPPED a rule it must not install and installed the rest. When every rule in
// the file was dropped the store ended up empty, and the startup default-action
// derivation keys off the rule count (empty + unset default_action => "allow",
// non-empty => "deny"), so a refusal meant to fail closed could flip the global
// default open. The first fix counted the dropped rules as configured.
//
// That still left the drop itself, which is fail-open for any rule that
// restricts: the rule is gone and its traffic falls through. Load now refuses
// the WHOLE file instead (POL-005). A file holding a rule this build cannot
// enforce installs nothing, returns a typed error, and leaves whatever the store
// held before exactly as it was; at startup that error is fatal. So "a file
// filtered down to nothing" can no longer happen, and ConfiguredRuleCount is
// simply the installed count.
//
// These tests pin the new guarantee for the same scenarios the old ones
// covered, and keep the negative controls: a genuinely empty policy and a
// missing file still allow, and an explicit default_action still wins.

import (
	"encoding/json"
	"errors"
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

// Two access rules carrying a subjectMatch: Stage 2 would not enforce their
// source scope, so this build cannot enforce them as written.
const dropTestInvalidScopeRules = `[
  {"name":"block-one","priority":10,"destFQDN":"blocked.example.com","action":"Allow","subjectMatch":{}},
  {"name":"block-two","priority":20,"destFQDN":"also-blocked.example.com","action":"Allow","subjectMatch":{}}
]`

// dropTestGoodRules is a loadable policy: the state a refused reload must leave.
const dropTestGoodRules = `[
  {"name":"keep-one","priority":10,"destFQDN":"blocked.example.com","action":"Drop"},
  {"name":"keep-two","priority":20,"destFQDN":"ok.example.com","action":"Allow"}
]`

// loadRefused loads body into ps and returns the typed refusal, failing the
// test if Load accepted the file or failed for another reason.
func loadRefused(t *testing.T, ps *PolicyStore, body string) *unenforceableRuleError {
	t.Helper()
	ensureRewriteDefaultTestLogger(t)
	err := ps.Load(writePolicyFileForDropTest(t, body))
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Fatalf("Load = %v, want an *unenforceableRuleError (the whole file refused)", err)
	}
	return ue
}

func installedNames(ps *PolicyStore) string {
	rules := ps.List()
	names := make([]string, 0, len(rules))
	for i := range rules {
		names = append(names, rules[i].Name)
	}
	return strings.Join(names, ",")
}

// ── Positive: the defect case is refused, not filtered ────────────────────────

// The original defect file. It used to load "successfully" with nothing
// installed; it is now refused, so there is no empty store for the default
// derivation to misread. initPolicy turns this error into a fatal exit.
func TestSECPOLICYDROP1_FileOfUnenforceableRulesIsRefusedNotFilteredToEmpty(t *testing.T) {
	ps := &PolicyStore{}
	ue := loadRefused(t, ps, dropTestInvalidScopeRules)

	if ue.Name != "block-one" || ue.Count != 2 {
		t.Errorf("refusal names %q x%d, want block-one x2 (first offender, every offender counted)", ue.Name, ue.Count)
	}
	if got := len(ps.List()); got != 0 {
		t.Fatalf("a refused file installed %d rule(s), want 0", got)
	}
	if ps.path != "" {
		t.Errorf("a refused file's path was adopted: %q", ps.path)
	}
	if got := ps.DroppedOnLoad(); got != 0 {
		t.Errorf("DroppedOnLoad = %d, want 0: Load no longer drops", got)
	}
}

// TestSECPOLICYDROP1_PreFixOutcomeWouldHaveSelectedAllow is the differential
// oracle, restated. Before any fix this file loaded with zero rules installed
// and no error, and a zero count derives "allow". The property that prevents it
// now is the ERROR: if Load ever returns nil for this file again with nothing
// installed, the derivation below is what startup would compute.
func TestSECPOLICYDROP1_PreFixOutcomeWouldHaveSelectedAllow(t *testing.T) {
	ps := &PolicyStore{}
	loadRefused(t, ps, dropTestInvalidScopeRules)

	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "allow" {
		t.Fatalf("control: a zero count derives %q, want allow — this is why the refusal must be an error and not an empty load", got)
	}
}

// Each refusal reason, alone and mixed with valid rules, refuses the whole
// file: nothing is installed, valid neighbours included.
func TestSECPOLICYDROP1_EveryRefusalReasonRefusesTheWholeFile(t *testing.T) {
	const valid = `{"name":"valid","priority":90,"destFQDN":"ok.example.com","action":"Drop"}`
	cases := []struct {
		name, rule, wantName, wantReason string
	}{
		{"unsupported access scope", `{"name":"scoped","priority":10,"destFQDN":"blocked.example.com","action":"Allow","subjectMatch":{}}`, "scoped", "subjectMatch"},
		{"auth spec on an access rule", `{"name":"authspec","priority":10,"destFQDN":"blocked.example.com","action":"Drop","auth":{}}`, "authspec", "auth spec"},
		{"invalid auth rule", `{"name":"bad-auth","priority":10,"ruleType":"auth"}`, "bad-auth", "invalid auth rule"},
		{"null entry", `null`, "", "nil rule"},
	}
	for _, tc := range cases {
		for label, body := range map[string]string{"alone": "[" + tc.rule + "]", "beside a valid rule": "[" + valid + "," + tc.rule + "]"} {
			t.Run(tc.name+"/"+label, func(t *testing.T) {
				ps := &PolicyStore{}
				ue := loadRefused(t, ps, body)
				if ue.Name != tc.wantName || !strings.Contains(ue.Reason, tc.wantReason) {
					t.Errorf("refusal = %q / %q, want rule %q and a %q reason", ue.Name, ue.Reason, tc.wantName, tc.wantReason)
				}
				if got := len(ps.List()); got != 0 {
					t.Fatalf("installed %d rule(s) from a refused file, want 0 (no partial apply)", got)
				}
			})
		}
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

// ── Boundaries ─────────────────────────────────────────────────�

// A file with one valid and one unenforceable rule used to install the valid
// one. It is refused whole: installing "survivor" alone would be a policy the
// operator did not write.
func TestSECPOLICYDROP1_PartiallyUnenforceableFileIsRefusedWhole(t *testing.T) {
	ps := &PolicyStore{}
	ue := loadRefused(t, ps, `[
  {"name":"survivor","priority":10,"destFQDN":"ok.example.com","action":"Drop"},
  {"name":"refused","priority":20,"destFQDN":"blocked.example.com","action":"Allow","subjectMatch":{}}
]`)
	if ue.Name != "refused" || ue.Count != 1 {
		t.Errorf("refusal names %q x%d, want refused x1", ue.Name, ue.Count)
	}
	if got := installedNames(ps); got != "" {
		t.Fatalf("installed [%s], want nothing", got)
	}
}

// A refused RELOAD leaves the previously loaded policy exactly as it was:
// rules, path, and the count the default derivation reads.
func TestSECPOLICYDROP1_RefusedReloadKeepsTheLoadedPolicy(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestGoodRules)
	path := ps.path
	loadRefused(t, ps, dropTestInvalidScopeRules)

	if got := installedNames(ps); got != "keep-one,keep-two" {
		t.Fatalf("after a refused reload the store holds [%s], want [keep-one,keep-two]", got)
	}
	if ps.path != path {
		t.Errorf("a refused reload adopted path %q, want %q", ps.path, path)
	}
	if got := ps.ConfiguredRuleCount(); got != 2 {
		t.Errorf("ConfiguredRuleCount after a refused reload = %d, want 2", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "deny" {
		t.Errorf("default action derived after a refused reload = %q, want deny", got)
	}
}

// An explicit default_action is the operator's decision and still wins — in
// BOTH directions, whatever the store holds after a refused reload.
func TestSECPOLICYDROP1_ExplicitDefaultActionStillWins(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestGoodRules)
	loadRefused(t, ps, dropTestInvalidScopeRules)

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

// A refusal is not sticky. Once the operator corrects the file, the reload
// succeeds and the store describes the new file.
func TestSECPOLICYDROP1_CleanReloadAfterARefusalSucceeds(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestGoodRules)
	loadRefused(t, ps, dropTestInvalidScopeRules)

	if err := ps.Load(writePolicyFileForDropTest(t, `[]`)); err != nil {
		t.Fatalf("reload of a corrected file: %v", err)
	}
	if got := ps.ConfiguredRuleCount(); got != 0 {
		t.Fatalf("ConfiguredRuleCount after the operator emptied the file = %d, want 0", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "allow" {
		t.Fatalf("after the operator emptied the file: got %q, want %q", got, "allow")
	}
}

// Adopting a path with no file yet is a successful load that KEEPS the rules in
// memory, also right after a refusal: the count stays the installed count.
func TestSECPOLICYDROP1_AdoptingAMissingFileAfterARefusalKeepsTheRules(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestGoodRules)
	loadRefused(t, ps, dropTestInvalidScopeRules)

	absent := filepath.Join(t.TempDir(), "absent.json")
	if err := ps.Load(absent); err != nil {
		t.Fatalf("Load of a missing file should adopt the path: %v", err)
	}
	if ps.path != absent {
		t.Errorf("path = %q, want the adopted %q", ps.path, absent)
	}
	if got := ps.ConfiguredRuleCount(); got != 2 {
		t.Fatalf("ConfiguredRuleCount = %d, want 2 (adoption keeps the in-memory rules)", got)
	}
}

// ── Malformed input ────────────────────────────────────────────────

// A file Load never managed to parse leaves the rules and the count exactly as
// they were, like a refused one.
func TestSECPOLICYDROP1_MalformedFileLeavesTheStateUntouched(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestGoodRules)
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
	if got := installedNames(ps); got != "keep-one,keep-two" {
		t.Fatalf("rules after a failed load: [%s], want [keep-one,keep-two]", got)
	}
	if got := derivedDefaultAction(t, ps.ConfiguredRuleCount()); got != "deny" {
		t.Fatalf("default action: got %q, want %q", got, "deny")
	}
}

// ── Concurrency ─────────────────────────────────────────────────�

// Under -race: ConfiguredRuleCount is safe to call while the store is reloaded
// (accepted and refused files interleaved) and listed, and a refused load never
// shows through as a changed count.
func TestSECPOLICYDROP1_ConfiguredRuleCountIsRaceFree(t *testing.T) {
	ps := loadIntoFreshStore(t, dropTestGoodRules)
	good := writePolicyFileForDropTest(t, dropTestGoodRules)
	bad := writePolicyFileForDropTest(t, dropTestInvalidScopeRules)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 4 {
			case 0:
				if got := ps.ConfiguredRuleCount(); got != 2 {
					t.Errorf("ConfiguredRuleCount mid-storm: got %d, want 2", got)
				}
			case 1:
				_ = ps.List()
			case 2:
				if err := ps.Load(good); err != nil {
					t.Errorf("concurrent Load of the good file: %v", err)
				}
			default:
				if err := ps.Load(bad); err == nil {
					t.Errorf("concurrent Load of the refused file returned nil")
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
	// Anchored to pkgSourceDir(), not the CWD: a concurrent os.Chdir in another
	// test would otherwise flake this (static_read_wall_test.go enforces it).
	// Reading once and handing the bytes to the parser also keeps the offsets
	// below in step with the source they index.
	path := filepath.Join(pkgSourceDir(), "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// The ARGUMENT is the assertion, not a substring of the body. A body that
	// merely mentions ConfiguredRuleCount() while passing 0 to the loader would
	// satisfy a `strings.Contains` check and reintroduce the whole defect, and
	// no behavioural test of the loader can see it — the behavioural tests call
	// loadRewriteAndDefaultAction directly. (CodeRabbit, PR #1651: correct, and
	// on a gate whose only job is precision.)
	var (
		body  string
		found bool
		arg   string
	)
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "initRewriteAndDefaultAction" || fn.Body == nil {
			return true
		}
		body = string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			call, isCall := inner.(*ast.CallExpr)
			if !isCall {
				return true
			}
			name, isIdent := call.Fun.(*ast.Ident)
			if !isIdent || name.Name != "loadRewriteAndDefaultAction" {
				return true
			}
			found = true
			if len(call.Args) != 2 {
				t.Errorf("loadRewriteAndDefaultAction called with %d argument(s), want 2 — move this wall with the signature", len(call.Args))
				return false
			}
			start := fset.Position(call.Args[1].Pos()).Offset
			end := fset.Position(call.Args[1].End()).Offset
			arg = string(src[start:end])
			return false
		})
		return false
	})

	if body == "" {
		t.Fatalf("initRewriteAndDefaultAction not found in main.go — if it was renamed or moved, move this wall with it")
	}
	if !found {
		t.Fatalf("initRewriteAndDefaultAction no longer calls loadRewriteAndDefaultAction directly; this wall can no longer see the argument it exists to check:\n%s", body)
	}
	if arg != "policyStore.ConfiguredRuleCount()" {
		t.Errorf("the rule count passed to loadRewriteAndDefaultAction is %q, want %q — refused rules must still count as a configured policy, or a fully refused policy file selects the passthrough Allow default (SEC-POLICYDROP-1)",
			arg, "policyStore.ConfiguredRuleCount()")
	}
	// Kept alongside the argument check: it names the specific wrong answer, so
	// a regression reports the defect rather than just a mismatch.
	if strings.Contains(body, "len(policyStore.List())") {
		t.Errorf("initRewriteAndDefaultAction must NOT derive the default action from the INSTALLED rule count: a fully refused policy file would select passthrough Allow (SEC-POLICYDROP-1); body:\n%s", body)
	}
}
