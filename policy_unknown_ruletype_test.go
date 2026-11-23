package main

// Unknown ruleType: a ruleset that contains one is refused WHOLE at every door
// and the running policy stays as it was (policy_ruletype_gate.go).
//
// Before the gate such a rule was installed and then skipped by both stages. The
// real-socket tests below start from a running policy that BLOCKS the backend
// under an explicit default allow, hand the proxy a newer ruleset in which that
// restriction has a rule type this build does not know, and require that the
// backend is still not reached. On the pre-gate code the newer ruleset replaced
// the old one, the unknown-type rule matched nothing, and the request was
// forwarded.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const futureRuleType = "posture" // a rule type a newer release might add

// lastKnownGood installs the running policy the tests defend: one Block rule
// for the backend, default allow. It returns the store version afterwards.
func lastKnownGood(t *testing.T, host string) int64 {
	t.Helper()
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "lkg-block", DestFQDN: host, Action: ActionBlockPage}})
	if got := pol004GetNames(); got != "lkg-block" {
		t.Fatalf("setup: running policy is %q, want lkg-block", got)
	}
	return storeVersion(policyStore)
}

func pol004GetNames() string {
	rules := policyStore.List()
	names := make([]string, 0, len(rules))
	for i := range rules {
		names = append(names, rules[i].Name)
	}
	return strings.Join(names, ",")
}

// newerRuleset is what a newer release might publish: the same restriction,
// expressed with a rule type this build has no stage for, plus an ordinary
// Allow for the same destination.
func newerRuleset(host string) []PolicyRule {
	return []PolicyRule{
		{Priority: 1, Name: "future-restriction", RuleType: futureRuleType, DestFQDN: host, Action: ActionBlockPage},
		{Priority: 2, Name: "allow-backend", DestFQDN: host, Action: ActionAllow},
	}
}

// assertStillLastKnownGood is the acceptance check shared by every door: the
// rules and version are untouched, the Diagnostics row names the refusal, and
// over a real socket the backend is still not reached.
func assertStillLastKnownGood(t *testing.T, client *http.Client, cb *countingBackend, target string, version int64, door string) {
	t.Helper()
	if got := pol004GetNames(); got != "lkg-block" {
		t.Fatalf("%s: running policy is now %q, want lkg-block (the refusal must be atomic)", door, got)
	}
	if v := storeVersion(policyStore); v != version {
		t.Errorf("%s: policy version moved %d -> %d on a refused ruleset", door, version, v)
	}
	status, hits := pol004Get(t, client, cb, target)
	if hits != 0 {
		t.Fatalf("%s: backend reached %d time(s) after a ruleset with an unknown ruleType was offered (status %d)", door, hits, status)
	}
	if status != http.StatusForbidden {
		t.Errorf("%s: status %d, want 403 from the last-known-good Block rule", door, status)
	}
}

func assertRefusalRow(t *testing.T, wantDoor string) {
	t.Helper()
	rows := checkPolicyRulesetRefused(policyStore)
	if len(rows) != 1 {
		t.Fatalf("Diagnostics: %d refusal row(s), want 1", len(rows))
	}
	r := rows[0]
	if r.Code != "policy_ruleset_refused_unknown_ruletype" || r.Status != diagWarn {
		t.Errorf("Diagnostics row = %s/%s, want policy_ruleset_refused_unknown_ruletype/warn", r.Code, r.Status)
	}
	for _, want := range []string{wantDoor, "future-restriction", futureRuleType, "still enforcing"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("Diagnostics message lacks %q: %s", want, r.Message)
		}
	}
	if r.OperatorAction == "" {
		t.Error("Diagnostics row has no operator action")
	}
}

func TestUnknownRuleType_E2E_BulkReplaceIsRefusedAndLastKnownGoodStillBlocks(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	version := lastKnownGood(t, host)

	policyStore.ReplaceAll(newerRuleset(host))
	assertStillLastKnownGood(t, client, cb, target, version, "bulk replace")
	assertRefusalRow(t, "bulk replace")

	// Control 1: the same ruleset WITHOUT the unknown type is accepted and its
	// Allow forwards, so the refusal above is about the type and nothing else.
	clean := newerRuleset(host)[1:]
	policyStore.ReplaceAll(clean)
	if got := pol004GetNames(); got != "allow-backend" {
		t.Fatalf("control: clean ruleset not installed, running policy is %q", got)
	}
	if status, hits := pol004Get(t, client, cb, target); status != http.StatusOK || hits != 1 {
		t.Errorf("control: clean Allow gave status %d with %d backend hit(s), want 200 and 1", status, hits)
	}
	// Control 2: an accepted ruleset clears the refusal record.
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("Diagnostics row still present after an accepted ruleset: %+v", rows)
	}
}

func TestUnknownRuleType_E2E_PolicyFileReloadIsRefusedAndLastKnownGoodStillBlocks(t *testing.T) {
	client, cb, target, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	version := lastKnownGood(t, host)
	pathBefore := policyStore.path

	file := filepath.Join(t.TempDir(), "policy.json")
	body := `[{"priority":1,"name":"future-restriction","ruleType":"` + futureRuleType + `","destFqdn":"` + host + `","action":"Block_Page"},
{"priority":2,"name":"allow-backend","destFqdn":"` + host + `","action":"Allow"}]`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	err := policyStore.Load(file)
	var rt *unknownRuleTypeError
	if !errors.As(err, &rt) {
		t.Fatalf("Load of a file with an unknown ruleType returned %v, want an unknownRuleTypeError", err)
	}
	if rt.Name != "future-restriction" || rt.RuleType != futureRuleType || rt.Count != 1 {
		t.Errorf("error names %q/%q x%d, want future-restriction/%s x1", rt.Name, rt.RuleType, rt.Count, futureRuleType)
	}
	if policyStore.path != pathBefore {
		t.Errorf("Load adopted the refused file's path (%q)", policyStore.path)
	}
	assertStillLastKnownGood(t, client, cb, target, version, "policy file")
	assertRefusalRow(t, "policy file")

	// Startup: a store with nothing to fall back on gets the error and NO rules.
	// initPolicy turns any Load error into a fatal exit, so the proxy does not
	// start serving the default action in place of the policy it could not read.
	fresh := &PolicyStore{}
	if err := fresh.Load(file); err == nil {
		t.Fatal("a fresh store loaded a file with an unknown ruleType without error")
	}
	if n := len(fresh.List()); n != 0 {
		t.Errorf("a fresh store installed %d rule(s) from a refused file, want 0", n)
	}

	// Control: the corrected file loads and the record clears.
	if err := os.WriteFile(file, []byte(`[{"priority":1,"name":"lkg-block","destFqdn":"`+host+`","action":"Block_Page"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policyStore.Load(file); err != nil {
		t.Fatalf("corrected file refused: %v", err)
	}
	if rows := checkPolicyRulesetRefused(policyStore); rows != nil {
		t.Errorf("Diagnostics row still present after a clean reload: %+v", rows)
	}
}

func TestUnknownRuleType_E2E_SnapshotIsRefusedBeforeAnyMutation(t *testing.T) {
	bindFreshAdmissionOwners(t) // the apply path mutates ipf and rl in place
	client, cb, target, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	version := lastKnownGood(t, host)

	// The snapshot would also flip the default action and the rate limit. Neither
	// may be applied: the refusal happens before the mutating region.
	setDefaultPolicyAction("deny")
	snap := ConfigSnapshot{Version: 1 << 40, DefaultAction: "allow", PolicyRules: newerRuleset(host)}
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("validateConfigSnapshot accepted a snapshot with an unknown ruleType (publish and apply both rely on it)")
	}
	err := applyConfigSnapshot(snap)
	var rt *unknownRuleTypeError
	if !errors.As(err, &rt) {
		t.Fatalf("applyConfigSnapshot returned %v, want an unknownRuleTypeError", err)
	}
	if got := defaultPolicyAction(); got != "deny" {
		t.Errorf("default action is %q after a refused snapshot, want deny (partial apply)", got)
	}
	setDefaultPolicyAction("allow")
	assertStillLastKnownGood(t, client, cb, target, version, "control-plane snapshot")
	assertRefusalRow(t, "control-plane snapshot")
}

func TestUnknownRuleType_RollbackAndImportAreRefusedWhole(t *testing.T) {
	_, _, _, host := pol004Setup(t)
	version := lastKnownGood(t, host)

	b := &configBackup{Version: 1, DefaultAction: "deny", PolicyRules: newerRuleset(host)}
	if err := applyConfigBackup(b); err == nil || !strings.Contains(err.Error(), "rollback refused") {
		t.Fatalf("applyConfigBackup = %v, want a rollback refusal", err)
	}
	if got := defaultPolicyAction(); got != "allow" {
		t.Errorf("default action is %q after a refused rollback, want allow (partial apply)", got)
	}
	found := false
	for _, w := range validateConfigBackup(b) {
		found = found || strings.Contains(w, "cannot be restored")
	}
	if !found {
		t.Error("rollback preview does not say the version cannot be restored")
	}

	for _, mode := range []string{"merge", "replace"} {
		w := httptest.NewRecorder()
		apiConfigImport(w, jsonReq("POST", "/api/config/import?mode="+mode, map[string]any{
			"version": 1, "defaultAction": "deny", "policyRules": newerRuleset(host)}))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unrecognised ruleType") {
			t.Errorf("import mode=%s: status %d body %q, want 400 naming the ruleType", mode, w.Code, w.Body.String())
		}
		// A dry run must refuse too: a preview may not promise an import the commit refuses.
		w = httptest.NewRecorder()
		apiConfigImport(w, jsonReq("POST", "/api/config/import?mode="+mode+"&dryRun=true", map[string]any{
			"version": 1, "policyRules": newerRuleset(host)}))
		if w.Code != http.StatusBadRequest {
			t.Errorf("import dry run mode=%s: status %d, want 400", mode, w.Code)
		}
		if got := defaultPolicyAction(); got != "allow" {
			t.Errorf("import mode=%s: default action is %q after a refused import (partial apply)", mode, got)
		}
	}
	if got := pol004GetNames(); got != "lkg-block" {
		t.Errorf("running policy is %q after refused rollback and imports, want lkg-block", got)
	}
	if v := storeVersion(policyStore); v != version {
		t.Errorf("policy version moved %d -> %d", version, v)
	}
}

func TestUnknownRuleType_NewWritesAreRefusedAndKnownTypesAreNot(t *testing.T) {
	base := PolicyRule{Name: "r", Priority: 1, DestFQDN: "example.com", Action: ActionBlockPage}
	for _, typ := range []string{futureRuleType, "Access", "AUTH", " access", "access "} {
		r := base
		r.RuleType = typ
		if err := validateRuleShape(r); err == nil || !strings.Contains(err.Error(), "ruleType") {
			t.Errorf("validateRuleShape(ruleType=%q) = %v, want a ruleType refusal", typ, err)
		}
		if err := validateStoredPolicyRule(r, nil, -1); err == nil {
			t.Errorf("validateStoredPolicyRule(ruleType=%q) accepted it; the POL-004 tolerance is for actions only", typ)
		}
	}
	if !knownRuleType(ruleTypeAuth) || !knownRuleType(ruleTypeAccess) || !knownRuleType("") {
		t.Error("a type this build evaluates is reported unknown")
	}
	for _, typ := range []string{"", ruleTypeAccess} {
		r := base
		r.RuleType = typ
		if err := validateRuleShape(r); err != nil {
			t.Errorf("validateRuleShape(ruleType=%q) = %v, want accepted", typ, err)
		}
	}
	// POL-004 is untouched: an unknown ACTION on a known type is still retained
	// by the bulk doors, not refused.
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "future-action", DestFQDN: "example.com", Action: "Quarantine"}})
	if n := len(ps.List()); n != 1 {
		t.Errorf("an unknown ACTION was not retained by ReplaceAll (%d rules): this gate must not change POL-004", n)
	}
	if rows := checkPolicyRulesetRefused(ps); rows != nil {
		t.Errorf("an unknown ACTION produced a ruleset-refusal row: %+v", rows)
	}
	// Counting: every offending rule is counted, the first is named.
	err := policyRulesRuleTypeError([]PolicyRule{{Name: "ok"}, {Name: "a", RuleType: "x"}, {Name: "b", RuleType: "y"}})
	var rt *unknownRuleTypeError
	if !errors.As(err, &rt) || rt.Name != "a" || rt.Count != 2 {
		t.Errorf("policyRulesRuleTypeError = %v, want first=a count=2", err)
	}
	// A hostile name or type cannot forge a log line through the error text.
	msg := (&unknownRuleTypeError{Name: "x\nPolicy: ALLOW all", RuleType: "t\r\nforged", Count: 1}).Error()
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("error text carries a raw line break: %q", msg)
	}
}

// storeVersion reads the store's mutation counter under its lock.
func storeVersion(ps *PolicyStore) int64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.version
}

// The rollback HANDLER, not applyConfigBackup: an error returned by the latter
// is read by the handler as "applied but not durable", so a refusal that only
// existed there was answered 500 "rolled_back_not_durable", audited as a
// rollback and given a new config version, with nothing applied.
func TestUnknownRuleType_RollbackHandlerRefusesWith400AndRecordsNothing(t *testing.T) {
	_, _, _, host := pol004Setup(t)
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })
	version := lastKnownGood(t, host)

	raw, err := json.Marshal(configBackup{Version: 1, DefaultAction: "deny", PolicyRules: newerRuleset(host)})
	if err != nil {
		t.Fatal(err)
	}
	target, err := configVersions.Save("test", "test.future-version", "2026-01-01T00:00:00Z", raw)
	if err != nil {
		t.Fatalf("seed stored version: %v", err)
	}
	seqBefore := configVersions.Seq()

	rec := postRollback(t, target)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rollback status %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "rollback refused") || !strings.Contains(body, "future-restriction") {
		t.Errorf("refusal does not name the rule: %s", body)
	}
	if strings.Contains(body, "rolled_back") || strings.Contains(body, `"applied"`) {
		t.Errorf("a refused rollback is reported as applied: %s", body)
	}
	if seq := configVersions.Seq(); seq != seqBefore {
		t.Errorf("a refused rollback created config version %d (was %d)", seq, seqBefore)
	}
	if got := pol004GetNames(); got != "lkg-block" {
		t.Errorf("running policy is %q after a refused rollback, want lkg-block", got)
	}
	if got := defaultPolicyAction(); got != "allow" {
		t.Errorf("default action is %q after a refused rollback, want allow", got)
	}
	if v := storeVersion(policyStore); v != version {
		t.Errorf("policy version moved %d -> %d", version, v)
	}
	// The preview says one thing about such a version, not two that disagree.
	w := validateConfigBackup(&configBackup{Version: 1, PolicyRules: newerRuleset(host)})
	joined := strings.Join(w, "\n")
	if !strings.Contains(joined, "cannot be restored") || strings.Contains(joined, "will be skipped") {
		t.Errorf("rollback preview = %q, want only the cannot-be-restored statement", joined)
	}
}

// A pending draft written before the gate existed (the API accepted any
// ruleType) must not come back as an ACTIVE draft with an EMPTY candidate: a
// commit of that draft published an empty rulebase over the running policy.
func TestUnknownRuleType_PendingDraftIsNotReloadedAndCannotWipeThePolicy(t *testing.T) {
	_, _, _, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	lastKnownGood(t, host)

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	draft := map[string]any{
		"state": draftState{Active: true, Actor: "admin"},
		"rules": []PolicyRule{
			{Priority: 1, Name: "lkg-block", DestFQDN: host, Action: ActionBlockPage},
			{Priority: 2, Name: "future-restriction", RuleType: futureRuleType, DestFQDN: host, Action: ActionBlockPage},
		},
	}
	raw, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyDraftPathFor(policyPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	orig := policyDraft
	policyDraft = &policyDraftCoordinator{cand: &PolicyStore{}}
	t.Cleanup(func() { policyDraft = orig })

	initPolicyDraft(policyPath)
	if policyDraft.active() {
		t.Fatal("a draft holding an unknown ruleType was reloaded as an active draft")
	}
	if n := len(policyDraft.candidateList()); n != 0 {
		t.Errorf("candidate holds %d rule(s) from a refused draft", n)
	}
	if got := pol004GetNames(); got != "lkg-block" {
		t.Errorf("running policy is %q, want lkg-block", got)
	}
	assertRefusalRow(t, "pending policy draft")

	// Control: the same draft without the unknown type reloads as before.
	draft["rules"] = draft["rules"].([]PolicyRule)[:1]
	raw, _ = json.Marshal(draft)
	if err := os.WriteFile(policyDraftPathFor(policyPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	policyDraft = &policyDraftCoordinator{cand: &PolicyStore{}}
	initPolicyDraft(policyPath)
	if !policyDraft.active() || len(policyDraft.candidateList()) != 1 {
		t.Errorf("control: a clean pending draft was not reloaded (active=%v, %d rules)", policyDraft.active(), len(policyDraft.candidateList()))
	}
}

// Reload: a refused policy file must not let the reloaded configuration's
// default action land on top of the PREVIOUS rules.
func TestUnknownRuleType_ReloadKeepsTheRunningDefaultActionWhenThePolicyFileIsRefused(t *testing.T) {
	_, _, _, host := pol004Setup(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "old-allow", DestFQDN: host, Action: ActionAllow}})
	setDefaultPolicyAction("deny")

	bad := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(bad, []byte(`[{"priority":1,"name":"future-restriction","ruleType":"`+futureRuleType+`","destFqdn":"`+host+`","action":"Block_Page"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if hotReloadPolicyFile(bad) {
		t.Fatal("hotReloadPolicyFile reports the default action may be applied after refusing the policy file")
	}
	if got := pol004GetNames(); got != "old-allow" {
		t.Errorf("running policy is %q after a refused reload, want old-allow", got)
	}

	// Controls: no policy file configured, and a loadable one, both allow it.
	if !hotReloadPolicyFile("") {
		t.Error("hotReloadPolicyFile(\"\") = false; a configuration without a policy file must still apply its default action")
	}
	good := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(good, []byte(`[{"priority":1,"name":"new-block","destFqdn":"`+host+`","action":"Block_Page"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hotReloadPolicyFile(good) || pol004GetNames() != "new-block" {
		t.Errorf("a loadable policy file was not applied (rules %q)", pol004GetNames())
	}
}
