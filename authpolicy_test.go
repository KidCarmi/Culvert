package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"
)

// ─── RuleType discriminator ─────────────────────────────────────────────────

func TestRuleTypeOf_DefaultAccess(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ruleTypeAccess},       // load-default
		{"access", ruleTypeAccess}, // explicit access
		{"auth", ruleTypeAuth},     // Stage-1 rule
		{"custom", "custom"},       // passthrough (no silent rewrite)
	}
	for _, c := range cases {
		r := &PolicyRule{RuleType: c.in}
		if got := ruleTypeOf(r); got != c.want {
			t.Errorf("ruleTypeOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := ruleTypeOf(nil); got != ruleTypeAccess {
		t.Errorf("ruleTypeOf(nil) = %q, want %q", got, ruleTypeAccess)
	}
}

// ─── SubjectMatch validation (fail-closed) ──────────────────────────────────

func TestValidateSubjectMatch(t *testing.T) {
	tests := []struct {
		name    string
		sm      *SubjectMatch
		wantErr bool
	}{
		{"nil is valid", nil, false},
		{"valid cidr", &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "cidr", Values: []string{"10.0.5.0/24"}}}}, false},
		{"valid bare ip", &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "cidr", Values: []string{"10.0.5.7"}}}}, false},
		{"invalid cidr value", &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "cidr", Values: []string{"not-an-ip"}}}}, true},
		{"unknown predicate type fails closed", &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "posture", Values: []string{"compliant"}}}}, true},
		{"reserved type device_id rejected in phase 0", &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "device_id", Values: []string{"x"}}}}, true},
		{"empty all rejected", &SubjectMatch{SchemaVersion: 1, All: nil}, true},
		{"schemaVersion < 1 rejected", &SubjectMatch{SchemaVersion: 0, All: []SubjectPredicate{{Type: "cidr", Values: []string{"10.0.0.0/8"}}}}, true},
		{"cidr with no values rejected", &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: "cidr"}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSubjectMatch(tc.sm)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSubjectMatch err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidatePolicyRule_RejectsUnknownSubjectPredicate(t *testing.T) {
	rule := PolicyRule{
		Name:   "auth-exempt",
		Action: ActionAllow,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: "tag", Values: []string{"no-idp"}}},
		},
	}
	if err := validatePolicyRule(rule, nil, -1); err == nil {
		t.Fatal("expected validatePolicyRule to reject an unknown subject predicate type (fail-closed)")
	}
}

// ─── Stable ULID IDs ────────────────────────────────────────────────────────

func TestNewRuleID_StrictParseAndUnique(t *testing.T) {
	a := newRuleID()
	b := newRuleID()
	if _, err := ulid.ParseStrict(a); err != nil {
		t.Errorf("newRuleID() produced non-ULID %q: %v", a, err)
	}
	if a == b {
		t.Errorf("newRuleID() returned duplicate IDs %q", a)
	}
}

// ─── Unified PDP seam (not on hot path) ─────────────────────────────────────

func TestDecide_EquivalentToEvaluate(t *testing.T) {
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })

	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "block-social", DestCategory: CategorySocial, Action: ActionDrop},
		{Priority: 2, Name: "hr-allow", SourceIP: "10.10.0.0/16", Action: ActionAllow},
		{Priority: 3, Name: "allow-all", Action: ActionAllow},
	})

	type probe struct {
		ip, identity, authSrc, host string
		groups                      []string
	}
	probes := []probe{
		{"10.10.0.5", "", "unauth", "www.facebook.com", nil},
		{"10.10.0.5", "", "unauth", "example.com", nil},
		{"1.2.3.4", "", "unauth", "example.com", nil},
		{"1.2.3.4", "alice", "oidc:okta", "twitter.com", []string{"eng"}},
	}
	for _, p := range probes {
		want := policyStore.Evaluate(p.ip, p.identity, p.authSrc, p.host, p.groups)
		got := Decide(RequestContext{
			ClientIP: p.ip, Identity: p.identity, AuthSource: p.authSrc,
			Host: p.host, Groups: p.groups,
		})
		if got.AuthSource != p.authSrc {
			t.Errorf("Decide AuthSource = %q, want %q", got.AuthSource, p.authSrc)
		}
		switch {
		case want == nil && got.Match == nil:
			// equivalent: both no-match
		case want == nil || got.Match == nil:
			t.Errorf("probe %+v: Decide.Match=%v but Evaluate=%v", p, got.Match, want)
		case want.Rule.Name != got.Match.Rule.Name || want.Action != got.Match.Action:
			t.Errorf("probe %+v: Decide matched %q/%v, Evaluate matched %q/%v",
				p, got.Match.Rule.Name, got.Match.Action, want.Rule.Name, want.Action)
		}
	}
}

// ─── Kill switch (read-once accessor only) ──────────────────────────────────

func TestParseAuthBypassDisable(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", " yes ", "On"}
	falsy := []string{"", "0", "false", "no", "off", "garbage"}
	for _, v := range truthy {
		if !parseAuthBypassDisable(v) {
			t.Errorf("parseAuthBypassDisable(%q) = false, want true", v)
		}
	}
	for _, v := range falsy {
		if parseAuthBypassDisable(v) {
			t.Errorf("parseAuthBypassDisable(%q) = true, want false", v)
		}
	}
}

func TestAuthBypassDisabled_DefaultFalse(t *testing.T) {
	// No env set in the test environment; the read-once accessor must default
	// to false and Phase 0 wires no behavior to it.
	if os.Getenv(envAuthBypassDisable) == "" && authBypassDisabled() {
		t.Error("authBypassDisabled() = true with no env set; want false")
	}
}

// ─── ULID load migration (idempotent, one-time) ─────────────────────────────

func writePolicyFile(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return p
}

func TestPolicyStore_Load_BackfillsIDs_Persists_Idempotent(t *testing.T) {
	dir := t.TempDir()
	// Legacy JSON without "id" fields.
	path := writePolicyFile(t, dir, `[
		{"priority":1,"name":"allow-all","action":"Allow"},
		{"priority":2,"name":"block-fb","destFQDN":"facebook.com","action":"Drop"}
	]`)

	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, r := range ps.List() {
		if r.ID == "" {
			t.Fatalf("rule %q missing ID after load migration", r.Name)
		}
		if _, err := ulid.ParseStrict(r.ID); err != nil {
			t.Errorf("rule %q has non-ULID ID %q", r.Name, r.ID)
		}
	}

	// File must have been rewritten with the IDs.
	after1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after first load: %v", err)
	}
	if !strings.Contains(string(after1), `"id"`) {
		t.Fatal("expected migrated policy file to contain id fields")
	}

	// Idempotency at the unit level: a second backfill assigns nothing.
	ps.mu.Lock()
	again := ps.backfillIDsLocked()
	ps.mu.Unlock()
	if again != 0 {
		t.Errorf("second backfill assigned %d IDs, want 0", again)
	}

	// Idempotency at the file level: loading the migrated file into a fresh
	// store does not rewrite it (byte-identical before/after).
	ps2 := &PolicyStore{}
	if err := ps2.Load(path); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	after2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after second load: %v", err)
	}
	if !bytes.Equal(after1, after2) {
		t.Error("second load rewrote the policy file; migration is not idempotent")
	}
}

func TestPolicyStore_Load_PreservesExistingIDs(t *testing.T) {
	dir := t.TempDir()
	const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	path := writePolicyFile(t, dir, `[
		{"priority":1,"name":"keep","action":"Allow","id":"`+id+`"}
	]`)
	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	list := ps.List()
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("existing ID not preserved: got %+v", list)
	}
}

func TestPolicyStore_Add_StampsID(t *testing.T) {
	ps := &PolicyStore{}
	added := ps.Add(PolicyRule{Priority: 1, Name: "x", Action: ActionAllow})
	if added.ID == "" {
		t.Fatal("Add did not stamp an ID")
	}
	if _, err := ulid.ParseStrict(added.ID); err != nil {
		t.Errorf("Add stamped a non-ULID ID %q", added.ID)
	}
}

func TestPolicyStore_Update_PreservesID_WhenBodyOmits(t *testing.T) {
	ps := &PolicyStore{}
	added := ps.Add(PolicyRule{Priority: 1, Name: "x", Action: ActionAllow})
	origID := added.ID

	// Simulate a PUT whose body omits "id" (older client).
	ok := ps.Update(1, PolicyRule{Priority: 1, Name: "x-renamed", Action: ActionAllow})
	if !ok {
		t.Fatal("Update returned false")
	}
	list := ps.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(list))
	}
	if list[0].ID != origID {
		t.Errorf("Update wiped/changed ID: got %q, want %q", list[0].ID, origID)
	}
	if list[0].Name != "x-renamed" {
		t.Errorf("Update did not apply new name: %q", list[0].Name)
	}
}

// ─── Stage-2 ignores auth-type rules; access behavior unchanged ─────────────

func TestEvaluate_IgnoresAuthTypeRules(t *testing.T) {
	ps := &PolicyStore{}
	// A would-be Stage-1 auth rule must NOT match in the Stage-2 engine.
	ps.Add(PolicyRule{Priority: 1, Name: "auth-rule", RuleType: ruleTypeAuth, Action: ActionAllow})
	if m := ps.Evaluate("1.2.3.4", "", "unauth", "example.com", nil); m != nil {
		t.Errorf("Stage-2 Evaluate matched an auth-type rule: %+v", m)
	}

	// An explicit access rule (and the default empty type) still match.
	ps.Add(PolicyRule{Priority: 2, Name: "access-rule", RuleType: ruleTypeAccess, Action: ActionAllow})
	if m := ps.Evaluate("1.2.3.4", "", "unauth", "example.com", nil); m == nil || m.Rule.Name != "access-rule" {
		t.Errorf("expected access-rule to match, got %+v", m)
	}
}

// ─── LogEntry additive fields: byte-identical wire output when unset ─────────

func TestLogEntry_AdditiveFieldsOmitWhenEmpty(t *testing.T) {
	e := LogEntry{TS: 1, Time: "00:00:00", IP: "1.2.3.4", Method: "GET", Host: "h", Status: "OK", Level: "INFO"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(b)
	for _, key := range []string{
		"schema_version", "auth_source", "auth_policy_rule_id",
		"auth_policy_rule_name", "access_rule_id", "subject_match_types",
	} {
		if strings.Contains(out, key) {
			t.Errorf("unpopulated Phase-0 field %q leaked into wire output: %s", key, out)
		}
	}
}

// ─── Rollback tolerance: older structs ignore the new JSON fields ───────────

func TestPolicyRuleJSON_RollbackTolerated(t *testing.T) {
	// A pre-Phase-0 binary models PolicyRule without id/ruleType/subjectMatch.
	type oldRule struct {
		Priority int          `json:"priority"`
		Name     string       `json:"name"`
		Action   PolicyAction `json:"action"`
	}
	newJSON := `{"priority":1,"name":"x","action":"Allow",
		"id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","ruleType":"access",
		"subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]}}`
	var r oldRule
	if err := json.Unmarshal([]byte(newJSON), &r); err != nil {
		t.Fatalf("old struct failed to unmarshal new JSON (rollback broken): %v", err)
	}
	if r.Name != "x" || r.Action != ActionAllow {
		t.Errorf("rollback unmarshal lost known fields: %+v", r)
	}
}
