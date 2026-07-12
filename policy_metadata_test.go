package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// policy_metadata_test.go — Tier-A rule metadata (policy-metadata P1;
// authority docs/design/POLICY-ARCHITECTURE-FUTURE.md §2). Pins the
// server-authoritative stamping contract: createdAt/modifiedAt/modifiedBy are
// set by the handler (never trusted from the client), createdAt is preserved
// across edits, comment is admin-authored, and all four round-trip through the
// config-version rollback surface without being wiped.

// findRuleByName returns a copy of the stored rule with the given name.
func findRuleByName(t *testing.T, name string) PolicyRule {
	t.Helper()
	// Index-based range: PolicyRule is a large struct (CLAUDE.md rangeValCopy).
	rules := policyStore.List()
	for i := range rules {
		if rules[i].Name == name {
			return rules[i]
		}
	}
	t.Fatalf("rule %q not found in store", name)
	return PolicyRule{}
}

func TestPolicyMetadata_StampedOnCreate(t *testing.T) {
	withFreshPolicyStore(t)
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "meta-create", "action": "Allow", "priority": 100,
		"comment": "why this exists",
	}))
	if w.Code != 200 {
		t.Fatalf("POST = %d (%s), want 200", w.Code, w.Body.String())
	}
	r := findRuleByName(t, "meta-create")
	if r.CreatedAt == "" {
		t.Error("createdAt not stamped on create")
	}
	if r.ModifiedAt == "" {
		t.Error("modifiedAt not stamped on create")
	}
	if r.ModifiedBy == "" {
		t.Error("modifiedBy not stamped on create")
	}
	if _, err := time.Parse(time.RFC3339, r.CreatedAt); err != nil {
		t.Errorf("createdAt %q is not RFC3339: %v", r.CreatedAt, err)
	}
	if r.Comment != "why this exists" {
		t.Errorf("comment = %q, want the admin-supplied note", r.Comment)
	}
}

func TestPolicyMetadata_PreservedCreatedAtAcrossUpdate(t *testing.T) {
	withFreshPolicyStore(t)
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "meta-edit", "action": "Allow", "priority": 101,
	}))
	if w.Code != 200 {
		t.Fatalf("POST = %d (%s)", w.Code, w.Body.String())
	}
	created := findRuleByName(t, "meta-edit").CreatedAt
	if created == "" {
		t.Fatal("precondition: createdAt should be set after create")
	}

	// Edit the rule — the client body carries no metadata (typical PUT).
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("PUT", "/api/policy?priority=101", map[string]any{
		"name": "meta-edit", "action": "Block_Page", "priority": 101,
		"comment": "updated reason",
	}))
	if w.Code != 200 {
		t.Fatalf("PUT = %d (%s)", w.Code, w.Body.String())
	}
	r := findRuleByName(t, "meta-edit")
	if r.CreatedAt != created {
		t.Errorf("createdAt changed on edit: was %q, now %q — an edit must not rewrite birth time", created, r.CreatedAt)
	}
	if r.ModifiedBy == "" {
		t.Error("modifiedBy not set on edit")
	}
	if r.Comment != "updated reason" {
		t.Errorf("comment = %q, want the edited note", r.Comment)
	}
}

func TestPolicyMetadata_ClientCannotSpoof(t *testing.T) {
	withFreshPolicyStore(t)
	// A client tries to backdate creation and forge the actor.
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "meta-spoof", "action": "Allow", "priority": 102,
		"createdAt": "1999-01-01T00:00:00Z", "modifiedAt": "1999-01-01T00:00:00Z",
		"modifiedBy": "attacker",
	}))
	if w.Code != 200 {
		t.Fatalf("POST = %d (%s)", w.Code, w.Body.String())
	}
	r := findRuleByName(t, "meta-spoof")
	if r.CreatedAt == "1999-01-01T00:00:00Z" {
		t.Error("client-supplied createdAt was trusted — provenance is spoofable")
	}
	if r.ModifiedBy == "attacker" {
		t.Error("client-supplied modifiedBy was trusted — actor is spoofable")
	}
}

func TestPolicyMetadata_PreFeatureRuleNotBackdated(t *testing.T) {
	withFreshPolicyStore(t)
	// A rule that predates the feature: added straight to the store, no metadata.
	policyStore.Add(PolicyRule{Priority: 103, Name: "pre-feature", Action: ActionAllow})
	if findRuleByName(t, "pre-feature").CreatedAt != "" {
		t.Fatal("precondition: pre-feature rule should have empty createdAt")
	}
	// Editing it stamps modifiedAt/By but must NOT invent a createdAt (that
	// would be a lie about when the rule was born).
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("PUT", "/api/policy?priority=103", map[string]any{
		"name": "pre-feature", "action": "Drop", "priority": 103,
	}))
	if w.Code != 200 {
		t.Fatalf("PUT = %d (%s)", w.Code, w.Body.String())
	}
	r := findRuleByName(t, "pre-feature")
	if r.CreatedAt != "" {
		t.Errorf("edit back-dated a pre-feature rule's createdAt to %q — should stay empty", r.CreatedAt)
	}
	if r.ModifiedAt == "" || r.ModifiedBy == "" {
		t.Error("edit should still stamp modifiedAt/modifiedBy on a pre-feature rule")
	}
}

func TestPolicyMetadata_SurvivesConfigVersionRollback(t *testing.T) {
	withFreshPolicyStore(t)
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{
		"name": "meta-rollback", "action": "Allow", "priority": 104,
		"comment": "keep me through rollback",
	}))
	if w.Code != 200 {
		t.Fatalf("POST = %d (%s)", w.Code, w.Body.String())
	}
	before := findRuleByName(t, "meta-rollback")

	// Capture, wipe, restore — the config-version rollback surface.
	backup := captureConfigBackup()
	policyStore.ReplaceAll(nil)
	applyConfigBackup(backup)

	after := findRuleByName(t, "meta-rollback")
	if after.CreatedAt != before.CreatedAt || after.ModifiedAt != before.ModifiedAt ||
		after.ModifiedBy != before.ModifiedBy || after.Comment != before.Comment {
		t.Errorf("metadata wiped by rollback round-trip:\n before=%+v\n after =%+v",
			metaOnly(before), metaOnly(after))
	}
}

// metaOnly extracts just the Tier-A metadata for a compact failure message.
func metaOnly(r PolicyRule) string {
	b, _ := json.Marshal(map[string]string{
		"createdAt": r.CreatedAt, "modifiedAt": r.ModifiedAt,
		"modifiedBy": r.ModifiedBy, "comment": r.Comment,
	})
	return string(b)
}
