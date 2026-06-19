package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Pre-Phase-2 corrections (approved in the Phase 2 architecture review):
//
//  1. The authSource namespace {exempt, unauth, local, system} is RESERVED:
//     IdP profile IDs and names must not collide with it, or Stage-2 rules
//     keyed on AuthSource become ambiguous.
//  2. The reserved IdPRef field is superseded by reserved ProviderRefs
//     (validation-rejected when set, persistence-safe, no behavior change).

func validTestIdPProfile() *IdPProfile {
	return &IdPProfile{
		ID:      "abc123def456",
		Name:    "Corp Okta",
		Type:    IdPTypeOIDC,
		Enabled: true,
		OIDC:    &OIDCProfileConfig{Issuer: "https://idp.example.com"},
	}
}

func TestPrePhase2_ReservedAuthSourceNames_IdPProfileRejected(t *testing.T) {
	// Baseline: a clean profile gets PAST the reserved-name checks. (Full
	// validation may still fail later on the issuer's DNS-resolving SSRF guard
	// in sandboxed environments — the reserved-name gate runs before it, so we
	// assert only that no reserved-namespace error is returned.)
	if err := validateIdPProfile(validTestIdPProfile()); err != nil && strings.Contains(err.Error(), "reserved authSource namespace") {
		t.Fatalf("clean profile must pass the reserved-name checks: %v", err)
	}
	for _, reserved := range []string{"exempt", "unauth", "local", "system", "Exempt", "UNAUTH", " local ", "System"} {
		p := validTestIdPProfile()
		p.ID = reserved
		if err := validateIdPProfile(p); err == nil || !strings.Contains(err.Error(), "reserved authSource namespace") {
			t.Errorf("profile ID %q must be rejected as reserved, got: %v", reserved, err)
		}
		p = validTestIdPProfile()
		p.Name = reserved
		if err := validateIdPProfile(p); err == nil || !strings.Contains(err.Error(), "reserved authSource namespace") {
			t.Errorf("profile Name %q must be rejected as reserved, got: %v", reserved, err)
		}
	}
	// Non-reserved names that merely contain a reserved word are fine.
	p := validTestIdPProfile()
	p.Name = "Local Office Okta"
	if err := validateIdPProfile(p); err != nil && strings.Contains(err.Error(), "reserved authSource namespace") {
		t.Errorf("name containing (but not equal to) a reserved word must pass the name checks: %v", err)
	}
}

// Every IdP entry point must enforce the reserved-name guard, not just
// validateIdPProfile (PR #448 review): the admin create/update path runs through
// IdPRegistry.Upsert, and startup runs through IdPRegistry.Load.
func TestPrePhase2_ReservedAuthSourceNames_UpsertRejected(t *testing.T) {
	reg := &IdPRegistry{}
	for _, reserved := range []string{"exempt", "Local", "UNAUTH", "system"} {
		p := validTestIdPProfile()
		p.ID = "" // force generation; the collision must come from Name
		p.Name = reserved
		if err := reg.Upsert(p); err == nil || !strings.Contains(err.Error(), "reserved authSource namespace") {
			t.Errorf("Upsert name %q must be rejected as reserved, got: %v", reserved, err)
		}
		// Supplied reserved ID must also be rejected.
		p = validTestIdPProfile()
		p.ID = reserved
		if err := reg.Upsert(p); err == nil || !strings.Contains(err.Error(), "reserved authSource namespace") {
			t.Errorf("Upsert id %q must be rejected as reserved, got: %v", reserved, err)
		}
	}
	if got := len(reg.All()); got != 0 {
		t.Errorf("no reserved-name profile may be stored, got %d", got)
	}
}

func TestPrePhase2_ReservedAuthSourceNames_LoadDropsFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp.json")
	good := validTestIdPProfile()
	good.ID = "abc123def456"
	good.Name = "Corp Okta"
	bad := validTestIdPProfile()
	bad.ID = "exempt" // reserved
	bad.Name = "Sneaky"
	data, err := json.Marshal([]*IdPProfile{good, bad})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	reg := &IdPRegistry{}
	if err := reg.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := reg.All()
	if len(got) != 1 || got[0].ID != "abc123def456" {
		t.Fatalf("reserved-ID profile must be dropped fail-closed on load, got: %+v", got)
	}
}

func TestPrePhase2_IsReservedAuthSourceName(t *testing.T) {
	for _, s := range []string{"exempt", "unauth", "local", "system", "EXEMPT", "  system\t"} {
		if !isReservedAuthSourceName(s) {
			t.Errorf("%q must be reserved", s)
		}
	}
	for _, s := range []string{"", "okta", "exempt2", "my-local", "oidc:corp"} {
		if isReservedAuthSourceName(s) {
			t.Errorf("%q must not be reserved", s)
		}
	}
}

// A rule carrying the reserved providerRefs (e.g. written by a future version
// or hand-edited) is dropped fail-closed by the persistence gate on this
// binary: an older binary cannot honor a provider restriction, and honoring
// the rule while ignoring the restriction would widen it.
func TestPrePhase2_ProviderRefs_LoadDropsFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	withRefs := validExemptRule()
	withRefs.Auth.ProviderRefs = []string{"okta-prod"}
	data, err := json.MarshalIndent([]PolicyRule{
		withRefs,
		{Priority: 2, Name: "plain-allow", Action: ActionAllow},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := ps.List()
	if len(got) != 1 || got[0].Name != "plain-allow" {
		t.Fatalf("providerRefs-bearing rule must be dropped fail-closed, got: %+v", got)
	}
}

// The /api/authpolicy accept path rejects providerRefs too (single validation
// path through validatePolicyRule).
func TestPrePhase2_ProviderRefs_APIRejected(t *testing.T) {
	withFreshPolicyStore(t)
	body := slice8Rule("with-provider-refs")
	body["auth"].(map[string]any)["providerRefs"] = []string{"okta-prod"}
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
	// providerRefs is active for SSORequired as of Phase 3 Slice 2, but remains
	// rejected on Exempt rules (this rule is Exempt). The rejection still 400s;
	// the message now names the outcome rather than "reserved".
	if w.Code != 400 || !strings.Contains(w.Body.String(), "providerRefs is not valid on Exempt") {
		t.Fatalf("POST with providerRefs on Exempt = %d (%q), want 400", w.Code, w.Body.String())
	}
	if got := len(listAuthRules()); got != 0 {
		t.Errorf("providerRefs-bearing Exempt rule must not be stored, got %d", got)
	}
}
