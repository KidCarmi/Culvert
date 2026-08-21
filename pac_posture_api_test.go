package main

// pac_posture_api_test.go — PAC Exception Intelligence P0: the read-only
// DIRECT inventory endpoint.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

func TestAPIPACPostureInventory(t *testing.T) {
	// Isolate the global stores.
	oc := pacStore.Snapshot()
	op := pacProfiles.Snapshot()
	t.Cleanup(func() { pacStore.Restore(oc); pacProfiles.Restore(op) })

	// Legacy default: a proxy host + one exclusion → the synthesized default
	// profile is DIRECT-capable (exclusion → DIRECT rule + private-direct).
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080, Exclusions: []string{"corp.local"}}); err != nil {
		t.Fatal(err)
	}
	// Custom profiles: one proxy-only (no DIRECT), one with a broad DIRECT rule.
	if err := pacProfiles.Set(pac.ProfilesConfig{
		Pools: []pac.Pool{{ID: "p", Name: "P", Endpoints: []pac.PoolEndpoint{{Host: "px.example", Port: 8080}}}},
		Profiles: []pac.Profile{
			{ID: "safe", Name: "Safe", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1},
			{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p", PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Revision: 1,
				Rules: []pac.Rule{{Kind: pac.RuleKindWildcard, Pattern: "*.cdn.example", Action: pac.ActionDirect}}},
		},
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pac/posture/inventory", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
	rec := httptest.NewRecorder()
	apiPACPostureInventory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory: %d (%s)", rec.Code, rec.Body.String())
	}
	var inv pac.DirectInventory
	if err := json.Unmarshal(rec.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.EvidenceClass != "config" {
		t.Errorf("evidence class must be config (Observable), got %q", inv.EvidenceClass)
	}
	// default (legacy) + safe + hq = 3 profiles.
	if inv.TotalProfiles != 3 {
		t.Errorf("TotalProfiles = %d, want 3 (default + safe + hq)", inv.TotalProfiles)
	}
	// Every profile carries the unconditional plain-host bypass → all capable.
	if inv.DirectCapableProfiles != 3 {
		t.Errorf("DirectCapableProfiles = %d, want 3 (plain-host is universal)", inv.DirectCapableProfiles)
	}
	byID := map[string]pac.ProfileDirectInventory{}
	for _, p := range inv.Profiles {
		byID[p.ProfileID] = p
	}
	if _, ok := byID[pac.DefaultProfileID]; !ok {
		t.Error("inventory must include the synthesized legacy default profile")
	}
	// Proxy-only profile is still capable via the plain-host bypass, but only
	// that one path (no rule/private/availability DIRECT).
	if !byID["safe"].DirectCapable || len(byID["safe"].DirectPaths) != 1 ||
		byID["safe"].DirectPaths[0].Kind != pac.BypassPlainHost {
		t.Errorf("proxy-only profile must expose exactly the plain-host bypass: %+v", byID["safe"])
	}
	if !byID["hq"].DirectCapable || inv.BroadDirectPaths < 1 {
		t.Errorf("hq wildcard DIRECT rule must be a broad path: %+v", byID["hq"])
	}

	// Non-GET is rejected.
	req2 := httptest.NewRequest(http.MethodPost, "/api/pac/posture/inventory", http.NoBody)
	req2 = req2.WithContext(context.WithValue(req2.Context(), uiRoleKey{}, RoleViewer))
	rec2 := httptest.NewRecorder()
	apiPACPostureInventory(rec2, req2)
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST inventory: %d, want 405", rec2.Code)
	}
}

// TestAPIPACPostureInventory_FailOpen pins the F1 fix: when no proxy host is
// configured, the legacy /proxy.pac fails OPEN to DIRECT for all traffic, so
// the default profile must carry a broad fail_open DIRECT path in the
// inventory (the static profile model cannot otherwise express it).
func TestAPIPACPostureInventory_FailOpen(t *testing.T) {
	oc := pacStore.Snapshot()
	op := pacProfiles.Snapshot()
	t.Cleanup(func() { pacStore.Restore(oc); pacProfiles.Restore(op) })

	// Empty ProxyHost = the fail-open case.
	if err := pacStore.Set(PACConfig{ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	if err := pacProfiles.Set(pac.ProfilesConfig{}); err != nil {
		t.Fatal(err)
	}

	inv := pacDirectInventory()
	var def *pac.ProfileDirectInventory
	for i := range inv.Profiles {
		if inv.Profiles[i].ProfileID == pac.DefaultProfileID {
			def = &inv.Profiles[i]
		}
	}
	if def == nil {
		t.Fatal("default profile missing from inventory")
	}
	var failOpen *pac.DirectEntry
	for i := range def.DirectPaths {
		if def.DirectPaths[i].Kind == pac.BypassFailOpen {
			failOpen = &def.DirectPaths[i]
		}
	}
	if failOpen == nil || !failOpen.Broad {
		t.Errorf("empty ProxyHost must surface a broad fail_open DIRECT path: %+v", def.DirectPaths)
	}

	// With a proxy host configured, there is NO fail-open path.
	if err := pacStore.Set(PACConfig{ProxyHost: "proxy.example", ProxyPort: 8080}); err != nil {
		t.Fatal(err)
	}
	inv2 := pacDirectInventory()
	for _, p := range inv2.Profiles {
		for _, d := range p.DirectPaths {
			if d.Kind == pac.BypassFailOpen {
				t.Errorf("configured ProxyHost must NOT produce a fail_open path: %+v", p)
			}
		}
	}
}
