package main

// ui_access_policy_startup_test.go — PR3 expansion Batch 2 coverage.

import (
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var uiAccessPolicyLoggerMu sync.Mutex

func ensureUIAccessPolicyTestLogger(t *testing.T) {
	t.Helper()
	uiAccessPolicyLoggerMu.Lock()
	defer uiAccessPolicyLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetUIAccessPolicyGlobals snapshots/restores uiAllowedNets,
// proxyExternalBaseURL, and idpRegistry state for isolation under
// -shuffle. idpRegistry.path in particular must be restored because
// subsequent tests call Upsert() which persists via save() to the
// path — a leaked temp-dir path causes spurious failures elsewhere.
func resetUIAccessPolicyGlobals(t *testing.T) {
	t.Helper()
	uiAllowedNetsMu.RLock()
	origNets := append([]*net.IPNet(nil), uiAllowedNets...)
	origRefused, origUnknown, origExplicit := uiAccessRefused, uiAccessUnknown, uiAccessExplicit
	origRetained := append([]string(nil), uiAccessRetained...)
	uiAllowedNetsMu.RUnlock()
	origBase := proxyExternalBaseURL
	idpRegistry.mu.RLock()
	origPath := idpRegistry.path
	origProfiles := append([]*IdPProfile(nil), idpRegistry.profiles...)
	idpRegistry.mu.RUnlock()
	t.Cleanup(func() {
		uiAllowedNetsMu.Lock()
		uiAllowedNets = origNets
		uiAccessRefused, uiAccessUnknown, uiAccessRetained = origRefused, origUnknown, origRetained
		uiAccessExplicit = origExplicit
		uiAllowedNetsMu.Unlock()
		proxyExternalBaseURL = origBase
		idpRegistry.mu.Lock()
		idpRegistry.path = origPath
		idpRegistry.profiles = origProfiles
		idpRegistry.mu.Unlock()
	})
}

func TestResolveUIAccessPolicyStartupConfig_CopiesAllFields(t *testing.T) {
	fc := &FileConfig{
		UIAllowIPs: []string{"10.0.0.0/8"},
		OIDC:       OIDCConfig{IntrospectionURL: "https://idp.example/introspect"},
	}
	fc.Proxy.BaseURL = "https://proxy.example"
	fc.Proxy.IdPProfilesFile = "/etc/culvert/idp.json"
	got := resolveUIAccessPolicyStartupConfig(fc, "192.168.1.0/24", "", "")
	if got.AllowIPCLI != "192.168.1.0/24" {
		t.Errorf("AllowIPCLI: got %q", got.AllowIPCLI)
	}
	if len(got.AllowList) != 1 || got.AllowList[0] != "10.0.0.0/8" {
		t.Errorf("AllowList: got %v", got.AllowList)
	}
	if got.BaseURL != "https://proxy.example" {
		t.Errorf("BaseURL: got %q", got.BaseURL)
	}
	if got.IdPProfilesFile != "/etc/culvert/idp.json" {
		t.Errorf("IdPProfilesFile: got %q", got.IdPProfilesFile)
	}
	if !got.HasOIDCOrSAML {
		t.Errorf("HasOIDCOrSAML: expected true (OIDC + registry file set)")
	}
}

func TestResolveUIAccessPolicyStartupConfig_HasOIDCFromRegistryOnly(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.IdPProfilesFile = "/etc/culvert/idp.json"
	got := resolveUIAccessPolicyStartupConfig(fc, "", "", "")
	if !got.HasOIDCOrSAML {
		t.Errorf("HasOIDCOrSAML: expected true (registry file alone)")
	}
}

func TestResolveUIAccessPolicyStartupConfig_HasOIDCFalse(t *testing.T) {
	got := resolveUIAccessPolicyStartupConfig(&FileConfig{}, "", "", "")
	if got.HasOIDCOrSAML {
		t.Errorf("HasOIDCOrSAML: expected false")
	}
}

func TestResolveUIAccessPolicyStartupConfig_IdPProfilesCLIOverridesYAML(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.IdPProfilesFile = "/etc/culvert/idp.json"
	got := resolveUIAccessPolicyStartupConfig(fc, "", "", "/data/idp_profiles.json")
	if got.IdPProfilesFile != "/data/idp_profiles.json" {
		t.Errorf("IdPProfilesFile: got %q, want CLI value to win", got.IdPProfilesFile)
	}
	if !got.HasOIDCOrSAML {
		t.Errorf("HasOIDCOrSAML: expected true (CLI registry file)")
	}
}

func TestResolveUIAccessPolicyStartupConfig_IdPProfilesCLIOnly(t *testing.T) {
	got := resolveUIAccessPolicyStartupConfig(&FileConfig{}, "", "", "/data/idp_profiles.json")
	if got.IdPProfilesFile != "/data/idp_profiles.json" {
		t.Errorf("IdPProfilesFile: got %q", got.IdPProfilesFile)
	}
	if !got.HasOIDCOrSAML {
		t.Errorf("HasOIDCOrSAML: expected true (CLI registry file alone)")
	}
}

func TestLoadUIAccessPolicy_MergesCLIAndFileAllowList(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	c := uiAccessPolicyStartupConfig{
		AllowIPCLI: "192.168.1.0/24, 203.0.113.5",
		AllowList:  []string{"10.0.0.0/8"},
	}
	if err := loadUIAccessPolicy(c); err != nil {
		t.Fatalf("loadUIAccessPolicy: %v", err)
	}
	uiAllowedNetsMu.RLock()
	got := len(uiAllowedNets)
	uiAllowedNetsMu.RUnlock()
	if got != 3 {
		t.Errorf("expected 3 entries in uiAllowedNets; got %d", got)
	}
}

func TestLoadUIAccessPolicy_InvalidCIDRRefusesUIWithoutKillingTheProcess(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	c := uiAccessPolicyStartupConfig{AllowIPCLI: "not-a-cidr"}
	// A non-nil error is log.Fatalf in initUIAccessPolicy: the admin plane
	// would terminate the data plane (CHAOS-57). It must refuse the UI instead.
	if err := loadUIAccessPolicy(c); err != nil {
		t.Fatalf("invalid configured policy terminated startup: %v", err)
	}
	if !uiAccessPolicyRefused() {
		t.Fatal("invalid configured policy left management unrestricted")
	}
	if got := uiPolicyResponse(t, "198.51.100.4:1234").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("invalid configured policy served the UI: %d", got)
	}
}

func TestLoadUIAccessPolicy_BlankEntriesAreSkipped(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	if err := SetUIAllowedCIDRs(nil); err != nil {
		t.Fatal(err)
	}
	c := uiAccessPolicyStartupConfig{AllowIPCLI: "192.0.2.0/24, ,", AllowList: []string{" ", "2001:db8::/32"}}
	if err := loadUIAccessPolicy(c); err != nil {
		t.Fatal(err)
	}
	if uiAccessPolicyRefused() {
		t.Fatal("a trailing comma refused management")
	}
	if got := ListUIAllowedCIDRs(); len(got) != 2 {
		t.Fatalf("restriction not applied: %v", got)
	}
}

func TestLoadUIAccessPolicy_SetsBaseURL(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	c := uiAccessPolicyStartupConfig{BaseURL: "https://proxy.example/"}
	if err := loadUIAccessPolicy(c); err != nil {
		t.Fatalf("loadUIAccessPolicy: %v", err)
	}
	if proxyExternalBaseURL != "https://proxy.example" {
		t.Errorf("proxyExternalBaseURL: got %q", proxyExternalBaseURL)
	}
}

func TestLoadUIAccessPolicy_WarnsWhenOIDCButNoBaseURL(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	// We can't easily capture logger output across tests, but the path
	// must execute without error when HasOIDCOrSAML=true and BaseURL="".
	c := uiAccessPolicyStartupConfig{HasOIDCOrSAML: true}
	if err := loadUIAccessPolicy(c); err != nil {
		t.Fatalf("loadUIAccessPolicy: %v", err)
	}
	if proxyExternalBaseURL != "" {
		t.Errorf("proxyExternalBaseURL should remain empty; got %q", proxyExternalBaseURL)
	}
}

func TestLoadUIAccessPolicy_IdPProfilesMissingFileIsNonFatal(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	// idpRegistry.Load treats os.IsNotExist as a first-run no-op.
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-idp.json")
	c := uiAccessPolicyStartupConfig{IdPProfilesFile: path}
	if err := loadUIAccessPolicy(c); err != nil {
		t.Fatalf("loadUIAccessPolicy: %v", err)
	}
}

func TestLoadUIAccessPolicy_IdPProfilesParseErrorSurfaces(t *testing.T) {
	resetUIAccessPolicyGlobals(t)
	ensureUIAccessPolicyTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-idp.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad json: %v", err)
	}
	err := loadUIAccessPolicy(uiAccessPolicyStartupConfig{IdPProfilesFile: path})
	if err == nil {
		t.Fatal("expected error from malformed IdP file; got nil")
	}
	if !strings.Contains(err.Error(), "IdP profiles load error:") {
		t.Errorf("error prefix mismatch: %v", err)
	}
}
