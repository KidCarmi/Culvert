package main

// legacy_auth_providers_startup_test.go — PR3 expansion Batch 2 coverage.

import (
	"log"
	"os"
	"strings"
	"sync"
	"testing"
)

var legacyAuthLoggerMu sync.Mutex

func ensureLegacyAuthTestLogger(t *testing.T) {
	t.Helper()
	legacyAuthLoggerMu.Lock()
	defer legacyAuthLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetLegacyAuthGlobals snapshots/restores cfg.provider and
// oidcLoginURL for isolation under -shuffle. It also snapshots/restores the
// legacy-LDAP YAML retention and the durable cutover sentinel:
// loadLegacyAuthProviders overwrites legacyLDAPYAMLState, and a leaked YAML
// block would let ANY later test that enables a registry LDAP profile flip
// the process-global legacy_ldap_retired flag — which makes cfg.IsConfigured()
// true for the rest of the suite (the exact shuffle failure seen in
// TestAPIAuthLogin_AuthDisabled).
func resetLegacyAuthGlobals(t *testing.T) {
	t.Helper()
	cfg.mu.RLock()
	origProv := cfg.provider
	cfg.mu.RUnlock()
	origLogin := oidcLoginURL
	legacyLDAPYAMLState.mu.Lock()
	origYAML := legacyLDAPYAMLState.cfg
	legacyLDAPYAMLState.mu.Unlock()
	origRetired := legacyLDAPRetiredFlag.Load()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.provider = origProv
		cfg.mu.Unlock()
		oidcLoginURL = origLogin
		legacyLDAPYAMLState.mu.Lock()
		legacyLDAPYAMLState.cfg = origYAML
		legacyLDAPYAMLState.mu.Unlock()
		legacyLDAPRetiredFlag.Store(origRetired)
	})
}

func TestResolveLegacyAuthProvidersStartupConfig_CopiesFields(t *testing.T) {
	fc := &FileConfig{
		LDAP: LDAPConfig{URL: "ldaps://ldap.example", BaseDN: "dc=example"},
		OIDC: OIDCConfig{IntrospectionURL: "https://idp.example/introspect", ClientID: "cid"},
	}
	got := resolveLegacyAuthProvidersStartupConfig(fc, "admin")
	if got.LDAP.URL != "ldaps://ldap.example" {
		t.Errorf("LDAP.URL: got %q", got.LDAP.URL)
	}
	if got.OIDC.IntrospectionURL != "https://idp.example/introspect" {
		t.Errorf("OIDC.IntrospectionURL: got %q", got.OIDC.IntrospectionURL)
	}
	if got.LocalUser != "admin" {
		t.Errorf("LocalUser: got %q", got.LocalUser)
	}
}

func TestLoadLegacyAuthProviders_LDAPWins(t *testing.T) {
	resetLegacyAuthGlobals(t)
	ensureLegacyAuthTestLogger(t)
	c := legacyAuthProvidersStartupConfig{
		LDAP: LDAPConfig{URL: "ldaps://ldap.example", BaseDN: "dc=example"},
		// OIDC also set, but LDAP precedence means OIDC is ignored.
		OIDC: OIDCConfig{IntrospectionURL: "https://idp.example/introspect", ClientID: "cid"},
	}
	if err := loadLegacyAuthProviders(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg.mu.RLock()
	name := ""
	if cfg.provider != nil {
		name = cfg.provider.Name()
	}
	cfg.mu.RUnlock()
	if name != "ldap" {
		t.Errorf("expected ldap provider; got %q", name)
	}
}

func TestLoadLegacyAuthProviders_LDAPConfigError(t *testing.T) {
	resetLegacyAuthGlobals(t)
	ensureLegacyAuthTestLogger(t)
	// BaseDN missing triggers NewLDAPAuth error.
	c := legacyAuthProvidersStartupConfig{
		LDAP: LDAPConfig{URL: "ldaps://ldap.example"},
	}
	err := loadLegacyAuthProviders(c)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "LDAP config error:") {
		t.Errorf("error prefix mismatch: %v", err)
	}
}

func TestLoadLegacyAuthProviders_OIDCWhenLDAPAbsent(t *testing.T) {
	resetLegacyAuthGlobals(t)
	ensureLegacyAuthTestLogger(t)
	c := legacyAuthProvidersStartupConfig{
		OIDC: OIDCConfig{
			IntrospectionURL: "https://idp.example/introspect",
			ClientID:         "cid",
			LoginURL:         "https://idp.example/authorize",
		},
	}
	if err := loadLegacyAuthProviders(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg.mu.RLock()
	name := ""
	if cfg.provider != nil {
		name = cfg.provider.Name()
	}
	cfg.mu.RUnlock()
	if name != "oidc" {
		t.Errorf("expected oidc provider; got %q", name)
	}
	if oidcLoginURL != "https://idp.example/authorize" {
		t.Errorf("oidcLoginURL not applied; got %q", oidcLoginURL)
	}
}

func TestLoadLegacyAuthProviders_OIDCConfigError(t *testing.T) {
	resetLegacyAuthGlobals(t)
	ensureLegacyAuthTestLogger(t)
	// ClientID missing triggers NewOIDCAuth error.
	c := legacyAuthProvidersStartupConfig{
		OIDC: OIDCConfig{IntrospectionURL: "https://idp.example/introspect"},
	}
	err := loadLegacyAuthProviders(c)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "OIDC config error:") {
		t.Errorf("error prefix mismatch: %v", err)
	}
}

func TestLoadLegacyAuthProviders_LocalOnlyNoError(t *testing.T) {
	resetLegacyAuthGlobals(t)
	ensureLegacyAuthTestLogger(t)
	c := legacyAuthProvidersStartupConfig{LocalUser: "admin"}
	if err := loadLegacyAuthProviders(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadLegacyAuthProviders_NoProviderNoUser(t *testing.T) {
	resetLegacyAuthGlobals(t)
	ensureLegacyAuthTestLogger(t)
	if err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
