package main

import (
	"path/filepath"
	"testing"
)

func withIdPSyncGlobals(t *testing.T) {
	t.Helper()
	origRegistry := idpRegistry
	origBaseURL := cfg.ProxyBaseURL()
	origTrustForwarded := trustForwardedHeaders
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() {
		idpRegistry = origRegistry
		SetProxyBaseURL(origBaseURL)
		trustForwardedHeaders = origTrustForwarded
	})
}

func TestApplyConfigSnapshot_SyncsIdPProfilesAndAuthBaseURL(t *testing.T) {
	withIdPSyncGlobals(t)

	applyConfigSnapshot(ConfigSnapshot{
		Version:               1,
		ProxyBaseURL:          "https://proxy.example.com/culvert",
		TrustForwardedHeaders: true,
		IdPProfiles: []*IdPProfile{{
			ID:           "saml-disabled",
			Name:         "SAML Disabled",
			Type:         IdPTypeSAML,
			Enabled:      false,
			EmailDomains: []string{"example.com"},
			SAML: &SAMLProfileConfig{
				MetadataXML:     "<EntityDescriptor/>",
				GroupsAttribute: "groups",
			},
		}},
	})

	if got := cfg.ProxyBaseURL(); got != "https://proxy.example.com/culvert" {
		t.Fatalf("ProxyBaseURL = %q, want external CP value", got)
	}
	if !trustForwardedHeaders {
		t.Fatal("trustForwardedHeaders = false, want true")
	}
	got := idpRegistry.Get("saml-disabled")
	if got == nil {
		t.Fatal("synced IdP profile missing")
	}
	if got.SAML == nil || got.SAML.MetadataXML == "" {
		t.Fatalf("synced inline SAML metadata lost: %+v", got.SAML)
	}
	if providers := idpRegistry.EnabledProviders(); len(providers) != 0 {
		t.Fatalf("disabled profile compiled %d live provider(s), want 0", len(providers))
	}
}

func TestApplyConfigSnapshot_BadIdPProfileDoesNotReplaceWorkingRegistry(t *testing.T) {
	withIdPSyncGlobals(t)
	if err := idpRegistry.ReplaceAll([]*IdPProfile{{
		ID:      "working",
		Name:    "Working Disabled",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML: &SAMLProfileConfig{
			MetadataXML: "<EntityDescriptor/>",
		},
	}}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	if err := syncSnapshotIdPProfiles(ConfigSnapshot{
		Version: 2,
		IdPProfiles: []*IdPProfile{{
			ID:      "bad-enabled-saml",
			Name:    "Bad Enabled SAML",
			Type:    IdPTypeSAML,
			Enabled: true,
			SAML:    nil,
		}},
	}); err == nil {
		t.Fatal("syncSnapshotIdPProfiles accepted bad enabled IdP profile")
	}

	if idpRegistry.Get("bad-enabled-saml") != nil {
		t.Fatal("bad IdP snapshot replaced registry")
	}
	if idpRegistry.Get("working") == nil {
		t.Fatal("working IdP profile was lost after rejected snapshot")
	}
}

func TestApplyConfigSnapshot_BadIdPProfileDoesNotPublishPolicy(t *testing.T) {
	withIdPSyncGlobals(t)
	snapshotPolicyStoreForTest(t)
	policyStore.path = filepath.Join(t.TempDir(), "policy.json")
	policyStore.ReplaceAll([]PolicyRule{{Name: "old-policy", Action: ActionAllow}})
	before := policyStore.List()
	err := applyConfigSnapshot(ConfigSnapshot{
		Version:     2,
		PolicyRules: []PolicyRule{{Name: "must-not-publish", Action: ActionAllow}},
		IdPProfiles: []*IdPProfile{{ID: "bad-enabled-saml", Name: "Bad", Type: IdPTypeSAML, Enabled: true}},
	})
	if err == nil {
		t.Fatal("accepted invalid IdP snapshot")
	}
	if after := policyStore.List(); !sameRuleSet(before, after) {
		t.Fatalf("invalid IdP snapshot published policy: before=%v after=%v", before, after)
	}
}

func TestPublishCurrentConfigSnapshotIncludesIdPAndAuthBaseURL(t *testing.T) {
	withIdPSyncGlobals(t)
	origStore := globalConfigStore
	globalConfigStore = &ConfigStore{}
	t.Cleanup(func() {
		globalConfigStore = origStore
	})

	SetProxyBaseURL("https://cluster.example.com/proxy/")
	trustForwardedHeaders = true
	if err := idpRegistry.Upsert(&IdPProfile{
		ID:      "cluster-saml",
		Name:    "Cluster SAML",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML: &SAMLProfileConfig{
			MetadataXML: "<EntityDescriptor/>",
		},
	}); err != nil {
		t.Fatalf("seed IdP profile: %v", err)
	}

	publishCurrentConfigSnapshot()
	snap := globalConfigStore.Get()
	if snap.ProxyBaseURL != "https://cluster.example.com/proxy" {
		t.Fatalf("snapshot ProxyBaseURL = %q, want published external URL", snap.ProxyBaseURL)
	}
	if !snap.TrustForwardedHeaders {
		t.Fatal("snapshot TrustForwardedHeaders = false, want true")
	}
	if len(snap.IdPProfiles) != 1 || snap.IdPProfiles[0].ID != "cluster-saml" {
		t.Fatalf("snapshot IdPProfiles = %+v, want cluster-saml", snap.IdPProfiles)
	}
}
