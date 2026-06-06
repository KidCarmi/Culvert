package main

import "testing"

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

	applyConfigSnapshot(ConfigSnapshot{
		Version: 2,
		IdPProfiles: []*IdPProfile{{
			ID:      "bad-enabled-saml",
			Name:    "Bad Enabled SAML",
			Type:    IdPTypeSAML,
			Enabled: true,
			SAML:    nil,
		}},
	})

	if idpRegistry.Get("bad-enabled-saml") != nil {
		t.Fatal("bad IdP snapshot replaced registry")
	}
	if idpRegistry.Get("working") == nil {
		t.Fatal("working IdP profile was lost after rejected snapshot")
	}
}
