package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestOIDCFlowProvider(t *testing.T, body map[string]any, cfg *OIDCProfileConfig) (*httptest.Server, *OIDCFlowProvider) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	if cfg == nil {
		cfg = &OIDCProfileConfig{ClientID: "culvert-client", ClientSecret: "secret"}
	}
	prov := &OIDCFlowProvider{
		profile: &IdPProfile{ID: "oidc-test-id", Name: "OIDC Test"},
		cfg:     cfg,
		disc:    &oidcDiscoveryDoc{IntrospectionEndpoint: srv.URL},
		client:  srv.Client(),
	}
	return srv, prov
}

func TestOIDCFlowIntrospection_RequiredAudience(t *testing.T) {
	tests := []struct {
		name string
		aud  any
		want bool
	}{
		{name: "match string", aud: "culvert-api", want: true},
		{name: "match array", aud: []string{"other", "culvert-api"}, want: true},
		{name: "mismatch", aud: "other-api", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, prov := newTestOIDCFlowProvider(t, map[string]any{
				"active": true,
				"sub":    "alice",
				"aud":    tt.aud,
			}, &OIDCProfileConfig{
				ClientID:         "culvert-client",
				ClientSecret:     "secret",
				RequiredAudience: "culvert-api",
			})
			defer srv.Close()

			id, ok := prov.ResolveIdentity("alice", "access-token")
			if ok != tt.want {
				t.Fatalf("ResolveIdentity ok=%v, want %v (id=%+v)", ok, tt.want, id)
			}
		})
	}
}

func TestOIDCFlowIntrospection_GroupsFeedPolicy(t *testing.T) {
	srv, prov := newTestOIDCFlowProvider(t, map[string]any{
		"active": true,
		"sub":    "alice",
		"groups": []string{"users", "finance"},
	}, nil)
	defer srv.Close()

	id, ok := prov.ResolveIdentity("alice", "access-token")
	if !ok || id == nil {
		t.Fatalf("ResolveIdentity failed: ok=%v id=%+v", ok, id)
	}
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:    1,
		Name:        "finance-only",
		SourceGroup: "finance",
		Action:      ActionAllow,
	})

	match := ps.Evaluate("10.0.0.1", id.Sub, id.Provider, "app.example.com", id.Groups)
	if match == nil || match.Action != ActionAllow {
		t.Fatalf("expected finance group policy allow, got %+v (groups=%v)", match, id.Groups)
	}
}

func TestOIDCFlowIntrospection_ConfiguredGroupsClaim(t *testing.T) {
	srv, prov := newTestOIDCFlowProvider(t, map[string]any{
		"active": true,
		"sub":    "alice",
		"roles":  "admin",
	}, &OIDCProfileConfig{
		ClientID:     "culvert-client",
		ClientSecret: "secret",
		GroupsClaim:  "roles",
	})
	defer srv.Close()

	id, ok := prov.ResolveIdentity("alice", "access-token")
	if !ok || id == nil {
		t.Fatalf("ResolveIdentity failed: ok=%v id=%+v", ok, id)
	}
	if len(id.Groups) != 1 || id.Groups[0] != "admin" {
		t.Fatalf("groups = %v, want [admin]", id.Groups)
	}
}
