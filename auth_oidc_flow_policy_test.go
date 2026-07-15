package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newRawTestOIDCFlowProvider(t *testing.T, status int, body string, cfg *OIDCProfileConfig) (*httptest.Server, *OIDCFlowProvider) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
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

func newTestOIDCFlowProvider(t *testing.T, body any, cfg *OIDCProfileConfig) (*httptest.Server, *OIDCFlowProvider) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal introspection response: %v", err)
	}
	return newRawTestOIDCFlowProvider(t, http.StatusOK, string(raw), cfg)
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

func TestOIDCFlowIntrospectionRejectsMissingCanonicalIdentity(t *testing.T) {
	srv, prov := newTestOIDCFlowProvider(t, map[string]any{"active": true}, nil)
	defer srv.Close()
	if id, ok := prov.ResolveIdentity("caller-controlled", "access-token"); ok || id != nil {
		t.Fatalf("ResolveIdentity = (%+v, %v), want fail-closed rejection without token identity", id, ok)
	}
}

func TestOIDCFlowIntrospectionRejectsExpiredActiveToken(t *testing.T) {
	srv, prov := newTestOIDCFlowProvider(t, map[string]any{
		"active": true,
		"sub":    "expired-subject",
		"exp":    time.Now().Add(-time.Minute).Unix(),
	}, nil)
	defer srv.Close()
	if id, ok := prov.ResolveIdentity("caller-controlled", "expired-token"); ok || id != nil {
		t.Fatalf("ResolveIdentity = (%+v, %v), want rejection of active token past exp", id, ok)
	}
}

func TestOIDCFlowIntrospectionRejectsPresentInvalidExpiry(t *testing.T) {
	for name, exp := range map[string]any{
		"null":     nil,
		"string":   "123",
		"fraction": float64(time.Now().Add(time.Hour).Unix()) + 0.5,
	} {
		t.Run(name, func(t *testing.T) {
			srv, prov := newTestOIDCFlowProvider(t, map[string]any{
				"active": true,
				"sub":    "invalid-exp-subject",
				"exp":    exp,
			}, nil)
			defer srv.Close()
			if id, ok := prov.ResolveIdentity("caller-controlled", "invalid-exp-token"); ok || id != nil {
				t.Fatalf("ResolveIdentity = (%+v, %v), want rejection of present exp=%v", id, ok, exp)
			}
		})
	}
}

func TestOIDCFlowIntrospectionRejectsSubFloatPrecisionExpiry(t *testing.T) {
	for _, rawExp := range []string{"4102444800.0000001", "4102444800.0000000001"} {
		t.Run(rawExp, func(t *testing.T) {
			body := json.RawMessage(`{"active":true,"sub":"fractional-subject","exp":` + rawExp + `}`)
			srv, prov := newTestOIDCFlowProvider(t, body, nil)
			defer srv.Close()
			if id, ok := prov.ResolveIdentity("caller-controlled", "fractional-token"); ok || id != nil {
				t.Fatalf("ResolveIdentity = (%+v, %v), want rejection of exact fractional exp=%s", id, ok, rawExp)
			}
		})
	}
}

func TestOIDCFlowIntrospectionRejectsInvalidResponseEnvelope(t *testing.T) {
	active := `{"active":true,"sub":"envelope-subject"}`
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"non-200":           {status: http.StatusUnauthorized, body: active},
		"concatenated-json": {status: http.StatusOK, body: active + `{}`},
		"trailing-garbage":  {status: http.StatusOK, body: active + `garbage`},
		"oversized":         {status: http.StatusOK, body: active + strings.Repeat(" ", (64<<10)+1)},
	} {
		t.Run(name, func(t *testing.T) {
			srv, prov := newRawTestOIDCFlowProvider(t, tc.status, tc.body, nil)
			defer srv.Close()
			if id, ok := prov.ResolveIdentity("caller-controlled", "envelope-token"); ok || id != nil {
				t.Fatalf("ResolveIdentity = (%+v, %v), want response-envelope rejection", id, ok)
			}
		})
	}
}

func TestOIDCFlowIntrospectionCanonicalIdentityFallback(t *testing.T) {
	srv, prov := newTestOIDCFlowProvider(t, map[string]any{
		"active":   true,
		"sub":      "  ",
		"username": " token-user ",
	}, nil)
	defer srv.Close()
	id, ok := prov.ResolveIdentity("caller-controlled", "access-token")
	if !ok || id == nil || id.Sub != " token-user " {
		t.Fatalf("ResolveIdentity = (%+v, %v), want exact nonblank token username", id, ok)
	}
}
