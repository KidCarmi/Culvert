package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The registry OIDC provider's credential path (a token presented as the
// Proxy-Authorization password) has two ways to say yes: a JWT that validates
// locally against the JWKS, and RFC 7662 introspection. requiredScope and
// requiredAudience ("Optional enforcement filters", OIDCProfileConfig) are
// evaluated ONLY on the introspection response, so the local-JWT answer must
// not be allowed to stand in for it when either filter is configured.

// filteredOIDCFlowProvider builds a provider that can validate a JWT locally
// AND reach an introspection endpoint that answers with introspection. hits
// counts the introspection round trips.
func filteredOIDCFlowProvider(t *testing.T, cfg *OIDCProfileConfig, introspection map[string]any) (prov *OIDCFlowProvider, token string, hits *atomic.Int64) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	hits = &atomic.Int64{}
	prov = oidcFlowProviderForTest(t, key)
	prov.cfg = cfg
	if introspection != nil {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(introspection)
		}))
		t.Cleanup(srv.Close)
		prov.disc.IntrospectionEndpoint = srv.URL
		prov.client = srv.Client()
	}
	// A genuine token from this IdP for this client: right issuer, right
	// audience (the client id), unexpired, signed by a key in the JWKS.
	return prov, mintIDTokenForTest(t, key, prov.disc.Issuer), hits
}

func TestOIDCFlowCredential_RequiredFiltersApplyToLocallyValidJWT(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	tests := []struct {
		name string
		cfg  *OIDCProfileConfig
	}{
		{"required scope", &OIDCProfileConfig{ClientID: "culvert-client", RequiredScope: "proxy:access"}},
		{"required audience", &OIDCProfileConfig{ClientID: "culvert-client", RequiredAudience: "culvert-api"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The IdP says the token is active but carries neither the required
			// scope nor the required audience: the filter's answer is "no".
			prov, token, hits := filteredOIDCFlowProvider(t, tt.cfg, map[string]any{
				"active": true, "sub": "alice", "scope": "openid email", "aud": "culvert-client", "exp": exp,
			})
			id, ok := prov.ResolveIdentity("alice", token)
			if ok {
				t.Fatalf("a token the configured filter refuses was accepted via the local-JWT shortcut (id=%+v)", id)
			}
			if hits.Load() != 1 {
				t.Fatalf("introspection round trips = %d, want 1: the filter can only be evaluated there", hits.Load())
			}
		})
	}
}

// With a filter configured and no introspection endpoint the filter cannot be
// evaluated at all, so nothing may be admitted on the credential path.
func TestOIDCFlowCredential_RequiredFilterWithoutIntrospectionDenies(t *testing.T) {
	prov, token, _ := filteredOIDCFlowProvider(t,
		&OIDCProfileConfig{ClientID: "culvert-client", RequiredScope: "proxy:access"}, nil)
	if id, ok := prov.ResolveIdentity("alice", token); ok {
		t.Fatalf("accepted a token with requiredScope set and no way to evaluate it (id=%+v)", id)
	}
}

// Negative controls: the fix must not change either path when it is not the
// one being closed.
func TestOIDCFlowCredential_RequiredFilterControls(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()

	t.Run("filter satisfied by introspection is admitted", func(t *testing.T) {
		prov, token, hits := filteredOIDCFlowProvider(t,
			&OIDCProfileConfig{ClientID: "culvert-client", RequiredScope: "proxy:access"},
			map[string]any{"active": true, "sub": "alice", "scope": "openid proxy:access", "exp": exp})
		id, ok := prov.ResolveIdentity("alice", token)
		if !ok || id == nil || id.Sub != "alice" {
			t.Fatalf("ResolveIdentity = (%+v, %v), want alice admitted", id, ok)
		}
		if hits.Load() != 1 {
			t.Fatalf("introspection round trips = %d, want 1", hits.Load())
		}
	})

	t.Run("no filter keeps the local-JWT answer and makes no round trip", func(t *testing.T) {
		prov, token, hits := filteredOIDCFlowProvider(t,
			&OIDCProfileConfig{ClientID: "culvert-client"},
			map[string]any{"active": false})
		id, ok := prov.ResolveIdentity("alice", token)
		if !ok || id == nil || id.Sub != "alice" {
			t.Fatalf("ResolveIdentity = (%+v, %v), want alice admitted as before", id, ok)
		}
		if hits.Load() != 0 {
			t.Fatalf("introspection round trips = %d, want 0 (unchanged behaviour)", hits.Load())
		}
	})
}
