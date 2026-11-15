package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// oidcUserinfoFixture is a fake IdP for the authorization-code callback: a
// token endpoint that returns a correctly signed ID token for idTokenSub, and
// a userinfo endpoint that answers with whatever userinfo holds.
type oidcUserinfoFixture struct {
	prov  *OIDCFlowProvider
	state string
}

func newOIDCUserinfoFixture(t *testing.T, idTokenSub string, userinfo map[string]any) *oidcUserinfoFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	const (
		kid      = "userinfo-sub-kid"
		clientID = "userinfo-sub-client"
		nonce    = "userinfo-sub-nonce"
	)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
		"iss":   srv.URL,
		"aud":   clientID,
		"sub":   idTokenSub,
		"nonce": nonce,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = kid
	rawIDToken, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "id_token": rawIDToken})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(userinfo)
	})

	f := &oidcUserinfoFixture{
		prov: &OIDCFlowProvider{
			profile: &IdPProfile{ID: "userinfo-sub-idp"},
			cfg:     &OIDCProfileConfig{ClientID: clientID},
			disc: &oidcDiscoveryDoc{
				Issuer:           srv.URL,
				TokenEndpoint:    srv.URL + "/token",
				UserinfoEndpoint: srv.URL + "/userinfo",
			},
			jwks: &jwksCache{
				keys:      map[string]interface{}{kid: &key.PublicKey},
				fetchedAt: time.Now(),
			},
			client: srv.Client(),
		},
		state: "userinfo-sub-state-" + t.Name(),
	}
	globalPKCEStore.Set(f.state, "userinfo-sub-test", &pkceEntry{
		nonce:      nonce,
		providerID: f.prov.profile.ID,
	})
	t.Cleanup(func() { globalPKCEStore.Pop(f.state) })
	return f
}

func (f *oidcUserinfoFixture) exchange(t *testing.T) *Identity {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://proxy.test/auth/oidc/callback", http.NoBody)
	id, err := f.prov.ExchangeCode(r, "code", f.state)
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	return id
}

// OIDC Core §5.3.2: the userinfo `sub` MUST exactly match the ID token `sub`,
// and when it does not the userinfo values MUST NOT be used. The ID token is
// the only signed statement about who logged in; the userinfo response is
// plain JSON fetched with a bearer token. Without the comparison, a userinfo
// answer about a DIFFERENT subject donates its groups — which identity- and
// group-scoped policy matches on — to the session being minted.
func TestOIDCUserinfo_MismatchedSubIsNotMergedIntoIdentity(t *testing.T) {
	f := newOIDCUserinfoFixture(t, "alice", map[string]any{
		"sub":    "mallory",
		"email":  "mallory@example.test",
		"name":   "Mallory",
		"groups": []string{"proxy-admins"},
	})
	id := f.exchange(t)
	if id.Sub != "alice" {
		t.Fatalf("Sub = %q, want the ID token subject", id.Sub)
	}
	if len(id.Groups) != 0 || id.Email != "" || id.Name != "" {
		t.Errorf("session for sub=%q carries claims of userinfo sub=mallory: groups=%v email=%q name=%q; a mismatched userinfo response must be discarded",
			id.Sub, id.Groups, id.Email, id.Name)
	}
}

// A userinfo response that names no subject at all cannot be shown to describe
// the ID token's subject either.
func TestOIDCUserinfo_MissingSubIsNotMergedIntoIdentity(t *testing.T) {
	f := newOIDCUserinfoFixture(t, "alice", map[string]any{
		"groups": []string{"proxy-admins"},
	})
	if id := f.exchange(t); len(id.Groups) != 0 {
		t.Errorf("groups = %v from a userinfo response with no sub; want none", id.Groups)
	}
}

// Negative control: the matching-subject enrichment keeps working.
func TestOIDCUserinfo_MatchingSubStillEnriches(t *testing.T) {
	f := newOIDCUserinfoFixture(t, "alice", map[string]any{
		"sub":    "alice",
		"email":  "alice@example.test",
		"name":   "Alice",
		"groups": []string{"engineering"},
	})
	id := f.exchange(t)
	if id.Email != "alice@example.test" || id.Name != "Alice" || len(id.Groups) != 1 || id.Groups[0] != "engineering" {
		t.Errorf("identity = %+v, want userinfo enrichment for the matching subject", id)
	}
	if id.Provider != "userinfo-sub-idp" {
		t.Errorf("Provider = %q", id.Provider)
	}
}
