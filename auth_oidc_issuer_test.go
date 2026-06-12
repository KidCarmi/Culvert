package main

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// validateIDToken must pin the iss claim to the discovery document's issuer
// (OIDC Core §3.1.3.7 step 2). Multi-tenant IdPs sign every tenant's tokens
// with the same JWKS — without the issuer check, a token minted by an
// attacker-controlled tenant (same signing keys, same client_id audience)
// would authenticate against this proxy.

func oidcFlowProviderForTest(t *testing.T, key *rsa.PrivateKey) *OIDCFlowProvider {
	t.Helper()
	return &OIDCFlowProvider{
		profile: &IdPProfile{ID: "test-idp"},
		cfg:     &OIDCProfileConfig{ClientID: "culvert-client"},
		disc:    &oidcDiscoveryDoc{Issuer: "https://idp.example.test/realms/culvert"},
		jwks: &jwksCache{
			keys:      map[string]interface{}{"test-kid": &key.PublicKey},
			fetchedAt: time.Now(),
		},
	}
}

func mintIDTokenForTest(t *testing.T, key *rsa.PrivateKey, issuer string) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
		"iss": issuer,
		"aud": "culvert-client",
		"sub": "alice",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "test-kid"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign test id_token: %v", err)
	}
	return raw
}

func TestValidateIDToken_AcceptsMatchingIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := oidcFlowProviderForTest(t, key)

	raw := mintIDTokenForTest(t, key, "https://idp.example.test/realms/culvert")
	id, err := p.validateIDToken(raw, "")
	if err != nil {
		t.Fatalf("validateIDToken with matching issuer: %v", err)
	}
	if id.Sub != "alice" {
		t.Fatalf("Sub = %q, want %q", id.Sub, "alice")
	}
}

func TestValidateIDToken_RejectsForeignIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := oidcFlowProviderForTest(t, key)

	// Same signing key, same audience — only the issuer differs. This is
	// the multi-tenant IdP attack shape.
	raw := mintIDTokenForTest(t, key, "https://idp.example.test/realms/attacker")
	if _, err := p.validateIDToken(raw, ""); err == nil {
		t.Fatal("validateIDToken accepted a token from a foreign issuer signed with the same JWKS")
	} else if !strings.Contains(err.Error(), "iss") {
		t.Fatalf("rejection should mention issuer validation, got: %v", err)
	}
}
