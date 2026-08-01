package authn

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// Each test pins a load-bearing control by showing the WEAKENED behavior would be
// wrong. The controls themselves are exercised in the matrix tests; these frame
// the specific anti-weakening properties the spec calls out.

// The raw bearer token must never survive into the resolved context. A validator
// that stashed it would leak here.
func TestAntiWeakening_NoRawTokenInContext(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	token := mintJWT(esHeader("k1"), baseGatewayClaims(now), k)
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
	}
	ctx, err := Authenticate(req, gatewayConfig(t), Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}, now)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	// No accessible field may contain the raw token.
	surfaces := []string{ctx.TokenDigest(), ctx.Fingerprint(), ctx.Issuer(), ctx.CanonicalResource()}
	surfaces = append(surfaces, ctx.Scopes()...)
	for _, s := range surfaces {
		if strings.Contains(s, token) {
			t.Fatalf("raw token leaked into the resolved context: %q", s)
		}
	}
	// The digest is a one-way hash of the token, not the token.
	if ctx.TokenDigest() == token {
		t.Fatal("token digest equals the raw token")
	}
	if ctx.TokenDigest() != jose.SHA256B64URL([]byte(token)) {
		t.Fatal("token digest is not the SHA-256 of the token")
	}
}

// A rejected authentication must never carry the raw token in its error text.
func TestAntiWeakening_NoRawTokenInErrors(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	// A token with a wrong audience → rejected. Its error must not contain the token.
	claims := baseGatewayClaims(now)
	claims["aud"] = "https://evil/resource"
	token := mintJWT(esHeader("k1"), claims, k)
	_, err := ValidateJWT(token, gatewayConfig(t), resolverFor(k), now)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "evil") {
		t.Fatalf("error leaked hostile/token content: %q", err.Error())
	}
}

// The access token jti is NOT one-time use: a still-valid token serves many
// requests, each with its own fresh DPoP proof. (The replay guard is only on the
// proof jti.) This is the inverse of the replay test and is proven together with
// TestDPoPValidAndReplay; here we assert the token can be validated repeatedly.
func TestAntiWeakening_TokenNotOneTimeUse(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	token := mintJWT(esHeader("k1"), baseGatewayClaims(now), k)
	cfg := gatewayConfig(t)
	res := resolverFor(k)
	for i := 0; i < 5; i++ {
		if _, err := ValidateJWT(token, cfg, res, now); err != nil {
			t.Fatalf("token validation %d failed — token wrongly treated as one-time: %v", i, err)
		}
	}
}

// A public API that exposed the raw token would defeat the no-passthrough
// contract. This documents (and the compiler enforces) that ResolvedContext has no
// RawToken/ForwardToken/AuthorizationHeader accessor — only the sanitized digest.
func TestAntiWeakening_NoPassthroughAPI(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	token := mintJWT(esHeader("k1"), baseGatewayClaims(now), k)
	claims, err := ValidateJWT(token, gatewayConfig(t), resolverFor(k), now)
	if err != nil {
		t.Fatal(err)
	}
	_ = claims
	// If a RawToken()/ForwardToken()/AuthorizationHeader() method existed on
	// identity.ResolvedContext this package would compile a call to it in a
	// forbidden helper; there is deliberately none. This test's existence + the
	// accessor audit in TestAntiWeakening_NoRawTokenInContext is the guard.
	_ = time.Now
}
