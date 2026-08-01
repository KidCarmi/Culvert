package authn

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func resolverFor(k *esKey) *StaticKeyResolver {
	r := NewStaticKeyResolver()
	r.Add(testIssuer, k.kid, k.priv.Public())
	return r
}

func TestJWTValid(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	tok := mintJWT(esHeader("k1"), baseGatewayClaims(now), k)
	claims, err := ValidateJWT(tok, gatewayConfig(t), resolverFor(k), now)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Subject != "user-1" || claims.ClientID != testClientG || claims.Tenant != testTenant {
		t.Fatalf("claims not extracted: %+v", claims)
	}
}

func TestJWTNegativeMatrix(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	cfg := gatewayConfig(t)
	res := resolverFor(k)

	// mutate returns a token whose claims start from the valid base then are patched.
	mutate := func(patch func(m map[string]any)) string {
		c := baseGatewayClaims(now)
		patch(c)
		return mintJWT(esHeader("k1"), c, k)
	}

	cases := []struct {
		name string
		tok  string
		want mcperr.Reason
	}{
		{"malformed-compact", "not.a.jwt.at.all", mcperr.ReasonMalformedToken},
		{"two-segments", "aaa.bbb", mcperr.ReasonMalformedToken},
		{"wrong-issuer", mutate(func(m map[string]any) { m["iss"] = "https://evil/x" }), mcperr.ReasonSignatureInvalid},
		{"missing-audience", mutate(func(m map[string]any) { delete(m, "aud") }), mcperr.ReasonAudienceMissing},
		{"wrong-audience", mutate(func(m map[string]any) { m["aud"] = "https://evil/resource" }), mcperr.ReasonAudienceRejected},
		{"upstream-as-audience", mutate(func(m map[string]any) { m["aud"] = "https://upstream.example/mcp" }), mcperr.ReasonAudienceRejected},
		{"client-id-as-audience", mutate(func(m map[string]any) { m["aud"] = testClientG }), mcperr.ReasonAudienceRejected},
		{"management-resource-on-gateway", mutate(func(m map[string]any) { m["aud"] = mgmtResource }), mcperr.ReasonAudienceRejected},
		{"expired", mutate(func(m map[string]any) { m["exp"] = now.Add(-2 * time.Hour).Unix() }), mcperr.ReasonTokenExpired},
		{"missing-exp", mutate(func(m map[string]any) { delete(m, "exp") }), mcperr.ReasonTokenExpired},
		{"not-yet-valid", mutate(func(m map[string]any) { m["nbf"] = now.Add(10 * time.Minute).Unix() }), mcperr.ReasonTokenNotYetValid},
		{"excessive-ttl", mutate(func(m map[string]any) { m["exp"] = now.Add(48 * time.Hour).Unix() }), mcperr.ReasonTokenTTLExceeded},
		{"malformed-numeric-date", mutate(func(m map[string]any) { m["exp"] = "not-a-number" }), mcperr.ReasonMalformedToken},
		{"missing-subject", mutate(func(m map[string]any) { delete(m, "sub") }), mcperr.ReasonDelegationChainInvalid},
		{"missing-client", mutate(func(m map[string]any) { delete(m, "client_id") }), mcperr.ReasonDelegationChainInvalid},
		{"missing-tenant", mutate(func(m map[string]any) { delete(m, "tenant") }), mcperr.ReasonTenantMismatch},
		{"missing-scope", mutate(func(m map[string]any) { delete(m, "scope") }), mcperr.ReasonScopeMissing},
		{"wrong-capability-scope", mutate(func(m map[string]any) { m["scope"] = mgmtScope }), mcperr.ReasonScopeMissing},
		{"blanket-scope", mutate(func(m map[string]any) { m["scope"] = gwScope + " mcp" }), mcperr.ReasonScopeMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateJWT(tc.tok, cfg, res, now)
			if got := mcperr.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %v, want %v (err=%v)", got, tc.want, err)
			}
		})
	}
}

func TestJWTAlgNone(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	// alg=none header, empty signature.
	tok := mintJWT(map[string]any{"alg": "none", "kid": "k1"}, baseGatewayClaims(now), k)
	if got := mcperr.ReasonOf(mustErr(ValidateJWT(tok, gatewayConfig(t), resolverFor(k), now))); got != mcperr.ReasonUnsupportedAlgorithm {
		t.Fatalf("alg=none must be unsupported_algorithm, got %v", got)
	}
	// missing alg.
	tok2 := mintJWT(map[string]any{"kid": "k1"}, baseGatewayClaims(now), k)
	if got := mcperr.ReasonOf(mustErr(ValidateJWT(tok2, gatewayConfig(t), resolverFor(k), now))); got != mcperr.ReasonUnsupportedAlgorithm {
		t.Fatalf("missing alg must be unsupported_algorithm, got %v", got)
	}
}

func TestJWTAlgConfusion(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	// Sign with ES256 but claim RS256 in the header: the resolved EC key cannot
	// serve RS256 → algorithm confusion rejected.
	tok := mintJWT(map[string]any{"alg": "RS256", "kid": "k1"}, baseGatewayClaims(now), k)
	if got := mcperr.ReasonOf(mustErr(ValidateJWT(tok, gatewayConfig(t), resolverFor(k), now))); got != mcperr.ReasonUnsupportedAlgorithm {
		t.Fatalf("algorithm confusion must be rejected, got %v", got)
	}
}

func TestJWTUnknownKidAndBadSig(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	other := newESKey(t, "k1")
	// Unknown kid (resolver has k1's key, token says k9).
	tok := mintJWT(esHeader("k9"), baseGatewayClaims(now), k)
	if got := mcperr.ReasonOf(mustErr(ValidateJWT(tok, gatewayConfig(t), resolverFor(k), now))); got != mcperr.ReasonSignatureInvalid {
		t.Fatalf("unknown kid must be signature_invalid, got %v", got)
	}
	// Valid kid but signed by a different key → bad signature.
	tok2 := mintJWT(esHeader("k1"), baseGatewayClaims(now), other)
	if got := mcperr.ReasonOf(mustErr(ValidateJWT(tok2, gatewayConfig(t), resolverFor(k), now))); got != mcperr.ReasonSignatureInvalid {
		t.Fatalf("bad signature must be signature_invalid, got %v", got)
	}
}

func mustErr(_ *Claims, err error) error { return err }
