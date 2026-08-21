package authn

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jose"
)

// FuzzValidateJWT proves JWT validation never panics on arbitrary input, never
// leaks the raw token in an error, and only ever accepts a token that survives
// full validation (arbitrary bytes cannot forge the trusted-key signature).
func FuzzValidateJWT(f *testing.F) {
	now := fixedClock()
	k := newESKey(f, "k1")
	res := resolverFor(k)
	cfg := gatewayConfig(f)
	seeds := []string{
		"", "a", "a.b", "a.b.c",
		mintJWT(esHeader("k1"), baseGatewayClaims(now), k),
		"eyJhbGciOiJub25lIn0.eyJ9.",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		claims, err := ValidateJWT(token, cfg, res, now)
		if err != nil {
			if len(token) > 8 && strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked the raw token")
			}
			return
		}
		if claims.Issuer != testIssuer {
			t.Fatalf("accepted a token with a foreign issuer: %q", claims.Issuer)
		}
	})
}

// FuzzExtractClaims proves the claim normalizer never panics on arbitrary JSON.
func FuzzExtractClaims(f *testing.F) {
	seeds := []string{
		`{}`, `{"aud":"x"}`, `{"aud":["a","b"]}`, `{"scope":"a b c"}`,
		`{"scp":["a","b"]}`, `{"exp":123,"iat":100}`, `{"cnf":{"jkt":"x"}}`,
		`{"exp":"bad"}`, `{"aud":5}`, `{"cnf":{"jkt":"a","x5t#S256":"b"}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	lim := testAuthLimits()
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := decodeSegment(jose.B64URLEncode(raw), lim)
		if err != nil {
			return
		}
		_, _ = extractClaims(n, lim) // must not panic
	})
}

// FuzzValidateIntrospection proves opaque-metadata validation never panics on
// arbitrary field values and never accepts a result whose issuer is untrusted,
// whose audience omits the canonical resource, or that lacks a finite expiry.
func FuzzValidateIntrospection(f *testing.F) {
	now := fixedClock()
	cfg := gatewayConfig(f)
	seed := validOpaque(now)
	f.Add(seed.Active, seed.Issuer, seed.Subject, seed.ClientID, seed.Scope, seed.Tenant, seed.Audiences[0], seed.Expiry, seed.HasExpiry)
	f.Add(true, "https://evil/issuer", "s", "c", "bad", "t", "https://evil/aud", int64(0), false)
	f.Fuzz(func(t *testing.T, active bool, iss, sub, cid, scope, tenant, aud string, exp int64, hasExp bool) {
		res := IntrospectionResult{
			Active: active, Issuer: iss, Audiences: []string{aud}, Subject: sub,
			ClientID: cid, Scope: scope, Tenant: tenant, Expiry: exp, HasExpiry: hasExp,
			IssuedAt: now.Unix(), HasIat: true,
		}
		claims, err := ValidateIntrospection(res, cfg, now)
		if err != nil {
			return
		}
		// A validated result must carry the trusted issuer, the canonical resource
		// as an audience, and a finite expiry.
		if claims.Issuer != testIssuer {
			t.Fatalf("accepted untrusted issuer: %q", claims.Issuer)
		}
		if !hasExp {
			t.Fatal("accepted metadata with no finite expiry")
		}
		if aud != gwResource {
			t.Fatalf("accepted a foreign audience: %q", aud)
		}
	})
}
