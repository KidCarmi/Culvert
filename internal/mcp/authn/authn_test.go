package authn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

func mintJWTEd(header, claims map[string]any, k *edKey) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(cb)
	sig := ed25519Sign(k, []byte(signingInput))
	return signingInput + "." + b64(sig)
}

func TestJWTEdDSA(t *testing.T) {
	now := fixedClock()
	k := newEdKey(t)
	r := NewStaticKeyResolver()
	r.Add(testIssuer, "ed1", k.pub)
	tok := mintJWTEd(map[string]any{"alg": "EdDSA", "kid": "ed1"}, baseGatewayClaims(now), k)
	if _, err := ValidateJWT(tok, gatewayConfig(t), r, now); err != nil {
		t.Fatalf("valid EdDSA token rejected: %v", err)
	}
}

// --- capability isolation (both directions) --------------------------------

func TestConfigSetRejectsOverlap(t *testing.T) {
	base := func(cap protocol.Capability, res, scope, client string) CapabilityConfigInput {
		return CapabilityConfigInput{
			Capability: cap, TrustedIssuers: []string{testIssuer},
			AcceptedClientIDs: []string{client}, CanonicalResource: res,
			RequiredScopes: []string{scope}, SenderProfile: senderconstraint.BearerControlled,
			Limits: testAuthLimits(),
		}
	}
	mk := func(in CapabilityConfigInput) CapabilityAuthConfig {
		c, err := NewCapabilityConfig(in)
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		return c
	}
	// Shared scope must fail.
	if _, err := NewConfigSet(
		mk(base(protocol.Management, mgmtResource, "shared.scope", testClientM)),
		mk(base(protocol.Gateway, gwResource, "shared.scope", testClientG)),
	); mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("shared scope must be rejected, got %v", err)
	}
	// Shared client id must fail.
	if _, err := NewConfigSet(
		mk(base(protocol.Management, mgmtResource, mgmtScope, "shared-client")),
		mk(base(protocol.Gateway, gwResource, gwScope, "shared-client")),
	); mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("shared client must be rejected, got %v", err)
	}
	// Valid disjoint set constructs.
	if _, err := NewConfigSet(mk(base(protocol.Management, mgmtResource, mgmtScope, testClientM)),
		mk(base(protocol.Gateway, gwResource, gwScope, testClientG))); err != nil {
		t.Fatalf("disjoint set rejected: %v", err)
	}
}

func TestConfigRejectsBlanketScope(t *testing.T) {
	for _, s := range []string{"mcp", "mcp.access", "*"} {
		_, err := NewCapabilityConfig(CapabilityConfigInput{
			Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
			CanonicalResource: gwResource, RequiredScopes: []string{s},
			SenderProfile: senderconstraint.BearerControlled, Limits: testAuthLimits(),
		})
		if mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
			t.Fatalf("blanket scope %q must be rejected, got %v", s, err)
		}
	}
}

func TestConfigRejectsUnsetSenderProfile(t *testing.T) {
	_, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		CanonicalResource: gwResource, RequiredScopes: []string{gwScope},
		SenderProfile: senderconstraint.ProfileUnset, Limits: testAuthLimits(),
	})
	if mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("unset sender profile must fail closed, got %v", err)
	}
}

// A management token must never validate for gateway (audience + scope + client).
func TestCrossCapabilityRejection(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	res := resolverFor(k)
	// A management-shaped token presented to the gateway config.
	mgmtTok := mintJWT(esHeader("k1"), map[string]any{
		"iss": testIssuer, "sub": "admin-1", "client_id": testClientM,
		"aud": mgmtResource, "scope": mgmtScope, "tenant": testTenant,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}, k)
	if _, err := ValidateJWT(mgmtTok, gatewayConfig(t), res, now); mcperr.ReasonOf(err) == mcperr.ReasonNone {
		t.Fatal("management token validated for gateway")
	}
	// And a gateway token presented to management.
	gwTok := mintJWT(esHeader("k1"), baseGatewayClaims(now), k)
	if _, err := ValidateJWT(gwTok, managementConfig(t), res, now); mcperr.ReasonOf(err) == mcperr.ReasonNone {
		t.Fatal("gateway token validated for management")
	}
}

// --- opaque introspection --------------------------------------------------

type fakeIntrospector struct{ res IntrospectionResult }

func (f fakeIntrospector) Introspect(string) (IntrospectionResult, error) { return f.res, nil }

func validOpaque(now time.Time) IntrospectionResult {
	return IntrospectionResult{
		Active: true, Issuer: testIssuer, Audiences: []string{gwResource},
		Subject: "user-1", ClientID: testClientG, Scope: gwScope, Tenant: testTenant,
		Expiry: now.Add(5 * time.Minute).Unix(), HasExpiry: true,
		IssuedAt: now.Unix(), HasIat: true,
	}
}

func TestOpaqueMatrix(t *testing.T) {
	now := fixedClock()
	cfg := gatewayConfig(t)
	cases := []struct {
		name  string
		patch func(r *IntrospectionResult)
		want  mcperr.Reason
	}{
		{"valid", func(r *IntrospectionResult) {}, mcperr.ReasonNone},
		{"inactive", func(r *IntrospectionResult) { r.Active = false }, mcperr.ReasonInactiveToken},
		{"missing-expiry", func(r *IntrospectionResult) { r.HasExpiry = false }, mcperr.ReasonTokenExpired},
		{"expired", func(r *IntrospectionResult) { r.Expiry = now.Add(-time.Hour).Unix() }, mcperr.ReasonTokenExpired},
		{"wrong-issuer", func(r *IntrospectionResult) { r.Issuer = "https://evil/x" }, mcperr.ReasonIssuerRejected},
		{"missing-audience", func(r *IntrospectionResult) { r.Audiences = nil }, mcperr.ReasonAudienceMissing},
		{"wrong-audience", func(r *IntrospectionResult) { r.Audiences = []string{mgmtResource} }, mcperr.ReasonAudienceRejected},
		{"wrong-tenant-missing", func(r *IntrospectionResult) { r.Tenant = "" }, mcperr.ReasonTenantMismatch},
		{"wrong-scope", func(r *IntrospectionResult) { r.Scope = mgmtScope }, mcperr.ReasonScopeMissing},
		{"both-cnf", func(r *IntrospectionResult) { r.CnfJKT = "a"; r.CnfX5T = "b" }, mcperr.ReasonMalformedToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validOpaque(now)
			tc.patch(&r)
			_, err := ValidateOpaque("opaque-token", cfg, fakeIntrospector{r}, now)
			if got := mcperr.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %v, want %v (err=%v)", got, tc.want, err)
			}
		})
	}
}

// --- credential location ---------------------------------------------------

func TestCredentialLocation(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	cfg := gatewayConfig(t)
	req := func(loc Location) AuthRequest {
		return AuthRequest{
			Credential: Credential{Location: loc, Type: TokenJWT, Token: mintJWT(esHeader("k1"), baseGatewayClaims(now), k)},
			Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
			Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
			Tenant:     identity.Tenant{ID: testTenant},
			Server:     serverPtr("srv-1"),
		}
	}
	deps := Deps{Keys: resolverFor(k)}
	if _, err := Authenticate(req(LocationQueryString), cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonCredentialInQuery {
		t.Fatalf("query-string token must be credential_in_query, got %v", err)
	}
	if _, err := Authenticate(req(LocationUnknown), cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonCredentialMissing {
		t.Fatalf("unknown location must be credential_missing, got %v", err)
	}
}
