package authn

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// Review fix (F1 / P1): a DPoP-required profile must reject an access token that is
// NOT itself DPoP-bound (no cnf.jkt). Otherwise anyone holding a bare bearer token
// could mint their own key + proof and satisfy the sender constraint.
func TestReviewFix_DPoPRequiresTokenBinding(t *testing.T) {
	now := fixedClock()
	sk, pk := newESKey(t, "k1"), newESKey(t, "pk")
	cfg := gatewayDPoPConfig(t)
	deps := Deps{Keys: resolverFor(sk), Registry: gwRegistry(t), Replay: senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })}
	// Token carries NO cnf.jkt; attacker mints a proof with their own key `pk`.
	claims := baseGatewayClaims(now)
	token := mintJWT(esHeader("k1"), claims, sk)
	proof := mintDPoP(map[string]any{
		"htm": "POST", "htu": "https://culvert.example/mcp/gateway/srv-1",
		"iat": now.Unix(), "jti": "p1", "ath": athOf(token),
	}, pk)
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
		Binding: RequestBinding{HTTPMethod: "POST", HTTPURI: "https://culvert.example/mcp/gateway/srv-1", DPoPProof: proof},
	}
	if _, err := Authenticate(req, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonDPoPBindingMismatch {
		t.Fatalf("unbound token + attacker proof must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

// Review fix (F1 downgrade): under DPoPOrMTLSRequired, an mTLS-bound token (cnf.x5t,
// no cnf.jkt) must NOT be downgradable by presenting an attacker DPoP proof.
func TestReviewFix_DPoPOrMTLSNoDowngrade(t *testing.T) {
	now := fixedClock()
	sk, pk := newESKey(t, "k1"), newESKey(t, "pk")
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.DPoPOrMTLSRequired,
		Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	deps := Deps{Keys: resolverFor(sk), Registry: gwRegistry(t), Replay: senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })}
	// Token is mTLS-bound (cnf.x5t#S256), NOT DPoP-bound.
	claims := baseGatewayClaims(now)
	claims["cnf"] = map[string]any{"x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	token := mintJWT(esHeader("k1"), claims, sk)
	proof := mintDPoP(map[string]any{
		"htm": "POST", "htu": "https://culvert.example/mcp/gateway/srv-1",
		"iat": now.Unix(), "jti": "p1", "ath": athOf(token),
	}, pk)
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Subject:    identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: identity.AssuranceHigh}},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
		Binding: RequestBinding{HTTPMethod: "POST", HTTPURI: "https://culvert.example/mcp/gateway/srv-1", DPoPProof: proof},
	}
	if _, err := Authenticate(req, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonDPoPBindingMismatch {
		t.Fatalf("mTLS-bound token must not be DPoP-downgradable, got %v", mcperr.ReasonOf(err))
	}
}

// Review fix (P1): a token co-issued for Culvert AND a foreign audience must be
// rejected — the effective audience set must contain ONLY the canonical resource.
func TestReviewFix_ForeignCoAudienceRejected(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	claims := baseGatewayClaims(now)
	claims["aud"] = []any{gwResource, "https://upstream.example/mcp"}
	token := mintJWT(esHeader("k1"), claims, k)
	if _, err := ValidateJWT(token, gatewayConfig(t), resolverFor(k), now); mcperr.ReasonOf(err) != mcperr.ReasonAudienceRejected {
		t.Fatalf("foreign co-audience (JWT) must be rejected, got %v", mcperr.ReasonOf(err))
	}
	// Same via the opaque path.
	res := IntrospectionResult{
		Active: true, Issuer: testIssuer, Audiences: []string{gwResource, "https://upstream.example/mcp"},
		Subject: "user-1", ClientID: testClientG, Scope: gwScope, Tenant: testTenant,
		Expiry: now.Add(5 * time.Minute).Unix(), HasExpiry: true, IssuedAt: now.Unix(), HasIat: true,
	}
	if _, err := ValidateIntrospection(res, gatewayConfig(t), now); mcperr.ReasonOf(err) != mcperr.ReasonAudienceRejected {
		t.Fatalf("foreign co-audience (opaque) must be rejected, got %v", mcperr.ReasonOf(err))
	}
	// A duplicate copy of the canonical resource is NOT a foreign co-audience.
	claims["aud"] = []any{gwResource, gwResource}
	dup := mintJWT(esHeader("k1"), claims, k)
	if _, err := ValidateJWT(dup, gatewayConfig(t), resolverFor(k), now); err != nil {
		t.Fatalf("duplicate canonical audience must be accepted, got %v", err)
	}
}

// Review fix (P1): a config with an empty (or all-empty-string) accepted-client
// allowlist must fail construction, not silently accept every client id.
func TestReviewFix_EmptyClientAllowlistRejected(t *testing.T) {
	for _, ids := range [][]string{nil, {}, {""}, {"", ""}} {
		_, err := NewCapabilityConfig(CapabilityConfigInput{
			Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
			AcceptedClientIDs: ids, CanonicalResource: gwResource,
			RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.BearerControlled,
			Limits: testAuthLimits(),
		})
		if err == nil {
			t.Fatalf("empty client allowlist %v must fail closed", ids)
		}
	}
}

// Review fix (P2): a token whose iat is far in the future (beyond skew) must be
// rejected even when exp-iat is within the max TTL and no nbf is present.
func TestReviewFix_FutureIatRejected(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	claims := baseGatewayClaims(now)
	claims["iat"] = now.Add(time.Hour).Unix()
	claims["exp"] = now.Add(time.Hour + 5*time.Minute).Unix()
	token := mintJWT(esHeader("k1"), claims, k)
	if _, err := ValidateJWT(token, gatewayConfig(t), resolverFor(k), now); mcperr.ReasonOf(err) != mcperr.ReasonTokenNotYetValid {
		t.Fatalf("future iat must be rejected, got %v", mcperr.ReasonOf(err))
	}
}

// Review fix (P1): an unattested workload cannot reach high assurance; an attested
// one can. The escalation seam (label-as-workload ⇒ AssuranceHigh) is closed.
func TestReviewFix_WorkloadAssuranceRequiresAttestation(t *testing.T) {
	un := identity.Subject{Kind: identity.SubjectWorkload, Workload: &identity.Workload{Service: "svc-1", Tenant: testTenant}}
	if got := subjectAssurance(un); got >= identity.AssuranceHigh {
		t.Fatalf("unattested workload assurance = %v, must be below High", got)
	}
	at := identity.Subject{Kind: identity.SubjectWorkload, Workload: &identity.Workload{Service: "svc-1", Tenant: testTenant, Attestation: "spiffe://svc-1"}}
	if got := subjectAssurance(at); got != identity.AssuranceHigh {
		t.Fatalf("attested workload assurance = %v, want High", got)
	}

	// End-to-end: a High MinAssurance gate rejects the unattested workload and
	// admits the attested one.
	now := fixedClock()
	sk := newESKey(t, "k1")
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.BearerControlled,
		MinAssurance: identity.AssuranceHigh, Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := baseGatewayClaims(now)
	claims["sub"] = "svc-1"
	token := mintJWT(esHeader("k1"), claims, sk)
	base := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: token},
		Client:     identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant:     identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
	}
	deps := Deps{Keys: resolverFor(sk), Registry: gwRegistry(t)}
	r1 := base
	r1.Subject = un
	if _, err := Authenticate(r1, cfg, deps, now); mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("unattested workload must fail the High assurance gate, got %v", mcperr.ReasonOf(err))
	}
	r2 := base
	r2.Subject = at
	if _, err := Authenticate(r2, cfg, deps, now); err != nil {
		t.Fatalf("attested workload should pass the High gate, got %v", err)
	}
}
