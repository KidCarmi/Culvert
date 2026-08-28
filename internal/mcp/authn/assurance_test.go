package authn

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// gatewayConfigWith builds a gateway auth config with an explicit sender profile
// and minimum assurance.
func gatewayConfigWith(t testing.TB, prof senderconstraint.Profile, floor identity.AssuranceLevel) CapabilityAuthConfig {
	t.Helper()
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: prof,
		MinAssurance: floor, Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatalf("gateway config: %v", err)
	}
	return cfg
}

// bearerRequest builds a plain-bearer AuthRequest whose caller-ASSERTED subject
// assurance is `assert`. Nothing about the request proves that assurance.
func bearerRequest(t testing.TB, now time.Time, k *esKey, assert identity.AssuranceLevel) AuthRequest {
	t.Helper()
	return AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: mintJWT(esHeader("k1"), baseGatewayClaims(now), k)},
		Subject: identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{
			Subject: "user-1", Tenant: testTenant, Issuer: testIssuer, Assurance: assert,
		}},
		Client: identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant: identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
	}
}

// SEC-MCP-01. Effective assurance is a property of what was CRYPTOGRAPHICALLY
// VERIFIED, never of what the caller asserted. Under a BearerControlled profile
// nothing binds the token to its sender, so no caller assertion may raise the
// subject above AssuranceLow — otherwise the MinAssurance admission floor (and
// every `principal.assurance` policy condition downstream) is satisfiable by an
// unverified request-shaped hint.
func TestAssurance_UnverifiedAssertionCannotSatisfyTheFloor(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	deps := Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}

	cfg := gatewayConfigWith(t, senderconstraint.BearerControlled, identity.AssuranceHigh)
	_, err := Authenticate(bearerRequest(t, now, k, identity.AssuranceHigh), cfg, deps, now)
	if mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("asserted-high bearer must not satisfy a high assurance floor; got err=%v", err)
	}
}

// A WORKLOAD subject is deliberately outside the clamp: its level is derived from
// evidence authn itself checks (Workload.Attestation), so an ATTESTED workload
// keeps High even under a BearerControlled profile. This pins the boundary of the
// clamp so a future widening cannot silently break the attestation contract.
func TestAssurance_AttestedWorkloadIsNotClamped(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	claims := baseGatewayClaims(now)
	claims["sub"] = "svc-1"
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: mintJWT(esHeader("k1"), claims, k)},
		Subject: identity.Subject{Kind: identity.SubjectWorkload, Workload: &identity.Workload{
			Service: "svc-1", Tenant: testTenant, Attestation: "spiffe://svc-1",
		}},
		Client: identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant: identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
	}
	cfg := gatewayConfigWith(t, senderconstraint.BearerControlled, identity.AssuranceHigh)
	ctx, err := Authenticate(req, cfg, Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}, now)
	if err != nil {
		t.Fatalf("attested workload must still satisfy a high floor under bearer: %v", err)
	}
	if got := ctx.Assurance(); got != identity.AssuranceHigh {
		t.Fatalf("attested workload assurance = %v, want High", got)
	}
}

// A VERIFIED sender constraint preserves a legitimately-asserted high assurance —
// the clamp must not cost availability on a correctly-configured deployment.
func TestAssurance_VerifiedDPoPPreservesHigh(t *testing.T) {
	now := fixedClock()
	sk, pk := newESKey(t, "k1"), newESKey(t, "dpop")
	cfg, err := NewCapabilityConfig(CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: senderconstraint.DPoPRequired,
		MinAssurance: identity.AssuranceHigh, Limits: testAuthLimits(),
	})
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	deps := Deps{Keys: resolverFor(sk), Registry: gwRegistry(t),
		Replay: senderconstraint.NewReplayCache(testAuthLimits(), func() time.Time { return now })}

	req := dpopRequest(t, now, sk, pk, nil, nil)
	req.Subject.Human.Assurance = identity.AssuranceHigh
	ctx, err := Authenticate(req, cfg, deps, now)
	if err != nil {
		t.Fatalf("verified DPoP with a high floor must be admitted: %v", err)
	}
	if got := ctx.Assurance(); got != identity.AssuranceHigh {
		t.Fatalf("verified DPoP must preserve AssuranceHigh, got %v", got)
	}
}

// An UNATTESTED workload keeps its existing low ceiling under every profile — the
// clamp composes with, and never relaxes, the pre-existing workload rule.
func TestAssurance_UnattestedWorkloadStaysLow(t *testing.T) {
	now := fixedClock()
	k := newESKey(t, "k1")
	claims := baseGatewayClaims(now)
	claims["sub"] = "svc-1"
	req := AuthRequest{
		Credential: Credential{Location: LocationAuthorizationHeader, Type: TokenJWT, Token: mintJWT(esHeader("k1"), claims, k)},
		Subject: identity.Subject{Kind: identity.SubjectWorkload, Workload: &identity.Workload{
			Service: "svc-1", Tenant: testTenant,
		}},
		Client: identity.Client{ClientID: testClientG, Tenant: testTenant, Capability: protocol.Gateway},
		Tenant: identity.Tenant{ID: testTenant}, Server: serverPtr("srv-1"),
	}
	cfg := gatewayConfigWith(t, senderconstraint.BearerControlled, identity.AssuranceHigh)
	_, err := Authenticate(req, cfg, Deps{Keys: resolverFor(k), Registry: gwRegistry(t)}, now)
	if mcperr.ReasonOf(err) != mcperr.ReasonDelegationChainInvalid {
		t.Fatalf("unattested workload must not satisfy a high floor, got %v", err)
	}
}
