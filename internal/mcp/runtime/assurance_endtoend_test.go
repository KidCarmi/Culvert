package runtime

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// gwAuthConfigFloor builds a Gateway auth config with an explicit minimum-assurance
// floor.
func gwAuthConfigFloor(t testing.TB, prof senderconstraint.Profile, floor identity.AssuranceLevel) authn.CapabilityAuthConfig {
	t.Helper()
	cfg, err := authn.NewCapabilityConfig(authn.CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: prof,
		MinAssurance: floor, Limits: limits.DefaultAuth(),
	})
	if err != nil {
		t.Fatalf("auth config: %v", err)
	}
	return cfg
}

// The 2026-08-24 P0 finding was that an UNVERIFIED request could reach
// AssuranceHigh. The fix clamps a Human subject's asserted assurance to what the
// VERIFIED sender constraint justifies, inside internal/mcp/authn.
//
// authn's own tests prove the clamp works. Nothing proved the pipeline routes
// through it — and that is the gap that matters here, because buildAuthRequest
// hardcodes `assur := identity.AssuranceHigh` for every request and relies
// ENTIRELY on the clamp to bring it back down. Mutation testing made the gap
// concrete: removing the clamp altogether, and making assuranceCeiling return High
// for unbound tokens, both left the whole runtime package green.
//
// A control proven only in the package that implements it is precisely the shape
// this review keeps finding. These two tests pin the composition instead.
func TestAssuranceEndToEnd_BearerTokenCannotSatisfyAHighFloor(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	cfg := gwListenerConfig(t)
	// Bearer-only: no DPoP proof, no client certificate — so nothing verifies who is
	// presenting this token, and the High floor must not be satisfiable.
	cfg.AuthConfig = gwAuthConfigFloor(t, senderconstraint.BearerControlled, identity.AssuranceHigh)
	p, err := newPipeline(cfg, deps, "floor-gw", &counters{}, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}

	out := p.Process(context.Background(), gwRequest(gwToken(k), initializeBody(1)), fixedClock())
	if out.SessionID != "" || out.Status == 200 {
		t.Fatalf("a bearer-only request satisfied a min_assurance=high floor "+
			"(status=%d session=%q reason=%v): assurance is being taken from the caller's "+
			"assertion rather than from the verified sender constraint",
			out.Status, out.SessionID, out.Reason)
	}
}

// The control must not be a blanket denial: with the SAME High floor, a request
// carrying a genuinely verified DPoP proof is admitted. Without this half, a clamp
// that simply denied everything would pass the test above.
func TestAssuranceEndToEnd_VerifiedDPoPSatisfiesTheSameFloor(t *testing.T) {
	kit := newDPoPKit(t)
	cfg := gwListenerConfig(t)
	cfg.AuthConfig = gwAuthConfigFloor(t, senderconstraint.DPoPRequired, identity.AssuranceHigh)
	p, err := newPipeline(cfg, kit.deps, "floor-pop-gw", &counters{}, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}

	tok := kit.token(t)
	out := p.Process(context.Background(), kit.request(t, tok, "floor-jti-1", initializeBody(1)), fixedClock())
	if out.SessionID == "" {
		t.Fatalf("a VERIFIED DPoP request was refused by a min_assurance=high floor "+
			"(status=%d reason=%v): the clamp has become a blanket denial", out.Status, out.Reason)
	}
}
