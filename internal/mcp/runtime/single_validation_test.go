package runtime

import (
	"context"
	"crypto"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// countingKeyResolver counts how many times a signature verification asked for a
// key. For the ES256 fixture that is exactly one resolution per verification, so
// it is a direct count of cryptographic verifications performed.
type countingKeyResolver struct {
	inner authn.KeyResolver
	n     atomic.Int64
}

func (c *countingKeyResolver) ResolveKey(issuer, kid, alg string) (crypto.PublicKey, error) {
	c.n.Add(1)
	return c.inner.ResolveKey(issuer, kid, alg)
}

// OVN-06. The credential must be validated EXACTLY ONCE per request.
//
// The runtime used to validate every token twice: once to derive the asserted
// principals, and again inside authn.Authenticate, which re-validates. Measured on
// this pipeline that was 2 full ECDSA P-256 verifications per request — ~96 µs of
// a ~206 µs authenticated request (47%), 8.7 KB and 206 allocations — a 2x
// amplification of the most expensive attacker-reachable operation, on the stage
// an unauthenticated flood reaches first.
//
// This is a permanent gate, not a benchmark: it fails deterministically on any
// hardware if a second verification returns.
func TestAuth_CredentialIsValidatedExactlyOnce(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ck := &countingKeyResolver{inner: deps.Keys}
	deps.Keys = ck
	p := newGatewayPipeline(t, deps)

	out := p.Process(context.Background(), gwRequest(gwToken(k), initializeBody(1)), fixedClock())
	if out.Status != 200 {
		t.Fatalf("fixture must authenticate successfully, got %d (%v)", out.Status, out.Reason)
	}
	if got := ck.n.Load(); got != 1 {
		t.Fatalf("signature verifications per request = %d, want exactly 1", got)
	}
}

// The same must hold on the DPoP path, where an additional proof verification is
// legitimate but the ACCESS TOKEN must still be verified only once.
func TestAuth_DPoPRequestStillValidatesTheTokenOnce(t *testing.T) {
	kit := newDPoPKit(t)
	ck := &countingKeyResolver{inner: kit.deps.Keys}
	kit.deps.Keys = ck

	cfg := gwListenerConfig(t)
	cfg.AuthConfig = gwAuthConfigProfile(t, senderconstraint.DPoPRequired)
	p, err := newPipeline(cfg, kit.deps, "once-gw", &counters{}, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	out := p.Process(context.Background(), kit.request(t, kit.token(t), "jti-once", initializeBody(1)), fixedClock())
	if out.Status != 200 {
		t.Fatalf("DPoP fixture must authenticate, got %d (%v)", out.Status, out.Reason)
	}
	if got := ck.n.Load(); got != 1 {
		t.Fatalf("access-token verifications on the DPoP path = %d, want exactly 1", got)
	}
}

// A REJECTED credential must not be validated more than once either — otherwise
// the amplification survives precisely where it matters most, on the path an
// attacker with an invalid token drives.
func TestAuth_RejectedCredentialIsValidatedOnce(t *testing.T) {
	k, other := newESKey(t, "k1"), newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ck := &countingKeyResolver{inner: deps.Keys}
	deps.Keys = ck
	p := newGatewayPipeline(t, deps)

	// Signed by a key the resolver does not know: signature verification fails.
	bad := gwToken(other)
	out := p.Process(context.Background(), gwRequest(bad, initializeBody(1)), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("a badly-signed token must be rejected, got %v", out.Disposition)
	}
	if got := ck.n.Load(); got > 1 {
		t.Fatalf("verifications for a rejected credential = %d, want at most 1", got)
	}
}
