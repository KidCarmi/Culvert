package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// gwAuthConfigProfile builds a gateway auth config with an explicit sender profile.
func gwAuthConfigProfile(t testing.TB, prof senderconstraint.Profile) authn.CapabilityAuthConfig {
	t.Helper()
	cfg, err := authn.NewCapabilityConfig(authn.CapabilityConfigInput{
		Capability: protocol.Gateway, TrustedIssuers: []string{testIssuer},
		AcceptedClientIDs: []string{testClientG}, CanonicalResource: gwResource,
		RequiredScopes: []string{gwScope}, SenderProfile: prof,
		Limits: limits.DefaultAuth(),
	})
	if err != nil {
		t.Fatalf("auth config: %v", err)
	}
	return cfg
}

// pipelineWithProfile builds a gateway pipeline with the given sender profile and
// concurrency bounds.
func pipelineWithProfile(t testing.TB, deps Deps, prof senderconstraint.Profile, authN, dpopN int) *pipeline {
	t.Helper()
	cfg := gwListenerConfig(t)
	cfg.AuthConfig = gwAuthConfigProfile(t, prof)
	cfg.Limits = limitsWithConcurrency(t, authN, dpopN)
	p, err := newPipeline(cfg, deps, "dpop-gw", &counters{}, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	return p
}

// OVN-01. The DPoPConcurrency bound must be consumed IF AND ONLY IF a DPoP proof
// verification will actually run. Gating it on `req.HasDPoP` alone — the mere
// presence of an attacker-supplied header — lets a caller consume a scarce
// security bound for work that is never performed:
//
//   - under BearerControlled the proof is never verified at all;
//   - under MTLSRequired it is never verified;
//   - under DPoPRequired with no proof presented, verifyDPoP errors before any
//     cryptography.
//
// A bound that can be consumed without doing the work it bounds is an amplifier,
// not a control.
func TestLimits_DPoPSlotTracksRealVerificationWork(t *testing.T) {
	cases := []struct {
		prof    senderconstraint.Profile
		hasDPoP bool
		want    bool
	}{
		{senderconstraint.BearerControlled, true, false}, // junk header, never verified
		{senderconstraint.BearerControlled, false, false},
		{senderconstraint.MTLSRequired, true, false}, // junk header, never verified
		{senderconstraint.MTLSRequired, false, false},
		{senderconstraint.DPoPRequired, false, false}, // rejected before any crypto
		{senderconstraint.DPoPRequired, true, true},
		{senderconstraint.DPoPOrMTLSRequired, false, false}, // takes the mTLS branch
		{senderconstraint.DPoPOrMTLSRequired, true, true},
	}
	for _, c := range cases {
		got := dpopVerificationRuns(c.prof, c.hasDPoP)
		if got != c.want {
			t.Fatalf("profile=%v hasDPoP=%v ⇒ takes slot %v, want %v", c.prof, c.hasDPoP, got, c.want)
		}
	}
}

// OVN-01 (behavioural). Under a bearer profile an attacker's junk `DPoP:` header
// must not touch the DPoP bound at all: if it does, filling that bound stalls
// every subsequent request carrying such a header until its budget elapses — a
// free denial-of-service against a control that performs no work.
func TestLimits_JunkDPoPHeaderDoesNotConsumeTheDPoPBound(t *testing.T) {
	k := newESKey(t, "k1")
	p := pipelineWithProfile(t, testDeps(t, k, nil), senderconstraint.BearerControlled, 8, 1)

	// Occupy the single DPoP slot and never release it.
	p.dpopSem <- struct{}{}

	req := gwRequest(gwToken(k), initializeBody(1))
	req.DPoPProof, req.HasDPoP = "not-a-real-proof", true

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan Outcome, 1)
	go func() { done <- p.Process(ctx, req, fixedClock()) }()

	select {
	case out := <-done:
		if out.Reason == mcperr.ReasonRequestDeadlineExceeded {
			t.Fatal("a junk DPoP header queued on the DPoP bound: the bound is consumable without doing its work")
		}
		if out.Status != 200 {
			t.Fatalf("bearer request with a junk DPoP header should still succeed, got %d (%v)", out.Status, out.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request never completed: it is blocked on a DPoP bound it should not touch")
	}
}

// OVN-02. Acquiring the auth slot and then WAITING for the DPoP slot while
// holding it is hold-and-wait: DPoP waiters occupy the auth pool without doing any
// authentication work, so once DPoPConcurrency is saturated they starve every
// caller that needs only the auth bound. The two bounds must be acquired
// scarcest-first, so a caller queued for DPoP holds nothing.
func TestLimits_DPoPQueueDoesNotHoldAnAuthSlot(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	bk := &blockingKeys{inner: deps.Keys, entered: make(chan struct{}, 8), release: make(chan struct{})}
	deps.Keys = bk
	// DPoPOrMTLS: a request WITH a proof needs both bounds; one WITHOUT needs only
	// the auth bound — the two classes the inversion pits against each other.
	p := pipelineWithProfile(t, deps, senderconstraint.DPoPOrMTLSRequired, 2, 1)

	// Saturate the DPoP bound.
	p.dpopSem <- struct{}{}

	// Two DPoP-carrying requests: both must queue on the DPoP bound. One context is
	// shared rather than one created per iteration: the two requests already had the
	// same budget (the loop body runs in microseconds), and a per-iteration
	// `defer cancel()` accumulates deferred calls inside the loop (gocritic
	// deferInLoop) instead of releasing them as each iteration ends.
	waiterCtx, cancelWaiters := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWaiters()
	for i := 0; i < 2; i++ {
		r := gwRequest(gwToken(k), initializeBody(i+1))
		r.DPoPProof, r.HasDPoP = "proof", true
		go p.Process(waiterCtx, r, fixedClock())
	}
	time.Sleep(150 * time.Millisecond) // let them reach their queue

	// A caller needing only the AUTH bound must still be admitted to it. With
	// AuthConcurrency=2 and two DPoP waiters holding auth slots, it cannot be.
	plain := gwRequest(gwToken(k), initializeBody(9))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Process(ctx, plain, fixedClock())

	select {
	case <-bk.entered:
		// reached token validation ⇒ it obtained an auth slot
	case <-time.After(2 * time.Second):
		close(bk.release)
		t.Fatal("a non-DPoP request could not obtain an auth slot: DPoP waiters are holding the auth bound while queued")
	}
	close(bk.release)
}
