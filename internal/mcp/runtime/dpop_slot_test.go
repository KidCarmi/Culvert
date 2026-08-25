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

// OVN-02. The auth and DPoP bounds must NEVER be held at once. A DPoP-carrying
// request validates its access token under the auth bound, RELEASES it, and only
// then queues for the (scarcer) DPoP bound. Holding the auth slot while WAITING for
// DPoP is hold-and-wait: DPoP waiters would occupy the auth pool doing no auth work,
// so once DPoPConcurrency saturates they starve every caller that needs only the
// auth bound.
func TestLimits_DPoPQueueDoesNotHoldAnAuthSlot(t *testing.T) {
	k := newESKey(t, "k1")
	// DPoPOrMTLS: a request WITH a proof needs both bounds; one WITHOUT needs only
	// the auth bound — the two classes the inversion pits against each other. The
	// NORMAL (fast) key source is deliberate: token validation completes quickly, so
	// a DPoP request reaches — and parks on — the DPoP bound holding no auth slot.
	// (A blocking key source would instead park it INSIDE validation, legitimately
	// holding an auth slot for auth work — a different scenario from a DPoP waiter.)
	p := pipelineWithProfile(t, testDeps(t, k, nil), senderconstraint.DPoPOrMTLSRequired, 2, 1)

	// Saturate the single DPoP slot and never release it.
	p.dpopSem <- struct{}{}

	// Two DPoP-carrying requests: each validates under the auth bound, releases it,
	// then blocks on the saturated DPoP bound. One shared context: the two requests
	// already had the same budget (the loop body runs in microseconds), and a
	// per-iteration `defer cancel()` accumulates deferred calls inside the loop
	// (gocritic deferInLoop).
	waiterCtx, cancelWaiters := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWaiters()
	for i := 0; i < 2; i++ {
		r := gwRequest(gwToken(k), initializeBody(i+1))
		r.DPoPProof, r.HasDPoP = "proof", true
		go p.Process(waiterCtx, r, fixedClock())
	}
	time.Sleep(200 * time.Millisecond) // let both validate, release auth, and park on DPoP

	// A caller needing only the AUTH bound (no proof ⇒ the mTLS branch ⇒ no DPoP
	// slot) must be admitted to the auth bound rather than starving behind the DPoP
	// waiters. The sender constraint will still REFUSE it later (no proof, no mTLS) —
	// that is fine; the invariant is that it is not parked on the auth semaphore, so
	// it must not time out. Under a hold-and-wait regression the two DPoP waiters
	// pin both auth slots and this request elapses its budget instead.
	plain := gwRequest(gwToken(k), initializeBody(9)) // HasDPoP=false
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan Outcome, 1)
	go func() { done <- p.Process(ctx, plain, fixedClock()) }()
	select {
	case out := <-done:
		if out.Reason == mcperr.ReasonRequestDeadlineExceeded {
			t.Fatal("a non-DPoP request starved on the auth bound: DPoP waiters are holding auth slots while queued for DPoP")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a non-DPoP request never completed: it is parked behind DPoP waiters holding the auth bound")
	}
}

// The DPoP bound must not be held ACROSS access-token validation. The DPoP proof is
// verified only inside AuthenticateVerified, AFTER the access token is validated, so
// a slow opaque introspection — or an INVALID token, which never reaches the proof
// stage at all — must not occupy a DPoP slot while no DPoP work is in progress.
// (Codex review of 7fd0869: a DPoP slot held during validation is an amplifier that
// stalls legitimate DPoP requests while no DPoP verification runs.)
func TestLimits_DPoPSlotNotHeldDuringTokenValidation(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	// Block token validation — a stand-in for a slow introspection / key fetch — so
	// the request is observably parked mid-validation, before any proof stage.
	bk := &blockingKeys{inner: deps.Keys, entered: make(chan struct{}, 2), release: make(chan struct{})}
	deps.Keys = bk
	// DPoPRequired with a proof present ⇒ the DPoP bound WOULD be consumed once
	// validation succeeds; DPoPConcurrency=1 makes a single held slot observable.
	p := pipelineWithProfile(t, deps, senderconstraint.DPoPRequired, 8, 1)

	req := gwRequest(gwToken(k), initializeBody(1))
	req.DPoPProof, req.HasDPoP = "proof", true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go p.Process(ctx, req, fixedClock())

	// Wait until the request is parked INSIDE token validation (holding an auth slot,
	// pre-proof).
	select {
	case <-bk.entered:
	case <-time.After(2 * time.Second):
		close(bk.release)
		t.Fatal("request never reached token validation")
	}

	// The DPoP bound must be FREE: the proof stage has not begun, so no DPoP slot is
	// held across the (here stalled) validation. Probe it without blocking.
	select {
	case p.dpopSem <- struct{}{}:
		<-p.dpopSem // release the probe immediately
	default:
		close(bk.release)
		t.Fatal("a DPoP slot is held during access-token validation: a slow introspection or an invalid token occupies the DPoP bound for no DPoP work")
	}
	close(bk.release)
}
