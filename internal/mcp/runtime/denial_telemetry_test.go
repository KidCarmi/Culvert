package runtime

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// A duplicate singleton security header is a deliberate header-confusion attempt,
// and it is refused at the TRANSPORT layer — before the pipeline — so nothing
// downstream can count it. Without a classified reason travelling back, the refusal
// moved only the generic rejected-request counter and was indistinguishable from a
// malformed body, leaving the attack invisible to authentication-denial telemetry.
//
// ReasonAmbiguousRequestHeader existed for exactly this and was wired to nothing.
func TestDenialTelemetry_DuplicateSingletonHeaderIsClassified(t *testing.T) {
	k := newESKey(t, "k1")
	l, err := newListener(gwListenerConfig(t), testDeps(t, k, nil), "dup-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
	r.Host = gwHost
	r.Header.Add("Authorization", "Bearer a")
	r.Header.Add("Authorization", "Bearer b")

	_, status, reason, _ := l.extractRequest(nil, r)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if reason != mcperr.ReasonAmbiguousRequestHeader {
		t.Fatalf("reason = %v, want %v — the refusal carries no classification, so the "+
			"denial cannot be attributed to header confusion", reason, mcperr.ReasonAmbiguousRequestHeader)
	}
}

// A well-formed request must carry NO reason, so the classified-denial path above
// cannot fire on ordinary traffic.
func TestDenialTelemetry_WellFormedRequestCarriesNoReason(t *testing.T) {
	k := newESKey(t, "k1")
	l, err := newListener(gwListenerConfig(t), testDeps(t, k, nil), "ok-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
	r.Host = gwHost
	r.Header.Set("Authorization", "Bearer "+gwToken(k))

	_, status, reason, _ := l.extractRequest(nil, r)
	if status != 0 {
		t.Fatalf("a well-formed request was rejected with %d", status)
	}
	if reason != mcperr.ReasonNone {
		t.Fatalf("a well-formed request carried reason %v", reason)
	}
}

// OVERLOAD IS NOT AN AUTHENTICATION FAILURE.
//
// authenticate() bounds its wait for a verification slot by the request budget, so
// a saturated listener returns ReasonRequestDeadlineExceeded — the same reason
// checkBudget answers with 503. Routed through the authentication-failure branch it
// became a 401 with a WWW-Authenticate challenge, telling a caller whose credential
// was never examined that the credential was rejected, and charging the episode to
// authFailures and the denial lane — so a capacity incident read as a
// credential-stuffing spike in the very telemetry used to tell them apart.
func TestDenialTelemetry_SlotTimeoutIsOverloadNotAuthFailure(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	p := pipelineWithProfile(t, deps, senderconstraint.BearerControlled, 1, 1)

	// Saturate the auth bound so the next request must wait for a slot.
	p.authSem <- struct{}{}
	defer func() { <-p.authSem }()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	out := p.Process(ctx, gwRequest(gwToken(k), initializeBody(1)), fixedClock())

	if out.Status == http.StatusUnauthorized {
		t.Fatalf("a saturated verification bound answered 401: overload is being reported "+
			"as bad credentials (reason=%v)", out.Reason)
	}
	if out.Status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (reason=%v)", out.Status, out.Reason)
	}
	if out.Reason != mcperr.ReasonRequestDeadlineExceeded {
		t.Fatalf("reason = %v, want request-deadline-exceeded", out.Reason)
	}
	if n := p.ctr.authFailures.Load(); n != 0 {
		t.Errorf("authFailures = %d after an overload rejection; a capacity incident must not "+
			"be charged to authentication-denial telemetry", n)
	}
	// EXACTLY once. acquireSlot is the only producer of this reason on the
	// authenticate path and already counts it; counting again in the pipeline branch
	// exported every verification-slot timeout twice, overstating the very overload
	// rate an operator alerts on.
	if n := p.ctr.timeouts.Load(); n != 1 {
		t.Errorf("timeouts = %d after ONE overload rejection, want exactly 1", n)
	}
}
