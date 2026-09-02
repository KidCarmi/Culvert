package execution

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// Codex review fixes for PR #1290 (execution-package half).

// stubLiveGate is a deterministic LiveExecutionGate: it records the Now it was handed and either
// admits (with a no-op Release) or refuses with a fixed reason.
type stubLiveGate struct {
	admit  bool
	reason mcperr.Reason
	mu     sync.Mutex
	gotNow time.Time
	calls  int
}

func (g *stubLiveGate) AdmitSideEffect(in LiveGateInput) LiveGateDecision {
	g.mu.Lock()
	g.gotNow = in.Now
	g.calls++
	g.mu.Unlock()
	if g.admit {
		return LiveGateDecision{Admit: true, Release: func() {}}
	}
	return LiveGateDecision{Admit: false, Reason: g.reason}
}

func (g *stubLiveGate) observedNow() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gotNow
}

// P1: the live gate's decision clock must be the EXECUTOR'S clock at the boundary, not the
// request-entry timestamp in.Now. A durable commit / credential materialization can delay the request
// past an approval expiry or budget window; the gate must evaluate trust/expiry/budget against the
// actual side-effect instant. liveGateInput is the single builder, so this pins the field directly.
func TestLiveGateInput_UsesBoundaryClockNotRequestEntry(t *testing.T) {
	boundary := time.Unix(1_700_000_500, 0) // the executor's "now" at the boundary
	requestEntry := time.Unix(1_700_000_000, 0)
	e, err := New(Config{
		State:           stateForMode(t, rollout.ModeCanary),
		Upstream:        &fakeUpstream{},
		Events:          realEvents(t, nil),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return boundary },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	in := runtime.ExecInput{Now: requestEntry} // in.Server/in.Input.Tool nil ⇒ target fields empty
	got := e.liveGateInput(in)
	if !got.Now.Equal(boundary) {
		t.Fatalf("liveGateInput.Now must be the executor boundary clock %v, got %v", boundary, got.Now)
	}
	if got.Now.Equal(requestEntry) {
		t.Fatalf("liveGateInput.Now must NOT reuse the request-entry in.Now %v (stale-clock regression)", requestEntry)
	}
}

// P2: a credential-path live-gate refusal must be metered EXACTLY ONCE, on the gate's real reason —
// never a stray ReasonNone pre-metered inside materializeAndCall before the caller reclassifies. This
// is the live-gate sibling of TestKillBoundary_CredentialKillMetersOnce (Codex P2, PR #1248).
func TestLiveGate_CredentialGateRefusalMetersOnce(t *testing.T) {
	st := credDriftStateMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	spy := &blockReasonSpy{}
	b, id := newCredKillBroker(t, nil)
	gate := &stubLiveGate{admit: false, reason: mcperr.ReasonRolloutBudgetExhausted}
	e, err := New(Config{
		State: st, Upstream: up, Events: realEvents(t, nil), Broker: b, Metrics: spy,
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           credDriftClock(),
		LiveGate:        gate,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Tool still current so the gate (which runs before preCallGuard) owns the refusal.
	in := credDriftInput(id, func() bool { return true })

	out := runExec(e, context.Background(), in)

	// The refusal happened after materialization but before the upstream call (§11): Upstream.Call == 0.
	req0Upstream(t, up)
	if out.Reason != mcperr.ReasonRolloutBudgetExhausted {
		t.Fatalf("the credential-path gate refusal must surface the gate's reason, got %s", out.Reason.Code())
	}
	if gate.calls != 1 {
		t.Fatalf("the gate must be consulted exactly once, got %d", gate.calls)
	}
	if got := spy.count(mcperr.ReasonRolloutBudgetExhausted); got != 1 {
		t.Fatalf("a credential-path gate refusal must meter its reason exactly once, got %d (all: %v)", got, spy.reasons)
	}
	if got := spy.count(mcperr.ReasonNone); got != 0 {
		t.Fatalf("a credential-path gate refusal must NOT contaminate the ReasonNone series, got %d (all: %v)", got, spy.reasons)
	}
	_ = gate.observedNow() // touch the accessor so it is not flagged unused
}
