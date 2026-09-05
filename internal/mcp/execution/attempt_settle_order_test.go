package execution

// attempt_settle_order_test.go — the health sample must be durable no later than the terminal
// outcome (First Controlled Canary review, blocker #7; Codex round 3).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// countingBackend wraps the real OS backend and counts durable appends, so a test can ask "how many
// events were durable at the moment the health sample was reported".
type countingBackend struct {
	spool.Backend
	mu      sync.Mutex
	appends int
}

func (b *countingBackend) AppendSync(path string, frame []byte, perm os.FileMode) error {
	err := b.Backend.AppendSync(path, frame, perm)
	if err == nil {
		b.mu.Lock()
		b.appends++
		b.mu.Unlock()
	}
	return err
}

func (b *countingBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.appends
}

// orderSafety records the durable-append count observed when AttemptSettled fired.
type orderSafety struct {
	be           *countingBackend
	mu           sync.Mutex
	settled      bool
	appendsThen  int
	breachCodes  []string
	settledCount int
}

func (s *orderSafety) Breach(_ string, _ uint64, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.breachCodes = append(s.breachCodes, code)
}

func (s *orderSafety) AttemptSettled(_ string, _ uint64, _ bool, _ time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settled = true
	s.settledCount++
	s.appendsThen = s.be.count()
}

// TestAttemptSettled_IsReportedBeforeTheTerminalOutcomeCommit pins the ORDER, not merely that both
// happen.
//
// AttemptSettled persists the detector counters; CommitDecision persists the terminal outcome. If
// the outcome is durable FIRST, a crash in between leaves the ledger proving a settled attempt while
// the runtime snapshot omits its health sample — and restore legitimately accepts fewer samples than
// reservations (a reservation refused at the boundary settles nothing), so that missing sample is
// indistinguishable from one that never happened. A failed first attempt would simply disappear and
// the next failure would be counted as sample one (Codex round 3 P1).
//
// The assertion is that the settle observed strictly fewer durable events than exist at the end:
// i.e. the terminal outcome had NOT yet been written when the sample was reported.
func TestAttemptSettled_IsReportedBeforeTheTerminalOutcomeCommit(t *testing.T) {
	be := &countingBackend{Backend: spool.NewOSBackend()}
	sfy := &orderSafety{be: be}
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, be))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = identityGate{reservationID: "rsv_order", generation: 7}

	in := execInput(policy.ActionAllow, false)
	_ = e.Execute(context.Background(), in, e.Resolve(in))

	if !sfy.settled {
		t.Fatal("premise: a completed execution must report one settled attempt")
	}
	if sfy.settledCount != 1 {
		t.Fatalf("exactly one settle per attempt, got %d", sfy.settledCount)
	}
	total := be.count()
	if total == 0 {
		t.Fatal("premise: the execution must have written durable events")
	}
	if sfy.appendsThen >= total {
		t.Fatalf("SECURITY: the health sample must be reported BEFORE the terminal outcome is durable; "+
			"appends at settle=%d, total=%d (the outcome was already written)", sfy.appendsThen, total)
	}
}

// failSafety records the failure flags AttemptSettled reported.
type failSafety struct {
	mu     sync.Mutex
	failed []bool
}

func (s *failSafety) Breach(string, uint64, string) {}
func (s *failSafety) AttemptSettled(_ string, _ uint64, failed bool, _ time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, failed)
}

func (s *failSafety) flags() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bool(nil), s.failed...)
}

// TestAttemptSettled_PeerErrorResponseCountsAsAFailure is the gate for the failure predicate.
//
// run.go records SendPeerResponseReceived for a non-200, an unreadable body and an undecodable one,
// because a peer that answers badly has still RUN the tool. Deriving "failed" from receipt therefore
// counted an HTTP 500 as a SUCCESS: two consecutive upstream errors produced zero failures, never
// reached the 1-of-2 elevated_error_rate threshold, and a third execution was admitted against a
// demonstrably unhealthy target (Codex round 5 P1).
func TestAttemptSettled_PeerErrorResponseCountsAsAFailure(t *testing.T) {
	sfy := &failSafety{}
	// The error must carry the OBSERVED-RESPONSE fact, or the fixture does not reproduce the
	// defect: a bare error leaves the send state at may_have_been_sent, where the old
	// receipt-derived predicate ALSO reports failure and the gate proves nothing. This is the shape
	// the production client returns for a non-200.
	up := &fakeUpstream{err: upstreamclient.MarkResponseObservedForTest(errors.New("upstream returned HTTP 500"))}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = identityGate{reservationID: "rsv_err", generation: 7}

	in := execInput(policy.ActionAllow, false)
	_ = e.Execute(context.Background(), in, e.Resolve(in))

	got := sfy.flags()
	if len(got) != 1 {
		t.Fatalf("exactly one settled attempt expected, got %d", len(got))
	}
	if !got[0] {
		t.Fatal("SECURITY: an upstream error response must count as a FAILED attempt — " +
			"the detector cannot see an unhealthy peer otherwise")
	}
}

// THE CONTROL: an ordinary successful execution must still report failed=false, or the detector
// would trip on healthy traffic and the fix would be satisfiable by counting everything.
func TestAttemptSettled_SuccessfulExecutionIsNotAFailure(t *testing.T) {
	sfy := &failSafety{}
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = identityGate{reservationID: "rsv_ok", generation: 7}

	in := execInput(policy.ActionAllow, false)
	_ = e.Execute(context.Background(), in, e.Resolve(in))

	got := sfy.flags()
	if len(got) != 1 {
		t.Fatalf("exactly one settled attempt expected, got %d", len(got))
	}
	if got[0] {
		t.Fatal("a successful execution must not count as a failure")
	}
}

// jsonrpcErrorUpstream answers with a decoded JSON-RPC `error` object: a NON-NIL response and a NIL
// Go error. That is the shape upstreamclient.Client.Call returns when the peer answers correctly at
// the transport level and reports that the TOOL failed, and it is the most ordinary tool failure
// there is. The shared fakeUpstream cannot produce it — its error field short-circuits to a nil
// response — so reproducing the defect needs its own double.
type jsonrpcErrorUpstream struct{ calls int }

func (u *jsonrpcErrorUpstream) Call(_ context.Context, _ upstreamclient.Target, _ string, _ json.RawMessage, _ upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	u.calls++
	return &upstreamclient.Response{
		ID:       jsonrpc.ID{Kind: jsonrpc.IDString, Str: "u"},
		Error:    &jsonrpc.ErrorObject{Code: -32000, Message: "tool execution failed"},
		RawBytes: []byte(`{"error":{"code":-32000}}`),
	}, nil
}

// TestAttemptSettled_PeerJSONRPCErrorCountsAsAFailure is the gate for the third failure shape.
//
// The peer answered, the body decoded, and it said the tool did not work. finishUpstream already
// classifies exactly this response as ReasonUpstreamCallFailed — but a transport-only predicate
// (err != nil || resp == nil) reports failed=false, so two such tool failures produced ZERO
// failures, never reached the 1-of-2 elevated_error_rate threshold, and a third execution was
// admitted against a target that had just failed twice (Codex round 6 P1).
//
// This is the round-5 defect one shape further in, which is why it gets its own gate rather than a
// widened assertion on the existing one: each shape can regress independently.
func TestAttemptSettled_PeerJSONRPCErrorCountsAsAFailure(t *testing.T) {
	sfy := &failSafety{}
	up := &jsonrpcErrorUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = identityGate{reservationID: "rsv_rpcerr", generation: 7}

	in := execInput(policy.ActionAllow, false)
	_ = e.Execute(context.Background(), in, e.Resolve(in))

	if up.calls != 1 {
		t.Fatalf("the upstream must have been called exactly once, got %d", up.calls)
	}
	got := sfy.flags()
	if len(got) != 1 {
		t.Fatalf("exactly one settled attempt expected, got %d", len(got))
	}
	if !got[0] {
		t.Fatal("SECURITY: a JSON-RPC error response is the peer saying the tool failed — " +
			"counting it as a success blinds the error-rate detector to the most ordinary " +
			"failure mode there is")
	}
}

// releaseOrderGate hands out a Release that counts its own invocations, so a Safety double can ask
// "had the slot already gone back when this attempt settled?".
type releaseOrderGate struct {
	reservationID string
	generation    uint64
	releases      *int32
}

func (g releaseOrderGate) AdmitSideEffect(LiveGateInput) LiveGateDecision {
	return LiveGateDecision{
		Admit: true, Release: func() { atomic.AddInt32(g.releases, 1) },
		ReservationID: g.reservationID, ActivationGeneration: g.generation,
	}
}

// releaseOrderSafety captures the release count observed at the instant AttemptSettled fired.
type releaseOrderSafety struct {
	releases      *int32
	mu            sync.Mutex
	settled       int
	releasesAt    int32
	settledFailed bool
}

func (s *releaseOrderSafety) Breach(string, uint64, string) {}

func (s *releaseOrderSafety) AttemptSettled(_ string, _ uint64, failed bool, _ time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settled++
	s.settledFailed = failed
	s.releasesAt = atomic.LoadInt32(s.releases)
}

// TestAttemptSettled_IsReportedBeforeTheReservationIsReleased pins the second ordering the settle
// carries, and it is the one that decides whether a reachable threshold actually STOPS anything.
//
// The settle is what may latch elevated_error_rate. The release is what lets the next request
// reserve. Ordered the other way — release deferred inside callUpstream, settle deferred by the
// outer runExecute — the release necessarily ran first, because an inner closure's defers run when
// the closure returns. With MaxConcurrentExecutions of 1 that means: the second failing call
// returns, its slot comes back, a waiting third request reserves and crosses Upstream.Call, and
// only THEN is the second failure counted. The 1-of-2 threshold was reachable and still failed to
// prevent the next physical invocation (Codex round 7 P1).
//
// The assertion is that ZERO releases had happened when the sample was reported. That is exactly
// the property; it does not depend on scheduling, a sleep, or a second goroutine.
func TestAttemptSettled_IsReportedBeforeTheReservationIsReleased(t *testing.T) {
	var releases int32
	sfy := &releaseOrderSafety{releases: &releases}
	up := &jsonrpcErrorUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = releaseOrderGate{reservationID: "rsv_rel", generation: 7, releases: &releases}

	in := execInput(policy.ActionAllow, false)
	_ = e.Execute(context.Background(), in, e.Resolve(in))

	if sfy.settled != 1 {
		t.Fatalf("exactly one settled attempt expected, got %d", sfy.settled)
	}
	if !sfy.settledFailed {
		t.Fatal("premise: this fixture must settle as a FAILURE, or the ordering it pins is moot")
	}
	if sfy.releasesAt != 0 {
		t.Fatalf("SECURITY: the slot was released before the attempt settled (%d release(s) already "+
			"done) — the next request can reserve and reach the upstream before the failure that "+
			"should have stopped the Canary is even counted", sfy.releasesAt)
	}
	// THE CONTROL: the slot must still come back. An "ordering fix" that leaked the reservation
	// would satisfy the assertion above and break the budget's own accounting (§11).
	if got := atomic.LoadInt32(&releases); got != 1 {
		t.Fatalf("the reservation must still be released exactly once, got %d", got)
	}
}
