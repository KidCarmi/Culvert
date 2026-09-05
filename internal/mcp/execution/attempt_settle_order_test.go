package execution

// attempt_settle_order_test.go — the health sample must be durable no later than the terminal
// outcome (First Controlled Canary review, blocker #7; Codex round 3).

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
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
