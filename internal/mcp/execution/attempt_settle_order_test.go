package execution

// attempt_settle_order_test.go — the health sample must be durable no later than the terminal
// outcome (First Controlled Canary review, blocker #7; Codex round 3).

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
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
