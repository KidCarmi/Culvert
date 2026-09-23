package policylearn

// Isolated deterministic fixtures for paths whose coverage previously depended
// on timing; see roadmap/CI-REDESIGN.md stage 5B.
//
// maybeExpireLocked's `if e.finishing { return }` guard runs only when a READ
// (ActiveSession/Sessions) lands inside the window in which finishActive has
// released e.mu to run its drain barrier. The existing barrier tests create
// that window but never issue a read inside it, so the guard was covered only
// when some unrelated reader happened to interleave. The fixture below holds
// the window open on purpose and reads inside it.

import (
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Pins session.go maybeExpireLocked `if e.finishing { return }` — a lazy
// max-duration expiry must not race an in-progress finish.
//
// Determinism: the Sink blocks the drain on the first observation, so the
// StopSession barrier cannot complete; the test observes e.finishing == true
// (set under e.mu before the barrier, cleared only after it) and only then
// advances the clock past MaxSessionDuration and reads. Without the guard the
// read would flip the session to system:max-duration underneath the finish;
// with it, the session stays Learning until the finish lands and the finish's
// own actor and state win.
func TestIsolation_LazyExpiryDefersToInProgressFinish(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	sinkEntered := make(chan struct{}, 1)

	clk := newTestClock()
	e, err := New(Config{
		Now:                clk.now,
		StorePath:          filepath.Join(dir, "pl.json"),
		SubjectKeyPath:     filepath.Join(dir, "sk.key"),
		MaxSessionDuration: 2 * time.Hour,
		Categories:         func(string) (string, string) { return "Dev Tools", "admin" },
		Sink: func(Observation) {
			select {
			case sinkEntered <- struct{}{}:
			default:
			}
			<-release
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unblock()
		_ = e.Close()
	})
	maxDur := e.cfg.MaxSessionDuration

	started, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}
	e.Observe(Observation{Subject: "alice", AuthSource: "idp", Groups: []string{"eng"},
		Host: "code.example", Method: "GET", Status: "OK"})
	<-sinkEntered // the drain goroutine is now parked inside the Sink

	type stopResult struct {
		s   Session
		err error
	}
	stopDone := make(chan stopResult, 1)
	go func() {
		s, err := e.StopSession("op-finisher")
		stopDone <- stopResult{s, err}
	}()

	// Wait for the finish to enter its barrier window. finishing cannot be
	// cleared while the Sink is blocked, so this observation is stable.
	deadline := time.Now().Add(10 * time.Second)
	for {
		e.mu.Lock()
		f := e.finishing
		e.mu.Unlock()
		if f {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("StopSession never entered its drain-barrier window")
		}
		runtime.Gosched()
	}

	// The session is now overdue. A lazy expiry here would steal the
	// transition from the in-progress finish.
	clk.advance(maxDur + time.Hour)

	active, ok := e.ActiveSession()
	if !ok {
		t.Fatal("ActiveSession expired the session while a finish owned the transition")
	}
	if active.ID != started.ID || active.State != StateLearning {
		t.Fatalf("active session during finish = %+v, want %s still Learning", active, started.ID)
	}
	for _, s := range e.Sessions() {
		if s.ID == started.ID && (s.State != StateLearning || s.StoppedBy != "") {
			t.Fatalf("Sessions() lazily expired the session mid-finish: state=%s stoppedBy=%q", s.State, s.StoppedBy)
		}
	}
	select {
	case r := <-stopDone:
		t.Fatalf("StopSession returned (%+v, %v) while the barrier was still blocked", r.s, r.err)
	default:
	}

	unblock()
	r := <-stopDone
	if r.err != nil {
		t.Fatalf("StopSession: %v", r.err)
	}
	if r.s.State != StateCompleted || r.s.StoppedBy != "op-finisher" {
		t.Fatalf("finished session = state %s stoppedBy %q, want Completed by op-finisher (the finish, not lazy expiry, owns the transition)",
			r.s.State, r.s.StoppedBy)
	}
	if _, ok := e.ActiveSession(); ok {
		t.Fatal("a session is still active after the finish completed")
	}
}
