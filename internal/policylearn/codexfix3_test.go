package policylearn

// Codex round-3 regressions (PR #1181): producer-wait before the stop
// barrier, drain-held observations in lazy-expiry loss accounting, the
// session-gap confidence cap, and group-scope deduplication.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStopSession_WaitsForInFlightProducers: an Observe that passed the
// active gate but has not completed its enqueue is a REGISTERED producer;
// StopSession must not rotate the window and place the barrier while one is
// registered — otherwise the producer's observation lands with a
// post-rotation generation and resolves as a drop OUTSIDE the session that
// accepted it. Pre-fix, StopSession completed immediately with the producer
// still registered.
func TestStopSession_WaitsForInFlightProducers(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	a, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the in-flight producer: registered (as Observe does first),
	// enqueue not yet performed. Released via Cleanup too so a failing assert
	// can never leave Close (which waits on the producer count) spinning.
	e.tr.producers.Add(1)
	var released atomic.Bool
	releaseProducer := func() {
		if released.CompareAndSwap(false, true) {
			e.tr.producers.Add(-1)
		}
	}
	t.Cleanup(releaseProducer)
	stopDone := make(chan error, 1)
	go func() {
		_, err := e.StopSession("op")
		stopDone <- err
	}()
	barrierWait(t, func() bool { return !e.learningActive.Load() }, "stop turned the gate off")
	select {
	case <-stopDone:
		t.Fatal("StopSession completed while a producer was still registered")
	case <-time.After(50 * time.Millisecond):
	}

	// The producer completes its enqueue: stamped with the CURRENT (pre-
	// rotation) generation, exactly as Observe would.
	e.tr.ch <- queuedItem{o: Observation{
		Subject: "p", AuthSource: "idp", Host: "late.example", Status: "OK",
		At: clk.now().Unix(), gen: e.windowGen.Load(),
	}}
	e.tr.accepted.Add(1)
	releaseProducer()

	if err := <-stopDone; err != nil {
		t.Fatalf("StopSession: %v", err)
	}
	ov, ok := e.SessionOverview(a.ID)
	if !ok || ov.Cells != 1 {
		t.Fatalf("late-enqueued observation not attributed to its accepting session (cells=%d ok=%v)", ov.Cells, ok)
	}
}

// TestLazyExpiry_CountsDrainHeldObservation: an observation the drain has
// DEQUEUED but not yet consumed (it is waiting for e.mu) is invisible to a
// queue-length probe — lazy expiry must still charge it to the expiring
// session's loss accounting, or the terminal window claims zero loss while
// the event resolves as a post-close drop. Pre-fix, Transport.Dropped stayed 0.
func TestLazyExpiry_CountsDrainHeldObservation(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	a, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}

	// Hold e.mu so the drain dequeues the observation and parks on the lock.
	e.mu.Lock()
	e.Observe(Observation{Subject: "a", AuthSource: "idp", Host: "x.example", Status: "OK"})
	barrierWait(t, func() bool { return len(e.tr.ch) == 0 }, "drain dequeued the observation")

	clk.advance(e.cfg.MaxSessionDuration + time.Minute)
	e.maybeExpireLocked(clk.now())
	var dropped int64
	state := ""
	for _, s := range e.sessions {
		if s.ID == a.ID {
			dropped, state = s.Transport.Dropped, s.State
		}
	}
	e.mu.Unlock()

	if state != StateCompleted {
		t.Fatalf("session did not lazily expire (state=%s)", state)
	}
	if dropped == 0 {
		t.Fatal("expired window claims zero loss while the drain held an unconsumed observation")
	}
}

// TestLazyExpiry_DrainHeldLossNotMaskedByEnqueueDrops: the outstanding count
// must subtract only the CONSUME-side drop share — the public Dropped counter
// also contains enqueue-side drops (queue full) that were never accepted, and
// a combined subtraction under that history goes negative and silently
// un-charges a real drain-held loss (undercount — the direction loss
// accounting must never err in).
func TestLazyExpiry_DrainHeldLossNotMaskedByEnqueueDrops(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	a, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}
	// Simulated queue-full history: enqueue-side drops, never accepted.
	e.tr.dropped.Add(5)

	e.mu.Lock()
	e.Observe(Observation{Subject: "a", AuthSource: "idp", Host: "x.example", Status: "OK"})
	barrierWait(t, func() bool { return len(e.tr.ch) == 0 }, "drain dequeued the observation")
	clk.advance(e.cfg.MaxSessionDuration + time.Minute)
	e.maybeExpireLocked(clk.now())
	var dropped int64
	for _, s := range e.sessions {
		if s.ID == a.ID {
			dropped = s.Transport.Dropped
		}
	}
	e.mu.Unlock()

	// 5 folded enqueue-side drops + the 1 drain-held accepted event.
	if dropped != 6 {
		t.Fatalf("drain-held loss masked by enqueue-drop history: window Dropped=%d, want 6", dropped)
	}
}

// TestConfidence_SessionGapCapsBelowHigh: a recorded observation gap (process
// restart while Learning) is unobserved traffic the transport counters could
// not see — it must cap confidence below HIGH and be identified as a limit.
func TestConfidence_SessionGapCapsBelowHigh(t *testing.T) {
	th := Thresholds{}.withDefaults()
	cell := &Cell{Allowed: 100, Subjects: map[string]bool{}, Days: map[string]bool{}}
	for i := 0; i < 10; i++ {
		cell.Subjects[string(rune('a'+i))] = true
		cell.Days["2026-08-0"+string(rune('1'+i))] = true
	}
	clean := &Session{}
	if level, _, _ := confidenceFor(clean, cell, th); level != ConfidenceHigh {
		t.Fatalf("baseline without gaps should be HIGH, got %s", level)
	}
	gapped := &Session{Gaps: []Gap{{At: "2026-08-13T12:00:00Z", Reason: "process_restart"}}}
	level, _, limits := confidenceFor(gapped, cell, th)
	if level == ConfidenceHigh {
		t.Fatal("session with a recorded observation gap still produced HIGH confidence")
	}
	found := false
	for _, l := range limits {
		if strings.HasPrefix(l, "session_gaps:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("gap cap not identified in limits: %v", limits)
	}
}

// TestScopesFor_DuplicateGroupNamesContributeOnce: duplicate group names in
// one identity assertion (OIDC/SAML extractors preserve duplicate claim
// values) must contribute exactly one scope — duplicate scope keys would
// multiply one observation's evidence into the same cell (inflation, the
// direction evidence must never err in).
func TestScopesFor_DuplicateGroupNamesContributeOnce(t *testing.T) {
	got := scopesFor(&Observation{Subject: "u", Groups: []string{"eng", "eng", "ops", "eng"}}, nil)
	if len(got) != 2 || got[0] != "g:eng" || got[1] != "g:ops" {
		t.Fatalf("scopes not deduplicated: %v", got)
	}

	// End-to-end: one allowed observation with a duplicated group must count
	// once in the cell. Pre-fix, Requests/Allowed were 3 for g:eng.
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	e.Observe(Observation{Subject: "u", AuthSource: "idp", Groups: []string{"eng", "eng", "eng"}, Host: "x.example", Status: "OK"})
	sess, err := e.StopSession("op")
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	var cell Cell
	for _, s := range e.sessions {
		if s.ID == sess.ID && s.Agg != nil {
			if c := s.Agg.Cells[CellKey("g:eng", "")]; c != nil {
				cell = *c
			}
		}
	}
	e.mu.Unlock()
	if cell.Requests != 1 || cell.Allowed != 1 {
		t.Fatalf("duplicated group inflated the cell: requests=%d allowed=%d", cell.Requests, cell.Allowed)
	}
}

// ── Codex round-4 regressions ────────────────────────────────────────────────

// TestFinishActive_ConcurrentObserversNeverLeakPastWindowClose (round 4):
// producer registration now precedes the gate check, so an enqueue can only
// happen when the producer was registered AND then observed the gate on — the
// stop's producer wait therefore covers every possible enqueuer, and no
// observation's acceptance can land outside a session window. Stress-guard
// under -race: after the stop, every accepted event is resolved AND every
// accepted/dropped count is attributed to a session window (the pre-fix
// gate-racer leaked its counts into the inter-window gap).
func TestFinishActive_ConcurrentObserversNeverLeakPastWindowClose(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					e.Observe(Observation{Subject: "u", AuthSource: "idp", Host: "x.example", Status: "OK"})
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	close(stop)
	wg.Wait()
	e.drainBarrier()

	st := e.ObservationStats()
	if unresolved := st.Accepted - st.Delivered - e.tr.consumeDropped.Load() - st.ConsumerPanics; unresolved != 0 {
		t.Fatalf("%d unresolved accepted observations after window close: %+v", unresolved, st)
	}
	var winAccepted, winDropped int64
	for _, s := range e.Sessions() {
		winAccepted += s.Transport.Accepted
		winDropped += s.Transport.Dropped
	}
	if winAccepted != st.Accepted || winDropped != st.Dropped {
		t.Fatalf("transport counts leaked outside session windows: windows accepted=%d dropped=%d, global %+v",
			winAccepted, winDropped, st)
	}
}

// TestLoad_RejectsMultipleLearningSessionsToQuarantine (round 4): one-active
// is a load-bearing invariant — a store carrying two Learning records would
// aggregate into one session while the APIs display/complete the other.
// Decode must reject it into the quarantine path, never partially honor it.
func TestLoad_RejectsMultipleLearningSessionsToQuarantine(t *testing.T) {
	dir := t.TempDir()
	raw := `{"schema_version":7,"sessions":[` +
		`{"id":"a","state":"learning","created_at":"2026-08-13T12:00:00Z","started_at":"2026-08-13T12:00:00Z","created_by":"op","baseline":{}},` +
		`{"id":"b","state":"learning","created_at":"2026-08-13T12:01:00Z","started_at":"2026-08-13T12:01:00Z","created_by":"op","baseline":{}}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy_learning.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var quarantined error
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) {
		c.Quarantine = func(_ string, err error) { quarantined = err }
	})
	t.Cleanup(func() { _ = e.Close() })
	if quarantined == nil || !strings.Contains(quarantined.Error(), "learning sessions") {
		t.Fatalf("two-learning store not quarantined (err=%v)", quarantined)
	}
	if n := len(e.Sessions()); n != 0 {
		t.Fatalf("malformed store partially honored: %d sessions loaded", n)
	}
}

// TestObserve_GroupTruncationCountedOnlyOnAcceptedEnqueue (round 4):
// GroupsTruncated means "an ACCEPTED observation carries incomplete group
// context" — an over-wide observation dropped at a full queue must count as a
// drop only, or the truncation counter can exceed Accepted and corrupt the
// coverage facts carried on recommendations.
func TestObserve_GroupTruncationCountedOnlyOnAcceptedEnqueue(t *testing.T) {
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	wide := make([]string, MaxObservationGroups+4)
	for i := range wide {
		wide[i] = fmt.Sprintf("g%d", i)
	}

	// Accepted + truncated: counted (the existing contract).
	e.Observe(Observation{Subject: "u", AuthSource: "idp", Groups: wide, Host: "x.example", Status: "OK"})
	if got := e.ObservationStats().GroupsTruncated; got != 1 {
		t.Fatalf("accepted truncated observation not counted (got %d)", got)
	}

	// Park the drain on e.mu and fill the queue to capacity, then attempt an
	// over-wide observation: dropped, and NOT counted as truncated.
	e.mu.Lock()
	filled := false
	for i := 0; i < observationQueueCap+2; i++ {
		e.Observe(Observation{Subject: "u", AuthSource: "idp", Host: "fill.example", Status: "OK"})
		if len(e.tr.ch) == observationQueueCap {
			filled = true
			break
		}
	}
	if !filled {
		e.mu.Unlock()
		t.Fatal("could not fill the transport queue")
	}
	before := e.ObservationStats()
	e.Observe(Observation{Subject: "u", AuthSource: "idp", Groups: wide, Host: "y.example", Status: "OK"})
	after := e.ObservationStats()
	e.mu.Unlock()
	if after.Dropped != before.Dropped+1 {
		t.Fatalf("full-queue observation not dropped (before=%+v after=%+v)", before, after)
	}
	if after.GroupsTruncated != before.GroupsTruncated {
		t.Fatal("dropped observation counted as truncated-accepted")
	}
}
