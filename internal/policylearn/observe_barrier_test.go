package policylearn

// Codex-review fixes (PR #1181): the session-close drain barrier, terminal-
// aggregate immutability, window-generation attribution, closed-transport
// refusal, and transactional prune rollback. Each test here fails on the
// pre-fix implementation.

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func barrierWait(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// TestStopSession_DrainsBacklogBeforeCompleting: with a backlog parked behind
// a blocked consumer, StopSession must BLOCK until every observation accepted
// under the session's window is aggregated into it, the completed aggregate
// must then be immutable, and a subsequent StartSession must never consume
// the prior window's events. Pre-fix: StopSession returned immediately with
// the backlog unaggregated, and the next session consumed it.
func TestStopSession_DrainsBacklogBeforeCompleting(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var releaseOnce atomic.Bool
	var sinkEntered atomic.Bool
	clk := newTestClock()
	e, err := New(Config{
		Now:            clk.now,
		StorePath:      filepath.Join(dir, "pl.json"),
		SubjectKeyPath: filepath.Join(dir, "sk.key"),
		Categories:     func(string) (string, string) { return "Dev Tools", "admin" },
		Sink: func(Observation) {
			sinkEntered.Store(true)
			<-release
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if releaseOnce.CompareAndSwap(false, true) {
			close(release)
		}
		_ = e.Close()
	})

	a, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		e.Observe(Observation{Subject: "alice", AuthSource: "idp", Groups: []string{"eng"},
			Host: "code.example", Method: "GET", Status: "OK"})
	}
	barrierWait(t, sinkEntered.Load, "drain to park in the blocked sink")

	stopDone := make(chan error, 1)
	go func() {
		_, err := e.StopSession("op")
		stopDone <- err
	}()
	select {
	case <-stopDone:
		t.Fatal("StopSession returned while accepted observations were still queued — no drain barrier")
	case <-time.After(150 * time.Millisecond):
	}
	if releaseOnce.CompareAndSwap(false, true) {
		close(release)
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("StopSession: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StopSession did not return after the backlog drained")
	}

	cellAllowed := func(id string) int64 {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, s := range e.sessions {
			if s.ID == id && s.Agg != nil {
				if c := s.Agg.Cells[CellKey("g:eng", "Dev Tools")]; c != nil {
					return c.Allowed
				}
			}
		}
		return 0
	}
	if got := cellAllowed(a.ID); got != 5 {
		t.Fatalf("completed session aggregated %d of 5 accepted observations", got)
	}

	// The next session must receive ONLY its own window's events, and the
	// completed aggregate must not move.
	b, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		e.Observe(Observation{Subject: "bob", AuthSource: "idp", Groups: []string{"eng"},
			Host: "code.example", Method: "GET", Status: "OK"})
	}
	barrierWait(t, func() bool { return e.ObservationStats().Delivered >= 7 }, "session B delivery")
	if got := cellAllowed(b.ID); got != 2 {
		t.Fatalf("session B aggregated %d observations, want exactly its own 2", got)
	}
	if got := cellAllowed(a.ID); got != 5 {
		t.Fatalf("terminal aggregate mutated after completion: %d", got)
	}
}

// TestObserve_RefusedAndCountedAfterClose: once the drain has exited, a
// producer must not enqueue successfully into the abandoned channel — the
// observation is refused at the gate and COUNTED as a drop. Pre-fix: it was
// counted Accepted and silently lost.
func TestObserve_RefusedAndCountedAfterClose(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e, err := New(Config{
		Now:            clk.now,
		StorePath:      filepath.Join(dir, "pl.json"),
		SubjectKeyPath: filepath.Join(dir, "sk.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	e.Observe(Observation{Subject: "a", AuthSource: "idp", Host: "x.example", Status: "OK"})
	barrierWait(t, func() bool { return e.ObservationStats().Delivered >= 1 }, "pre-close delivery")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	before := e.ObservationStats()
	e.Observe(Observation{Subject: "a", AuthSource: "idp", Host: "x.example", Status: "OK"})
	st := e.ObservationStats()
	if st.Accepted != before.Accepted {
		t.Fatalf("post-close Observe was accepted into an abandoned channel (accepted %d -> %d)",
			before.Accepted, st.Accepted)
	}
	if st.Dropped != before.Dropped+1 {
		t.Fatalf("post-close Observe not counted as a drop (dropped %d -> %d)", before.Dropped, st.Dropped)
	}
}

// TestFinishActive_PersistFailureRestoresPrunedSessions: completing a session
// at the retention cap prunes the oldest terminal record BEFORE the save; a
// failed save must restore the pruned membership, not just the active
// session's fields — otherwise a transition that reported failure silently
// destroyed history. Pre-fix: the pruned record was permanently lost.
func TestFinishActive_PersistFailureRestoresPrunedSessions(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o750); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e, err := New(Config{
		Now:                 clk.now,
		StorePath:           filepath.Join(store, "pl.json"),
		SubjectKeyPath:      filepath.Join(dir, "sk.key"),
		MaxRetainedSessions: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })

	s1, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.StopSession("op"); err != nil {
		t.Fatal(err)
	}
	s2, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}

	// Break the durable store: completing s2 would prune s1, and the save fails.
	if err := os.RemoveAll(store); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StopSession("op"); err == nil {
		t.Fatal("StopSession succeeded with the store directory removed")
	}

	// Invariant: the failed transition changed NOTHING — s1 retained, s2 learning.
	foundS1 := false
	for _, s := range e.Sessions() {
		if s.ID == s1.ID {
			foundS1 = true
		}
	}
	if !foundS1 {
		t.Fatal("failed completion permanently pruned the oldest terminal session")
	}
	active, ok := e.ActiveSession()
	if !ok || active.ID != s2.ID {
		t.Fatalf("active session not restored after failed completion: ok=%v", ok)
	}

	// Recovery: restore the volume; the retried completion succeeds and the
	// prune now happens as part of a SUCCESSFUL transition.
	if err := os.Mkdir(store, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StopSession("op"); err != nil {
		t.Fatalf("retried completion: %v", err)
	}
}

// TestScopesFor_EmptyGroupNamesNeverMintRealGroupScope (Codex re-review):
// an IdP emitting an empty group array entry must never create the scope
// "g:" — generation would strip the prefix into SourceGroup == "", which a
// PolicyRule treats as "any source". Empty entries are skipped; all-empty
// groups aggregate as groupless.
func TestScopesFor_EmptyGroupNamesNeverMintRealGroupScope(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e, err := New(Config{
		Now:            clk.now,
		StorePath:      filepath.Join(dir, "pl.json"),
		SubjectKeyPath: filepath.Join(dir, "sk.key"),
		Categories:     func(string) (string, string) { return "Dev Tools", "admin" },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	e.Observe(Observation{Subject: "a", AuthSource: "idp", Groups: []string{"", "eng"},
		Host: "code.example", Status: "OK"})
	e.Observe(Observation{Subject: "b", AuthSource: "idp", Groups: []string{""},
		Host: "code.example", Status: "OK"})
	barrierWait(t, func() bool { return e.ObservationStats().Delivered >= 2 }, "delivery")
	e.mu.Lock()
	defer e.mu.Unlock()
	agg := e.aggSession.Agg
	if c := agg.Cells[CellKey(scopeGroupPrefix, "Dev Tools")]; c != nil {
		t.Fatalf("empty group name minted the real-group scope %q", scopeGroupPrefix)
	}
	if c := agg.Cells[CellKey("g:eng", "Dev Tools")]; c == nil || c.Allowed != 1 {
		t.Fatal("non-empty group did not aggregate")
	}
	if c := agg.Cells[CellKey(ScopeGroupless, "Dev Tools")]; c == nil || c.Allowed != 1 {
		t.Fatal("all-empty groups did not aggregate as groupless")
	}
}

// TestGenerate_EmptyGroupScopeSkippedAsSynthetic (Codex re-review, defense in
// depth): a legacy persisted cell under the bare "g:" scope must never
// generate a recommendation (SourceGroup "" would mean "any source").
func TestGenerate_EmptyGroupScopeSkippedAsSynthetic(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e, err := New(Config{
		Now:                     clk.now,
		StorePath:               filepath.Join(dir, "pl.json"),
		SubjectKeyPath:          filepath.Join(dir, "sk.key"),
		RecommendableCategories: []string{"Dev Tools"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	done, err := e.StopSession("op")
	if err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	sess := e.sessions[len(e.sessions)-1]
	if sess.Agg == nil {
		sess.Agg = newAggregate()
	}
	sess.Agg.Cells[CellKey(scopeGroupPrefix, "Dev Tools")] = &Cell{Requests: 5, Allowed: 5}
	e.mu.Unlock()
	res, err := e.GenerateRecommendations(done.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Recommendations) != 0 {
		t.Fatalf("empty-group scope generated %d recommendation(s): first group %q",
			len(res.Recommendations), res.Recommendations[0].Group)
	}
	if res.SkippedSyntheticScope == 0 {
		t.Fatal("empty-group scope not counted as a synthetic skip")
	}
}

// TestLazyExpiry_AttributesQueuedBacklogToExpiredWindow (Codex re-review):
// max-duration expiry cannot run a drain barrier (it fires under e.mu from
// read paths), so the still-queued backlog of the expired window must be
// attributed to the expired session's loss accounting — a generate from it
// then sees a DEGRADED window instead of a clean one.
func TestLazyExpiry_AttributesQueuedBacklogToExpiredWindow(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var releaseOnce atomic.Bool
	var sinkEntered atomic.Bool
	clk := newTestClock()
	e, err := New(Config{
		Now:            clk.now,
		StorePath:      filepath.Join(dir, "pl.json"),
		SubjectKeyPath: filepath.Join(dir, "sk.key"),
		Sink: func(Observation) {
			sinkEntered.Store(true)
			<-release
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if releaseOnce.CompareAndSwap(false, true) {
			close(release)
		}
		_ = e.Close()
	})
	a, err := e.StartSession("op")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		e.Observe(Observation{Subject: "a", AuthSource: "idp", Host: "x.example", Status: "OK"})
	}
	barrierWait(t, sinkEntered.Load, "drain parked in sink")

	clk.advance(e.cfg.MaxSessionDuration + time.Minute)
	sessions := e.Sessions() // triggers lazy expiry with the backlog still queued
	var expired *Session
	for i := range sessions {
		if sessions[i].ID == a.ID {
			expired = &sessions[i]
		}
	}
	if expired == nil || expired.State != StateCompleted {
		t.Fatalf("session did not lazily expire: %+v", expired)
	}
	if expired.Transport.Dropped == 0 {
		t.Fatal("expired session's window shows zero loss despite a doomed queued backlog")
	}
	if !expired.Transport.Degraded() {
		t.Fatal("expired window not degraded")
	}
}

// TestClose_ConcurrentProducersNeverStrandEvents (Codex re-review): the
// producer gate makes the closed-check-then-send atomic with shutdown — after
// Close returns, no event may remain in the channel.
func TestClose_ConcurrentProducersNeverStrandEvents(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e, err := New(Config{
		Now:            clk.now,
		StorePath:      filepath.Join(dir, "pl.json"),
		SubjectKeyPath: filepath.Join(dir, "sk.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	stopProducers := make(chan struct{})
	producersDone := make(chan struct{})
	go func() {
		defer close(producersDone)
		for {
			select {
			case <-stopProducers:
				return
			default:
				e.Observe(Observation{Subject: "a", AuthSource: "idp", Host: "x.example", Status: "OK"})
			}
		}
	}()
	time.Sleep(10 * time.Millisecond)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	close(stopProducers)
	<-producersDone
	if n := len(e.tr.ch); n != 0 {
		t.Fatalf("%d event(s) stranded in the channel after Close", n)
	}
}
