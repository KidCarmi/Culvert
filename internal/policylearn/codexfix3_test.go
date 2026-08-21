package policylearn

// Codex round-3 regressions (PR #1181): producer-wait before the stop
// barrier, drain-held observations in lazy-expiry loss accounting, the
// session-gap confidence cap, and group-scope deduplication.

import (
	"errors"
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

// TestStartSession_RefusedAfterClose (round 7): the engine closes at shutdown
// order 67 while the admin UI stops at 70, so a session start can still
// arrive after Close — it must refuse rather than persist a new active
// session and arm the gate on a closed transport (whose observations could
// only ever become unpersistable post-final-save drops).
func TestStartSession_RefusedAfterClose(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, nil)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StartSession("op"); !errors.Is(err, ErrEngineClosed) {
		t.Fatalf("post-close StartSession not refused (err=%v)", err)
	}
	if e.LearningActive() {
		t.Fatal("post-close start armed the learning gate")
	}
	e2 := newTestEngine(t, dir, clk, nil)
	t.Cleanup(func() { _ = e2.Close() })
	if n := len(e2.Sessions()); n != 0 {
		t.Fatalf("post-close start persisted a session (%d found)", n)
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

// TestScopesFor_CaseAndWhitespaceVariantsShareOneScope (round 9): enforcement
// compares groups trimmed and case-insensitively, so case/whitespace variants
// of one group are ONE population — they must fold to one canonical scope,
// not split evidence across cells or mint duplicate recommendations.
func TestScopesFor_CaseAndWhitespaceVariantsShareOneScope(t *testing.T) {
	got := scopesFor(&Observation{Subject: "u", Groups: []string{"Engineering", " engineering ", "ENGINEERING", "\tEngineering"}}, nil)
	if len(got) != 1 || got[0] != "g:engineering" {
		t.Fatalf("case/whitespace variants not folded to one canonical scope: %v", got)
	}
	// Whitespace-only entries fold to empty and are skipped (groupless when
	// nothing else remains).
	got = scopesFor(&Observation{Subject: "u", Groups: []string{"   ", "\t"}}, nil)
	if len(got) != 1 || got[0] != ScopeGroupless {
		t.Fatalf("whitespace-only groups did not aggregate as groupless: %v", got)
	}
}

// TestScopesFor_EqualFoldEquivalentsShareOneScope (round 10): the canonical
// fold must implement enforcement's FULL EqualFold equivalence, not ASCII
// ToLower — Σ/ς/σ, S/ſ, and K/U+212A compare equal under containsGroupCI's
// EqualFold but lower to different strings.
func TestScopesFor_EqualFoldEquivalentsShareOneScope(t *testing.T) {
	cases := [][]string{
		{"\u03a3\u0391\u039b\u0395\u03a3", "\u03c3\u03b1\u03bb\u03b5\u03c2"}, // sigma forms compare equal under EqualFold
		{"Sales", "\u017fales"},   // long s (U+017F) vs S
		{"Kelvin", "\u212aelvin"}, // Kelvin sign (U+212A) vs K
	}
	for _, groups := range cases {
		got := scopesFor(&Observation{Subject: "u", Groups: groups}, nil)
		if len(got) != 1 {
			t.Fatalf("EqualFold-equivalent variants %q not folded to one scope: %v", groups, got)
		}
		for _, g := range groups {
			folded := got[0][len(scopeGroupPrefix):]
			if !strings.EqualFold(strings.TrimSpace(g), folded) {
				t.Fatalf("canonical scope %q not EqualFold-equal to source %q", folded, g)
			}
		}
	}
}

// TestScopesFor_DistinctFoldCyclesStayDistinct (round 11): the canonical fold
// must never MERGE distinct EqualFold cycles — İ (U+0130) is a singleton
// cycle (EqualFold("İ","i") is false), but an unconditional ToLower mapped it
// onto ASCII i, so a group named İ would be recommended as (and authorize)
// the different ASCII-I population.
func TestScopesFor_DistinctFoldCyclesStayDistinct(t *testing.T) {
	got := scopesFor(&Observation{Subject: "u", Groups: []string{"İT", "it"}}, nil)
	if len(got) != 2 {
		t.Fatalf("EqualFold-DISTINCT groups merged into one scope: %v", got)
	}
	for _, s := range got {
		folded := s[len(scopeGroupPrefix):]
		if folded != "it" && !strings.EqualFold(folded, "İT") {
			t.Fatalf("scope %q is EqualFold-equal to neither source group", folded)
		}
	}
}

// TestClose_PersistsTransportOnlyDeltas (round 5): a transport-only counter
// change after the last cadence save (an empty-host rejection, a consumer
// panic) modifies the active session's TransportWindow at Close's final sync
// but set no dirty flag — Close returned without writing it, and the next
// process reloaded a window missing recorded loss.
func TestClose_PersistsTransportOnlyDeltas(t *testing.T) {
	dir := t.TempDir()
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, nil)
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	// Transport-only event: rejected at the gate (empty host), no aggregation,
	// no cadence save — the store believes itself clean.
	e.Observe(Observation{Subject: "u", AuthSource: "idp", Host: "", Status: "OK"})
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	e2 := newTestEngine(t, dir, clk, nil)
	t.Cleanup(func() { _ = e2.Close() })
	sessions := e2.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 reloaded session, got %d", len(sessions))
	}
	if sessions[0].Transport.Rejected != 1 {
		t.Fatalf("transport-only delta lost across Close/reload: %+v", sessions[0].Transport)
	}
}

// TestLoad_LegacyActiveSessionPinnedToCurrentKey (round 5): an active session
// with NO subject-key pin (pre-pseudonym schema) must be pinned to the
// current key at load — unpinned, a later key loss would merge disjoint token
// populations without ever setting SubjectKeyChanged (double-counting
// subjects), and the blank ID is skipped by staleness so it never surfaces.
// A session already carrying subject evidence under an unknowable key must
// additionally record the discontinuity.
func TestLoad_LegacyActiveSessionPinnedToCurrentKey(t *testing.T) {
	dir := t.TempDir()
	raw := `{"schema_version":7,"sessions":[` +
		`{"id":"a","state":"learning","created_at":"2026-08-13T12:00:00Z","started_at":"2026-08-13T12:00:00Z","created_by":"op","baseline":{}}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy_learning.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	sessions := e.Sessions()
	if len(sessions) != 1 || sessions[0].SubjectKeyID != e.SubjectKeyID() || e.SubjectKeyID() == "" {
		t.Fatalf("legacy active session not pinned to the current key: %+v (want key %q)", sessions[0], e.SubjectKeyID())
	}
	ov, _ := e.SessionOverview("a")
	if ov.SubjectKeyChanged {
		t.Fatal("clean legacy session (no subject evidence) flagged as key-changed")
	}
}

// TestLoad_LegacyUnpinnedSessionWithTokensRecordsDiscontinuity (round 5): the
// unknowable-key variant — subject evidence exists, so the merge hazard is
// real and must be recorded, never silently pinned over.
func TestLoad_LegacyUnpinnedSessionWithTokensRecordsDiscontinuity(t *testing.T) {
	dir := t.TempDir()
	raw := `{"schema_version":7,"sessions":[` +
		`{"id":"a","state":"learning","created_at":"2026-08-13T12:00:00Z","started_at":"2026-08-13T12:00:00Z","created_by":"op","baseline":{},` +
		`"agg":{"subject_budget_used":3}}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy_learning.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, nil)
	t.Cleanup(func() { _ = e.Close() })
	ov, ok := e.SessionOverview("a")
	if !ok || !ov.SubjectKeyChanged {
		t.Fatalf("unpinned session with subject evidence not flagged key-changed (ok=%v ov=%+v)", ok, ov)
	}
	sessions := e.Sessions()
	found := false
	for _, g := range sessions[0].Gaps {
		if g.Reason == "subject_key_changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("subject_key_changed gap not recorded: %+v", sessions[0].Gaps)
	}
}

// TestChurn_TransientEpochRoundTripWithinCadenceLatched (round 13): a
// taxonomy A→B→A round trip completing within fewer than 64 delivered
// observations evaded the old cadence check — observations classified under
// B looked baseline-consistent. The churn latch now runs per consumed
// observation.
func TestChurn_TransientEpochRoundTripWithinCadenceLatched(t *testing.T) {
	var epoch atomic.Value
	epoch.Store("A")
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, func(c *Config) {
		c.CategoryEpoch = func() string { return epoch.Load().(string) }
	})
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	obs := func() {
		before := e.ObservationStats().Delivered
		e.Observe(Observation{Subject: "u", AuthSource: "idp", Host: "x.example", Status: "OK"})
		barrierWait(t, func() bool { return e.ObservationStats().Delivered > before }, "observation delivered")
	}
	obs()
	epoch.Store("B")
	obs() // classified while the taxonomy is B — far below the old 64 cadence
	epoch.Store("A")
	obs()
	sess, err := e.StopSession("op")
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.CategoryChurn) < 2 {
		t.Fatalf("A→B→A round trip within the old cadence window not latched: churn=%v", sess.CategoryChurn)
	}
}

// TestChurn_TransientPolicyRoundTripLatched (round 13): evidence collected
// under a TRANSIENT policy change (A→B→A) is invisible to the generation-time
// content-hash comparison — the restored hash matches the baseline again.
// The per-observation policy-content latch records it as it happens, and the
// churn caps confidence below HIGH.
func TestChurn_TransientPolicyRoundTripLatched(t *testing.T) {
	var content atomic.Value
	content.Store("hash-A")
	clk := newTestClock()
	e := newTestEngine(t, t.TempDir(), clk, func(c *Config) {
		c.Baseline = func() Baseline { return Baseline{PolicyContentHash: content.Load().(string)} }
		c.PolicyContent = func() string { return content.Load().(string) }
	})
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	obs := func() {
		before := e.ObservationStats().Delivered
		e.Observe(Observation{Subject: "u", AuthSource: "idp", Host: "x.example", Status: "OK"})
		barrierWait(t, func() bool { return e.ObservationStats().Delivered > before }, "observation delivered")
	}
	obs()
	content.Store("hash-B")
	obs()
	content.Store("hash-A") // restored — the identity comparison alone sees no change
	obs()
	sess, err := e.StopSession("op")
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.PolicyChurn) < 2 {
		t.Fatalf("transient policy round trip not latched: churn=%v", sess.PolicyChurn)
	}

	// The churn caps confidence below HIGH with an identified limit.
	th := Thresholds{}.withDefaults()
	cell := &Cell{Allowed: 100, Subjects: map[string]bool{}, Days: map[string]bool{}}
	for i := 0; i < 10; i++ {
		cell.Subjects[string(rune('a'+i))] = true
		cell.Days["2026-08-0"+string(rune('1'+i))] = true
	}
	level, _, limits := confidenceFor(&sess, cell, th)
	if level == ConfidenceHigh {
		t.Fatal("policy-churned session still produced HIGH confidence")
	}
	found := false
	for _, l := range limits {
		if strings.HasPrefix(l, "policy_churn:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("policy churn not identified in limits: %v", limits)
	}
}

// TestFinishActive_PersistFailureRecordsGap (round 13): the gate is OFF for
// the whole drain + failed write of a stop — requests in that interval went
// unobserved. Reopening the session without recording the window as a gap
// let a later successful completion claim full confidence over it.
func TestFinishActive_PersistFailureRecordsGap(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.Mkdir(store, 0o750); err != nil {
		t.Fatal(err)
	}
	clk := newTestClock()
	e, err := New(Config{
		Now:            clk.now,
		StorePath:      filepath.Join(store, "pl.json"),
		SubjectKeyPath: filepath.Join(dir, "sk.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if _, err := e.StartSession("op"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(store); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StopSession("op"); err == nil {
		t.Fatal("StopSession succeeded with the store directory removed")
	}
	sessions := e.Sessions()
	if len(sessions) != 1 || sessions[0].State != StateLearning {
		t.Fatalf("failed stop did not resume the session: %+v", sessions)
	}
	found := false
	for _, g := range sessions[0].Gaps {
		if g.Reason == "failed_transition" {
			found = true
		}
	}
	if !found {
		t.Fatalf("failed-transition window not recorded as a gap: %+v", sessions[0].Gaps)
	}
}

// TestLoad_RejectsNullAggregateCellToQuarantine (round 12): a syntactically
// valid store carrying `"cells":{"…":null}` must quarantine at decode — the
// aggregate consumers dereference cell fields, so a nil cell would panic
// every later recommendation generation for the session.
func TestLoad_RejectsNullAggregateCellToQuarantine(t *testing.T) {
	dir := t.TempDir()
	raw := `{"schema_version":7,"sessions":[` +
		`{"id":"a","state":"completed","created_at":"2026-08-13T12:00:00Z","started_at":"2026-08-13T12:00:00Z",` +
		`"stopped_at":"2026-08-13T13:00:00Z","created_by":"op","stopped_by":"op","baseline":{},` +
		`"agg":{"cells":{"g:eng\\u001fBusiness":null}}}]}`
	if err := os.WriteFile(filepath.Join(dir, "policy_learning.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var quarantined error
	clk := newTestClock()
	e := newTestEngine(t, dir, clk, func(c *Config) {
		c.Quarantine = func(_ string, err error) { quarantined = err }
	})
	t.Cleanup(func() { _ = e.Close() })
	if quarantined == nil || !strings.Contains(quarantined.Error(), "null aggregate cell") {
		t.Fatalf("null-cell store not quarantined (err=%v)", quarantined)
	}
	if n := len(e.Sessions()); n != 0 {
		t.Fatalf("corrupt store partially honored: %d sessions loaded", n)
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
