package livetier

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAdmissionOpen_MatchesAdmitExecution pins the tier predicate the revalidation reads
// against the admission it mirrors. They must agree on every state, or the boundary
// re-check would answer a different question from the admission — in particular
// admitClosed, which is the bit quiesce and demote actually set.
func TestAdmissionOpen_MatchesAdmitExecution(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state       State
		admitClosed bool
		want        bool
	}{
		{"absent", Absent, false, false},
		{"composed but unarmed", Composed, false, false},
		{"armed", Armed, false, true},
		{"armed with admission closed (demoted)", Armed, true, false},
		{"quiescing", Quiescing, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lt := New(Options{})
			lt.state, lt.admitClosed = tc.state, tc.admitClosed
			if got := lt.AdmissionOpen(); got != tc.want {
				t.Fatalf("admissionOpen() = %v, want %v", got, tc.want)
			}
			// The predicate is the read-only form of admitExecution, so the two must
			// never disagree — that equivalence is the whole reason it is safe to use
			// one as the other's boundary re-check.
			rel, ok := lt.AdmitExecution()
			if ok != tc.want {
				t.Fatalf("admitExecution ok = %v but admissionOpen = %v; the two must agree", ok, tc.want)
			}
			if ok {
				rel()
			}
		})
	}
}

// armedSink records every SetArmed call a tier makes.
type armedSink struct {
	mu    sync.Mutex
	calls []bool
	bit   atomic.Bool
}

func (s *armedSink) set(armed bool) {
	s.mu.Lock()
	s.calls = append(s.calls, armed)
	s.mu.Unlock()
	s.bit.Store(armed)
}

func (s *armedSink) take() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.calls
	s.calls = nil
	return out
}

func newSinkTier() (*Tier, *armedSink) {
	s := &armedSink{}
	return New(Options{SetArmed: s.set, DepsReady: s.bit.Load}), s
}

func mustArm(t *testing.T, lt *Tier) {
	t.Helper()
	lt.MarkComposed()
	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatalf("Arm on a composed, ready tier: %v", err)
	}
}

// TestTier_ArmedBitWrittenOnlyByArmAndTheRevocations pins which transitions
// reach the registry and with what value. Main binds SetArmed to the one
// dispatcher that toggles the bit the mode gate reads, so a transition that
// called it and should not have (or the converse) changes what a rollout
// commit is allowed to authorize.
func TestTier_ArmedBitWrittenOnlyByArmAndTheRevocations(t *testing.T) {
	lt, sink := newSinkTier()
	expect := func(step string, want ...bool) {
		t.Helper()
		if got := sink.take(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: SetArmed calls = %v, want %v", step, got, want)
		}
	}

	if err := lt.Arm(true, "x"); err != ErrNotComposed {
		t.Fatalf("Arm on an absent tier = %v, want ErrNotComposed", err)
	}
	expect("refused arm (absent)")
	lt.SetComposeReason("opt_out")
	lt.MarkComposed()
	lt.MarkComposed()
	expect("compose")
	if err := lt.Arm(false, "x"); err != ErrNotReady {
		t.Fatalf("Arm without readiness = %v, want ErrNotReady", err)
	}
	expect("refused arm (not ready)")
	if lt.State() != Composed {
		t.Fatalf("a refused arm moved the tier to %s", lt.State())
	}

	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	expect("arm", true)
	if err := lt.Arm(true, "again"); err != ErrNotComposed {
		t.Fatalf("Arm on an armed tier = %v, want ErrNotComposed", err)
	}
	rel, ok := lt.AdmitExecution()
	if !ok {
		t.Fatal("an armed tier refused admission")
	}
	_ = lt.AdmissionOpen()
	_ = lt.Status()
	_ = lt.Reason()
	_ = lt.InFlightCount()
	rel()
	rel() // release is once-only; a second call must not go negative or signal the sink
	lt.ResetForStartupFailure()
	expect("admission, reads and a refused startup reset")
	if lt.State() != Armed {
		t.Fatalf("ResetForStartupFailure touched an armed tier: %s", lt.State())
	}

	if rem := lt.Quiesce(nil); rem != 0 {
		t.Fatalf("idle quiesce left %d in flight", rem)
	}
	expect("quiesce", false)
	if rem := lt.Quiesce(nil); rem != 0 {
		t.Fatalf("repeated quiesce left %d in flight", rem)
	}
	expect("quiesce of an idle unarmed tier (no-op)")

	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	lt.UnarmForDemote()
	expect("arm then demote", true, false)
	if lt.State() != Composed || lt.AdmissionOpen() {
		t.Fatalf("after demote: state %s, admission open %v", lt.State(), lt.AdmissionOpen())
	}

	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	lt.DisarmForRestart()
	expect("arm then restart disarm", true, false)
	lt.ResetForStartupFailure()
	expect("startup reset of a composed tier")
	if lt.State() != Absent || lt.Reason() != "runtime_start_failed" {
		t.Fatalf("startup reset: state %s reason %q", lt.State(), lt.Reason())
	}
}

// TestTier_ArmedBitWrittenUnderTheTierLock: every registry write happens with
// the tier lock held, so a reader that takes the tier lock (Status) can never
// see the state and the bit from two different transitions.
func TestTier_ArmedBitWrittenUnderTheTierLock(t *testing.T) {
	var lt *Tier
	var unlocked []bool
	lt = New(Options{SetArmed: func(armed bool) {
		if lt.mu.TryLock() {
			lt.mu.Unlock()
			unlocked = append(unlocked, armed)
		}
	}})
	mustArm(t, lt)
	lt.Quiesce(nil)
	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	lt.UnarmForDemote()
	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	lt.DisarmForRestart()
	if len(unlocked) != 0 {
		t.Fatalf("SetArmed ran without the tier lock for %v", unlocked)
	}
}

// probeLock is a commit lock that records what it sees.
type probeLock struct {
	mu         sync.Mutex
	held       atomic.Bool
	tierFreeAt []bool // at each Lock(): was the tier lock free?
	tier       *Tier
	lockN      atomic.Int32
}

func (p *probeLock) Lock() {
	p.mu.Lock()
	p.held.Store(true)
	p.lockN.Add(1)
	free := p.tier.mu.TryLock()
	if free {
		p.tier.mu.Unlock()
	}
	p.tierFreeAt = append(p.tierFreeAt, free)
}

func (p *probeLock) Unlock() {
	p.held.Store(false)
	p.mu.Unlock()
}

// TestQuiesce_CommitLockCoversTheRevocationAndNotTheDrain pins the three
// facts the rollout commit path depends on: the commit lock is taken BEFORE
// the tier lock (order commit → tier), the armed bit is cleared while the
// commit lock is held (so the revocation cannot land between a commit's armed
// read and its install), and the lock is released before the drain wait (so a
// slow drain never blocks a commit or the emergency kill).
func TestQuiesce_CommitLockCoversTheRevocationAndNotTheDrain(t *testing.T) {
	probe := &probeLock{}
	var heldAtRevocation, heldAtArm []bool
	lt := New(Options{
		SetArmed: func(armed bool) {
			if armed {
				heldAtArm = append(heldAtArm, probe.held.Load())
			} else {
				heldAtRevocation = append(heldAtRevocation, probe.held.Load())
			}
		},
		CommitLock: func() sync.Locker { return probe },
	})
	probe.tier = lt
	mustArm(t, lt)
	rel, ok := lt.AdmitExecution()
	if !ok {
		t.Fatal("armed tier refused admission")
	}

	var heldInDrain, stateInDrain = true, Absent
	rem := lt.Quiesce(func(inFlight func() int) int {
		heldInDrain = probe.held.Load()
		stateInDrain = lt.State()
		if lt.AdmissionOpen() {
			t.Error("admission is open during the drain")
		}
		if _, ok := lt.AdmitExecution(); ok {
			t.Error("a quiescing tier admitted a new execution")
		}
		if err := lt.Arm(true, "re-arm"); err != ErrNotComposed {
			t.Errorf("Arm during the drain = %v, want ErrNotComposed", err)
		}
		n := inFlight()
		rel()
		return n
	})
	if rem != 1 {
		t.Fatalf("Quiesce returned %d, want the wait's own answer 1", rem)
	}
	if !reflect.DeepEqual(heldAtRevocation, []bool{true}) {
		t.Fatalf("commit lock held at the revocation = %v, want [true]", heldAtRevocation)
	}
	if !reflect.DeepEqual(heldAtArm, []bool{false}) {
		t.Fatalf("commit lock held at Arm = %v, want [false]: Arm must not take the commit lock "+
			"(its callers may already hold it)", heldAtArm)
	}
	if !reflect.DeepEqual(probe.tierFreeAt, []bool{true}) {
		t.Fatalf("tier lock free when the commit lock was taken = %v, want [true] (order commit → tier)", probe.tierFreeAt)
	}
	if heldInDrain {
		t.Fatal("the commit lock was still held during the drain wait")
	}
	if stateInDrain != Quiescing {
		t.Fatalf("state during the drain = %s, want quiescing", stateInDrain)
	}
	if lt.State() != Composed || lt.Reason() != "quiesced" || probe.held.Load() {
		t.Fatalf("after quiesce: state %s reason %q commit lock held %v", lt.State(), lt.Reason(), probe.held.Load())
	}
}

// TestQuiesce_ResolvesTheCommitLockOnEveryCall: main's rollout owner can be
// replaced, so a lock captured at construction could be the previous owner's.
func TestQuiesce_ResolvesTheCommitLockOnEveryCall(t *testing.T) {
	first, second := &probeLock{}, &probeLock{}
	current := first
	lt := New(Options{CommitLock: func() sync.Locker { return current }})
	first.tier, second.tier = lt, lt
	mustArm(t, lt)
	lt.Quiesce(nil)
	current = second
	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	lt.Quiesce(nil)
	lt.Quiesce(nil) // an idle quiesce still serializes its (empty) revocation
	if first.lockN.Load() != 1 || second.lockN.Load() != 2 {
		t.Fatalf("commit lock taken %d and %d times, want 1 and 2", first.lockN.Load(), second.lockN.Load())
	}
	// UnarmForDemote and DisarmForRestart run with the commit lock already held
	// by their caller (the rollout commit), so they must not take it.
	if err := lt.Arm(true, "armed"); err != nil {
		t.Fatal(err)
	}
	lt.UnarmForDemote()
	lt.DisarmForRestart()
	if second.lockN.Load() != 2 {
		t.Fatalf("a non-quiesce revocation took the commit lock (%d takes)", second.lockN.Load())
	}
}

// TestQuiesce_ResidualInFlightReentersQuiescing: a bounded drain that timed
// out leaves the tier composed with work still in flight. A retry must report
// that work, and must hold the tier in quiescing (so a concurrent re-arm stays
// refused) instead of answering a clean drain.
func TestQuiesce_ResidualInFlightReentersQuiescing(t *testing.T) {
	lt, sink := newSinkTier()
	mustArm(t, lt)
	rel, _ := lt.AdmitExecution()
	if rem := lt.Quiesce(lt.DrainWait(time.Now().Add(-time.Second))); rem != 1 {
		t.Fatalf("first bounded quiesce = %d, want residual 1", rem)
	}
	if lt.State() != Composed || lt.InFlightCount() != 1 {
		t.Fatalf("after the timed-out drain: state %s in flight %d", lt.State(), lt.InFlightCount())
	}
	sink.take()
	var during State
	rem := lt.Quiesce(func(inFlight func() int) int {
		during = lt.State()
		return inFlight()
	})
	if rem != 1 || during != Quiescing {
		t.Fatalf("retry = %d in state %s, want residual 1 while quiescing", rem, during)
	}
	if got := sink.take(); !reflect.DeepEqual(got, []bool{false}) {
		t.Fatalf("retry SetArmed calls = %v, want [false]", got)
	}
	rel()
	if rem := lt.Quiesce(lt.DrainWait(time.Now().Add(time.Second))); rem != 0 {
		t.Fatalf("quiesce after release = %d, want 0", rem)
	}
}

// TestDrainWait_Bounds covers the three answers of the bounded wait.
func TestDrainWait_Bounds(t *testing.T) {
	t.Run("nothing in flight returns at once", func(t *testing.T) {
		lt := New(Options{})
		if got := lt.DrainWait(time.Now().Add(time.Hour))(nil); got != 0 {
			t.Fatalf("got %d, want 0", got)
		}
	})
	t.Run("a past deadline reports the residual without waiting", func(t *testing.T) {
		lt := New(Options{})
		mustArm(t, lt)
		rel, _ := lt.AdmitExecution()
		defer rel()
		start := time.Now()
		if got := lt.DrainWait(start.Add(-time.Second))(nil); got != 1 {
			t.Fatalf("got %d, want 1", got)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("a past deadline waited")
		}
	})
	t.Run("a stalled execution cannot hold the wait past its deadline", func(t *testing.T) {
		lt := New(Options{})
		mustArm(t, lt)
		rel, _ := lt.AdmitExecution()
		defer rel()
		done := make(chan int, 1)
		go func() { done <- lt.DrainWait(time.Now().Add(50 * time.Millisecond))(nil) }()
		select {
		case got := <-done:
			if got != 1 {
				t.Fatalf("got %d, want residual 1", got)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the wait outlived its deadline: nothing woke it")
		}
	})
	t.Run("the last release wakes the wait before the deadline", func(t *testing.T) {
		lt := New(Options{})
		mustArm(t, lt)
		relA, _ := lt.AdmitExecution()
		relB, _ := lt.AdmitExecution()
		done := make(chan int, 1)
		go func() { done <- lt.DrainWait(time.Now().Add(time.Hour))(nil) }()
		relA()
		select {
		case got := <-done:
			t.Fatalf("the wait returned %d with one execution still in flight", got)
		case <-time.After(20 * time.Millisecond):
		}
		relB()
		select {
		case got := <-done:
			if got != 0 {
				t.Fatalf("got %d, want 0", got)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the final release did not wake the wait")
		}
	})
}

// TestTiers_ShareNothing: two tiers built separately cannot see each other's
// state, in-flight work or registry.
func TestTiers_ShareNothing(t *testing.T) {
	a, sinkA := newSinkTier()
	b, sinkB := newSinkTier()
	mustArm(t, a)
	relA, ok := a.AdmitExecution()
	if !ok {
		t.Fatal("tier a refused admission")
	}
	defer relA()
	if b.State() != Absent || b.IsComposed() || b.IsArmed() || b.AdmissionOpen() || b.InFlightCount() != 0 {
		t.Fatalf("arming a changed b: %v", b.Status())
	}
	if _, ok := b.AdmitExecution(); ok {
		t.Fatal("tier b admitted on tier a's arming")
	}
	if got := sinkB.take(); len(got) != 0 {
		t.Fatalf("tier b's registry was written: %v", got)
	}
	if !sinkA.bit.Load() || sinkB.bit.Load() {
		t.Fatalf("registry bits a=%v b=%v, want true/false", sinkA.bit.Load(), sinkB.bit.Load())
	}
	if rem := b.Quiesce(b.DrainWait(time.Now().Add(-time.Second))); rem != 0 {
		t.Fatalf("tier b's quiesce counted tier a's execution: %d", rem)
	}
	if !a.IsArmed() || a.InFlightCount() != 1 {
		t.Fatalf("tier b's quiesce changed a: %v", a.Status())
	}
}

// TestNew_WithoutCollaboratorsFailsClosed: a tier nobody wired can change
// state, but nothing reads an armed bit from it and its status says so.
func TestNew_WithoutCollaboratorsFailsClosed(t *testing.T) {
	lt := New(Options{})
	if lt.State() != Absent || lt.Reason() != "not_composed" || lt.AdmissionOpen() {
		t.Fatalf("a new tier is not absent and closed: %v", lt.Status())
	}
	mustArm(t, lt)
	if got := lt.Status()["live_deps_ready"]; got != false {
		t.Fatalf("live_deps_ready = %v with no registry, want false", got)
	}
	if rem := lt.Quiesce(nil); rem != 0 {
		t.Fatalf("quiesce without a commit lock = %d", rem)
	}
}

// TestStatus_RowShape pins the status row main publishes on the viewer-safe
// admin surface: the key set, the value types and the row for each state.
func TestStatus_RowShape(t *testing.T) {
	lt, _ := newSinkTier()
	row := func(state string, composed, armed bool, reason string, inFlight int, closed, ready bool) map[string]any {
		return map[string]any{
			"state": state, "composed": composed, "armed": armed, "compose_reason": reason,
			"in_flight": inFlight, "admit_closed": closed, "live_deps_ready": ready,
		}
	}
	check := func(step string, want map[string]any) {
		t.Helper()
		if got := lt.Status(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s:\n got %v\nwant %v", step, got, want)
		}
	}
	check("absent", row("absent", false, false, "not_composed", 0, false, false))
	lt.SetComposeReason("opt_out")
	check("declined composition", row("absent", false, false, "opt_out", 0, false, false))
	lt.MarkComposed()
	check("composed", row("composed", true, false, "composed", 0, false, false))
	if err := lt.Arm(true, "armed:ready"); err != nil {
		t.Fatal(err)
	}
	rel, _ := lt.AdmitExecution()
	check("armed with one execution", row("armed", true, true, "armed:ready", 1, false, true))
	lt.Quiesce(func(func() int) int {
		check("quiescing", row("quiescing", true, false, "quiescing", 1, true, false))
		return 1
	})
	check("quiesced with a residual", row("composed", true, false, "quiesced", 1, true, false))
	rel()
	lt.UnarmForDemote()
	check("demoted", row("composed", true, false, "demoted", 0, true, false))
	lt.DisarmForRestart()
	check("restart", row("composed", true, false, "restart_unarmed", 0, false, false))
}

// TestStateNames pins the state names on the status surface. (The refusal
// texts are pinned by main's credential-matrix wall, whose allowlist quotes
// the not-ready message at this package's path and fails when it goes stale.)
func TestStateNames(t *testing.T) {
	for s, want := range map[State]string{Absent: "absent", Composed: "composed", Armed: "armed", Quiescing: "quiescing", State(99): "absent"} {
		if s.String() != want {
			t.Errorf("State(%d).String() = %q, want %q", int(s), s.String(), want)
		}
	}
}
