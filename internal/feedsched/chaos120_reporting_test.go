package feedsched

// chaos120_reporting_test.go — CHAOS-120: the scheduler's two containment gaps,
// handed to "the round that takes the scheduler" by CHAOS-119 §5.1 and §5.2.
//
//	§5.1  Config.OnPanic was defined, documented and wired by NOBODY, so every
//	      panic this package contained itself fell to an obs.Warnf line. Warnf
//	      does not reach the panic sink, so there was no crash record, no
//	      culvert_crash_records_total increment, no panic_recovered audit entry
//	      and no page: containment with no reporting, in the package whose own
//	      doc promises "a panicking round is a FAILED round, not a dead loop".
//
//	§5.2  Run consulted cfg.RunNow() OUTSIDE every guard, and internal/threatfeed
//	      launches Run with a bare `go` statement. feedsync's predicate is
//	      `fs.db.Stats() == 0` — a BadgerDB call on a handle this package does not
//	      own. Go terminates the process on an unrecovered panic in any goroutine,
//	      so a corrupt or closed store killed the gateway from the one line in the
//	      cold-start path nobody guarded.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// chaos120Sink installs an observer on the shared panic sink and returns a
// reader for what reached it.
//
// obs.SetPanicSink ignores a nil fn by design ("a mis-wired startup can never
// silence panic reporting entirely"), so the installed observer cannot be
// uninstalled. It is left in place for the rest of this test binary, which is
// safe here: this package's own tests are the only callers, and the observer
// only appends.
func chaos120Sink(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	obs.SetPanicSink(func(component string, v any) {
		mu.Lock()
		got = append(got, component)
		mu.Unlock()
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// TestCHAOS120_APanickingRunNowPredicateIsContainedReportedAndFallsThrough
// pins §5.2: the predicate is contained, reported, and the loop lives on.
//
// Pre-fix this test did not fail — the test BINARY died, because the panic was
// unrecovered in the goroutine Run was launched on. That is the defect: a
// predicate panic was a process kill at startup, on the path whose whole purpose
// is cold-start recovery.
func TestCHAOS120_APanickingRunNowPredicateIsContainedReportedAndFallsThrough(t *testing.T) {
	reported := chaos120Sink(t)
	clock := &fakeClock{}
	roundRan := make(chan struct{}, 4)
	s := New(Config{
		Name:     "chaos120-feed",
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    clock,
		// The shape of feedsync's own predicate: a call into a store handle this
		// package does not own.
		RunNow: func() bool { panic("badger: DB closed") },
		Run: func(context.Context) bool {
			roundRan <- struct{}{}
			return true
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// Launched detached, exactly as internal/threatfeed launches it, so this
	// goroutine's survival is the thing under test.
	go func() { s.Run(ctx); close(done) }()

	// The loop must be ALIVE: a contained predicate panic falls through to the
	// interval loop rather than returning, so the feed still has a schedule.
	waitDelay(t, clock, 1)
	if d := clock.all()[0]; d != 6*time.Hour {
		t.Fatalf("first scheduled delay after a panicking predicate = %s, want the steady-state interval 6h — "+
			"the loop must fall through to the normal cadence, not exit and not enter backoff", d)
	}

	// And the panic must have REACHED the sink, not just a WARN line.
	got := reported()
	if len(got) != 1 || got[0] != crashComponentFeedschedRound {
		t.Fatalf("panic sink received %v, want exactly [%q]. obs.Warnf does not reach the crash plane: a panic "+
			"reported only there produces no crash record, no counter increment, no audit entry and no page.",
			got, crashComponentFeedschedRound)
	}

	// A real round still runs at the first tick, so the cold-start sync is
	// delayed by one window and never abandoned.
	fire(t, clock)
	select {
	case <-roundRan:
	case <-time.After(5 * time.Second):
		t.Fatal("no round ran after the first tick — the predicate panic cost the loop, not one window")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

// TestCHAOS120_AContainedRoundPanicReachesThePanicSink — §5.1 for the round
// path. The containment was already correct; only the reporting was missing.
func TestCHAOS120_AContainedRoundPanicReachesThePanicSink(t *testing.T) {
	reported := chaos120Sink(t)
	s := New(Config{
		Name:     "chaos120-feed",
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    &fakeClock{},
		Run:      func(context.Context) bool { panic("hostile archive") },
	})

	if ok := s.round(context.Background()); ok {
		t.Fatal("a panicking round reported success — it must be charged as a FAILURE")
	}
	got := reported()
	if len(got) != 1 || got[0] != crashComponentFeedschedRound {
		t.Fatalf("panic sink received %v, want exactly [%q]", got, crashComponentFeedschedRound)
	}
}

// TestCHAOS120_AConfiguredOnPanicOwnsTheReport — a caller that installed
// OnPanic has said how it wants its panics handled. Reporting to the sink as
// well would double-count culvert_crash_records_total for one panic, and the
// counter's rate is what an operator reads to tell a transient fault from a
// permanent one.
func TestCHAOS120_AConfiguredOnPanicOwnsTheReport(t *testing.T) {
	reported := chaos120Sink(t)
	var seen []any
	s := New(Config{
		Name:     "chaos120-feed",
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    &fakeClock{},
		OnPanic:  func(v any) { seen = append(seen, v) },
		Run:      func(context.Context) bool { panic("owned") },
	})

	if ok := s.round(context.Background()); ok {
		t.Fatal("a panicking round reported success")
	}
	if len(seen) != 1 {
		t.Fatalf("OnPanic called %d times, want 1", len(seen))
	}
	if got := reported(); len(got) != 0 {
		t.Errorf("the sink also received %v: one panic must produce exactly one crash record", got)
	}
}

// TestCHAOS120_BothContainmentPathsShareOneReporter is the structural gate for
// the shape of the fix. round and runNow must report through the same path, or a
// later round can fix one and leave the other silent — which is the state §5.1
// and §5.2 together described.
func TestCHAOS120_BothContainmentPathsShareOneReporter(t *testing.T) {
	var mu sync.Mutex
	var seen []any
	cfg := Config{
		Name:     "chaos120-feed",
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    &fakeClock{},
		OnPanic: func(v any) {
			mu.Lock()
			seen = append(seen, v)
			mu.Unlock()
		},
		RunNow: func() bool { panic("predicate") },
		Run:    func(context.Context) bool { panic("round") },
	}

	s := New(cfg)
	if s.runNow() {
		t.Error("a panicking predicate answered true — it must answer false")
	}
	if s.round(context.Background()) {
		t.Error("a panicking round answered true")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("OnPanic saw %d panics (%v), want 2 — both containment paths must route through the same "+
			"reporter so neither can be fixed while the other stays silent", len(seen), seen)
	}
}

// TestCHAOS120_TheCrashComponentLabelIsFixed. The sink's component set is capped
// (package main's maxCrashLabels) and past the cap crashThrottleAllow fails
// CLOSED: no record, no log line, no audit entry, no page. A label derived from
// Config.Name would be an unbounded label in a bounded map — and the source
// enumerator that holds the cap resolves same-file string constants, so it would
// not be countable either.
func TestCHAOS120_TheCrashComponentLabelIsFixed(t *testing.T) {
	reported := chaos120Sink(t)
	for _, name := range []string{"feedsync", "threatfeed", "blocklistfeed", "a-feed-added-next-year"} {
		s := New(Config{
			Name:     name,
			Interval: func() time.Duration { return time.Hour },
			Jitter:   noJitter,
			Clock:    &fakeClock{},
			Run:      func(context.Context) bool { panic("per-feed fault") },
		})
		s.round(context.Background())
	}
	got := reported()
	if len(got) != 4 {
		t.Fatalf("sink received %d reports, want 4", len(got))
	}
	for i, c := range got {
		if c != crashComponentFeedschedRound {
			t.Errorf("report %d used component %q, want the single fixed label %q — four feeds must not be four "+
				"labels in a capped map", i, c, crashComponentFeedschedRound)
		}
	}
	if strings.ContainsAny(crashComponentFeedschedRound, " \t\n\"\\") {
		t.Errorf("the label %q is not safe as a Prometheus label value", crashComponentFeedschedRound)
	}
}
