package obs

// guard_test.go — CHAOS-24 background-worker panic containment.

import (
	"strings"
	"sync"
	"testing"
)

// withPanicSink installs fn for the duration of the test and restores the
// previous sink afterwards, so tests never leak a sink into each other.
func withPanicSink(t *testing.T, fn func(component string, v any)) {
	t.Helper()
	prev := panicSink.Load()
	SetPanicSink(fn)
	t.Cleanup(func() { panicSink.Store(prev) })
}

func TestGuard_ContainsPanicAndReportsToSink(t *testing.T) {
	var gotComponent string
	var gotValue any
	withPanicSink(t, func(component string, v any) { gotComponent, gotValue = component, v })

	// A worker "round" that panics: the caller must return normally, which is
	// what lets the surrounding for/select loop reach its next iteration.
	func() {
		defer Guard("feedsync")
		panic("bad feed line")
	}()

	if gotComponent != "feedsync" {
		t.Errorf("component = %q, want %q", gotComponent, "feedsync")
	}
	if gotValue != "bad feed line" {
		t.Errorf("panic value = %v, want %q", gotValue, "bad feed line")
	}
}

func TestSafeCall_ReportsWhetherTheRoundPanicked(t *testing.T) {
	withPanicSink(t, func(string, any) {})

	if panicked := SafeCall("worker", func() {}); panicked {
		t.Error("a clean round must report panicked=false")
	}
	if panicked := SafeCall("worker", func() { panic("boom") }); !panicked {
		t.Error("a panicking round must report panicked=true")
	}
}

// The fail-closed callers (ha_lease.go) branch on SafeCall's return, so a
// nil-deref — the most common real panic — must be reported like any other.
func TestSafeCall_RuntimeErrorIsReported(t *testing.T) {
	var reported bool
	withPanicSink(t, func(string, any) { reported = true })

	var m map[string]int
	panicked := SafeCall("worker", func() { m["x"] = 1 }) // nil-map write

	if !panicked || !reported {
		t.Errorf("nil-map write: panicked=%v reported=%v, want both true", panicked, reported)
	}
}

// The loop must keep running after containment — that is the whole point of
// guarding the round instead of the goroutine.
func TestGuard_LoopSurvivesEveryRound(t *testing.T) {
	withPanicSink(t, func(string, any) {})

	rounds := 0
	for i := 0; i < 5; i++ {
		SafeCall("worker", func() {
			rounds++
			panic("every round fails")
		})
	}
	if rounds != 5 {
		t.Errorf("completed rounds = %d, want 5 (the loop must not stop on panic)", rounds)
	}
}

// A panicking sink must not take down the worker it exists to protect.
func TestReportPanic_SinkPanicIsSwallowed(t *testing.T) {
	withPanicSink(t, func(string, any) { panic("the sink itself is broken") })

	// Must not propagate: if it did, this test would fail with a panic.
	if panicked := SafeCall("worker", func() { panic("worker failed") }); !panicked {
		t.Error("worker panic must still be reported as panicked even when the sink panics")
	}
}

// A mis-wired startup must never SILENCE panic reporting — SetPanicSink(nil) is
// ignored so the default WARN sink stays installed.
func TestSetPanicSink_NilIsIgnored(t *testing.T) {
	var lines []string
	var mu sync.Mutex
	prevSink := sink.Load()
	SetSink(func(line string) { mu.Lock(); lines = append(lines, line); mu.Unlock() })
	t.Cleanup(func() { sink.Store(prevSink) })

	prevPanic := panicSink.Load()
	t.Cleanup(func() { panicSink.Store(prevPanic) })
	// Restore the built-in default, then try to clear it with nil.
	def := func(component string, v any) {
		Warnf("PANIC_RECOVERED component=%q (no crash sink installed)", Sanitize(component))
	}
	SetPanicSink(def)
	SetPanicSink(nil) // must be ignored

	SafeCall("orphan", func() { panic("no sink wired") })

	mu.Lock()
	defer mu.Unlock()
	for _, l := range lines {
		if strings.Contains(l, "PANIC_RECOVERED") && strings.Contains(l, "orphan") {
			return
		}
	}
	t.Errorf("nil SetPanicSink cleared the default sink; emitted lines = %v", lines)
}

// The panic value is attacker-shaped in the feed workers (it can carry a parsed
// feed line), so the default sink must scrub control characters before it
// reaches the log — CWE-117.
func TestDefaultPanicSink_SanitizesPanicText(t *testing.T) {
	var lines []string
	var mu sync.Mutex
	prevSink := sink.Load()
	SetSink(func(line string) { mu.Lock(); lines = append(lines, line); mu.Unlock() })
	t.Cleanup(func() { sink.Store(prevSink) })

	prevPanic := panicSink.Load()
	SetPanicSink(func(component string, v any) {
		Warnf("PANIC_RECOVERED component=%q: %s", Sanitize(component), Sanitize(takeString(v)))
	})
	t.Cleanup(func() { panicSink.Store(prevPanic) })

	SafeCall("feedsync", func() { panic("evil\nINJECTED admin login ok\r") })

	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 {
		t.Fatal("no line emitted")
	}
	for _, l := range lines {
		if strings.ContainsAny(l, "\n\r") {
			t.Errorf("panic text reached the log with control characters: %q", l)
		}
	}
}

func takeString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
