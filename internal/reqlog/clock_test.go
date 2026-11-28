package reqlog

// clock_test.go — correctness wall for the memoised Entry.Time
// render. The optimization is only acceptable if it is EXACT, so the tests
// below are written as an equivalence proof against time.Format rather than as
// spot checks: whatever Format would have produced, stamp must produce.

import (
	"sync"
	"testing"
	"time"
)

// TestLogClockStamp_MatchesFormatAcrossInstants walks a dense range of instants
// — many hits inside one second, every second boundary, a leap-second-adjacent
// minute, midnight, and a DST transition — and requires byte equality with the
// value the pre-memo code produced.
func TestLogClockStamp_MatchesFormatAcrossInstants(t *testing.T) {
	nyc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}

	bases := []struct {
		name string
		at   time.Time
	}{
		{"midnight-utc", time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)},
		{"midday-utc", time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)},
		{"last-second-of-day-utc", time.Date(2026, 8, 9, 23, 59, 59, 0, time.UTC)},
		{"leap-second-adjacent-utc", time.Date(2026, 12, 31, 23, 59, 58, 0, time.UTC)},
		// The US spring-forward instant: local wall time jumps 01:59:59 → 03:00:00.
		// The unix-second → clock-string mapping stays a function, so the memo
		// stays exact across the discontinuity.
		{"dst-spring-forward-local", time.Date(2026, 3, 8, 6, 59, 58, 0, time.UTC).In(nyc)},
		{"dst-fall-back-local", time.Date(2026, 11, 1, 5, 59, 58, 0, time.UTC).In(nyc)},
	}

	for _, base := range bases {
		t.Run(base.name, func(t *testing.T) {
			var c clock
			// 4 seconds at 250 ms steps: repeated hits within each second plus
			// every boundary crossing in between.
			for step := 0; step < 16; step++ {
				at := base.at.Add(time.Duration(step) * 250 * time.Millisecond)
				want := at.Format(TimeLayout)
				if got := c.stamp(at); got != want {
					t.Fatalf("step %d (%s): stamp = %q, Format = %q",
						step, at, got, want)
				}
			}
		})
	}
}

// TestLogClockStamp_BackwardClockStepStaysExact pins the behaviour under an
// NTP correction that moves the wall clock backwards: the memo is keyed on the
// absolute unix second, never on "newer than the cache", so a step back must
// re-render rather than serve the future second's string.
func TestLogClockStamp_BackwardClockStepStaysExact(t *testing.T) {
	var c clock
	ahead := time.Date(2026, 8, 9, 12, 0, 10, 0, time.UTC)
	behind := ahead.Add(-7 * time.Second)

	if got, want := c.stamp(ahead), "12:00:10"; got != want {
		t.Fatalf("ahead: got %q want %q", got, want)
	}
	if got, want := c.stamp(behind), "12:00:03"; got != want {
		t.Fatalf("after backward step: got %q want %q — the memo served a stale future second", got, want)
	}
	// And forward again, to prove the cache is not sticky in either direction.
	if got, want := c.stamp(ahead), "12:00:10"; got != want {
		t.Fatalf("forward again: got %q want %q", got, want)
	}
}

// TestLogClockStamp_LocationIsPartOfTheKey proves a UTC caller can never be
// served a Local render (or vice versa) when the two share a unix second.
// Without the location guard this is exactly the silent wrong-answer case.
func TestLogClockStamp_LocationIsPartOfTheKey(t *testing.T) {
	nyc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	var c clock

	utc := time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)
	local := utc.In(nyc) // same instant, same unix second, different wall clock

	if got, want := c.stamp(utc), utc.Format(TimeLayout); got != want {
		t.Fatalf("utc: got %q want %q", got, want)
	}
	if got, want := c.stamp(local), local.Format(TimeLayout); got != want {
		t.Fatalf("local: got %q want %q — the location guard did not hold", got, want)
	}
	// Back to UTC in the same second: still the UTC render.
	if got, want := c.stamp(utc), utc.Format(TimeLayout); got != want {
		t.Fatalf("utc again: got %q want %q", got, want)
	}
}

// TestLogClockStamp_SteadyStateIsAllocationFree is the deterministic
// allocation gate. A hit must not allocate — that is the entire point of the
// change, and AllocsPerRun makes it hardware-independent.
func TestLogClockStamp_SteadyStateIsAllocationFree(t *testing.T) {
	var c clock
	at := time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)
	c.stamp(at) // warm

	if n := testing.AllocsPerRun(200, func() { _ = c.stamp(at) }); n != 0 {
		t.Errorf("REGRESSION: stamp allocates %v/op on a cache hit, want 0 — "+
			"the per-request clock render is back on the request-log hot path", n)
	}
}

// TestLogClockStamp_ConcurrentCallersAllGetTheirOwnSecond runs the memo the way
// the proxy does — many request goroutines at once, straddling second
// boundaries — and requires every single answer to equal Format. Run under
// -race this also proves the pointer swap is the only shared state.
func TestLogClockStamp_ConcurrentCallersAllGetTheirOwnSecond(t *testing.T) {
	var c clock
	base := time.Date(2026, 8, 9, 12, 34, 56, 0, time.UTC)

	const goroutines, iterations = 16, 500
	var wg sync.WaitGroup
	errs := make(chan string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Spread callers across a handful of adjacent seconds so the
				// cache is genuinely contended, not trivially stable.
				at := base.Add(time.Duration((i+g)%5) * time.Second)
				if got, want := c.stamp(at), at.Format(TimeLayout); got != want {
					errs <- "got " + got + " want " + want
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent mismatch: %s", e)
	}
}
