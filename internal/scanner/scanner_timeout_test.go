package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for the hoisted ReDoS budget: Scan now runs the whole pattern list in ONE
// timeout-bounded worker instead of one per pattern. These pin the two properties
// that made that safe to do — the budget is still PER PATTERN, and a timeout
// still fails closed — plus the copy-on-write pattern set that lets an abandoned
// worker outlive its scan.

// TestBudgetRemaining covers the budget arithmetic deterministically (no timers,
// no goroutines), including the boundary and a backwards clock step.
func TestBudgetRemaining(t *testing.T) {
	const budget = 100 * time.Millisecond
	cases := []struct {
		name          string
		startedAt     int64
		now           int64
		wantRemaining time.Duration
		wantExhausted bool
	}{
		{"just started: full budget left", 0, 0, budget, false},
		{"a quarter in", 0, int64(25 * time.Millisecond), 75 * time.Millisecond, false},
		{"one nano short of the budget", 0, int64(budget) - 1, 1, false},
		{"exactly at the budget: exhausted", 0, int64(budget), 0, true},
		{"well past the budget: exhausted", 0, int64(5 * budget), 0, true},
		{"clock stepped backwards: re-arm full", int64(50 * time.Millisecond), 0, budget, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remaining, exhausted := budgetRemaining(budget, tc.startedAt, tc.now)
			if exhausted != tc.wantExhausted {
				t.Errorf("exhausted = %v, want %v", exhausted, tc.wantExhausted)
			}
			if remaining != tc.wantRemaining {
				t.Errorf("remaining = %v, want %v", remaining, tc.wantRemaining)
			}
		})
	}
}

// fakeSet builds a patternSet of n identical patterns whose match step is driven
// by fn instead of the regex engine. Every timing assertion below is therefore
// controlled by the test, not by how fast the machine happens to run a regex.
func fakeSet(n int, fn func(idx int) bool) *patternSet {
	ps := &patternSet{}
	for i := 0; i < n; i++ {
		p := fmt.Sprintf(`pattern-%d`, i)
		ps.raw = append(ps.raw, p)
		ps.compiled = append(ps.compiled, regexp.MustCompile(p))
	}
	byName := map[string]int{}
	for i, p := range ps.raw {
		byName[p] = i
	}
	ps.matcher = func(re *regexp.Regexp, _ []byte) bool { return fn(byName[re.String()]) }
	return ps
}

// TestScan_BudgetIsPerPatternNotPerScan is the regression test for the semantics
// the hoist had to preserve. A scan whose TOTAL time far exceeds the budget must
// still complete, because no INDIVIDUAL pattern exceeds it.
//
// This is exactly what a naive hoist (one budget for the whole loop) would break:
// it would fail closed here and block legitimate traffic.
//
// Deterministic by construction: each match sleeps a fixed 10ms against a 200ms
// per-pattern budget (a 20x margin that CPU contention cannot close, since the
// sleep is wall-clock), and 40 of them put total scan time at ~400ms — twice the
// budget. Only a per-pattern budget completes this scan.
func TestScan_BudgetIsPerPatternNotPerScan(t *testing.T) {
	const (
		patterns    = 40
		perMatch    = 10 * time.Millisecond
		budget      = 200 * time.Millisecond
		wantMinimum = patterns * perMatch // ~400ms, comfortably over the budget
	)
	ps := fakeSet(patterns, func(int) bool {
		time.Sleep(perMatch)
		return false
	})

	start := time.Now()
	got, hit := ps.scan(nil, budget)
	elapsed := time.Since(start)

	if hit {
		t.Errorf("scan returned a fail-closed hit (%q) for a clean body: the budget is "+
			"being charged against the whole scan instead of the individual match", got)
	}
	if elapsed < wantMinimum {
		t.Fatalf("scan took %v, expected at least %v — the fake matcher did not run, "+
			"so this did not exercise the per-pattern property", elapsed, wantMinimum)
	}
	if elapsed <= budget {
		t.Fatalf("scan took %v, which is inside the %v budget — the test no longer "+
			"distinguishes a per-pattern budget from a whole-scan one", elapsed, budget)
	}
	t.Logf("scan took %v (%dx the %v per-pattern budget) and correctly did not time out",
		elapsed, int(elapsed/budget), budget)
}

// TestScan_TimeoutFailsClosed pins the S17 verdict: a match that overruns its own
// budget blocks (returns hit=true) and names the pattern.
//
// The match parks on a channel that is only closed by the deferred cleanup, so it
// CANNOT complete while the scan is running — only the timeout case can be
// selected. No race between a real regex and a short timer.
func TestScan_TimeoutFailsClosed(t *testing.T) {
	block := make(chan struct{})
	defer close(block)

	// Pattern 0 blocks forever; the rest would return quickly but must never run.
	ps := fakeSet(5, func(idx int) bool {
		if idx == 0 {
			<-block
		}
		return false
	})

	got, hit := ps.scan(nil, 20*time.Millisecond)
	if !hit {
		t.Fatal("an overrunning match must fail closed (hit=true) — Zero Trust / S17")
	}
	if want := ps.raw[0]; got != want {
		t.Errorf("timeout reported pattern %q, want the overrunning pattern %q", got, want)
	}
}

// TestScan_AbandonedWorkerStopsEarly proves the abandoned flag is honoured: once
// the parent has failed closed, the orphaned worker must not go on to evaluate the
// REMAINING patterns. re.Match cannot be interrupted, so the overrunning match
// itself always runs to completion — the guarantee is only about what comes after
// it, and it holds only if the flag is actually checked between patterns.
func TestScan_AbandonedWorkerStopsEarly(t *testing.T) {
	var (
		mu      sync.Mutex
		visited []int
	)
	release := make(chan struct{})
	finished := make(chan struct{})

	ps := fakeSet(40, func(idx int) bool {
		mu.Lock()
		visited = append(visited, idx)
		mu.Unlock()
		if idx == 0 {
			<-release // hold until the parent has timed out and abandoned us
			close(finished)
		}
		return false
	})

	if _, hit := ps.scan(nil, 20*time.Millisecond); !hit {
		t.Fatal("expected a fail-closed timeout")
	}

	// The parent has abandoned the worker. Let the stuck match complete and give
	// the worker room to (incorrectly) continue if the flag is being ignored.
	close(release)
	<-finished
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(visited) != 1 || visited[0] != 0 {
		t.Errorf("abandoned worker evaluated patterns %v — it must stop after the "+
			"overrunning match (index 0); the abandoned flag is not being checked "+
			"between patterns", visited)
	}
}

// TestScan_ConcurrentWithConfigMutation is the copy-on-write guard. Scan workers
// can outlive their scan, so the pattern set they walk must never be written
// again. Before the snapshot, Remove shifted the shared backing array in place
// (append(s.compiled[:i], s.compiled[i+1:]...)) — a data race against any
// in-flight or abandoned worker. Run under -race, this fails on that design.
func TestScan_ConcurrentWithConfigMutation(t *testing.T) {
	s := New(1 << 20)
	if err := s.Set([]string{`alpha`, `beta`, `gamma`, `delta`}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	body := []byte(strings.Repeat("clean payload ", 64))

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.Scan(body)
					s.Enabled()
					s.List()
				}
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
					p := fmt.Sprintf(`churn-%d-%d`, id, n%3)
					if err := s.Add(p); err != nil {
						t.Errorf("Add(%q): %v", p, err)
						return
					}
					s.Remove(p)
					s.Remove(`gamma`)
					_ = s.Set([]string{`alpha`, `beta`, `gamma`, `delta`})
				}
			}
		}(i)
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestAddRemove_CopyOnWrite pins that the mutators publish a replacement set
// rather than editing the live one, and that they stay functionally correct.
func TestAddRemove_CopyOnWrite(t *testing.T) {
	s := New(1 << 20)
	if err := s.Set([]string{`one`, `two`, `three`}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	before := s.patterns()

	if err := s.Add(`four`); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if after := s.patterns(); after == before {
		t.Error("Add must publish a NEW pattern set, not mutate the live one")
	}
	if got := s.List(); len(got) != 4 || got[3] != "four" {
		t.Errorf("after Add, List = %v, want [one two three four]", got)
	}
	// The pre-Add snapshot an in-flight worker holds is unchanged.
	if len(before.raw) != 3 || len(before.compiled) != 3 {
		t.Errorf("Add mutated the previously-published set: raw=%v", before.raw)
	}

	mid := s.patterns()
	if !s.Remove(`two`) {
		t.Fatal("Remove(two) should report it existed")
	}
	if after := s.patterns(); after == mid {
		t.Error("Remove must publish a NEW pattern set, not mutate the live one")
	}
	if got := s.List(); len(got) != 3 || got[0] != "one" || got[1] != "three" || got[2] != "four" {
		t.Errorf("after Remove, List = %v, want [one three four]", got)
	}
	if len(mid.raw) != 4 || mid.raw[1] != "two" {
		t.Errorf("Remove mutated the previously-published set: raw=%v", mid.raw)
	}
	// raw[i] must still line up with compiled[i] after the shift.
	cur := s.patterns()
	for i, r := range cur.raw {
		if cur.compiled[i].String() != r {
			t.Errorf("index %d: raw=%q but compiled=%q — Remove desynced the pair",
				i, r, cur.compiled[i].String())
		}
	}
	if _, hit := s.Scan([]byte("contains two here")); hit {
		t.Error("a removed pattern must no longer match")
	}
	if pat, hit := s.Scan([]byte("contains three here")); !hit || pat != "three" {
		t.Errorf("Scan = (%q, %v), want (three, true)", pat, hit)
	}
}

// TestScan_ZeroValueScannerIsSafe covers the zero-value ContentScanner (built
// directly rather than via New) now that the pattern set lives behind a pointer.
func TestScan_ZeroValueScannerIsSafe(t *testing.T) {
	var s ContentScanner
	if s.Enabled() {
		t.Error("a zero-value scanner should be disabled")
	}
	if pat, hit := s.Scan([]byte("anything")); hit || pat != "" {
		t.Errorf("Scan = (%q, %v), want (\"\", false)", pat, hit)
	}
	if got := s.List(); len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
	if err := s.Add(`late`); err != nil {
		t.Fatalf("Add on a zero-value scanner: %v", err)
	}
	if pat, hit := s.Scan([]byte("a late arrival")); !hit || pat != "late" {
		t.Errorf("Scan = (%q, %v), want (late, true)", pat, hit)
	}
}
