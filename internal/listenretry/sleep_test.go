package listenretry

import (
	"math"
	"sync"
	"testing"
	"time"
)

// The constants every listener in package main uses today. The package does
// not own them; the tests use them so the cases read as the supervisors' own.
const (
	testInitial   = 1 * time.Second
	testCeiling   = 30 * time.Second
	testThreshold = 30 * time.Second
	testFloor     = 100 * time.Millisecond
)

func TestLadderNext_Schedule(t *testing.T) {
	l := Ladder{Initial: testInitial, Ceiling: testCeiling}
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second,
	}
	var cur time.Duration
	for i, w := range want {
		cur = l.Next(cur)
		if cur != w {
			t.Fatalf("rung %d = %s, want %s", i+1, cur, w)
		}
	}
}

func TestLadderNext_Edges(t *testing.T) {
	l := Ladder{Initial: testInitial, Ceiling: testCeiling}
	for _, tc := range []struct {
		name string
		cur  time.Duration
		want time.Duration
	}{
		{"zero is no failure yet", 0, testInitial},
		{"negative is treated as a reset", -time.Minute, testInitial},
		{"most negative", math.MinInt64, testInitial},
		{"one nanosecond doubles", 1, 2},
		{"half the ceiling reaches it exactly", testCeiling / 2, testCeiling},
		{"just over half the ceiling is capped", testCeiling/2 + 1, testCeiling},
		{"the ceiling stays", testCeiling, testCeiling},
		{"above the ceiling comes back down", time.Hour, testCeiling},
		{"largest rung that does not wrap", math.MaxInt64 / 2, testCeiling},
		// int64 doubling wraps here. The wrapped value is negative, so it is
		// not above the ceiling and is returned as is. Pinned because the
		// rule is moved unchanged, not because a supervisor reaches it.
		{"first rung that wraps", math.MaxInt64/2 + 1, math.MinInt64},
		{"largest rung wraps to -2ns", math.MaxInt64, -2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := l.Next(tc.cur); got != tc.want {
				t.Fatalf("Next(%d) = %d, want %d", tc.cur, got, tc.want)
			}
		})
	}
}

func TestLadderNext_UsesItsOwnFields(t *testing.T) {
	a := Ladder{Initial: 3 * time.Second, Ceiling: 10 * time.Second}
	b := Ladder{Initial: 7 * time.Millisecond, Ceiling: 20 * time.Millisecond}
	if got := a.Next(0); got != 3*time.Second {
		t.Errorf("a first rung = %s", got)
	}
	if got := b.Next(0); got != 7*time.Millisecond {
		t.Errorf("b first rung = %s", got)
	}
	if got := a.Next(6 * time.Second); got != 10*time.Second {
		t.Errorf("a capped rung = %s", got)
	}
	if got := b.Next(6 * time.Second); got != 20*time.Millisecond {
		t.Errorf("b capped rung = %s", got)
	}
	// Initial and Ceiling are not interchangeable.
	swapped := Ladder{Initial: 10 * time.Second, Ceiling: 3 * time.Second}
	if got := swapped.Next(0); got != 10*time.Second {
		t.Errorf("a ladder with Ceiling below Initial answers Initial first, got %s", got)
	}
	if got := swapped.Next(10 * time.Second); got != 3*time.Second {
		t.Errorf("and Ceiling afterwards, got %s", got)
	}
}

func TestLadderNext_ZeroValue(t *testing.T) {
	var l Ladder
	for _, cur := range []time.Duration{-1, 0, 1, time.Second} {
		if got := l.Next(cur); got != 0 {
			t.Errorf("zero Ladder Next(%s) = %s, want 0", cur, got)
		}
	}
}

func TestClampSleep_Cases(t *testing.T) {
	c := Clamp{Threshold: testThreshold, Floor: testFloor}
	for _, tc := range []struct {
		name       string
		wait       time.Duration
		failingFor time.Duration
		want       time.Duration
	}{
		{"well short of the threshold", time.Second, time.Second, time.Second},
		{"ends exactly at the threshold", 10 * time.Second, 20 * time.Second, 10 * time.Second},
		{"straddles by one nanosecond", 10*time.Second + 1, 20 * time.Second, 10 * time.Second},
		{"the 29 s case", 36 * time.Second, 29 * time.Second, time.Second},
		{"remaining equals the floor", time.Minute, testThreshold - testFloor, testFloor},
		{"remaining one below the floor", time.Minute, testThreshold - testFloor + 1, testFloor},
		{"one nanosecond remaining", time.Minute, testThreshold - 1, testFloor},
		{"threshold reached: clamp is off", 36 * time.Second, testThreshold, 36 * time.Second},
		{"threshold long passed", 36 * time.Second, time.Hour, 36 * time.Second},
		{"zero wait", 0, 29 * time.Second, 0},
		{"negative wait is returned", -time.Second, 29 * time.Second, -time.Second},
		{"negative failingFor lengthens the remaining time", 40 * time.Second, -20 * time.Second, 40 * time.Second},
		{"negative failingFor still clamps", 60 * time.Second, -20 * time.Second, 50 * time.Second},
		// Kept as it was: the floor is not compared with wait.
		{"a straddling wait shorter than the floor is lengthened to it", 50 * time.Millisecond, testThreshold - 10*time.Millisecond, testFloor},
		// Threshold - failingFor wraps positive at the most negative
		// failingFor, so the clamp does not apply.
		{"subtraction wraps", time.Hour, math.MinInt64, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Sleep(tc.wait, tc.failingFor); got != tc.want {
				t.Fatalf("Sleep(%s, %s) = %s, want %s", tc.wait, tc.failingFor, got, tc.want)
			}
		})
	}
}

// The property the clamp exists for: a sleep that starts before the threshold
// ends no later than the threshold plus the floor, and is never longer than
// the larger of the intended wait and the floor.
func TestClampSleep_NeverStraddlesByMoreThanTheFloor(t *testing.T) {
	c := Clamp{Threshold: testThreshold, Floor: testFloor}
	for failingFor := time.Duration(0); failingFor < testThreshold; failingFor += 37 * time.Millisecond {
		for _, wait := range []time.Duration{
			800 * time.Millisecond, time.Second, 2400 * time.Millisecond,
			16 * time.Second, 24 * time.Second, 30 * time.Second, 36 * time.Second,
		} {
			got := c.Sleep(wait, failingFor)
			if end := failingFor + got; end > testThreshold+testFloor {
				t.Fatalf("Sleep(%s, %s) = %s ends at %s, past the threshold by more than the floor", wait, failingFor, got, end)
			}
			if got > wait && got != testFloor {
				t.Fatalf("Sleep(%s, %s) = %s lengthened the wait", wait, failingFor, got)
			}
			if got <= 0 {
				t.Fatalf("Sleep(%s, %s) = %s: a positive wait became a spin", wait, failingFor, got)
			}
		}
	}
}

func TestClampSleep_UsesItsOwnFields(t *testing.T) {
	a := Clamp{Threshold: 10 * time.Second, Floor: time.Second}
	b := Clamp{Threshold: time.Minute, Floor: time.Millisecond}
	if got := a.Sleep(time.Hour, 4*time.Second); got != 6*time.Second {
		t.Errorf("a = %s, want 6s", got)
	}
	if got := b.Sleep(time.Hour, 4*time.Second); got != 56*time.Second {
		t.Errorf("b = %s, want 56s", got)
	}
	if got := a.Sleep(time.Hour, 10*time.Second-time.Millisecond); got != time.Second {
		t.Errorf("a floor = %s, want 1s", got)
	}
	if got := b.Sleep(time.Hour, time.Minute-time.Microsecond); got != time.Millisecond {
		t.Errorf("b floor = %s, want 1ms", got)
	}
}

func TestClampSleep_ZeroValue(t *testing.T) {
	var c Clamp
	// A zero threshold is reached by any failingFor that is not negative, so
	// the clamp is off.
	for _, failingFor := range []time.Duration{0, 1, time.Second, time.Hour} {
		if got := c.Sleep(time.Hour, failingFor); got != time.Hour {
			t.Errorf("zero Clamp Sleep(1h, %s) = %s, want 1h", failingFor, got)
		}
	}
	// A negative failingFor leaves time remaining to a zero threshold, and
	// the clamp applies as for any other threshold.
	if got := c.Sleep(time.Hour, -time.Second); got != time.Second {
		t.Errorf("zero Clamp Sleep(1h, -1s) = %s, want 1s", got)
	}
}

// Two values share nothing: the package has no state, so concurrent callers
// with different constants each get their own answers. Run under -race.
func TestIndependentValues_ConcurrentCallersAgree(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			initial := time.Duration(g+1) * time.Second
			l := Ladder{Initial: initial, Ceiling: 8 * initial}
			c := Clamp{Threshold: 10 * initial, Floor: initial / 10}
			for i := 0; i < 2000; i++ {
				if got := l.Next(0); got != initial {
					t.Errorf("goroutine %d: first rung = %s, want %s", g, got, initial)
					return
				}
				if got := l.Next(5 * initial); got != 8*initial {
					t.Errorf("goroutine %d: capped rung = %s, want %s", g, got, 8*initial)
					return
				}
				if got := c.Sleep(100*initial, 4*initial); got != 6*initial {
					t.Errorf("goroutine %d: clamped sleep = %s, want %s", g, got, 6*initial)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
