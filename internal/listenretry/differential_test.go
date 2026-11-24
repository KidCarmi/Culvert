package listenretry

import (
	"math"
	"testing"
	"time"
)

// Frozen copies of the bodies package main carried on main 46b4ffa6e, before
// IM-027 bound them here. They are the oracle for the differential tests and
// the fuzz targets; they are not edited when the package is.
//
// frozenLadder is nextCPGRPCBindBackoff (cp_grpc_bind.go) and
// nextScanSvcBindBackoff (scan_svc_listener.go): the two bodies were the same
// statements over each listener's two constants, here the two parameters.
func frozenLadder(cur, initial, ceiling time.Duration) time.Duration {
	if cur <= 0 {
		return initial
	}
	cur *= 2
	if cur > ceiling {
		return ceiling
	}
	return cur
}

// frozenClamp is clampCPGRPCBindSleep (cp_grpc_health.go) and
// clampSOCKS5BindSleep (socks5_health.go), likewise.
func frozenClamp(d, failingFor, threshold, floor time.Duration) time.Duration {
	remaining := threshold - failingFor
	if remaining <= 0 || d <= remaining {
		return d
	}
	if remaining < floor {
		return floor
	}
	return remaining
}

// splitMix64 is a fixed-seed generator, so the input set is the same on every
// run and does not depend on math/rand's algorithm.
type splitMix64 uint64

func (s *splitMix64) next() uint64 {
	*s += 0x9E3779B97F4A7C15
	z := uint64(*s)
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// duration draws from three ranges in turn: the supervisors' own (up to about
// two minutes), any int64 of either sign, and values within a few nanoseconds
// of a boundary constant.
func (s *splitMix64) duration(i int) time.Duration {
	switch i % 3 {
	case 0:
		return time.Duration(s.next() % uint64(2*time.Minute))
	case 1:
		return time.Duration(int64(s.next())) // #nosec G115 -- the wrap is wanted: any int64 of either sign
	}
	anchors := []time.Duration{
		0, testFloor, testInitial, testCeiling / 2, testCeiling,
		math.MaxInt64 / 2, math.MaxInt64, math.MinInt64,
	}
	anchor := anchors[s.next()%uint64(len(anchors))]
	return anchor + time.Duration(int64(s.next()%7)-3) // wraps at the limits, deliberately
}

func TestLadderNext_MatchesFrozenCopy(t *testing.T) {
	gen := splitMix64(0x0BADC0FFEE0DDF00)
	const inputs = 60000
	for i := 0; i < inputs; i++ {
		cur, initial, ceiling := gen.duration(i), gen.duration(i+1), gen.duration(i+2)
		got := Ladder{Initial: initial, Ceiling: ceiling}.Next(cur)
		if want := frozenLadder(cur, initial, ceiling); got != want {
			t.Fatalf("input %d: Ladder{%d,%d}.Next(%d) = %d, frozen copy = %d", i, initial, ceiling, cur, got, want)
		}
	}
}

func TestClampSleep_MatchesFrozenCopy(t *testing.T) {
	gen := splitMix64(0x5EED5EED5EED5EED)
	const inputs = 60000
	for i := 0; i < inputs; i++ {
		wait, failingFor := gen.duration(i), gen.duration(i+1)
		threshold, floor := gen.duration(i+2), gen.duration(i)
		got := Clamp{Threshold: threshold, Floor: floor}.Sleep(wait, failingFor)
		if want := frozenClamp(wait, failingFor, threshold, floor); got != want {
			t.Fatalf("input %d: Clamp{%d,%d}.Sleep(%d,%d) = %d, frozen copy = %d", i, threshold, floor, wait, failingFor, got, want)
		}
	}
}

func FuzzLadderNext(f *testing.F) {
	f.Add(int64(0), int64(testInitial), int64(testCeiling))
	f.Add(int64(16*time.Second), int64(testInitial), int64(testCeiling))
	f.Add(int64(math.MaxInt64), int64(testInitial), int64(testCeiling))
	f.Add(int64(-1), int64(0), int64(0))
	f.Fuzz(func(t *testing.T, cur, initial, ceiling int64) {
		l := Ladder{Initial: time.Duration(initial), Ceiling: time.Duration(ceiling)}
		got := l.Next(time.Duration(cur))
		if want := frozenLadder(time.Duration(cur), l.Initial, l.Ceiling); got != want {
			t.Fatalf("Next = %d, frozen copy = %d", got, want)
		}
		// With a sane ladder and a rung that cannot wrap, the answer is a
		// rung of the ladder: positive and at most the ceiling.
		sane := initial > 0 && ceiling >= initial && cur <= math.MaxInt64/2
		if sane && (got <= 0 || got > l.Ceiling) {
			t.Fatalf("Ladder{%d,%d}.Next(%d) = %d: outside (0, ceiling]", initial, ceiling, cur, got)
		}
	})
}

func FuzzClampSleep(f *testing.F) {
	f.Add(int64(36*time.Second), int64(29*time.Second), int64(testThreshold), int64(testFloor))
	f.Add(int64(time.Second), int64(time.Second), int64(testThreshold), int64(testFloor))
	f.Add(int64(time.Minute), int64(testThreshold-1), int64(testThreshold), int64(testFloor))
	f.Add(int64(0), int64(math.MinInt64), int64(0), int64(0))
	f.Fuzz(func(t *testing.T, wait, failingFor, threshold, floor int64) {
		c := Clamp{Threshold: time.Duration(threshold), Floor: time.Duration(floor)}
		got := c.Sleep(time.Duration(wait), time.Duration(failingFor))
		if want := frozenClamp(time.Duration(wait), time.Duration(failingFor), c.Threshold, c.Floor); got != want {
			t.Fatalf("Sleep = %d, frozen copy = %d", got, want)
		}
		// The answer is always one of three values; the clamp invents none.
		if got != time.Duration(wait) && got != c.Floor && got != c.Threshold-time.Duration(failingFor) {
			t.Fatalf("Clamp{%d,%d}.Sleep(%d,%d) = %d: not the wait, the floor or the remaining time", threshold, floor, wait, failingFor, got)
		}
	})
}
