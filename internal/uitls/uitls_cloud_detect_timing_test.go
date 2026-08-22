package uitls

import (
	"net"
	"testing"
	"time"
)

// These tests exercise raceProbesByPrecedence directly with synthetic probe
// functions (no HTTP, no real network, no dependency on container detection
// or the real 169.254.169.254/checkip/icanhazip endpoints) so the timing
// assertions are deterministic on any host or CI runner — unlike probing
// through detectCloudPublicIPs/detectPublicIPFallback end-to-end, whose
// AWS-hardcoded probe and container-gated fallback phase depend on real,
// unmockable network/environment behavior that varies by sandbox.
//
// raceProbesByPrecedence backs both detectCloudPublicIPs (called
// synchronously from startUI -> selfSignedTLS on every process start whenever
// no explicit -tls-cert/-tls-key is configured, the shipped docker-compose.yml
// default) and detectPublicIPFallback.

// TestRaceProbesByPrecedence_BoundedByMaxNotSum_WhenAllFail guards against
// the original bug: on a host where cloud metadata is unreachable in a way
// that HANGS rather than fails fast (a common enterprise/air-gapped
// posture — DROPPING rather than REJECTING metadata traffic to deter SSRF),
// probing every candidate one after another paid the SUM of their timeouts.
// Probed concurrently, the cost is bounded by the SLOWEST single probe.
func TestRaceProbesByPrecedence_BoundedByMaxNotSum_WhenAllFail(t *testing.T) {
	const perProbeDelay = 300 * time.Millisecond
	probes := make([]func() net.IP, 4)
	for i := range probes {
		probes[i] = func() net.IP {
			time.Sleep(perProbeDelay)
			return nil
		}
	}

	start := time.Now()
	got := raceProbesByPrecedence(probes)
	elapsed := time.Since(start)

	if got != nil {
		t.Fatalf("got %v, want nil (every probe fails)", got)
	}
	// Sequential would sum to ~1.2s (4 x 300ms); concurrent costs ~300ms.
	// Generous margin for scheduler jitter while still catching a regression
	// back to sequential probing.
	if elapsed > 2*perProbeDelay {
		t.Errorf("raceProbesByPrecedence took %s for 4 concurrent %s-each failing probes; "+
			"want close to a single probe's delay, not the sum", elapsed, perProbeDelay)
	}
}

// TestRaceProbesByPrecedence_ReturnsAssoonAsWinnerConfirmed guards against
// the review-flagged regression in the FIRST version of this fix: a naive
// "launch everything, sync.WaitGroup.Wait for all of them" implementation
// bounds the ALL-FAIL case correctly but then holds up a fast,
// highest-precedence SUCCESS behind a slow or hanging lower-precedence probe
// — worse than the original sequential code, which returned immediately on
// the first success and never even started the rest.
func TestRaceProbesByPrecedence_ReturnsAssoonAsWinnerConfirmed(t *testing.T) {
	winner := net.ParseIP("203.0.113.9")
	probes := []func() net.IP{
		func() net.IP { return winner }, // highest precedence, resolves instantly
		func() net.IP {
			time.Sleep(2 * time.Second) // lower precedence, hangs
			return net.ParseIP("198.51.100.1")
		},
	}

	start := time.Now()
	got := raceProbesByPrecedence(probes)
	elapsed := time.Since(start)

	if got == nil || !got.Equal(winner) {
		t.Fatalf("got %v, want %v", got, winner)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("raceProbesByPrecedence took %s to return a same-instant highest-precedence "+
			"success; want it to not wait on the slower, lower-precedence probe", elapsed)
	}
}

// TestRaceProbesByPrecedence_HigherPrecedenceWinsEvenIfSlower proves the
// precedence contract survives concurrency: a slower success ranked ABOVE a
// faster success (or a faster failure) must still win, matching "a host is
// only on one provider, try candidates in a fixed order" — a plain
// first-to-finish race would pick the wrong one here.
func TestRaceProbesByPrecedence_HigherPrecedenceWinsEvenIfSlower(t *testing.T) {
	winner := net.ParseIP("203.0.113.44")
	probes := []func() net.IP{
		func() net.IP {
			time.Sleep(150 * time.Millisecond)
			return winner
		},
		func() net.IP { return nil }, // resolves immediately but ranks lower
	}

	got := raceProbesByPrecedence(probes)
	if got == nil || !got.Equal(winner) {
		t.Fatalf("got %v, want %v (higher-precedence probe must win despite being slower)", got, winner)
	}
}

// TestRaceProbesByPrecedence_Empty is the degenerate case.
func TestRaceProbesByPrecedence_Empty(t *testing.T) {
	if got := raceProbesByPrecedence(nil); got != nil {
		t.Errorf("got %v, want nil for an empty probe list", got)
	}
}
