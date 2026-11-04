//go:build benchgate

package catoverride

// Wall-clock ratio gate for the suppression walk. It is benchgate-tagged because
// it compares elapsed times: under the default suite's concurrent, shuffled
// determinism run, scheduler pauses could exceed the ratio with no algorithmic
// regression. The deterministic allocation gates for the same fast path stay in
// the default suite (compose_benchgate_test.go).

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestBenchGate_SuppressionBoundedByKeyLengthNotHostLength is the CHAOS-69 guard
// on the new walk.
//
// covers() probes the host's ancestor suffixes against the key set. Probing a
// suffix means HASHING it, and the suffixes of a dot-dense authority sum to
// O(len(host)^2) — so an unbounded walk would have swapped a quadratic in the
// override count for a quadratic in the host length. The maxLen bound is what
// refuses that: a key can only equal a candidate of its own length, so longer
// candidates are skipped without being hashed, and the hashing is capped by the
// longest KEY (NormalizeHost-bounded) rather than by the host.
//
// This matters because composition does not only see signed feed hosts, which
// urlcatfeed.NormalizeHost caps at 253 octets. On the embedded-source bulk-apply
// path (bulk_ref_validation.go candidateCategoryNames) the base memberships come
// from admin-supplied catStore category hosts, and no length cap was found on
// that write path — so the bound belongs here, at the matcher, not in an
// assumption about the caller.
//
// The gate is a RATIO, not a wall-clock budget: a host 16x longer than another
// must not cost ~256x more. A quadratic walk fails this by a wide margin while a
// bounded one stays near-linear.
func TestBenchGate_SuppressionBoundedByKeyLengthNotHostLength(t *testing.T) {
	// The key set must be big enough to force a real hashed map lookup. Go's
	// mapaccess_faststr has a single-bucket short-cut that compares key LENGTHS
	// before it ever hashes, so a set of one key makes this gate VACUOUS — the
	// unbounded walk costs nothing measurable and the mutant passes (verified:
	// it did). Past 8 entries the map has multiple buckets and every probe hashes
	// its candidate, which is the cost the maxLen bound exists to avoid.
	//
	// Every key stays SHORT so the bound is what does the skipping, and none of
	// them covers the probe hosts, so the walk always runs to completion.
	ov := Overrides{}
	for i := 0; i < 64; i++ {
		ov.Tombstones = append(ov.Tombstones, fmt.Sprintf("k%d.covered.example", i))
	}
	sup := newSuffixSuppressor(ov)

	dotDense := func(labels int) string {
		return strings.Repeat("a.", labels) + "example"
	}
	const (
		small = 512
		big   = small * 16
	)
	timeFor := func(host string) time.Duration {
		// Enough repetitions that the measurement is not timer-resolution bound.
		const reps = 200
		start := time.Now()
		for i := 0; i < reps; i++ {
			if sup.covers(host) {
				t.Fatal("control host must not be covered")
			}
		}
		return time.Since(start) / reps
	}
	// Warm up so neither row pays first-touch costs.
	_ = timeFor(dotDense(small))
	tSmall := timeFor(dotDense(small))
	tBig := timeFor(dotDense(big))

	// Linear would be ~16x. Quadratic would be ~256x. Allow a generous 64x so a
	// loaded CI runner cannot flake the gate, while still failing a quadratic.
	const maxRatio = 64
	if tSmall > 0 && tBig > tSmall*maxRatio {
		t.Errorf("covers() cost grew %.1fx for a %dx longer host (%v -> %v); "+
			"the walk is super-linear in host length — the maxLen bound is gone",
			float64(tBig)/float64(tSmall), big/small, tSmall, tBig)
	}
}
