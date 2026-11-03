package catoverride

// Regression gate for the composition suppression fast path.
//
// WHY THIS GATES ALLOCATIONS AND NOT TIME
//
// The defect this guards against is algorithmic: suppression used to scan the
// override key list once per feed host, so composition was O(feed x overrides)
// and concatenated `"."+key` on every pair. A wall-clock gate for that is
// either flaky on shared CI runners or so loose it catches nothing — the
// quadratic term only dominates past a feed size too large to spend a unit test
// on.
//
// The allocation count, by contrast, is a DETERMINISTIC witness of the same
// defect and is independent of machine speed. With override keys longer than the
// 32-byte stack buffer Go uses for a non-escaping concat, the old form shed one
// transient string per (feed host x override key) — F x M allocations — while
// the current form allocates only its output map plus the one-off suppressor
// set. So: hold the feed fixed, sweep the override count, and assert the
// allocation count does NOT grow with it. A revert to any per-host scan over the
// key list fails this by orders of magnitude.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// gateFeedHosts is small on purpose: the gate reads a SHAPE (allocations flat in
// the override count), not a magnitude, so it does not need a realistic feed to
// be decisive. At 2 000 hosts and 512 keys the old form allocated ~1.02M strings
// where the current one allocates a few dozen.
const gateFeedHosts = 2000

// gateLongKey is past the compiler's 32-byte non-escaping-concat buffer, so the
// `"."+key` temporary the old form built had to reach the heap. A short key would
// make this gate vacuous — Go would stack-allocate the concat and the allocation
// counts would match. Keep it long.
func gateLongKey(i int) string {
	return fmt.Sprintf("tomb%d.some-long-subdomain.customer-tenant-name.example.com", i)
}

// gateGrowthMargin is the allowance over the single-key baseline. The current
// implementation's only override-count-dependent allocation is the suppressor map
// itself (a handful of buckets), so a couple of dozen allocations is generous
// while still being ~4 orders of magnitude below the quadratic form.
const gateGrowthMargin = 48

func TestBenchGate_ComposeViewAllocsFlatInOverrideCount(t *testing.T) {
	feed := make(map[string]string, gateFeedHosts)
	for i := 0; i < gateFeedHosts; i++ {
		feed[fmt.Sprintf("host%d.tenant%d.example.com", i, i%64)] = "Social Media"
	}
	baseline := composeViewAllocs(t, feed, gateOverrides(1))
	for _, m := range []int{64, 512} {
		got := composeViewAllocs(t, feed, gateOverrides(m))
		if limit := baseline + gateGrowthMargin; got > limit {
			t.Errorf("ComposeView with %d override keys allocated %.0f objects (baseline at 1 key: %.0f, limit %.0f).\n"+
				"Allocations must not grow with the override count — a per-host scan over the key list is back "+
				"(it would allocate about feed x overrides = %d here).",
				m, got, baseline, limit, gateFeedHosts*m)
		}
	}
}

// TestBenchGate_ComposeMembershipAllocsFlatInOverrideCount is the same gate for
// the many-to-many composition, which shares the suppression path. Its baseline
// is much higher (one category slice copied per surviving host), so the gate is
// still stated as growth over its OWN single-key baseline rather than an absolute.
func TestBenchGate_ComposeMembershipAllocsFlatInOverrideCount(t *testing.T) {
	members := make(map[string][]string, gateFeedHosts)
	for i := 0; i < gateFeedHosts; i++ {
		members[fmt.Sprintf("host%d.tenant%d.example.com", i, i%64)] = []string{"Social Media", "Collaboration"}
	}
	baseline := composeMembershipAllocs(t, members, gateOverrides(1))
	for _, m := range []int{64, 512} {
		got := composeMembershipAllocs(t, members, gateOverrides(m))
		if limit := baseline + gateGrowthMargin; got > limit {
			t.Errorf("ComposeMembership with %d override keys allocated %.0f objects (baseline at 1 key: %.0f, limit %.0f); "+
				"allocations must not grow with the override count", m, got, baseline, limit)
		}
	}
}

// TestBenchGate_GateWouldCatchTheLegacyForm is the NEGATIVE CONTROL: it runs the
// frozen pre-change composition through the very same measurement and asserts it
// BLOWS the budget. Without this, a future change that made the gate vacuous
// (short keys, a feed too small, a margin too wide) would keep passing silently
// and the gate would protect nothing.
func TestBenchGate_GateWouldCatchTheLegacyForm(t *testing.T) {
	feed := make(map[string]string, gateFeedHosts)
	for i := 0; i < gateFeedHosts; i++ {
		feed[fmt.Sprintf("host%d.tenant%d.example.com", i, i%64)] = "Social Media"
	}
	baseline := composeViewAllocs(t, feed, gateOverrides(1))
	ov := gateOverrides(512)
	legacy := testing.AllocsPerRun(1, func() { _ = legacyComposeView(feed, ov) })
	if limit := baseline + gateGrowthMargin; legacy <= limit {
		t.Fatalf("the frozen legacy composition allocated only %.0f objects (limit %.0f) — "+
			"this gate is vacuous and would not catch a revert", legacy, limit)
	}
}

// gateOverrides builds m long-key tombstones that cover NOTHING in the feed, so
// every feed host pays the full suppression cost. A covering key would let the old
// form short-circuit and hide the very growth this gate measures.
func gateOverrides(m int) Overrides {
	o := Overrides{Tombstones: make([]string, 0, m)}
	for i := 0; i < m; i++ {
		o.Tombstones = append(o.Tombstones, gateLongKey(i))
	}
	return o
}

func composeViewAllocs(t *testing.T, feed map[string]string, o Overrides) float64 {
	t.Helper()
	return testing.AllocsPerRun(1, func() { _ = ComposeView(feed, o) })
}

func composeMembershipAllocs(t *testing.T, feed map[string][]string, o Overrides) float64 {
	t.Helper()
	return testing.AllocsPerRun(1, func() { _ = ComposeMembership(feed, o) })
}

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
