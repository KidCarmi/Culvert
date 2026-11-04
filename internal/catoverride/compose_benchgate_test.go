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
//
// These allocation gates are deterministic and stay in the default suite. The
// one wall-clock RATIO gate on the suppression walk lives in the
// benchgate-tagged compose_suppress_benchgate_test.go: a timing assertion must
// not run under the shuffled, concurrent default-suite determinism job.

import (
	"fmt"
	"testing"
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
