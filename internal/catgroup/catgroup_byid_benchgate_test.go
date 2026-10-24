//go:build benchgate

package catgroup

import (
	"testing"
	"time"
)

// Wall-clock cost-shape gate for the byID index, kept BEHIND THE benchgate TAG.
//
// It lives here, and not beside the rest of the byID gates, because a
// wall-clock ratio is not a property an ordinary test run can decide. The
// repo's standing rule is that a gate which can flake gets muted, and this one
// proved it: measured on a 4-core box with six competing CPU hogs, the
// untagged form failed 2 of 8 runs against an UNCHANGED implementation
// (ratios of 11.22x and 15.75x against an 8x bound). An external review
// reproduced the same shape independently (9.44x, and up to 41.13x on a
// repeat). A gate that red-lights a correct tree a quarter of the time is
// worse than no gate, because the first thing anyone does is stop believing
// it — and it would land on `Deep · determinism`, which runs the whole module
// shuffled twice and has already cost this branch one cycle.
//
// `benchgate`-tagged tests are outside the default `go test ./...` build and
// run in the dedicated serial job (`Gate · perf-regression (allocs/op)` in
// .github/workflows/pr-fast-gate.yml, mirrored in qa-gate.yml and
// proxy-weekly-stress.yml), which is the only place a timing comparison is
// meaningful. `./internal/catgroup` is in those commands; without it this file
// would compile nowhere and the gate would silently never run — which is the
// other half of the defect, since the untagged names already claimed
// benchgate membership they did not have.
//
// What the ORDINARY suite keeps instead, deterministically:
//   - TestByIDIndex_WallNoLinearIDScanSurvives — an AST wall over the source,
//     so a reintroduced `if g.ID == id` walk fails the build regardless of load.
//   - TestByIDIndex_BulkInstallReindexesOnce — a revision-delta assertion, the
//     exact invariant the old quadratic-cost ratio was approximating.

// measureBest runs fn iters times and returns the best of three samples: a
// scheduler hiccup inflates a sample, never deflates it, so best-of-three is
// the noise-robust statistic for a ratio gate. It is necessary but NOT
// sufficient on a loaded runner — hence the tag above.
func measureBest(iters int, fn func()) time.Duration {
	one := func() time.Duration {
		for i := 0; i < iters/10; i++ { // warm up; neither arm pays first-touch alone
			fn()
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			fn()
		}
		return time.Since(start)
	}
	d := one()
	for i := 0; i < 2; i++ {
		if e := one(); e < d {
			d = e
		}
	}
	return d
}

// TestBenchGate_MatchesCategoryByIDIsFlatInGroupCount is a RATIO gate, so it is
// machine-independent: it compares the resolve against ITSELF at two store
// sizes rather than against an absolute nanosecond budget (the standing rule —
// an absolute bound gets re-baselined per machine and then muted).
//
// The pre-index walk cost ~5 ns per group, so 1000 groups cost ~45x what 4
// cost (measured 117.6 ns → 5298 ns on a 4-core Xeon @2.10GHz). The index makes
// the cost independent of store size; measured ratio after the change is ~1.0.
// The bound is 4x, which keeps a wide margin while still failing hard if the
// walk returns.
//
// The resolve assertion inside `measure` is an EMBEDDED CONTROL: the cheapest
// way to make a resolve flat is to stop resolving, and an implementation that
// answered "unresolved" would fail here rather than post a fast green.
func TestBenchGate_MatchesCategoryByIDIsFlatInGroupCount(t *testing.T) {
	const (
		small = 4
		large = 1000
		bound = 4.0
	)
	measure := func(n int) time.Duration {
		s, ids := seedGroups(t, n)
		id := ids[0] // first-seeded: the walk's position is map-order random anyway
		return measureBest(20000, func() {
			if m, ok := s.MatchesCategoryByID(id, "Social Media"); !ok || !m {
				t.Fatal("expected a resolved match")
			}
		})
	}
	dSmall, dLarge := measure(small), measure(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("groups=%d: %v, groups=%d: %v, ratio=%.2fx (flat ~1x, linear ~45x, bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("MatchesCategoryByID cost scales with the group count (%.2fx for %dx the "+
			"groups, bound %.1fx): the linear g.ID walk has returned",
			ratio, large/small, bound)
	}
}
