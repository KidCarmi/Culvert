//go:build benchgate

package decryptprofile

import (
	"testing"
	"time"
)

// Wall-clock cost-shape gate for the stable-ID index, kept BEHIND THE
// benchgate TAG.
//
// It is tagged for the reason internal/catgroup recorded against its own byID
// ratio gate: a wall-clock ratio is not a property an ordinary test run can
// decide. Measured there on a 4-core box under competing CPU load, the
// untagged form failed 2 of 8 runs against an UNCHANGED implementation. A
// gate that red-lights a correct tree a quarter of the time is worse than no
// gate, and it would land on `Deep · determinism`, which runs the module
// shuffled twice.
//
// `benchgate`-tagged tests are outside the default `go test ./...` build and
// run in the dedicated serial job (`Gate · perf-regression (allocs/op)` in
// .github/workflows/pr-fast-gate.yml, mirrored in qa-gate.yml and
// proxy-weekly-stress.yml), which is the only place a timing comparison is
// meaningful. `./internal/decryptprofile` was ADDED to all three of those
// commands in the same change that added this file: without it the file would
// compile nowhere and the gate would silently never run — the other half of
// the defect catgroup recorded, where tagged names claimed a membership they
// did not have.
//
// What the ORDINARY suite keeps instead, deterministically (see
// decryptprofile_idindex_test.go):
//   - TestIDIndex_WallNoLinearIDScanSurvives — a source wall, so an ID-keyed
//     READ that goes back to `range s.profiles` fails regardless of load.
//   - TestIDIndex_ConsistentAfterEveryMutation — the index can never serve
//     content the name map does not hold.
//   - TestIDIndex_BulkInstallReindexesOnce — the O(N^2)-install invariant, by
//     counting mutations rather than timing them.

// measureBestIDX runs fn iters times and returns the best of three samples: a
// scheduler hiccup inflates a sample, never deflates it, so best-of-three is
// the noise-robust statistic for a ratio gate. Necessary but NOT sufficient on
// a loaded runner — hence the tag above.
func measureBestIDX(iters int, fn func()) time.Duration {
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

// TestBenchGate_FailOpenScopeByIDIsFlatInProfileCount is a RATIO gate, so it
// is machine-independent: it compares the resolve against ITSELF at two store
// sizes rather than against an absolute nanosecond budget (the standing rule —
// an absolute bound gets re-baselined per machine and then muted).
//
// It gates FailOpenScopeByID rather than GetByID because FailOpenScopeByID
// returns no copy: its whole cost IS the lookup, so the ratio moves the full
// distance the shape change is worth. GetByID's constant 177 B copy dilutes
// the same signal (862 → 118 ns measured, but a 7.3x ratio rather than 30x),
// and the two share one lookup, so gating the undiluted one gates both.
//
// The pre-index walk cost ~5.5 ns per profile: 1 profile measured 49.6 ns and
// 1000 would be ~5.6 µs, a ratio near 100x. After the index the measured ratio
// is ~1.0. The bound is 4x — a wide margin for a loaded runner that still
// fails hard the moment the walk returns.
//
// The resolve assertion inside `measure` is an EMBEDDED CONTROL: the cheapest
// way to make a resolve flat is to stop resolving, and an implementation that
// answered "unresolved" would fail here rather than post a fast green.
func TestBenchGate_FailOpenScopeByIDIsFlatInProfileCount(t *testing.T) {
	const (
		small = 1
		large = 1000
		bound = 4.0
	)
	measure := func(n int) time.Duration {
		s, id := benchIDStore(n)
		return measureBestIDX(20000, func() {
			if scope, _, ok := s.FailOpenScopeByID(id); !ok || scope == "" {
				t.Fatal("expected a resolved fail-open scope")
			}
		})
	}
	dSmall, dLarge := measure(small), measure(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("profiles=%d: %v, profiles=%d: %v, ratio=%.2fx (flat ~1x, linear ~100x, bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("FailOpenScopeByID cost scales with the profile count (%.2fx for %dx the "+
			"profiles, bound %.1fx): the linear p.ID walk has returned",
			ratio, large/small, bound)
	}
}

// TestBenchGate_GetByIDAllocs pins the per-H2-stream resolve's allocation
// count. Allocations are deterministic and hardware-independent, so unlike the
// ratio above this is a hard number rather than a margin.
//
// Two is the copyOut cost: the Profile value plus the deep-copied
// InspectHTTP2 *bool. The bound is NOT tightened to remove them — that is the
// separate no-copy-accessor change the benchmark file describes. What it
// catches is the lookup growing an allocation (a built key, an interface box,
// a slice of candidates), which is how an O(1) rewrite of a scan usually
// regresses.
func TestBenchGate_GetByIDAllocs(t *testing.T) {
	const maxAllocs = 2
	for _, n := range []int{1, 128, 1000} {
		s, id := benchIDStore(n)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if p := s.GetByID(id); p == nil {
					b.Fatal("resolve missed")
				}
			}
		})
		if got := res.AllocsPerOp(); got > maxAllocs {
			t.Errorf("GetByID at %d profiles allocates %d/op, bound %d: the ID lookup has "+
				"grown an allocation beyond copyOut's two", n, got, maxAllocs)
		} else {
			t.Logf("profiles=%d: %d allocs/op, %d B/op", n, got, res.AllocedBytesPerOp())
		}
	}
}
