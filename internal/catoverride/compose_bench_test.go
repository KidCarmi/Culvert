package catoverride

// Composition benchmarks for the override fold (ComposeView / ComposeMembership).
//
// WHY THESE ARE SIZED THE WAY THEY ARE
//
// The composition is not per-request, but it is not off-path either. It runs
// over the WHOLE feed-owned snapshot:
//
//   - saas_feed_activate.go buildEffectiveView / composeEmbeddedForOverrides —
//     every signed activation and every override-only recompose, under the
//     activation coordinator's lock.
//   - bulk_ref_validation.go candidateCategoryNames — an ADMIN REQUEST path: a
//     bulk category apply composes the candidate override set over the live
//     view's raw signed base before it can judge one category edge.
//
// The feed snapshot is bounded by urlcatfeed.MaxArtifactSize (8 MiB) of
// canonical host->category JSON, which is ~240k entries at a realistic ~35
// bytes per entry, so the feed axis below sweeps to 100k: large enough to show
// the asymptotics without making the bench suite slow. The override axis is
// UNBOUNDED by contract — nothing in Normalize/Validate caps how many
// additions, recategorizations or tombstones an administrator may hold — so it
// sweeps to 1024, a posture a large multi-tenant deployment reaches.
//
// Run locally:
//
//	go test -run '^$' -bench 'BenchmarkCompose' -benchmem ./internal/catoverride/
//
// MEASURED (this machine: Go 1.27.3, linux/amd64, 4 vCPU Xeon @ 2.30GHz, medians
// of -count=6, legacy vs current IN ONE BINARY via BenchmarkComposeAB):
//
//	ComposeView                  legacy        current      time
//	feed=100k  overrides=1024    1322.1 ms      16.8 ms    -98.7%
//	feed=100k  overrides=16        35.3 ms      15.9 ms    -54.9%
//	feed=10k   overrides=1024     128.2 ms       1.01 ms   -99.2%
//	feed=10k   overrides=16         2.90 ms      0.96 ms   -66.8%
//	LongKeys   (F=5k, M=64)        17.2 ms       0.50 ms   -97.1%
//	                               320 018 allocs -> 22
//	AllCovered (1 covering key)     0.49 ms      0.47 ms    -5.0%
//
// AND THE HONEST OTHER SIDE — a single NON-covering key gets slower, because one
// strings.HasSuffix beats a hashed set probe plus a label walk:
//
//	feed=100k  overrides=1          12.8 ms      14.6 ms    +14.1%
//	feed=10k   overrides=1           0.80 ms      1.01 ms   +26.1%
//	feed=100k  overrides=0          10.0 ms      10.5 ms     +4.3%  (same path)
//
// The crossover is between 1 and 16 keys. A hybrid (scan below a few keys, probe
// above) would recover those rows, and it is deliberately NOT implemented: the
// absolute cost is +1.8 ms on a feed activation, against 1.3 SECONDS of
// quadratic blowup removed, and the repository's conventions forbid buying a gain
// that small with a branch in a security-relevant composition.

import (
	"fmt"
	"testing"
)

// composeBenchFeed builds a feed-owned snapshot of n hosts in a shape that
// matches the real artifact: a few labels, dot-dense, mostly NOT covered by any
// override (the common case — overrides are a thin admin layer over a large
// feed).
func composeBenchFeed(n int) map[string]string {
	feed := make(map[string]string, n)
	for i := 0; i < n; i++ {
		feed[fmt.Sprintf("host%d.tenant%d.example.com", i, i%64)] = "Social Media"
	}
	return feed
}

// composeBenchMembers is composeBenchFeed in the many-to-many shape
// ComposeMembership consumes.
func composeBenchMembers(n int) map[string][]string {
	members := make(map[string][]string, n)
	for i := 0; i < n; i++ {
		members[fmt.Sprintf("host%d.tenant%d.example.com", i, i%64)] = []string{"Social Media", "Collaboration"}
	}
	return members
}

// composeBenchOverrides builds an override set of m keys split across the three
// kinds. The keys deliberately do NOT cover the feed hosts above: a miss is the
// case that pays the FULL suppression cost for every feed host, which is the
// honest worst case and also the common one.
func composeBenchOverrides(m int) Overrides {
	o := Overrides{
		Added:         make(map[string]string, m/3+1),
		Recategorized: make(map[string]string, m/3+1),
	}
	for i := 0; i < m; i++ {
		switch i % 3 {
		case 0:
			o.Added[fmt.Sprintf("added%d.override.example", i)] = "Business"
		case 1:
			o.Recategorized[fmt.Sprintf("recat%d.override.example", i)] = "Finance"
		default:
			o.Tombstones = append(o.Tombstones, fmt.Sprintf("tomb%d.override.example", i))
		}
	}
	return o
}

// composeBenchFeedSizes / composeBenchOverrideCounts are the swept axes. The
// override=0 row is the no-op posture (both callers short-circuit it in
// production, but it anchors the baseline cost of the copy itself).
var (
	composeBenchFeedSizes      = []int{1000, 10000, 100000}
	composeBenchOverrideCounts = []int{0, 16, 256, 1024}
)

func BenchmarkComposeView(b *testing.B) {
	for _, f := range composeBenchFeedSizes {
		feed := composeBenchFeed(f)
		for _, m := range composeBenchOverrideCounts {
			ov := composeBenchOverrides(m)
			b.Run(fmt.Sprintf("feed=%d/overrides=%d", f, m), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if out := ComposeView(feed, ov); len(out) == 0 {
						b.Fatal("composition produced an empty view")
					}
				}
			})
		}
	}
}

func BenchmarkComposeMembership(b *testing.B) {
	for _, f := range composeBenchFeedSizes {
		members := composeBenchMembers(f)
		for _, m := range composeBenchOverrideCounts {
			ov := composeBenchOverrides(m)
			b.Run(fmt.Sprintf("feed=%d/overrides=%d", f, m), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if out := ComposeMembership(members, ov); len(out) == 0 {
						b.Fatal("composition produced an empty membership")
					}
				}
			})
		}
	}
}

// BenchmarkComposeView_AllCovered is the opposite extreme: every feed host is a
// subdomain of a tombstone, so suppression HITS on the first probe. It is the
// control for the miss-dominated rows above — a linear scan looks fine here
// precisely because it stops immediately, which is why the miss rows are the
// ones to read.
func BenchmarkComposeView_AllCovered(b *testing.B) {
	const f = 10000
	feed := make(map[string]string, f)
	for i := 0; i < f; i++ {
		feed[fmt.Sprintf("host%d.covered.example", i)] = "Social Media"
	}
	ov := Overrides{Tombstones: []string{"covered.example"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if out := ComposeView(feed, ov); len(out) != 0 {
			b.Fatalf("expected full suppression, got %d entries", len(out))
		}
	}
}

// ─── in-binary before/after ────────────────────────────────────────────────
//
// The rows below run the FROZEN pre-change composition (legacyComposeView /
// legacyComposeMembership in compose_suppress_equiv_test.go, kept verbatim as
// the differential oracle) against the current one IN THE SAME BINARY and the
// same run. Comparing two separate `go test` invocations made the small rows
// unreadable: the 100k rows allocate a 5 MiB map per op, so allocator and GC
// state drift between runs showed up as double-digit "changes" on rows whose
// code path did not change at all. One binary removes that drift.
//
//	go test -run '^$' -bench 'BenchmarkComposeAB' -benchmem -count=6 ./internal/catoverride/

func BenchmarkComposeAB_View(b *testing.B) {
	for _, f := range []int{10000, 100000} {
		feed := composeBenchFeed(f)
		for _, m := range []int{0, 1, 16, 1024} {
			ov := composeBenchOverrides(m)
			b.Run(fmt.Sprintf("feed=%d/overrides=%d/impl=legacy", f, m), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = legacyComposeView(feed, ov)
				}
			})
			b.Run(fmt.Sprintf("feed=%d/overrides=%d/impl=current", f, m), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = ComposeView(feed, ov)
				}
			})
		}
	}
}

// BenchmarkComposeAB_AllCovered is the adverse row kept honest and in view: a
// SINGLE tombstone that covers every feed host. The old scan hit on its first
// and only key (one memcmp); covers() hashes the full host, misses, then walks
// one label and hits. Two map probes cost more than one memcmp, so this posture
// one label and hits. That was measurably SLOWER (+11.7%) until covers() gained
// its maxLen bound, which now skips hashing the full host — a candidate longer
// than every key cannot match one — leaving this posture 5% FASTER than the scan.
// It stays in the suite as the adverse shape most likely to regress.
func BenchmarkComposeAB_AllCovered(b *testing.B) {
	const f = 10000
	feed := make(map[string]string, f)
	for i := 0; i < f; i++ {
		feed[fmt.Sprintf("host%d.covered.example", i)] = "Social Media"
	}
	ov := Overrides{Tombstones: []string{"covered.example"}}
	b.Run("impl=legacy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = legacyComposeView(feed, ov)
		}
	})
	b.Run("impl=current", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = ComposeView(feed, ov)
		}
	})
}

// BenchmarkComposeAB_LongKeys is the ALLOCATION row, and it is the one that shows
// why the old form's cost was not only time.
//
// `strings.HasSuffix(host, "."+key)` concatenates per (host, key) pair. Go stack-
// allocates a concat whose result fits a 32-byte temporary buffer, so SHORT
// override keys hid the cost entirely and allocs/op looked flat. A realistic
// enterprise override key — a tenant subdomain under a customer domain — exceeds
// 31 bytes, the temporary escapes to the heap, and the old form sheds one string
// per (feed host x override key): F x M transient allocations for a single
// composition. The current form does not concatenate at all.
func BenchmarkComposeAB_LongKeys(b *testing.B) {
	const f = 5000
	feed := composeBenchFeed(f)
	for _, keyLen := range []string{"short", "long"} {
		ov := Overrides{}
		for i := 0; i < 64; i++ {
			if keyLen == "short" {
				ov.Tombstones = append(ov.Tombstones, fmt.Sprintf("t%d.ex.example", i))
			} else {
				ov.Tombstones = append(ov.Tombstones,
					fmt.Sprintf("tomb%d.some-long-subdomain.customer-tenant-name.example.com", i))
			}
		}
		b.Run(fmt.Sprintf("keys=%s/impl=legacy", keyLen), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = legacyComposeView(feed, ov)
			}
		})
		b.Run(fmt.Sprintf("keys=%s/impl=current", keyLen), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ComposeView(feed, ov)
			}
		})
	}
}
