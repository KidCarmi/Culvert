package decryptprofile

// decryptprofile_idindex_bench_test.go — the measurement behind the stable-ID
// index (reindexLocked).
//
// WHY THESE READS ARE HOT. The profile store looks like an admin surface, and
// GetByID's O(profiles) walk was reasoned about as one: FailOpenScopeByID
// still carries the original note, "a small admin set, only on the SSL-inspect
// CONNECT path". That premise stopped holding when InspectHTTP2 landed.
// resolveH2StallTimeout (decryptprofile_resolve.go) resolves the matched
// rule's profile PER HTTP/2 STREAM inside h2InspectStream, to read one int —
// and one inspected H2 connection multiplexes many streams, so a page load
// pays the walk tens of times. The per-CONNECT path pays it too, three times
// over: resolveStripALPN once and upstreamInspectTLSConfigForMatch twice
// (resolveInspectSkipVerify + applyProfileUpstreamTLSVersions).
//
// It is the same lesson handleRequest records for CHAOS-69: a cost is a
// property of the POSITION as well as the value. "O(n) over a small admin set"
// was answered for the CONNECT path and never re-asked for the stream path.
//
// MEASURED on an idle 4-core Intel Xeon @2.10GHz, Go 1.27.3, -benchtime=1s
// -count=5, medians. BOTH ARMS WERE TIMED IN THE SAME RUN, against a verbatim
// copy of the replaced walk — a cross-run comparison on a shared runner is not
// a measurement (an earlier pass of these same numbers read ~2x slower purely
// because a full-tree lint was running beside it). `profiles` is the number
// installed in the store:
//
//	benchmark                   profiles │  walk    │  index   │ delta
//	GetByID                            1 │  152 ns  │  120 ns  │ -21%
//	GetByID                            8 │  174 ns  │  121 ns  │ -30%
//	GetByID                           32 │  354 ns  │  120 ns  │ -66%
//	GetByID                          128 │  934 ns  │  116 ns  │ -88%
//	GetByID (parallel, GOMAXPROCS=4)   8 │  168 ns  │  167 ns  │  -1%
//	GetByID (parallel, GOMAXPROCS=4) 128 │  302 ns  │  185 ns  │ -39%
//	FailOpenScopeByID                  1 │ 51.8 ns  │ 26.2 ns  │ -49%
//	FailOpenScopeByID                  8 │ 68.8 ns  │ 27.6 ns  │ -60%
//	FailOpenScopeByID                 32 │  225 ns  │ 24.7 ns  │ -89%
//	FailOpenScopeByID                128 │  741 ns  │ 24.7 ns  │ -97%
//
// The SHAPE is the result, not any single number: after the change the cost is
// FLAT in the profile count, where before it grew at ~5.5 ns per installed
// profile. The absolute nanoseconds are hardware-sensitive and must not be
// quoted as a budget — which is why the gate that protects this is a RATIO
// (decryptprofile_idindex_benchgate_test.go) and not a threshold.
//
// Even at ONE profile the walk lost (152 → 120 ns): ranging a Go map pays
// iterator setup that a single hashed lookup does not. There is no store size
// at which the walk was the better shape.
//
// State the parallel row honestly: at 8 profiles it is a wash. The walk is
// short enough there that the RLock pair dominates, and the index does not
// touch the locking. The win appears once the walk is long enough to widen the
// window it holds the read lock open — which is also when it starts delaying
// the writer (an admin edit, a CP→DP install) queued behind it.
//
// WHAT IT COSTS. Every mutation rebuilds the index, which on the bulk-install
// path (BenchmarkReplaceAll_Reindex) is 376 ns of 6.5 µs at 8 profiles, 6.2 µs
// of 101 µs at 128, and 58 µs of 825 µs at 1000 — ~6-7% of an in-memory
// rebuild that a real install then follows with a JSON marshal and an fsync,
// so the deployed share is smaller still. Reads outnumber installs by many
// orders of magnitude on a gateway.
//
// WHAT IS NOT FIXED HERE, deliberately (one concern per change). GetByID still
// costs 177 B and 2 allocs/op — copyOut's defensive full-struct copy plus the
// deep-copied InspectHTTP2 *bool — and that is now the whole of its remaining
// ~118 ns, paid per H2 stream to read one int field. FailOpenScopeByID shows
// what removing it is worth: it is the no-copy accessor of the same lookup and
// lands at ~25 ns, 0 allocs. The fix is a no-copy accessor for the stall
// timeout on the same pattern; it is a separate change with its own
// before/after, not a rider on this one.

import (
	"fmt"
	"testing"
)

// benchIDStore installs n profiles and returns the store plus an id to resolve.
// The id is the LAST installed: the replaced walk ranged a Go map, whose order
// is randomized per range, so no choice of id is "the worst case" — every
// lookup drew uniformly from the whole store. The last id keeps the seed
// deterministic without pretending to pick an adversarial position.
func benchIDStore(n int) (store *Store, id string) {
	store = New()
	ps := make([]Profile, 0, n)
	for i := 0; i < n; i++ {
		h2 := true
		ps = append(ps, Profile{
			ID:               fmt.Sprintf("id-%09d", i),
			Name:             fmt.Sprintf("profile-%04d", i),
			InspectHTTP2:     &h2,
			CertVerification: "strict",
			OnInspectError:   "fail-open",
			MinTLSVersion:    "1.2",
			StallTimeoutSecs: 30,
		})
	}
	store.ReplaceAll(ps)
	return store, fmt.Sprintf("id-%09d", n-1)
}

// benchProfileCounts spans a realistic deployment (1–8 profiles) and the
// enterprise tail. 128 is below the 200-label cap that
// decryptprofile_resolve.go's profileRejectCounter sizes for, so it is inside
// the range an operator can actually configure, not a strawman.
var benchProfileCounts = []int{1, 8, 32, 128}

// BenchmarkGetByID is the per-H2-stream resolve (resolveH2StallTimeout →
// resolveDecryptionProfile → GetByID). Allocation is reported because the
// copy, not the lookup, is what remains after this change.
func BenchmarkGetByID(b *testing.B) {
	for _, n := range benchProfileCounts {
		s, id := benchIDStore(n)
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if p := s.GetByID(id); p == nil {
					b.Fatal("resolve missed: the benchmark would be timing a no-op")
				}
			}
		})
	}
}

// BenchmarkGetByIDParallel is the contention shape. Proxy requests resolve
// concurrently, and the read lock is process-wide, so the serial number alone
// would understate what a gateway pays: the walk holds the RLock for its whole
// duration, so a longer walk widens the window in which a writer (an admin
// edit, a CP→DP install) is blocked and other readers queue behind it.
func BenchmarkGetByIDParallel(b *testing.B) {
	for _, n := range benchProfileCounts {
		s, id := benchIDStore(n)
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if p := s.GetByID(id); p == nil {
						b.Fatal("resolve missed")
					}
				}
			})
		})
	}
}

// BenchmarkFailOpenScopeByID is the per-CONNECT autoexclude scope read. It
// shares the lookup with GetByID but returns no copy, so it isolates the
// lookup cost from the copy cost — the two halves the table at the top of this
// file reports separately.
func BenchmarkFailOpenScopeByID(b *testing.B) {
	for _, n := range benchProfileCounts {
		s, id := benchIDStore(n)
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, ok := s.FailOpenScopeByID(id); !ok {
					b.Fatal("resolve missed")
				}
			}
		})
	}
}

// BenchmarkReplaceAll_Reindex measures what the index COSTS, on the only path
// that pays for it: the bulk install (disk Load, config import, config-version
// rollback, CP→DP snapshot apply). The rebuild is one extra O(profiles) pass
// inside a write-locked section that was already building two maps and is
// followed by a JSON marshal and an fsync, so it should disappear into the
// noise — this benchmark is here so that claim stays checkable rather than
// asserted.
func BenchmarkReplaceAll_Reindex(b *testing.B) {
	for _, n := range []int{8, 128, 1000} {
		ps := make([]Profile, 0, n)
		for i := 0; i < n; i++ {
			ps = append(ps, Profile{
				ID:   fmt.Sprintf("id-%09d", i),
				Name: fmt.Sprintf("profile-%04d", i),
			})
		}
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			s := New()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s.ReplaceAll(ps)
			}
		})
	}
}
