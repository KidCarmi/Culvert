package urlcat

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Before/after benchmarks for the FORWARD index read view (Store.catIndex).
//
// Both arms are measured in ONE run, because that is the only form of this
// comparison that survives the machine it ran on. urlcat's own categoryKey
// note records why: an earlier CROSS-RUN reading of a question in this same
// file was "wrong by an order of magnitude" because the arms were measured
// minutes apart and the box drifted in between. Quote the RATIO and the
// SCALING, never the absolutes.
//
// What to read: not ns/op at one core, but how ns/op MOVES with core count.
//
//	go test -run '^$' -bench 'MatchesHostView' -benchmem -cpu 1,2,4 -count=5 ./internal/urlcat/
//
// Measured on a 4-core Intel Xeon @2.10GHz, go1.26.8 (medians of n=5):
//
//	                    GOMAXPROCS=1   =2       =4      1→4 scaling
//	  Legacy (s.mu)     108.8 ns       150.0    142.9   0.76x  (cores SUBTRACT)
//	  View (lock-free)  111.9 ns        57.0     29.2   3.84x
//
// i.e. parity serially and 4.9x at four cores, 0 allocs/op throughout. The
// serial parity is the honest part: an atomic.Pointer load replaces an
// UNCONTENDED RLock/RUnlock pair, which is roughly a wash — the whole gain is
// in not writing one shared cache line from every core at once.

// legacyMatchesHost is the VERBATIM pre-view body of Store.MatchesHost, kept
// so the comparison above stays reproducible in-tree rather than being a pair
// of numbers in a commit message. It is the benchmark baseline ONLY and is
// never reachable from production code.
//
// It is also the oracle for TestCatIndexViewDifferential_MatchesLegacyVerdict:
// this change must be a pure COST change, and a membership matcher that
// disagrees with the code it replaced is a silently mis-enforced policy rule.
func legacyMatchesHost(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.index[string(inlineKey)]
	} else {
		hostSet = s.index[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// legacyMatchesHostAdmin is the VERBATIM pre-view body of MatchesHostAdmin.
func legacyMatchesHostAdmin(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.adminIndex[string(inlineKey)]
	} else {
		hostSet = s.adminIndex[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

func BenchmarkMatchesHostView_Legacy(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Per-worker sink: a shared package-level one turns false sharing into
		// the thing being measured (the trap recorded on internal/blocklist's
		// hot-read benchmarks).
		var sink bool
		for pb.Next() {
			sink = legacyMatchesHost(s, cat, host)
		}
		_ = sink
	})
}

func BenchmarkMatchesHostView_Current(b *testing.B) {
	s := benchMatchStore()
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			sink = s.MatchesHost(cat, host)
		}
		_ = sink
	})
}

// BenchmarkMatchesHostView_RuleScanLegacy / _RuleScanCurrent model the real
// shape of the cost: a rulebase of N category-scoped access rules resolves N
// memberships for ONE request, so the per-request read-lock traffic is N
// acquisitions, not one. This is the arm that shows what a gateway pays.
func BenchmarkMatchesHostView_RuleScanLegacy(b *testing.B)  { benchRuleScan(b, true) }
func BenchmarkMatchesHostView_RuleScanCurrent(b *testing.B) { benchRuleScan(b, false) }

func benchRuleScan(b *testing.B, legacy bool) {
	s := benchMatchStore()
	// 20 category-scoped rules, i.e. 20 memberships resolved per request.
	cats := make([]Category, 0, 20)
	for _, e := range DefaultEntries() {
		cats = append(cats, Category(e.Name))
		if len(cats) == 20 {
			break
		}
	}
	if len(cats) < 20 {
		b.Skipf("shipped taxonomy has %d categories, need 20", len(cats))
	}
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for pb.Next() {
			for _, c := range cats {
				if legacy {
					sink = legacyMatchesHost(s, c, host)
				} else {
					sink = s.MatchesHost(c, host)
				}
			}
		}
		_ = sink
	})
}
