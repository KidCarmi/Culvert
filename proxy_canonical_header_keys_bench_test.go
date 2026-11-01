package main

import (
	"context"
	"net/http"
	"testing"
)

// Benchmarks behind the canonical-header-key change (see
// proxy_canonical_header_keys_test.go for the contract and the differential
// oracle, and the hdrRealIP comment block in proxy.go for the numbers).
//
// Each pair times the SAME net/http call on the SAME header map, differing only
// in the SPELLING of the key: the canonical spelling is scanned and returned
// verbatim, while any other spelling copies the key into a []byte, rewrites the
// casing and allocates. Both address the same map slot, so each pair compares
// two BEHAVIOUR-IDENTICAL forms — which is why the gate protecting the tree is
// structural (an AST check) rather than a timing threshold: the direction never
// changes, but the size of the win is allocator- and cache-governed and varies
// by machine.
//
// Keep the NonCanonical halves. They are the baseline that makes the canonical
// numbers mean anything, and after this change they are the only place in the
// tree where the slow spellings are exercised at all.
//
// benchHeaderGet / benchHeaderSet are the helpers the X-Request-ID canonical-key
// work already left in proxy_tracing_bench_test.go; reused here deliberately so
// both generations of this finding are measured by the same instrument.

func BenchmarkCanonKey_RealIPGet_Canonical(b *testing.B)    { benchHeaderGet(b, hdrRealIP) }
func BenchmarkCanonKey_RealIPGet_NonCanonical(b *testing.B) { benchHeaderGet(b, "X-Real-IP") }

func BenchmarkCanonKey_MCPVersionGet_Canonical(b *testing.B) {
	benchHeaderGet(b, "Mcp-Protocol-Version")
}
func BenchmarkCanonKey_MCPVersionGet_NonCanonical(b *testing.B) {
	benchHeaderGet(b, "MCP-Protocol-Version")
}

func BenchmarkCanonKey_DPoPGet_Canonical(b *testing.B)    { benchHeaderGet(b, "Dpop") }
func BenchmarkCanonKey_DPoPGet_NonCanonical(b *testing.B) { benchHeaderGet(b, "DPoP") }

func BenchmarkCanonKey_XSSSet_Canonical(b *testing.B)    { benchHeaderSet(b, "X-Xss-Protection") }
func BenchmarkCanonKey_XSSSet_NonCanonical(b *testing.B) { benchHeaderSet(b, "X-XSS-Protection") }

// Del has no shared helper yet — scrubForwardedHeaders reaches hdrRealIP
// through Del as well as Get, and Del is the cheapest of the three, so the
// constant re-derivation is the largest share of its cost.
func benchHeaderDel(b *testing.B, key string) {
	h := http.Header{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Del(key)
	}
}

func BenchmarkCanonKey_RealIPDel_Canonical(b *testing.B)    { benchHeaderDel(b, hdrRealIP) }
func BenchmarkCanonKey_RealIPDel_NonCanonical(b *testing.B) { benchHeaderDel(b, "X-Real-IP") }

// ── In situ: the real per-request scrub ─────────────────────────────────────
//
// The shipped BenchmarkScrubForwardedHeaders (policy_bench_test.go) builds a
// fresh http.Request and sets three headers INSIDE the timed loop, so it
// reports ~992 B / 12 allocs of net/http request construction and the scrub's
// own cost is lost inside it. These hoist the construction out, which is what
// makes the scrub's own allocation count visible — and it was that visibility,
// on an alloc_objects profile at memprofilerate=1, that showed the
// Header.Get(hdrRealIP) allocating once per forwarded request.
//
// The header set is the COMMON shape: every X-Forwarded-For hop public and
// already canonical, so the scrub takes its documented no-rewrite fast path.
// That is the cheapest real request, and therefore where a CONSTANT
// per-request allocation shows up most plainly.
func benchScrubRequest(b *testing.B, withRealIP bool) {
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://target.example.com/", http.NoBody)
	if err != nil {
		b.Fatalf("new request: %v", err)
	}
	r.Header.Set(hdrForwardedFor, "203.0.113.9, 198.51.100.7")
	if withRealIP {
		r.Header.Set(hdrRealIP, "203.0.113.9")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scrubForwardedHeaders(r)
	}
}

// BenchmarkScrubForwardedHeaders_InSitu is the allocation-free shape: all hops
// public and canonical, no X-Real-IP to delete. Before the canonical-key change
// this reported 16 B / 1 alloc per call, all of it Header.Get(hdrRealIP)
// re-deriving a compile-time constant.
func BenchmarkScrubForwardedHeaders_InSitu(b *testing.B) { benchScrubRequest(b, false) }

// BenchmarkScrubForwardedHeaders_InSituRealIP adds a PUBLIC X-Real-IP, so the
// Get returns a value and parsePublicAddr runs. The hop is public, so no Del
// follows and the scrub still allocates nothing.
func BenchmarkScrubForwardedHeaders_InSituRealIP(b *testing.B) { benchScrubRequest(b, true) }
