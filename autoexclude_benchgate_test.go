//go:build benchgate

package main

// Deterministic allocation-regression gate for the adaptive decryption-exclusion
// hot path (resolveSSLAction runs on EVERY CONNECT). Pairs with the existing
// benchgate family (bench_regression_test.go): allocs/op are hardware-independent,
// so this is a hard cross-runner gate, unlike ns/op.
//
//	go test -tags benchgate -run 'TestBenchGate_AutoExclude' -v .

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// TestBenchGate_AutoExcludeResolveAllocs locks the two production-confidence
// guarantees the qualification report proved by measurement:
//
//  1. FEATURE-OFF IS ZERO-COST. A rule with no decryption profile never reaches
//     the cache, and — critically — a FAIL-CLOSE profile takes the FailOpenScope
//     gate but must add NO allocation over the feature-unused path (the gate is a
//     lowercase+trim+map-lookup returning ok=false; strings.ToLower has a no-map
//     fast path). This is the "un-poisonable AND near-free" contract: critical
//     hosts kept on fail-close rules pay nothing. Asserted RELATIVELY
//     (failClose <= featureUnused) so it holds regardless of the sslBypass
//     baseline allocation count.
//
//  2. THE FAIL-OPEN READ PATH STAYS O(1)-ALLOCATION. Miss and hit are small
//     constants independent of cache size; a regression that adds a per-CONNECT
//     allocation (e.g. a new map alloc, or losing the string-key fast path) blows
//     the constant bounds. Bounds carry headroom over the measured baseline
//     (miss 5, hit 9 allocs/op) so runtime noise never flakes the gate while an
//     O(n) or per-request-alloc regression fails immediately.
func TestBenchGate_AutoExcludeResolveAllocs(t *testing.T) {
	// Silence the logger: the fail-open HIT path emits SSL_AUTOEXCLUDE_BYPASS every
	// iteration. Without this the gate does real stderr I/O and dumps thousands of
	// log lines (CI-log/timeout noise), matching BenchmarkResolveSSLAction_FailOpenHit.
	// The sanitizeLog string allocations still occur before the discarded write, so
	// the measured allocs/op are unchanged — only the I/O flood is removed.
	defer benchSilenceLogger()()
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)

	unused := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "r", SSLAction: SSLInspect}}
	fc, _ := bindFailOpenProfile(t, "fc", "fail-close")
	fo, foScope := bindFailOpenProfile(t, "fo", "fail-open")
	// Seed one active exclusion so the hit path is exercised.
	autoExclude().Observe(foScope, "fo", "hit.example", autoexclude.ReasonUnsupportedParams, "id:u1")
	if _, ok := autoExclude().Contains(foScope, "hit.example"); !ok {
		t.Fatal("precondition: hit.example must be excluded under fo scope")
	}

	measure := func(m *PolicyMatch, host string) int64 {
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = resolveSSLAction(m, host, "203.0.113.7")
			}
		})
		return res.AllocsPerOp()
	}

	featureUnused := measure(unused, "example.com")
	failClose := measure(fc, "example.com")
	failOpenMiss := measure(fo, "miss.example")
	failOpenHit := measure(fo, "hit.example")

	t.Logf("allocs/op — featureUnused=%d failClose=%d failOpenMiss=%d failOpenHit=%d",
		featureUnused, failClose, failOpenMiss, failOpenHit)

	// (1) Fail-close must add NO allocation over feature-unused — the gate is free.
	if failClose > featureUnused {
		t.Errorf("REGRESSION: fail-close path allocates %d/op vs feature-unused %d/op — the "+
			"FailOpenScope gate is no longer allocation-free (a critical-host / un-poisonable "+
			"path must stay zero-cost). See roadmap/AUTOEXCLUDE-PRODUCTION-QUALIFICATION.md §Perf.",
			failClose, featureUnused)
	}

	// (2) The fail-open read path stays a small constant (headroom over baseline 5/9).
	const (
		maxUnused = 4  // baseline 2 (sslBypass normalize + client-IP parse)
		maxMiss   = 7  // baseline 5
		maxHit    = 12 // baseline 9 (adds the SSL_AUTOEXCLUDE_BYPASS log fields)
	)
	if featureUnused > maxUnused {
		t.Errorf("REGRESSION: feature-unused allocates %d/op, exceeds constant bound %d", featureUnused, maxUnused)
	}
	if failOpenMiss > maxMiss {
		t.Errorf("REGRESSION: fail-open MISS allocates %d/op, exceeds constant bound %d — "+
			"a per-CONNECT allocation entered Contains()", failOpenMiss, maxMiss)
	}
	if failOpenHit > maxHit {
		t.Errorf("REGRESSION: fail-open HIT allocates %d/op, exceeds constant bound %d", failOpenHit, maxHit)
	}
}
