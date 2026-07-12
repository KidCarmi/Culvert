package main

import (
	"fmt"
	"io"
	"log"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// autoexclude_bench_test.go — CONNECT hot-path benchmarks for the adaptive
// decryption-exclusion cache (Track 2/3 qualification). resolveSSLAction is THE
// per-CONNECT decision function; these measure its cost across the 7 scenarios
// the reviewer asked for, plus concurrency. Run:
//
//	go test -run '^$' -bench 'BenchmarkResolveSSLAction|BenchmarkAutoExcludeConc' -benchmem -benchtime=1s .
//
// The FEATURE-OFF scenarios (Unused, FailClose) must show no material regression
// vs base — the added cost there is a single resolveFailOpen() nil-profile check
// (no lock, no map, no alloc). base/head comparison uses a worktree at origin/main
// (see the qualification report).

// benchSetProfiles installs a profile store for a benchmark and returns a restore.
func benchSetProfiles() func() {
	prev := globalDecryptionProfiles
	globalDecryptionProfiles = decryptprofile.New()
	return func() { globalDecryptionProfiles = prev }
}

func benchSetCache(cfg autoexclude.Config) func() {
	prev := autoExclude
	autoExclude = autoexclude.New(cfg)
	return func() { autoExclude = prev }
}

// benchMatch builds a match referencing a profile with the given fail-open mode
// ("" = no profile at all — the true feature-off path). Returns the match + scope.
func benchMatch(b *testing.B, onInspectError string) (match *PolicyMatch, scopeID string) {
	b.Helper()
	if onInspectError == "" {
		return &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "r", SSLAction: SSLInspect}}, ""
	}
	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "bench", OnInspectError: onInspectError})
	if err != nil {
		b.Fatalf("add profile: %v", err)
	}
	m := &PolicyMatch{Action: ActionAllow, SSLAction: SSLInspect, Rule: &PolicyRule{Name: "r", SSLAction: SSLInspect, DecryptionProfile: "bench"}}
	return m, p.ID
}

// 1. Feature entirely unused — no decryption profile on the rule. This is the
// base/feature-off path; resolveFailOpen returns false at the nil-profile check.
func BenchmarkResolveSSLAction_FeatureUnused(b *testing.B) {
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{})()
	m, _ := benchMatch(b, "")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "example.com", "1.2.3.4")
	}
}

// 2. Fail-close profile — profile present but not fail-open; cache never consulted.
func BenchmarkResolveSSLAction_FailClose(b *testing.B) {
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{})()
	m, _ := benchMatch(b, "fail-close")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "example.com", "1.2.3.4")
	}
}

// 3. Fail-open, empty cache — Contains miss on an empty map.
func BenchmarkResolveSSLAction_FailOpenEmpty(b *testing.B) {
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{})()
	m, _ := benchMatch(b, "fail-open")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "example.com", "1.2.3.4")
	}
}

// 4. Fail-open cache miss — cache holds many OTHER hosts; this host is absent.
func BenchmarkResolveSSLAction_FailOpenMiss(b *testing.B) {
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{ConfirmN: 1})()
	m, scope := benchMatch(b, "fail-open")
	for i := 0; i < 1000; i++ {
		autoExclude.Observe(scope, "bench", fmt.Sprintf("other-%d.example", i), autoexclude.ReasonClientPinned, "id:x")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "absent.example", "1.2.3.4")
	}
}

// 5. Fail-open cache HIT — the host is excluded; bypass path increments the hit
// counter under the mutex.
func BenchmarkResolveSSLAction_FailOpenHit(b *testing.B) {
	defer benchSilenceLogger()()
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{ConfirmN: 1})()
	m, scope := benchMatch(b, "fail-open")
	autoExclude.Observe(scope, "bench", "hit.example", autoexclude.ReasonClientPinned, "id:x")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "hit.example", "1.2.3.4")
	}
}

// 6. Cache at MAX active capacity — miss lookups against a full 4096-entry map.
func BenchmarkResolveSSLAction_MaxActive(b *testing.B) {
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{ConfirmN: 1, MaxEntries: 4096})()
	m, scope := benchMatch(b, "fail-open")
	for i := 0; i < 4096; i++ {
		autoExclude.Observe(scope, "bench", fmt.Sprintf("full-%d.example", i), autoexclude.ReasonClientPinned, "id:x")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "absent.example", "1.2.3.4")
	}
}

// 7. Max PENDING observations — a full pending map; measures Contains (read) cost
// which is unaffected by pending size (separate map), and a learn under pressure.
func BenchmarkResolveSSLAction_MaxPending(b *testing.B) {
	defer benchSetProfiles()()
	defer benchSetCache(autoexclude.Config{ConfirmN: 5, MaxEntries: 4096})()
	m, scope := benchMatch(b, "fail-open")
	for i := 0; i < 4096; i++ {
		autoExclude.Observe(scope, "bench", fmt.Sprintf("pend-%d.example", i), autoexclude.ReasonClientPinned, "id:x") // never promotes
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolveSSLAction(m, "absent.example", "1.2.3.4")
	}
}

// benchSilenceLogger routes logger output to io.Discard for the benchmark so the
// per-hit SSL_AUTOEXCLUDE_BYPASS line doesn't pollute -bench output or skew timing.
func benchSilenceLogger() func() {
	prev := logger
	logger = log.New(io.Discard, "", 0)
	return func() { logger = prev }
}

// BenchmarkAutoExcludeContainsHit measures the single-mutex contention on the HOT
// read path in isolation: parallel Contains hits on ONE (scope,host), each taking
// the mutex and incrementing the hit counter. Worst case for the single-mutex
// design. Run with -cpu=1,10,100 and -mutexprofile to quantify contention.
func BenchmarkAutoExcludeContainsHit(b *testing.B) {
	defer benchSetCache(autoexclude.Config{ConfirmN: 1})()
	autoExclude.Observe("s", "bench", "hot.example", autoexclude.ReasonClientPinned, "id:x")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			autoExclude.Contains("s", "hot.example")
		}
	})
}

// BenchmarkAutoExcludeContainsMiss measures parallel miss lookups against a
// pre-populated cache (misses still take the mutex).
func BenchmarkAutoExcludeContainsMiss(b *testing.B) {
	defer benchSetCache(autoexclude.Config{ConfirmN: 1, MaxEntries: 4096})()
	for i := 0; i < 4096; i++ {
		autoExclude.Observe("s", "bench", fmt.Sprintf("h-%d.example", i), autoexclude.ReasonClientPinned, "id:x")
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			autoExclude.Contains("s", "absent.example")
		}
	})
}

// BenchmarkAutoExcludePollWhileTraffic models the API-poll-while-CONNECT-traffic
// case: a fraction of goroutines call List() (the panel poll) while the rest do
// hot Contains reads. Tests whether List (O(n) copy under lock) stalls the hot path.
func BenchmarkAutoExcludePollWhileTraffic(b *testing.B) {
	defer benchSetCache(autoexclude.Config{ConfirmN: 1, MaxEntries: 4096})()
	for i := 0; i < 512; i++ {
		autoExclude.Observe("s", "bench", fmt.Sprintf("h-%d.example", i), autoexclude.ReasonClientPinned, "id:x")
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var n int
		for pb.Next() {
			n++
			if n%64 == 0 { // ~1.5% poll
				_ = autoExclude.List()
			} else {
				autoExclude.Contains("s", "h-1.example")
			}
		}
	})
}
