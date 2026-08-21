package main

// store_alertgate_bench_test.go — evidence for the per-request alert-producer
// gate (recordStats block path + fireDNSFailureAlert).
//
// Measured on linux/amd64, Intel Xeon @ 2.80GHz, go1.26, -benchtime=200000x,
// with NO webhooks configured (the default posture and the state of every test
// binary):
//
//	                          BEFORE (ungated)        AFTER (gated)
//	Block                     2884 ns/op  2 allocs    101 ns/op  0 allocs
//	Block-8                    752 ns/op  3 allocs    101 ns/op  0 allocs
//	BlockParallel             3106 ns/op  2 allocs    117 ns/op  0 allocs
//	BlockParallel-8           2247 ns/op  3 allocs    221 ns/op  0 allocs
//	BlockDistinctDetail       2269 ns/op  2 allocs    104 ns/op  0 allocs
//	BlockDistinctDetail-8     1118 ns/op  3 allocs    108 ns/op  0 allocs
//
// The headline is not the multiplier, it is the SHAPE: before the gate a
// blocked request cost 5-20x an allowed request and allocated; after it, the
// block path and the allow path cost the same and neither allocates. The
// remaining per-op cost is the stats bookkeeping (statTotal + tsRecordResult),
// which both paths share.
//
// Run:
//
//	go test -run '^$' -bench 'AlertGate' -benchmem -cpu=1,8 .

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// benchNoSubscriber installs an empty alert store — the default posture.
func benchNoSubscriber(b *testing.B) {
	b.Helper()
	orig := globalAlertStore
	b.Cleanup(func() { globalAlertStore = orig })
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as
}

// benchWithSubscriber installs a store with a live subscriber for event, so the
// gate falls through to the real dispatch. This is the anti-regression arm: it
// proves the gate does not make the SUBSCRIBED path slower.
func benchWithSubscriber(b *testing.B, event string) {
	b.Helper()
	// Let the delivery to the loopback test server actually succeed: a FAILED
	// delivery would enqueue a retry, and the retry queue persists to a path
	// this package cannot redirect (internal/alerts.retryFile), which would put
	// a stray disk write inside the measurement.
	b.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b.Cleanup(srv.Close)
	orig := globalAlertStore
	b.Cleanup(func() { globalAlertStore = orig })
	as := &AlertStore{}
	as.Init("")
	as.Add(AlertWebhook{Name: "b", URL: srv.URL, Events: []string{event}, Enabled: true})
	globalAlertStore = as
}

// BenchmarkAlertGate_Block is the headline: a policy-blocked request with
// nobody subscribed. Allocation count is the durable signal here — ns/op is
// hardware-sensitive, but "0 allocs/op" is deterministic and is what
// TestBenchGate_BlockPathAlertAllocs pins.
func BenchmarkAlertGate_Block(b *testing.B) {
	benchNoSubscriber(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordStats("203.0.113.7", "target.example.com", "POLICY_BLOCK", "deny-rule", "block")
	}
}

// BenchmarkAlertGate_Allow is the reference point. The gate's goal is for
// BenchmarkAlertGate_Block to match this; before the change it was 5-20x worse.
func BenchmarkAlertGate_Allow(b *testing.B) {
	benchNoSubscriber(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordStats("203.0.113.7", "target.example.com", "OK", "allow-rule", "allow")
	}
}

// BenchmarkAlertGate_BlockParallel is the concurrency arm. The ungated path
// serialized every blocked request on the single global dedup mutex (after
// paying a goroutine spawn); this measures whether the gate removed that
// contention rather than just moving it.
func BenchmarkAlertGate_BlockParallel(b *testing.B) {
	benchNoSubscriber(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			recordStats("203.0.113.7", "target.example.com", "POLICY_BLOCK", "deny-rule", "block")
		}
	})
}

// BenchmarkAlertGate_BlockDistinctDetail is the stress arm. A flood of blocks
// with VARYING detail (a scanner sweeping hosts across many rules) defeats the
// 30s dedup window, so the ungated path took the exclusive dedup mutex, wrote
// the map, ran a full O(n) prune, and copied the whole webhook slice — per
// request. This is the worst realistic case, and the one an attacker controls.
func BenchmarkAlertGate_BlockDistinctDetail(b *testing.B) {
	benchNoSubscriber(b)
	details := make([]string, 512)
	for i := range details {
		details[i] = "rule-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordStats("203.0.113.7", "target.example.com", "POLICY_BLOCK", details[i%len(details)], "block")
	}
}

// BenchmarkAlertGate_BlockWithSubscriber is the anti-regression arm: when a
// webhook IS listening the gate is one extra RLock+scan on top of work that was
// already happening, and the dispatch is byte-identical. Deliveries are
// dedup-suppressed after the first, so this measures the steady-state
// subscribed path rather than webhook I/O.
func BenchmarkAlertGate_BlockWithSubscriber(b *testing.B) {
	benchWithSubscriber(b, "policy_block")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recordStats("203.0.113.7", "target.example.com", "POLICY_BLOCK", "deny-rule", "block")
	}
}

// BenchmarkAlertGate_DNSFailure covers the second producer class. Its rate is
// set by the environment (a resolver brownout, DGA beaconing), not by the
// operator, so the ungated version spawned a goroutine and formatted
// err.Error() per failed request.
func BenchmarkAlertGate_DNSFailure(b *testing.B) {
	benchNoSubscriber(b)
	err := errTestDNS{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fireDNSFailureAlert("dns-fail.example.com", err)
	}
}

// BenchmarkAlertGate_DNSFailureParallel mirrors a resolver outage across cores.
func BenchmarkAlertGate_DNSFailureParallel(b *testing.B) {
	benchNoSubscriber(b)
	err := errTestDNS{}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			fireDNSFailureAlert("dns-fail.example.com", err)
		}
	})
}
