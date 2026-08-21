package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// traffic_redaction_bench_test.go — the correctness wall and the performance gate for
// the pooled keyed-HMAC destination pseudonymizer.
//
// pseudonymizeHost sits on the per-request path: with the privacy posture ON it runs
// for every recorded request (top-hosts/alert sink via recordStats, the persistLogEntry
// chokepoint, and dec.host/dec.sni on the inspect path). It previously built a fresh
// hmac.New per call, so each token paid the ipad/opad key schedule and ~11 allocations
// to MAC one short hostname. The hasher is now pooled and key-generation-fenced.
//
// The token is a PERSISTED, correlatable identifier, so the optimization is only
// admissible if the output is byte-identical — TestTrafficRedaction_TokenMatchesReferenceHMAC
// is the load-bearing proof, and the rotation/concurrency tests below prove the pool
// cannot serve a token under a superseded key.

// referencePseudonym is the pre-optimization implementation, kept verbatim as the
// oracle. If this and pseudonymizeHost ever disagree, the optimization changed observable
// behavior and must be reverted — not the test relaxed.
func referencePseudonym(key []byte, host string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(hostutil.NormalizeHost(hostutil.StripHostPort(host))))
	return pseudonymPrefix + hex.EncodeToString(h.Sum(nil))[:12]
}

// pseudonymCorpus spans the shapes the normalizer collapses (case, port, trailing dot,
// IPv6 literal) plus ordinary and long hostnames.
var pseudonymCorpus = []string{
	"cdn.example.com",
	"cdn.example.com:443",
	"CDN.Example.COM",
	"cdn.example.com.",
	"a.b.c.d.e.f.g.h.example.com",
	"192.0.2.10",
	"[2001:db8::1]:8443",
	"xn--bcher-kva.example",
	"single",
	"very-long-subdomain-label-used-to-exercise-the-scratch-buffer.example.com",
}

// TestTrafficRedaction_TokenMatchesReferenceHMAC pins that the pooled hasher produces
// EXACTLY the token the original hmac.New-per-call form produced, for every corpus
// entry and across two different keys.
func TestTrafficRedaction_TokenMatchesReferenceHMAC(t *testing.T) {
	swapDecRedact(t, true)
	for _, key := range [][]byte{[]byte(testTrafficKey), []byte("ffffffffffffffffffffffffffffffff")} {
		swapTrafficKey(t, key)
		for _, host := range pseudonymCorpus {
			want := referencePseudonym(key, host)
			if got := pseudonymizeHost(host); got != want {
				t.Fatalf("host %q: pooled token %q != reference %q", host, got, want)
			}
		}
	}
}

// TestTrafficRedaction_PooledHasherIsKeyFenced is the regression test for the pool's
// one real hazard: a hasher built under key A being reused after a rotation to key B.
// It primes the pool under each key, then rotates and re-checks against the reference
// for the NEW key — a missing generation fence returns the stale-key token here.
func TestTrafficRedaction_PooledHasherIsKeyFenced(t *testing.T) {
	swapDecRedact(t, true)
	keyA := []byte(testTrafficKey)
	keyB := []byte("ffffffffffffffffffffffffffffffff")

	swapTrafficKey(t, keyA)
	for i := 0; i < 64; i++ { // prime the pool with keyA-bound hashers
		pseudonymizeHost("cdn.example.com")
	}
	gotA := pseudonymizeHost("cdn.example.com")

	swapTrafficKey(t, keyB)
	gotB := pseudonymizeHost("cdn.example.com")

	if want := referencePseudonym(keyA, "cdn.example.com"); gotA != want {
		t.Fatalf("keyA token %q != reference %q", gotA, want)
	}
	if want := referencePseudonym(keyB, "cdn.example.com"); gotB != want {
		t.Fatalf("post-rotation token %q != reference %q — pooled hasher served a stale key", gotB, want)
	}
	if gotA == gotB {
		t.Fatal("rotation must change the token")
	}
}

// TestTrafficRedaction_ClearedKeyFailsClosedThenRecovers proves the clear path also
// burns a generation: after clearing (fail-closed sentinel) and re-publishing the SAME
// key bytes, the token must still be the correct keyed token, not a pool artifact.
func TestTrafficRedaction_ClearedKeyFailsClosedThenRecovers(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	pseudonymizeHost("cdn.example.com") // prime

	setTrafficPseudonymKey(nil)
	if got := pseudonymizeHost("cdn.example.com"); got != redactedSentinel {
		t.Fatalf("cleared key must fail closed to %q, got %q", redactedSentinel, got)
	}

	swapTrafficKey(t, []byte(testTrafficKey))
	if got, want := pseudonymizeHost("cdn.example.com"), referencePseudonym([]byte(testTrafficKey), "cdn.example.com"); got != want {
		t.Fatalf("post-clear token %q != reference %q", got, want)
	}
}

// TestTrafficRedaction_ConcurrentTokensAreStable runs the pooled path from many
// goroutines while the key is held fixed: every goroutine must agree on the token for a
// given host. Run under -race this also covers the pool/scratch-buffer sharing.
func TestTrafficRedaction_ConcurrentTokensAreStable(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))

	want := make(map[string]string, len(pseudonymCorpus))
	for _, h := range pseudonymCorpus {
		want[h] = referencePseudonym([]byte(testTrafficKey), h)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				h := pseudonymCorpus[i%len(pseudonymCorpus)]
				if got := pseudonymizeHost(h); got != want[h] {
					select {
					case errs <- fmt.Sprintf("host %q: got %q want %q", h, got, want[h]):
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if msg, ok := <-errs; ok {
		t.Fatalf("concurrent token mismatch: %s", msg)
	}
}

// TestTrafficRedaction_ConcurrentRotationNeverPanics hammers the pooled path while the
// key rotates underneath it. Tokens are intentionally not asserted (a racing rotation
// legitimately yields either key's token); what must hold is that the generation fence
// never pairs a key with the wrong hasher in a way that panics or trips the race
// detector, and that every result keeps the token shape.
func TestTrafficRedaction_ConcurrentRotationNeverPanics(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	t.Cleanup(func() { setTrafficPseudonymKey([]byte(testTrafficKey)) })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := rotateTrafficPseudonymKey(); err != nil {
					return
				}
			}
		}
	}()
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				got := pseudonymizeHost("cdn.example.com")
				if len(got) != len(pseudonymPrefix)+pseudonymHexLen {
					t.Errorf("malformed token under rotation: %q", got)
					return
				}
			}
		}()
	}
	close(stop)
	wg.Wait()
}

// ── Benchmarks ───────────────────────────────────────────────────────────────
//
// Baseline measured on this change's parent commit, INTERLEAVED with the post-change
// run in one sitting (Intel Xeon @2.80GHz, GOMAXPROCS=4, -count=6, medians). Interleaving
// matters: this is a shared vCPU whose absolute ns/op drifts >2x between sittings, so
// before/after figures taken minutes apart are not comparable. The allocation columns are
// the machine-independent signal and the ones the benchgate below actually asserts on.
//
//	                                    before                     after
//	PseudonymizeHost           881 ns  672 B  10 allocs    264 ns  16 B  1 alloc
//	PseudonymizeHostParallel   398 ns  672 B  10 allocs     77 ns  16 B  1 alloc
//	RecordStats/posture_on    1890 ns 1344 B  20 allocs    386 ns  16 B  1 alloc
//	RecordStats/posture_off    112 ns    0 B   0 allocs    112 ns   0 B  0 allocs

func benchTrafficPostureOn(b *testing.B) {
	b.Helper()
	prevKey := getTrafficPseudonymKey()
	prevOn := decRedactHosts()
	setTrafficPseudonymKey([]byte(testTrafficKey))
	setDecRedactHosts(true)
	b.Cleanup(func() { setDecRedactHosts(prevOn); setTrafficPseudonymKey(prevKey) })
}

func BenchmarkPseudonymizeHost(b *testing.B) {
	benchTrafficPostureOn(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTokenSink = pseudonymizeHost("cdn.example.com:443")
	}
}

// BenchmarkPseudonymizeHostParallel is the contention benchmark: the pool must scale
// with cores rather than serialize. This is the shape production sees — many request
// goroutines pseudonymizing concurrently.
//
// The sink is deliberately goroutine-LOCAL inside the timed loop, published once per
// worker afterwards. A shared package-level sink would be both a data race under
// `go test -race -bench` and — worse for a benchmark whose whole job is to measure
// scaling — a shared cache line that every worker writes on every iteration, so it
// would report the cost of false sharing rather than the cost of the pool.
func BenchmarkPseudonymizeHostParallel(b *testing.B) {
	benchTrafficPostureOn(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local string
		for pb.Next() {
			local = pseudonymizeHost("cdn.example.com:443")
		}
		benchTokenSinkParallel.Store(&local) // one synchronized publish per worker
	})
}

// BenchmarkRecordStats measures the full per-request stats fan-out with the posture ON
// vs OFF — the OFF arm is the "feature costs nothing when unused" guarantee, the ON arm
// is what the pooling plus the recordStats de-duplication improve.
func BenchmarkRecordStats(b *testing.B) {
	b.Run("posture_on", func(b *testing.B) {
		benchTrafficPostureOn(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow")
		}
	})
	b.Run("posture_off", func(b *testing.B) {
		prev := decRedactHosts()
		setDecRedactHosts(false)
		b.Cleanup(func() { setDecRedactHosts(prev) })
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow")
		}
	})
}

// benchTokenSink keeps the serial benchmarks' results live so the compiler cannot
// elide the call under test. benchTokenSinkParallel is its concurrency-safe counterpart
// for RunParallel workers — see BenchmarkPseudonymizeHostParallel.
var (
	benchTokenSink         string
	benchTokenSinkParallel atomic.Pointer[string]
)

// ── Benchgate ────────────────────────────────────────────────────────────────

// pseudonymizeHostAllocBudget is the fraction of the UNPOOLED reference's allocations
// that the pooled path is allowed to spend. It is a RATIO, not an absolute count,
// because the race detector inflates the pooled path but not the reference, and CI's
// Fast PR Gate runs the whole suite under -race: an absolute ceiling would have to
// either fail there or be loosened until it no longer caught anything.
//
// Measured ratios (healthy 0.10 plain / 0.30 under -race; a forced rebuild-every-call
// regression measures 0.60) place 0.45 roughly midway between the worst healthy value
// and the regression, so the gate has margin on both sides.
const pseudonymizeHostAllocBudget = 0.45

// TestBenchGate_PseudonymizeHostAllocs fails if the pooled hasher stops being reused —
// a reintroduced hmac.New-per-call, a lost generation fence forcing a rebuild every
// call, or a pool Put that stops happening. It compares against referencePseudonym
// measured in the SAME process, so the assertion holds identically with and without
// race instrumentation. Allocation count is the sensitive, machine-independent signal;
// wall-clock is deliberately not asserted.
func TestBenchGate_PseudonymizeHostAllocs(t *testing.T) {
	swapDecRedact(t, true)
	key := []byte(testTrafficKey)
	swapTrafficKey(t, key)
	pseudonymizeHost("cdn.example.com:443") // prime the pool

	pooled := testing.AllocsPerRun(200, func() {
		benchTokenSink = pseudonymizeHost("cdn.example.com:443")
	})
	reference := testing.AllocsPerRun(200, func() {
		benchTokenSink = referencePseudonym(key, "cdn.example.com:443")
	})
	if ceiling := reference * pseudonymizeHostAllocBudget; pooled > ceiling {
		t.Fatalf("pseudonymizeHost allocated %.0f/op vs %.0f/op for the unpooled reference (ceiling %.1f) — the pooled HMAC is no longer being reused",
			pooled, reference, ceiling)
	}
}

// recordStatsRedactedMaxHMACs pins the de-duplication in recordStats: the alert sink and
// the top-hosts sink share ONE derived pseudonym, so an allowed request must derive the
// token exactly once. Counting is indirect but exact — allocations scale linearly with
// the number of pseudonymizeHost calls, so a second derivation shows up as a step.
func TestBenchGate_RecordStatsDerivesPseudonymOnce(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow") // prime

	one := testing.AllocsPerRun(200, func() {
		benchTokenSink = pseudonymizeHost("cdn.example.com:443")
	})
	stats := testing.AllocsPerRun(200, func() {
		recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow")
	})
	// Two derivations would put recordStats at >= 2x the single-token cost. One
	// derivation plus the fan-out's own bookkeeping stays well under that.
	if stats >= 2*one {
		t.Fatalf("recordStats allocated %.0f/op vs %.0f/op for a single token — the destination pseudonym looks like it is derived twice", stats, one)
	}
}
