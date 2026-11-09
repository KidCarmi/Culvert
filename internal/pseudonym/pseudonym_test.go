package pseudonym

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

const testKey = "0123456789abcdef0123456789abcdef" // 32 bytes

// benchTokenSink keeps results live so the compiler cannot elide the call under test.
var benchTokenSink string

func swapKey(t *testing.T, p *Pseudonymizer, key []byte) {
	t.Helper()
	prev := p.Key()
	p.Set(key)
	t.Cleanup(func() { p.Set(prev) })
}

// referencePseudonym is the pre-optimization implementation, kept verbatim as the
// oracle. If this and pseudonymizeHost ever disagree, the optimization changed observable
// behavior and must be reverted — not the test relaxed.
func referencePseudonym(key []byte, host string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(hostutil.NormalizeHost(hostutil.StripHostPort(host))))
	return Prefix + hex.EncodeToString(h.Sum(nil))[:12]
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
	p := New()
	for _, key := range [][]byte{[]byte(testKey), []byte("ffffffffffffffffffffffffffffffff")} {
		swapKey(t, p, key)
		for _, host := range pseudonymCorpus {
			want := referencePseudonym(key, host)
			if got := p.Pseudonymize(host); got != want {
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
	p := New()
	keyA := []byte(testKey)
	keyB := []byte("ffffffffffffffffffffffffffffffff")

	swapKey(t, p, keyA)
	for i := 0; i < 64; i++ { // prime the pool with keyA-bound hashers
		p.Pseudonymize("cdn.example.com")
	}
	gotA := p.Pseudonymize("cdn.example.com")

	swapKey(t, p, keyB)
	gotB := p.Pseudonymize("cdn.example.com")

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
	p := New()
	swapKey(t, p, []byte(testKey))
	p.Pseudonymize("cdn.example.com") // prime

	p.Set(nil)
	if got := p.Pseudonymize("cdn.example.com"); got != Sentinel {
		t.Fatalf("cleared key must fail closed to %q, got %q", Sentinel, got)
	}

	swapKey(t, p, []byte(testKey))
	if got, want := p.Pseudonymize("cdn.example.com"), referencePseudonym([]byte(testKey), "cdn.example.com"); got != want {
		t.Fatalf("post-clear token %q != reference %q", got, want)
	}
}

// TestTrafficRedaction_ConcurrentTokensAreStable runs the pooled path from many
// goroutines while the key is held fixed: every goroutine must agree on the token for a
// given host. Run under -race this also covers the pool/scratch-buffer sharing.
func TestTrafficRedaction_ConcurrentTokensAreStable(t *testing.T) {
	p := New()
	swapKey(t, p, []byte(testKey))

	want := make(map[string]string, len(pseudonymCorpus))
	for _, h := range pseudonymCorpus {
		want[h] = referencePseudonym([]byte(testKey), h)
	}

	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				h := pseudonymCorpus[i%len(pseudonymCorpus)]
				if got := p.Pseudonymize(h); got != want[h] {
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
	p := New()
	swapKey(t, p, []byte(testKey))
	t.Cleanup(func() { p.Set([]byte(testKey)) })

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
				if err := p.Rotate(); err != nil {
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
				got := p.Pseudonymize("cdn.example.com")
				if len(got) != len(Prefix)+hexLen {
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
	p := New()
	key := []byte(testKey)
	swapKey(t, p, key)
	p.Pseudonymize("cdn.example.com:443") // prime the pool

	pooled := testing.AllocsPerRun(200, func() {
		benchTokenSink = p.Pseudonymize("cdn.example.com:443")
	})
	reference := testing.AllocsPerRun(200, func() {
		benchTokenSink = referencePseudonym(key, "cdn.example.com:443")
	})
	if ceiling := reference * pseudonymizeHostAllocBudget; pooled > ceiling {
		t.Fatalf("pseudonymizeHost allocated %.0f/op vs %.0f/op for the unpooled reference (ceiling %.1f) — the pooled HMAC is no longer being reused",
			pooled, reference, ceiling)
	}
}

func TestPseudonymizer_FailClosedAndEmpty(t *testing.T) {
	p := New()
	if got := p.Pseudonymize("secret.example.com"); got != Sentinel {
		t.Fatalf("no key: got %q want sentinel", got)
	}
	if got := p.Pseudonymize(""); got != "" {
		t.Fatalf("empty host must stay empty, got %q", got)
	}
	if p.KeyID() != "" || p.Key() != nil {
		t.Fatal("fresh instance must have no key or id")
	}
}

func TestPseudonymizer_InstancesAreIndependent(t *testing.T) {
	a, b := New(), New()
	a.Set([]byte(testKey))
	if b.Key() != nil || b.Pseudonymize("x.example.com") != Sentinel {
		t.Fatal("key leaked across instances")
	}
	b.Set([]byte("ffffffffffffffffffffffffffffffff"))
	if a.Pseudonymize("x.example.com") == b.Pseudonymize("x.example.com") {
		t.Fatal("instances with different keys must differ")
	}
}

func TestPseudonymizer_SetPairKeepsIDAndCopiesKey(t *testing.T) {
	p := New()
	k := []byte(testKey)
	p.SetPair(k, "abc123")
	k[0] = 'X' // caller mutation must not alias
	if p.KeyID() != "abc123" || string(p.Key()) != testKey {
		t.Fatalf("pair not preserved: id=%q key=%q", p.KeyID(), p.Key())
	}
	id := p.KeyID()
	if err := p.Rotate(); err != nil {
		t.Fatal(err)
	}
	if p.KeyID() == id || len(p.Key()) != KeyLen {
		t.Fatal("rotation must mint a new id and a full-length key")
	}
}

func TestPseudonymizer_EnsureIsIdempotent(t *testing.T) {
	p := New()
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	id := p.KeyID()
	if err := p.Ensure(); err != nil || p.KeyID() != id {
		t.Fatal("Ensure must not replace an existing full-length key")
	}
}

func TestReplaceHostFold_WholeHostOnly(t *testing.T) {
	if got := ReplaceHostFold("ex.com/a/complex.com/EX.COM", "ex.com", "T"); got != "T/a/complex.com/T" {
		t.Fatalf("got %q", got)
	}
	if got := ReplaceHostFold("example.com.evil", "example.com", "T"); got != "example.com.evil" {
		t.Fatalf("prefix of longer host rewritten: %q", got)
	}
	if got := ReplaceHostFold("abc", "", "T"); got != "abc" {
		t.Fatalf("empty host must be a no-op, got %q", got)
	}
}
