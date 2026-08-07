package alerts

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// CHAOS-27 regression gates for the alert delivery plane under an alert storm.
//
// Two independent failure modes, both reachable from attacker-controlled
// traffic volume (the `threat_detected` / `policy_block` producers fire with
// the request's host in Detail, so a scanning flood produces a flood of
// UNIQUE dedup keys that the Q17 window cannot suppress):
//
//  1. Socket accumulation — deliverAttempt built a fresh http.Transport per
//     attempt. Its idle keep-alive connection outlived the attempt in an
//     abandoned pool with a zero-value IdleConnTimeout (= never expires), so
//     every delivery cost one permanently-held FD + its two persistConn
//     goroutines. The P4 semaphore bounds CONCURRENT deliveries, not
//     CUMULATIVE sockets.
//  2. Dedup bookkeeping — dedupMap was unbounded and fully rescanned under a
//     process-wide mutex on every Dispatch.

// connCounter counts distinct TCP connections a test server accepts.
type connCounter struct {
	mu   sync.Mutex
	seen int
}

func (c *connCounter) hook(_ net.Conn, state http.ConnState) {
	if state == http.StateNew {
		c.mu.Lock()
		c.seen++
		c.mu.Unlock()
	}
}

func (c *connCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen
}

// swapDeliveryClientForTest points the process-wide delivery client at a
// loopback-capable dialer and returns the restore func (the swapAutoExclude
// idiom: isolate the global for the duration of one test).
//
// The substitution is only the DIAL: ssrf.SafeDialContext correctly refuses
// the loopback address an httptest.Server listens on, so a test cannot use
// the production dialer. The client is still built by the production
// constructor, so the pooling configuration under test — the thing this gate
// exists to pin — is production's.
//
// No test in this package calls t.Parallel, so the swap is safe.
func swapDeliveryClientForTest() func() {
	restore := deliveryClient
	deliveryClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: newDeliveryTransport((&net.Dialer{Timeout: 5 * time.Second}).DialContext),
	}
	return func() { deliveryClient = restore }
}

// TestChaos27_DeliveryReusesConnections pins that N sequential deliveries to
// the same webhook endpoint do not open N sockets. Against the pre-fix code
// (a new http.Transport per attempt) this observes one connection per
// delivery — the FD leak, reproduced deterministically.
func TestChaos27_DeliveryReusesConnections(t *testing.T) {
	var cc connCounter
	// Unstarted: Config.ConnState has to be installed before Serve reads it,
	// or the hook assignment races the accept loop.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Config.ConnState = cc.hook
	srv.Start()
	defer srv.Close()

	defer swapDeliveryClientForTest()()

	as := &Store{}
	h := Webhook{ID: "w1", Name: "sink", URL: srv.URL, Events: []string{"*"}, Enabled: true}

	const deliveries = 8
	for i := 0; i < deliveries; i++ {
		if ok := as.Deliver(h, Payload{Event: "policy_block", Detail: fmt.Sprintf("host-%d", i)}); !ok {
			t.Fatalf("delivery %d failed", i)
		}
	}

	if got := cc.count(); got > 2 {
		t.Fatalf("alert delivery opened %d connections for %d sequential deliveries — "+
			"each attempt is leaking a keep-alive socket (want connection reuse, ≤2)", got, deliveries)
	}
}

// TestChaos27_DedupMapIsBounded pins that a flood of UNIQUE dedup keys (the
// scanning-flood shape) cannot grow the dedup map without bound.
func TestChaos27_DedupMapIsBounded(t *testing.T) {
	as := &Store{}
	const floods = maxDedupEntries * 3
	for i := 0; i < floods; i++ {
		as.dedupSuppressed(fmt.Sprintf("policy_block:scan-host-%d.example", i))
	}

	as.dedupMu.Lock()
	size := len(as.dedupMap)
	as.dedupMu.Unlock()

	if size > maxDedupEntries {
		t.Fatalf("dedup map grew to %d entries from %d unique attacker-supplied details "+
			"(cap %d) — unbounded memory growth on the alert path", size, floods, maxDedupEntries)
	}
	if DedupEvictionsTotal() == 0 {
		t.Fatal("dedup map was capped but the eviction counter stayed at 0 — the loss is invisible to operators")
	}
}

// TestChaos27_DedupPruneIsAmortised pins the CPU half of the finding. Capping
// the map fixes memory but not cost: the pre-fix code ran an O(len) expiry
// scan on EVERY dispatch while holding the process-wide dedup mutex, so a
// flood paid a full scan per alert with every other producer blocked behind
// the lock. Only the scan count distinguishes the two, which is why the Store
// tracks it.
func TestChaos27_DedupPruneIsAmortised(t *testing.T) {
	as := &Store{}
	const inserts = maxDedupEntries * 3
	for i := 0; i < inserts; i++ {
		as.dedupSuppressed(fmt.Sprintf("policy_block:scan-host-%d.example", i))
	}

	as.dedupMu.Lock()
	runs := as.dedupPruneRuns
	as.dedupMu.Unlock()

	if maxRuns := inserts/dedupPruneEvery + 1; runs > maxRuns {
		t.Fatalf("expiry scan ran %d times for %d inserts (amortised budget %d) — "+
			"the O(len) scan is back on the per-dispatch path", runs, inserts, maxRuns)
	}
}

// BenchmarkDedupSuppressedUnderFlood measures the per-alert cost of the dedup
// bookkeeping with the map already at its cap — the sustained-flood steady
// state.
func BenchmarkDedupSuppressedUnderFlood(b *testing.B) {
	as := &Store{}
	for i := 0; i < maxDedupEntries; i++ {
		as.dedupSuppressed(fmt.Sprintf("policy_block:warm-%d.example", i))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		as.dedupSuppressed(fmt.Sprintf("policy_block:flood-%d.example", i))
	}
}

// TestChaos27_QuietPeriodCountsNoPhantomEvictions covers the case where the
// count-based prune schedule and the time-based expiry disagree (Codex review
// on PR #1078).
//
// A flood fills the map to the cap and then stops. Entries expire with TIME,
// but the prune is triggered by INSERTS — and a quiet period has none. So the
// map sits full of entirely stale keys, and the next insert finds itself over
// cap and charges an eviction: a phantom saturation signal, on a monotonic
// counter that drives a sticky "degraded" state in the admin UI. It can also
// evict the key just inserted, letting an immediate duplicate through.
//
// Nothing is saturated here. Every entry is dead.
func TestChaos27_QuietPeriodCountsNoPhantomEvictions(t *testing.T) {
	as := &Store{}
	for i := 0; i < maxDedupEntries; i++ {
		as.dedupSuppressed(fmt.Sprintf("policy_block:flood-%d.example", i))
	}

	// The flood ends and the window passes with no traffic. Real elapsed time
	// ages the prune stamp exactly as it ages the entries, so the test moves
	// both — advancing only the entries would model a clock that stopped.
	as.dedupMu.Lock()
	stale := time.Now().Add(-2 * dedupTTL)
	for k := range as.dedupMap {
		as.dedupMap[k] = stale
	}
	as.dedupLastPrune = stale
	as.dedupMu.Unlock()

	before := DedupEvictionsTotal()
	if as.dedupSuppressed("cert_expiry:ca") {
		t.Fatal("a fresh key was reported as a duplicate")
	}

	if got := DedupEvictionsTotal() - before; got != 0 {
		t.Fatalf("charged %d eviction(s) against a map holding only EXPIRED keys — "+
			"a quiet period after a flood fabricates a permanent saturation warning", got)
	}
	as.dedupMu.Lock()
	size := len(as.dedupMap)
	_, kept := as.dedupMap["cert_expiry:ca"]
	as.dedupMu.Unlock()
	if !kept {
		t.Fatal("the just-inserted key was evicted, so its immediate duplicate would deliver again")
	}
	if size > 1 {
		t.Fatalf("map still holds %d entries after every key expired — stale keys are not being reclaimed", size)
	}
}

// TestChaos27_DedupStillSuppressesDuplicates proves the bound did not break
// the Q17 contract it guards: an identical event+detail inside the window is
// still suppressed, and a distinct one is not.
func TestChaos27_DedupStillSuppressesDuplicates(t *testing.T) {
	as := &Store{}
	if as.dedupSuppressed("policy_block:evil.example") {
		t.Fatal("first fire of a key was suppressed")
	}
	if !as.dedupSuppressed("policy_block:evil.example") {
		t.Fatal("duplicate inside the dedup window was NOT suppressed")
	}
	if as.dedupSuppressed("policy_block:other.example") {
		t.Fatal("a distinct detail was suppressed")
	}
}

// TestChaos27_DedupPrunesExpiredEntries proves the amortised prune still
// expires stale keys, so a key that fired longer ago than dedupTTL delivers
// again rather than being silenced forever.
func TestChaos27_DedupPrunesExpiredEntries(t *testing.T) {
	as := &Store{}
	as.dedupSuppressed("cert_expiry:ca")

	as.dedupMu.Lock()
	as.dedupMap["cert_expiry:ca"] = time.Now().Add(-2 * dedupTTL)
	as.dedupMu.Unlock()

	if as.dedupSuppressed("cert_expiry:ca") {
		t.Fatal("an entry older than dedupTTL still suppressed its alert — alerts silenced permanently")
	}
}
