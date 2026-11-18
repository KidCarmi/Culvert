package alerts

// dedup_alloc_bench_test.go — the regression gate for the SUPPRESSED dispatch
// path's allocation and contention shape (Store.Dispatch / dedupSuppressed).
//
// WHAT THIS MEASURES
//
// Suppression is the COMMON answer on this path, not the rare one. Every
// producer that reaches Dispatch at request rate is fault-driven — a policy
// block flood, a resolver outage, a scanner outage — and those producers put a
// LOW-cardinality value in Detail (a rule name, a bounded reason class), so a
// flood against one rule collapses onto ONE dedup key that the 30 s window
// suppresses by construction. The interesting cost of Dispatch is therefore the
// cost of discovering it has nothing to do.
//
// Measured (4-core Xeon @ 2.10 GHz, Go 1.27.4, n=5 medians, ns/op, RunParallel so
// ns/op is wall time per op across all workers; BOTH shapes compiled into the
// SAME binary so the A/B is re-runnable rather than a frozen number — the
// `_Legacy` variants below keep the pre-change implementation alive as the
// negative control, exactly as hasSubscriberScan does in subscriptions_test.go):
//
//	case                       impl      P=1     P=2     P=4   allocs
//	Dispatch, suppressed       legacy  240.5   286.1   360.0   2 / 56 B
//	                           now      91.3   131.0   217.0   0
//	dedup check alone          legacy  116.3   151.3   266.2   1 / 32 B
//	                           now      93.0   131.4   195.4   0
//
// 2.6x at P=1, 2.2x at P=2, 1.7x at P=4, and the allocation rate of the whole
// suppressed path goes to ZERO — which is the part that matters most, because
// these dispatches run on detached goroutines whose only lasting cost is the
// garbage they leave for the collector to mark.
//
// Two independent costs are removed and they are NOT the same kind of thing:
//
//   - The timestamp. payload.Timestamp was defaulted BEFORE the dedup gate, so
//     a dispatch that was about to be dropped still paid ~121 ns and one 24-byte
//     allocation to format an RFC3339 stamp nothing would ever read. Pure waste;
//     scales fine, but it is waste on the one path where the node is already
//     degraded.
//   - The dedup key. The caller handed dedupSuppressed `event + ":" + Detail`,
//     a 32-byte heap allocation built only to be LOOKED UP. Rendering it into a
//     frame-local scratch lets the read go through `map[string(key)]`, which the
//     compiler hashes in place, so the suppressed answer is allocation-free.
//
// What is NOT fixed here, and is visible in the numbers above: the dedup MUTEX
// still does not scale (195.4 ns at P=4 against 93.0 ns at P=1 — four cores
// deliver under half of one core's throughput). That is the same shape subscriptions.go
// records, one layer deeper. It is left alone deliberately: unlike HasSubscriber
// this runs on a DETACHED goroutine, not the request goroutine, so it costs CPU
// and scheduler pressure rather than request latency, and the only ways to remove
// it are a lock-free rewrite or sharding — and sharding buys nothing in the exact
// case that matters, because a flood collapses onto one key and therefore one
// shard. Complexity the measurement does not justify.
//
// A regression shows up two ways: the allocation tests below fail outright, and
// the Parallel variants' curve reverts toward the Legacy column.

import (
	"strings"
	"testing"
	"time"
)

// legacyDedupSuppressed is the pre-change implementation, kept VERBATIM as the
// negative control. It must NOT be "kept in sync" with the shipped code — its
// whole value is that it does not move. It takes the joined key the old caller
// built, so the benchmark pairs below charge it the concatenation the shipped
// shape no longer pays.
func legacyDedupSuppressed(as *Store, dedupKey string) bool {
	as.dedupMu.Lock()
	defer as.dedupMu.Unlock()
	if as.dedupMap == nil {
		as.dedupMap = map[string]time.Time{}
	}
	now := time.Now()
	if last, ok := as.dedupMap[dedupKey]; ok && now.Sub(last) < dedupTTL {
		return true
	}
	as.dedupMap[dedupKey] = now
	as.dedupSincePrune++
	if as.dedupSincePrune >= dedupPruneEvery {
		as.pruneExpiredLocked(now)
	}
	if len(as.dedupMap) > maxDedupEntries {
		if now.Sub(as.dedupLastPrune) >= dedupPruneMinInterval {
			as.pruneExpiredLocked(now)
		}
		as.evictOverCapLocked(now, dedupKey)
	}
	return false
}

// legacyDispatchPrefix is the pre-change ordering of Dispatch's two opening
// steps: stamp first, gate second. Kept so the benchmark can charge the shipped
// ordering against the one it replaced, in one binary.
func legacyDispatchPrefix(as *Store, event string, payload Payload) bool {
	payload.Event = event
	if payload.Timestamp == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	return legacyDedupSuppressed(as, event+":"+payload.Detail)
}

// benchDedupStore returns a store whose dedup window already holds the key the
// benchmark then asks about, so every measured iteration takes the SUPPRESSED
// branch — the branch a flood actually takes.
func benchDedupStore(event, detail string) *Store {
	as := &Store{}
	as.publishSubscriptions()
	as.dedupSuppressed(event, detail) // prime the window
	return as
}

const (
	benchDedupEvent  = "policy_block"
	benchDedupDetail = "block-corp-social"
)

func BenchmarkDispatchSuppressed(b *testing.B) {
	as := benchDedupStore(benchDedupEvent, benchDedupDetail)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		as.Dispatch(benchDedupEvent, Payload{Detail: benchDedupDetail})
	}
}

// BenchmarkDispatchSuppressedParallel is the shape that matters: ns/op is wall
// time per op across all workers, so a path that genuinely scales gets FASTER
// per op as -cpu rises and one that serialises gets slower.
func BenchmarkDispatchSuppressedParallel(b *testing.B) {
	as := benchDedupStore(benchDedupEvent, benchDedupDetail)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			as.Dispatch(benchDedupEvent, Payload{Detail: benchDedupDetail})
		}
	})
}

func BenchmarkDispatchSuppressed_Legacy(b *testing.B) {
	as := benchDedupStore(benchDedupEvent, benchDedupDetail)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		legacyDispatchPrefix(as, benchDedupEvent, Payload{Detail: benchDedupDetail})
	}
}

func BenchmarkDispatchSuppressedParallel_Legacy(b *testing.B) {
	as := benchDedupStore(benchDedupEvent, benchDedupDetail)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			legacyDispatchPrefix(as, benchDedupEvent, Payload{Detail: benchDedupDetail})
		}
	})
}

// benchKeyEvent/benchKeyDetail are VARIABLES, not constants, and that is
// load-bearing for the pair below. With constants the compiler folds
// `event + ":" + detail` into one static string at compile time, so the legacy
// arm measures a key it never had to build — it reported 84 ns and ZERO
// allocations, flattering the shape this change replaced. Reading them through
// variables forces the runtime concatenation production actually paid.
var (
	benchKeyEvent  = benchDedupEvent
	benchKeyDetail = benchDedupDetail
)

// BenchmarkDedupSuppressedKeyOnly isolates the dedup check from the rest of
// Dispatch, so a future pass can tell which half of the win it moved — and so
// the MUTEX's curve is recorded separately from the allocation win. Read the
// P=1 → P=4 slope: it rises in both arms, because this change does not touch
// the lock. See the header for why that is deliberate.
func BenchmarkDedupSuppressedKeyOnly(b *testing.B) {
	as := benchDedupStore(benchDedupEvent, benchDedupDetail)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			as.dedupSuppressed(benchKeyEvent, benchKeyDetail)
		}
	})
}

func BenchmarkDedupSuppressedKeyOnly_Legacy(b *testing.B) {
	as := benchDedupStore(benchDedupEvent, benchDedupDetail)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			// The concatenation is INSIDE the loop on purpose: it is a cost the
			// old caller paid per dispatch, and hoisting it would measure a
			// shape that never shipped.
			legacyDedupSuppressed(as, benchKeyEvent+":"+benchKeyDetail)
		}
	})
}

// ── Allocation contracts ─────────────────────────────────────────────────────

// TestDedupSuppressedHitIsAllocationFree is the arming contract for the claim in
// dedupSuppressed's comment. The suppressed answer is the one a flood takes, so
// it is the one that must cost nothing; a change that reintroduces a string
// conversion on the read path is a correct, memory-safe change that silently
// restores the allocation rate, and only this test distinguishes the two.
func TestDedupSuppressedHitIsAllocationFree(t *testing.T) {
	as := &Store{}
	if as.dedupSuppressed("policy_block", "block-corp-social") {
		t.Fatal("first call must not be suppressed")
	}
	got := testing.AllocsPerRun(200, func() {
		if !as.dedupSuppressed("policy_block", "block-corp-social") {
			t.Fatal("expected the primed key to stay suppressed")
		}
	})
	if got > 0 {
		t.Errorf("suppressed dedup check allocated %v times per call, want 0", got)
	}
}

// TestDispatchSuppressedIsAllocationFree covers the whole gated prefix, which is
// what a blocked request actually runs: the timestamp default must not be reached
// on the suppressed return.
func TestDispatchSuppressedIsAllocationFree(t *testing.T) {
	as := &Store{}
	as.publishSubscriptions()
	as.Dispatch("policy_block", Payload{Detail: "block-corp-social"})
	got := testing.AllocsPerRun(200, func() {
		as.Dispatch("policy_block", Payload{Detail: "block-corp-social"})
	})
	if got > 0 {
		t.Errorf("suppressed Dispatch allocated %v times per call, want 0", got)
	}
}

// TestDispatchSuppressedAllocationFree_LegacyIsNot is the negative control for
// the test above: it asserts the pre-change shape DID allocate, so a future
// reader can see the gate measures a real difference rather than a tautology.
func TestDispatchSuppressedAllocationFree_LegacyIsNot(t *testing.T) {
	as := &Store{}
	legacyDispatchPrefix(as, "policy_block", Payload{Detail: "block-corp-social"})
	got := testing.AllocsPerRun(200, func() {
		legacyDispatchPrefix(as, "policy_block", Payload{Detail: "block-corp-social"})
	})
	if got < 2 {
		t.Errorf("legacy suppressed dispatch allocated %v times per call, want >= 2 "+
			"(the RFC3339 stamp and the joined key); if this now reports 0 the "+
			"control has drifted and the gate above proves nothing", got)
	}
}

// ── Key-encoding differential oracle ────────────────────────────────────────

// TestDedupKeyEncodingUnchanged is the differential oracle for the signature
// change. The two halves are now passed separately, but the bytes the map is
// keyed by must be IDENTICAL to what the old `event + ":" + Detail` produced —
// the CHAOS-27 regression tests index dedupMap by that spelling, and a
// pseudonymised correlation of suppressed events would silently fork if it moved.
func TestDedupKeyEncodingUnchanged(t *testing.T) {
	cases := []struct{ event, detail string }{
		{"policy_block", "block-corp-social"},
		{"cert_expiry", "ca"},
		{"threat_detected", "feed-x deny"},
		{"dns_failure", ""},                      // empty detail
		{"*", "catch-all"},                       // the catch-all event name
		{"policy_block", "a:b"},                  // a separator inside the detail
		{"scan_skipped", strings.Repeat("x", 8)}, // short
	}
	for _, c := range cases {
		t.Run(c.event+"/"+c.detail, func(t *testing.T) {
			as := &Store{}
			if as.dedupSuppressed(c.event, c.detail) {
				t.Fatal("first call must not be suppressed")
			}
			want := c.event + ":" + c.detail
			as.dedupMu.Lock()
			_, ok := as.dedupMap[want]
			n := len(as.dedupMap)
			as.dedupMu.Unlock()
			if !ok {
				t.Errorf("dedupMap is not keyed by %q", want)
			}
			if n != 1 {
				t.Errorf("expected exactly 1 key, got %d", n)
			}
		})
	}
}

// TestDedupSuppressedKeyLongerThanScratch covers the spill path: a key past
// dedupKeyScratch must still be rendered, keyed and suppressed correctly. The
// scratch is a performance ceiling, never a correctness bound — a truncating
// render would make two distinct floods share one suppression window and
// SILENCE a real alert, which is the failure direction that matters.
func TestDedupSuppressedKeyLongerThanScratch(t *testing.T) {
	long := strings.Repeat("d", dedupKeyScratch*2)
	other := long[:len(long)-1] + "e" // differs only in the final byte
	as := &Store{}

	if as.dedupSuppressed("policy_block", long) {
		t.Fatal("first call must not be suppressed")
	}
	if !as.dedupSuppressed("policy_block", long) {
		t.Error("an over-long key must still suppress its own repeat")
	}
	if as.dedupSuppressed("policy_block", other) {
		t.Error("two over-long keys differing past the scratch must NOT share a window")
	}
	as.dedupMu.Lock()
	_, ok := as.dedupMap["policy_block:"+long]
	n := len(as.dedupMap)
	as.dedupMu.Unlock()
	if !ok {
		t.Error("over-long key was not stored under its full joined spelling")
	}
	if n != 2 {
		t.Errorf("expected 2 distinct keys, got %d", n)
	}
}

// ── The reordering's behavioral contract ────────────────────────────────────

// TestDispatchStampsTimestampOnDeliveredPayload is the contract the reorder must
// not break: moving the Timestamp default BEHIND the dedup gate is only safe if a
// payload that gets past the gate is still stamped.
//
// It observes the payload without any network by saturating webhookSem, which
// sends Dispatch down its `default:` branch — enqueueRetry, synchronously, on
// this goroutine. That is a real production branch (a saturated delivery
// semaphore), not a test-only seam.
func TestDispatchStampsTimestampOnDeliveredPayload(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryCounters(t)
	saturateWebhookSem(t)
	withRetryStateDir(t)

	as := &Store{hooks: []Webhook{{
		ID: "h1", Enabled: true, Events: []string{"policy_block"},
		URL: "https://collector.example.invalid/hook",
	}}}
	as.publishSubscriptions()
	as.Dispatch("policy_block", Payload{Detail: "rule-a"})

	got := soleRetryPayload(t)
	if got.Timestamp == "" {
		t.Fatal("a delivered payload must carry a Timestamp")
	}
	if _, err := time.Parse(time.RFC3339, got.Timestamp); err != nil {
		t.Errorf("Timestamp %q is not RFC3339: %v", got.Timestamp, err)
	}
	if got.Event != "policy_block" {
		t.Errorf("Event = %q, want policy_block", got.Event)
	}
}

// TestDispatchPreservesCallerTimestamp — the default must stay a DEFAULT. A
// producer that stamped the payload itself (the retry path replays one) must get
// its own value through untouched, on either side of the gate.
func TestDispatchPreservesCallerTimestamp(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryCounters(t)
	saturateWebhookSem(t)
	withRetryStateDir(t)

	const stamp = "2020-01-02T03:04:05Z"
	as := &Store{hooks: []Webhook{{
		ID: "h1", Enabled: true, Events: []string{"policy_block"},
		URL: "https://collector.example.invalid/hook",
	}}}
	as.publishSubscriptions()
	as.Dispatch("policy_block", Payload{Detail: "rule-a", Timestamp: stamp})

	if got := soleRetryPayload(t).Timestamp; got != stamp {
		t.Errorf("Timestamp = %q, want the caller's %q", got, stamp)
	}
}

// TestDispatchSuppressedDeliversNothing is the suppression contract itself,
// asserted through the same no-network branch: the second identical dispatch
// must not reach the fan-out at all.
func TestDispatchSuppressedDeliversNothing(t *testing.T) {
	snapshotRetryQueue(t)
	snapshotRetryCounters(t)
	saturateWebhookSem(t)
	withRetryStateDir(t)

	as := &Store{hooks: []Webhook{{
		ID: "h1", Enabled: true, Events: []string{"policy_block"},
		URL: "https://collector.example.invalid/hook",
	}}}
	as.publishSubscriptions()
	as.Dispatch("policy_block", Payload{Detail: "rule-a"})
	as.Dispatch("policy_block", Payload{Detail: "rule-a"})

	retryMu.Lock()
	n := len(retryQueue)
	retryMu.Unlock()
	if n != 1 {
		t.Errorf("queued %d payloads, want 1 (the duplicate must be suppressed)", n)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// saturateWebhookSem fills the package-level delivery semaphore so Dispatch
// takes its queue-instead-of-deliver branch, and drains it on cleanup.
func saturateWebhookSem(t *testing.T) {
	t.Helper()
	held := 0
	for {
		select {
		case webhookSem <- struct{}{}:
			held++
		default:
			t.Cleanup(func() {
				for i := 0; i < held; i++ {
					<-webhookSem
				}
			})
			if held == 0 {
				t.Fatal("webhookSem was already saturated by another test")
			}
			return
		}
	}
}

// withRetryStateDir points the retry queue's persistence at a temp directory so
// these tests do not write the real state file.
func withRetryStateDir(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

// soleRetryPayload returns the single queued payload, failing if the count is
// anything but one.
func soleRetryPayload(t *testing.T) Payload {
	t.Helper()
	retryMu.Lock()
	defer retryMu.Unlock()
	if len(retryQueue) != 1 {
		t.Fatalf("expected exactly 1 queued payload, got %d", len(retryQueue))
	}
	return retryQueue[0].Payload
}
