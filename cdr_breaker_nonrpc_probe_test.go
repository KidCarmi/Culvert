package main

// cdr_breaker_nonrpc_probe_test.go — a request that never calls Sluice must
// not keep the half-open probe it was handed (Codex P1 on PR #1611).
//
// safeCDRSanitize picks a pooled instance — which, in half-open, RESERVES the
// single probe — and only then reaches the oversize gate (which needs that
// instance's profile cap) and the cache lookup. Both return without an RPC,
// and so without OnSuccess/OnFailure. The reservation was abandoned, every
// normal document after it was denied by the breaker and skipped CDR (under
// the default fail-OPEN mode: forwarded unsanitized), and the wedge escape
// handed the replacement probe to whichever request came first after
// HalfOpenProbeTimeout — another oversize file re-abandoned it, so the breaker
// could stay half-open indefinitely.
//
// The fix hands the slot back (Breaker.Release) on every non-recording return.
// All clocks here are injected; nothing sleeps.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// nonRPCProbeHarness installs a CLEAN-answering fake Sluice as the only pool
// member with a 1 MiB per-file cap, and drives its breaker from a
// test-advanced clock.
func nonRPCProbeHarness(t *testing.T) (b *cdrCircuitBreaker, advance func(time.Duration)) {
	t.Helper()
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	c, stop := startFakeSluice(t, &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}})
	t.Cleanup(stop)
	withActiveCDRClient(t, c, CDRConfig{Enabled: true, MaxFileSizeMB: 1})
	pool := cdrPool.List()
	if len(pool) != 1 {
		t.Fatalf("pool has %d members, want 1", len(pool))
	}
	b = pool[0].Breaker
	now := time.Now()
	b.setNowFn(func() time.Time { return now })
	return b, func(d time.Duration) { now = now.Add(d) }
}

// oversizeBody is over the harness's 1 MiB cap, so it never reaches Sluice.
func oversizeBody() []byte { return make([]byte, 2<<20) }

// normalBody is a document the fake Sluice answers CLEAN. Distinct per i so
// no cache entry can answer it instead of the RPC.
func normalBody(i int) []byte { return []byte(fmt.Sprintf("doc-%d", i)) }

func sanitizeForProbeTest(body []byte) *cdrRunResult {
	return safeCDRSanitize(context.Background(), sampleReq("example.com"),
		body, "application/pdf", sampleID, cdrActiveConfig())
}

// assertNormalDocClosesBreaker sends a normal document and requires that it
// takes the probe, is sanitized (not skipped), and closes the breaker.
func assertNormalDocClosesBreaker(t *testing.T, b *cdrCircuitBreaker, i int, label string) {
	t.Helper()
	out := sanitizeForProbeTest(normalBody(i))
	if out.Status != "CLEAN" {
		t.Fatalf("%s: normal document got status %q, want CLEAN — the breaker denied it "+
			"because an earlier request that never called Sluice kept the half-open probe, "+
			"so CDR was skipped (forwarded unsanitized under fail-open)", label, out.Status)
	}
	if b.State() != cbStateClosed {
		t.Fatalf("%s: breaker %s after a successful probe, want closed",
			label, breakerStateName(b.State()))
	}
}

// TestCDRBreaker_NonRPCRequestFirstDoesNotStrandTheProbe is case (a): open
// breaker, ResetTimeout elapses, a request that will not RPC arrives first,
// then a normal document. The document must get the probe and close the
// breaker. Covered for every non-RPC return in safeCDRSanitize after the
// pick: the config-cap oversize gate, the profile-cap oversize gate and a
// cache hit.
func TestCDRBreaker_NonRPCRequestFirstDoesNotStrandTheProbe(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
		body  []byte
		want  string
	}{
		{name: "OversizeConfigCap", body: oversizeBody(), want: "SKIPPED_OVERSIZE"},
		{
			name: "OversizeProfileCap",
			setup: func(t *testing.T) {
				for _, pc := range cdrPool.List() {
					pc.profileCap.Store(16) // tighter than the config cap
				}
			},
			body: make([]byte, 64),
			want: "SKIPPED_OVERSIZE",
		},
		{
			name: "CacheHit",
			setup: func(t *testing.T) {
				sum := sha256.Sum256([]byte("cached-doc"))
				cdrCache.Put(hex.EncodeToString(sum[:]), &cdrCacheEntry{
					status: "CLEAN", expiresAt: time.Now().Add(time.Hour), epoch: cdrPolicyStore.Epoch(),
				})
			},
			body: []byte("cached-doc"),
			want: "CLEAN",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, advance := nonRPCProbeHarness(t)
			if c.setup != nil {
				c.setup(t)
			}
			tripOpen(t, b)
			advance(b.cfg.ResetTimeout + time.Second)

			out := sanitizeForProbeTest(c.body)
			if out.Status != c.want {
				t.Fatalf("non-RPC request got %q, want %q; the case proves nothing", out.Status, c.want)
			}
			if n := b.halfOpenTried.Load(); n != 0 {
				t.Errorf("REGRESSION: %d half-open reservation(s) still held after a request "+
					"that never called Sluice — nothing will ever report an outcome for it", n)
			}
			for _, pc := range cdrPool.List() {
				pc.profileCap.Store(0) // let the normal document through the gate
			}
			assertNormalDocClosesBreaker(t, b, 0, c.name)
			if n := b.staleProbes.Load(); n != 0 {
				t.Errorf("staleProbes = %d, want 0: no reservation should ever have been abandoned", n)
			}
		})
	}
}

// TestCDRBreaker_RepeatedOversizeFirstNeverWedgesHalfOpen is case (b): many
// open/half-open episodes, each one opened by a run of oversize files spaced
// HalfOpenProbeTimeout apart — the exact re-arm cadence the abandoned-probe
// shape exploited — before a normal document arrives. Every episode must end
// closed, and no budget may ever have needed the wedge escape.
func TestCDRBreaker_RepeatedOversizeFirstNeverWedgesHalfOpen(t *testing.T) {
	b, advance := nonRPCProbeHarness(t)
	const episodes, oversizePerEpisode = 25, 8
	for ep := 0; ep < episodes; ep++ {
		tripOpen(t, b)
		advance(b.cfg.ResetTimeout + time.Second)
		for i := 0; i < oversizePerEpisode; i++ {
			if out := sanitizeForProbeTest(oversizeBody()); out.Status != "SKIPPED_OVERSIZE" {
				t.Fatalf("episode %d oversize %d: got %q", ep, i, out.Status)
			}
			if n := b.halfOpenTried.Load(); n != 0 {
				t.Fatalf("REGRESSION (episode %d, oversize %d): %d probe reservation(s) held by "+
					"requests that never called Sluice", ep, i, n)
			}
			if !b.Available() {
				t.Fatalf("episode %d oversize %d: breaker reports unavailable in half-open with "+
					"an empty budget", ep, i)
			}
			advance(b.cfg.HalfOpenProbeTimeout)
		}
		assertNormalDocClosesBreaker(t, b, ep, "episode")
	}
	if n := b.staleProbes.Load(); n != 0 {
		t.Fatalf("REGRESSION: the wedge escape re-armed %d budget(s) — some request abandoned "+
			"its reservation", n)
	}
}

// TestCDRBreaker_ReleaseIsNeutralAndGenerationScoped pins Release's contract
// at the breaker level: it returns a half-open slot without counting an
// outcome, is a no-op for a closed-state reservation and after an outcome,
// and cannot free a slot of a budget the wedge escape has since re-armed.
func TestCDRBreaker_ReleaseIsNeutralAndGenerationScoped(t *testing.T) {
	b, advance := wedgeBreaker(t, cdrBreakerConfig{})

	// Closed: nothing reserved, Release is a no-op.
	ok, r := b.Reserve()
	if !ok || r.gen != 0 {
		t.Fatalf("closed Reserve = (%v, gen %d), want (true, 0)", ok, r.gen)
	}
	b.Release(r)

	tripOpen(t, b)
	advance(b.cfg.ResetTimeout + time.Second)
	ok, r = b.Reserve()
	if !ok || r.gen == 0 {
		t.Fatalf("half-open Reserve = (%v, gen %d), want a generation-tagged slot", ok, r.gen)
	}
	b.Release(r)
	if b.State() != cbStateHalfOpen || b.consecFails.Load() != int64(b.cfg.FailureThreshold) {
		t.Fatalf("Release changed the outcome state: %s, consecFails %d",
			breakerStateName(b.State()), b.consecFails.Load())
	}
	if n := b.halfOpenTried.Load(); n != 0 {
		t.Fatalf("Release left %d slots held, want 0", n)
	}

	// A slot taken AFTER a release must not be judged stale from the arm time.
	advance(b.cfg.HalfOpenProbeTimeout - time.Second)
	if ok, _ := b.Reserve(); !ok {
		t.Fatal("budget empty after Release, yet Reserve denied")
	}
	advance(2 * time.Second) // past HalfOpenProbeTimeout since the ARM, not since this slot
	if ok, _ := b.Reserve(); ok {
		t.Fatal("a second probe was admitted while a fresh one is in flight — the wedge " +
			"escape measured staleness from the arm time and reclaimed a live probe")
	}

	// Re-arm: an abandoned slot of the old generation cannot free the new one.
	advance(b.cfg.HalfOpenProbeTimeout)
	ok, fresh := b.Reserve()
	if !ok || fresh.gen == r.gen {
		t.Fatalf("re-arm Reserve = (%v, gen %d), want a new generation", ok, fresh.gen)
	}
	b.Release(r) // stale generation
	if n := b.halfOpenTried.Load(); n != 1 {
		t.Fatalf("a stale-generation Release freed the replacement probe's slot (held %d, want 1)", n)
	}

	// After an outcome, Release is a no-op.
	b.OnSuccess()
	b.Release(fresh)
	if b.State() != cbStateClosed || b.halfOpenTried.Load() != 0 {
		t.Fatalf("Release after OnSuccess disturbed the closed breaker: %s, held %d",
			breakerStateName(b.State()), b.halfOpenTried.Load())
	}
}
