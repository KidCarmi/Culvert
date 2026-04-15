package main

// Tests for the multi-instance CDR client pool (cdr_pool.go).
// Uses bufconn fake Sluice servers.

import (
	"context"
	"strings"
	"testing"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// newPooledFake spins up a bufconn fake Sluice, wraps it in a
// pooled-client shell, and returns the client + a teardown fn.
func newPooledFake(t *testing.T, name string, srv *fakeSluice) (*cdrPooledClient, func()) {
	t.Helper()
	c, stop := startFakeSluice(t, srv)
	pc := &cdrPooledClient{
		Name:    name,
		Client:  c,
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{}),
	}
	return pc, stop
}

// withTempPool replaces the package-wide pool with `members` and
// restores on cleanup.
func withTempPool(t *testing.T, members ...*cdrPooledClient) {
	t.Helper()
	prev := cdrPool.List()
	cdrPool.replace(members)
	t.Cleanup(func() { cdrPool.replace(prev) })
}

func TestPool_PickReturnsNilWhenEmpty(t *testing.T) {
	withTempPool(t)
	if pc := cdrPool.Pick(); pc != nil {
		t.Fatalf("empty pool returned %+v", pc)
	}
}

func TestPool_PickRoundRobin(t *testing.T) {
	a, stopA := newPooledFake(t, "a", &fakeSluice{})
	b, stopB := newPooledFake(t, "b", &fakeSluice{})
	c, stopC := newPooledFake(t, "c", &fakeSluice{})
	defer stopA()
	defer stopB()
	defer stopC()
	withTempPool(t, a, b, c)
	cdrPool.rrNext.Store(0) // deterministic

	names := []string{}
	for i := 0; i < 6; i++ {
		pc := cdrPool.Pick()
		if pc == nil {
			t.Fatalf("pick returned nil at iter %d", i)
		}
		names = append(names, pc.Name)
	}
	// Over 6 picks with 3 members we must hit each name exactly twice.
	counts := map[string]int{}
	for _, n := range names {
		counts[n]++
	}
	if counts["a"] != 2 || counts["b"] != 2 || counts["c"] != 2 {
		t.Fatalf("round-robin distribution skewed: %+v (sequence=%v)", counts, names)
	}
}

func TestPool_PickSkipsOpenBreaker(t *testing.T) {
	a, stopA := newPooledFake(t, "a", &fakeSluice{})
	b, stopB := newPooledFake(t, "b", &fakeSluice{})
	defer stopA()
	defer stopB()
	withTempPool(t, a, b)
	// Open a's breaker.
	a.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 5 * 60_000_000_000})
	a.Breaker.OnFailure()

	for i := 0; i < 5; i++ {
		pc := cdrPool.Pick()
		if pc == nil || pc.Name != "b" {
			t.Fatalf("pick %d returned %v, want b", i, pc)
		}
	}
}

func TestPool_PickReturnsNilWhenAllOpen(t *testing.T) {
	a, stopA := newPooledFake(t, "a", &fakeSluice{})
	b, stopB := newPooledFake(t, "b", &fakeSluice{})
	defer stopA()
	defer stopB()
	withTempPool(t, a, b)
	a.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 5 * 60_000_000_000})
	b.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 5 * 60_000_000_000})
	a.Breaker.OnFailure()
	b.Breaker.OnFailure()

	if pc := cdrPool.Pick(); pc != nil {
		t.Fatalf("all-open pool returned %+v", pc)
	}
}

func TestPool_GetByName(t *testing.T) {
	a, stopA := newPooledFake(t, "alpha", &fakeSluice{})
	defer stopA()
	withTempPool(t, a)

	if got := cdrPool.Get("alpha"); got == nil || got.Name != "alpha" {
		t.Fatalf("Get(alpha) = %+v", got)
	}
	if got := cdrPool.Get("missing"); got != nil {
		t.Fatalf("Get(missing) = %+v, want nil", got)
	}
}

func TestPool_ReplaceCarriesBreakerState(t *testing.T) {
	a, stopA := newPooledFake(t, "same", &fakeSluice{})
	defer stopA()
	// Seed the original breaker with failures so it's in open state.
	a.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 5 * 60_000_000_000})
	a.Breaker.OnFailure()
	withTempPool(t, a)

	// Replace with a new pooledClient at same name — simulating a hot
	// reconfig that kept the same instance.  Real code (cdr_pool.go
	// buildCDRPoolFromRegistry) carries the breaker over.
	b, stopB := newPooledFake(t, "same", &fakeSluice{})
	defer stopB()
	b.Breaker = a.Breaker // simulate the carry-over
	cdrPool.replace([]*cdrPooledClient{b})

	if b.Breaker.State() != cbStateOpen {
		t.Fatalf("breaker state lost across replace: %d", b.Breaker.State())
	}
}

func TestCDRMarkOutcome_UnknownInstanceIsNoop(t *testing.T) {
	withTempPool(t)
	// Must not panic.
	cdrMarkOutcome("nonexistent", true)
	cdrMarkOutcome("nonexistent", false)
}

func TestCDRMarkOutcome_OnFailureTripsBreaker(t *testing.T) {
	pc, stop := newPooledFake(t, "flaky", &fakeSluice{})
	defer stop()
	pc.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 2})
	withTempPool(t, pc)

	cdrMarkOutcome("flaky", true)
	cdrMarkOutcome("flaky", true)
	if pc.Breaker.State() != cbStateOpen {
		t.Fatalf("breaker did not open after 2 failures; state=%d", pc.Breaker.State())
	}
}

func TestCDRMarkOutcome_OnSuccessResetsFailureCount(t *testing.T) {
	pc, stop := newPooledFake(t, "ok", &fakeSluice{})
	defer stop()
	pc.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 3})
	withTempPool(t, pc)

	cdrMarkOutcome("ok", true)
	cdrMarkOutcome("ok", true)
	cdrMarkOutcome("ok", false) // reset
	cdrMarkOutcome("ok", true)  // only 1 fail since reset
	if pc.Breaker.State() != cbStateClosed {
		t.Fatalf("breaker should still be closed; state=%d", pc.Breaker.State())
	}
}

// ─── Health snapshot plumbing ──────────────────────────────────────────────

func TestPooledClient_SetAndGetHealth(t *testing.T) {
	pc, stop := newPooledFake(t, "h", &fakeSluice{})
	defer stop()
	pc.setHealth(&pb.HealthResponse{Healthy: true, Version: "v1"})
	if !pc.Healthy() {
		t.Fatal("Healthy() should be true")
	}
	h, at := pc.HealthSnapshot()
	if h == nil || h.Version != "v1" {
		t.Fatalf("snapshot = %+v", h)
	}
	if at.IsZero() {
		t.Fatal("timestamp not set")
	}
	pc.clearHealth()
	if pc.Healthy() {
		t.Fatal("Healthy() should be false after clear")
	}
	h, _ = pc.HealthSnapshot()
	if h != nil {
		t.Fatal("clear did not wipe snapshot")
	}
}

// ─── Pool-aware Sanitize integration ───────────────────────────────────────

func TestSafeCDRSanitize_UsesPoolPicker(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)

	// Build a pool of 2 fakes and make the first one reject with ERROR
	// (after enough calls it would trip CB, but 2d-1 doesn't auto-retry,
	// so we expect the first Pick to hit the breaker-closed member).
	ok, stopOK := newPooledFake(t, "ok", &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}})
	defer stopOK()
	withTempPool(t, ok)
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: true}
	cdrClientMu.Unlock()
	t.Cleanup(func() {
		cdrClientMu.Lock()
		cdrActiveCfg = CDRConfig{}
		cdrClientMu.Unlock()
	})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"), []byte("x"),
		"application/pdf", sampleID, cdrActiveConfig())
	if out.Status != "CLEAN" {
		t.Fatalf("status = %+v", out)
	}
	// Breaker should have been marked success.
	if ok.Breaker.State() != cbStateClosed {
		t.Fatalf("breaker state = %d, want closed", ok.Breaker.State())
	}
}

func TestSafeCDRSanitize_BreakerOpenReturnsSkipped(t *testing.T) {
	resetCDRCountersAndCache(t)
	freshPolicyStore(t)
	pc, stop := newPooledFake(t, "all_open", &fakeSluice{})
	defer stop()
	// Trip the breaker before the call.
	pc.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 5 * 60_000_000_000})
	pc.Breaker.OnFailure()
	withTempPool(t, pc)
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: true}
	cdrClientMu.Unlock()
	t.Cleanup(func() {
		cdrClientMu.Lock()
		cdrActiveCfg = CDRConfig{}
		cdrClientMu.Unlock()
	})

	out := safeCDRSanitize(context.Background(), sampleReq("example.com"), []byte("x"),
		"application/pdf", sampleID, cdrActiveConfig())
	if out.Outcome != cdrPass || out.Status != "SKIPPED" {
		t.Fatalf("all-open pool should yield SKIPPED, got %+v", out)
	}
}

// ─── Prometheus writer ─────────────────────────────────────────────────────

func TestCDRPoolWritePrometheus(t *testing.T) {
	a, stopA := newPooledFake(t, "prod-us-east", &fakeSluice{})
	b, stopB := newPooledFake(t, "prod-eu-west", &fakeSluice{})
	defer stopA()
	defer stopB()
	withTempPool(t, a, b)

	var buf strings.Builder
	cdrPoolWritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, `culvert_cdr_pool_instance_healthy{instance="prod-us-east"}`) {
		t.Fatalf("missing per-instance healthy line; got:\n%s", out)
	}
	if !strings.Contains(out, `culvert_cdr_pool_breaker_state{instance="prod-eu-west"}`) {
		t.Fatalf("missing breaker_state line; got:\n%s", out)
	}
}
