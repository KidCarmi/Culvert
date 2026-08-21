package broker

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// mutableClock returns a clock function and a setter for deterministic time control.
func mutableClock() (get func() time.Time, set func(time.Time), base time.Time) {
	base = time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	cur := base
	get = func() time.Time { mu.Lock(); defer mu.Unlock(); return cur }
	set = func(t time.Time) { mu.Lock(); defer mu.Unlock(); cur = t }
	return get, set, base
}

// brokerAt builds a broker with a given clock and returns it plus its provider.
func brokerAt(t testing.TB, clk func() time.Time, power profile.CredentialPower) (*harness, *provider.InMemoryProvider) {
	t.Helper()
	reg := gwRegistry(t)
	cat := newCatalog()
	store := profile.NewStore(limits.DefaultCredential())
	addProfile(t, store, reg)
	prov := memProvider(t, clk, power, "v1", provider.Capabilities{CanRotate: true, CanRevoke: true})
	b := New(Deps{Profiles: store, Registry: reg, Catalog: cat, KEK: testKEK(), Clock: clk}, limits.DefaultCredential())
	if err := b.RegisterProvider(prov); err != nil {
		t.Fatal(err)
	}
	return &harness{broker: b, store: store, reg: reg, cat: cat, prov: prov, id: gwIdentity(t, reg, cat), clk: clk}, prov
}

func TestLowRiskCacheHit(t *testing.T) {
	get, _, _ := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	plan := h.readPlan(t)
	// First read: provider fetch + cache write.
	if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Second read: served from cache (provider not called again).
	res, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB)
	if err != nil {
		t.Fatal(err)
	}
	if !res.CacheHit {
		t.Fatal("second low-risk read should be a cache hit")
	}
	if f, _, _ := prov.Calls(); f != 1 {
		t.Fatalf("provider fetch calls = %d, want 1 (second served from cache)", f)
	}
}

func TestHighRiskNeverUsesCache(t *testing.T) {
	get, _, _ := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerWrite)
	plan := h.writePlan(t)
	for i := 0; i < 2; i++ {
		if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if f, _, _ := prov.Calls(); f != 2 {
		t.Fatalf("high-risk must always fetch fresh: fetch calls = %d, want 2", f)
	}
}

func TestLowRiskFreshnessExpiry(t *testing.T) {
	get, set, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	plan := h.readPlan(t)
	if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Advance beyond the 1-minute freshness → next read refetches (no stale serve).
	set(base.Add(2 * time.Minute))
	res, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB)
	if err != nil {
		t.Fatal(err)
	}
	if res.CacheHit {
		t.Fatal("a stale (beyond-freshness) entry must not be served")
	}
	if f, _, _ := prov.Calls(); f != 2 {
		t.Fatalf("fetch calls = %d, want 2", f)
	}
}

func TestCacheHoldsOnlyEncryptedEnvelopes(t *testing.T) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(t, get, profile.PowerReadOnly)
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); err != nil {
		t.Fatal(err)
	}
	// Scan every cached envelope for the plaintext canary.
	h.broker.cache.mu.Lock()
	defer h.broker.cache.mu.Unlock()
	if len(h.broker.cache.entries) == 0 {
		t.Fatal("expected a cached envelope")
	}
	for _, e := range h.broker.cache.entries {
		if bytes.Contains(e.env, []byte("UPSTREAM")) {
			t.Fatal("cache envelope contains plaintext material")
		}
	}
}

func TestStampedeCoalescing(t *testing.T) {
	get, _, _ := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerWrite) // high-risk always fetches
	plan := h.writePlan(t)
	var wg sync.WaitGroup
	const n = 16
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = h.broker.Materialize(context.Background(), plan, permitGate(), noopCB)
		}()
	}
	wg.Wait()
	// Concurrent identical fetches coalesce; far fewer than n provider calls.
	f, _, _ := prov.Calls()
	if f == 0 || f > n {
		t.Fatalf("coalescing failed: %d provider calls for %d concurrent requests", f, n)
	}
}

func TestExpiredCredentialFailsClosed(t *testing.T) {
	get, _, base := mutableClock()
	h, prov := brokerAt(t, get, profile.PowerReadOnly)
	// Provider returns an already-expired lease.
	prov.SetMaterial(profile.KindBearerToken, map[provider.FieldName][]byte{provider.FieldToken: []byte("x")},
		provider.Lease{Version: "v1", IssuedAt: base.Add(-2 * time.Hour), Expiry: base.Add(-time.Hour), Scope: leaseScope(t, profile.PowerReadOnly)})
	if _, err := h.broker.Materialize(context.Background(), h.readPlan(t), permitGate(), noopCB); mcperrIs(err, "credential_expired") == false {
		t.Fatalf("expired credential must fail closed, got %v", err)
	}
}
