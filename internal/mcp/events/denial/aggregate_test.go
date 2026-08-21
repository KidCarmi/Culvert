package denial

import (
	"strconv"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

func testAgg(maxBuckets, maxPerSource int) *Aggregator {
	n := 0
	return NewAggregator(Config{
		Capability: model.CapGateway, NodeID: "dp", Window: time.Second,
		MaxBuckets: maxBuckets, MaxPerSource: maxPerSource,
		IDGen: func(prefix string) string { n++; return prefix + strconv.Itoa(n) },
	})
}

// TestCoalescingIsO1 proves N equivalent denials in one bucket/window produce
// exactly ONE aggregate record with the correct count and first/last-seen.
func TestCoalescingIsO1(t *testing.T) {
	a := testAgg(1000, 100)
	base := time.Unix(100, 0)
	const N = 5000
	for i := 0; i < N; i++ {
		a.Observe(Observation{Now: base.Add(time.Duration(i) * time.Microsecond), Listener: "gw", Source: "203.0.113.7", Reason: "auth_failed"})
	}
	if s := a.Stats(); s.ActiveBuckets != 1 {
		t.Fatalf("coalescing failed: %d active buckets for %d denials", s.ActiveBuckets, N)
	}
	// Flush the closed window (advance well past it).
	evs := a.Flush(base.Add(2*time.Second), false)
	if len(evs) != 1 {
		t.Fatalf("want 1 aggregate record, got %d", len(evs))
	}
	d := evs[0].Denial
	if d.Count != N {
		t.Fatalf("count = %d, want %d", d.Count, N)
	}
	if d.FirstSeenUnixNano != base.UnixNano() {
		t.Fatalf("first-seen wrong: %d", d.FirstSeenUnixNano)
	}
	wantLast := base.Add(time.Duration(N-1) * time.Microsecond).UnixNano()
	if d.LastSeenUnixNano != wantLast {
		t.Fatalf("last-seen wrong: %d != %d", d.LastSeenUnixNano, wantLast)
	}
	if evs[0].Partition != model.PartDen || evs[0].Criticality != model.CritDenial {
		t.Fatal("denial aggregate not routed to P-DEN")
	}
	if err := evs[0].Validate(); err != nil {
		t.Fatalf("aggregate event invalid: %v", err)
	}
}

// TestPreIdentityNeverInventsTenant proves a pre-authentication denial carries no
// tenant attribution, while a verified-identity denial does.
func TestPreIdentityNeverInventsTenant(t *testing.T) {
	a := testAgg(1000, 100)
	base := time.Unix(100, 0)
	// Pre-identity (no tenant/principal).
	a.Observe(Observation{Now: base, Listener: "gw", Source: "198.51.100.9", Reason: "auth_failed"})
	// Authenticated-but-unauthorized (verified identity present).
	a.Observe(Observation{Now: base, Listener: "gw", Source: "198.51.100.9", Reason: "authz_denied", Tenant: "acme", Principal: "user-1"})
	evs := a.Flush(base.Add(2*time.Second), true)
	if len(evs) != 2 {
		t.Fatalf("want 2 aggregates, got %d", len(evs))
	}
	for _, e := range evs {
		switch e.Denial.DenialReason {
		case "auth_failed":
			if e.Identity.Tenant != "" || e.Identity.PrincipalID != "" {
				t.Fatal("pre-identity denial invented tenant/principal attribution")
			}
		case "authz_denied":
			if e.Identity.Tenant != "acme" || e.Identity.PrincipalID != "user-1" {
				t.Fatal("verified-identity denial dropped attribution")
			}
		}
	}
}

// TestBucketCardinalityBounded proves an attacker cannot create unbounded
// aggregation keys: past MaxBuckets, new keys are dropped (and counted), while
// the request is still denied by the caller.
func TestBucketCardinalityBounded(t *testing.T) {
	a := testAgg(10, 100)
	base := time.Unix(100, 0)
	admitted := 0
	for i := 0; i < 100; i++ {
		if a.Observe(Observation{Now: base, Listener: "gw", Source: "10.0.0." + strconv.Itoa(i), Reason: "auth_failed"}) {
			admitted++
		}
	}
	if s := a.Stats(); s.ActiveBuckets > 10 {
		t.Fatalf("bucket cardinality exceeded bound: %d", s.ActiveBuckets)
	}
	if admitted > 10 {
		t.Fatalf("admitted %d distinct buckets past the bound", admitted)
	}
	if a.Stats().Dropped == 0 {
		t.Fatal("dropped observations were not counted")
	}
}

// TestPerSourceBounded proves one source cannot occupy unbounded buckets.
func TestPerSourceBounded(t *testing.T) {
	a := testAgg(10000, 3)
	base := time.Unix(100, 0)
	for i := 0; i < 50; i++ {
		// Same source, distinct reasons → distinct keys, bounded per source.
		a.Observe(Observation{Now: base, Listener: "gw", Source: "203.0.113.5", Reason: "reason-" + strconv.Itoa(i)})
	}
	if s := a.Stats(); s.ActiveBuckets > 3 {
		t.Fatalf("per-source bound exceeded: %d", s.ActiveBuckets)
	}
}

func TestNormalizeSource(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":       "ip4:203.0.113.7",
		"203.0.113.7:44321": "ip4:203.0.113.7",
		"2001:db8::1":       "ip6:2001:db8::/64",
		"[2001:db8::1]:443": "ip6:2001:db8::/64",
		"":                  "src:unknown",
	}
	for in, want := range cases {
		if got := NormalizeSource(in); got != want {
			t.Errorf("NormalizeSource(%q) = %q, want %q", in, got, want)
		}
	}
	// Two distinct hosts within one /64 collapse to the same bucket.
	if NormalizeSource("2001:db8::1") != NormalizeSource("2001:db8::ffff") {
		t.Fatal("IPv6 /64 collapse failed")
	}
	// Two distinct IPv4 hosts stay distinct (no /24 over-collapse).
	if NormalizeSource("10.0.0.1") == NormalizeSource("10.0.0.2") {
		t.Fatal("IPv4 raw normalization over-collapsed")
	}
}
