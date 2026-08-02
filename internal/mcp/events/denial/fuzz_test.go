package denial

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// FuzzNormalizeSource asserts source normalization is total and bounded: no input
// panics, the output is always non-empty and within the bounded token size, and it
// never returns raw unbounded attacker text.
func FuzzNormalizeSource(f *testing.F) {
	f.Add("203.0.113.7")
	f.Add("2001:db8::1")
	f.Add("[::1]:443")
	f.Add("")
	f.Add("a very long \x00 hostile string with control bytes")
	f.Fuzz(func(t *testing.T, raw string) {
		out := NormalizeSource(raw)
		if out == "" {
			t.Fatal("normalized source is empty")
		}
		if len(out) > maxSourceBytes+8 {
			t.Fatalf("normalized source exceeds bound: %d", len(out))
		}
	})
}

// FuzzAggregatorObserve fuzzes the aggregator with arbitrary observations. The
// invariant is bounded cardinality: the active bucket count never exceeds the
// configured maximum, regardless of attacker-driven source/reason variety.
func FuzzAggregatorObserve(f *testing.F) {
	f.Add("gw", "1.2.3.4", "auth_failed", "", "")
	f.Fuzz(func(t *testing.T, listener, source, reason, tenant, principal string) {
		a := NewAggregator(Config{
			Capability: model.CapGateway, NodeID: "dp", Window: time.Second,
			MaxBuckets: 8, MaxPerSource: 4, IDGen: func(p string) string { return p + "x" },
		})
		base := time.Unix(1000, 0)
		for i := 0; i < 50; i++ {
			a.Observe(Observation{Now: base, Listener: listener, Source: source + string(rune('a'+i%7)), Reason: reason, Tenant: tenant, Principal: principal})
		}
		if s := a.Stats(); s.ActiveBuckets > 8 {
			t.Fatalf("bucket cardinality exceeded bound: %d", s.ActiveBuckets)
		}
		// Flushed aggregates must all be structurally valid.
		for _, e := range a.Flush(base.Add(2*time.Second), true) {
			if err := e.Validate(); err != nil {
				t.Fatalf("flushed aggregate invalid: %v", err)
			}
		}
	})
}
