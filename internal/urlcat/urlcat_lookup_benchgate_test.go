package urlcat

import (
	"fmt"
	"testing"
)

// buildTaxonomy makes a store with catCount categories of hostsPerCat patterns
// each, none of which match the probe used by the gate below.
func buildTaxonomy(catCount, hostsPerCat int) *Store {
	entries := make([]*Entry, 0, catCount)
	for c := 0; c < catCount; c++ {
		hosts := make([]string, 0, hostsPerCat)
		for h := 0; h < hostsPerCat; h++ {
			hosts = append(hosts, fmt.Sprintf("host%d-%d.vendor%d.example", c, h, c))
		}
		entries = append(entries, &Entry{Name: fmt.Sprintf("Cat%d", c), Hosts: hosts})
	}
	s := New(entries)
	s.LookupHost("warm.example") // force the lazy index build out of the timed region
	return s
}

// TestBenchGate_CategoryLookupConstantInTaxonomySize pins the STRUCTURAL
// property that makes LookupHost safe on the proxy hot path: its cost depends
// on the number of labels in the queried host, not on how many host patterns
// the operator has configured.
//
// LookupHost is reached per request from categoryGroupMatchesHostRule ->
// lookupHostCategory for any rule carrying a DestCategoryGroup. It used to scan
// every configured pattern, so an operator importing a large taxonomy silently
// bought proportional per-request latency (22.6 us on the ~665-pattern shipped
// default alone). The assertion is deliberately a ratio across two taxonomy
// sizes rather than an absolute ns/op, so it stays meaningful on slow or noisy
// CI runners while still failing hard if the linear scan returns: a regression
// shows up as ~100x here, and the threshold is 4x.
func TestBenchGate_CategoryLookupConstantInTaxonomySize(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive benchmark gate")
	}

	const probe = "unmatched.host.customer.example"

	measure := func(s *Store) float64 {
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s.LookupHost(probe)
			}
		})
		if res.AllocsPerOp() != 0 {
			t.Errorf("LookupHost allocated %d allocs/op; want 0 — the lookup runs "+
				"per request and must not add GC pressure", res.AllocsPerOp())
		}
		return float64(res.NsPerOp())
	}

	small := measure(buildTaxonomy(5, 20))   // 100 patterns
	large := measure(buildTaxonomy(50, 200)) // 10,000 patterns — 100x more

	if small <= 0 {
		t.Fatalf("degenerate small-taxonomy measurement: %v ns/op", small)
	}
	ratio := large / small
	t.Logf("LookupHost: 100 patterns = %.1f ns/op, 10,000 patterns = %.1f ns/op (ratio %.2fx)",
		small, large, ratio)

	if ratio > 4 {
		t.Fatalf("LookupHost cost scales with taxonomy size (%.2fx slower for 100x more "+
			"patterns, %.1f -> %.1f ns/op); it must stay O(labels) via the reverse index, "+
			"not O(configured hosts)", ratio, small, large)
	}
}
