//go:build benchgate

package main

// Complexity-regression gate for host→category resolution, which runs on the
// proxy request path: matchDestNorm → categoryGroupMatchesHostRule →
// lookupHostCategory → urlcat.Store.LookupHost, for every request evaluated
// against a rule carrying a DestCategoryGroup.
//
//	go test -tags benchgate -run 'TestBenchGate_CategoryLookup' -v .

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// buildBenchTaxonomy makes a store with catCount categories of hostsPerCat
// patterns each, none of which match the probe used below.
func buildBenchTaxonomy(catCount, hostsPerCat int) *urlcat.Store {
	entries := make([]*urlcat.Entry, 0, catCount)
	for c := 0; c < catCount; c++ {
		hosts := make([]string, 0, hostsPerCat)
		for h := 0; h < hostsPerCat; h++ {
			hosts = append(hosts, fmt.Sprintf("host%d-%d.vendor%d.example", c, h, c))
		}
		entries = append(entries, &urlcat.Entry{Name: fmt.Sprintf("Cat%d", c), Hosts: hosts})
	}
	s := urlcat.New(entries)
	s.LookupHost("warm.example") // force the lazy index build out of the timed region
	return s
}

// TestBenchGate_CategoryLookupConstantInTaxonomySize locks in the property that
// makes LookupHost safe on the request path: its cost depends on the number of
// labels in the queried host, NOT on how many host patterns the operator has
// configured.
//
// LookupHost used to scan every configured pattern in every category. On the
// SHIPPED default taxonomy (~665 patterns) an unmatched host cost 22.6 us of
// CPU per request — ~200x the entire allow-path policy evaluation — and because
// the cost is proportional to the taxonomy, an operator importing a large
// category feed silently bought proportional per-request latency (10,000
// patterns measured 475 us per request). The reverse index in internal/urlcat
// made it O(labels); this gate is what stops a future edit from quietly
// reintroducing the scan.
//
// TWO assertions, with different strengths:
//
//   - allocs/op == 0 is the hard, hardware-INDEPENDENT half, the same contract
//     the rest of this file's family keys on. The lookup runs per request and
//     must add no GC pressure.
//
//   - The ns/op RATIO is the complexity half. This file's family deliberately
//     avoids absolute ns/op because it is hardware-sensitive and not
//     comparable across runners — but a ratio of two measurements of the SAME
//     operation on the SAME runner cancels machine speed, which is exactly the
//     term that makes absolute ns/op unusable. It is the only way to state an
//     asymptotic property without instrumenting the hot path with a counter,
//     which would cost production complexity to serve a test. The threshold is
//     deliberately loose (4x against an expected ~1x): a genuine regression to
//     the linear scan measures ~107x here, so the gate does not need to be
//     tight to have teeth.
func TestBenchGate_CategoryLookupConstantInTaxonomySize(t *testing.T) {
	const probe = "unmatched.host.customer.example"

	measure := func(s *urlcat.Store) float64 {
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				s.LookupHost(probe)
			}
		})
		if res.AllocsPerOp() != 0 {
			t.Errorf("LookupHost allocated %d allocs/op; want 0 — it runs per "+
				"request and must not add GC pressure", res.AllocsPerOp())
		}
		return float64(res.NsPerOp())
	}

	small := measure(buildBenchTaxonomy(5, 20))   // 100 patterns
	large := measure(buildBenchTaxonomy(50, 200)) // 10,000 patterns — 100x more

	if small <= 0 {
		t.Fatalf("degenerate small-taxonomy measurement: %v ns/op", small)
	}
	ratio := large / small
	t.Logf("LookupHost: 100 patterns = %.1f ns/op, 10,000 patterns = %.1f ns/op (ratio %.2fx)",
		small, large, ratio)

	if ratio > 4 {
		t.Fatalf("LookupHost cost scales with taxonomy size (%.2fx slower for 100x more "+
			"patterns, %.1f -> %.1f ns/op); it must stay O(labels) via the reverse index "+
			"in internal/urlcat, not O(configured hosts)", ratio, small, large)
	}
}
