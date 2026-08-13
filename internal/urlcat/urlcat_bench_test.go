package urlcat

import (
	"fmt"
	"testing"
)

// urlcat_bench_test.go — the performance gate for the indexed host → category
// lookup.
//
// LookupHost is reached once per rule per request for any policy rule with a
// destination category GROUP (policy.go categoryGroupMatchesHostRule →
// lookupHostCategory), so its cost is per-request cost. It used to scan every
// configured host in every category. Measured on the shipped taxonomy
// (DefaultEntries: 27 categories / 625 hosts), Go 1.26, Xeon @ 2.80GHz:
//
//	                       before          after
//	miss (common case)   34244 ns/op     184 ns/op    -99.5%
//	hit, late in list    14470 ns/op      94 ns/op    -99.4%
//	hit, early in list    1344 ns/op      87 ns/op    -93.5%
//
// The miss is the shape that matters: an ordinary destination belongs to no
// category, and that was precisely the branch that walked the entire list.
//
// Cost is now O(labels in the hostname) instead of O(hosts configured), so the
// win grows with the taxonomy — which is the direction customers move it, since
// every category they add lengthened the old scan. Measured flat at 198 / 187 /
// 188 ns/op across 1000 / 5000 / 20000 configured hosts, where the old scan
// would have been ~20x apart end to end; that flatness is what
// TestBenchGate_LookupHostConstantInTaxonomySize holds.
//
// Concurrency improves too, because the probe now runs with the store lock
// released rather than holding it for the whole scan: 177 ns/op serial, 62.7
// ns/op at 4x parallel.

// benchStore builds a store with hostCount synthetic hosts spread across ten
// categories, appended AFTER the shipped taxonomy so lookups traverse a
// realistic base first.
func benchStore(hostCount int) *Store {
	entries := DefaultEntries()
	const cats = 10
	for c := 0; c < cats; c++ {
		hosts := make([]string, 0, hostCount/cats)
		for i := 0; i < hostCount/cats; i++ {
			hosts = append(hosts, fmt.Sprintf("host%d-%d.synthetic%d.test", c, i, c))
		}
		entries = append(entries, &Entry{Name: fmt.Sprintf("Synthetic %d", c), Hosts: hosts})
	}
	return New(entries)
}

func BenchmarkLookupHost(b *testing.B) {
	s := New(DefaultEntries())
	cases := []struct{ name, host string }{
		// The dominant production shape: an ordinary destination in no
		// category at all. This walked the ENTIRE list before the index.
		{"miss", "www.some-ordinary-corporate-host.example.com"},
		{"hit_late", "salesforce.com"},
		{"hit_early", "openai.com"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _ = s.LookupHost(c.host)
			}
		})
	}
}

// BenchmarkLookupHost_TaxonomyScale is the shape of the win: the old scan was
// linear in the configured-host count, the index is flat.
func BenchmarkLookupHost_TaxonomyScale(b *testing.B) {
	for _, n := range []int{1000, 5000, 20000} {
		s := benchStore(n)
		b.Run(fmt.Sprintf("hosts=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _ = s.LookupHost("www.some-ordinary-corporate-host.example.com")
			}
		})
	}
}

// BenchmarkLookupHost_Parallel checks the read path scales across cores: the
// probe now runs with the store lock released, so concurrent requests contend
// only on the brief pointer read.
func BenchmarkLookupHost_Parallel(b *testing.B) {
	s := New(DefaultEntries())
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = s.LookupHost("www.some-ordinary-corporate-host.example.com")
		}
	})
}

func BenchmarkLookupHostAdmin(b *testing.B) {
	s := benchStore(5000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = s.LookupHostAdmin("www.some-ordinary-corporate-host.example.com")
	}
}

// TestBenchGate_LookupHostConstantInTaxonomySize is the regression wall.
//
// It deliberately asserts the SHAPE of the cost curve rather than a wall-clock
// threshold: absolute nanoseconds vary with CI hardware and would either flake
// or be set so loose they catch nothing, whereas "does the cost grow with the
// number of configured hosts" is exactly the property that was wrong and is
// hardware-independent. A reversion to any linear scan makes the 20x-larger
// taxonomy roughly 20x slower and fails here.
//
// The bound is generous (4x for a 20x size increase) so it flags a return to
// linearity, not ordinary measurement noise.
func TestBenchGate_LookupHostConstantInTaxonomySize(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}
	const host = "www.some-ordinary-corporate-host.example.com"

	measure := func(hostCount int) float64 {
		s := benchStore(hostCount)
		r := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = s.LookupHost(host)
			}
		})
		return float64(r.NsPerOp())
	}

	small := measure(1000)
	large := measure(20000)
	if small <= 0 {
		t.Skip("benchmark produced no measurable time")
	}
	if ratio := large / small; ratio > 4 {
		t.Errorf("LookupHost cost grew %.1fx for a 20x larger taxonomy "+
			"(%.0f ns/op at 1000 hosts, %.0f ns/op at 20000) — the lookup is scaling "+
			"with the configured-host count again, i.e. it has reverted to a linear scan",
			ratio, small, large)
	}
}

// TestBenchGate_LookupHostAllocs pins the lookup at zero allocations. The old
// scan built a `"."+pattern` temporary per candidate; those stayed on the stack
// as non-escaping, so the allocation count is not where the regression would
// show — but a future change that made the probe allocate would put allocator
// pressure on a per-request path, so it is worth holding at zero.
func TestBenchGate_LookupHostAllocs(t *testing.T) {
	s := New(DefaultEntries())
	for _, host := range []string{
		"www.some-ordinary-corporate-host.example.com", // miss
		"api.openai.com", // suffix hit
		"salesforce.com", // exact hit
	} {
		got := testing.AllocsPerRun(200, func() {
			_, _, _ = s.LookupHost(host)
		})
		if got > 0 {
			t.Errorf("LookupHost(%q) = %.0f allocs/op, want 0", host, got)
		}
	}
}
