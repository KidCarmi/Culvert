package urlcat

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// Regression gates for the ContentFingerprint memo (security review
// 2026-08-21). Two properties are pinned here, and they pull in opposite
// directions — which is exactly why both are needed:
//
//	COST      AddHost must stay flat in taxonomy size. It is the ONE mutation
//	          path that folds incrementally (addHostToIndexes) precisely
//	          because the legacy SaaS feed merge calls it once per merged host
//	          while holding the write lock every category lookup on the
//	          request path contends on. An eager per-AddHost hash of the whole
//	          taxonomy reintroduced the O(hosts × patterns) stall that fold
//	          exists to avoid.
//	FRESHNESS Making the fingerprint lazy must not make it stale. The value is
//	          pinned by the policy-learning category epoch, so a memo that
//	          survived a taxonomy edit would report recommendations FRESH
//	          against a taxonomy their evidence was never observed under —
//	          an evidence-integrity failure, not a performance one.

// costTaxonomy builds a taxonomy of cats categories with hostsPer hosts each.
func costTaxonomy(cats, hostsPer int) []*Entry {
	out := make([]*Entry, 0, cats)
	for c := range cats {
		hs := make([]string, 0, hostsPer)
		for h := range hostsPer {
			hs = append(hs, fmt.Sprintf("h%d-%d.cost.example", c, h))
		}
		out = append(out, &Entry{Name: fmt.Sprintf("Cat%d", c), Hosts: hs})
	}
	return out
}

// allocsPerAddHost returns the mean heap allocations of one AddHost call on a
// store of the given shape. Allocation COUNT is the machine-independent
// signal: the eager hash allocated a map + a slice per taxonomy ENTRY on
// every call, so it scales with the store; the incremental fold does not.
func allocsPerAddHost(cats, hostsPer, n int) float64 {
	s := New(costTaxonomy(cats, hostsPer)) // path == "" ⇒ Save() is a no-op
	// Warm the memo so a lazy implementation cannot get credit for simply not
	// having been read yet: this is the steady state a live node runs in.
	_ = s.ContentFingerprint()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range n {
		_ = s.AddHost("Cat0", fmt.Sprintf("new%d.cost.example", i))
	}
	runtime.ReadMemStats(&after)
	return float64(after.Mallocs-before.Mallocs) / float64(n)
}

// TestFingerprint_AddHostCostIsFlatInTaxonomySize is the cost gate. It is a
// RATIO, not an absolute threshold, so it is machine-independent: the same
// AddHost call is measured against a small and a large taxonomy, and the
// large one must not cost meaningfully more. Measured on the pre-fix tree the
// ratio was ~20x (the eager hash dominated); with the incremental fold it is
// ~1x.
func TestFingerprint_AddHostCostIsFlatInTaxonomySize(t *testing.T) {
	if testing.Short() {
		t.Skip("cost gate: allocation measurement is slow under -short")
	}
	const iterations = 300
	small := allocsPerAddHost(5, 10, iterations)    // 50 patterns
	large := allocsPerAddHost(200, 500, iterations) // 100k patterns, 40x the entries
	if small <= 0 {
		t.Fatalf("no allocations measured for the small taxonomy (%v) — the gate cannot compare", small)
	}
	const maxRatio = 4.0
	if ratio := large / small; ratio > maxRatio {
		t.Fatalf("AddHost allocation cost scales with taxonomy size: %.1f allocs/op at 100k patterns vs %.1f at 50 (%.1fx, bound %.1fx).\n"+
			"AddHost holds the urlcat WRITE lock, and the SaaS feed merge calls it once per merged host — an O(taxonomy) step here stalls every "+
			"category-scoped policy evaluation on the request path once per added host.",
			large, small, ratio, maxRatio)
	}
}

// TestFingerprint_WarmMemoStillSeesEveryMutation is the freshness half of the
// gate: with the memo already populated, EVERY semantic mutation kind must
// still produce a different fingerprint on the next read. A memo keyed on
// anything that a mutation fails to advance would pass the cost gate above
// and silently break the category-epoch staleness contract.
func TestFingerprint_WarmMemoStillSeesEveryMutation(t *testing.T) {
	s := New([]*Entry{{Name: "Dev", Hosts: []string{"git.lab"}}})
	seen := map[string]string{}
	step := func(label string, mutate func()) {
		warm := s.ContentFingerprint() // populate the memo BEFORE mutating
		mutate()
		got := s.ContentFingerprint()
		if got == warm {
			t.Fatalf("%s: fingerprint unchanged (%q) after a semantic mutation — a warm memo outlived the change it must invalidate", label, got)
		}
		if prev, dup := seen[got]; dup {
			t.Fatalf("%s: fingerprint %q collides with %s", label, got, prev)
		}
		seen[got] = label
	}
	step("AddHost", func() { _ = s.AddHost("Dev", "wiki.lab") })
	step("RemoveHost", func() { _ = s.RemoveHost("Dev", "git.lab") })
	step("Set(new category)", func() { _ = s.Set("Finance", []string{"bank.lab"}, false) })
	step("Set(existing category)", func() { _ = s.Set("Dev", []string{"wiki.lab", "ci.lab"}, false) })
	step("Delete", func() { _ = s.Delete("Finance") })
	step("ReplaceAll", func() {
		s.ReplaceAll([]Entry{{Name: "Only", Hosts: []string{"only.lab"}}})
	})
}

// TestFingerprint_ConcurrentReadersNeverSeeAThirdValue pins the memo's
// consistency under concurrency: a writer toggles the taxonomy between two
// states, so every concurrent read must return one of those two fingerprints.
// A memo published against the wrong revision — or a hash computed over a
// half-applied mutation — would surface here as a value belonging to neither
// state. Run under -race for the data-race half.
func TestFingerprint_ConcurrentReadersNeverSeeAThirdValue(t *testing.T) {
	s := New([]*Entry{{Name: "Dev", Hosts: []string{"git.lab"}}})
	stateA := s.ContentFingerprint()
	if err := s.AddHost("Dev", "wiki.lab"); err != nil {
		t.Fatal(err)
	}
	stateB := s.ContentFingerprint()
	if err := s.RemoveHost("Dev", "wiki.lab"); err != nil {
		t.Fatal(err)
	}
	if got := s.ContentFingerprint(); got != stateA {
		t.Fatalf("setup: A→B→A did not restore the fingerprint (%q != %q)", got, stateA)
	}

	stop := make(chan struct{})
	var writer, readers sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = s.AddHost("Dev", "wiki.lab")
			_ = s.RemoveHost("Dev", "wiki.lab")
		}
	}()
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 2000; i++ {
				got := s.ContentFingerprint()
				if got != stateA && got != stateB {
					t.Errorf("concurrent read returned %q, which is neither taxonomy state (%q / %q)", got, stateA, stateB)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}
