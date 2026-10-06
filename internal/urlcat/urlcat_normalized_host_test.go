package urlcat

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// MatchesNormalizedHost / MatchesNormalizedHostAdmin equivalence + cost gates.
//
// These two entry points exist so that package main's hostCatScratch can
// canonicalize ONE request host per rule SCAN instead of once per
// category-scoped rule (policy_hostcat.go normHost()). The membership probe
// itself is unchanged, so the whole deliverable of the split is:
//
//  1. the verdict is EXACTLY what MatchesHost returned, and
//  2. the normalized form really is the expensive part that was removed.
//
// (1) is what these tests pin. It needs no idempotence argument: MatchesHost is
// now a one-line wrapper that normalizes and calls the normalized form, so the
// property under test is that the WRAPPER is faithful — i.e. that nothing in the
// probe depended on the raw input.
//
//	go test -run 'NormalizedHost' ./internal/urlcat/
//	go test -run '^$' -bench 'NormalizedHost' -benchmem ./internal/urlcat/

// normCorpus is the host-shape corpus. Every entry is a shape where raw and
// normalized forms can DIFFER (uppercase, trailing dot, Unicode, ACE, IP
// literal, invalid UTF-8) plus the already-canonical control. A corpus of
// already-canonical hosts only would pass against a broken wrapper, because for
// those two inputs raw == normalized — the sampling trap recorded on CHAOS-69.
func normCorpus() []string {
	return []string{
		"", ".", "example.com", "a.b.example.com",
		"EXAMPLE.COM", "Example.Com", "A.B.EXAMPLE.COM",
		"example.com.", "EXAMPLE.COM.", "a.b.example.com.",
		"xn--bcher-kva.example.com", "XN--BCHER-KVA.example.com",
		"bücher.example.com", "BÜCHER.example.com", "bücher.example.com.",
		"straße.example.com", "ß.example.com", "İ.example.com", "K.example.com",
		"192.0.2.1", "[2001:db8::1]", "2001:DB8::1",
		"host_with_underscore.example.com",
		"\xff\xfe.example.com", "a..b.example.com",
		strings.Repeat("sub.", 20) + "example.com",
		"uncategorized.example.net",
	}
}

// normStore builds a taxonomy whose keys deliberately cover the corpus shapes,
// so the corpus produces HITS as well as misses. A differential over misses
// alone is nearly vacuous: both implementations return false for everything.
func normStore() *Store {
	return New([]*Entry{
		{Name: "Social Media", Hosts: []string{"example.com", "xn--bcher-kva.example.com"}},
		{Name: "Corp Internal", Hosts: []string{"192.0.2.1", "2001:db8::1", "a.b.example.com"}},
		{Name: "MixedCase Admin", Hosts: []string{"EXAMPLE.COM", "straße.example.com"}},
		{Name: "trailing dot", BuiltIn: true, Hosts: []string{"example.com.", "ß.example.com"}},
		{Name: "Empty Seed", BuiltIn: true},
	})
}

func normCategories(s *Store) []Category {
	cats := []Category{"No Such Category", "", "social media", "SOCIAL MEDIA"}
	for _, e := range s.All() {
		cats = append(cats, Category(e.Name))
	}
	return cats
}

// TestMatchesNormalizedHost_AgreesWithMatchesHost is the differential: for every
// (category, host) pair the normalized entry point fed NormalizeHost(host) must
// return exactly what MatchesHost(host) returns.
func TestMatchesNormalizedHost_AgreesWithMatchesHost(t *testing.T) {
	s := normStore()
	hits, checked := 0, 0
	for _, cat := range normCategories(s) {
		for _, h := range normCorpus() {
			checked++
			norm := hostutil.NormalizeHost(h)

			want := s.MatchesHost(cat, h)
			if got := s.MatchesNormalizedHost(cat, norm); got != want {
				t.Errorf("MatchesNormalizedHost(%q, %q /* raw %q */) = %v, MatchesHost = %v",
					cat, norm, h, got, want)
			}
			wantAdmin := s.MatchesHostAdmin(cat, h)
			if got := s.MatchesNormalizedHostAdmin(cat, norm); got != wantAdmin {
				t.Errorf("MatchesNormalizedHostAdmin(%q, %q /* raw %q */) = %v, MatchesHostAdmin = %v",
					cat, norm, h, got, wantAdmin)
			}
			if want {
				hits++
			}
		}
	}
	// Not-vacuous check: a corpus that never matches would pass with the probe
	// deleted entirely.
	if hits == 0 {
		t.Fatalf("differential saw %d pairs and ZERO hits: it cannot fail for a broken probe", checked)
	}
	t.Logf("differential: %d pairs, %d hits", checked, hits)
}

// TestMatchesNormalizedHost_DifferentialIsNotVacuous proves the corpus really
// does contain shapes where raw and normalized differ — i.e. that the test above
// is capable of failing if the wrapper stopped normalizing.
func TestMatchesNormalizedHost_DifferentialIsNotVacuous(t *testing.T) {
	differing := 0
	for _, h := range normCorpus() {
		if hostutil.NormalizeHost(h) != h {
			differing++
		}
	}
	if differing < 8 {
		t.Fatalf("only %d corpus hosts change under NormalizeHost; the differential is near-vacuous", differing)
	}

	// And prove the DEFECT is observable: feeding the RAW host to the normalized
	// entry point must disagree with MatchesHost for at least one pair. This is
	// the misuse the two names exist to prevent, and it is a FAIL-OPEN for a Deny
	// rule — a category whose index keys are canonical misses an uppercase or
	// Unicode host.
	s := normStore()
	disagreements := 0
	for _, cat := range normCategories(s) {
		for _, h := range normCorpus() {
			if hostutil.NormalizeHost(h) == h {
				continue
			}
			if s.MatchesNormalizedHost(cat, h) != s.MatchesHost(cat, h) {
				disagreements++
			}
		}
	}
	if disagreements == 0 {
		t.Fatal("no (cat, host) pair distinguishes raw from normalized input: " +
			"the differential cannot detect a wrapper that stopped normalizing")
	}
	t.Logf("raw-input misuse is observable on %d pairs", disagreements)
}

// TestMatchesNormalizedHost_RandomizedAgreement sweeps generated taxonomies, so
// agreement does not rest on one hand-written store shape.
func TestMatchesNormalizedHost_RandomizedAgreement(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5ca1ab1e))
	frags := []string{"example", "EXAMPLE", "bücher", "straße", "xn--bcher-kva", "a", "B", "com", "NET", ""}
	for iter := 0; iter < 200; iter++ {
		nCat := 1 + rng.Intn(4)
		entries := make([]*Entry, 0, nCat)
		for c := 0; c < nCat; c++ {
			nHost := rng.Intn(4)
			hosts := make([]string, 0, nHost)
			for h := 0; h < nHost; h++ {
				host := frags[rng.Intn(len(frags))] + "." + frags[rng.Intn(len(frags))]
				if rng.Intn(4) == 0 {
					host += "."
				}
				hosts = append(hosts, host)
			}
			entries = append(entries, &Entry{
				Name:    fmt.Sprintf("Cat %d", c),
				BuiltIn: rng.Intn(2) == 0,
				Hosts:   hosts,
			})
		}
		s := New(entries)
		for _, cat := range normCategories(s) {
			for _, h := range normCorpus() {
				norm := hostutil.NormalizeHost(h)
				if got, want := s.MatchesNormalizedHost(cat, norm), s.MatchesHost(cat, h); got != want {
					t.Fatalf("iter %d: MatchesNormalizedHost(%q, %q /* raw %q */) = %v, want %v",
						iter, cat, norm, h, got, want)
				}
				if got, want := s.MatchesNormalizedHostAdmin(cat, norm), s.MatchesHostAdmin(cat, h); got != want {
					t.Fatalf("iter %d: MatchesNormalizedHostAdmin(%q, %q /* raw %q */) = %v, want %v",
						iter, cat, norm, h, got, want)
				}
			}
		}
	}
}

// FuzzMatchesNormalizedHost is the open-ended half of the differential.
func FuzzMatchesNormalizedHost(f *testing.F) {
	s := normStore()
	for _, h := range normCorpus() {
		f.Add("Social Media", h)
		f.Add("MixedCase Admin", h)
	}
	f.Fuzz(func(t *testing.T, cat, host string) {
		norm := hostutil.NormalizeHost(host)
		if got, want := s.MatchesNormalizedHost(Category(cat), norm), s.MatchesHost(Category(cat), host); got != want {
			t.Fatalf("MatchesNormalizedHost(%q, %q /* raw %q */) = %v, want %v", cat, norm, host, got, want)
		}
		if got, want := s.MatchesNormalizedHostAdmin(Category(cat), norm), s.MatchesHostAdmin(Category(cat), host); got != want {
			t.Fatalf("MatchesNormalizedHostAdmin(%q, %q /* raw %q */) = %v, want %v", cat, norm, host, got, want)
		}
	})
}

// TestBenchGate_MatchesNormalizedHostIsAllocationFree keeps the new entry points
// inside the allocation contract the probe already had. STRUCTURAL via
// AllocsPerRun, not a timing bound, so it cannot flake on a loaded runner or
// under -race.
func TestBenchGate_MatchesNormalizedHostIsAllocationFree(t *testing.T) {
	s := New(DefaultEntries())
	mixed := ""
	for _, e := range DefaultEntries() {
		if e.Name != strings.ToLower(e.Name) {
			mixed = e.Name
			break
		}
	}
	if mixed == "" {
		t.Fatal("shipped taxonomy has no mixed-case category name; gate would be vacuous")
	}
	hit := New([]*Entry{{Name: "Social Media", Hosts: []string{"example.com"}}})

	cases := []struct {
		name string
		fn   func()
	}{
		{"miss", func() { s.MatchesNormalizedHost(Category(mixed), "uncategorized.example.net") }},
		{"unknown-category", func() { s.MatchesNormalizedHost("No Such Category", "uncategorized.example.net") }},
		{"admin-miss", func() { s.MatchesNormalizedHostAdmin(Category(mixed), "uncategorized.example.net") }},
		{"hit-exact", func() { hit.MatchesNormalizedHost("Social Media", "example.com") }},
		{"hit-subdomain", func() { hit.MatchesNormalizedHost("Social Media", "a.b.example.com") }},
		{"empty-host", func() { s.MatchesNormalizedHost(Category(mixed), "") }},
	}
	for _, tc := range cases {
		if got := testing.AllocsPerRun(200, tc.fn); got != 0 {
			t.Errorf("%s: %v allocs/op, want 0", tc.name, got)
		}
	}
}

// legacyMatchesHost is a VERBATIM copy of MatchesHost's PRE-SPLIT body:
// normalization and probe fused in one function, reaching nothing that this
// change introduced. It is the baseline for the cost gate and for the _Legacy
// benchmark arm.
//
// It must NOT delegate to either shipped entry point, and that is the whole
// reason it exists. The first version of the cost gate used MatchesHost as its
// baseline, which is circular: MatchesHost is now DEFINED as
// "normalize, then call MatchesNormalizedHost", so a mutation that put the
// normalization back INSIDE MatchesNormalizedHost made the baseline normalize
// twice and the gate still read the probe as cheaper. The gate passed against
// the exact regression it exists to catch (verified by mutation). A frozen copy
// cannot move when the code under test moves.
func legacyMatchesHost(s *Store, cat Category, host string) bool {
	host = hostutil.NormalizeHost(host)
	var keyBuf [maxInlineCategoryKey]byte
	inlineKey, strKey, inlineOK := categoryKey(keyBuf[:], string(cat))

	s.mu.RLock()
	var hostSet map[string]bool
	if inlineOK {
		hostSet = s.index[string(inlineKey)]
	} else {
		hostSet = s.index[strKey]
	}
	s.mu.RUnlock()

	if hostSet == nil {
		return false
	}
	if hostSet[host] {
		return true
	}
	for i, ch := range host {
		if ch == '.' && hostSet[host[i+1:]] {
			return true
		}
	}
	return false
}

// TestLegacyMatchesHost_StillMatchesTheShippedWrapper keeps the frozen baseline
// honest: it must agree with MatchesHost on the whole corpus. A baseline that
// drifted from the code it is supposed to represent would make the cost gate
// measure two unrelated functions.
func TestLegacyMatchesHost_StillMatchesTheShippedWrapper(t *testing.T) {
	s := normStore()
	for _, cat := range normCategories(s) {
		for _, h := range normCorpus() {
			if got, want := legacyMatchesHost(s, cat, h), s.MatchesHost(cat, h); got != want {
				t.Fatalf("frozen baseline drifted: legacyMatchesHost(%q, %q) = %v, MatchesHost = %v",
					cat, h, got, want)
			}
		}
	}
}

// TestBenchGate_NormalizedEntryPointIsCheaperThanNormalizing is the COST gate,
// and it is a same-run RATIO rather than an absolute bound: both arms are timed
// in one process on one machine, so the clock cancels. An absolute ns bound gets
// re-baselined per machine and then muted (the standing rule recorded for
// sanitizeLog, connlimit and the latency histogram).
//
// It asserts only the DIRECTION and a conservative margin: skipping
// hostutil.NormalizeHost must make the probe materially cheaper. The margin is
// deliberately loose (10%) because the point is that the saving exists and is
// not noise, not that it equals any particular figure — the figures belong in
// the benchmark output.
func TestBenchGate_NormalizedEntryPointIsCheaperThanNormalizing(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	s := New(DefaultEntries())
	cat := Category("Social Media")
	const host = "uncategorized.example.net"

	// Best-of-N on both arms, interleaved, to blunt scheduler noise. Taking the
	// MINIMUM of each arm is the right statistic for "how cheap can this be":
	// the maximum is set by preemption, which is not a property of the code.
	measure := func(fn func()) float64 {
		best := -1.0
		for trial := 0; trial < 4; trial++ {
			r := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					fn()
				}
			})
			ns := float64(r.NsPerOp())
			if best < 0 || ns < best {
				best = ns
			}
		}
		return best
	}

	var sink bool
	// Baseline is the FROZEN pre-split body, never MatchesHost — see
	// legacyMatchesHost for why that distinction is load-bearing.
	withNorm := measure(func() { sink = legacyMatchesHost(s, cat, host) })
	preNorm := measure(func() { sink = s.MatchesNormalizedHost(cat, host) })
	_ = sink

	t.Logf("legacy (fused normalize+probe) %.1f ns/op; MatchesNormalizedHost %.1f ns/op; ratio %.2f",
		withNorm, preNorm, preNorm/withNorm)
	if preNorm >= withNorm*0.90 {
		t.Errorf("pre-normalized probe is not materially cheaper: %.1f vs %.1f ns/op (ratio %.2f, want < 0.90). "+
			"If hostutil.NormalizeHost became free this gate is obsolete — delete it rather than loosening it, "+
			"and revisit normHost() in policy_hostcat.go, which exists only for this saving.",
			preNorm, withNorm, preNorm/withNorm)
	}
}

// BenchmarkStoreMatchesNormalizedHost_Miss / _Legacy are the same-run before/after
// pair. The _Legacy arm is the PRE-SPLIT call shape (raw host, normalization
// inside the probe), kept in-tree so the comparison stays reproducible rather
// than living in a commit message — the convention established by
// BenchmarkPolicyDecisionLine_Legacy and the CheckRequestURL benchmarks.
//
//	go test -run '^$' -bench 'MatchesNormalizedHost' -benchmem -cpu 1,2,4 ./internal/urlcat/
func BenchmarkStoreMatchesNormalizedHost_Miss(b *testing.B) {
	s := New(DefaultEntries())
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if s.MatchesNormalizedHost(cat, host) {
			b.Fatal("unexpected match")
		}
	}
}

func BenchmarkStoreMatchesNormalizedHost_MissLegacy(b *testing.B) {
	s := New(DefaultEntries())
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if legacyMatchesHost(s, cat, host) {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkStoreMatchesNormalizedHost_Parallel is the concurrency arm. It is the
// instrument for the residual this change deliberately does NOT close: both
// probes still take s.mu.RLock once per call. A CPU profile of the pre-split
// miss path attributed only ~9% to RLock/RUnlock against ~31% to
// NormalizeHost and ~38% to the suffix walk, and the measured parallel curve was
// roughly flat (~126 -> ~141 ns/op from 1 to 4 cores, noise-dominated) rather
// than the throughput ceiling the earlier note predicted — so the lock is a real
// but second-order term here, not the bound. Read this against core count before
// reshaping the lock.
func BenchmarkStoreMatchesNormalizedHost_Parallel(b *testing.B) {
	s := New(DefaultEntries())
	cat := benchCategoryName(b)
	const host = "uncategorized.example.net"
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Each worker keeps its OWN sink: a shared package-level sink turns
		// false sharing into the thing being measured.
		var sink bool
		for pb.Next() {
			sink = s.MatchesNormalizedHost(cat, host)
		}
		_ = sink
	})
}
