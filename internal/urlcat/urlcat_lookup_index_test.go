package urlcat

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// referenceLookup is the pre-index implementation of LookupHost, kept verbatim
// as the equivalence oracle. The reverse index is only a legitimate
// optimization if it returns the SAME (category, matchedBy, ok) triple for
// every input — including the cases where several patterns match one host and
// the scan's iteration order, not specificity, picked the winner.
func referenceLookup(s *Store, host string, adminOnly bool) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if adminOnly && e.BuiltIn {
			continue
		}
		for _, p := range e.Hosts {
			pl := strings.ToLower(p)
			if h == pl || strings.HasSuffix(h, "."+pl) {
				return e.Name, p, true
			}
		}
	}
	return "", "", false
}

func assertSameAsReference(t *testing.T, s *Store, hosts []string) {
	t.Helper()
	for _, h := range hosts {
		wantCat, wantBy, wantOK := referenceLookup(s, h, false)
		gotCat, gotBy, gotOK := s.LookupHost(h)
		if gotCat != wantCat || gotBy != wantBy || gotOK != wantOK {
			t.Errorf("LookupHost(%q) = (%q,%q,%v); reference = (%q,%q,%v)",
				h, gotCat, gotBy, gotOK, wantCat, wantBy, wantOK)
		}

		wantCat, wantBy, wantOK = referenceLookup(s, h, true)
		gotCat, gotBy, gotOK = s.LookupHostAdmin(h)
		if gotCat != wantCat || gotBy != wantBy || gotOK != wantOK {
			t.Errorf("LookupHostAdmin(%q) = (%q,%q,%v); reference = (%q,%q,%v)",
				h, gotCat, gotBy, gotOK, wantCat, wantBy, wantOK)
		}
	}
}

// TestLookupHost_MatchesReferenceOnDefaults walks the shipped taxonomy: every
// configured pattern, a subdomain of it, and a near-miss for each.
func TestLookupHost_MatchesReferenceOnDefaults(t *testing.T) {
	s := New(DefaultEntries())

	var hosts []string
	for _, e := range s.entries {
		for _, p := range e.Hosts {
			hosts = append(hosts,
				p,
				strings.ToUpper(p),
				"deep.sub."+p,
				p+".",
				"not"+p,
				strings.TrimPrefix(p, "a"),
			)
		}
	}
	hosts = append(hosts, "", ".", "..", "example.invalid", "a.b.c.d.e.f")
	assertSameAsReference(t, s, hosts)
}

// TestLookupHost_ScanOrderWinsOverSpecificity is the case a naive host→category
// map gets wrong. "example.com" sits in an EARLIER category than the more
// specific "api.example.com", so the linear scan returned the earlier, broader
// one — and policy decisions depend on that.
func TestLookupHost_ScanOrderWinsOverSpecificity(t *testing.T) {
	s := New([]*Entry{
		{Name: "Broad", Hosts: []string{"example.com"}},
		{Name: "Specific", Hosts: []string{"api.example.com"}},
	})

	cat, by, ok := s.LookupHost("api.example.com")
	if !ok || cat != "Broad" || by != "example.com" {
		t.Fatalf("LookupHost = (%q,%q,%v); want (Broad, example.com, true) — "+
			"the earlier, broader pattern must keep winning", cat, by, ok)
	}
	assertSameAsReference(t, s, []string{"api.example.com", "example.com", "x.api.example.com"})
}

// TestLookupHost_DuplicatePatternKeepsFirstEntry pins the tie-break when the
// SAME pattern appears in two categories.
func TestLookupHost_DuplicatePatternKeepsFirstEntry(t *testing.T) {
	s := New([]*Entry{
		{Name: "First", Hosts: []string{"shared.example", "other.example"}},
		{Name: "Second", Hosts: []string{"shared.example"}},
	})
	if cat, _, _ := s.LookupHost("shared.example"); cat != "First" {
		t.Fatalf("category = %q; want First", cat)
	}
	// Within one entry, the earlier host also wins.
	s2 := New([]*Entry{{Name: "One", Hosts: []string{"example", "a.example"}}})
	if _, by, _ := s2.LookupHost("a.example"); by != "example" {
		t.Fatalf("matchedBy = %q; want example", by)
	}
}

// TestLookupHost_PreservesVerbatimPattern is the admin URL-lookup API contract:
// matchedBy reports the admin's configured casing, not the normalized key.
func TestLookupHost_PreservesVerbatimPattern(t *testing.T) {
	s := New([]*Entry{{Name: "Corp SaaS", Hosts: []string{"Example.COM"}}})
	cat, by, ok := s.LookupHost("www.example.com")
	if !ok || by != "Example.COM" || cat != "Corp SaaS" {
		t.Fatalf("LookupHost = (%q,%q,%v); want (Corp SaaS, Example.COM, true)", cat, by, ok)
	}
}

// TestLookupHostAdmin_SkipsBuiltIn pins the F3b-4 boundary: the admin-only
// lookup must never surface a BuiltIn category, and must fall through to a
// later admin entry that the full lookup would have shadowed.
func TestLookupHostAdmin_SkipsBuiltIn(t *testing.T) {
	s := New([]*Entry{
		{Name: "Seeded", BuiltIn: true, Hosts: []string{"example.com"}},
		{Name: "AdminOwned", Hosts: []string{"api.example.com"}},
	})
	if cat, _, _ := s.LookupHost("api.example.com"); cat != "Seeded" {
		t.Fatalf("LookupHost category = %q; want Seeded", cat)
	}
	cat, by, ok := s.LookupHostAdmin("api.example.com")
	if !ok || cat != "AdminOwned" || by != "api.example.com" {
		t.Fatalf("LookupHostAdmin = (%q,%q,%v); want (AdminOwned, api.example.com, true)", cat, by, ok)
	}
	if _, _, ok := s.LookupHostAdmin("www.example.com"); ok {
		t.Fatal("LookupHostAdmin matched a BuiltIn-only host")
	}
}

// TestLookupHost_InvalidatedByEveryMutator is the correctness half of the lazy
// rebuild: a stale reverse index would keep answering from the pre-mutation
// taxonomy, which for a Delete or RemoveHost means a policy rule keeps matching
// a category the admin just removed.
func TestLookupHost_InvalidatedByEveryMutator(t *testing.T) {
	s := New([]*Entry{{Name: "Base", Hosts: []string{"base.example"}}})

	// Prime the index so every step below starts from a warm, non-stale state.
	if _, _, ok := s.LookupHost("base.example"); !ok {
		t.Fatal("seed lookup missed")
	}

	steps := []struct {
		name  string
		apply func()
		probe string
	}{
		{"AddHost", func() { _ = s.AddHost("Base", "added.example") }, "added.example"},
		{"RemoveHost", func() { _ = s.RemoveHost("Base", "added.example") }, "added.example"},
		{"Set-replace", func() { _ = s.Set("Base", []string{"replaced.example"}, false) }, "replaced.example"},
		{"Set-new", func() { _ = s.Set("Extra", []string{"extra.example"}, false) }, "extra.example"},
		{"Delete", func() { _ = s.Delete("Extra") }, "extra.example"},
		{"ReplaceAll", func() { s.ReplaceAll([]Entry{{Name: "Fresh", Hosts: []string{"fresh.example"}}}) }, "fresh.example"},
	}
	for _, st := range steps {
		st.apply()
		wantCat, wantBy, wantOK := referenceLookup(s, st.probe, false)
		gotCat, gotBy, gotOK := s.LookupHost(st.probe)
		if gotCat != wantCat || gotBy != wantBy || gotOK != wantOK {
			t.Errorf("after %s: LookupHost(%q) = (%q,%q,%v); reference = (%q,%q,%v)",
				st.name, st.probe, gotCat, gotBy, gotOK, wantCat, wantBy, wantOK)
		}
	}
}

// TestLookupHost_ZeroValueStoreBuildsIndex covers the Store built as a struct
// literal instead of through New. Nothing calls rebuildIndex on that path, so
// a "stale" flag defaulting to false would leave the lookup reading a nil index
// and reporting every host as uncategorized — a silent policy change, not a
// crash. The flag is "ready" precisely so the zero value forces a rebuild.
func TestLookupHost_ZeroValueStoreBuildsIndex(t *testing.T) {
	s := &Store{entries: []*Entry{{Name: "Direct", Hosts: []string{"literal.example"}}}}

	cat, by, ok := s.LookupHost("sub.literal.example")
	if !ok || cat != "Direct" || by != "literal.example" {
		t.Fatalf("LookupHost = (%q,%q,%v); want (Direct, literal.example, true)", cat, by, ok)
	}
	assertSameAsReference(t, s, []string{"literal.example", "sub.literal.example", "other.example"})
}

// TestLookupHost_RandomizedDifferential fuzzes taxonomy shapes that hand-written
// cases miss: overlapping suffixes, duplicate patterns across categories, mixed
// BuiltIn flags, and deep label chains.
func TestLookupHost_RandomizedDifferential(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for a reproducible
	// differential test; a crypto/rand source would make a failure impossible
	// to replay, which is the whole point of the oracle comparison.
	rng := rand.New(rand.NewSource(20260819))
	labels := []string{"a", "b", "c", "example", "corp", "net", "com", "api", "cdn"}

	randomHost := func() string {
		n := 1 + rng.Intn(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = labels[rng.Intn(len(labels))]
		}
		return strings.Join(parts, ".")
	}

	for iter := 0; iter < 300; iter++ {
		var entries []*Entry
		for e := 0; e < 1+rng.Intn(5); e++ {
			var hosts []string
			for h := 0; h < 1+rng.Intn(6); h++ {
				p := randomHost()
				if rng.Intn(4) == 0 {
					p = strings.ToUpper(p)
				}
				hosts = append(hosts, p)
			}
			entries = append(entries, &Entry{
				Name:    fmt.Sprintf("Cat%d", e),
				Hosts:   hosts,
				BuiltIn: rng.Intn(2) == 0,
			})
		}
		s := New(entries)

		probes := make([]string, 0, 12)
		for i := 0; i < 12; i++ {
			probes = append(probes, randomHost())
		}
		assertSameAsReference(t, s, probes)
	}
}

// TestLookupHost_ConcurrentWithMutationNoRace exercises the lazy-rebuild
// lock dance (RLock fast path, write-lock rebuild) under -race.
func TestLookupHost_ConcurrentWithMutationNoRace(t *testing.T) {
	s := New(DefaultEntries())
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.LookupHost("api.openai.com")
					s.LookupHostAdmin("nothing.here.example")
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		_ = s.AddHost("AI", fmt.Sprintf("h%d.churn.example", i))
		_ = s.RemoveHost("AI", fmt.Sprintf("h%d.churn.example", i))
	}
	close(stop)
	wg.Wait()

	assertSameAsReference(t, s, []string{"api.openai.com", "nothing.here.example"})
}
