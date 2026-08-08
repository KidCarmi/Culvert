package urlcat

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// The LookupHost family moved from a nested scan over every configured host
// pattern to a reverse index probed once per label. That is a pure cost change,
// so the tests that matter most are the ones proving the ANSWER did not move:
// referenceLookup below is the exact algorithm the index replaced, and the
// differential tests hold the two against each other over randomized taxonomies.

// referenceLookup is a verbatim transcription of the pre-index implementation.
// adminOnly selects the LookupHostAdmin variant.
func referenceLookup(entries []*Entry, host string, adminOnly bool) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	for _, e := range entries {
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

func assertAgrees(t *testing.T, s *Store, entries []*Entry, host string) {
	t.Helper()
	for _, adminOnly := range []bool{false, true} {
		var gotCat, gotPat string
		var gotOK bool
		if adminOnly {
			gotCat, gotPat, gotOK = s.LookupHostAdmin(host)
		} else {
			gotCat, gotPat, gotOK = s.LookupHost(host)
		}
		wantCat, wantPat, wantOK := referenceLookup(entries, host, adminOnly)
		if gotCat != wantCat || gotPat != wantPat || gotOK != wantOK {
			t.Errorf("host=%q adminOnly=%v: index gave (%q,%q,%v), reference gave (%q,%q,%v)",
				host, adminOnly, gotCat, gotPat, gotOK, wantCat, wantPat, wantOK)
		}
	}
}

// TestLookupIndex_MatchesReferenceOnDefaultTaxonomy runs the shipped default
// taxonomy — the configuration a real deployment starts from.
func TestLookupIndex_MatchesReferenceOnDefaultTaxonomy(t *testing.T) {
	entries := DefaultEntries()
	s := New(entries)

	hosts := []string{
		"facebook.com", "www.facebook.com", "a.b.c.facebook.com",
		"netflix.com", "cdn.netflix.com", "bbc.co.uk", "news.bbc.co.uk",
		"api.internal.corp.example.com", "example.com", "com", "",
		"FACEBOOK.COM", "Facebook.Com.", "notfacebook.com", "facebook.com.evil.tld",
		"x.com", "eicar.org", "sub.sub.sub.twitch.tv",
	}
	for _, e := range entries {
		for _, h := range e.Hosts {
			hosts = append(hosts, h, "deep.sub."+h, strings.ToUpper(h))
		}
	}
	for _, h := range hosts {
		assertAgrees(t, s, entries, h)
	}
}

// TestLookupIndex_MatchesReferenceOnOverlappingCategories is the case the index
// could most plausibly get wrong: one host matching patterns owned by several
// categories at once. The winner must stay the FIRST entry in order, not the
// most specific pattern.
func TestLookupIndex_MatchesReferenceOnOverlappingCategories(t *testing.T) {
	entries := []*Entry{
		// "example.com" here is a broader pattern in an EARLIER entry than the
		// exact "foo.example.com" below — a specificity-ordered index would
		// wrongly prefer the later, more specific one.
		{Name: "Broad", BuiltIn: true, Hosts: []string{"example.com"}},
		{Name: "Specific", BuiltIn: false, Hosts: []string{"foo.example.com"}},
		// Duplicate pattern across entries: earliest entry must win.
		{Name: "DupeLate", BuiltIn: false, Hosts: []string{"example.com", "shared.test"}},
		{Name: "DupeEarlyish", BuiltIn: false, Hosts: []string{"shared.test"}},
		// Two matching patterns inside ONE entry: earliest pattern must win.
		{Name: "Intra", BuiltIn: false, Hosts: []string{"deep.a.test", "a.test"}},
		{Name: "Casing", BuiltIn: false, Hosts: []string{"MixedCase.Example"}},
	}
	s := New(entries)

	for _, h := range []string{
		"example.com", "foo.example.com", "bar.foo.example.com",
		"shared.test", "x.shared.test", "a.test", "deep.a.test", "z.deep.a.test",
		"mixedcase.example", "sub.MIXEDCASE.example",
	} {
		assertAgrees(t, s, entries, h)
	}

	// Pin the specificity trap explicitly, so the intent survives a refactor of
	// the reference helper.
	if cat, _, _ := s.LookupHost("foo.example.com"); cat != "Broad" {
		t.Errorf("first-match ordering broken: want category Broad, got %q", cat)
	}
}

// TestLookupIndex_MatchesReferenceFuzz sweeps randomized taxonomies and hosts.
func TestLookupIndex_MatchesReferenceFuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(20260808))
	labels := []string{"a", "b", "example", "corp", "test", "co", "uk", "com", "MiXeD"}
	pick := func() string { return labels[rng.Intn(len(labels))] }
	randHost := func(maxLabels int) string {
		n := 1 + rng.Intn(maxLabels)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = pick()
		}
		return strings.Join(parts, ".")
	}

	for iter := 0; iter < 300; iter++ {
		nEntries := 1 + rng.Intn(5)
		entries := make([]*Entry, nEntries)
		for i := range entries {
			nHosts := rng.Intn(5)
			hosts := make([]string, nHosts)
			for j := range hosts {
				hosts[j] = randHost(3)
				// Occasionally emit a trailing-dot pattern, the shape where the
				// scan and the forward index deliberately disagree.
				if rng.Intn(10) == 0 {
					hosts[j] += "."
				}
			}
			entries[i] = &Entry{Name: fmt.Sprintf("cat-%d", i), BuiltIn: rng.Intn(2) == 0, Hosts: hosts}
		}
		s := New(entries)
		for probe := 0; probe < 20; probe++ {
			assertAgrees(t, s, entries, randHost(4))
		}
	}
}

// TestLookupIndex_TracksMutations proves the index is rebuilt by every mutator,
// so a lookup never answers from a stale view.
func TestLookupIndex_TracksMutations(t *testing.T) {
	s := New([]*Entry{{Name: "Seed", BuiltIn: false, Hosts: []string{"seed.test"}}})

	if _, _, ok := s.LookupHost("new.test"); ok {
		t.Fatal("unexpected pre-mutation hit")
	}
	if err := s.Set("Added", []string{"new.test"}, false); err != nil {
		t.Fatal(err)
	}
	if cat, _, ok := s.LookupHost("sub.new.test"); !ok || cat != "Added" {
		t.Fatalf("after Set: got (%q,%v), want (Added,true)", cat, ok)
	}

	if err := s.AddHost("Added", "extra.test"); err != nil {
		t.Fatal(err)
	}
	if cat, _, ok := s.LookupHost("extra.test"); !ok || cat != "Added" {
		t.Fatalf("after AddHost: got (%q,%v), want (Added,true)", cat, ok)
	}

	if err := s.RemoveHost("Added", "extra.test"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.LookupHost("extra.test"); ok {
		t.Fatal("after RemoveHost: host still resolves")
	}

	if err := s.Delete("Added"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.LookupHost("new.test"); ok {
		t.Fatal("after Delete: category still resolves")
	}

	s.ReplaceAll([]Entry{{Name: "Fresh", BuiltIn: false, Hosts: []string{"fresh.test"}}})
	if cat, _, ok := s.LookupHost("fresh.test"); !ok || cat != "Fresh" {
		t.Fatalf("after ReplaceAll: got (%q,%v), want (Fresh,true)", cat, ok)
	}
	if _, _, ok := s.LookupHost("seed.test"); ok {
		t.Fatal("after ReplaceAll: superseded entry still resolves")
	}
}

// TestLookupIndex_ConcurrentReadersDuringMutation is the race-detector case.
//
// Readers copy a map header under the lock and then scan it lock-free, which is
// only sound because published maps are immutable — mutators install fresh ones
// instead of editing in place. Under -race this fails if that ever regresses.
func TestLookupIndex_ConcurrentReadersDuringMutation(t *testing.T) {
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
				}
				s.LookupHost("cdn.netflix.com")
				s.LookupHostAdmin("api.internal.corp.example.com")
				s.MatchesHost(Streaming, "sub.youtube.com")
				s.MatchesHostAdmin(Social, "www.facebook.com")
			}
		}()
	}

	s.SetPathForTest("") // keep Save() from touching disk
	for i := 0; i < 200; i++ {
		_ = s.Set("Churn", []string{fmt.Sprintf("h%d.test", i), "netflix.com"}, false)
		_ = s.AddHost("Churn", fmt.Sprintf("extra%d.test", i))
		_ = s.RemoveHost("Churn", fmt.Sprintf("extra%d.test", i))
	}
	close(stop)
	wg.Wait()
}
