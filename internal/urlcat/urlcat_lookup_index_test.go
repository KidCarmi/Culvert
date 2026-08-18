package urlcat

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// The reverse host index replaced a nested scan over every pattern of every
// category. That was a COST change only — the winner it picks must be the same
// one the scan picked, including the non-obvious cases:
//
//   - a LESS specific pattern in an EARLIER category outranks a more specific
//     pattern in a later one (a plain most-specific-suffix walk inverts this),
//   - within the winning category, the FIRST matching pattern in Hosts order is
//     the one reported as matchedBy,
//   - matchedBy is the admin's verbatim configured string, not a normalized
//     form.
//
// referenceLookup is the algorithm as it stood before the index, kept verbatim
// so the tests below compare against the real thing rather than a paraphrase.
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

func assertSameLookup(t *testing.T, s *Store, host string) {
	t.Helper()
	wantCat, wantBy, wantOK := referenceLookup(s.entries, host, false)
	gotCat, gotBy, gotOK := s.LookupHost(host)
	if gotCat != wantCat || gotBy != wantBy || gotOK != wantOK {
		t.Errorf("LookupHost(%q) = (%q, %q, %v); reference scan = (%q, %q, %v)",
			host, gotCat, gotBy, gotOK, wantCat, wantBy, wantOK)
	}
	wantCat, wantBy, wantOK = referenceLookup(s.entries, host, true)
	gotCat, gotBy, gotOK = s.LookupHostAdmin(host)
	if gotCat != wantCat || gotBy != wantBy || gotOK != wantOK {
		t.Errorf("LookupHostAdmin(%q) = (%q, %q, %v); reference scan = (%q, %q, %v)",
			host, gotCat, gotBy, gotOK, wantCat, wantBy, wantOK)
	}
}

// TestLookupIndex_MatchesReferenceScan pins the hand-picked shapes where an
// index could plausibly diverge from the scan.
func TestLookupIndex_MatchesReferenceScan(t *testing.T) {
	cases := []struct {
		name    string
		entries []*Entry
		hosts   []string
	}{
		{
			name: "earlier broad pattern beats later specific one",
			entries: []*Entry{
				{Name: "Broad", Hosts: []string{"example.com"}},
				{Name: "Specific", Hosts: []string{"foo.example.com"}},
			},
			hosts: []string{"foo.example.com", "a.foo.example.com", "example.com", "bar.example.com"},
		},
		{
			name: "first matching pattern within the winning entry wins",
			entries: []*Entry{
				{Name: "Multi", Hosts: []string{"example.com", "foo.example.com"}},
			},
			hosts: []string{"foo.example.com"},
		},
		{
			name: "specific pattern listed after the broad one in the same entry",
			entries: []*Entry{
				{Name: "Multi", Hosts: []string{"foo.example.com", "example.com"}},
			},
			hosts: []string{"foo.example.com", "bar.example.com"},
		},
		{
			name: "duplicate pattern across categories resolves to the earlier one",
			entries: []*Entry{
				{Name: "First", Hosts: []string{"dup.example"}},
				{Name: "Second", Hosts: []string{"dup.example"}},
			},
			hosts: []string{"dup.example", "x.dup.example"},
		},
		{
			name: "built-in ahead of admin: differs between the two lookups",
			entries: []*Entry{
				{Name: "Builtin", BuiltIn: true, Hosts: []string{"example.com"}},
				{Name: "Admin", Hosts: []string{"foo.example.com"}},
			},
			hosts: []string{"foo.example.com", "example.com"},
		},
		{
			name: "matchedBy reports the verbatim configured pattern",
			entries: []*Entry{
				{Name: "Mixed", Hosts: []string{"ExAmPlE.CoM"}},
			},
			hosts: []string{"example.com", "sub.EXAMPLE.com"},
		},
		{
			name: "trailing-dot pattern is not matched (pre-index behavior)",
			entries: []*Entry{
				{Name: "Dotted", Hosts: []string{"example.com."}},
				{Name: "Plain", Hosts: []string{"other.example"}},
			},
			hosts: []string{"example.com", "sub.example.com", "other.example"},
		},
		{
			name: "empty pattern",
			entries: []*Entry{
				{Name: "Empty", Hosts: []string{""}},
				{Name: "Real", Hosts: []string{"example.com"}},
			},
			hosts: []string{"example.com", "a.b.example.com"},
		},
		{
			name:    "empty store",
			entries: []*Entry{},
			hosts:   []string{"example.com", "", "."},
		},
		{
			name: "single-label host and pattern",
			entries: []*Entry{
				{Name: "TLD", Hosts: []string{"invalid"}},
			},
			hosts: []string{"invalid", "host.invalid", "notinvalid"},
		},
		{
			name: "unicode host resolves through IDNA normalization",
			entries: []*Entry{
				{Name: "IDN", Hosts: []string{"xn--bcher-kva.example"}},
			},
			hosts: []string{"bücher.example", "www.bücher.example", "xn--bcher-kva.example"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.entries)
			for _, h := range tc.hosts {
				assertSameLookup(t, s, h)
			}
		})
	}
}

// TestLookupIndex_MatchesReferenceScanRandomized is the broader net: random
// taxonomies with heavy pattern overlap, probed with hosts drawn from the same
// label pool so hits and misses are both common.
func TestLookupIndex_MatchesReferenceScanRandomized(t *testing.T) {
	rng := rand.New(rand.NewSource(20260818))
	labels := []string{"a", "b", "c", "example", "com", "net", "corp", "invalid"}

	randHost := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = labels[rng.Intn(len(labels))]
		}
		return strings.Join(parts, ".")
	}

	for iter := 0; iter < 200; iter++ {
		entries := make([]*Entry, 0, 6)
		for c := 0; c < 1+rng.Intn(5); c++ {
			hosts := make([]string, 0, 5)
			for h := 0; h < rng.Intn(5); h++ {
				hosts = append(hosts, randHost(1+rng.Intn(3)))
			}
			entries = append(entries, &Entry{
				Name:    fmt.Sprintf("Cat%d", c),
				Hosts:   hosts,
				BuiltIn: rng.Intn(2) == 0,
			})
		}
		s := New(entries)
		for probe := 0; probe < 10; probe++ {
			assertSameLookup(t, s, randHost(1+rng.Intn(4)))
		}
	}
}

// TestLookupIndex_TracksMutations proves the index is rebuilt by every mutator,
// including the ones that shift entry positions. A stale positional index would
// resolve to the wrong category — or panic on an out-of-range entry — so this is
// the safety net for folding the mutators onto rebuildIndex.
func TestLookupIndex_TracksMutations(t *testing.T) {
	s := New([]*Entry{
		{Name: "First", Hosts: []string{"first.example"}},
		{Name: "Second", Hosts: []string{"second.example"}},
		{Name: "Third", Hosts: []string{"third.example"}},
	})

	check := func(step string, hosts ...string) {
		t.Helper()
		for _, h := range hosts {
			wantCat, wantBy, wantOK := referenceLookup(s.entries, h, false)
			gotCat, gotBy, gotOK := s.LookupHost(h)
			if gotCat != wantCat || gotBy != wantBy || gotOK != wantOK {
				t.Errorf("after %s: LookupHost(%q) = (%q, %q, %v); want (%q, %q, %v)",
					step, h, gotCat, gotBy, gotOK, wantCat, wantBy, wantOK)
			}
		}
	}

	probes := []string{"first.example", "second.example", "third.example", "added.example", "x.second.example"}
	check("build", probes...)

	if err := s.Delete("First"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	check("Delete", probes...)

	if err := s.AddHost("Third", "added.example"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	check("AddHost", probes...)

	if err := s.RemoveHost("Second", "second.example"); err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	check("RemoveHost", probes...)

	if err := s.Set("Second", []string{"reset.example"}, false); err != nil {
		t.Fatalf("Set existing: %v", err)
	}
	check("Set existing", append(probes, "reset.example")...)

	if err := s.Set("Fourth", []string{"fourth.example"}, false); err != nil {
		t.Fatalf("Set new: %v", err)
	}
	check("Set new", append(probes, "reset.example", "fourth.example")...)

	if err := s.Delete("Fourth"); err != nil {
		t.Fatalf("Delete new: %v", err)
	}
	check("Delete new", append(probes, "reset.example", "fourth.example")...)
}

// TestLookupIndex_ShippedTaxonomyUnchanged runs the whole default taxonomy
// through both implementations: every configured pattern, each of its
// subdomains, and a set of misses. This is the regression that matters in
// practice — the shipped categories are what a fresh install evaluates.
func TestLookupIndex_ShippedTaxonomyUnchanged(t *testing.T) {
	s := New(DefaultEntries())
	probes := []string{"www.example.com", "no-such-host.invalid", "com", ""}
	for _, e := range s.entries {
		for _, p := range e.Hosts {
			probes = append(probes, p, "www."+p, "a.b."+p, strings.ToUpper(p))
		}
	}
	for _, h := range probes {
		assertSameLookup(t, s, h)
	}
}

// TestLookupIndex_ConcurrentReadsDuringMutation is the race-detector target:
// the reverse index is swapped wholesale under the write lock while readers
// dereference s.entries by position under the read lock, so a reader must never
// observe an index that outlives the slice it indexes.
func TestLookupIndex_ConcurrentReadsDuringMutation(t *testing.T) {
	s := New(DefaultEntries())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			name := fmt.Sprintf("Churn%d", i%4)
			_ = s.Set(name, []string{fmt.Sprintf("churn-%d.invalid", i)}, false)
			_ = s.Delete(name)
		}
	}()
	for i := 0; i < 4000; i++ {
		s.LookupHost("www.facebook.com")
		s.LookupHostAdmin("churn-1.invalid")
	}
	<-done
}
