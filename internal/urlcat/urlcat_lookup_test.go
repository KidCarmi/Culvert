package urlcat

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// urlcat_lookup_test.go — the correctness wall for the indexed LookupHost /
// LookupHostAdmin.
//
// These lookups resolve host → category on the policy hot path (a rule with a
// destination category GROUP reaches them once per rule per request), so the
// index replaced a linear scan for speed. A speed change is only admissible if
// the ANSWER is identical, and "identical" here has a sharp edge: the scan
// returned the first pattern it REACHED, not the most specific one. The oracle
// below is the pre-index implementation kept verbatim; if it and the index ever
// disagree, the optimization changed a policy decision and must be reverted —
// not the test relaxed.

// referenceLookupHost is the pre-index LookupHost, kept verbatim as the oracle.
func referenceLookupHost(s *Store, host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		for _, p := range e.Hosts {
			pl := strings.ToLower(p)
			if h == pl || strings.HasSuffix(h, "."+pl) {
				return e.Name, p, true
			}
		}
	}
	return "", "", false
}

// referenceLookupHostAdmin is the pre-index LookupHostAdmin, kept verbatim.
func referenceLookupHostAdmin(s *Store, host string) (category, matchedBy string, ok bool) {
	h := hostutil.NormalizeHost(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.BuiltIn {
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

// lookupOracleStores spans the shapes where a map probe could plausibly diverge
// from a linear scan: declaration order vs. specificity, duplicated patterns,
// mixed casing on both the category name and the pattern, and the empty
// pattern.
func lookupOracleStores() map[string]*Store {
	return map[string]*Store{
		// The tie-break case. The scan reaches the BROADER pattern first and
		// answers "Broad" even for a host the later, more specific pattern also
		// matches. Probing the exact host before its suffixes would answer
		// "Specific" — a different category, hence a different policy decision.
		"broad_declared_first": New([]*Entry{
			{Name: "Broad", Hosts: []string{"example.com"}},
			{Name: "Specific", Hosts: []string{"foo.example.com"}},
		}),
		// The same two patterns in the opposite order, where first-reached and
		// most-specific happen to agree.
		"specific_declared_first": New([]*Entry{
			{Name: "Specific", Hosts: []string{"foo.example.com"}},
			{Name: "Broad", Hosts: []string{"example.com"}},
		}),
		// Three levels, deliberately shuffled so no single ordering rule
		// (declaration, length, specificity) explains all three answers.
		"three_levels_shuffled": New([]*Entry{
			{Name: "Mid", Hosts: []string{"b.example.com"}},
			{Name: "Root", Hosts: []string{"example.com"}},
			{Name: "Leaf", Hosts: []string{"a.b.example.com"}},
		}),
		// The same pattern claimed by two categories: the scan answers with the
		// first, so the index must keep the lowest rank and not the last write.
		"duplicate_pattern": New([]*Entry{
			{Name: "First", Hosts: []string{"dup.example.com"}},
			{Name: "Second", Hosts: []string{"dup.example.com"}},
		}),
		// Casing on both sides — the pattern is lowercased for comparison but
		// returned verbatim, and the category name is returned verbatim too.
		"mixed_case": New([]*Entry{
			{Name: "Social Media", Hosts: []string{"Facebook.COM", "X.com"}},
		}),
		// An empty host string is accepted by Set/ReplaceAll, so the index must
		// handle the key it produces rather than assuming non-empty patterns.
		"empty_pattern": New([]*Entry{
			{Name: "Empty", Hosts: []string{""}},
			{Name: "Real", Hosts: []string{"example.com"}},
		}),
		// BuiltIn interleaved with admin entries, so LookupHostAdmin's skip has
		// to preserve relative order among the entries it does consider.
		"builtin_interleaved": New([]*Entry{
			{Name: "SeedBroad", BuiltIn: true, Hosts: []string{"example.com"}},
			{Name: "AdminBroad", Hosts: []string{"example.com"}},
			{Name: "AdminLeaf", Hosts: []string{"a.example.com"}},
		}),
		// The shipped production taxonomy.
		"default_entries": New(DefaultEntries()),
	}
}

// lookupOracleHosts spans exact hits, suffix hits at every depth, misses, and
// the inputs the normalizer collapses.
var lookupOracleHosts = []string{
	"example.com",
	"foo.example.com",
	"a.b.example.com",
	"b.example.com",
	"deep.a.b.example.com",
	"notexample.com",
	"example.com.evil.test",
	"dup.example.com",
	"sub.dup.example.com",
	"facebook.com",
	"www.facebook.com",
	"FACEBOOK.com",
	"x.com",
	"example.com.",
	"example.com:443",
	"",
	".",
	"com",
	"single",
	"192.0.2.10",
	"[2001:db8::1]",
	"xn--bcher-kva.example",
	"bücher.example",
	"openai.com",
	"api.openai.com",
	"salesforce.com",
	"www.some-ordinary-corporate-host.example.com",
}

func TestLookupHost_MatchesReferenceScan(t *testing.T) {
	for storeName, s := range lookupOracleStores() {
		for _, host := range lookupOracleHosts {
			wantCat, wantPat, wantOK := referenceLookupHost(s, host)
			gotCat, gotPat, gotOK := s.LookupHost(host)
			if gotCat != wantCat || gotPat != wantPat || gotOK != wantOK {
				t.Errorf("LookupHost(%q) in %s = (%q, %q, %v), reference scan = (%q, %q, %v)",
					host, storeName, gotCat, gotPat, gotOK, wantCat, wantPat, wantOK)
			}
		}
	}
}

func TestLookupHostAdmin_MatchesReferenceScan(t *testing.T) {
	for storeName, s := range lookupOracleStores() {
		for _, host := range lookupOracleHosts {
			wantCat, wantPat, wantOK := referenceLookupHostAdmin(s, host)
			gotCat, gotPat, gotOK := s.LookupHostAdmin(host)
			if gotCat != wantCat || gotPat != wantPat || gotOK != wantOK {
				t.Errorf("LookupHostAdmin(%q) in %s = (%q, %q, %v), reference scan = (%q, %q, %v)",
					host, storeName, gotCat, gotPat, gotOK, wantCat, wantPat, wantOK)
			}
		}
	}
}

// TestLookupHost_DeclarationOrderBeatsSpecificity states the tie-break the
// oracle enforces as a standalone assertion, so the intended semantics survive
// even if the oracle were ever deleted. This is the case a naive
// exact-probe-then-suffix index gets wrong.
func TestLookupHost_DeclarationOrderBeatsSpecificity(t *testing.T) {
	s := New([]*Entry{
		{Name: "Broad", Hosts: []string{"example.com"}},
		{Name: "Specific", Hosts: []string{"foo.example.com"}},
	})
	cat, pat, ok := s.LookupHost("foo.example.com")
	if !ok || cat != "Broad" || pat != "example.com" {
		t.Fatalf("LookupHost(foo.example.com) = (%q, %q, %v); want the FIRST-DECLARED "+
			"pattern (Broad/example.com), not the more specific later one", cat, pat, ok)
	}
}

// TestLookupHost_TracksMutations proves the index is republished by every
// mutator. A stale index here would keep enforcing a category the admin already
// changed — the failure mode the copy-on-write conversion has to rule out.
func TestLookupHost_TracksMutations(t *testing.T) {
	s := New([]*Entry{{Name: "AI", Hosts: []string{"openai.com"}}})

	assert := func(step, host, wantCat string) {
		t.Helper()
		gotCat, _, ok := s.LookupHost(host)
		if wantCat == "" {
			if ok {
				t.Fatalf("after %s: LookupHost(%q) = %q, want no match", step, host, gotCat)
			}
			return
		}
		if !ok || gotCat != wantCat {
			t.Fatalf("after %s: LookupHost(%q) = (%q, %v), want %q", step, host, gotCat, ok, wantCat)
		}
	}

	assert("new", "chat.openai.com", "AI")
	assert("new", "slack.com", "")

	if err := s.AddHost("AI", "slack.com"); err != nil {
		t.Fatalf("AddHost: %v", err)
	}
	assert("AddHost", "slack.com", "AI")

	if err := s.RemoveHost("AI", "slack.com"); err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
	assert("RemoveHost", "slack.com", "")

	if err := s.Set("Chat", []string{"discord.com"}, false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	assert("Set", "voice.discord.com", "Chat")

	if err := s.Set("AI", []string{"anthropic.com"}, false); err != nil {
		t.Fatalf("Set replace: %v", err)
	}
	assert("Set replace", "chat.openai.com", "")
	assert("Set replace", "api.anthropic.com", "AI")

	if err := s.Delete("Chat"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assert("Delete", "voice.discord.com", "")

	s.ReplaceAll([]Entry{{Name: "News", Hosts: []string{"bbc.com"}}})
	assert("ReplaceAll", "www.bbc.com", "News")
	assert("ReplaceAll", "api.anthropic.com", "")
}

// TestLookupHostAdmin_IgnoresBuiltIn pins the BuiltIn filter surviving the
// index conversion: the signed-feed cutover depends on the built-in taxonomy
// being invisible to the admin lookup.
func TestLookupHostAdmin_IgnoresBuiltIn(t *testing.T) {
	s := New([]*Entry{
		{Name: "Seed", BuiltIn: true, Hosts: []string{"example.com"}},
		{Name: "Admin", Hosts: []string{"corp.test"}},
	})
	if _, _, ok := s.LookupHostAdmin("www.example.com"); ok {
		t.Error("LookupHostAdmin matched a BuiltIn category")
	}
	if cat, _, ok := s.LookupHostAdmin("www.corp.test"); !ok || cat != "Admin" {
		t.Errorf("LookupHostAdmin(www.corp.test) = (%q, %v), want Admin", cat, ok)
	}
	// The full lookup still sees both.
	if cat, _, ok := s.LookupHost("www.example.com"); !ok || cat != "Seed" {
		t.Errorf("LookupHost(www.example.com) = (%q, %v), want Seed", cat, ok)
	}
}

// TestConcurrent_MatchesHostDuringAddHost is the race gate.
//
// Before the copy-on-write conversion, AddHost/Set/RemoveHost patched the very
// maps the read paths had snapshotted and were probing with the lock released,
// and `go test -race` reported a genuine data race between the admin category
// API and the per-request policy path (urlcat.go:275 write vs urlcat.go:337
// read). Publication by replacement is what makes the unlocked probe sound, so
// this test only means anything under -race.
func TestConcurrent_MatchesHostDuringAddHost(t *testing.T) {
	s := New(DefaultEntries())
	if err := s.Set("Corp", []string{"corp.test"}, false); err != nil {
		t.Fatalf("Set: %v", err)
	}

	const iterations = 500
	var wg sync.WaitGroup
	reader := func(fn func()) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			fn()
		}
	}
	wg.Add(5)
	go reader(func() { _ = s.MatchesHost("AI", "chat.openai.com") })
	go reader(func() { _ = s.MatchesHostAdmin("Corp", "www.corp.test") })
	go reader(func() { _, _, _ = s.LookupHost("www.some-ordinary-host.example.com") })
	go reader(func() { _, _, _ = s.LookupHostAdmin("www.corp.test") })
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = s.AddHost("Corp", fmt.Sprintf("h%d.corp.test", i))
			if i%50 == 0 {
				_ = s.Set("Churn", []string{fmt.Sprintf("c%d.test", i)}, false)
			}
		}
	}()
	wg.Wait()
}
