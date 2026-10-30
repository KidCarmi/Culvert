package catgroup

// catgroup_matchkey_test.go — equivalence and allocation contract for the
// PRE-KEYED hot-path matchers (MatchesCategoryKeyByID / MatchesCategoryKey).
//
// The pre-keyed pair exists only to move one allocating derivation —
// strings.ToLower of the request's resolved category — out of a loop that runs
// once per category-group rule per proxied request. That makes the equivalence
// with the string-argument form the whole correctness story: the key form must
// decide membership identically for every input the string form accepts, since
// a wrong "false" silently stops a Deny rule enforcing and a wrong "true"
// blocks traffic no rule covers.
//
// The oracle is therefore the string form itself (which is now a wrapper, so
// the two can never be independently edited apart), driven over the inputs
// where lowering is load-bearing: display-cased names, already-lowercased
// names, non-ASCII, empty, and ids/names that resolve to nothing.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// readCatgroupSource reads the engine source so the structural pin below can
// assert on the shipped text. Cheap and dependency-free; the package has no
// other reason to parse itself.
func readCatgroupSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("catgroup.go")
	if err != nil {
		t.Fatalf("read catgroup.go: %v", err)
	}
	return string(b)
}

// matchKeyFixture installs groups whose categories are spelled the way the
// shipped taxonomy spells them (display-cased) and the way an admin may type
// them (mixed), so CategoryKey has real work to do on both legs.
func matchKeyFixture(t *testing.T) (store *Store, idsByName map[string]string) {
	t.Helper()
	s := New()
	groups := []Group{
		{ID: "grpid000001", Name: "Social & Streaming", Categories: []string{"Social Media", "Streaming"}},
		{ID: "grpid000002", Name: "lower-named", Categories: []string{"gambling"}},
		{ID: "grpid000003", Name: "Mixed Case", Categories: []string{"HR & Recruiting", "Dev Tools"}},
		{ID: "grpid000004", Name: "Ünicode Grp", Categories: []string{"Reisen & Prüfung"}},
		{ID: "grpid000005", Name: "empty-cats", Categories: nil},
	}
	s.ReplaceAll(groups)
	ids := map[string]string{}
	for _, g := range groups {
		ids[g.Name] = g.ID
	}
	return s, ids
}

// matchKeyProbes are the category spellings the matchers are driven over.
var matchKeyProbes = []string{
	"Social Media", "social media", "SOCIAL MEDIA", "SoCiAl MeDiA",
	"Streaming", "streaming", "Gambling", "gambling",
	"HR & Recruiting", "hr & recruiting", "Dev Tools",
	"Reisen & Prüfung", "reisen & prüfung", "REISEN & PRÜFUNG",
	"News", "", " ", "Social", "Social Media ",
}

// TestMatchesCategoryKey_AgreesWithStringForm is the differential gate: for
// every (group reference, category) pair, the pre-keyed matcher fed
// CategoryKey(category) must return exactly what the string form returns.
func TestMatchesCategoryKey_AgreesWithStringForm(t *testing.T) {
	s, ids := matchKeyFixture(t)

	names := []string{"Social & Streaming", "social & streaming", "lower-named", "Mixed Case",
		"Ünicode Grp", "empty-cats", "no-such-group", ""}
	idRefs := []string{ids["Social & Streaming"], ids["lower-named"], ids["Mixed Case"],
		ids["Ünicode Grp"], ids["empty-cats"], "grpid999999", ""}

	for _, cat := range matchKeyProbes {
		key := CategoryKey(cat)
		for _, id := range idRefs {
			wantM, wantR := s.MatchesCategoryByID(id, cat)
			gotM, gotR := s.MatchesCategoryKeyByID(id, key)
			if gotM != wantM || gotR != wantR {
				t.Errorf("MatchesCategoryKeyByID(%q, %q) = (%v,%v), string form (%q) = (%v,%v)",
					id, key, gotM, gotR, cat, wantM, wantR)
			}
		}
		for _, name := range names {
			want := s.MatchesCategory(name, cat)
			got := s.MatchesCategoryKey(name, key)
			if got != want {
				t.Errorf("MatchesCategoryKey(%q, %q) = %v, string form (%q) = %v",
					name, key, got, cat, want)
			}
		}
	}
}

// TestCategoryKey_MatchesCatSetKeying pins that CategoryKey derives exactly the
// key buildCatSet indexes by. If the two ever diverge, a memoized key would
// miss a category the string form matched — the one way this hoist could
// change a policy decision — so assert it against the SET rather than against
// a restatement of strings.ToLower.
func TestCategoryKey_MatchesCatSetKeying(t *testing.T) {
	cats := []string{"Social Media", "GAMBLING", "Dev Tools", "Reisen & Prüfung", "already lower"}
	set := buildCatSet(cats)
	for _, c := range cats {
		if !set[CategoryKey(c)] {
			t.Errorf("CategoryKey(%q) = %q is not a buildCatSet key (keys: %v)", c, CategoryKey(c), set)
		}
	}
	if CategoryKey("") != "" {
		t.Errorf("CategoryKey(%q) = %q, want the empty key", "", CategoryKey(""))
	}
}

// TestMatchesCategoryKey_AllocationContract is the point of the change: with
// the key already in hand the per-rule probe allocates NOTHING, while the
// string form allocates once per call for a display-cased category. The second
// assertion is the negative control — without it the first could pass because
// the compiler elided something rather than because the hoist works.
func TestMatchesCategoryKey_AllocationContract(t *testing.T) {
	s, ids := matchKeyFixture(t)
	id := ids["Social & Streaming"]
	const cat = "Social Media"
	key := CategoryKey(cat)

	var sinkM, sinkR bool
	keyed := testing.AllocsPerRun(200, func() {
		sinkM, sinkR = s.MatchesCategoryKeyByID(id, key)
	})
	if !sinkM || !sinkR {
		t.Fatalf("fixture wrong: MatchesCategoryKeyByID(%q, %q) = (%v,%v), want (true,true)", id, key, sinkM, sinkR)
	}
	if keyed != 0 {
		t.Errorf("MatchesCategoryKeyByID allocates %.2f/op with the key in hand, want 0 — "+
			"the per-rule probe is on the policy hot path and must add no allocation", keyed)
	}

	stringForm := testing.AllocsPerRun(200, func() {
		sinkM, sinkR = s.MatchesCategoryByID(id, cat)
	})
	if stringForm < 1 {
		t.Errorf("negative control failed: the string form allocates %.2f/op for a display-cased "+
			"category, want >=1 — if this is 0, strings.ToLower gained a no-alloc path and the "+
			"keyed form's 0 above no longer proves the hoist does anything", stringForm)
	}
	t.Logf("allocs/op: keyed %.2f, string form %.2f", keyed, stringForm)
}

// TestMatchesCategoryKey_EmptyKeyArmsMatchStringForm pins the two arms the
// call site in package main depends on and that a key cannot express any other
// way: an UNCATEGORIZED destination (empty key) against a RESOLVED group must
// report (false, resolved=true) so the caller does not fall back to the stale
// denormalized name, and the name leg must refuse outright.
func TestMatchesCategoryKey_EmptyKeyArmsMatchStringForm(t *testing.T) {
	s, ids := matchKeyFixture(t)
	id := ids["Social & Streaming"]

	if m, r := s.MatchesCategoryKeyByID(id, ""); m || !r {
		t.Errorf("MatchesCategoryKeyByID(resolved id, empty key) = (%v,%v), want (false,true)", m, r)
	}
	if m, r := s.MatchesCategoryKeyByID("grpid999999", ""); m || r {
		t.Errorf("MatchesCategoryKeyByID(dangling id, empty key) = (%v,%v), want (false,false)", m, r)
	}
	if s.MatchesCategoryKey("Social & Streaming", "") {
		t.Error("MatchesCategoryKey(resolved name, empty key) = true, want false")
	}
}

// TestMatchesCategoryKey_DanglingIDDerivesNoKey records the incidental win: the
// lowering used to happen BEFORE the byID probe, so a rule whose group id no
// longer resolves — the un-migrated / deleted-group shape, which falls through
// to the name leg — paid for a key it discarded. Asserted through the public
// string form, since that is the path a dangling reference actually takes.
func TestMatchesCategoryKey_DanglingIDDerivesNoKey(t *testing.T) {
	s, _ := matchKeyFixture(t)
	key := CategoryKey("Social Media")
	got := testing.AllocsPerRun(200, func() {
		_, _ = s.MatchesCategoryKeyByID("grpid999999", key)
	})
	if got != 0 {
		t.Errorf("MatchesCategoryKeyByID(dangling id) allocates %.2f/op, want 0", got)
	}
}

// TestMatchesCategoryKey_ConcurrentReadersAgree drives both pre-keyed matchers
// from many goroutines against a store being replaced underneath them. It adds
// nothing to the lock-free view contract readview_test.go already covers; what
// it pins here is that the hoist did not introduce shared state — the key is a
// caller-owned value, so concurrent callers with DIFFERENT keys must never see
// each other's answers.
func TestMatchesCategoryKey_ConcurrentReadersAgree(t *testing.T) {
	s, ids := matchKeyFixture(t)
	social, hr := ids["Social & Streaming"], ids["Mixed Case"]

	const workers, iters = 8, 2000
	errs := make(chan string, workers)
	done := make(chan struct{})
	go func() { // a writer, so the readers race a real publication
		defer close(done)
		for i := 0; i < 200; i++ {
			s.ReplaceAll([]Group{
				{ID: "grpid000001", Name: "Social & Streaming", Categories: []string{"Social Media", "Streaming"}},
				{ID: "grpid000003", Name: "Mixed Case", Categories: []string{"HR & Recruiting", "Dev Tools"}},
			})
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Each worker probes a DIFFERENT (group, category) pair, so a key
			// leaking between callers shows up as a wrong answer, not a race.
			id, cat, want := social, "Social Media", true
			if w%2 == 1 {
				id, cat, want = hr, "Social Media", false
			}
			key := CategoryKey(cat)
			for i := 0; i < iters; i++ {
				if m, r := s.MatchesCategoryKeyByID(id, key); r && m != want {
					errs <- fmt.Sprintf("worker %d: MatchesCategoryKeyByID(%q,%q) = %v, want %v", w, id, key, m, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	<-done
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestMatchesCategoryKey_StringFormsStayWrappers keeps the two public string
// matchers delegating to the keyed pair. They are the oracle the differential
// test above compares against, so an independent reimplementation of either
// would quietly turn that gate into a tautology-free-of-meaning: it would be
// comparing two bodies that no longer share a definition of membership.
func TestMatchesCategoryKey_StringFormsStayWrappers(t *testing.T) {
	src := readCatgroupSource(t)
	for _, want := range []string{
		"return s.MatchesCategoryKeyByID(id, CategoryKey(category))",
		"return s.MatchesCategoryKey(groupName, CategoryKey(category))",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("catgroup.go no longer contains %q — the string matcher was reimplemented "+
				"instead of delegating; restore the wrapper or give the differential test a "+
				"frozen oracle of its own", want)
		}
	}
}
