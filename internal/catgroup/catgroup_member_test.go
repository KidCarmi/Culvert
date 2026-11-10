package catgroup

// catgroup_member_test.go — contract for the MEMBERSHIP matchers
// (MatchesMemberKeyByID / MatchesMemberKey): a group matches when the host
// belongs to ANY of its categories, with the classification winner (catKey)
// probed first off the catSet and the caller's member probe consulted only for
// the remaining categories.

import (
	"testing"
)

func memberFixture(t *testing.T) *Store {
	t.Helper()
	s := New()
	s.ReplaceAll([]Group{
		{ID: "grpmbr000001", Name: "Non-Productive", Categories: []string{"Social Media", "News"}},
		{ID: "grpmbr000002", Name: "empty-cats", Categories: nil},
	})
	return s
}

// memberOf returns a probe answering membership from a fixed set, recording
// every category it is asked about.
func memberOf(cats ...string) (MemberFunc, *[]string) {
	set := map[string]bool{}
	for _, c := range cats {
		set[CategoryKey(c)] = true
	}
	var asked []string
	return func(c string) bool { asked = append(asked, c); return set[c] }, &asked
}

func TestMatchesMember_NonWinnerMembershipMatches(t *testing.T) {
	s := memberFixture(t)
	// The host classifies as "webmail" (an admin suffix winner) but is also a
	// member of News: the group must match.
	member, asked := memberOf("webmail", "news")
	if m, r := s.MatchesMemberKeyByID("grpmbr000001", "webmail", member); !m || !r {
		t.Fatalf("ByID = (%v,%v), want (true,true)", m, r)
	}
	if !s.MatchesMemberKey("non-productive", "webmail", member) {
		t.Fatal("by name: non-winner member category must match")
	}
	for _, c := range *asked {
		if c != "social media" && c != "news" {
			t.Errorf("member probed %q, which is not a normalized group category", c)
		}
	}
}

func TestMatchesMember_WinnerFastPathSkipsProbe(t *testing.T) {
	s := memberFixture(t)
	member, asked := memberOf()
	if m, _ := s.MatchesMemberKeyByID("grpmbr000001", "news", member); !m {
		t.Fatal("winner in the group must match")
	}
	if len(*asked) != 0 {
		t.Errorf("winner hit must not consult the member probe, asked %v", *asked)
	}
	// On a miss every remaining group category is probed once and the winner
	// itself is not re-asked.
	member2, asked2 := memberOf()
	if m, _ := s.MatchesMemberKeyByID("grpmbr000001", "gambling", member2); m {
		t.Fatal("non-member must not match")
	}
	if got := *asked2; len(got) != 2 || got[0] != "social media" || got[1] != "news" {
		t.Errorf("miss probed %v, want [social media news]", got)
	}
	// Winner in the group on the name leg: no probe either.
	member3, asked3 := memberOf()
	if !s.MatchesMemberKey("Non-Productive", "social media", member3) || len(*asked3) != 0 {
		t.Errorf("name-leg winner hit must match without probing, asked %v", *asked3)
	}
}

func TestMatchesMember_NonMembersAndFailClosed(t *testing.T) {
	s := memberFixture(t)
	none, _ := memberOf("webmail")
	if m, r := s.MatchesMemberKeyByID("grpmbr000001", "webmail", none); m || !r {
		t.Errorf("non-member host: ByID = (%v,%v), want (false,true)", m, r)
	}
	if s.MatchesMemberKey("Non-Productive", "webmail", none) {
		t.Error("non-member host must not match by name")
	}
	// Uncategorized host (empty key): no match, probe never consulted — even a
	// probe that would claim everything.
	all := func(string) bool { t.Error("member consulted for an uncategorized host"); return true }
	if m, r := s.MatchesMemberKeyByID("grpmbr000001", "", all); m || !r {
		t.Errorf("empty key ByID = (%v,%v), want (false,true)", m, r)
	}
	if s.MatchesMemberKey("Non-Productive", "", all) {
		t.Error("empty key must not match by name")
	}
	// Unknown / dangling references: unresolved, never matched.
	if m, r := s.MatchesMemberKeyByID("nosuchid", "news", nil); m || r {
		t.Errorf("dangling id = (%v,%v), want (false,false)", m, r)
	}
	if m, r := s.MatchesMemberKeyByID("", "news", nil); m || r {
		t.Errorf("empty id = (%v,%v), want (false,false)", m, r)
	}
	if s.MatchesMemberKey("no-such-group", "news", func(string) bool { return true }) {
		t.Error("unknown group must fail closed")
	}
	// A group with no categories holds nobody.
	if m, r := s.MatchesMemberKeyByID("grpmbr000002", "news", func(string) bool { return true }); m || !r {
		t.Errorf("empty group = (%v,%v), want (false,true)", m, r)
	}
	// nil probe degrades to winner-only, never panics.
	if m, _ := s.MatchesMemberKeyByID("grpmbr000001", "webmail", nil); m {
		t.Error("nil probe with a non-member winner must not match")
	}
}

// The membership matchers must agree with the winner-only matchers whenever the
// probe claims nothing beyond the winner — i.e. they only ever ADD matches.
func TestMatchesMember_AgreesWithWinnerOnlyFormWhenProbeIsSilent(t *testing.T) {
	s, ids := matchKeyFixture(t)
	silent := func(string) bool { return false }
	for _, cat := range matchKeyProbes {
		key := CategoryKey(cat)
		for name, id := range ids {
			wm, wr := s.MatchesCategoryKeyByID(id, key)
			gm, gr := s.MatchesMemberKeyByID(id, key, silent)
			if wm != gm || wr != gr {
				t.Errorf("id %q key %q: winner-only (%v,%v) vs member (%v,%v)", id, key, wm, wr, gm, gr)
			}
			if w, g := s.MatchesCategoryKey(name, key), s.MatchesMemberKey(name, key, silent); w != g {
				t.Errorf("name %q key %q: winner-only %v vs member %v", name, key, w, g)
			}
		}
	}
}

// The hot path calls these once per category-group rule per request; a
// non-escaping probe must keep them allocation-free on every leg.
func TestMatchesMember_AllocationContract(t *testing.T) {
	s := memberFixture(t)
	hits := 0
	probe := func(c string) bool { hits++; return c == "news" }
	allocs := testing.AllocsPerRun(200, func() {
		_, _ = s.MatchesMemberKeyByID("grpmbr000001", "webmail", probe) // probe leg, matches
		_, _ = s.MatchesMemberKeyByID("grpmbr000001", "gambling", func(string) bool { return false })
		_ = s.MatchesMemberKey("non-productive", "news", probe) // winner leg
	})
	if allocs != 0 {
		t.Errorf("membership matchers allocate %.1f/op, want 0", allocs)
	}
	if hits == 0 {
		t.Fatal("probe never ran — the allocation measurement is vacuous")
	}
}
