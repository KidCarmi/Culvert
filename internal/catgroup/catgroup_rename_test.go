package catgroup

// catgroup_rename_test.go — Rename (re-keys the name map + order, references-by-id
// S2) and MatchesCategoryByID (rename-safe hot-path group match).

import "testing"

func TestRename(t *testing.T) {
	s := New()
	g, err := s.Add("Orig", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Rename(g.ID, "NewName")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if old != "Orig" {
		t.Errorf("Rename returned old name %q, want Orig", old)
	}
	if s.GetByName("Orig") != nil {
		t.Error("old name still resolves after rename")
	}
	got := s.GetByName("NewName")
	if got == nil || got.ID != g.ID {
		t.Errorf("new name does not resolve to the same id: %+v", got)
	}
	// order slice re-keyed: Names() lists the new name, not the stale key.
	names := s.Names()
	if len(names) != 1 || names[0] != "NewName" {
		t.Errorf("Names() after rename = %v, want [NewName]", names)
	}
	// Membership survives the rename (catSet intact under the new key).
	if !s.MatchesCategory("NewName", "news") {
		t.Error("membership lost after rename")
	}

	// Collision with a different group is rejected.
	if _, err := s.Add("Taken", []string{"ads"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rename(g.ID, "Taken"); err == nil {
		t.Error("rename onto an existing name should be rejected")
	}
	// Case-only change is allowed (same key).
	if _, err := s.Rename(g.ID, "newname"); err != nil {
		t.Errorf("case-only rename: %v", err)
	}
	if got := s.GetByName("NEWNAME"); got == nil || got.Name != "newname" {
		t.Errorf("case-only rename did not update display name: %+v", got)
	}
	// Unknown id / empty name.
	if _, err := s.Rename("nope", "X"); err == nil {
		t.Error("rename of unknown id should error")
	}
	if _, err := s.Rename(g.ID, "   "); err == nil {
		t.Error("rename to empty name should error")
	}
}

func TestMatchesCategoryByID(t *testing.T) {
	s := New()
	g, err := s.Add("grp", []string{"news", "saas"})
	if err != nil {
		t.Fatal(err)
	}
	// Resolved + member → (true, true).
	if matched, resolved := s.MatchesCategoryByID(g.ID, "news"); !matched || !resolved {
		t.Errorf("MatchesCategoryByID(member) = (%v,%v), want (true,true)", matched, resolved)
	}
	// Resolved + non-member → (false, true): the group EXISTS but the category
	// is not in it. resolved=true is load-bearing — the caller must NOT fall back
	// to a possibly-stale name.
	if matched, resolved := s.MatchesCategoryByID(g.ID, "gambling"); matched || !resolved {
		t.Errorf("MatchesCategoryByID(non-member) = (%v,%v), want (false,true)", matched, resolved)
	}
	// Resolved + empty category → (false, true): empty never matches, but the id
	// still resolved.
	if matched, resolved := s.MatchesCategoryByID(g.ID, ""); matched || !resolved {
		t.Errorf("MatchesCategoryByID(empty cat) = (%v,%v), want (false,true)", matched, resolved)
	}
	// Not found → (false, false): the caller may fall back to the name.
	if matched, resolved := s.MatchesCategoryByID("nonexistent", "news"); matched || resolved {
		t.Errorf("MatchesCategoryByID(missing) = (%v,%v), want (false,false)", matched, resolved)
	}
	// Empty id → (false, false).
	if matched, resolved := s.MatchesCategoryByID("", "news"); matched || resolved {
		t.Errorf("MatchesCategoryByID(\"\") = (%v,%v), want (false,false)", matched, resolved)
	}
	// Match tracks the group across a rename (ID unchanged).
	if _, err := s.Rename(g.ID, "grp-renamed"); err != nil {
		t.Fatal(err)
	}
	if matched, resolved := s.MatchesCategoryByID(g.ID, "news"); !matched || !resolved {
		t.Error("match should survive a rename (keyed by stable id)")
	}
}
