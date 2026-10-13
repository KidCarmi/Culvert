package catgroup

// catgroup_byid_index_test.go — the byID index is DERIVED state: it holds the
// same *Group values as the name-keyed groups map so that resolving a rule's
// authoritative DestCategoryGroupID on the proxy hot path is a map probe
// rather than a walk.
//
// Derived state earns its keep only while it cannot disagree with its source,
// and the way it comes to disagree is a new write path that forgets to
// maintain it. These tests are that guard: assertIndexConsistent is applied
// after EVERY mutation the store exposes, so a future write path that changes
// the group set without reindexing fails here rather than silently resolving a
// policy rule to a stale group — a policy decision, not a cosmetic drift.

import (
	"fmt"
	"path/filepath"
	"testing"
)

// assertIndexConsistent checks the two directions that matter: every live
// group is reachable by its ID, and the index contains nothing else.
func assertIndexConsistent(t *testing.T, s *Store, what string) {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()

	want := 0
	for _, g := range s.groups {
		if g.ID == "" {
			continue // never indexed; both ID lookups reject an empty id
		}
		want++
		indexed, ok := s.byID[g.ID]
		if !ok {
			t.Fatalf("%s: group %q (id %q) is in groups but not in byID", what, g.Name, g.ID)
		}
		if indexed != g {
			// Pointer identity, not field equality: the index must alias the
			// live group so an in-place Update is visible through it.
			t.Fatalf("%s: byID[%q] is a different *Group than groups[%q]", what, g.ID, g.Name)
		}
	}
	if len(s.byID) != want {
		t.Fatalf("%s: byID has %d entries, groups has %d ID-bearing groups (stale entry left behind)",
			what, len(s.byID), want)
	}
}

func TestByIDIndex_ConsistentAcrossEveryMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "category_groups.json")
	s := New()
	s.SetPathForTest(path)
	assertIndexConsistent(t, s, "new")

	// ReplaceAll (bulk install: cluster sync / import / rollback).
	s.ReplaceAll([]Group{
		{ID: "id-a", Name: "Alpha", Categories: []string{"Streaming"}},
		{ID: "id-b", Name: "Beta", Categories: []string{"Gambling"}},
		{ID: "id-c", Name: "Gamma", Categories: []string{"Social Media"}},
	})
	assertIndexConsistent(t, s, "ReplaceAll")

	// Add.
	added, err := s.Add("Delta", []string{"Streaming"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	assertIndexConsistent(t, s, "Add")

	// Update (in place: the pointer and ID are unchanged, so the index must
	// show the NEW categories without being rebuilt).
	if err := s.Update("Delta", []string{"Gambling"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertIndexConsistent(t, s, "Update")
	if matched, resolved := s.MatchesCategoryByID(added.ID, "Gambling"); !matched || !resolved {
		t.Fatalf("after Update, MatchesCategoryByID = (%v,%v), want (true,true)", matched, resolved)
	}
	if matched, _ := s.MatchesCategoryByID(added.ID, "Streaming"); matched {
		t.Fatal("after Update, the removed category still matches through the index")
	}

	// UpdateByID.
	if err := s.UpdateByID("id-a", []string{"Gambling"}); err != nil {
		t.Fatalf("UpdateByID: %v", err)
	}
	assertIndexConsistent(t, s, "UpdateByID")

	// Rename (re-keys the NAME map; ID and pointer unchanged).
	if _, err := s.Rename("id-b", "Beta Renamed"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	assertIndexConsistent(t, s, "Rename")

	// Case-only rename (the in-place branch).
	if _, err := s.Rename("id-b", "BETA RENAMED"); err != nil {
		t.Fatalf("Rename case-only: %v", err)
	}
	assertIndexConsistent(t, s, "Rename case-only")

	// Delete by name.
	if err := s.Delete("Delta"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertIndexConsistent(t, s, "Delete")
	if _, resolved := s.MatchesCategoryByID(added.ID, "Gambling"); resolved {
		t.Fatal("a deleted group still resolves through the index")
	}

	// DeleteByID.
	if _, err := s.DeleteByID("id-c"); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	assertIndexConsistent(t, s, "DeleteByID")
	if _, resolved := s.MatchesCategoryByID("id-c", "Social Media"); resolved {
		t.Fatal("a group removed by DeleteByID still resolves through the index")
	}

	// Load into a fresh store (the restart oracle).
	s.Save()
	fresh := New()
	if err := fresh.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertIndexConsistent(t, fresh, "Load")
	if matched, resolved := fresh.MatchesCategoryByID("id-a", "Gambling"); !matched || !resolved {
		t.Fatalf("after Load, MatchesCategoryByID(id-a) = (%v,%v), want (true,true)", matched, resolved)
	}

	// restoreSnapshot (the MutateDurable rollback path).
	fresh.restoreSnapshot([]Group{
		{ID: "id-z", Name: "Zeta", Categories: []string{"Streaming"}},
	}, 99)
	assertIndexConsistent(t, fresh, "restoreSnapshot")
	if matched, resolved := fresh.MatchesCategoryByID("id-z", "Streaming"); !matched || !resolved {
		t.Fatalf("after restoreSnapshot, MatchesCategoryByID(id-z) = (%v,%v), want (true,true)", matched, resolved)
	}
	if _, resolved := fresh.MatchesCategoryByID("id-a", "Gambling"); resolved {
		t.Fatal("restoreSnapshot left the replaced group reachable by ID")
	}
}

// TestByIDIndex_RenameKeepsIDResolution is the rename-safety property the ID
// link exists for, now served by the index: a renamed group stays reachable by
// the ID its policy rules carry.
func TestByIDIndex_RenameKeepsIDResolution(t *testing.T) {
	s := New()
	s.ReplaceAll([]Group{{ID: "id-r", Name: "Before", Categories: []string{"Streaming"}}})

	if _, err := s.Rename("id-r", "After"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	assertIndexConsistent(t, s, "Rename")

	if matched, resolved := s.MatchesCategoryByID("id-r", "Streaming"); !matched || !resolved {
		t.Fatalf("renamed group not reachable by ID: (%v,%v), want (true,true)", matched, resolved)
	}
	if g := s.GetByID("id-r"); g == nil || g.Name != "After" {
		t.Fatalf("GetByID after rename = %+v, want the group named %q", g, "After")
	}
	// The stale NAME must no longer resolve — the index must not have
	// resurrected the old key.
	if s.MatchesCategory("Before", "Streaming") {
		t.Fatal("the pre-rename name still matches")
	}
}

// TestByIDIndex_EmptyIDNotIndexed pins the one group shape deliberately left
// out of the index, and that it is unreachable either way.
func TestByIDIndex_EmptyIDNotIndexed(t *testing.T) {
	s := New()
	// Build the map directly: ReplaceAll/Load backfill an ID, so an empty one
	// cannot arrive through them. This is the defensive shape.
	s.mu.Lock()
	g := &Group{ID: "", Name: "No ID", Categories: []string{"streaming"}}
	g.catSet = buildCatSet(g.Categories)
	s.groups["no id"] = g
	s.reindexByIDLocked()
	s.mu.Unlock()

	assertIndexConsistent(t, s, "empty ID")
	if _, resolved := s.MatchesCategoryByID("", "Streaming"); resolved {
		t.Fatal("an empty id resolved")
	}
	if got := s.GetByID(""); got != nil {
		t.Fatalf("GetByID(\"\") = %+v, want nil", got)
	}
}

// TestByIDIndex_MatchesNameAndIDPathsAgree is the differential oracle: for
// every group, resolving by ID and by name must reach the same membership
// answer. This is what makes the hot path's ID-first preference safe.
func TestByIDIndex_MatchesNameAndIDPathsAgree(t *testing.T) {
	const n = 24
	groups := make([]Group, n)
	for i := 0; i < n; i++ {
		groups[i] = Group{
			ID:         fmt.Sprintf("id-%02d", i),
			Name:       fmt.Sprintf("Group %d", i),
			Categories: []string{fmt.Sprintf("Cat %d", i%5), "Streaming"},
		}
	}
	s := New()
	s.ReplaceAll(groups)
	assertIndexConsistent(t, s, "ReplaceAll")

	for i := 0; i < n; i++ {
		id := fmt.Sprintf("id-%02d", i)
		name := fmt.Sprintf("Group %d", i)
		for _, cat := range []string{"Streaming", "Gambling", "Cat 0", "Cat 3", ""} {
			byID, resolved := s.MatchesCategoryByID(id, cat)
			if !resolved {
				t.Fatalf("id %q did not resolve", id)
			}
			byName := s.MatchesCategory(name, cat)
			if byID != byName {
				t.Fatalf("id/name disagree for group %q category %q: byID=%v byName=%v",
					name, cat, byID, byName)
			}
		}
	}
}
