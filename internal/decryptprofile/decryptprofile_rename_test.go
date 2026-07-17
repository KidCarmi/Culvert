package decryptprofile

// decryptprofile_rename_test.go — Rename (re-keys the name index, references-by-id)
// and FailOpenScopeByID (rename-safe autoexclude scope).

import "testing"

func TestRename(t *testing.T) {
	s := New()
	p, err := s.Add(Profile{Name: "Orig", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Rename(p.ID, "NewName")
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if old != "Orig" {
		t.Errorf("Rename returned old name %q, want Orig", old)
	}
	if s.GetByName("Orig") != nil {
		t.Error("old name still resolves after rename")
	}
	g := s.GetByName("NewName")
	if g == nil || g.ID != p.ID {
		t.Errorf("new name does not resolve to the same id: %+v", g)
	}
	// A cross-key rename must re-key s.order too, or the profile silently
	// vanishes from List/Save/Names (which iterate s.order). Regression guard
	// for the order-desync bug: List must still contain the renamed profile,
	// and a Save→Load round-trip must round-trip it.
	if got := s.List(); len(got) != 1 || got[0].ID != p.ID || got[0].Name != "NewName" {
		t.Fatalf("List() lost the renamed profile: %+v", got)
	}
	if names := s.Names(); len(names) != 1 || names[0] != "NewName" {
		t.Errorf("Names() lost the renamed profile: %v", names)
	}
	s2 := New()
	s2.ReplaceAll(s.List())
	if got := s2.GetByID(p.ID); got == nil || got.Name != "NewName" {
		t.Errorf("renamed profile did not survive a List→ReplaceAll round-trip: %+v", got)
	}

	// Collision with a different profile is rejected.
	if _, err := s.Add(Profile{Name: "Taken", CertVerification: "strict"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rename(p.ID, "Taken"); err == nil {
		t.Error("rename onto an existing name should be rejected")
	}
	// Case-only change is allowed (same key).
	if _, err := s.Rename(p.ID, "newname"); err != nil {
		t.Errorf("case-only rename: %v", err)
	}
	if g := s.GetByName("NEWNAME"); g == nil || g.Name != "newname" {
		t.Errorf("case-only rename did not update display name: %+v", g)
	}
	// Unknown id / empty name.
	if _, err := s.Rename("nope", "X"); err == nil {
		t.Error("rename of unknown id should error")
	}
	if _, err := s.Rename(p.ID, "   "); err == nil {
		t.Error("rename to empty name should error")
	}
}

func TestFailOpenScopeByID(t *testing.T) {
	s := New()
	fo, err := s.Add(Profile{Name: "FO", CertVerification: "strict", OnInspectError: "fail-open"})
	if err != nil {
		t.Fatal(err)
	}
	// Resolved + fail-open → (id, true).
	scope, resolved := s.FailOpenScopeByID(fo.ID)
	if !resolved || scope != fo.ID {
		t.Errorf("FailOpenScopeByID(fail-open) = (%q,%v), want (%q,true)", scope, resolved, fo.ID)
	}
	// A fail-close profile is RESOLVED but scopeless: ("", true). The
	// resolved=true is load-bearing — the caller must NOT fall back to the
	// name (the ID is authoritative), so we distinguish it from not-found.
	fc, err := s.Add(Profile{Name: "FC", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if scope, resolved := s.FailOpenScopeByID(fc.ID); scope != "" || !resolved {
		t.Errorf("FailOpenScopeByID(fail-close) = (%q,%v), want (\"\",true)", scope, resolved)
	}
	// Not found → ("", false): the ID resolves to no profile, so the caller
	// may fall back to the denormalized name.
	if scope, resolved := s.FailOpenScopeByID("nonexistent"); scope != "" || resolved {
		t.Errorf("FailOpenScopeByID(missing) = (%q,%v), want (\"\",false)", scope, resolved)
	}
	// Empty id → ("", false).
	if scope, resolved := s.FailOpenScopeByID(""); scope != "" || resolved {
		t.Errorf("FailOpenScopeByID(\"\") = (%q,%v), want (\"\",false)", scope, resolved)
	}
	// Scope tracks the profile across a rename (ID unchanged).
	if _, err := s.Rename(fo.ID, "FO-renamed"); err != nil {
		t.Fatal(err)
	}
	if scope, resolved := s.FailOpenScopeByID(fo.ID); !resolved || scope != fo.ID {
		t.Error("scope should survive a rename (keyed by stable id)")
	}
}
