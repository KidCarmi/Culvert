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
	scope, ok := s.FailOpenScopeByID(fo.ID)
	if !ok || scope != fo.ID {
		t.Errorf("FailOpenScopeByID = (%q,%v), want (%q,true)", scope, ok, fo.ID)
	}
	// A fail-close profile (default) does not scope.
	fc, err := s.Add(Profile{Name: "FC", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.FailOpenScopeByID(fc.ID); ok {
		t.Error("fail-close profile must not produce a scope")
	}
	if _, ok := s.FailOpenScopeByID(""); ok {
		t.Error("empty id must not scope")
	}
	// Scope tracks the profile across a rename (ID unchanged).
	if _, err := s.Rename(fo.ID, "FO-renamed"); err != nil {
		t.Fatal(err)
	}
	if scope, ok := s.FailOpenScopeByID(fo.ID); !ok || scope != fo.ID {
		t.Error("scope should survive a rename (keyed by stable id)")
	}
}
