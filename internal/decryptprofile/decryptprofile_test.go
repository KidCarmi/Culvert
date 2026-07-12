package decryptprofile

import (
	"path/filepath"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestStore_AddValidateUnique(t *testing.T) {
	s := New()
	if _, err := s.Add(Profile{Name: "recommended-h2", InspectHTTP2: boolPtr(true)}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Duplicate name (case-insensitive) rejected.
	if _, err := s.Add(Profile{Name: "Recommended-H2"}); err == nil {
		t.Fatal("duplicate name must be rejected")
	}
	// Invalid enum rejected.
	if _, err := s.Add(Profile{Name: "bad", CertVerification: "nope"}); err == nil {
		t.Fatal("invalid certVerification must be rejected")
	}
	if _, err := s.Add(Profile{Name: "bad2", MinTLSVersion: "1.4"}); err == nil {
		t.Fatal("invalid minTlsVersion must be rejected")
	}
	// min>max rejected.
	if _, err := s.Add(Profile{Name: "bad3", MinTLSVersion: "1.3", MaxTLSVersion: "1.2"}); err == nil {
		t.Fatal("min>max must be rejected")
	}
	// Stall out of range rejected; 0 (default) and in-range accepted.
	if _, err := s.Add(Profile{Name: "bad4", StallTimeoutSecs: 2}); err == nil {
		t.Fatal("stall below MinStallSecs must be rejected")
	}
	if _, err := s.Add(Profile{Name: "bad5", StallTimeoutSecs: MaxStallSecs + 1}); err == nil {
		t.Fatal("stall above MaxStallSecs must be rejected")
	}
	if _, err := s.Add(Profile{Name: "ok-stall", StallTimeoutSecs: 30}); err != nil {
		t.Fatalf("in-range stall rejected: %v", err)
	}
	// Invalid name charset rejected.
	if _, err := s.Add(Profile{Name: "bad/slash"}); err == nil {
		t.Fatal("invalid name charset must be rejected")
	}
}

func TestStore_GetUpdateDelete(t *testing.T) {
	s := New()
	got, err := s.Add(Profile{Name: "p1", InspectHTTP2: boolPtr(true), MinTLSVersion: "1.2"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if got.ID == "" {
		t.Fatal("Add must assign an ID")
	}
	id := got.ID
	if p := s.GetByName("P1"); p == nil || p.MinTLSVersion != "1.2" {
		t.Fatalf("GetByName case-insensitive failed: %+v", p)
	}
	// Update preserves ID + CreatedAt.
	if err := s.Update(Profile{Name: "p1", MinTLSVersion: "1.3"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	p := s.GetByName("p1")
	if p.ID != id {
		t.Fatalf("Update must preserve ID: was %q now %q", id, p.ID)
	}
	if p.MinTLSVersion != "1.3" {
		t.Fatalf("Update did not apply: %+v", p)
	}
	if err := s.Delete("p1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if s.GetByName("p1") != nil {
		t.Fatal("profile should be gone after delete")
	}
}

// TestStore_ReplaceAllPreservesIDsAndSkipsInvalid pins the rollback/sync contract:
// provided IDs are preserved (round-trip stability) and invalid entries are dropped
// fail-safe rather than taking down the store.
func TestStore_ReplaceAllPreservesIDsAndSkipsInvalid(t *testing.T) {
	s := New()
	s.ReplaceAll([]Profile{
		{ID: "fixed-id-01", Name: "keep", InspectHTTP2: boolPtr(false)},
		{Name: "bad", OnUnsupported: "explode"}, // invalid → skipped
		{Name: "backfill"},                       // valid, no ID → assigned
	})
	names := s.Names()
	if len(names) != 2 {
		t.Fatalf("expected 2 valid profiles, got %d (%v)", len(names), names)
	}
	if p := s.GetByName("keep"); p == nil || p.ID != "fixed-id-01" {
		t.Fatalf("ReplaceAll must preserve provided IDs: %+v", p)
	}
	if p := s.GetByName("backfill"); p == nil || p.ID == "" {
		t.Fatal("ReplaceAll must backfill a missing ID")
	}
	if s.GetByName("bad") != nil {
		t.Fatal("invalid profile must be skipped by ReplaceAll")
	}
}

func TestStore_LoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decryption_profiles.json")
	s1 := New()
	s1.SetPathForTest(path)
	if _, err := s1.Add(Profile{Name: "prod", InspectHTTP2: boolPtr(true), CertVerification: "strict", OnUnsupported: "fail-close", MinTLSVersion: "1.2", StallTimeoutSecs: 45}); err != nil {
		t.Fatalf("add: %v", err)
	}
	s1.Save()

	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	p := s2.GetByName("prod")
	if p == nil || p.CertVerification != "strict" || p.StallTimeoutSecs != 45 || p.InspectHTTP2 == nil || !*p.InspectHTTP2 {
		t.Fatalf("round-trip mismatch: %+v", p)
	}
}
