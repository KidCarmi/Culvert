package decryptprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The retired "permissive" certVerification value must be:
//   - rejected on the interactive write paths (Add/Update/UpdateByID) with an
//     explicit error, and
//   - fail-closed-migrated to "strict" on the bulk install paths (Load,
//     ReplaceAll — which backs config import, rollback, and CP→DP apply),
//     never silently dropped.
//
// These tests pin that contract at the engine layer (the single chokepoint all
// three write families funnel through) so a regression can't reopen the
// misleading operator contract closed in issue #716.

// TestValidate_RejectsPermissive proves the accepted certVerification set no
// longer contains "permissive".
func TestValidate_RejectsPermissive(t *testing.T) {
	if err := Validate(&Profile{Name: "p", CertVerification: "permissive"}); err == nil {
		t.Fatal("Validate must reject certVerification=permissive")
	}
	// The still-supported values must remain accepted.
	for _, v := range []string{"", "strict", "skip"} {
		if err := Validate(&Profile{Name: "p", CertVerification: v}); err != nil {
			t.Fatalf("certVerification=%q must remain valid: %v", v, err)
		}
	}
}

// TestValidCertVerificationSet pins the exact accepted-value set so schema/GUI/
// docs parity has a runtime anchor. "permissive" MUST be absent.
func TestValidCertVerificationSet(t *testing.T) {
	want := map[string]bool{"": true, "strict": true, "skip": true}
	if len(validCertVerification) != len(want) {
		t.Fatalf("validCertVerification = %v, want %v", validCertVerification, want)
	}
	for k := range want {
		if !validCertVerification[k] {
			t.Fatalf("validCertVerification missing %q", k)
		}
	}
	if validCertVerification["permissive"] {
		t.Fatal("validCertVerification must NOT accept permissive")
	}
}

// TestAdd_RejectsPermissive — interactive create rejects, does not migrate.
func TestAdd_RejectsPermissive(t *testing.T) {
	s := New()
	if _, err := s.Add(Profile{Name: "p", CertVerification: "permissive"}); err == nil {
		t.Fatal("Add must reject certVerification=permissive")
	}
	if s.GetByName("p") != nil {
		t.Fatal("rejected profile must not be stored")
	}
}

// TestUpdate_RejectsPermissive — interactive update rejects, does not migrate.
func TestUpdate_RejectsPermissive(t *testing.T) {
	s := New()
	if _, err := s.Add(Profile{Name: "p", CertVerification: "strict"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.Update(Profile{Name: "p", CertVerification: "permissive"}); err == nil {
		t.Fatal("Update must reject certVerification=permissive")
	}
	// The original stays intact (no partial mutation).
	if got := s.GetByName("p"); got == nil || got.CertVerification != "strict" {
		t.Fatalf("original profile must be unchanged, got %+v", got)
	}
}

// TestUpdateByID_RejectsPermissive — id-addressed update rejects too.
func TestUpdateByID_RejectsPermissive(t *testing.T) {
	s := New()
	p, err := s.Add(Profile{Name: "p", CertVerification: "strict"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpdateByID(p.ID, Profile{CertVerification: "permissive"}); err == nil {
		t.Fatal("UpdateByID must reject certVerification=permissive")
	}
	if got := s.GetByName("p"); got == nil || got.CertVerification != "strict" {
		t.Fatalf("original profile must be unchanged, got %+v", got)
	}
}

// TestReplaceAll_MigratesPermissive — the bulk install path (import/rollback/
// CP→DP) fail-closed-migrates rather than dropping the profile.
func TestReplaceAll_MigratesPermissive(t *testing.T) {
	s := New()
	s.ReplaceAll([]Profile{
		{Name: "legacy", CertVerification: "permissive"},
		{Name: "keep", CertVerification: "strict"},
	})
	got := s.GetByName("legacy")
	if got == nil {
		t.Fatal("permissive profile must be migrated, not dropped")
	}
	if got.CertVerification != "strict" {
		t.Fatalf("permissive must migrate to strict, got %q", got.CertVerification)
	}
	if k := s.GetByName("keep"); k == nil || k.CertVerification != "strict" {
		t.Fatalf("strict profile must be unaffected, got %+v", k)
	}
}

// TestReplaceAll_MigrationFiresSink — the migration is observable through the
// wired sink (package main turns this into an audit-ring diagnostic).
func TestReplaceAll_MigrationFiresSink(t *testing.T) {
	var fired []string
	SetCertMigrationSink(func(name string) { fired = append(fired, name) })
	t.Cleanup(func() { SetCertMigrationSink(nil) })

	s := New()
	s.ReplaceAll([]Profile{
		{Name: "legacy", CertVerification: "permissive"},
		{Name: "clean", CertVerification: "strict"},
	})
	if len(fired) != 1 || fired[0] != "legacy" {
		t.Fatalf("migration sink must fire once for the legacy profile, got %v", fired)
	}
}

// TestReplaceAll_DroppedProfileDoesNotReportMigration — a profile carrying the
// retired value AND an independently-invalid field is skipped as invalid, and
// MUST NOT be reported as migrated (the notice fires only for installed
// profiles). Guards the diagnostic-truthfulness fix from the pre-merge review.
func TestReplaceAll_DroppedProfileDoesNotReportMigration(t *testing.T) {
	var fired []string
	SetCertMigrationSink(func(name string) { fired = append(fired, name) })
	t.Cleanup(func() { SetCertMigrationSink(nil) })

	s := New()
	s.ReplaceAll([]Profile{
		// permissive + an invalid TLS version → dropped by Validate.
		{Name: "dropped", CertVerification: "permissive", MinTLSVersion: "9.9"},
		// permissive + valid → installed and legitimately reported.
		{Name: "kept", CertVerification: "permissive"},
	})
	if s.GetByName("dropped") != nil {
		t.Fatal("invalid profile must be dropped, not stored")
	}
	if len(fired) != 1 || fired[0] != "kept" {
		t.Fatalf("migration notice must fire ONLY for the installed profile, got %v", fired)
	}
}

// TestReplaceAll_DuplicatePermissiveReportedOnce — a duplicate permissive entry
// is dropped by the dedup gate and must not double-report the migration.
func TestReplaceAll_DuplicatePermissiveReportedOnce(t *testing.T) {
	var fired []string
	SetCertMigrationSink(func(name string) { fired = append(fired, name) })
	t.Cleanup(func() { SetCertMigrationSink(nil) })

	s := New()
	s.ReplaceAll([]Profile{
		{Name: "dup", CertVerification: "permissive"},
		{Name: "dup", CertVerification: "permissive"}, // dropped by dedup
	})
	if len(fired) != 1 || fired[0] != "dup" {
		t.Fatalf("duplicate must report migration once, got %v", fired)
	}
}

// TestLoad_MigratesAndPersistsPermissive — an existing persisted permissive
// profile follows the approved migration path AND is rewritten to disk so the
// retired value does not survive across restarts.
func TestLoad_MigratesAndPersistsPermissive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	// A legacy on-disk profile carrying the retired value, with a stable ID so
	// the load has nothing else to migrate (isolates the cert migration).
	seed := []Profile{{ID: "abc123", Name: "legacy", CertVerification: "permissive"}}
	data, _ := json.MarshalIndent(seed, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.GetByName("legacy"); got == nil || got.CertVerification != "strict" {
		t.Fatalf("loaded profile must be migrated to strict, got %+v", got)
	}

	// Persisted: the on-disk file no longer carries permissive.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var reloaded []Profile
	if err := json.Unmarshal(after, &reloaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(reloaded) != 1 || reloaded[0].CertVerification != "strict" {
		t.Fatalf("on-disk file must be rewritten with strict, got %s", after)
	}

	// A second clean load finds nothing to migrate (idempotent).
	var fired int
	SetCertMigrationSink(func(string) { fired++ })
	t.Cleanup(func() { SetCertMigrationSink(nil) })
	s2 := New()
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if fired != 0 {
		t.Fatalf("clean reload must not re-migrate, sink fired %d times", fired)
	}
}

// TestReplaceAll_MigrationRaceFree hammers the migrating install path against
// concurrent readers under -race, proving the sink read + in-place migration
// hold no lock-ordering or data-race hazard (PR review "race proof").
func TestReplaceAll_MigrationRaceFree(t *testing.T) {
	SetCertMigrationSink(func(string) {}) // exercise the atomic-pointer read path
	t.Cleanup(func() { SetCertMigrationSink(nil) })

	s := New()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.ReplaceAll([]Profile{
					{Name: "a", CertVerification: "permissive"},
					{Name: "b", CertVerification: "strict"},
				})
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.List()
				_ = s.GetByName("a")
				_, _ = s.FailOpenScope("a")
			}
		}()
	}
	wg.Wait()
	if got := s.GetByName("a"); got == nil || got.CertVerification != "strict" {
		t.Fatalf("final state must be migrated to strict, got %+v", got)
	}
}
