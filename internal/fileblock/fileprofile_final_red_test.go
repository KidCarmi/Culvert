package fileblock

// fileprofile_final_red_test.go — 2D-C FINAL correction, red-before rows D
// (fingerprint encoding ambiguity) and E-load (identity invariants at the
// disk-load boundary). Written to compile at both the reviewed candidate and
// the corrected tree.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDCFin_RevisionNotAmbiguousAcrossCommaExtensions (§10–§12): normExts
// permits a comma INSIDE an extension, and the fpv1 row joined extensions
// with ",", so the semantically different sets [".a", ".b"] and [".a,.b"]
// serialized identically — different file-filter behavior, same optimistic
// revision, which lets a stale editor false-pass. The fingerprint must be
// collision-safe (length-framed, no reserved delimiters in user strings).
func TestDCFin_RevisionNotAmbiguousAcrossCommaExtensions(t *testing.T) {
	a := dcFinLoadStore(t, `[{"id":"x","name":"n","extensions":[".a",".b"]}]`)
	b := dcFinLoadStore(t, `[{"id":"x","name":"n","extensions":[".a,.b"]}]`)
	if a.Revision() == b.Revision() {
		t.Fatalf("fingerprint collision: [\".a\",\".b\"] and [\".a,.b\"] are different extension sets but share revision %s — a stale mutation can false-pass the fence", a.Revision())
	}
}

// dcFinLoadStore seeds a store from literal JSON via the real Load boundary
// (the construction path both the candidate and the corrected tree share).
func dcFinLoadStore(t *testing.T, jsonBody string) *FileProfileStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(jsonBody), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := &FileProfileStore{}
	if err := s.Load(path); err != nil {
		t.Fatalf("load healthy seed: %v", err)
	}
	return s
}

// TestDCFin_RevisionStableForSameContent (control — green at both trees): the
// fingerprint stays a pure content function: same profiles ⇒ same revision
// across independent stores (the restart-stability the browser fence needs).
func TestDCFin_RevisionStableForSameContent(t *testing.T) {
	body := `[{"id":"x","name":"n","extensions":[".a",".b"]},{"id":"y","name":"m","extensions":[".c"]}]`
	if dcFinLoadStore(t, body).Revision() != dcFinLoadStore(t, body).Revision() {
		t.Fatal("revision must be a pure content function (restart-stable)")
	}
}

// TestDCFin_LoadRefusesDuplicateProfileIDs (§13–§15): FileProfile IDs are
// enforcement-authoritative, and every version that ever persisted
// file_profiles.json wrote IDs (the struct was born with the field, built-in
// deterministic IDs, and uuid-minting Create — §14 audit), so a persisted set
// with duplicate or missing IDs is corruption: Load must refuse it rather
// than make first-match GetByID ambiguity authoritative.
func TestDCFin_LoadRefusesDuplicateProfileIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(path, []byte(
		`[{"id":"dup","name":"A","extensions":[".a"]},{"id":"dup","name":"B","extensions":[".b"]}]`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := &FileProfileStore{}
	if err := s.Load(path); err == nil {
		t.Fatal("Load accepted duplicate profile IDs — GetByID becomes first-match ambiguity, incompatible with stable identity")
	}
	if len(s.List()) != 0 {
		t.Fatalf("a refused load must not publish the ambiguous set, got %d profiles", len(s.List()))
	}
}

// TestDCFin_LoadRefusesMissingProfileID (§14): missing IDs are corruption
// (see the audit above) — refuse, never invent identity nondeterministically
// on every load.
func TestDCFin_LoadRefusesMissingProfileID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(path, []byte(
		`[{"name":"NoID","extensions":[".a"]}]`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := &FileProfileStore{}
	if err := s.Load(path); err == nil {
		t.Fatal("Load accepted a profile without an ID — corruption must refuse, not mint a fresh identity per boot")
	}
}

// TestDCFin_LoadRefusesDuplicateNames (§14): names are the interactive intent
// namespace (case-insensitive unique everywhere else in the product) — a
// persisted set with two profiles sharing a name is equally corrupt.
func TestDCFin_LoadRefusesDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(path, []byte(
		`[{"id":"a1","name":"Same","extensions":[".a"]},{"id":"b2","name":"same","extensions":[".b"]}]`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := &FileProfileStore{}
	if err := s.Load(path); err == nil {
		t.Fatal("Load accepted case-insensitively duplicate profile names")
	}
}

// TestDCFin_LoadAcceptsHealthyLegacyShapes (control — green at both trees):
// the seeded built-ins (deterministic non-UUID `builtin-*` IDs) and a healthy
// custom set keep loading; the validation must not demand UUIDs.
func TestDCFin_LoadAcceptsHealthyLegacyShapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(path, []byte(
		`[{"id":"builtin-executables","name":"Executables","extensions":[".exe"]},`+
			`{"id":"9f8e7d6c-1111-2222-3333-444455556666","name":"CAD","extensions":[".dwg"]}]`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := &FileProfileStore{}
	if err := s.Load(path); err != nil {
		t.Fatalf("healthy persisted set must load: %v", err)
	}
	if len(s.List()) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(s.List()))
	}
}
