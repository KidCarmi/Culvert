package decryptprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// PR2: the security generation must be a deterministic fingerprint over ONLY the
// security-effective fields — so a security-relevant edit changes it (invalidating
// learned adaptive-decryption exclusions) while a cosmetic edit does not.

func genOf(t *testing.T, s *Store, id string) string {
	t.Helper()
	p := s.GetByID(id)
	if p == nil {
		t.Fatal("profile missing")
	}
	return p.SecurityGen()
}

// TestSecurityGen_RenameStable — a rename (and case-only rename) must NOT change
// the gen, so a learned exclusion survives a rename.
func TestSecurityGen_RenameStable(t *testing.T) {
	s := New()
	p, err := s.Add(Profile{Name: "orig", OnInspectError: "fail-open", CertVerification: "strict", MinTLSVersion: "1.2"})
	if err != nil {
		t.Fatal(err)
	}
	before := genOf(t, s, p.ID)
	if _, err := s.Rename(p.ID, "renamed-display"); err != nil {
		t.Fatal(err)
	}
	if after := genOf(t, s, p.ID); after != before {
		t.Fatalf("rename changed the security gen: %q -> %q", before, after)
	}
	if _, err := s.Rename(p.ID, "RENAMED-display"); err != nil { // case-only
		t.Fatal(err)
	}
	if after := genOf(t, s, p.ID); after != before {
		t.Fatalf("case-only rename changed the security gen: %q -> %q", before, after)
	}
}

// TestSecurityGen_SecurityFieldsChangeIt — every security-effective field must flip
// the gen when changed.
func TestSecurityGen_SecurityFieldsChangeIt(t *testing.T) {
	h2 := true
	base := Profile{Name: "p", OnInspectError: "fail-open", CertVerification: "strict",
		OnUnsupported: "fail-close", MinTLSVersion: "1.2", MaxTLSVersion: "1.3", InspectHTTP2: &h2}
	baseGen := base.SecurityGen()

	cases := []struct {
		name string
		mut  func(p *Profile)
	}{
		{"OnInspectError", func(p *Profile) { p.OnInspectError = "fail-close" }},
		{"CertVerification", func(p *Profile) { p.CertVerification = "skip" }},
		{"OnUnsupported", func(p *Profile) { p.OnUnsupported = "fail-open" }},
		{"MinTLSVersion", func(p *Profile) { p.MinTLSVersion = "1.3" }},
		{"MaxTLSVersion", func(p *Profile) { p.MaxTLSVersion = "" }},
		{"InspectHTTP2=false", func(p *Profile) { f := false; p.InspectHTTP2 = &f }},
		{"InspectHTTP2=nil", func(p *Profile) { p.InspectHTTP2 = nil }},
	}
	for _, c := range cases {
		p := base
		if base.InspectHTTP2 != nil { // independent pointee
			v := *base.InspectHTTP2
			p.InspectHTTP2 = &v
		}
		c.mut(&p)
		if p.SecurityGen() == baseGen {
			t.Errorf("changing %s did NOT change the security gen (stale exclusion would survive a security edit)", c.name)
		}
	}
}

// TestSecurityGen_CosmeticFieldsStable — identity/display/operational fields must
// NOT change the gen.
func TestSecurityGen_CosmeticFieldsStable(t *testing.T) {
	base := Profile{Name: "p", ID: "id1", OnInspectError: "fail-open", CertVerification: "strict",
		MinTLSVersion: "1.2", StallTimeoutSecs: 30, CreatedAt: "2026-01-01", UpdatedAt: "2026-01-01"}
	g := base.SecurityGen()
	for _, mut := range []struct {
		name string
		fn   func(p *Profile)
	}{
		{"Name", func(p *Profile) { p.Name = "totally-different" }},
		{"ID", func(p *Profile) { p.ID = "id2" }},
		{"CreatedAt", func(p *Profile) { p.CreatedAt = "2000-01-01" }},
		{"UpdatedAt", func(p *Profile) { p.UpdatedAt = "2099-12-31" }},
		{"StallTimeoutSecs", func(p *Profile) { p.StallTimeoutSecs = 3600 }},
	} {
		p := base
		mut.fn(&p)
		if p.SecurityGen() != g {
			t.Errorf("changing cosmetic/operational field %s changed the security gen (a rename/display edit must not invalidate exclusions)", mut.name)
		}
	}
}

// TestSecurityGen_Deterministic — the precomputed (store-write) gen equals the
// on-demand compute, and both are stable across calls. This is the restart-parity
// guarantee: a reload recomputes the identical value from the persisted fields.
func TestSecurityGen_Deterministic(t *testing.T) {
	p := Profile{Name: "p", OnInspectError: "fail-open", CertVerification: "strict", MinTLSVersion: "1.2"}
	g1 := p.SecurityGen()
	g2 := computeSecurityGen(&p)
	if g1 == "" || g1 != g2 {
		t.Fatalf("gen not deterministic: on-demand=%q compute=%q", g1, g2)
	}
	s := New()
	added, err := s.Add(p)
	if err != nil {
		t.Fatal(err)
	}
	if added.SecurityGen() != g1 {
		t.Fatalf("stored precomputed gen %q != computed %q", added.SecurityGen(), g1)
	}
	// A second identical profile in a second store fingerprints identically
	// (CP↔DP parity: same fields ⇒ same gen, no shared state).
	s2 := New()
	added2, _ := s2.Add(p)
	if added2.SecurityGen() != g1 {
		t.Fatalf("independent store produced a different gen %q (CP→DP would disagree)", added2.SecurityGen())
	}
}

// TestSecurityGen_EveryWritePathPrecomputes pins the store invariant that EVERY
// write path (Add / Update / UpdateByID / ReplaceAll / Load) leaves the stored
// profile's securityGen precomputed and equal to computeSecurityGen — so the read
// accessors and the learn path always agree, and a future write path that forgets to
// set it fails this test rather than silently degrading the fencing. (The read
// accessor also self-heals via SecurityGen(), but this keeps the precompute honest.)
func TestSecurityGen_EveryWritePathPrecomputes(t *testing.T) {
	assertPrecomputed := func(t *testing.T, s *Store, id, path string) {
		t.Helper()
		s.mu.RLock()
		defer s.mu.RUnlock()
		for _, p := range s.profiles {
			if id != "" && p.ID != id {
				continue
			}
			if p.securityGen == "" {
				t.Fatalf("%s: stored profile %q has empty securityGen (write path did not precompute)", path, p.Name)
			}
			if want := computeSecurityGen(p); p.securityGen != want {
				t.Fatalf("%s: stored gen %q != recomputed %q", path, p.securityGen, want)
			}
		}
	}

	// Add
	s := New()
	fo, err := s.Add(Profile{Name: "fo", OnInspectError: "fail-open", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	assertPrecomputed(t, s, fo.ID, "Add")

	// Update (by name)
	if err := s.Update(Profile{Name: "fo", OnInspectError: "fail-open", CertVerification: "skip"}); err != nil {
		t.Fatal(err)
	}
	assertPrecomputed(t, s, "", "Update")

	// UpdateByID
	if err := s.UpdateByID(fo.ID, Profile{OnInspectError: "fail-open", MinTLSVersion: "1.3"}); err != nil {
		t.Fatal(err)
	}
	assertPrecomputed(t, s, "", "UpdateByID")

	// ReplaceAll
	s2 := New()
	s2.ReplaceAll([]Profile{{Name: "a", OnInspectError: "fail-open"}, {Name: "b", CertVerification: "skip"}})
	assertPrecomputed(t, s2, "", "ReplaceAll")

	// Load (from disk)
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	data, _ := json.Marshal([]Profile{{ID: "id1", Name: "loaded", OnInspectError: "fail-open", MinTLSVersion: "1.2"}})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := New()
	if err := s3.Load(path); err != nil {
		t.Fatal(err)
	}
	assertPrecomputed(t, s3, "", "Load")
}

// TestSecurityGen_FailOpenScopeCarriesGen — the hot-path scope accessors return the
// precomputed gen for a fail-open profile.
func TestSecurityGen_FailOpenScopeCarriesGen(t *testing.T) {
	s := New()
	fo, err := s.Add(Profile{Name: "fo", OnInspectError: "fail-open", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	wantGen := fo.SecurityGen()
	if id, gen, ok := s.FailOpenScope("fo"); !ok || id != fo.ID || gen != wantGen {
		t.Fatalf("FailOpenScope = (%q,%q,%v), want (%q,%q,true)", id, gen, ok, fo.ID, wantGen)
	}
	if scope, gen, resolved := s.FailOpenScopeByID(fo.ID); !resolved || scope != fo.ID || gen != wantGen {
		t.Fatalf("FailOpenScopeByID = (%q,%q,%v), want (%q,%q,true)", scope, gen, resolved, fo.ID, wantGen)
	}
	// A fail-close profile carries no scope and no gen.
	fc, _ := s.Add(Profile{Name: "fc", OnInspectError: "fail-close"})
	if scope, gen, resolved := s.FailOpenScopeByID(fc.ID); scope != "" || gen != "" || !resolved {
		t.Fatalf("fail-close FailOpenScopeByID = (%q,%q,%v), want (\"\",\"\",true)", scope, gen, resolved)
	}
}
