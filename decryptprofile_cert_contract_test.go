package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// PR1 (issue #716): the retired certVerification="permissive" value must be
// rejected on the interactive API write paths and fail-closed-migrated to
// "strict" on every bulk install path (config import, CP→DP snapshot apply),
// exercised here through the real package-main entry points rather than the
// engine directly. The schema/GUI/docs/runtime accepted-value sets must stay in
// lockstep so the operator never sees an option the runtime rejects (or vice
// versa).

// TestApiDecryptionProfiles_RejectsPermissive_POST — interactive create.
func TestApiDecryptionProfiles_RejectsPermissive_POST(t *testing.T) {
	swapDecProfileStore(t)
	req := httptest.NewRequest(http.MethodPost, "/api/decryption-profiles",
		strings.NewReader(`{"name":"legacy","certVerification":"permissive"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleOperator))
	rw := httptest.NewRecorder()
	apiDecryptionProfiles(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("POST permissive: status = %d, want 400", rw.Code)
	}
	if globalDecryptionProfiles.GetByName("legacy") != nil {
		t.Fatal("rejected permissive profile must not be stored")
	}
}

// TestApiDecryptionProfiles_RejectsPermissive_PUT — interactive update.
func TestApiDecryptionProfiles_RejectsPermissive_PUT(t *testing.T) {
	swapDecProfileStore(t)
	if _, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "p", CertVerification: "strict"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/decryption-profiles",
		strings.NewReader(`{"name":"p","certVerification":"permissive"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleOperator))
	rw := httptest.NewRecorder()
	apiDecryptionProfiles(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("PUT permissive: status = %d, want 400", rw.Code)
	}
	if got := globalDecryptionProfiles.GetByName("p"); got == nil || got.CertVerification != "strict" {
		t.Fatalf("original profile must be unchanged, got %+v", got)
	}
}

// TestConfigImport_MigratesPermissive — the config-import path (replace mode)
// cannot install permissive; it fail-closed-migrates to strict.
func TestConfigImport_MigratesPermissive(t *testing.T) {
	swapDecProfileStore(t)
	b := &configBackup{DecryptionProfiles: []DecryptionProfile{
		{Name: "imported", CertVerification: "permissive"},
	}}
	importCategoryTaxonomy(b, true /* replaceMode */)
	got := globalDecryptionProfiles.GetByName("imported")
	if got == nil {
		t.Fatal("imported profile must be migrated, not dropped")
	}
	if got.CertVerification != "strict" {
		t.Fatalf("import must migrate permissive to strict, got %q", got.CertVerification)
	}
}

// TestSnapshotApply_MigratesPermissive — the CP→DP snapshot-apply path cannot
// install permissive; it fail-closed-migrates to strict.
func TestSnapshotApply_MigratesPermissive(t *testing.T) {
	swapDecProfileStore(t)
	applyConfigSnapshot(ConfigSnapshot{
		Version: 1,
		DecryptionProfiles: []DecryptionProfile{
			{Name: "synced", CertVerification: "permissive"},
		},
	})
	got := globalDecryptionProfiles.GetByName("synced")
	if got == nil {
		t.Fatal("synced profile must be migrated, not dropped")
	}
	if got.CertVerification != "strict" {
		t.Fatalf("CP→DP apply must migrate permissive to strict, got %q", got.CertVerification)
	}
}

// TestSnapshotApply_PermissiveMigrationIsAuditVisible proves the migration
// leaves an audit-ring diagnostic (the mission's "audit-visible" requirement),
// wired in decryptprofile_vars.go's init. Follows the CLAUDE.md content-scan
// pattern (unique discriminator) rather than a len() delta, which saturates
// under the determinism gate.
func TestSnapshotApply_PermissiveMigrationIsAuditVisible(t *testing.T) {
	swapDecProfileStore(t)
	const uniq = "audit-probe-perm-716"
	applyConfigSnapshot(ConfigSnapshot{
		Version:            1,
		DecryptionProfiles: []DecryptionProfile{{Name: uniq, CertVerification: "permissive"}},
	})
	var found bool
	for _, e := range auditGet() {
		if e.Action == "decryption-profile.cert-verification.migrated" && e.Object == uniq {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("permissive migration must emit an audit-ring diagnostic")
	}
}

// TestResolveInspectSkipVerify_NoPermissiveRegression — strict verifies and skip
// skips exactly as before; the removed permissive value has no runtime path.
func TestResolveInspectSkipVerify_NoPermissiveRegression(t *testing.T) {
	swapDecProfileStore(t)
	for _, p := range []DecryptionProfile{
		{Name: "strict", CertVerification: "strict"},
		{Name: "skip", CertVerification: "skip"},
	} {
		if _, err := globalDecryptionProfiles.Add(p); err != nil {
			t.Fatalf("seed %q: %v", p.Name, err)
		}
	}
	if resolveInspectSkipVerify(matchWith(&PolicyRule{DecryptionProfile: "strict"}), true) {
		t.Fatal("strict must verify (override rule skip)")
	}
	if !resolveInspectSkipVerify(matchWith(&PolicyRule{DecryptionProfile: "skip"}), false) {
		t.Fatal("skip must skip verify")
	}
}

// TestCertVerificationParity_GUIandRuntime pins that the admin GUI's
// certVerification <select> offers exactly the runtime-accepted values (minus
// the "inherit" empty option): no option the runtime would reject, and in
// particular no resurrected "permissive". This is the schema/GUI/runtime
// lockstep guard the mission requires.
func TestCertVerificationParity_GUIandRuntime(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read GUI: %v", err)
	}
	// The dp-cert <select> block. Extract the options between the select open and
	// its close so we only inspect the certVerification control.
	s := string(html)
	open := strings.Index(s, `id="dp-cert"`)
	if open < 0 {
		t.Fatal("dp-cert select not found in GUI")
	}
	end := strings.Index(s[open:], "</select>")
	if end < 0 {
		t.Fatal("dp-cert select not terminated")
	}
	block := s[open : open+end]

	// Enumerate EVERY value="X" the GUI offers in the dp-cert control (not just a
	// permissive tripwire) so a future drift in either direction is caught: a new
	// GUI option the runtime rejects, or a runtime value the GUI drops.
	guiValues := map[string]bool{}
	for _, m := range regexp.MustCompile(`value="([^"]*)"`).FindAllStringSubmatch(block, -1) {
		guiValues[m[1]] = true
	}
	if len(guiValues) == 0 {
		t.Fatal("no options parsed from dp-cert select")
	}
	if guiValues["permissive"] {
		t.Fatal("GUI must NOT offer certVerification=permissive (retired contract)")
	}

	// Forward parity: every non-empty value the GUI offers must be runtime-accepted
	// (the empty "" option is the inherit choice — always valid, skip explicitly).
	for v := range guiValues {
		if v == "" {
			continue
		}
		if err := decryptprofile.Validate(&DecryptionProfile{Name: "probe", CertVerification: v}); err != nil {
			t.Fatalf("GUI offers certVerification=%q but runtime rejects it: %v", v, err)
		}
	}
	// Reverse parity: every runtime-accepted non-empty value must be offered by the
	// GUI (so a newly-supported value can't be silently unreachable from the panel).
	for _, v := range []string{"strict", "skip"} {
		if !guiValues[v] {
			t.Fatalf("runtime accepts certVerification=%q but the GUI does not offer it", v)
		}
	}
	// And the runtime must reject permissive (parity with the GUI removal).
	if decryptprofile.Validate(&DecryptionProfile{Name: "probe", CertVerification: "permissive"}) == nil {
		t.Fatal("runtime must reject permissive (parity with GUI removal)")
	}
}
