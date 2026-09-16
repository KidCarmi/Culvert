package main

// FE-6A.2 CORRECTION ROUND 4 — RED matrix, written against the frozen
// corrected candidate 67e2a4a8 BEFORE any product change, for the three
// source-level blockers the third external review named.
//
// Blocker 1 — unreadable-settings recovery can overwrite durable evidence
// and change the cutover identity: after an UNREADABLE settings load the
// first save mints a NEW observed record and atomically REPLACES the file
// without re-reading it.
//
//	U1  a COMPLETED cutover record → an injected unreadable boot →
//	    readability restored → an UNRELATED save: the SAME operationId is
//	    adopted (record + sentinel), the observation consumed, no new audit
//	U2  the file STAYS unreadable → the unrelated save is REFUSED with zero
//	    file/runtime mutation: no record minted, the observation still
//	    pending, the evidence untouched
//	U3  (control) corrupt/quarantined recovery still produces ONE durable
//	    identity and ONE keyed audit (TestFE6A3C_B3's contract, re-pinned)
//
// Blocker 2 — the lost-response recovery is not bound to the reviewed
// import source: the operation lookup does not expose the record's
// importSourceRevision.
//
//	L0  GET /api/idp/operations/{id} of an idp.import record exposes the
//	    NON-SECRET importSourceRevision it was bound to; a non-import record
//	    carries none
//
// Blocker 3 — an existing candidate key is trusted without validating its
// confidentiality boundary (os.ReadFile + a length check).
//
//	C1  a group/world-readable (0644) key ⇒ operation_ledger_degraded; the
//	    key is neither chmod'ed nor replaced (beside commitments or not)
//	C2  a SYMLINK named as the key ⇒ degraded; the link is left intact
//	C3  a NON-REGULAR object (a directory) named as the key ⇒ degraded
//	C4  (control) the contracted 0600 regular key loads and stays healthy
//
// On 67e2a4a8: U1 fails (a new identity replaces the restored record), U2
// fails (the observation is consumed and a record minted despite the
// refused write), L0 fails (no token on the lookup), C1 fails (a 0644 key
// is accepted), C2 fails (the symlink target is read as the key). U3, C3
// and C4 pass.

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fe6a4cCompletedSettings is a settings file carrying a COMPLETED,
// audited, admin-triggered cutover under opID.
func fe6a4cCompletedSettings(opID string) []byte {
	return []byte(`{"legacy_ldap_retired":true,"legacy_ldap_cutover":{"operationId":"` + opID + `","profileId":"p-corp","profileName":"Registry AD","registryRevision":"r-1","actor":"admin@10.0.0.9","trigger":"admin_api","at":"2026-09-16T00:00:00Z"}}`)
}

// fe6a4cMakeUnreadable replaces the settings file at path with an
// EXISTING object that cannot be read as a file (a directory — the one
// unreadable shape root cannot see through) and returns a restore func
// that puts the original bytes back at the SAME path.
func fe6a4cMakeUnreadable(t *testing.T, path string) (restore func()) {
	t.Helper()
	aside := path + ".aside"
	if err := os.Rename(path, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(aside, path); err != nil {
			t.Fatal(err)
		}
	}
}

// ── U1 — restored evidence is ADOPTED, never replaced ───────────────────────

func TestFE6A4C_U1_RestoredCompletedRecordIsAdoptedOnTheFirstSave(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	opID := mustRandHex(16)
	if err := os.WriteFile(settings, fe6a4cCompletedSettings(opID), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()

	// Boot 1: the readable file is the truth (control).
	fe6a3cSimulateBoot(t, settings)
	if rec := legacyLDAPCutover(); rec == nil || rec.OperationID != opID {
		t.Fatalf("boot 1 did not adopt the completed record: %+v", rec)
	}
	original, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}

	// Boot 2: the same file is UNREADABLE for this boot only.
	restore := fe6a4cMakeUnreadable(t, settings)
	fe6a3cSimulateBoot(t, settings)
	if !legacyLDAPBootReconcilePending() {
		t.Fatal("an unreadable load must leave the boot observation PENDING")
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("audits after the unreadable boot = %d, want 0", n)
	}

	// Storage recovers: the ORIGINAL file is readable again at the SAME path,
	// and an UNRELATED admin save lands.
	restore()
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("unrelated save after recovery: %v", err)
	}
	adminSettingsSaveWG.Wait()
	rec := legacyLDAPCutover()
	if rec == nil || rec.OperationID != opID {
		t.Fatalf("the unrelated save REPLACED the cutover identity: got %+v, want the restored record %s", rec, opID)
	}
	if rec.Trigger != "admin_api" || rec.Actor != "admin@10.0.0.9" || rec.ProfileID != "p-corp" {
		t.Fatalf("the adopted record is not the durable one verbatim: %+v", rec)
	}
	if legacyLDAPBootReconcilePending() {
		t.Fatal("the observation was not consumed by the adoption")
	}
	retired, frec, present := fe6a3cSettingsFile(t, settings)
	if !present || !retired || frec == nil || frec["operationId"] != opID {
		t.Fatalf("file after the save: retired=%v record=%v present=%v, want the same record %s", retired, frec, present, opID)
	}
	if n, ids := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("a NEW retirement audit was emitted for an already-completed cutover: %d %v", n, ids)
	}
	if legacyLDAPCutoverDurability() != "durable" {
		t.Fatalf("durability = %q after adopting a durable record", legacyLDAPCutoverDurability())
	}
	// Boot 3: the truth is stable.
	fe6a3cSimulateBoot(t, settings)
	if got := legacyLDAPCutover(); got == nil || got.OperationID != opID {
		t.Fatalf("boot 3 identity = %+v, want %s", got, opID)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("boot 3 audited: %d", n)
	}
	_ = original
}

// TestFE6A4C_U1b is the review's exact shape — a regular file made
// unreadable by MODE — which a root-run process cannot observe (root reads
// through 0000); it runs where the harness is unprivileged (CI).
func TestFE6A4C_U1b_RestoredCompletedRecordIsAdopted_ModeUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based unreadability is invisible to root; U1 covers the shape with an unreadable object")
	}
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	opID := mustRandHex(16)
	if err := os.WriteFile(settings, fe6a4cCompletedSettings(opID), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	fe6a3cSimulateBoot(t, settings)
	if err := os.Chmod(settings, 0o000); err != nil {
		t.Fatal(err)
	}
	fe6a3cSimulateBoot(t, settings)
	if !legacyLDAPBootReconcilePending() {
		t.Fatal("unreadable load must leave the observation pending")
	}
	if err := os.Chmod(settings, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("save after recovery: %v", err)
	}
	adminSettingsSaveWG.Wait()
	if rec := legacyLDAPCutover(); rec == nil || rec.OperationID != opID {
		t.Fatalf("identity replaced: %+v, want %s", rec, opID)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("new audit emitted: %d", n)
	}
}

// ── U2 — still unreadable: the save is REFUSED, nothing mutates ─────────────

func TestFE6A4C_U2_StillUnreadableSettingsRefuseTheSaveWithZeroMutation(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	opID := mustRandHex(16)
	if err := os.WriteFile(settings, fe6a4cCompletedSettings(opID), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	restore := fe6a4cMakeUnreadable(t, settings)
	fe6a3cSimulateBoot(t, settings)
	if !legacyLDAPBootReconcilePending() {
		t.Fatal("unreadable load must leave the observation pending")
	}
	// An unrelated save while the truth is STILL unknown.
	if err := SaveAdminSettings(); err == nil {
		t.Fatal("a save landed while the authoritative settings file is unreadable — the evidence can be replaced")
	}
	adminSettingsSaveWG.Wait()
	if !legacyLDAPBootReconcilePending() {
		t.Fatal("the refused save CONSUMED the boot observation (a later recovery can no longer adopt the durable record)")
	}
	if rec := legacyLDAPCutover(); rec != nil {
		t.Fatalf("the refused save MINTED a cutover record in memory: %+v", rec)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("audits after a refused save = %d, want 0", n)
	}
	if st, err := os.Lstat(settings); err != nil || !st.IsDir() {
		t.Fatalf("the unreadable object at the settings path was replaced: %v %v", st, err)
	}
	if b, err := os.ReadFile(settings + ".aside"); err != nil || !bytes.Equal(b, fe6a4cCompletedSettings(opID)) {
		t.Fatalf("original evidence changed: %v", err)
	}
	// Recovery afterwards still adopts the durable record (U1's contract).
	restore()
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("save after recovery: %v", err)
	}
	adminSettingsSaveWG.Wait()
	if rec := legacyLDAPCutover(); rec == nil || rec.OperationID != opID {
		t.Fatalf("recovery after the refused save did not adopt %s: %+v", opID, rec)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("audits = %d, want 0", n)
	}
}

func TestFE6A4C_U2b_StillUnreadableFileBytesUnchanged_ModeUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based unreadability is invisible to root; U2 covers the shape with an unreadable object")
	}
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	opID := mustRandHex(16)
	want := fe6a4cCompletedSettings(opID)
	if err := os.WriteFile(settings, want, 0o000); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	fe6a3cSimulateBoot(t, settings)
	if err := SaveAdminSettings(); err == nil {
		t.Fatal("save landed on an unreadable file")
	}
	adminSettingsSaveWG.Wait()
	if err := os.Chmod(settings, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(settings)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("original bytes changed: %v", err)
	}
}

// ── U3 — corrupt/quarantined: one identity, one keyed audit (control) ────────

func TestFE6A4C_U3_QuarantinedRecoveryMintsOneIdentityAndOneKeyedAudit(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	dir := t.TempDir()
	settings := filepath.Join(dir, "admin_settings.json")
	if err := os.WriteFile(settings, []byte("{\"legacy_ldap_retired\": tru"), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	fe6a3cSimulateBoot(t, settings)
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("save after quarantine: %v", err)
	}
	adminSettingsSaveWG.Wait()
	rec := legacyLDAPCutover()
	if rec == nil || rec.Trigger != "observed" {
		t.Fatalf("no observed record after quarantine recovery: %+v", rec)
	}
	if retired, frec, _ := fe6a3cSettingsFile(t, settings); !retired || frec == nil || frec["operationId"] != rec.OperationID {
		t.Fatalf("durable record mismatch: retired=%v file=%v mem=%s", retired, frec, rec.OperationID)
	}
	for boot := 1; boot <= 2; boot++ {
		fe6a3cSimulateBoot(t, settings)
		if got := legacyLDAPCutover(); got == nil || got.OperationID != rec.OperationID {
			t.Fatalf("boot %d identity = %+v, want %s", boot, got, rec.OperationID)
		}
		if n, ids := fe6a3cRetirementAudits(since); n != 1 || ids[0] != rec.OperationID {
			t.Fatalf("boot %d audits = %d %v, want one keyed on %s", boot, n, ids, rec.OperationID)
		}
	}
	entries, _ := os.ReadDir(dir)
	quarantined := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "admin_settings.json.corrupt.") {
			quarantined = true
		}
	}
	if !quarantined {
		t.Fatal("quarantined evidence removed")
	}
}

// ── L0 — the lookup exposes the import's reviewed-source token ──────────────

func TestFE6A4C_L0_OperationLookupExposesImportSourceRevisionOnlyForImports(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	fe6aLegacyLDAPFixture(t, settings)
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP1))
	token := fe6a3cSourceToken(t)
	docRev := fe6acDocRevision(t)
	importOp := testOperationID()
	if code, m := fe6a2cImport(t, "documentRevision="+docRev, "operationId="+importOp, "importSourceRevision="+token); code != http.StatusOK {
		t.Fatalf("import = %d %v", code, m)
	}
	code, m := fe6a2cLookup(t, importOp)
	if code != http.StatusOK || m["action"] != "idp.import" || m["state"] != "committed" {
		t.Fatalf("lookup = %d %v", code, m)
	}
	if m["importSourceRevision"] != token {
		t.Fatalf("the lookup of a committed idp.import carries importSourceRevision=%v, want the reviewed token %q — a lost-response recovery cannot bind the record to the marker", m["importSourceRevision"], token)
	}
	if strings.Contains(fmt.Sprint(m), fe6a3cLegacyBindP1) {
		t.Fatal("the lookup discloses the bind credential")
	}
	// A non-import record carries no token.
	createOp := testOperationID()
	body := ldapProfileBodyForPut("Other AD", map[string]any{"bindPassword": "s"})
	if code, m := fe6acCreateFenced(t, body, "operationId="+createOp); code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	code, m = fe6a2cLookup(t, createOp)
	if code != http.StatusOK || m["action"] != "idp.create" {
		t.Fatalf("create lookup = %d %v", code, m)
	}
	if _, has := m["importSourceRevision"]; has {
		t.Fatalf("a non-import record carries importSourceRevision: %v", m)
	}
}

// ── C1–C4 — the key's confidentiality boundary ──────────────────────────────

const fe6a4cCommitmentLedger = `[{"operationId":"a1b2c3d4-0000-4000-8000-000000000004","state":"aborted","action":"idp.create","actor":"x","profileId":"p","specDigest":"d","candidateCommitment":"c0ffee","registryRevision":"r","cutover":false,"startedAt":"2026-09-16T00:00:00Z","finishedAt":"2026-09-16T00:00:01Z","code":"stale","audited":false}]`

func fe6a4cKeyFixture(t *testing.T, withCommitments bool) (regPath, keyPath string) {
	t.Helper()
	regPath, keyPath, dir := fe6a3cKeyPaths(t)
	if withCommitments {
		if err := os.WriteFile(filepath.Join(dir, idpOperationsFile), []byte(fe6a4cCommitmentLedger), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return regPath, keyPath
}

func fe6a4cAssertDegradedAndUntouched(t *testing.T, regPath, keyPath string, before os.FileInfo, want []byte) {
	t.Helper()
	store := newIdPOperationStore(regPath)
	if store.Degraded() == nil {
		t.Fatalf("a key outside the node-local 0600 boundary (%v) was ACCEPTED — the exposed HMAC is an offline guessing oracle for short bind passwords", before.Mode())
	}
	if _, _, err := store.Begin(idpOperation{OperationID: testOperationID(), Action: "idp.create", SpecDigest: "d", CandidateCommitment: "c"}); !errors.Is(err, errIdPOperationLedgerDegraded) {
		t.Fatalf("Begin = %v, want %v", err, errIdPOperationLedgerDegraded)
	}
	after, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatalf("the key object was REMOVED: %v", err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("the key was silently re-moded: %v → %v", before.Mode(), after.Mode())
	}
	if want != nil {
		if got, rerr := os.ReadFile(keyPath); rerr != nil || !bytes.Equal(got, want) {
			t.Fatalf("the key bytes were replaced: %v", rerr)
		}
	}
}

func TestFE6A4C_C1_WorldReadableKeyIsDegradedNeverRemodedOrReplaced(t *testing.T) {
	for _, withCommitments := range []bool{true, false} {
		regPath, keyPath := fe6a4cKeyFixture(t, withCommitments)
		key := []byte(strings.Repeat("k", idpCandidateKeyLen))
		if err := os.WriteFile(keyPath, key, 0o644); err != nil { // #nosec G306 -- the exposed mode IS the fault under test
			t.Fatal(err)
		}
		if err := os.Chmod(keyPath, 0o644); err != nil { // umask-proof
			t.Fatal(err)
		}
		before, err := os.Lstat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		fe6a4cAssertDegradedAndUntouched(t, regPath, keyPath, before, key)
	}
}

func TestFE6A4C_C2_SymlinkKeyIsDegradedAndLeftIntact(t *testing.T) {
	regPath, keyPath := fe6a4cKeyFixture(t, true)
	target := filepath.Join(filepath.Dir(keyPath), "elsewhere.key")
	if err := os.WriteFile(target, []byte(strings.Repeat("s", idpCandidateKeyLen)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, keyPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode()&os.ModeSymlink == 0 {
		t.Fatal("fixture: not a symlink")
	}
	fe6a4cAssertDegradedAndUntouched(t, regPath, keyPath, before, nil)
	if link, err := os.Readlink(keyPath); err != nil || link != target {
		t.Fatalf("symlink changed: %q %v", link, err)
	}
}

func TestFE6A4C_C3_NonRegularKeyObjectIsDegraded(t *testing.T) {
	regPath, keyPath := fe6a4cKeyFixture(t, true)
	if err := os.Mkdir(keyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	fe6a4cAssertDegradedAndUntouched(t, regPath, keyPath, before, nil)
}

func TestFE6A4C_C4_OwnerOnlyRegularKeyLoads(t *testing.T) {
	regPath, keyPath := fe6a4cKeyFixture(t, true)
	key := []byte(strings.Repeat("g", idpCandidateKeyLen))
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	store := newIdPOperationStore(regPath)
	if d := store.Degraded(); d != nil {
		t.Fatalf("the contracted 0600 regular key must load: %+v", d)
	}
	if got, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("key changed: %v", err)
	}
	if st, err := os.Lstat(keyPath); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode changed: %v %v", st, err)
	}
}
