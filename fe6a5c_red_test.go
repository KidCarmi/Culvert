package main

// FE-6A.2 CORRECTION ROUND 5 — RED matrix, written against the frozen
// corrected candidate a56ac527 BEFORE any product change, for the three
// source-level blockers the fourth external review named.
//
// Blocker 1 — storage recovery adopts only the cutover fields and then
// rewrites the file from a DEFAULTED runtime: after an unreadable boot the
// first save re-reads the file, copies `legacy_ldap_retired` +
// `legacy_ldap_cutover`, and atomically replaces the whole file with a
// snapshot of a runtime that booted on defaults — every unrelated durable
// setting and every unknown-compatible field is destroyed. A sentinel
// without its record is accepted, at boot and under the save, as durable
// truth.
//
//	R1  a COMPLETED cutover + DISTINCTIVE unrelated settings across several
//	    ownership surfaces (session TTL, admin-UI allow CIDRs, rate-limit
//	    exemption, log level) + an unknown-compatible field → an unreadable
//	    boot on a defaulted runtime → readability restored → an UNRELATED
//	    save. EITHER the save is refused with the file byte-identical, the
//	    observation still pending, no record and no audit (restart
//	    required — the next boot adopts the complete file), OR it succeeds
//	    with every seeded field, the unknown field and the same cutover
//	    identity surviving. A partial adoption that rewrites the rest from
//	    defaults is the defect.
//	R2  `legacy_ldap_retired:true` WITHOUT its record: retired stays in
//	    force (fail closed), nothing is minted, no audit, and the durability
//	    word is the explicit degraded `record_missing` — never `durable`;
//	    a save carries the evidence verbatim (sentinel kept, still no
//	    record) and a restart reports the same.
//	R3  the same sentinel-only file restored after an unreadable boot is
//	    never adopted as `durable`: the save is refused (restart) or, if
//	    accepted, reports `record_missing`.
//	U1/U1b (fe6a4c_red_test.go) — ASSERTION CORRECTION recorded in this
//	    commit: the round-4 premise "the first save after recovery ADOPTS
//	    the record and succeeds without a restart" was only safe for the
//	    cutover fields; the corrected contract is "the save is refused
//	    with zero mutation and the restart adopts the COMPLETE file".
//
// Blocker 2 — the candidate key is validated on one path lookup and read
// on another (os.Lstat, then os.ReadFile): a path swap between the two
// makes a symlink target's bytes a healthy key.
//
//	K1  a channel-controlled swap between inspection and read — the key is
//	    replaced by a symlink to a group/world-readable target: the result
//	    is the already-opened validated key or fail-closed degradation,
//	    NEVER the symlink target's bytes
//	K2  the same swap to a symlink whose target is a 0600 regular file with
//	    different bytes: never the target's bytes
//	K3  (control) no swap ⇒ the validated key loads
//	K4  (control) a symlink present BEFORE the open ⇒ degraded, link intact
//	K5  (control) a 0600 regular key of the wrong length ⇒ refused
//
// Blocker 3 — the admin-API cutover's retirement audit is unkeyed
// (audit.Add, no Entry.OperationID, identity in free text) and not
// recoverable: a failed append is silently lost, a crash after the append
// duplicates it at the next boot.
//
//	A1  the admin cutover's `idp.legacy_ldap.retired` entry carries the
//	    STRUCTURAL operationId of the cutover record, exactly once, and the
//	    durable record is not left audit-pending
//	A2  an audit append failure leaves the durable cutover AUDIT-PENDING
//	    (no unkeyed best-effort entry) and the next boot completes it once
//	A3  (control) a durable admin_api record with auditPending completes
//	    exactly once across two restarts
//	A4  a crash AFTER the append but BEFORE the marker persisted does not
//	    duplicate the entry at the next boot (operation-keyed dedup on the
//	    durable JSONL record)
//	A5  (control) a refused cutover (persist failure; preflight failure)
//	    emits no retirement-success audit
//
// On a56ac527: R1 fails (the file is rewritten from defaults: the seeded
// session TTL, allow CIDRs, exemption, log level and the unknown field are
// gone), R2 fails (`durable`), R3 fails (adopted as `durable`), U1/U1b fail
// under the corrected premise (the save succeeds); K1/K2 fail (no seam —
// against a temporarily seamed a56ac527 the symlink target's bytes are
// returned as the key), K3–K5 pass; A1 fails (empty OperationID), A2 fails
// (an unkeyed entry is emitted best-effort and nothing is pending), A4
// fails (a second entry is appended at the next boot), A3 and A5 pass.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// ── Blocker 1 ────────────────────────────────────────────────────────────────

const fe6a5cUnknownField = `"fe6a5c_unknown_compatible_field":"kept-verbatim"`

// fe6a5cSeededSettings is a settings file carrying a COMPLETED admin cutover
// under opID plus distinctive unrelated durable settings on several
// ownership surfaces and one unknown-compatible field.
func fe6a5cSeededSettings(opID string) []byte {
	return []byte(`{"legacy_ldap_retired":true,"legacy_ldap_cutover":{"operationId":"` + opID + `","profileId":"p-corp","profileName":"Registry AD","registryRevision":"r-1","actor":"admin@10.0.0.9","trigger":"admin_api","at":"2026-09-16T00:00:00Z"},` +
		`"session_timeout_hours":3,"ui_allow_ips":["203.0.113.0/24"],"rate_limit_exemptions":["198.51.100.7"],"log_level":"DEBUG",` + fe6a5cUnknownField + `}`)
}

// fe6a5cDefaultRuntime emulates the FRESH PROCESS an unreadable boot runs
// on: every surface R1 seeds is back at its default before the boot, and
// restored to the pre-test value on cleanup.
func fe6a5cDefaultRuntime(t *testing.T) {
	t.Helper()
	prevTTL, prevCIDRs, prevLevel := getSessionTTL(), ListUIAllowedCIDRs(), effectiveAdminLogLevel()
	SetSessionTTL(8 * time.Hour)
	_ = SetUIAllowedCIDRs(nil)
	rl.RemoveExemption("198.51.100.7")
	SetLogLevel(ParseLogLevel("INFO"))
	t.Cleanup(func() {
		SetSessionTTL(prevTTL)
		_ = SetUIAllowedCIDRs(prevCIDRs)
		rl.RemoveExemption("198.51.100.7")
		SetLogLevel(prevLevel)
	})
}

// fe6a5cSettingsMap decodes the whole durable file.
func fe6a5cSettingsMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("settings file is not JSON: %v", err)
	}
	return m
}

func TestFE6A5C_R1_RecoveredSettingsAreNeverPartiallyAdoptedThenOverwritten(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	fe6a5cDefaultRuntime(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	opID := mustRandHex(16)
	if err := os.WriteFile(settings, fe6a5cSeededSettings(opID), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()

	// Boot 1 (control): the readable file is applied across its surfaces.
	fe6a3cSimulateBoot(t, settings)
	if got := getSessionTTL(); got != 3*time.Hour {
		t.Fatalf("boot 1 session TTL = %v, want the seeded 3h", got)
	}
	if got := ListUIAllowedCIDRs(); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("boot 1 UI allow CIDRs = %v", got)
	}
	original, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	unknownSurvivedBoot1 := bytes.Contains(original, []byte(`fe6a5c_unknown_compatible_field`))

	// Boot 2: a FRESH process (defaults everywhere) finds the file unreadable.
	fe6a5cDefaultRuntime(t)
	restore := fe6a4cMakeUnreadable(t, settings)
	fe6a3cSimulateBoot(t, settings)
	if !legacyLDAPBootReconcilePending() {
		t.Fatal("an unreadable load must leave the boot observation PENDING")
	}
	if got := getSessionTTL(); got != 8*time.Hour {
		t.Fatalf("the unreadable boot did not run on defaults (TTL %v) — the test premise is wrong", got)
	}

	// Storage recovers at the SAME path; an UNRELATED save lands on the
	// defaulted runtime.
	restore()
	saveErr := SaveAdminSettings()
	adminSettingsSaveWG.Wait()
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if n, ids := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("a retirement audit was emitted for an already-completed cutover: %d %v", n, ids)
	}
	if saveErr != nil {
		// Refused: zero mutation, restart required — the complete file is
		// adopted by the next boot.
		if !bytes.Equal(after, original) {
			t.Fatalf("the refused save still changed the file:\n got %s\nwant %s", after, original)
		}
		if !strings.Contains(saveErr.Error(), "restart") {
			t.Fatalf("a refused recovery save must name the remedy (restart): %v", saveErr)
		}
		if !legacyLDAPBootReconcilePending() {
			t.Fatal("the refused save consumed the observation")
		}
		if rec := legacyLDAPCutover(); rec != nil {
			t.Fatalf("the refused save minted/adopted a record on a defaulted runtime: %+v", rec)
		}
		if legacyLDAPCutoverDurability() == "durable" {
			t.Fatal("a refused save must not report the cutover durable")
		}
	} else {
		// Accepted: only a COMPLETE rehydration is acceptable — every
		// seeded field, the unknown field and the same identity survive.
		m := fe6a5cSettingsMap(t, settings)
		rec, _ := m["legacy_ldap_cutover"].(map[string]any)
		if m["legacy_ldap_retired"] != true || rec == nil || rec["operationId"] != opID {
			t.Fatalf("cutover identity not preserved by the accepted save: %v", m["legacy_ldap_cutover"])
		}
		if ttl, _ := m["session_timeout_hours"].(float64); ttl != 3 {
			t.Fatalf("PARTIAL ADOPTION: session_timeout_hours rewritten from the defaulted runtime: %v (want 3)", m["session_timeout_hours"])
		}
		if cidrs, _ := m["ui_allow_ips"].([]any); len(cidrs) != 1 || cidrs[0] != "203.0.113.0/24" {
			t.Fatalf("PARTIAL ADOPTION: ui_allow_ips rewritten from the defaulted runtime: %v", m["ui_allow_ips"])
		}
		if ex, _ := m["rate_limit_exemptions"].([]any); len(ex) != 1 || ex[0] != "198.51.100.7" {
			t.Fatalf("PARTIAL ADOPTION: rate_limit_exemptions rewritten: %v", m["rate_limit_exemptions"])
		}
		if m["log_level"] != "DEBUG" {
			t.Fatalf("PARTIAL ADOPTION: log_level rewritten: %v", m["log_level"])
		}
		if unknownSurvivedBoot1 && m["fe6a5c_unknown_compatible_field"] != "kept-verbatim" {
			t.Fatalf("PARTIAL ADOPTION: the unknown-compatible field was dropped: %v", m["fe6a5c_unknown_compatible_field"])
		}
		if getSessionTTL() != 3*time.Hour {
			t.Fatalf("an accepted recovery save must have rehydrated the runtime (TTL %v)", getSessionTTL())
		}
	}

	// Boot 3 (readable again): the COMPLETE file is the truth.
	fe6a5cDefaultRuntime(t)
	fe6a3cSimulateBoot(t, settings)
	if got := legacyLDAPCutover(); got == nil || got.OperationID != opID {
		t.Fatalf("boot 3 identity = %+v, want %s", got, opID)
	}
	if got := getSessionTTL(); got != 3*time.Hour {
		t.Fatalf("boot 3 session TTL = %v, want the seeded 3h (the durable settings were destroyed)", got)
	}
	if got := ListUIAllowedCIDRs(); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("boot 3 UI allow CIDRs = %v (destroyed)", got)
	}
	if legacyLDAPCutoverDurability() != "durable" {
		t.Fatalf("boot 3 durability = %q", legacyLDAPCutoverDurability())
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("boot 3 audited: %d", n)
	}
}

func TestFE6A5C_R2_SentinelWithoutRecordIsDegradedEvidenceNeverHealthyTruth(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.WriteFile(settings, []byte(`{"legacy_ldap_retired":true,"session_timeout_hours":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	prevTTL := getSessionTTL()
	t.Cleanup(func() { SetSessionTTL(prevTTL) })
	since := fe6aSince()
	for boot := 1; boot <= 2; boot++ {
		fe6a3cSimulateBoot(t, settings)
		if !legacyLDAPRetired() {
			t.Fatalf("boot %d: the sentinel must stay in force (fail closed — the legacy authenticator is never re-armed by a missing record)", boot)
		}
		if rec := legacyLDAPCutover(); rec != nil {
			t.Fatalf("boot %d: a record was INVENTED for a sentinel-only file: %+v", boot, rec)
		}
		if got := legacyLDAPCutoverDurability(); got != "record_missing" {
			t.Fatalf("boot %d: durability = %q, want the explicit degraded word record_missing (never durable)", boot, got)
		}
		if n, ids := fe6a3cRetirementAudits(since); n != 0 {
			t.Fatalf("boot %d: a sentinel-only file produced a retirement audit: %d %v", boot, n, ids)
		}
		// An unrelated save carries the evidence VERBATIM: sentinel kept,
		// still no record, the unrelated settings intact.
		if err := SaveAdminSettings(); err != nil {
			t.Fatalf("boot %d: unrelated save: %v", boot, err)
		}
		adminSettingsSaveWG.Wait()
		m := fe6a5cSettingsMap(t, settings)
		if m["legacy_ldap_retired"] != true {
			t.Fatalf("boot %d: the save dropped the sentinel: %v", boot, m)
		}
		if _, invented := m["legacy_ldap_cutover"]; invented {
			t.Fatalf("boot %d: the save perpetuated an INVENTED record as complete truth: %v", boot, m["legacy_ldap_cutover"])
		}
		if ttl, _ := m["session_timeout_hours"].(float64); ttl != 3 {
			t.Fatalf("boot %d: unrelated setting lost: %v", boot, m["session_timeout_hours"])
		}
		if got := legacyLDAPCutoverDurability(); got != "record_missing" {
			t.Fatalf("boot %d: durability after the save = %q", boot, got)
		}
	}
}

func TestFE6A5C_R3_SentinelWithoutRecordRestoredAfterUnreadableBootIsNeverDurable(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.WriteFile(settings, []byte(`{"legacy_ldap_retired":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	restore := fe6a4cMakeUnreadable(t, settings)
	fe6a3cSimulateBoot(t, settings)
	if !legacyLDAPBootReconcilePending() {
		t.Fatal("unreadable load must leave the observation pending")
	}
	restore()
	err := SaveAdminSettings()
	adminSettingsSaveWG.Wait()
	if rec := legacyLDAPCutover(); rec != nil {
		t.Fatalf("a record was invented on recovery: %+v", rec)
	}
	if got := legacyLDAPCutoverDurability(); got == "durable" {
		t.Fatalf("a sentinel without its record was adopted as DURABLE (save err=%v)", err)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("audited: %d", n)
	}
	m := fe6a5cSettingsMap(t, settings)
	if _, invented := m["legacy_ldap_cutover"]; invented {
		t.Fatalf("the file now carries an invented record: %v", m["legacy_ldap_cutover"])
	}
}

// ── Blocker 2 ────────────────────────────────────────────────────────────────

// idpCandidateKeyPreReadHook is the ROUND-5 test seam between the key's
// boundary validation and its read (nil in production). On a56ac527 it is
// declared HERE and never called — K1/K2 fail on that fact alone; against
// a temporarily seamed a56ac527 they fail on the defect itself. The product
// correction moves the declaration beside the key loader.
var idpCandidateKeyPreReadHook func()

// fe6a5cKeyDir lays out a validated 0600 regular key K and a decoy target
// with different bytes under mode, returning both paths and K's bytes.
func fe6a5cKeyDir(t *testing.T, decoyMode os.FileMode) (keyPath, decoyPath string, key, decoy []byte) {
	t.Helper()
	dir := t.TempDir()
	keyPath, decoyPath = filepath.Join(dir, ".idp_candidate_key"), filepath.Join(dir, "decoy.key")
	key, decoy = bytes.Repeat([]byte{0x11}, idpCandidateKeyLen), bytes.Repeat([]byte{0x22}, idpCandidateKeyLen)
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(decoyPath, decoy, decoyMode); err != nil { //nolint:gosec // G306: the decoy's exposed mode IS the fault under test
		t.Fatal(err)
	}
	return keyPath, decoyPath, key, decoy
}

// fe6a5cSwapBetweenInspectAndRead runs idpLoadCandidateKey with the seam
// armed to replace the key path by a symlink to decoyPath exactly between
// validation and read, and reports the outcome plus whether the seam ran.
func fe6a5cSwapBetweenInspectAndRead(t *testing.T, keyPath, decoyPath string) (got []byte, err error, seamRan bool) {
	t.Helper()
	prev := idpCandidateKeyPreReadHook
	idpCandidateKeyPreReadHook = func() {
		seamRan = true
		if rerr := os.Rename(keyPath, keyPath+".aside"); rerr != nil {
			t.Errorf("swap: %v", rerr)
		}
		if lerr := os.Symlink(decoyPath, keyPath); lerr != nil {
			t.Errorf("swap: %v", lerr)
		}
	}
	t.Cleanup(func() { idpCandidateKeyPreReadHook = prev })
	got, err = idpLoadCandidateKey(keyPath, false)
	return got, err, seamRan
}

func fe6a5cAssertNeverTheDecoy(t *testing.T, got []byte, err error, seamRan bool, key, decoy []byte) {
	t.Helper()
	if !seamRan {
		t.Fatal("the key loader has no seam between validation and read — the check/use race cannot be exercised (round-5 correction absent)")
	}
	switch {
	case err == nil && bytes.Equal(got, key):
		// the already-opened validated object
	case err != nil && errors.Is(err, errIdPCandidateKeyExposed):
		// fail-closed degradation
	case err == nil && bytes.Equal(got, decoy):
		t.Fatal("CHECK/USE RACE: the replacement symlink target's bytes were loaded as a healthy key")
	default:
		t.Fatalf("unexpected outcome: key=%x err=%v", got, err)
	}
}

func TestFE6A5C_K1_SwapToExposedTargetBetweenInspectAndReadNeverYieldsTheTarget(t *testing.T) {
	keyPath, decoyPath, key, decoy := fe6a5cKeyDir(t, 0o644)
	got, err, ran := fe6a5cSwapBetweenInspectAndRead(t, keyPath, decoyPath)
	fe6a5cAssertNeverTheDecoy(t, got, err, ran, key, decoy)
}

func TestFE6A5C_K2_SwapToOwnerOnlyTargetBetweenInspectAndReadNeverYieldsTheTarget(t *testing.T) {
	keyPath, decoyPath, key, decoy := fe6a5cKeyDir(t, 0o600)
	got, err, ran := fe6a5cSwapBetweenInspectAndRead(t, keyPath, decoyPath)
	fe6a5cAssertNeverTheDecoy(t, got, err, ran, key, decoy)
}

func TestFE6A5C_K3_ControlValidatedKeyLoadsWithoutASwap(t *testing.T) {
	keyPath, _, key, _ := fe6a5cKeyDir(t, 0o600)
	got, err := idpLoadCandidateKey(keyPath, false)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("validated key: %x %v", got, err)
	}
}

func TestFE6A5C_K4_ControlSymlinkPresentBeforeTheOpenIsDegradedAndLeftIntact(t *testing.T) {
	keyPath, decoyPath, _, _ := fe6a5cKeyDir(t, 0o600)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoyPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := idpLoadCandidateKey(keyPath, false); !errors.Is(err, errIdPCandidateKeyExposed) {
		t.Fatalf("symlink key = %v, want exposed", err)
	}
	if st, err := os.Lstat(keyPath); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was not left intact: %v %v", st, err)
	}
}

func TestFE6A5C_K5_ControlWrongLengthRegularKeyIsRefused(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), ".idp_candidate_key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x33}, idpCandidateKeyLen+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := idpLoadCandidateKey(keyPath, false); err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("a %d-byte key loaded: %x %v", idpCandidateKeyLen+1, got, err)
	}
}

// ── Blocker 3 ────────────────────────────────────────────────────────────────

// fe6a5cAdminCutover drives an ENABLED LDAP create carrying the legacy
// cutover through the admin API and returns the response.
func fe6a5cAdminCutover(t *testing.T, url string) *httptest.ResponseRecorder {
	t.Helper()
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s", "url": url})
	body["enabled"] = true
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath("operationId="+testOperationID(), "cutoverConfirm=ldap://legacy.corp.example:389"), body))
	return w
}

func fe6a5cAuditPendingInFile(t *testing.T, path string) bool {
	t.Helper()
	_, rec, present := fe6a3cSettingsFile(t, path)
	if !present || rec == nil {
		t.Fatalf("no cutover record in %s", path)
	}
	pending, _ := rec["auditPending"].(bool)
	return pending
}

func TestFE6A5C_A1_AdminCutoverAuditCarriesTheStructuralOperationID(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	since := fe6aSince()
	if w := fe6a5cAdminCutover(t, fe6aStubDirectory(t)); w.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	adminSettingsSaveWG.Wait()
	rec := legacyLDAPCutover()
	if rec == nil || rec.OperationID == "" || rec.Trigger != "admin_api" {
		t.Fatalf("cutover record = %+v", rec)
	}
	n, ids := fe6a3cRetirementAudits(since)
	if n != 1 {
		t.Fatalf("retirement audits = %d %v, want exactly one", n, ids)
	}
	if ids[0] != rec.OperationID {
		t.Fatalf("the admin cutover audit carries operationId %q, want the STRUCTURAL identity %q (free-text detail is not evidence)", ids[0], rec.OperationID)
	}
	if rec.AuditPending || fe6a5cAuditPendingInFile(t, settings) {
		t.Fatal("the completed audit is still marked pending")
	}
	if legacyLDAPCutoverDurability() != "durable" {
		t.Fatalf("durability = %q", legacyLDAPCutoverDurability())
	}
}

func TestFE6A5C_A2_AuditAppendFailureLeavesTheAdminCutoverAuditPendingThenCompletesOnce(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	// A durable sink that cannot synchronise: the operation-keyed append
	// boundary refuses it (audit.ErrSinkNotSyncable); the unkeyed best-effort
	// path writes to it happily — which is exactly the defect.
	restoreSink := audit.SetPersistForTest(&bytes.Buffer{})
	since := fe6aSince()
	if w := fe6a5cAdminCutover(t, fe6aStubDirectory(t)); w.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	adminSettingsSaveWG.Wait()
	restoreSink()
	rec := legacyLDAPCutover()
	if rec == nil || rec.OperationID == "" {
		t.Fatalf("cutover record = %+v", rec)
	}
	if n, ids := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("the audit could not be appended durably, yet %d entr(y/ies) %v were emitted (unkeyed best-effort) — nothing left to recover", n, ids)
	}
	if !rec.AuditPending {
		t.Fatal("the durable cutover is not marked audit-pending after the append failed")
	}
	if !fe6a5cAuditPendingInFile(t, settings) {
		t.Fatal("the audit-pending marker is not durable")
	}
	// The sink is healthy again: the next boot completes the SAME identity's
	// audit exactly once and clears the marker durably.
	opID := rec.OperationID
	for boot := 1; boot <= 2; boot++ {
		fe6a3cSimulateBoot(t, settings)
		n, ids := fe6a3cRetirementAudits(since)
		if n != 1 || ids[0] != opID {
			t.Fatalf("boot %d: audits = %d %v, want exactly one keyed on %s", boot, n, ids, opID)
		}
		if fe6a5cAuditPendingInFile(t, settings) {
			t.Fatalf("boot %d: still pending after completion", boot)
		}
	}
}

func TestFE6A5C_A3_ControlDurableAdminRecordWithPendingAuditCompletesOnceOnRestart(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	opID := mustRandHex(16)
	if err := os.WriteFile(settings, []byte(`{"legacy_ldap_retired":true,"legacy_ldap_cutover":{"operationId":"`+opID+`","profileId":"p-corp","actor":"admin@10.0.0.9","trigger":"admin_api","at":"2026-09-16T00:00:00Z","auditPending":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	for boot := 1; boot <= 2; boot++ {
		fe6a3cSimulateBoot(t, settings)
		n, ids := fe6a3cRetirementAudits(since)
		if n != 1 || ids[0] != opID {
			t.Fatalf("boot %d: audits = %d %v, want exactly one keyed on %s", boot, n, ids, opID)
		}
		if fe6a5cAuditPendingInFile(t, settings) {
			t.Fatalf("boot %d: still pending", boot)
		}
	}
}

func fe6a5cRetirementLinesInFile(t *testing.T, path string) (n int, opIDs []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		if e.Action == "idp.legacy_ldap.retired" {
			n++
			opIDs = append(opIDs, e.OperationID)
		}
	}
	return n, opIDs
}

func TestFE6A5C_A4_CrashAfterAppendBeforeMarkerPersistenceDoesNotDuplicateTheAudit(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	// A REAL durable sink (the production RotatingFile): the dedup the
	// boundary promises is against the JSONL record, not the ring.
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	restoreAudit := audit.ResetForTest()
	if err := audit.Init(auditPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = audit.Close()
		audit.ClearPersistForTest()
		restoreAudit()
	})
	if w := fe6a5cAdminCutover(t, fe6aStubDirectory(t)); w.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", w.Code, w.Body.String())
	}
	adminSettingsSaveWG.Wait()
	rec := legacyLDAPCutover()
	if rec == nil {
		t.Fatal("no cutover record")
	}
	if n, _ := fe6a5cRetirementLinesInFile(t, auditPath); n != 1 {
		t.Fatalf("durable audit lines after the cutover = %d, want 1", n)
	}
	// CRASH between the append and the marker's persistence: the durable
	// record still says auditPending, the JSONL already holds the entry.
	m := fe6a5cSettingsMap(t, settings)
	cut, _ := m["legacy_ldap_cutover"].(map[string]any)
	if cut == nil {
		t.Fatalf("no durable record: %v", m)
	}
	cut["auditPending"] = true
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, data, 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSimulateBoot(t, settings)
	n, ids := fe6a5cRetirementLinesInFile(t, auditPath)
	if n != 1 {
		t.Fatalf("DUPLICATE: durable audit lines after the recovery boot = %d %v, want exactly one keyed on %s", n, ids, rec.OperationID)
	}
	if ids[0] != rec.OperationID {
		t.Fatalf("the durable entry is not keyed on the cutover identity: %q vs %q", ids[0], rec.OperationID)
	}
	if fe6a5cAuditPendingInFile(t, settings) {
		t.Fatal("the marker was not cleared after the entry was found durable")
	}
}

func TestFE6A5C_A5_ControlRefusedCutoverEmitsNoRetirementAudit(t *testing.T) {
	// (a) the sentinel cannot be persisted.
	t.Run("persist_failure", func(t *testing.T) {
		_, _ = fe6aLegacyLDAPFixture(t, fe6aBrokenPath(t, "admin_settings.json"))
		fe6a2cResetCutoverRecord(t) // the record is process-global: start from none
		since := fe6aSince()
		w := fe6a5cAdminCutover(t, fe6aStubDirectory(t))
		fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")
		if n, ids := fe6a3cRetirementAudits(since); n != 0 {
			t.Fatalf("a refused cutover emitted a retirement audit: %d %v", n, ids)
		}
		if legacyLDAPRetired() || legacyLDAPCutover() != nil {
			t.Fatal("a refused cutover left runtime state behind")
		}
	})
	// (b) the directory preflight refuses the candidate.
	t.Run("preflight_failure", func(t *testing.T) {
		_, _ = fe6aLegacyLDAPFixture(t, filepath.Join(t.TempDir(), "admin_settings.json"))
		fe6a2cResetCutoverRecord(t)
		since := fe6aSince()
		w := fe6a5cAdminCutover(t, "ldap://127.0.0.1:1")
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("preflight refusal = %d: %s", w.Code, w.Body.String())
		}
		if n, ids := fe6a3cRetirementAudits(since); n != 0 {
			t.Fatalf("a preflight-refused cutover emitted a retirement audit: %d %v", n, ids)
		}
		if legacyLDAPRetired() || legacyLDAPCutover() != nil {
			t.Fatal("a refused cutover left runtime state behind")
		}
	})
}
