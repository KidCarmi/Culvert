package main

// FE-6A.2 CORRECTION ROUND 3 — RED matrix, written against the frozen
// corrected candidate eb90ebc5 BEFORE any product change, for the three
// source-level blockers the second external review named.
//
// Blocker 1 — the import is not bound to the legacy source the admin
// reviewed. GET /api/idp/legacy-ldap must publish a server-owned, keyed,
// non-disclosing `importSourceRevision` over EVERY security-effective
// imported field (credential value included); POST …/import must require
// it (428 import_source_required), refuse a stale one with a structured 409
// import_source_stale BEFORE any ledger intent or registry write, bind the
// operation record to it, and echo it on success and replay.
//
//	S1  reviewed source A, YAML changes to B before the POST ⇒ 409
//	    import_source_stale (current token published), zero mutation;
//	    an absent token ⇒ 428 import_source_required
//	S3  the exact token imports once, replays once (echoed) across a
//	    restart; the same operationId with a different token ⇒ mismatch
//	S4  a CREDENTIAL-ONLY change invalidates the reviewed token; nothing
//	    discloses the credential
//
// Blocker 2 — `.idp_candidate_key` is not durably created.
//
//	K1  the key's publication is fsynced (file + directory) before the
//	    store reports healthy
//	K2  a file-fsync or directory-fsync fault during publication leaves
//	    the store fail-closed (degraded), never a healthy store with a key
//	    of unknown durability — no intent can be recorded
//	K3  concurrent minting publishes exactly ONE generation and every
//	    caller reads it
//	K4  a ledger that already carries commitment-bearing records with a
//	    MISSING key is DEGRADED, never silently re-keyed
//	K5  (control) a missing key with no commitment-bearing ledger mints
//
// Blocker 3 — boot reconciliation loses the transition on missing/corrupt
// settings.
//
//	B1  missing settings + YAML + enabled registry profile ⇒ ONE durable
//	    observed record (sentinel + record together, operation-keyed
//	    audit) across two boots
//	B2  unreadable settings ⇒ shadowed, no success audit, no sentinel
//	    without its record; the first save after storage recovery
//	    reconciles the pending transition exactly once
//	B3  corrupt/quarantined settings ⇒ evidence preserved, no incomplete
//	    retirement record; reconciled exactly once on recovery
//	B4  crash after the durable record and BEFORE its audit ⇒ the same
//	    identity completes exactly one audit on restart
//	B5  (control) the completed admin cutover is TestFE6A2C_R8
//
// On eb90ebc5: S1/S3/S4 fail (no token exists), K1–K4 fail (os.WriteFile,
// no fsync, no exclusive publication, a missing key is re-minted), B1–B4
// fail (LoadAdminSettings returns before the reconciliation on every
// non-readable path; the audit is not operation-keyed). K5 and B5 pass.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/ldapstub"
)

const (
	fe6a3cLegacyURLA   = "ldap://legacy-a.corp.example:389"
	fe6a3cLegacyURLB   = "ldap://legacy-b.corp.example:389"
	fe6a3cLegacyBindP1 = "LEGACY-BIND-P1-never-disclosed-3c"
	fe6a3cLegacyBindP2 = "LEGACY-BIND-P2-never-disclosed-3c"
)

// fe6a3cLegacyGET reads the legacy block read model.
func fe6a3cLegacyGET(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPLegacyLDAP(w, jsonReq(http.MethodGet, "/api/idp/legacy-ldap", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET = %d %s", w.Code, w.Body.String())
	}
	return fe6a2JSON(w)
}

// fe6a3cSourceToken returns the published importSourceRevision — the
// server-owned commitment the browser reviews and echoes.
func fe6a3cSourceToken(t *testing.T) string {
	t.Helper()
	m := fe6a3cLegacyGET(t)
	tok, _ := m["importSourceRevision"].(string)
	if tok == "" {
		t.Fatalf("GET /api/idp/legacy-ldap publishes no importSourceRevision (got %v)", m["importSourceRevision"])
	}
	return tok
}

// fe6a3cLegacyYAML is the round's legacy block: url + credential vary per row.
func fe6a3cLegacyYAML(url, password string) *LDAPConfig {
	return &LDAPConfig{URL: url, BaseDN: "DC=legacy", BindDN: "cn=svc,dc=legacy", BindPassword: password,
		UserFilter: "(sAMAccountName=%s)"}
}

// fe6a3cRetirementAudits counts retirement audits since the watermark and
// returns the operation ids they carry (the operation-keyed audit boundary).
func fe6a3cRetirementAudits(since int64) (n int, opIDs []string) {
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS < since || e.Action != "idp.legacy_ldap.retired" {
			continue
		}
		n++
		opIDs = append(opIDs, e.OperationID)
	}
	return n, opIDs
}

// fe6a3cSimulateBoot replays the main.go order of a fresh process for the
// legacy-LDAP authority: registry (already loaded) → legacy-provider slice
// (settings path unknown) → settings load.
func fe6a3cSimulateBoot(t *testing.T, settings string) {
	t.Helper()
	adminSettingsSaveWG.Wait()
	legacyLDAPRetiredFlag.Store(false)
	legacyLDAPCutoverRec.Store(nil)
	legacyLDAPCutoverDurableFlag.Store(false)
	adminSettingsMu.Lock()
	adminSettingsPath = ""
	adminSettingsMu.Unlock()
	if err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{
		LDAP: LDAPConfig{URL: fe6a3cLegacyURLA, BaseDN: "DC=legacy"},
	}); err != nil {
		t.Fatalf("legacy slice: %v", err)
	}
	LoadAdminSettings(settings)
	adminSettingsSaveWG.Wait()
}

// fe6a3cSettingsFile decodes the durable settings file's retirement fields.
func fe6a3cSettingsFile(t *testing.T, path string) (retired bool, rec map[string]any, present bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil, false
		}
		t.Fatalf("read settings: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("settings file is not JSON: %v", err)
	}
	retired, _ = m["legacy_ldap_retired"].(bool)
	rec, _ = m["legacy_ldap_cutover"].(map[string]any)
	return retired, rec, true
}

// fe6a3cEnabledRegistryLDAP puts an ENABLED LDAP profile into a fresh
// registry with NO legacy block present (so no cutover is triggered), then
// installs the legacy YAML block: the "node booted with both" precondition
// of the observed transition, with no durable sentinel anywhere.
func fe6a3cEnabledRegistryLDAP(t *testing.T) (regPath string) {
	t.Helper()
	_, regPath = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withLegacyLDAPYAML(t, nil)
	fe6a2cResetCutoverRecord(t)
	stub := fe6a2cStub(t, ldapstub.Options{})
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL(), "bindPassword": "s"})
	body["enabled"] = true
	if code, m := fe6acCreateFenced(t, body, "operationId="+testOperationID()); code != http.StatusOK {
		t.Fatalf("enabled create = %d %v", code, m)
	}
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP1))
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	return regPath
}

// fe6a3cSettingsPath points the live settings path at p (restored on cleanup).
func fe6a3cSettingsPath(t *testing.T, p string) {
	t.Helper()
	adminSettingsSaveWG.Wait()
	adminSettingsMu.Lock()
	prev := adminSettingsPath
	adminSettingsPath = p
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsSaveWG.Wait()
		adminSettingsMu.Lock()
		adminSettingsPath = prev
		adminSettingsMu.Unlock()
	})
}

// ── S1 — the import is bound to the REVIEWED source ─────────────────────────

func TestFE6A3C_S1_ImportRefusesStaleReviewedSourceWithZeroMutation(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, regPath := fe6aLegacyLDAPFixture(t, settings)
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP1))
	tokenA := fe6a3cSourceToken(t)
	if strings.Contains(tokenA, fe6a3cLegacyBindP1) || strings.Contains(tokenA, "legacy-a") {
		t.Fatalf("the source token discloses source material: %q", tokenA)
	}
	docRev := fe6acDocRevision(t)
	probe := fe6aProbeIdP(t, reg, regPath)
	since := fe6aSince()

	// The ceremony was opened on A; the YAML source is now B (a restart with
	// an edited config.yaml, or a live reload).
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLB, fe6a3cLegacyBindP1))
	tokenB := fe6a3cSourceToken(t)
	if tokenB == tokenA {
		t.Fatalf("a different source URL produced the same token %q", tokenA)
	}
	opID := testOperationID()
	code, m := fe6a2cImport(t, "documentRevision="+docRev, "operationId="+opID, "importSourceRevision="+tokenA)
	if code != http.StatusConflict || m["code"] != "import_source_stale" {
		t.Fatalf("import with the stale reviewed source = %d %v, want 409 import_source_stale", code, m)
	}
	cur, _ := m["current"].(map[string]any)
	if cur["importSourceRevision"] != tokenB {
		t.Fatalf("stale refusal current.importSourceRevision = %v, want the CURRENT token %q", cur["importSourceRevision"], tokenB)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("stale source imported %d profile(s)", n)
	}
	if got := fe6acDocRevision(t); got != docRev {
		t.Fatalf("document revision moved on a refused import: %s → %s", docRev, got)
	}
	if lc, _ := fe6a2cLookup(t, opID); lc != http.StatusNotFound {
		t.Fatalf("refused-before-intent import left a ledger record (lookup %d)", lc)
	}
	if n := fe6a2cAuditCount(since, "idp.import", ""); n != 0 {
		t.Fatalf("refused import emitted %d audit(s)", n)
	}
	probe.assertIdPUnchanged(t, reg, regPath, "idp.import")

	// An absent token is a precondition failure, decided before any write.
	code, m = fe6a2cImport(t, "documentRevision="+docRev, "operationId="+testOperationID())
	if code != http.StatusPreconditionRequired || m["code"] != "import_source_required" {
		t.Fatalf("import without the source token = %d %v, want 428 import_source_required", code, m)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("tokenless import imported %d profile(s)", n)
	}
}

// ── S3 — the exact token imports once and replays across a restart ──────────

func TestFE6A3C_S3_ExactSourceTokenImportsOnceAndReplaysAcrossRestart(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, regPath := fe6aLegacyLDAPFixture(t, settings)
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP1))
	token := fe6a3cSourceToken(t)
	docRev := fe6acDocRevision(t)
	since := fe6aSince()
	opID := testOperationID()

	code, m := fe6a2cImport(t, "documentRevision="+docRev, "operationId="+opID, "importSourceRevision="+token)
	if code != http.StatusOK || m["imported"] != true {
		t.Fatalf("import = %d %v", code, m)
	}
	if m["importSourceRevision"] != token {
		t.Fatalf("success answer echoes importSourceRevision=%v, want the reviewed token %q", m["importSourceRevision"], token)
	}
	id, _ := m["id"].(string)

	// The same operationId with a DIFFERENT reviewed source is a different
	// candidate: refused, never replayed as if it were this import.
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLB, fe6a3cLegacyBindP1))
	other := fe6a3cSourceToken(t)
	code, m = fe6a2cImport(t, "documentRevision="+docRev, "operationId="+opID, "importSourceRevision="+other)
	if code != http.StatusConflict || m["code"] != "operation_mismatch" {
		t.Fatalf("same operation, different reviewed source = %d %v, want 409 operation_mismatch", code, m)
	}
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP1))

	for _, phase := range []string{"before restart", "after restart"} {
		if phase == "after restart" {
			fe6a2cRestartRegistry(t, regPath)
		}
		code, m = fe6a2cImport(t, "documentRevision="+docRev, "operationId="+opID, "importSourceRevision="+token)
		if code != http.StatusOK || m["replayed"] != true || m["id"] != id {
			t.Fatalf("%s: repeat = %d %v, want the replayed import of %s", phase, code, m, id)
		}
		if m["importSourceRevision"] != token {
			t.Fatalf("%s: replay echoes importSourceRevision=%v, want %q", phase, m["importSourceRevision"], token)
		}
		if n := len(fe6a2cProfiles(t)); n != 1 {
			t.Fatalf("%s: %d profiles, want exactly 1", phase, n)
		}
		if n := fe6a2cAuditCount(since, "idp.import", id); n != 1 {
			t.Fatalf("%s: idp.import audits = %d, want exactly 1", phase, n)
		}
	}
}

// ── S4 — a credential-only change invalidates the reviewed token ────────────

func TestFE6A3C_S4_CredentialOnlySourceChangeInvalidatesTokenWithoutDisclosure(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, regPath := fe6aLegacyLDAPFixture(t, settings)
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP1))
	token1 := fe6a3cSourceToken(t)
	docRev := fe6acDocRevision(t)

	// Same URL, base DN, bind DN, filter — only the credential differs.
	withLegacyLDAPYAML(t, fe6a3cLegacyYAML(fe6a3cLegacyURLA, fe6a3cLegacyBindP2))
	get := fe6a3cLegacyGET(t)
	token2, _ := get["importSourceRevision"].(string)
	if token2 == "" || token2 == token1 {
		t.Fatalf("a credential-only change did not change the reviewed token (%q → %q)", token1, token2)
	}
	code, m := fe6a2cImport(t, "documentRevision="+docRev, "operationId="+testOperationID(), "importSourceRevision="+token1)
	if code != http.StatusConflict || m["code"] != "import_source_stale" {
		t.Fatalf("import with the pre-rotation token = %d %v, want 409 import_source_stale", code, m)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("stale token imported %d profile(s)", n)
	}
	// Nothing discloses either credential: tokens, the read model, the
	// refusal, the ledger file.
	raw, _ := json.Marshal(get)
	rawRefusal, _ := json.Marshal(m)
	for _, s := range []string{token1, token2, string(raw), string(rawRefusal)} {
		if strings.Contains(s, fe6a3cLegacyBindP1) || strings.Contains(s, fe6a3cLegacyBindP2) {
			t.Fatalf("credential material disclosed: %q", s)
		}
	}
	if b, err := os.ReadFile(filepath.Join(filepath.Dir(regPath), idpOperationsFile)); err == nil {
		if strings.Contains(string(b), fe6a3cLegacyBindP1) || strings.Contains(string(b), fe6a3cLegacyBindP2) {
			t.Fatal("the ledger file carries a legacy credential")
		}
	}
}

// ── K1/K2 — the candidate key is PUBLISHED durably, or the store fails closed ─

func fe6a3cKeyPaths(t *testing.T) (regPath, keyPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	regPath = filepath.Join(dir, "idp_profiles.json")
	return regPath, filepath.Join(dir, fe6a2cCandidateKeyFile), dir
}

func TestFE6A3C_K1_CandidateKeyPublicationIsSynchronised(t *testing.T) {
	regPath, keyPath, dir := fe6a3cKeyPaths(t)
	var mu sync.Mutex
	var fileSynced, dirSynced bool
	restore := fileutil.SetSyncObserverForTest(func(kind, path string) {
		mu.Lock()
		defer mu.Unlock()
		switch kind {
		case "file":
			if filepath.Dir(path) == dir && strings.HasPrefix(filepath.Base(path), fe6a2cCandidateKeyFile) {
				fileSynced = true
			}
		case "dir":
			if path == dir {
				dirSynced = true
			}
		}
	})
	defer restore()
	store := newIdPOperationStore(regPath)
	if d := store.Degraded(); d != nil {
		t.Fatalf("fresh store degraded: %+v", d)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key not published: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !fileSynced {
		t.Fatal("the candidate key file was published without an fsync of its content")
	}
	if !dirSynced {
		t.Fatal("the candidate key was published without an fsync of its directory")
	}
}

func TestFE6A3C_K2_CandidateKeySyncFaultsFailClosed(t *testing.T) {
	for _, faultKind := range []string{"file", "dir"} {
		t.Run(faultKind, func(t *testing.T) {
			regPath, keyPath, dir := fe6a3cKeyPaths(t)
			injected := errors.New("injected " + faultKind + " fsync fault")
			restore := fileutil.SetSyncHookForTest(func(kind, path string) error {
				if kind == faultKind && (path == dir || (filepath.Dir(path) == dir && strings.HasPrefix(filepath.Base(path), fe6a2cCandidateKeyFile))) {
					return injected
				}
				return nil
			})
			defer restore()
			store := newIdPOperationStore(regPath)
			if d := store.Degraded(); d == nil {
				t.Fatalf("a %s fsync fault during key publication left the ledger HEALTHY — an intent could be recorded under a key of unknown durability", faultKind)
			}
			_, _, err := store.Begin(idpOperation{OperationID: testOperationID(), Action: "idp.create", SpecDigest: "d", CandidateCommitment: "c"})
			if !errors.Is(err, errIdPOperationLedgerDegraded) {
				t.Fatalf("Begin after a %s fault = %v, want %v", faultKind, err, errIdPOperationLedgerDegraded)
			}
			// No half-published key: either absent or complete; no temp
			// residue is ever mistaken for a key.
			if b, err := os.ReadFile(keyPath); err == nil && len(b) != idpCandidateKeyLen {
				t.Fatalf("a partial key (%d bytes) is published", len(b))
			}
		})
	}
}

// ── K3 — concurrent minting publishes ONE generation ─────────────────────────

func TestFE6A3C_K3_ConcurrentMintPublishesOneGeneration(t *testing.T) {
	// A racing WriteFile mint only SOMETIMES lets every caller read the same
	// generation, so the proof is many-trial: every trial must agree.
	for trial := 0; trial < 12; trial++ {
		fe6a3cConcurrentMintTrial(t)
	}
}

func fe6a3cConcurrentMintTrial(t *testing.T) {
	t.Helper()
	_, keyPath, dir := fe6a3cKeyPaths(t)
	const n = 32
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	keys := make([][]byte, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			keys[i], errs[i] = idpLoadOrMintCandidateKey(keyPath)
		}(i)
	}
	start.Done()
	done.Wait()
	published, err := os.ReadFile(keyPath)
	if err != nil || len(published) != idpCandidateKeyLen {
		t.Fatalf("published key: %v (%d bytes)", err, len(published))
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if !bytes.Equal(keys[i], published) {
			t.Fatalf("caller %d read a key that is NOT the published generation — a commitment it produced can never be verified", i)
		}
	}
	if st, _ := os.Stat(keyPath); st != nil && st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 0600", st.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != fe6a2cCandidateKeyFile {
			t.Fatalf("publication residue left beside the key: %s", e.Name())
		}
	}
}

// ── K4/K5 — a missing key is DEGRADED when commitments exist, minted otherwise ─

func TestFE6A3C_K4_MissingKeyWithCommitmentLedgerIsDegradedNeverReminted(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	body := ldapProfileBodyForPut("Corp AD", map[string]any{"bindPassword": fe6a2cSecretA})
	if code, m := fe6acCreateFenced(t, body, "operationId="+testOperationID()); code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	keyPath := filepath.Join(filepath.Dir(regPath), fe6a2cCandidateKeyFile)
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	store := newIdPOperationStore(regPath)
	d := store.Degraded()
	if d == nil {
		t.Fatal("a commitment-bearing ledger whose key is MISSING was opened HEALTHY (a replacement key verifies no earlier intent: every replay of the exact candidate would answer operation_mismatch)")
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("a replacement key was minted beside a ledger it cannot verify")
	}
	if _, _, err := store.Begin(idpOperation{OperationID: testOperationID(), Action: "idp.create", SpecDigest: "d", CandidateCommitment: "c"}); !errors.Is(err, errIdPOperationLedgerDegraded) {
		t.Fatalf("Begin = %v, want %v", err, errIdPOperationLedgerDegraded)
	}
}

func TestFE6A3C_K5_MissingKeyWithoutCommitmentsMints(t *testing.T) {
	regPath, keyPath, _ := fe6a3cKeyPaths(t)
	// An empty ledger (no file) and a ledger without commitments both mint.
	store := newIdPOperationStore(regPath)
	if d := store.Degraded(); d != nil {
		t.Fatalf("fresh store degraded: %+v", d)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("no key minted for a fresh ledger: %v", err)
	}
	ledger := filepath.Join(filepath.Dir(regPath), idpOperationsFile)
	if err := os.WriteFile(ledger, []byte(`[{"operationId":"a1b2c3d4-0000-4000-8000-000000000001","state":"aborted","action":"idp.create","actor":"x","profileId":"p","specDigest":"d","registryRevision":"r","cutover":false,"startedAt":"2026-09-16T00:00:00Z","audited":false}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	store = newIdPOperationStore(regPath)
	if d := store.Degraded(); d != nil {
		t.Fatalf("a ledger with NO commitment-bearing record must mint, got degraded: %+v", d)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("no key minted: %v", err)
	}
}

// ── B1 — missing settings: one durable observed record, one audit ───────────

func TestFE6A3C_B1_MissingSettingsMintsOneDurableRecordAndOneAudit(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	var rec0 *LegacyLDAPCutover
	for boot := 1; boot <= 2; boot++ {
		fe6a3cSimulateBoot(t, settings)
		if !legacyLDAPRetired() {
			t.Fatalf("boot %d: not retired", boot)
		}
		if _, wired := cfg.snapshotAuthBackend().provider.(*LDAPAuth); wired {
			t.Fatalf("boot %d: legacy provider wired on a retired node", boot)
		}
		rec := legacyLDAPCutover()
		if rec == nil || rec.Trigger != "observed" || rec.OperationID == "" {
			t.Fatalf("boot %d: no observed cutover record (%+v)", boot, rec)
		}
		if boot == 1 {
			rec0 = rec
		} else if rec.OperationID != rec0.OperationID {
			t.Fatalf("boot 2 minted a NEW record identity %s (boot 1: %s)", rec.OperationID, rec0.OperationID)
		}
		retired, frec, present := fe6a3cSettingsFile(t, settings)
		if !present || !retired || frec == nil || frec["operationId"] != rec0.OperationID {
			t.Fatalf("boot %d: settings file retired=%v record=%v present=%v, want the sentinel WITH its record %s", boot, retired, frec, present, rec0.OperationID)
		}
		if legacyLDAPCutoverDurability() != "durable" {
			t.Fatalf("boot %d: durability = %q", boot, legacyLDAPCutoverDurability())
		}
		n, ids := fe6a3cRetirementAudits(since)
		if n != 1 || ids[0] != rec0.OperationID {
			t.Fatalf("boot %d: retirement audits = %d %v, want exactly one keyed on %s", boot, n, ids, rec0.OperationID)
		}
	}
}

// ── B2 — unreadable settings: pending, no incomplete sentinel, reconciled once ─

func TestFE6A3C_B2_UnreadableSettingsStayPendingAndReconcileOnceOnRecovery(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	unreadable := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.Mkdir(unreadable, 0o700); err != nil { // a directory: exists, cannot be read as a file
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, unreadable)
	since := fe6aSince()
	fe6a3cSimulateBoot(t, unreadable)
	if !legacyLDAPRetired() {
		t.Fatal("unreadable settings must keep the legacy authenticator shadowed (fail closed)")
	}
	if _, wired := cfg.snapshotAuthBackend().provider.(*LDAPAuth); wired {
		t.Fatal("legacy provider wired while the durable truth is unknown")
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("a success audit was emitted for a transition that is not durable (%d)", n)
	}
	if legacyLDAPCutoverDurability() == "durable" {
		t.Fatal("durability claimed while the settings file could not be read")
	}
	// Storage recovers: an UNRELATED save lands on a writable path. It must
	// never serialise the sentinel without its record; it reconciles the
	// pending transition exactly once.
	recovered := filepath.Join(t.TempDir(), "admin_settings.json")
	fe6a3cSettingsPath(t, recovered)
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("recovery save: %v", err)
	}
	adminSettingsSaveWG.Wait()
	retired, frec, _ := fe6a3cSettingsFile(t, recovered)
	if retired && frec == nil {
		t.Fatal("an unrelated save serialised legacy_ldap_retired:true WITHOUT its cutover record — the transition identity is lost forever")
	}
	rec := legacyLDAPCutover()
	if !retired || frec == nil || rec == nil || frec["operationId"] != rec.OperationID {
		t.Fatalf("recovery save did not reconcile the pending transition: retired=%v file=%v mem=%+v", retired, frec, rec)
	}
	n, ids := fe6a3cRetirementAudits(since)
	if n != 1 || ids[0] != rec.OperationID {
		t.Fatalf("audits after recovery = %d %v, want exactly one keyed on %s", n, ids, rec.OperationID)
	}
	fe6a3cSimulateBoot(t, recovered)
	if got := legacyLDAPCutover(); got == nil || got.OperationID != rec.OperationID {
		t.Fatalf("next boot changed the identity: %+v vs %s", got, rec.OperationID)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 1 {
		t.Fatalf("next boot re-audited: %d", n)
	}
}

// ── B3 — corrupt settings: evidence preserved, no incomplete record ───────────

func TestFE6A3C_B3_CorruptSettingsPreserveEvidenceAndReconcileOnce(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	dir := t.TempDir()
	settings := filepath.Join(dir, "admin_settings.json")
	if err := os.WriteFile(settings, []byte("{\"legacy_ldap_retired\": tru"), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	fe6a3cSimulateBoot(t, settings)
	quarantined := false
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "admin_settings.json.corrupt.") {
			quarantined = true
		}
	}
	if !quarantined {
		t.Fatal("corrupt settings were not quarantined (evidence not preserved)")
	}
	if !legacyLDAPRetired() {
		t.Fatal("corrupt settings must keep the legacy authenticator shadowed")
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 0 {
		t.Fatalf("success audit emitted before anything durable (%d)", n)
	}
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("save after quarantine: %v", err)
	}
	adminSettingsSaveWG.Wait()
	retired, frec, _ := fe6a3cSettingsFile(t, settings)
	if retired && frec == nil {
		t.Fatal("the save after quarantine serialised the sentinel WITHOUT its record")
	}
	rec := legacyLDAPCutover()
	if !retired || frec == nil || rec == nil || frec["operationId"] != rec.OperationID {
		t.Fatalf("pending transition not reconciled on the first successful save: retired=%v file=%v mem=%+v", retired, frec, rec)
	}
	entries, _ = os.ReadDir(dir)
	quarantined = false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "admin_settings.json.corrupt.") {
			quarantined = true
		}
	}
	if !quarantined {
		t.Fatal("the quarantined evidence was removed")
	}
	if n, ids := fe6a3cRetirementAudits(since); n != 1 || ids[0] != rec.OperationID {
		t.Fatalf("audits = %d %v, want one keyed on %s", n, ids, rec.OperationID)
	}
	fe6a3cSimulateBoot(t, settings)
	if got := legacyLDAPCutover(); got == nil || got.OperationID != rec.OperationID {
		t.Fatalf("next boot changed the identity: %+v vs %s", got, rec.OperationID)
	}
	if n, _ := fe6a3cRetirementAudits(since); n != 1 {
		t.Fatalf("next boot re-audited: %d", n)
	}
}

// ── B4 — crash between the durable record and its audit ─────────────────────

func TestFE6A3C_B4_DurableRecordWithPendingAuditCompletesOnceOnRestart(t *testing.T) {
	fe6a3cEnabledRegistryLDAP(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	// A per-run identity: the audit boundary is EXACTLY-ONCE per
	// (action, operationId) across the process-global ring, so a constant id
	// would be found already recorded on a repeated run (-count>1) and the
	// second run would — correctly — append nothing.
	opID := mustRandHex(16)
	// The record was made durable, then the process died BEFORE the audit.
	if err := os.WriteFile(settings, []byte(`{"legacy_ldap_retired":true,"legacy_ldap_cutover":{"operationId":"`+opID+`","actor":"system","trigger":"observed","at":"2026-09-16T00:00:00Z","auditPending":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fe6a3cSettingsPath(t, settings)
	since := fe6aSince()
	for boot := 1; boot <= 2; boot++ {
		fe6a3cSimulateBoot(t, settings)
		rec := legacyLDAPCutover()
		if rec == nil || rec.OperationID != opID {
			t.Fatalf("boot %d: record identity = %+v, want %s", boot, rec, opID)
		}
		n, ids := fe6a3cRetirementAudits(since)
		if n != 1 || ids[0] != opID {
			t.Fatalf("boot %d: audits = %d %v, want exactly one keyed on %s completed on recovery", boot, n, ids, opID)
		}
		data, _ := os.ReadFile(settings)
		if strings.Contains(string(data), `"auditPending":true`) {
			t.Fatalf("boot %d: the audit is still marked pending after it was emitted", boot)
		}
	}
}
