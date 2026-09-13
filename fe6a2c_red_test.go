package main

// FE-6A.2 CORRECTION RED matrix (backend half) — written against the frozen
// FE-6A.2 candidate 64da0df0 BEFORE any product change. The external freeze
// review rejected the candidate on four source-level contract breaks; every
// row below pins the corrected contract and FAILS on 64da0df0 unless marked
// CONTROL.
//
//   Blocker 1 — POST /api/idp/legacy-ldap/import is an unfenced, unidentified
//     mutation (IdPRegistry.Upsert): a lost response + a repeat creates a
//     second profile, a concurrent registry change is never refused.
//     R1  a stale documentRevision (or none) is refused, zero mutation;
//         absent operationId ⇒ 428 operation_id_required.
//     R2  a lost response + repeat (before AND after a restart) yields ONE
//         imported profile, a replayed answer, ONE idp.import audit; the
//         answer is action-bound (imported:true, identity/revision, the
//         resulting documentRevision, the echoed operationId, the legacy
//         source identity WITHOUT its credential, the fleet fact).
//   Blocker 2 — the operation identity hashes the PUBLIC projection only, so
//     the same operationId re-sent with a DIFFERENT secret replays success.
//     R4  OIDC clientSecret / LDAP bindPassword / inline SAML metadata: the
//         same operationId with secret B ⇒ 409 operation_mismatch, zero
//         mutation, no secret in the ledger.
//     R5  CONTROL — the exact same candidate replays across a restart.
//   Blocker 3 — the React client never crosses the activation preflight.
//     R6  an enabled-LDAP create WITHOUT ?preflight= is refused
//         422 preflight_failed with bounded {step, reason}; zero mutation,
//         no ledger record, no audit.
//     R7  an enabling cutover PUT with a failing / unreachable directory
//         changes nothing (registry, cutover, ledger, audit, fleet); with a
//         healthy directory the write CROSSES the preflight (the directory
//         observes a bind) before it lands.
//   Blocker 4 — a completed cutover re-emits idp.legacy_ldap.retired on
//     every boot with a fresh record identity.
//     R8  two simulated boots (legacy slice, then the settings load) keep
//         the ADMIN record identity and the retirement-audit count.
//   R9  CONTROLS/walls — the node-local candidate-commitment key is a
//       never-archived artifact (0600, excluded by name); the ledger and
//       the responses carry no secret.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ldapstub"
)

const (
	fe6a2cSecretA = "SECRET-A-never-in-ledger-0f3a"
	fe6a2cSecretB = "SECRET-B-never-in-ledger-7c1d"
	// idpCandidateKeyFileName is the node-local key the corrected ledger
	// commits candidate secrets under (beside idp_operations.json).
	fe6a2cCandidateKeyFile = ".idp_candidate_key"
)

// fe6a2cImport POSTs the fenced, operation-identified legacy import.
func fe6a2cImport(t *testing.T, extra ...string) (status int, body map[string]any) {
	t.Helper()
	path := "/api/idp/legacy-ldap/import"
	if len(extra) > 0 {
		path += "?" + strings.Join(extra, "&")
	}
	w := httptest.NewRecorder()
	apiIdPLegacyLDAPImport(w, jsonReq(http.MethodPost, path, nil))
	return w.Code, fe6a2JSON(w)
}

// fe6a2cLookup GETs the operation ledger record.
func fe6a2cLookup(t *testing.T, opID string) (status int, body map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPOperations(w, jsonReq(http.MethodGet, "/api/idp/operations/"+opID, nil))
	return w.Code, fe6a2JSON(w)
}

// fe6a2cAuditCount counts audit entries with the action (and object id when
// non-empty) recorded since the watermark.
func fe6a2cAuditCount(since int64, action, objectID string) int {
	n := 0
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS < since || e.Action != action {
			continue
		}
		if objectID != "" && e.ObjectID != objectID && e.Object != objectID {
			continue
		}
		n++
	}
	return n
}

// fe6a2cClosedPort returns a loopback address nothing listens on.
func fe6a2cClosedPort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// fe6a2cStub starts an in-process directory with the given options.
func fe6a2cStub(t *testing.T, opts ldapstub.Options) *ldapstub.Server {
	t.Helper()
	s, err := ldapstub.Listen("127.0.0.1:0", opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// fe6a2cResetCutoverRecord isolates the process-global cutover record (the
// fixtures restore the retired FLAG, not the record another test recorded).
func fe6a2cResetCutoverRecord(t *testing.T) {
	t.Helper()
	prev := legacyLDAPCutoverRec.Load()
	prevDurable := legacyLDAPCutoverDurableFlag.Load()
	legacyLDAPCutoverRec.Store(nil)
	legacyLDAPCutoverDurableFlag.Store(false)
	t.Cleanup(func() {
		legacyLDAPCutoverRec.Store(prev)
		legacyLDAPCutoverDurableFlag.Store(prevDurable)
	})
}

func fe6a2cRestartRegistry(t *testing.T, regPath string) *IdPRegistry {
	t.Helper()
	adminSettingsSaveWG.Wait()
	reg, _ := fe6aSwapRegistry(t, regPath)
	return reg
}

func fe6a2cProfiles(t *testing.T) []map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodGet, "/api/idp", nil))
	m := fe6a2JSON(w)
	raw, _ := m["profiles"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, p := range raw {
		if pm, ok := p.(map[string]any); ok {
			out = append(out, pm)
		}
	}
	return out
}

// ── R1 — import is fenced on the document revision and operation-identified ──

func TestFE6A2C_R1_ImportRefusesStaleFenceWithZeroMutation(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, regPath := fe6aLegacyLDAPFixture(t, settings)
	stale := fe6acDocRevision(t)
	// A concurrent registry change moves the document revision.
	_ = fe6a2DisabledLDAP(t)
	if fe6acDocRevision(t) == stale {
		t.Fatal("precondition: the unrelated create must move the document revision")
	}
	probe := fe6aProbeIdP(t, reg, regPath)
	since := fe6aSince()
	op := testOperationID()

	code, m := fe6a2cImport(t, "documentRevision="+stale, "operationId="+op)
	if code != http.StatusConflict || m["code"] != "stale" {
		t.Fatalf("stale import = %d %v, want 409 stale", code, m)
	}
	if fe6a2Current(m, "documentRevision") != fe6acDocRevision(t) {
		t.Fatalf("409 stale must carry current.documentRevision; got %v", m)
	}
	probe.assertIdPUnchanged(t, reg, regPath, "idp.import")
	if n := fe6a2cAuditCount(since, "idp.import", ""); n != 0 {
		t.Fatalf("refused import emitted %d idp.import audit entries", n)
	}
	if code, _ := fe6a2cLookup(t, op); code != http.StatusNotFound {
		t.Fatalf("a refused-before-intent import must leave no ledger record; lookup = %d", code)
	}

	// No fence at all ⇒ 428 precondition_required with the current value.
	code, m = fe6a2cImport(t, "operationId="+testOperationID())
	if code != http.StatusPreconditionRequired || m["code"] != "precondition_required" {
		t.Fatalf("unfenced import = %d %v, want 428 precondition_required", code, m)
	}
	if fe6a2Current(m, "documentRevision") != fe6acDocRevision(t) {
		t.Fatalf("428 must carry current.documentRevision; got %v", m)
	}
	// No operation identity ⇒ 428 operation_id_required (a lost response
	// could otherwise only be "recovered" by a second import).
	code, m = fe6a2cImport(t, "documentRevision="+fe6acDocRevision(t))
	if code != http.StatusPreconditionRequired || m["code"] != "operation_id_required" {
		t.Fatalf("unidentified import = %d %v, want 428 operation_id_required", code, m)
	}
	probe.assertIdPUnchanged(t, reg, regPath, "idp.import")
}

// ── R2 — a lost response + repeat imports ONCE, before and after a restart ──

func TestFE6A2C_R2_LostImportRepeatIsOneProfileOneAudit(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, regPath := fe6aLegacyLDAPFixture(t, settings)
	since := fe6aSince()
	op := testOperationID()
	fence := fe6acDocRevision(t)

	code, m := fe6a2cImport(t, "documentRevision="+fence, "operationId="+op)
	if code != http.StatusOK {
		t.Fatalf("import = %d %v", code, m)
	}
	// Action-bound answer.
	if m["imported"] != true {
		t.Fatalf("import answer must state imported:true; got %v", m)
	}
	if m["operationId"] != op {
		t.Fatalf("import answer must echo the operationId; got %v", m["operationId"])
	}
	id, _ := m["id"].(string)
	if id == "" || m["type"] != "ldap" || m["enabled"] != false {
		t.Fatalf("import answer must carry the DISABLED ldap profile identity; got %v", m)
	}
	docRev, _ := m["documentRevision"].(string)
	if docRev == "" || docRev == fence || docRev != fe6acDocRevision(t) {
		t.Fatalf("import answer must carry the RESULTING documentRevision (got %q, fence %q, current %q)", docRev, fence, fe6acDocRevision(t))
	}
	src, _ := m["source"].(map[string]any)
	if src["url"] != fe6a2LegacyURL {
		t.Fatalf("import answer must name the legacy source it imported (source.url); got %v", m["source"])
	}
	if _, has := m["cluster"]; !has {
		t.Fatalf("import answer must carry the fleet publication fact; got %v", m)
	}
	raw, _ := json.Marshal(m)
	if strings.Contains(strings.ToLower(string(raw)), "bindpassword") {
		t.Fatalf("import answer carries a credential key: %s", raw)
	}
	if n := len(fe6a2cProfiles(t)); n != 1 {
		t.Fatalf("profiles after import = %d, want 1", n)
	}

	// The response was lost: the SAME operation is re-sent (same fence).
	code, m2 := fe6a2cImport(t, "documentRevision="+fence, "operationId="+op)
	if code != http.StatusOK || m2["replayed"] != true || m2["id"] != id {
		t.Fatalf("repeat import = %d %v, want the replayed recorded result for %s", code, m2, id)
	}
	if n := len(fe6a2cProfiles(t)); n != 1 {
		t.Fatalf("repeat import created a second profile (%d)", n)
	}

	// RESTART — the registry and its ledger reload from disk.
	fe6a2cRestartRegistry(t, regPath)
	code, m3 := fe6a2cImport(t, "documentRevision="+fence, "operationId="+op)
	if code != http.StatusOK || m3["replayed"] != true || m3["id"] != id {
		t.Fatalf("repeat import after restart = %d %v, want replayed", code, m3)
	}
	if n := len(fe6a2cProfiles(t)); n != 1 {
		t.Fatalf("profiles after restart+repeat = %d, want 1", n)
	}
	code, look := fe6a2cLookup(t, op)
	if code != http.StatusOK || look["state"] != "committed" || look["action"] != "idp.import" || look["profileId"] != id {
		t.Fatalf("ledger lookup = %d %v, want committed idp.import for %s", code, look, id)
	}
	if n := fe6a2cAuditCount(since, "idp.import", id); n != 1 {
		t.Fatalf("idp.import audit entries for %s = %d, want exactly 1", id, n)
	}
	if p := idpRegistry.Get(id); p == nil || p.OperationID != op {
		t.Fatalf("the imported profile must carry the operation as its provenance; got %+v", p)
	}
}

// ── R4 — the operation identity binds the EXACT submitted secret ──────────

func fe6a2cSecretCases() []struct {
	name string
	body func(secret string) map[string]any
} {
	return []struct {
		name string
		body func(secret string) map[string]any
	}{
		{"oidc", func(s string) map[string]any {
			return map[string]any{"name": "Corp OIDC", "type": "oidc", "enabled": false,
				"oidc": map[string]any{"issuer": "https://203.0.113.10", "clientId": "cid", "clientSecret": s}}
		}},
		{"ldap", func(s string) map[string]any {
			return ldapProfileBodyForPut("Corp AD", map[string]any{"bindPassword": s})
		}},
		{"saml", func(s string) map[string]any {
			return map[string]any{"name": "Corp SAML", "type": "saml", "enabled": false,
				"saml": map[string]any{"metadataXml": "<EntityDescriptor entityID=\"" + s + "\"/>"}}
		}},
	}
}

func TestFE6A2C_R4_SameOperationDifferentSecretIsMismatch(t *testing.T) {
	for _, tc := range fe6a2cSecretCases() {
		t.Run(tc.name, func(t *testing.T) {
			reg, regPath := fe6aSwapRegistry(t, "")
			fe6aSwapConfigStore(t)
			op := testOperationID()
			code, m := fe6acCreateFenced(t, tc.body(fe6a2cSecretA), "operationId="+op)
			if code != http.StatusOK {
				t.Fatalf("create A = %d %v", code, m)
			}
			id, _ := m["id"].(string)
			probe := fe6aProbeIdP(t, reg, regPath)
			since := fe6aSince()

			code, m2 := fe6acCreateFenced(t, tc.body(fe6a2cSecretB), "operationId="+op)
			if code != http.StatusConflict || m2["code"] != "operation_mismatch" {
				t.Fatalf("same operationId + secret B = %d %v, want 409 operation_mismatch (never a replayed success)", code, m2)
			}
			if m2["replayed"] == true || m2["id"] == id {
				t.Fatalf("secret B was answered with secret A's recorded success: %v", m2)
			}
			probe.assertIdPUnchanged(t, reg, regPath, "idp.create")
			if n := len(fe6a2cProfiles(t)); n != 1 {
				t.Fatalf("profiles = %d, want 1", n)
			}
			_ = since
			// Leak sweep: neither secret in the durable ledger or the answers.
			ledger, err := os.ReadFile(filepath.Join(filepath.Dir(regPath), idpOperationsFile))
			if err != nil {
				t.Fatalf("ledger: %v", err)
			}
			for _, s := range []string{fe6a2cSecretA, fe6a2cSecretB} {
				if strings.Contains(string(ledger), s) {
					t.Fatalf("the ledger stores a submitted secret (%s)", tc.name)
				}
				raw, _ := json.Marshal(m2)
				if strings.Contains(string(raw), s) {
					t.Fatalf("the refusal echoes a secret (%s)", tc.name)
				}
			}
		})
	}
}

// ── R5 — CONTROL: the exact same candidate replays across a restart ─────────

func TestFE6A2C_R5_ExactCandidateReplaysAcrossRestart(t *testing.T) {
	for _, tc := range fe6a2cSecretCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, regPath := fe6aSwapRegistry(t, "")
			fe6aSwapConfigStore(t)
			since := fe6aSince()
			op := testOperationID()
			code, m := fe6acCreateFenced(t, tc.body(fe6a2cSecretA), "operationId="+op)
			if code != http.StatusOK {
				t.Fatalf("create = %d %v", code, m)
			}
			id, _ := m["id"].(string)
			fe6a2cRestartRegistry(t, regPath)
			code, m2 := fe6acCreateFenced(t, tc.body(fe6a2cSecretA), "operationId="+op)
			if code != http.StatusOK || m2["replayed"] != true || m2["id"] != id {
				t.Fatalf("exact replay after restart = %d %v, want replayed %s", code, m2, id)
			}
			if n := len(fe6a2cProfiles(t)); n != 1 {
				t.Fatalf("profiles = %d, want 1", n)
			}
			if n := fe6a2cAuditCount(since, "idp.create", id); n != 1 {
				t.Fatalf("idp.create audits = %d, want 1", n)
			}
		})
	}
}

// ── R6 — an enabled-LDAP create ALWAYS crosses the connection preflight ─────

func fe6a2cAssertPreflightRefusal(t *testing.T, code int, m map[string]any, step, reason string) {
	t.Helper()
	if code != http.StatusUnprocessableEntity || m["code"] != "preflight_failed" {
		t.Fatalf("enabled-LDAP write without a passing preflight = %d %v, want 422 preflight_failed", code, m)
	}
	if fe6a2Current(m, "step") != step || fe6a2Current(m, "reason") != reason {
		t.Fatalf("preflight refusal must carry bounded current.step/reason %s/%s; got %v", step, reason, m["current"])
	}
}

func TestFE6A2C_R6_EnabledLDAPCreateWithoutPreflightIsRefused(t *testing.T) {
	reg, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	probe := fe6aProbeIdP(t, reg, regPath)
	since := fe6aSince()

	// Unreachable directory (nothing listens): step reachable / unreachable.
	closed := fe6a2cClosedPort(t)
	body := ldapProfileBodyForPut("Unreachable AD", map[string]any{"url": "ldap://" + closed, "bindPassword": "s"})
	body["enabled"] = true
	op := testOperationID()
	code, m := fe6acCreateFenced(t, body, "operationId="+op) // NO ?preflight=
	fe6a2cAssertPreflightRefusal(t, code, m, "reachable", "unreachable")
	probe.assertIdPUnchanged(t, reg, regPath, "idp.create")
	if code, _ := fe6a2cLookup(t, op); code != http.StatusNotFound {
		t.Fatalf("a preflight-refused write must leave no ledger record; lookup = %d", code)
	}
	if n := fe6a2cAuditCount(since, "idp.create", ""); n != 0 {
		t.Fatalf("preflight refusal emitted %d idp.create audits", n)
	}

	// Refusing directory (reachable, bind rejected): step service_bind /
	// invalid_credentials.
	stub := fe6a2cStub(t, ldapstub.Options{RejectBind: true})
	body = ldapProfileBodyForPut("Refusing AD", map[string]any{"url": stub.URL(), "bindPassword": "wrong"})
	body["enabled"] = true
	code, m = fe6acCreateFenced(t, body, "operationId="+testOperationID())
	fe6a2cAssertPreflightRefusal(t, code, m, "service_bind", "invalid_credentials")
	probe.assertIdPUnchanged(t, reg, regPath, "idp.create")
	if stub.Binds() < 1 {
		t.Fatal("the write never reached the directory: the preflight did not run at the write boundary")
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("profiles = %d, want 0", n)
	}
}

// ── R7 — a cutover PUT with a failing preflight changes NOTHING; a passing
// one crosses the directory before it lands ───────────────────────────────

func TestFE6A2C_R7_CutoverPutPreflightFailureIsZeroMutation(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, regPath := fe6aLegacyLDAPFixture(t, settings)
	fe6a2cResetCutoverRecord(t)
	closed := fe6a2cClosedPort(t)
	create := ldapProfileBodyForPut("Registry AD", map[string]any{"url": "ldap://" + closed, "bindPassword": "s"})
	create["enabled"] = false
	code, m := fe6acCreateFenced(t, create)
	if code != http.StatusOK {
		t.Fatalf("disabled create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	probe := fe6aProbeIdP(t, reg, regPath)
	since := fe6aSince()
	storeV := globalConfigStore.Version()

	enable := ldapProfileBodyForPut("Registry AD", map[string]any{"url": "ldap://" + closed})
	enable["enabled"] = true
	op := testOperationID()
	code, m = fe6a2PutFenced(t, id, enable, "operationId="+op, "cutoverConfirm="+fe6a2LegacyURL)
	fe6a2cAssertPreflightRefusal(t, code, m, "reachable", "unreachable")
	if legacyLDAPRetired() || legacyLDAPCutover() != nil {
		t.Fatal("a preflight-refused cutover retired the legacy block or recorded a cutover")
	}
	probe.assertIdPUnchanged(t, reg, regPath, "idp.update")
	if p := reg.Get(id); p == nil || p.Enabled {
		t.Fatal("a preflight-refused enable mutated the profile")
	}
	if code, _ := fe6a2cLookup(t, op); code != http.StatusNotFound {
		t.Fatalf("a preflight-refused cutover must leave no ledger record; lookup = %d", code)
	}
	if n := fe6a2cAuditCount(since, "idp.legacy_ldap.retired", ""); n != 0 {
		t.Fatalf("preflight refusal emitted %d retirement audits", n)
	}
	if globalConfigStore.Version() != storeV {
		t.Fatal("preflight refusal published a fleet snapshot")
	}

	// A HEALTHY directory: the write crosses the preflight (the directory
	// observes the bind) and then lands.
	stub := fe6a2cStub(t, ldapstub.Options{})
	ok := ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL()})
	ok["enabled"] = true
	code, m = fe6a2PutFenced(t, id, ok, "operationId="+testOperationID(), "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK {
		t.Fatalf("enable against a healthy directory = %d %v", code, m)
	}
	if stub.Binds() < 1 {
		t.Fatal("the enabling write landed WITHOUT crossing the directory preflight")
	}
	if !legacyLDAPRetired() {
		t.Fatal("the healthy cutover did not retire the legacy block")
	}
}

// ── R8 — a completed admin cutover survives restarts with ONE identity and
// NO new retirement audit ───────────────────────────────────────────────────

func TestFE6A2C_R8_CompletedCutoverIsIdempotentAcrossBoots(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	fe6a2cResetCutoverRecord(t)
	stub := fe6a2cStub(t, ldapstub.Options{})
	since := fe6aSince()
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL(), "bindPassword": "s"})
	body["enabled"] = true
	code, m := fe6acCreateFenced(t, body, "operationId="+testOperationID(), "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK {
		t.Fatalf("cutover create = %d %v", code, m)
	}
	adminSettingsSaveWG.Wait()
	rec0 := legacyLDAPCutover()
	if rec0 == nil || rec0.Trigger != "admin_api" {
		t.Fatalf("cutover record = %+v, want the admin_api record", rec0)
	}
	if n := fe6a2cAuditCount(since, "idp.legacy_ldap.retired", ""); n != 1 {
		t.Fatalf("retirement audits after the cutover = %d, want exactly 1", n)
	}
	prevDurable := legacyLDAPCutoverDurableFlag.Load()
	t.Cleanup(func() { legacyLDAPCutoverDurableFlag.Store(prevDurable) })

	for boot := 1; boot <= 2; boot++ {
		// A fresh process: no in-memory sentinel/record; the registry (with
		// its enabled LDAP profile) loads before the legacy-provider slice,
		// which runs before the settings load (main.go order).
		adminSettingsSaveWG.Wait()
		legacyLDAPRetiredFlag.Store(false)
		legacyLDAPCutoverRec.Store(nil)
		legacyLDAPCutoverDurableFlag.Store(false)
		// In a fresh process the settings PATH is unknown until the settings
		// load runs (persistent_admin_state, after the legacy slice).
		adminSettingsMu.Lock()
		adminSettingsPath = ""
		adminSettingsMu.Unlock()
		if err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{
			LDAP: LDAPConfig{URL: fe6a2LegacyURL, BaseDN: "DC=legacy"},
		}); err != nil {
			t.Fatalf("boot %d legacy slice: %v", boot, err)
		}
		LoadAdminSettings(settings)
		adminSettingsSaveWG.Wait()

		if !legacyLDAPRetired() {
			t.Fatalf("boot %d: the node is no longer retired", boot)
		}
		if _, wired := cfg.snapshotAuthBackend().provider.(*LDAPAuth); wired {
			t.Fatalf("boot %d: the legacy provider was wired on a retired node", boot)
		}
		rec := legacyLDAPCutover()
		if rec == nil || rec.OperationID != rec0.OperationID || rec.Trigger != rec0.Trigger || rec.Actor != rec0.Actor {
			t.Fatalf("boot %d: cutover record identity changed: before %+v after %+v", boot, rec0, rec)
		}
		if n := fe6a2cAuditCount(since, "idp.legacy_ldap.retired", ""); n != 1 {
			t.Fatalf("boot %d: retirement audits = %d, want the ORIGINAL 1 (a completed cutover is not a new transition)", boot, n)
		}
		if legacyLDAPCutoverDurability() != "durable" {
			t.Fatalf("boot %d: durability = %q, want durable", boot, legacyLDAPCutoverDurability())
		}
	}
}

// ── R9 — controls and walls ─────────────────────────────────────────────────

func TestFE6A2C_R9_CandidateKeyIsNodeLocalAndNeverArchived(t *testing.T) {
	if !isNodeLocalKeyArtifactPath("data/" + fe6a2cCandidateKeyFile) {
		t.Fatalf("%s must be excluded from every backup archive by name (a keyed commitment is only a commitment while its key never travels with the ledger)", fe6a2cCandidateKeyFile)
	}
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	body := ldapProfileBodyForPut("Corp AD", map[string]any{"bindPassword": fe6a2cSecretA})
	if code, m := fe6acCreateFenced(t, body, "operationId="+testOperationID()); code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	keyPath := filepath.Join(filepath.Dir(regPath), fe6a2cCandidateKeyFile)
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("an operation-identified write must mint the node-local candidate key beside the ledger: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("candidate key mode = %v, want 0600", st.Mode().Perm())
	}
	key, _ := os.ReadFile(keyPath)
	ledger, _ := os.ReadFile(filepath.Join(filepath.Dir(regPath), idpOperationsFile))
	if len(key) < 32 || strings.Contains(string(ledger), string(key)) || strings.Contains(string(ledger), fe6a2cSecretA) {
		t.Fatal("the ledger must carry neither the key nor the secret")
	}
}
