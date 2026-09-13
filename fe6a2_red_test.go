package main

// FE-6A.2 RED matrix (backend half) — written against the frozen FE-6A.1
// baseline 98d4a6c8 BEFORE any product change.
//
// The React write surface must run the legacy-LDAP authority cutover as a
// T2 ceremony bound to the reviewed candidate by SERVER facts, never by
// browser state (directive: "If the current server does not bind a ceremony
// to the reviewed candidate strongly enough, fix the backend contract
// first"). Two gaps in the shipped contract make that impossible today:
//
//   BR1 a cutover triggered through PUT /api/idp/{id} (enabling an existing
//       LDAP profile on a node with an un-retired YAML block) requires NO
//       operationId, records NO ledger intent and offers NO replay — a lost
//       PUT response cannot be recovered without risking a second cutover.
//   BR2 no write carries a server-required CONFIRMATION value for the
//       cutover: the only fence is the operationId (POST only), so nothing
//       proves the operator reviewed WHICH legacy block is being retired.
//
// Required contract (this matrix pins it; the product commit lands it):
//   - GET /api/idp/legacy-ldap present:true publishes `cutoverConfirmValue`
//     (the legacy directory URL — the block being retired);
//   - every cutover-bearing write (POST or PUT) requires `?operationId=`
//     (428 operation_id_required) AND `?cutoverConfirm=<cutoverConfirmValue>`
//     (428 cutover_confirm_required / 409 confirm_mismatch, both carrying
//     current.confirmValue), decided BEFORE any write;
//   - a cutover PUT is ledger-recorded (action idp.update), echoes its
//     operationId, replays on re-dispatch and refuses a different candidate;
//   - the legacy console sends both on its own enabling writes (2F-A rule).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const fe6a2LegacyURL = "ldap://legacy.corp.example:389"

// fe6a2PutFenced PUTs body on /api/idp/{id} with the CURRENT entry revision.
func fe6a2PutFenced(t *testing.T, id string, body map[string]any, extra ...string) (status int, out map[string]any) {
	t.Helper()
	rev := int64(1)
	if p := idpRegistry.Get(id); p != nil {
		rev = idpEntryRevision(p)
	}
	q := []string{"revision=" + strconv.FormatInt(rev, 10)}
	q = append(q, extra...)
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?"+strings.Join(q, "&"), body))
	return w.Code, fe6a2JSON(w)
}

func fe6a2JSON(w *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m
}

// fe6a2DisabledLDAP creates a DISABLED LDAP profile (no cutover) and returns its id.
func fe6a2DisabledLDAP(t *testing.T) string {
	t.Helper()
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = false
	code, m := fe6acCreateFenced(t, body)
	if code != http.StatusOK {
		t.Fatalf("disabled create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatalf("create answered no id: %v", m)
	}
	if legacyLDAPRetired() {
		t.Fatal("a DISABLED create must never retire the legacy block")
	}
	return id
}

func fe6a2Current(m map[string]any, key string) any {
	cur, _ := m["current"].(map[string]any)
	return cur[key]
}

// BR1 — a cutover through PUT requires the operation identity a lost
// response can be recovered with.
func TestFE6A2_BR1_CutoverPutRequiresOperationId(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, _ := fe6aLegacyLDAPFixture(t, settings)
	id := fe6a2DisabledLDAP(t)
	body := ldapProfileBodyForPut("Registry AD", nil)
	body["enabled"] = true
	code, m := fe6a2PutFenced(t, id, body, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusPreconditionRequired || m["code"] != "operation_id_required" {
		t.Fatalf("cutover PUT without operationId = %d %v, want 428 operation_id_required", code, m)
	}
	if legacyLDAPRetired() {
		t.Fatal("refused cutover PUT retired the legacy block")
	}
	if p := reg.Get(id); p == nil || p.Enabled {
		t.Fatal("refused cutover PUT mutated the profile")
	}
}

// BR2 — a cutover-bearing write requires the server's confirmation value.
func TestFE6A2_BR2_CutoverRequiresServerConfirmValue(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, _ := fe6aLegacyLDAPFixture(t, settings)
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s", "url": fe6aStubDirectory(t)})
	body["enabled"] = true
	const opID = "6a2e0000-0000-4000-8000-00000000be01"
	// absent confirm ⇒ 428 carrying the required value
	code, m := fe6acCreateFenced(t, body, "operationId="+opID)
	if code != http.StatusPreconditionRequired || m["code"] != "cutover_confirm_required" {
		t.Fatalf("cutover create without confirm = %d %v, want 428 cutover_confirm_required", code, m)
	}
	if fe6a2Current(m, "confirmValue") != fe6a2LegacyURL {
		t.Fatalf("428 must carry current.confirmValue = the legacy URL; got %v", m)
	}
	// wrong confirm ⇒ 409, nothing written, nothing retired
	code, m = fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm=ldap://other.example:389")
	if code != http.StatusConflict || m["code"] != "confirm_mismatch" {
		t.Fatalf("wrong confirm = %d %v, want 409 confirm_mismatch", code, m)
	}
	if fe6a2Current(m, "confirmValue") != fe6a2LegacyURL {
		t.Fatalf("409 must carry current.confirmValue; got %v", m)
	}
	if n := len(reg.All()); n != 0 || legacyLDAPRetired() {
		t.Fatalf("refused cutover mutated state (profiles=%d retired=%v)", n, legacyLDAPRetired())
	}
	// correct confirm ⇒ the cutover lands exactly as before
	code, m = fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK || m["operationId"] != opID {
		t.Fatalf("confirmed cutover create = %d %v", code, m)
	}
	if !legacyLDAPRetired() {
		t.Fatal("confirmed cutover did not retire the legacy block")
	}
}

// BR3 — the read model publishes the confirmation value the server requires.
func TestFE6A2_BR3_LegacyReadModelPublishesCutoverConfirmValue(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	fe6aLegacyLDAPFixture(t, settings)
	w := httptest.NewRecorder()
	apiIdPLegacyLDAP(w, getReq("/api/idp/legacy-ldap"))
	if w.Code != http.StatusOK {
		t.Fatalf("legacy GET = %d %s", w.Code, w.Body.String())
	}
	m := fe6a2JSON(w)
	if m["present"] != true {
		t.Fatalf("fixture must present the block; got %v", m)
	}
	if m["cutoverConfirmValue"] != fe6a2LegacyURL {
		t.Fatalf("present block must publish cutoverConfirmValue == url; got %v", m["cutoverConfirmValue"])
	}
}

// BR4 — a cutover PUT is ledger-recorded, echoes its identity, replays and
// refuses a different candidate.
func TestFE6A2_BR4_CutoverPutIsLedgerRecordedAndReplays(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, _ := fe6aLegacyLDAPFixture(t, settings)
	id := fe6a2DisabledLDAP(t)
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"url": fe6aStubDirectory(t)})
	body["enabled"] = true
	const opID = "6a2e0000-0000-4000-8000-00000000be04"
	code, first := fe6a2PutFenced(t, id, body, "operationId="+opID, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK {
		t.Fatalf("cutover PUT = %d %v", code, first)
	}
	if first["operationId"] != opID {
		t.Fatalf("cutover PUT must echo its operationId; got %v", first)
	}
	if !legacyLDAPRetired() {
		t.Fatal("cutover PUT did not retire the legacy block")
	}
	if p := reg.Get(id); p == nil || !p.Enabled || p.OperationID != opID {
		t.Fatalf("the enabled profile must carry the update's provenance; got %+v", p)
	}
	revAfter := idpEntryRevision(reg.Get(id))
	// Authoritative lookup names the update.
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	if w.Code != http.StatusOK {
		t.Fatalf("operation lookup = %d: %s", w.Code, w.Body.String())
	}
	lk := fe6a2JSON(w)
	if lk["state"] != "committed" || lk["action"] != "idp.update" || lk["profileId"] != id || lk["cutover"] != true {
		t.Fatalf("lookup must report committed idp.update bound to the profile with cutover=true; got %v", lk)
	}
	// Lost-response retry: same operationId, same candidate, the ORIGINAL
	// fence ⇒ REPLAY (never a second write, never stale).
	q := []string{"revision=" + strconv.FormatInt(revAfter-1, 10), "operationId=" + opID, "cutoverConfirm=" + fe6a2LegacyURL}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?"+strings.Join(q, "&"), body))
	again := fe6a2JSON(w)
	if w.Code != http.StatusOK {
		t.Fatalf("replay = %d %v", w.Code, again)
	}
	if rep, _ := again["replayed"].(bool); !rep || again["id"] != id {
		t.Fatalf("duplicate operationId must replay the recorded result, got %v", again)
	}
	if idpEntryRevision(reg.Get(id)) != revAfter {
		t.Fatal("a replay must not write")
	}
	// A different candidate under the same operationId is a mismatch.
	body["name"] = "Different"
	code, mm := fe6a2PutFenced(t, id, body, "operationId="+opID, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusConflict || mm["code"] != "operation_mismatch" {
		t.Fatalf("mismatched replay = %d %v, want 409 operation_mismatch", code, mm)
	}
}

// BR5 — the legacy console switches in the same commit (2F-A rule): its
// enabling writes carry the confirm and it handles the new 428.
func TestFE6A2_BR5_LegacyConsoleSendsCutoverConfirm(t *testing.T) {
	// The canonical cwd-independent path (static_read_wall_test.go).
	src, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"cutoverConfirm=", "cutover_confirm_required", "cutoverConfirmValue"} {
		if !strings.Contains(string(src), needle) {
			t.Fatalf("legacy console does not participate in the cutover confirm fence: %q missing", needle)
		}
	}
}

// C1 (control) — a non-cutover PUT needs neither the operationId nor the
// confirm: the new fences are scoped to the cutover-bearing write only.
func TestFE6A2_C1_NonCutoverPutIsUnchanged(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	// No legacy YAML block on this node ⇒ no cutover ⇒ plain fenced PUT.
	withLegacyLDAPYAML(t, nil)
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s", "url": fe6aStubDirectory(t)})
	body["enabled"] = false
	code, m := fe6acCreateFenced(t, body)
	if code != http.StatusOK {
		t.Fatalf("create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	body["enabled"] = true
	code, m = fe6a2PutFenced(t, id, body)
	if code != http.StatusOK {
		t.Fatalf("non-cutover enabling PUT = %d %v, want 200 with no new fence", code, m)
	}
	if p := reg.Get(id); p == nil || !p.Enabled {
		t.Fatal("PUT did not enable the profile")
	}
	if legacyLDAPRetired() {
		t.Fatal("no legacy block ⇒ nothing to retire")
	}
}
