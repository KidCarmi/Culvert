package main

// FE-6A RECOVERY FOLLOW-UP — IdP ledger eviction and re-send safety (record
// 6AR). Written against the entry head (frozen FE-6B head df17f835 + the
// origin/main 3d8c9bb1 entry merge 9ee4542f) BEFORE any product change.
//
// Question under proof: is the FE-6A.2 IdP surface's "Re-send the same
// operation after a 404 lookup" safe by the BACKEND contract, or does the
// certificate counterexample (fe6b2c_red_test.go, record 6B2C-B1) transfer?
// The certificate proof needed three things to be absent at once: a DECIDED
// record is evictable, a content-derived fence is re-armed by identical
// content, and the re-sent operation is a NEW intent. The IdP ledger shares
// the first (idpOperationsMax = 256, evictDecidedLocked drops aborted and
// committed+audited records oldest-first) and the third (idpReplayKnownOperation
// / idpReplayKnownImport consult the ledger and nothing else); the second
// differs PER ACTION, which is why every reachable action is proved
// separately, with the fence the ORIGINAL dispatch carried AND the fence the
// shipped frontend carries on a re-send (IdentityProvidersPage.tsx dispatches
// `documentRevision: snap.list.revision` / `revision: initial.revision` — the
// CURRENT value, never the marker's recorded fence).
//
// Every row runs the production handlers over a real durable registry and
// ledger; eviction is produced by real decided operations (a disabled OIDC
// create followed by its delete, so the registry's CONTENT returns to what it
// was and the document revision — content-derived — returns with it). No
// test-side lock, seam or fixture supplies a guarantee the product lacks.
//
// Verdict rows (the DEFECT, expected to pass on the entry head and to KEEP
// passing after a frontend-only correction — the backend contract is
// deliberately unchanged, exactly as 6B2C bounded its fix):
//   R1a create: commit → delete → (documentRevision == original fence again)
//       → 256 decided ops evict X → lookup 404 → re-send X with the ORIGINAL
//       fence and candidate ⇒ a SECOND create executes (new id, fresh
//       success audit, fleet publication, no replay).
//   R1b create without the delete: the ORIGINAL fence is 409 stale (the
//       fence protects only while the content still differs) but the fence
//       the frontend sends — the CURRENT revision — executes a second create
//       of a provider with the SAME name (the registry has no name
//       uniqueness), i.e. the shipped re-send duplicates the provider.
//   R2  cutover-bearing create: the RETIREMENT is not repeated (a one-way
//       durable state: legacyLDAPRetired() nils the hook), but the re-sent
//       operation still executes a second ENABLED LDAP provider (a second
//       directory bind, second idp.create audit, fleet publication).
//   R3  cutover-bearing update (PUT): the ORIGINAL fence is 409 stale — the
//       entry revision is per-profile monotonic and a delete+recreate mints a
//       fresh id, so the original fence is UNREACHABLE (the server invariant
//       that holds for this action) — but the frontend's current-revision
//       re-send executes a SECOND update (revision bump, second idp.update
//       audit, fleet publication).
//   R4  import: commit → delete → document revision returns → evict → 404 →
//       re-send with the SAME reviewed source token ⇒ a SECOND imported
//       profile; a source change after eviction is refused
//       import_source_stale (an invariant independent of retention).
//   R5  candidate-secret change: while RETAINED the same operationId with a
//       different secret is 409 operation_mismatch (control); after
//       eviction the same re-send EXECUTES with the new secret — the identity
//       ⇄ secret binding lives in the record and dies with it.
//   R6  restart continuity: an evicted record stays absent across a restart
//       (the ledger file is the truth and it no longer holds X); the re-send
//       executes after the restart exactly as before it.
// Controls (the protection the shipped re-send relies on, shown to exist and
// to depend ENTIRELY on retention):
//   R7a create: a RETAINED record replays across the identical delete with
//       the original fence (replayed:true, nothing written, one audit).
//   R7b import: a RETAINED record replays with the reviewed token even after
//       the legacy source changed (the recorded truth, never current YAML).
//   R7c update: a RETAINED record replays with the ORIGINAL fence (the
//       replay never re-decides the revision).

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ldapstub"
)

// fe6arOIDCBody is a disabled OIDC candidate (the cheapest decided
// operation this ledger accepts).
func fe6arOIDCBody(name, secret string) map[string]any {
	return map[string]any{"name": name, "type": "oidc", "enabled": false,
		"oidc": map[string]any{"issuer": "https://203.0.113.10", "clientId": "cid", "clientSecret": secret}}
}

// fe6arCreate POSTs /api/idp with an EXPLICIT document fence (the caller
// decides whether it is the original or the current one) and extra terms.
func fe6arCreate(t *testing.T, body map[string]any, docRev string, extra ...string) (int, map[string]any) {
	t.Helper()
	q := append([]string{"documentRevision=" + docRev}, extra...)
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp?"+strings.Join(q, "&"), body))
	return w.Code, fe6a2JSON(w)
}

// fe6arPut PUTs /api/idp/{id} with an EXPLICIT entry-revision fence.
func fe6arPut(t *testing.T, id string, rev int64, body map[string]any, extra ...string) (int, map[string]any) {
	t.Helper()
	q := append([]string{"revision=" + strconv.FormatInt(rev, 10)}, extra...)
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?"+strings.Join(q, "&"), body), id)
	return w.Code, fe6a2JSON(w)
}

// fe6arDelete deletes a profile under its current entry revision.
func fe6arDelete(t *testing.T, id string) {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPItem(w, fencedDeleteReq(fencedIdPPath(id)), id)
	if w.Code != http.StatusOK {
		t.Fatalf("delete %s = %d %s", id, w.Code, w.Body.String())
	}
}

// fe6arEvictUntilAbsent performs DECIDED operations (a disabled OIDC create
// with a fresh operationId, then its delete — the registry content is
// unchanged afterwards) until the lookup of opX answers 404. Bounded so a
// retention change fails loudly rather than looping.
func fe6arEvictUntilAbsent(t *testing.T, opX string) (pairs int) {
	t.Helper()
	for pairs = 0; pairs < idpOperationsMax+8; pairs++ {
		if code, _ := fe6a2cLookup(t, opX); code == http.StatusNotFound {
			return pairs
		}
		code, m := fe6acCreateFenced(t, fe6arOIDCBody("evict-"+strconv.Itoa(pairs), "e"), "operationId="+testOperationID())
		if code != http.StatusOK {
			t.Fatalf("eviction create %d = %d %v", pairs, code, m)
		}
		id, _ := m["id"].(string)
		fe6arDelete(t, id)
	}
	t.Fatalf("operation %s still retained after %d decided operations (idpOperationsMax=%d)", opX, pairs, idpOperationsMax)
	return pairs
}

// fe6arJSONLActionCount counts the durable audit lines carrying one action
// (current file + rotated archive).
func fe6arJSONLActionCount(t *testing.T, path, action string) int {
	t.Helper()
	n := 0
	for _, p := range []string{path, path + ".1"} {
		f, err := os.Open(p) // #nosec G304 -- test temp path
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil && m["action"] == action {
				n++
			}
		}
		_ = f.Close()
	}
	return n
}

func fe6arProfileIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, p := range fe6a2cProfiles(t) {
		id, _ := p["id"].(string)
		ids = append(ids, id)
	}
	return ids
}

func fe6arAssertAbsent(t *testing.T, opX, when string) {
	t.Helper()
	if code, m := fe6a2cLookup(t, opX); code != http.StatusNotFound || m["code"] != "not_found" {
		t.Fatalf("lookup of %s %s = %d %v, want 404 not_found", opX, when, code, m)
	}
}

// ── R1 — create ────────────────────────────────────────────────────────────

func TestFE6AR_R1a_EvictedCreateResentWithOriginalFenceExecutesTwice(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	store := fe6aSwapConfigStore(t)
	since := fe6aSince()
	opX := testOperationID()
	body := fe6arOIDCBody("Corp OIDC", fe6a2cSecretA)
	fence0 := fe6acDocRevision(t) // the fence the browser's marker records

	// 1. X commits; the browser never sees this answer.
	code, m := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK || m["replayed"] == true {
		t.Fatalf("X create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["state"] != "committed" {
		t.Fatalf("X lookup while retained = %d %v", code, look)
	}
	v1 := store.Version()

	// 2. an unrelated delete returns the registry to its previous CONTENT —
	//    and the content-derived document revision returns with it.
	fe6arDelete(t, id1)
	if cur := fe6acDocRevision(t); cur != fence0 {
		t.Fatalf("document revision after the delete %q != original fence %q (content-derived: identical content ⇒ identical token)", cur, fence0)
	}
	// 3. X is evicted by decided operations; the registry content is unchanged.
	pairs := fe6arEvictUntilAbsent(t, opX)
	fe6arAssertAbsent(t, opX, "after "+strconv.Itoa(pairs)+" decided operations")
	if cur := fe6acDocRevision(t); cur != fence0 {
		t.Fatalf("document revision after eviction %q != %q", cur, fence0)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("profiles before the re-send = %d, want 0", n)
	}
	// 4. THE HAZARD: the SAME operation, SAME candidate, ORIGINAL fence is a
	//    NEW intent and executes a second create.
	code, m2 := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK {
		t.Fatalf("re-sent X = %d %v; the defect proof expects the second execution to be ACCEPTED (a refusal here means the backend now carries a continuity contract this proof must be rewritten for)", code, m2)
	}
	if m2["replayed"] == true {
		t.Fatalf("re-sent X was answered as a replay although its record was evicted: %v", m2)
	}
	id2, _ := m2["id"].(string)
	if id2 == "" || id2 == id1 {
		t.Fatalf("re-sent X minted id %q (first execution %q): a second execution mints a fresh id", id2, id1)
	}
	if ids := fe6arProfileIDs(t); len(ids) != 1 || ids[0] != id2 {
		t.Fatalf("profiles after the re-send = %v, want exactly the second execution's %s", ids, id2)
	}
	if n := fe6a2cAuditCount(since, "idp.create", id2); n != 1 {
		t.Fatalf("idp.create audit for the second execution = %d, want 1 (a fresh success audit)", n)
	}
	if store.Version() <= v1 {
		t.Fatalf("fleet publication version %d did not advance past %d on the re-send", store.Version(), v1)
	}
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["state"] != "committed" || look["profileId"] != id2 {
		t.Fatalf("X after the re-send = %d %v, want a fresh committed record naming %s", code, look, id2)
	}
}

func TestFE6AR_R1b_EvictedCreateResentWithTheCurrentFenceDuplicatesTheProvider(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opX := testOperationID()
	body := fe6arOIDCBody("Corp OIDC", fe6a2cSecretA)
	fence0 := fe6acDocRevision(t)
	code, m := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK {
		t.Fatalf("X create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	fe6arEvictUntilAbsent(t, opX)
	fe6arAssertAbsent(t, opX, "after eviction (profile retained)")

	// The ORIGINAL fence is stale while the content differs — the fence's
	// protection exists, and it is the ONLY thing left.
	code, m2 := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusConflict || m2["code"] != "stale" {
		t.Fatalf("re-sent X with the original fence = %d %v, want 409 stale", code, m2)
	}
	if n := len(fe6a2cProfiles(t)); n != 1 {
		t.Fatalf("a stale refusal wrote something: profiles = %d", n)
	}
	// The fence the shipped frontend sends on a re-send is the CURRENT one.
	code, m3 := fe6arCreate(t, body, fe6acDocRevision(t), "operationId="+opX)
	if code != http.StatusOK || m3["replayed"] == true {
		t.Fatalf("re-sent X with the current fence = %d %v, want a second execution", code, m3)
	}
	id2, _ := m3["id"].(string)
	names := 0
	for _, p := range fe6a2cProfiles(t) {
		if p["name"] == "Corp OIDC" {
			names++
		}
	}
	if names != 2 || id2 == id1 {
		t.Fatalf("providers named %q = %d (ids %s, %s), want the duplicate the re-send produced", "Corp OIDC", names, id1, id2)
	}
}

// ── R2 — cutover-bearing create ────────────────────────────────────────────

func TestFE6AR_R2_EvictedCutoverCreateResentExecutesASecondEnabledProviderWithoutASecondRetirement(t *testing.T) {
	auditPath := fe6aeAuditFile(t)
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	fe6a2cResetCutoverRecord(t)
	stub := fe6a2cStub(t, ldapstub.Options{})
	store := globalConfigStore
	since := fe6aSince()
	opX := testOperationID()
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s", "url": stub.URL()})
	body["enabled"] = true
	fence0 := fe6acDocRevision(t)

	code, m := fe6arCreate(t, body, fence0, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK {
		t.Fatalf("cutover create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	if !legacyLDAPRetired() {
		t.Fatal("the cutover create did not retire the legacy block")
	}
	binds1 := stub.Binds()
	// The retirement's evidence is read from the DURABLE record and the
	// durable audit file, never from the 500-entry ring: the eviction below
	// pushes ~512 entries through the ring, which would evict the retirement
	// entry and make a ring count read as "0" for a reason unrelated to the
	// claim (the recorded test-authoring pitfall).
	// (The record's OperationID is its OWN minted identity; the ledger key is
	// the enabling profile's create-provenance operationId — FE-6A.1's two
	// server facts. Both are pinned: the profile's provenance must be X.)
	cut1 := legacyLDAPCutover()
	if cut1 == nil || cut1.ProfileID != id1 {
		t.Fatalf("cutover record after the create = %+v, want profile %s", cut1, id1)
	}
	if p := idpRegistry.Get(id1); p == nil || p.OperationID != opX {
		t.Fatalf("the enabling profile's provenance = %+v, want %s", p, opX)
	}
	if n := fe6arJSONLActionCount(t, auditPath, "idp.legacy_ldap.retired"); n != 1 {
		t.Fatalf("durable retirement audits after the create = %d, want 1", n)
	}
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["cutover"] != true {
		t.Fatalf("X lookup = %d %v, want a committed cutover record", code, look)
	}
	fe6arEvictUntilAbsent(t, opX)
	fe6arAssertAbsent(t, opX, "after eviction")
	v1 := store.Version()

	// Re-send with the fence the frontend carries (current) and the same
	// cutoverConfirm the marker recorded.
	code, m2 := fe6arCreate(t, body, fe6acDocRevision(t), "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK || m2["replayed"] == true {
		t.Fatalf("re-sent cutover create = %d %v, want a second execution", code, m2)
	}
	id2, _ := m2["id"].(string)
	if id2 == id1 || len(fe6a2cProfiles(t)) != 2 {
		t.Fatalf("re-send did not produce a second provider (ids %s/%s, profiles %d)", id1, id2, len(fe6a2cProfiles(t)))
	}
	if p := idpRegistry.Get(id2); p == nil || !p.Enabled {
		t.Fatalf("the second execution is not an ENABLED provider: %+v", p)
	}
	if stub.Binds() <= binds1 {
		t.Fatal("the second execution did not cross the directory preflight (no second bind observed)")
	}
	// THE SECOND EXECUTION IS NOT AUDITED. The success audit is
	// operation-keyed and exactly-once against the DURABLE record
	// (audit.AppendOperation: a line carrying (action, operationId) already
	// present ⇒ nothing appended), so the second create under X's identity
	// is deduplicated against the FIRST execution's line: the durable trail
	// holds ONE idp.create for X naming id1, none naming id2, while the
	// registry holds both providers and the lookup reports X committed and
	// audited for id2. A duplicate provider with no compliance record of
	// its creation.
	if byObj, byOp := fe6aeJSONLCounts(t, auditPath, "idp.create", id2, opX); byObj != 0 || byOp != 1 {
		t.Fatalf("durable idp.create lines: naming %s = %d (want 0 — the second execution is deduplicated), keyed %s = %d (want 1 — the first execution's)", id2, byObj, opX, byOp)
	}
	if byObj, _ := fe6aeJSONLCounts(t, auditPath, "idp.create", id1, opX); byObj != 1 {
		t.Fatalf("durable idp.create lines naming the first execution %s = %d, want 1", id1, byObj)
	}
	_ = since
	if store.Version() <= v1 {
		t.Fatal("the second execution published no fleet snapshot")
	}
	// The one guarantee that DOES hold: the retirement is one-way — the
	// durable record keeps the FIRST execution's identity and no second
	// retirement audit is appended.
	if cut2 := legacyLDAPCutover(); cut2 == nil || cut2.OperationID != cut1.OperationID || cut2.ProfileID != cut1.ProfileID || cut2.At != cut1.At {
		t.Fatalf("cutover record moved on the re-send: %+v → %+v", cut1, cut2)
	}
	if n := fe6arJSONLActionCount(t, auditPath, "idp.legacy_ldap.retired"); n != 1 {
		t.Fatalf("durable retirement audits after the re-send = %d, want still 1 (the cutover must not repeat)", n)
	}
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["cutover"] != false || look["profileId"] != id2 || look["audited"] != true {
		t.Fatalf("the re-sent record = %d %v, want committed for %s, audited:true (claimed), cutover:false (the retirement was not repeated)", code, look, id2)
	}
}

// ── R8 — with the DURABLE audit sink the second execution leaves no trail ──

func TestFE6AR_R8_EvictedCreateResentUnderTheDurableSinkIsExecutedButNotAudited(t *testing.T) {
	auditPath := fe6aeAuditFile(t)
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opX := testOperationID()
	body := fe6arOIDCBody("Corp OIDC", fe6a2cSecretA)
	fence0 := fe6acDocRevision(t)
	code, m := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK {
		t.Fatalf("X create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	if byObj, byOp := fe6aeJSONLCounts(t, auditPath, "idp.create", id1, opX); byObj != 1 || byOp != 1 {
		t.Fatalf("durable audit after the first execution: byObject %d byOperation %d, want 1/1", byObj, byOp)
	}
	fe6arDelete(t, id1)
	fe6arEvictUntilAbsent(t, opX)
	code, m2 := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK || m2["replayed"] == true {
		t.Fatalf("re-sent X = %d %v, want a second execution", code, m2)
	}
	id2, _ := m2["id"].(string)
	if id2 == "" || id2 == id1 || idpRegistry.Get(id2) == nil {
		t.Fatalf("second execution id %q (first %q)", id2, id1)
	}
	if m2["auditState"] == "pending" {
		t.Fatalf("the second execution reports its audit as pending; the defect proof expects it to CLAIM completion: %v", m2)
	}
	// Executed, provenance stamped, lookup says audited — and the durable
	// record carries no line for it.
	if byObj, byOp := fe6aeJSONLCounts(t, auditPath, "idp.create", id2, opX); byObj != 0 || byOp != 1 {
		t.Fatalf("durable idp.create lines: naming %s = %d (want 0), keyed %s = %d (want 1)", id2, byObj, opX, byOp)
	}
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["profileId"] != id2 || look["audited"] != true {
		t.Fatalf("X after the re-send = %d %v, want committed for %s with audited:true", code, look, id2)
	}
}

// ── R3 — cutover-bearing update ────────────────────────────────────────────

func TestFE6AR_R3_EvictedCutoverUpdate_OriginalFenceIsUnreachable_CurrentFenceExecutesTwice(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	fe6a2cResetCutoverRecord(t)
	stub := fe6a2cStub(t, ldapstub.Options{})
	store := globalConfigStore
	create := ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL(), "bindPassword": "s"})
	code, m := fe6acCreateFenced(t, create)
	if code != http.StatusOK {
		t.Fatalf("disabled create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	rev0 := idpEntryRevision(idpRegistry.Get(id)) // the fence the marker records
	since := fe6aSince()
	opX := testOperationID()
	enable := ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL()})
	enable["enabled"] = true
	code, m = fe6arPut(t, id, rev0, enable, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK {
		t.Fatalf("cutover PUT = %d %v", code, m)
	}
	rev1 := idpEntryRevision(idpRegistry.Get(id))
	if rev1 <= rev0 || !legacyLDAPRetired() {
		t.Fatalf("cutover PUT: revision %d → %d, retired=%v", rev0, rev1, legacyLDAPRetired())
	}
	fe6arEvictUntilAbsent(t, opX)
	fe6arAssertAbsent(t, opX, "after eviction")
	v1 := store.Version()
	audits1 := fe6a2cAuditCount(since, "idp.update", id)

	// (a) the ORIGINAL fence: unreachable — the entry revision is monotonic.
	code, m2 := fe6arPut(t, id, rev0, enable, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusConflict || m2["code"] != "stale" {
		t.Fatalf("re-sent PUT with the original fence = %d %v, want 409 stale", code, m2)
	}
	if idpEntryRevision(idpRegistry.Get(id)) != rev1 {
		t.Fatal("a stale refusal changed the revision")
	}
	// A delete + recreate cannot restore it either: the id is minted fresh.
	fe6arDelete(t, id)
	code, m3 := fe6acCreateFenced(t, create)
	if code != http.StatusOK {
		t.Fatalf("recreate = %d %v", code, m3)
	}
	if again, _ := m3["id"].(string); again == id {
		t.Fatalf("recreate reused id %s; mintIdPID is expected to mint a fresh identity", id)
	}
	code, m4 := fe6arPut(t, id, rev0, enable, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusNotFound || m4["code"] != "vanished" {
		t.Fatalf("re-sent PUT against the deleted id = %d %v, want 404 vanished", code, m4)
	}
	idNew, _ := m3["id"].(string)

	// (b) the fence the frontend carries — the CURRENT revision — executes a
	//     second update on the recreated profile (the browser resolves the
	//     target by marker.profileId; with the ORIGINAL id gone it finds
	//     none, so the equivalent hazard here is the profile still present:
	//     re-send against idNew under its current revision).
	cur := idpEntryRevision(idpRegistry.Get(idNew))
	sinceB := fe6aSince()
	code, m5 := fe6arPut(t, idNew, cur, enable, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK || m5["replayed"] == true {
		t.Fatalf("re-sent PUT with the current fence = %d %v, want a second execution", code, m5)
	}
	if got := idpEntryRevision(idpRegistry.Get(idNew)); got != cur+1 {
		t.Fatalf("revision after the re-send %d, want %d (a real write)", got, cur+1)
	}
	if p := idpRegistry.Get(idNew); p == nil || !p.Enabled || p.OperationID != opX {
		t.Fatalf("the second execution did not land as X's write: %+v", p)
	}
	if n := fe6a2cAuditCount(sinceB, "idp.update", idNew); n != 1 {
		t.Fatalf("idp.update audits for the second execution = %d, want 1 (audits before: %d)", n, audits1)
	}
	if store.Version() <= v1 {
		t.Fatal("the second execution published no fleet snapshot")
	}
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["state"] != "committed" || look["profileId"] != idNew || look["cutover"] != false {
		t.Fatalf("X after the re-send = %d %v, want committed for %s with cutover:false", code, look, idNew)
	}
}

// ── R4 — legacy import ─────────────────────────────────────────────────────

func TestFE6AR_R4_EvictedImportResentWithTheReviewedTokenImportsTwice_SourceChangeStaysRefused(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	since := fe6aSince()
	opX := testOperationID()
	token := fe6a3cSourceToken(t)
	fence0 := fe6acDocRevision(t)

	code, m := fe6a2cImport(t, "documentRevision="+fence0, "operationId="+opX, "importSourceRevision="+token)
	if code != http.StatusOK || m["imported"] != true {
		t.Fatalf("import = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	fe6arDelete(t, id1)
	if cur := fe6acDocRevision(t); cur != fence0 {
		t.Fatalf("document revision after the delete %q != original fence %q", cur, fence0)
	}
	fe6arEvictUntilAbsent(t, opX)
	fe6arAssertAbsent(t, opX, "after eviction")

	// The SAME import operation, SAME reviewed token, ORIGINAL fence.
	code, m2 := fe6a2cImport(t, "documentRevision="+fence0, "operationId="+opX, "importSourceRevision="+token)
	if code != http.StatusOK || m2["imported"] != true || m2["replayed"] == true {
		t.Fatalf("re-sent import = %d %v, want a second execution", code, m2)
	}
	id2, _ := m2["id"].(string)
	if id2 == "" || id2 == id1 || len(fe6a2cProfiles(t)) != 1 {
		t.Fatalf("re-sent import: id %q (first %q), profiles %d — want a fresh imported profile", id2, id1, len(fe6a2cProfiles(t)))
	}
	if n := fe6a2cAuditCount(since, "idp.import", id2); n != 1 {
		t.Fatalf("idp.import audit for the second execution = %d, want 1", n)
	}
	if code, look := fe6a2cLookup(t, opX); code != http.StatusOK || look["action"] != "idp.import" || look["profileId"] != id2 {
		t.Fatalf("X after the re-send = %d %v, want a fresh idp.import record for %s", code, look, id2)
	}

	// A changed source after eviction: the reviewed token no longer names
	// the current source ⇒ refused BEFORE any write. This invariant does not
	// depend on retention.
	fe6arDelete(t, id2)
	fe6arEvictUntilAbsent(t, opX)
	withLegacyLDAPYAML(t, &LDAPConfig{URL: fe6a2LegacyURL, BaseDN: "DC=legacy", BindDN: "cn=svc,dc=legacy", BindPassword: "rotated"})
	code, m3 := fe6a2cImport(t, "documentRevision="+fe6acDocRevision(t), "operationId="+opX, "importSourceRevision="+token)
	if code != http.StatusConflict || m3["code"] != "import_source_stale" {
		t.Fatalf("re-sent import against a changed source = %d %v, want 409 import_source_stale", code, m3)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("a stale-source refusal wrote %d profile(s)", n)
	}
}

// ── R5 — the candidate-secret binding dies with the record ─────────────────

func TestFE6AR_R5_SecretChange_RetainedIsMismatch_EvictedExecutes(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opX := testOperationID()
	fence0 := fe6acDocRevision(t)
	code, m := fe6arCreate(t, fe6arOIDCBody("Corp OIDC", fe6a2cSecretA), fence0, "operationId="+opX)
	if code != http.StatusOK {
		t.Fatalf("X create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	fe6arDelete(t, id1)

	// CONTROL — retained: the same id with secret B is a different candidate.
	code, m2 := fe6arCreate(t, fe6arOIDCBody("Corp OIDC", fe6a2cSecretB), fence0, "operationId="+opX)
	if code != http.StatusConflict || m2["code"] != "operation_mismatch" {
		t.Fatalf("retained X with secret B = %d %v, want 409 operation_mismatch", code, m2)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("a mismatch refusal wrote %d profile(s)", n)
	}
	// DEFECT — evicted: the same id with secret B executes under X's identity.
	fe6arEvictUntilAbsent(t, opX)
	code, m3 := fe6arCreate(t, fe6arOIDCBody("Corp OIDC", fe6a2cSecretB), fence0, "operationId="+opX)
	if code != http.StatusOK || m3["replayed"] == true {
		t.Fatalf("evicted X with secret B = %d %v, want an execution (the commitment is gone with the record)", code, m3)
	}
	id2, _ := m3["id"].(string)
	if p := idpRegistry.Get(id2); p == nil || p.OperationID != opX || p.OIDC == nil || p.OIDC.ClientSecret != fe6a2cSecretB {
		t.Fatalf("the executed write did not land secret B under X's identity: %+v", p)
	}
}

// ── R6 — restart continuity ────────────────────────────────────────────────

func TestFE6AR_R6_EvictionSurvivesARestart_ResendExecutesAfterIt(t *testing.T) {
	_, regPath := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	opX := testOperationID()
	body := fe6arOIDCBody("Corp OIDC", fe6a2cSecretA)
	fence0 := fe6acDocRevision(t)
	code, m := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK {
		t.Fatalf("X create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	fe6arDelete(t, id1)

	// CONTROL — a RETAINED record replays across a restart (fe6a2c R5's
	// guarantee), with nothing written.
	fe6a2cRestartRegistry(t, regPath)
	code, m2 := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK || m2["replayed"] != true || m2["id"] != id1 {
		t.Fatalf("retained X after restart = %d %v, want the replayed record for %s", code, m2, id1)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("a replay wrote %d profile(s)", n)
	}
	// DEFECT — eviction is durable: the file no longer holds X, so a restart
	// cannot bring the record back, and the re-send executes.
	fe6arEvictUntilAbsent(t, opX)
	fe6a2cRestartRegistry(t, regPath)
	fe6arAssertAbsent(t, opX, "after eviction and a restart")
	code, m3 := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK || m3["replayed"] == true {
		t.Fatalf("evicted X after restart = %d %v, want a second execution", code, m3)
	}
	if id2, _ := m3["id"].(string); id2 == "" || id2 == id1 {
		t.Fatalf("second execution id %q (first %q)", id2, id1)
	}
}

// ── R7 — CONTROLS: the retained-record replay is real and is ALL there is ──

func TestFE6AR_R7a_Control_RetainedCreateReplaysAcrossTheIdenticalDelete(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	since := fe6aSince()
	opX := testOperationID()
	body := fe6arOIDCBody("Corp OIDC", fe6a2cSecretA)
	fence0 := fe6acDocRevision(t)
	code, m := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK {
		t.Fatalf("X create = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	fe6arDelete(t, id1)
	code, m2 := fe6arCreate(t, body, fence0, "operationId="+opX)
	if code != http.StatusOK || m2["replayed"] != true || m2["id"] != id1 {
		t.Fatalf("retained X re-sent = %d %v, want replayed for %s", code, m2, id1)
	}
	if n := len(fe6a2cProfiles(t)); n != 0 {
		t.Fatalf("a replay wrote %d profile(s)", n)
	}
	if n := fe6a2cAuditCount(since, "idp.create", id1); n != 1 {
		t.Fatalf("idp.create audits = %d, want exactly 1", n)
	}
}

func TestFE6AR_R7b_Control_RetainedImportReplaysEvenAfterTheSourceChanged(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	opX := testOperationID()
	token := fe6a3cSourceToken(t)
	code, m := fe6a2cImport(t, "documentRevision="+fe6acDocRevision(t), "operationId="+opX, "importSourceRevision="+token)
	if code != http.StatusOK {
		t.Fatalf("import = %d %v", code, m)
	}
	id1, _ := m["id"].(string)
	withLegacyLDAPYAML(t, &LDAPConfig{URL: fe6a2LegacyURL, BaseDN: "DC=legacy", BindDN: "cn=svc,dc=legacy", BindPassword: "rotated"})
	code, m2 := fe6a2cImport(t, "documentRevision="+fe6acDocRevision(t), "operationId="+opX, "importSourceRevision="+token)
	if code != http.StatusOK || m2["replayed"] != true || m2["id"] != id1 {
		t.Fatalf("retained import re-sent after a source change = %d %v, want the replayed record for %s", code, m2, id1)
	}
	if n := len(fe6a2cProfiles(t)); n != 1 {
		t.Fatalf("profiles = %d, want 1", n)
	}
}

func TestFE6AR_R7c_Control_RetainedUpdateReplaysWithTheOriginalFence(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	_, _ = fe6aLegacyLDAPFixture(t, settings)
	fe6a2cResetCutoverRecord(t)
	stub := fe6a2cStub(t, ldapstub.Options{})
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL(), "bindPassword": "s"}))
	if code != http.StatusOK {
		t.Fatalf("disabled create = %d %v", code, m)
	}
	id, _ := m["id"].(string)
	rev0 := idpEntryRevision(idpRegistry.Get(id))
	opX := testOperationID()
	enable := ldapProfileBodyForPut("Registry AD", map[string]any{"url": stub.URL()})
	enable["enabled"] = true
	code, m = fe6arPut(t, id, rev0, enable, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK {
		t.Fatalf("cutover PUT = %d %v", code, m)
	}
	rev1 := idpEntryRevision(idpRegistry.Get(id))
	code, m2 := fe6arPut(t, id, rev0, enable, "operationId="+opX, "cutoverConfirm="+fe6a2LegacyURL)
	if code != http.StatusOK || m2["replayed"] != true {
		t.Fatalf("retained PUT re-sent with the original fence = %d %v, want replayed", code, m2)
	}
	if got := idpEntryRevision(idpRegistry.Get(id)); got != rev1 {
		t.Fatalf("a replay moved the revision %d → %d", rev1, got)
	}
}
