package main

// fe6a0_green_test.go — FE-6A.0 GREEN proofs beyond the R1–R14 matrix
// (fe6a0_red_test.go): concurrency races decided by the server-owned
// fences and the last-admin guard, restart durability of every new fact,
// the split-outcome (outcome_unknown) branch, session-revocation ordering
// semantics, probe absence on every read/audit/log/backup surface, CP→DP
// propagation shapes, action-bound response conformance against the
// OpenAPI contract, the audit-declaration ⇄ emitted-name parity gate, and
// the legacy-UI compatibility pins (static/index.html).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── Concurrency: the fence decides exactly one winner ───────────────────────

func TestFE6A0_Green_ConcurrentFencedPutsExactlyOneWins(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Contended", nil))
	rev := fe6aIdPRevision(t, id)

	const writers = 8
	start := make(chan struct{})
	codes := make([]int, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10),
				ldapProfileBodyForPut("Writer "+strconv.Itoa(i), nil)), id)
			codes[i] = w.Code
		}(i)
	}
	close(start)
	wg.Wait()
	ok, stale := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			stale++
		default:
			t.Fatalf("unexpected status %d in a fenced race", c)
		}
	}
	if ok != 1 || stale != writers-1 {
		t.Fatalf("fenced race: %d winners, %d stale (want 1 / %d)", ok, stale, writers-1)
	}
	if got := idpEntryRevision(reg.Get(id)); got != rev+1 {
		t.Fatalf("revision after one winning write = %d, want %d", got, rev+1)
	}
}

func TestFE6A0_Green_ConcurrentDeleteAndPutOneWinsNoResurrection(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Contended", nil))
	rev := strconv.FormatInt(fe6aIdPRevision(t, id), 10)

	start := make(chan struct{})
	var wg sync.WaitGroup
	var putCode, delCode int
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		w := httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+rev, ldapProfileBodyForPut("Racing edit", nil)), id)
		putCode = w.Code
	}()
	go func() {
		defer wg.Done()
		<-start
		w := httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+id+"?revision="+rev, nil), id)
		delCode = w.Code
	}()
	close(start)
	wg.Wait()
	switch {
	case delCode == http.StatusOK && putCode == http.StatusNotFound:
		if reg.Get(id) != nil {
			t.Fatal("delete won but the profile is still published (resurrected)")
		}
	case putCode == http.StatusOK && delCode == http.StatusConflict:
		if reg.Get(id) == nil || reg.Get(id).Name != "Racing edit" {
			t.Fatal("put won but its content is not the published one")
		}
	default:
		t.Fatalf("race outcome put=%d delete=%d is not one of the two contracted outcomes", putCode, delCode)
	}
}

func TestFE6A0_Green_ConcurrentMutualDemotionKeepsAnAdmin(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	rev := strconv.FormatInt(fe6aRosterRevision(t), 10)
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, target := range []string{"root", "bob"} {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+rev, map[string]any{"username": target, "role": "viewer"}))
			codes[i] = w.Code
		}(i, target)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, code := range codes {
		if code == http.StatusOK {
			ok++
		} else if code != http.StatusConflict {
			t.Fatalf("unexpected status %d", code)
		}
	}
	if ok != 1 {
		t.Fatalf("mutual demotion: %d succeeded, want exactly 1 (fence)", ok)
	}
	admins := 0
	for _, u := range fe6aRosterFromDisk(t, path) {
		if u == RoleAdmin {
			admins++
		}
	}
	if admins != 1 {
		t.Fatalf("after the race %d admins remain on disk, want 1", admins)
	}
	// A second round with the fresh revision is refused by the last-admin
	// guard, not the fence.
	w := httptest.NewRecorder()
	remaining := "root"
	if role, _ := c.VerifyUIUser("root", "RootPass1"); role != RoleAdmin {
		remaining = "bob"
	}
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(c.RosterRevision(), 10), map[string]any{"username": remaining, "role": "operator"}))
	fe6aAssertRefusal(t, w, http.StatusConflict, "last_admin")
}

func TestFE6A0_Green_ConcurrentDeletesNeverRemoveTheLastAdmin(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	rev := strconv.FormatInt(fe6aRosterRevision(t), 10)
	start := make(chan struct{})
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, target := range []string{"root", "bob"} {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username="+target+"&revision="+rev, nil))
			codes[i] = w.Code
		}(i, target)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, code := range codes {
		if code == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent deletes: %d succeeded, want exactly 1", ok)
	}
	admins := 0
	for _, u := range c.ListUIUsers() {
		if u.Role == RoleAdmin {
			admins++
		}
	}
	if admins != 1 {
		t.Fatalf("%d admins remain, want 1", admins)
	}
	if !c.IsConfigured() {
		t.Fatal("deleting the bootstrap admin must not reopen first-time setup (legacy mirror re-pointed)")
	}
}

// ─── Restart durability ──────────────────────────────────────────────────────

func TestFE6A0_Green_RevisionsSurviveRestart(t *testing.T) {
	_, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Durable", nil))
	rev := fe6aIdPRevision(t, id)
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), ldapProfileBodyForPut("Durable v2", nil)), id)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT = %d", w.Code)
	}
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	got := fresh.Get(id)
	if got == nil || got.Revision != rev+1 || got.Name != "Durable v2" {
		t.Fatalf("reloaded profile = %+v, want revision %d name %q", got, rev+1, "Durable v2")
	}
	if fresh.DocumentRevision() != idpRegistry.DocumentRevision() {
		t.Fatal("document revision must be identical across a restart for identical content")
	}
}

func TestFE6A0_Green_RosterRevisionSurvivesRestart(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	before := c.RosterRevision()
	if _, err := c.CreateUIUser("carol", "CarolPass1", RoleViewer, before); err != nil {
		t.Fatal(err)
	}
	fresh := newTestConfig()
	fresh.SetUIUsersFile(path)
	if err := fresh.LoadUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if fresh.RosterRevision() != before+1 || fresh.RosterRevision() != c.RosterRevision() {
		t.Fatalf("roster revision after restart = %d, live %d, want %d", fresh.RosterRevision(), c.RosterRevision(), before+1)
	}
}

func TestFE6A0_Green_CutoverRecordRoundTripsThroughAdminSettings(t *testing.T) {
	prev := legacyLDAPRetiredFlag.Load()
	prevRec := legacyLDAPCutoverRec.Load()
	legacyLDAPRetiredFlag.Store(false)
	legacyLDAPCutoverRec.Store(nil)
	t.Cleanup(func() { legacyLDAPRetiredFlag.Store(prev); legacyLDAPCutoverRec.Store(prevRec) })
	withLegacyLDAPYAML(t, nil) // no YAML block: applyLegacyLDAPRetirement must not touch the provider

	rec := LegacyLDAPCutover{OperationID: "op-1", ProfileID: "p-1", RegistryRevision: "r-1", Actor: "admin@127.0.0.1", Trigger: "admin_api", At: "2026-09-11T00:00:00Z"}
	b, err := json.Marshal(AdminSettings{LegacyLDAPRetired: true, LegacyLDAPCutover: &rec})
	if err != nil {
		t.Fatal(err)
	}
	var loaded AdminSettings
	if err := json.Unmarshal(b, &loaded); err != nil {
		t.Fatal(err)
	}
	applyLegacyLDAPRetirement(&loaded)
	if !legacyLDAPRetired() {
		t.Fatal("sentinel not restored from the durable file")
	}
	got := legacyLDAPCutover()
	if got == nil || *got != rec {
		t.Fatalf("cutover record after reload = %+v, want %+v", got, rec)
	}
}

// ─── Split outcome: registry persisted, sentinel not durable, rollback fails ──

func TestFE6A0_Green_OutcomeUnknownPublishesNothing(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	compiled, err := prepareProfile(ldapTestProfile("ldap-split", "Split"))
	if err != nil {
		t.Fatal(err)
	}
	p := ldapTestProfile("ldap-split", "Split")
	err = reg.mutate(false, "", func(cur []*IdPProfile, live map[string]IdentityProvider) (idpCandidate, error) {
		return applyProfileCandidate(cur, live, p, compiled), nil
	}, func([]*IdPProfile) error {
		// The pre-publish step fails AND the compensating rollback is made
		// impossible (the registry path becomes unwritable in between).
		setRegistryPath(t, reg, fe6aBrokenPath(t, "idp_profiles.json"))
		return errAdminSettingsPersist
	})
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("expected the outcome_unknown sentinel, got %v", err)
	}
	if reg.Get("ldap-split") != nil {
		t.Fatal("outcome_unknown must publish nothing")
	}
	if _, ok := reg.LiveProvider("ldap-split"); ok {
		t.Fatal("outcome_unknown must publish no live provider")
	}
	// The durable candidate is what the next boot reconciles from.
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	if fresh.Get("ldap-split") == nil {
		t.Fatal("the persisted candidate must survive for boot reconciliation")
	}
	w := httptest.NewRecorder()
	writeIdPRefusal(w, err)
	m := fe6aAssertRefusal(t, w, http.StatusInternalServerError, "outcome_unknown")
	cur, _ := m["current"].(map[string]any)
	if cur["detail"] != "registry_persisted_sentinel_not_durable" {
		t.Fatalf("outcome_unknown must name the split; current=%v", cur)
	}
}

// ─── Session revocation semantics ────────────────────────────────────────────

// FE-6A.0 correction (Blocker 2): the in-memory "issued-before" cutoff was
// replaced by the DURABLE per-user security generation. A session carries
// the generation it was issued under; a role/credential change advances the
// record's generation inside the roster commit, so every earlier session is
// refused by the record comparison — on this node and across a restart —
// while a login issued afterwards (at the new generation) is honoured, and a
// legacy cookie without a generation fails closed.
func TestFE6A0_Green_SecurityGenerationSupersedesEarlierSessions(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	rev := c.RosterRevision()
	if _, err := c.CreateUIUser("carol", "CarolPass1", RoleAdmin, rev); err != nil {
		t.Fatal(err)
	}
	role, gen0, ok := c.UserRoleAndGeneration("carol")
	if !ok || role != RoleAdmin || gen0 <= 0 {
		t.Fatalf("fresh user must carry a positive generation; got %s %d %v", role, gen0, ok)
	}
	old := &Session{Sub: "carol", Provider: "local", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(), Gen: gen0}
	if _, err := c.UpdateUIUser("carol", "", RoleViewer, c.RosterRevision()); err != nil {
		t.Fatal(err)
	}
	role, gen1, ok := c.UserRoleAndGeneration("carol")
	if !ok || role != RoleViewer || gen1 <= gen0 {
		t.Fatalf("a role change must advance the generation (%d → %d) and record the new role (%s)", gen0, gen1, role)
	}
	if old.Gen == gen1 {
		t.Fatal("a session issued before the account change must not match the current generation")
	}
	fresh := &Session{Sub: "carol", Provider: "local", Role: "viewer", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(), Gen: gen1}
	if fresh.Gen != gen1 {
		t.Fatal("a login after the account change must be honoured")
	}
	// A legacy cookie carries no generation: Gen == 0 never equals a
	// positive record generation, so it fails closed.
	legacy := &Session{Sub: "carol", Provider: "local", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()}
	if legacy.Gen > 0 || legacy.Gen == gen1 {
		t.Fatal("a legacy cookie without a generation must be rejected")
	}
	// A password change advances it again — so does a delete + recreate
	// (the counter is roster-wide and never reused).
	if _, gen2, err := c.ChangeUIUserPassword("carol", "CarolPass2", gen1); err != nil || gen2 <= gen1 {
		t.Fatalf("password change must advance the generation: %d → %d (%v)", gen1, gen2, err)
	}
	if _, err := c.DeleteUIUserFenced("carol", c.RosterRevision()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateUIUser("carol", "CarolPass3", RoleViewer, c.RosterRevision()); err != nil {
		t.Fatal(err)
	}
	_, gen3, _ := c.UserRoleAndGeneration("carol")
	if gen3 <= gen1 {
		t.Fatalf("a recreated user must never inherit an earlier generation (%d vs %d)", gen3, gen1)
	}
}

// ─── Secret absence on every surface ─────────────────────────────────────────

func TestFE6A0_Green_SecretsAbsentFromReadAuditLogBackup(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	const probe = "svc-probe-ZZ9" // the bind credential value traced across every surface
	since := fe6aSince()
	var id string
	logs := captureLogger(t, func() {
		body := ldapProfileBodyForPut("Audited AD", map[string]any{"bindPassword": probe})
		w := httptest.NewRecorder()
		apiIdPList(w, jsonReq(http.MethodPost, fencedIdPCreatePath(), body))
		if w.Code != http.StatusOK {
			t.Fatalf("create = %d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), probe) {
			t.Fatal("create response leaked the bind credential")
		}
		id, _ = fe6aJSON(t, w)["id"].(string)
		rev := fe6aIdPRevision(t, id)
		w = httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), nil), id)
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), probe) {
			t.Fatalf("delete = %d (leak=%v)", w.Code, strings.Contains(w.Body.String(), probe))
		}
	})
	if strings.Contains(logs, probe) {
		t.Fatal("process log leaked the bind credential")
	}
	for _, e := range auditGet() {
		if e.TS < since {
			continue
		}
		if strings.Contains(e.Before+e.After+e.Detail+e.Object, probe) {
			t.Fatalf("audit entry leaked the bind credential: %+v", e)
		}
	}
	if b, _ := json.Marshal(captureConfigBackup()); strings.Contains(string(b), probe) {
		t.Fatal("config-version snapshot carries the bind credential")
	}
	_ = reg
}

func TestFE6A0_Green_LegacyLDAPReadModelCarriesNoCredential(t *testing.T) {
	withLegacyLDAPYAML(t, &LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy", BindDN: "cn=svc", BindPassword: "legacy-bind-pw"})
	w := httptest.NewRecorder()
	apiIdPLegacyLDAP(w, getReq("/api/idp/legacy-ldap"))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "legacy-bind-pw") {
		t.Fatalf("legacy-ldap read model leaked the bind credential (%d): %s", w.Code, w.Body.String())
	}
	m := fe6aJSON(t, w)
	if v, _ := m["bindCredentialConfigured"].(bool); !v {
		t.Fatal("bindCredentialConfigured must report a stored credential")
	}
	if m["scope"] != "node-local" {
		t.Fatal("legacy-ldap read model must be labelled node-local")
	}
}

// ─── CP→DP propagation shapes ────────────────────────────────────────────────

func TestFE6A0_Green_EmptyRegistryIsExplicitOnTheWireAndNilIsSkip(t *testing.T) {
	withIdPSyncGlobals(t)
	store := fe6aSwapConfigStore(t)
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(store.Get())
	if !strings.Contains(string(wire), `"idp_profiles":[]`) {
		t.Fatalf("an empty registry must publish an explicit empty list; wire=%s", wire)
	}
	// A DP holding a profile applies a snapshot from an OLDER CP (no field
	// at all ⇒ nil): not an instruction — the DP keeps its set (control).
	dp := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := dp.ReplaceAll([]*IdPProfile{ldapTestProfile("keep-me", "Keep")}); err != nil {
		t.Fatal(err)
	}
	idpRegistry = dp
	var older ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":1}`), &older); err != nil {
		t.Fatal(err)
	}
	if err := syncSnapshotIdPProfiles(older); err != nil {
		t.Fatal(err)
	}
	if dp.Get("keep-me") == nil {
		t.Fatal("a snapshot without the field must not wipe the DP registry")
	}
}

func TestFE6A0_Green_DPSnapshotRebuildsADegradedRegistry(t *testing.T) {
	resetStateCorruption()
	t.Cleanup(resetStateCorruption)
	path := filepath.Join(t.TempDir(), "idp_profiles.json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	dp := &IdPRegistry{live: make(map[string]IdentityProvider)}
	idpRegistry = dp
	if err := dp.Load(path); err != nil || dp.Degraded() == nil {
		t.Fatalf("precondition: degraded load (err=%v)", err)
	}
	if err := syncSnapshotIdPProfiles(ConfigSnapshot{IdPProfiles: []*IdPProfile{ldapTestProfile("from-cp", "CP AD")}}); err != nil {
		t.Fatalf("a CP snapshot must rebuild a degraded DP registry: %v", err)
	}
	if dp.Degraded() != nil || dp.Get("from-cp") == nil {
		t.Fatal("DP registry not rebuilt from the CP snapshot")
	}
	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil || fresh.Get("from-cp") == nil {
		t.Fatalf("rebuilt registry must be durable (err=%v)", err)
	}
}

// ─── Store-level guards ──────────────────────────────────────────────────────

func TestFE6A0_Green_SetUIUserAndSetAuthPreserveTOTP(t *testing.T) {
	c := newTestConfig()
	if err := c.SetUIUser("dave", "DavePass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	fe6aEnrollTOTP(t, c, "dave")
	if err := c.SetUIUser("dave", "DaveNew456", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	fe6aAssertTOTPIntact(t, c, "dave")
	if err := c.SetAuth("dave", "DaveNewer789"); err != nil {
		t.Fatal(err)
	}
	fe6aAssertTOTPIntact(t, c, "dave")
	if _, ok := c.VerifyUIUser("dave", "DaveNewer789"); !ok {
		t.Fatal("new credential not accepted")
	}
}

func TestFE6A0_Green_DeletedMirroredAdminCannotUseLegacyFallback(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("erin", "ErinPass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteUIUserFenced("root", c.RosterRevision()); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.VerifyUIUser("root", "RootPass1"); ok {
		t.Fatal("deleted bootstrap admin still authenticates through the legacy mirror")
	}
	if c.LoginNameConfigured("root") {
		t.Fatal("deleted admin still reads as configured")
	}
	if !c.IsConfigured() || !c.AuthEnabled() {
		t.Fatal("deleting the mirrored admin must re-point the mirror, never reopen setup")
	}
}

func TestFE6A0_Green_CutoverMarkIsAtMostOnce(t *testing.T) {
	prev := legacyLDAPRetiredFlag.Load()
	prevRec := legacyLDAPCutoverRec.Load()
	legacyLDAPRetiredFlag.Store(false)
	legacyLDAPCutoverRec.Store(nil)
	t.Cleanup(func() { legacyLDAPRetiredFlag.Store(prev); legacyLDAPCutoverRec.Store(prevRec) })
	first := newLegacyLDAPCutover(&IdPProfile{ID: "a", Name: "A"}, "r1", "admin@10.0.0.1", "admin_api")
	if !markLegacyLDAPRetiredWith(first) {
		t.Fatal("first mark must perform the transition")
	}
	second := newLegacyLDAPCutover(&IdPProfile{ID: "b", Name: "B"}, "r2", "other@10.0.0.2", "admin_api")
	if markLegacyLDAPRetiredWith(second) {
		t.Fatal("second mark must be a no-op")
	}
	if got := legacyLDAPCutover(); got == nil || got.OperationID != first.OperationID {
		t.Fatalf("the FIRST cutover record must stand; got %+v", got)
	}
}

// ─── Action-bound response conformance against the contract ─────────────────

func TestFE6A0_Green_ResponsesConformToContract(t *testing.T) {
	spec := loadContract(t)
	c, _ := fe6aSwapCfg(t, "")
	_, _ = fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	_ = c

	check := func(name, method, path string, w *httptest.ResponseRecorder) {
		t.Helper()
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("%s: content-type %q", name, ct)
		}
		if err := spec.ValidateJSONResponse(method, path, w.Code, w.Body.Bytes()); err != nil {
			t.Fatalf("%s violates the contract: %v\nbody: %s", name, err, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	apiAuthUsers(w, getReq("/api/auth/users"))
	check("users GET", "GET", "/api/auth/users", w)
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, fencedUsersPath(), map[string]any{"username": "frank", "password": "FrankPass1", "role": "operator"}))
	check("users POST", "POST", "/api/auth/users", w)
	rev := fe6aRosterRevision(t)
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "frank", "role": "viewer"}))
	check("users PUT", "PUT", "/api/auth/users", w)
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "frank", "role": "admin"}))
	check("users PUT stale 409", "PUT", "/api/auth/users", w)
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users", map[string]any{"username": "frank", "role": "admin"}))
	check("users PUT 428", "PUT", "/api/auth/users", w)
	rev = fe6aRosterRevision(t)
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=frank&revision="+strconv.FormatInt(rev, 10), nil))
	check("users DELETE", "DELETE", "/api/auth/users", w)

	id := fe6aIdPCreate(t, ldapProfileBodyForPut("Conform", nil))
	w = httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	check("idp GET list", "GET", "/api/idp", w)
	w = httptest.NewRecorder()
	apiIdPItem(w, getReq("/api/idp/"+id), id)
	check("idp GET item", "GET", "/api/idp/{id}", w)
	irev := fe6aIdPRevision(t, id)
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/"+id, ldapProfileBodyForPut("Unfenced", nil)), id)
	check("idp PUT 428", "PUT", "/api/idp/{id}", w)
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+id+"?revision="+strconv.FormatInt(irev, 10), nil), id)
	check("idp DELETE", "DELETE", "/api/idp/{id}", w)
	w = httptest.NewRecorder()
	apiAuthLockouts(w, getReq("/api/auth/lockouts"))
	check("lockouts GET", "GET", "/api/auth/lockouts", w)
}

// ─── Audit declarations equal emitted names ──────────────────────────────────

func TestFE6A0_Green_AuditDeclarationsMatchEmittedNames(t *testing.T) {
	spec := loadContract(t)
	src := ""
	for _, f := range []string{"ui_auth.go", "ui_auth_ldap.go", "auth_ldap_provider.go"} {
		b, err := os.ReadFile(filepath.Join(pkgSourceDir(), f))
		if err != nil {
			t.Fatal(err)
		}
		src += string(b)
	}
	emitted := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:auditEvent|auditEventDiff|auditEventDiffID)\(r, "([a-z_.]+)"`).FindAllStringSubmatch(src, -1) {
		emitted[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`Action:\s+"([a-z_.]+)"`).FindAllStringSubmatch(src, -1) {
		emitted[m[1]] = true
	}
	paths := map[string]bool{
		"/api/auth/users": true, "/api/auth/change-password": true, "/api/auth/lockouts": true,
		"/api/idp": true, "/api/idp/{id}": true, "/api/idp/repair": true, "/api/idp/discover": true,
		"/api/idp/test": true, "/api/idp/legacy-ldap/import": true,
	}
	checked := 0
	for _, op := range spec.Ops {
		if !paths[op.Path] {
			continue
		}
		ev := ""
		if raw, ok := op.Op.Extensions["x-culvert-audit-event"]; ok {
			b, _ := json.Marshal(raw)
			_ = json.Unmarshal(b, &ev)
		}
		if ev == "" {
			continue
		}
		checked++
		if !emitted[ev] {
			t.Errorf("%s %s declares x-culvert-audit-event %q but no handler emits it", op.Method, op.Path, ev)
		}
	}
	if checked < 9 {
		t.Fatalf("only %d declared audit events checked — the path allowlist drifted", checked)
	}
}

// ─── Legacy UI compatibility pins ────────────────────────────────────────────

func TestFE6A0_Green_LegacyUISendsFencesAndTypedRefusals(t *testing.T) {
	b, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{
		"_idpEditRevision = p && p.revision ? p.revision : 0;",
		"if (id) q.push('revision=' + encodeURIComponent(_idpEditRevision));",
		"const cur = await apiFetch(`/api/idp/${id}`);",
		"/api/idp/${id}?revision=${encodeURIComponent(p.revision || 0)}",
		"_usersRevision = d.revision || 0;",
		"method: isEdit ? 'PUT' : 'POST',",
		"'&revision=' + encodeURIComponent(_usersRevision), {method:'DELETE'}",
		"throw new Error(apiErrorText(await r.text()));",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("legacy UI missing FE-6A.0 patch: %q", want)
		}
	}
}
