// 2F-E correction round 8 — RED proof, written and executed on the untouched
// round-7 candidate bde20ba1 BEFORE any product change.
//
// Round 7's pre-write settlement (pacSettlePendingBeforeWrite) lists the
// profiles a writer changes by iterating over the BEFORE profiles only, so an
// id absent from the active store and present in the candidate — a
// candidate-only ADDITION — is never settled. An absent profile can still
// carry a durable pending FIRST-PUBLISH lifecycle intent (the publish died
// after its intent was persisted, before its commit). A later writer adding
// that same id therefore bypasses the settlement: the POST create (whose
// PrepareCreate keeps the pending intent), a merge/replace config import, a
// config-version rollback and a CP→DP snapshot all install the profile while
// the earlier intent stays unsettled, and a later reconciliation must then
// reason from content/provenance the new writer already replaced.
//
// V1: the real POST create, with lifecycle persistence failing after the
//
//	create preparation — on the candidate the create succeeds and installs
//	the profile; required: fail-closed (no active mutation, no success
//	audit, no config version, no cluster publication) with the earlier
//	intent durably recoverable.
//
// V2: the same state added through the production import, rollback and
//
//	snapshot paths while settlement cannot persist — on the candidate the
//	PAC slice is applied; required: the round-7 refusal/deferral semantics
//	(pac_profiles_not_applied, rollback error, snapshot deferred) and the
//	target stays absent.
//
// V3 (controls): a genuinely new id with no pending intent stays allowed;
//
//	once persistence recovers the earlier intent is settled exactly once
//	and the later addition succeeds; untouched profiles and pool-only
//	mutations stay unblocked.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/google/uuid"
)

const pacCandidateOnlyID = "newprof"

func pacCandidateOnlySpec(name string) pac.Profile {
	return pac.Profile{ID: pacCandidateOnlyID, Name: name, Enabled: true, PoolID: "spare",
		PrivateNetworks: pac.PrivateProxy, AvailabilityMode: pac.ModeBalanced, Rules: []pac.Rule{}, Revision: 1}
}

// pacCandidateOnlyPendingIntent seeds a durable pending FIRST-PUBLISH intent
// for the absent profile newprof: the publish dies right after its intent is
// persisted (the handler goroutine exits at that stage; its deferred unlocks
// run, exactly as a crash leaves no lock behind) and nothing settles it.
func pacCandidateOnlyPendingIntent(t *testing.T) (opX string) {
	t.Helper()
	pacBoundaryEnv(t)
	opX = uuid.NewString()
	pacLifecycleStageHook = func(stage string) {
		if stage == "intent_persisted" {
			runtime.Goexit()
		}
	}
	etag := pacContinuityCollectionEtag(t)
	draft := fmt.Sprintf(`{"id":%q,"name":"First publish","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[]}`, pacCandidateOnlyID)
	body := fmt.Sprintf(`{"action":"publish","operationId":%q,"expectedActiveRevision":0,"collectionEtag":%q,"draft":%s}`, opX, etag, draft)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pacFenceReq(t, "POST", "/api/pac/profiles/"+pacCandidateOnlyID+"/lifecycle", body, pacIntentIP)
	}()
	<-done
	pacLifecycleStageHook = nil
	lc, ok := pacLifecycle.Get(pacCandidateOnlyID)
	if !ok || lc.PendingOp == nil || lc.PendingOp.OperationID != opX || lc.PendingOp.Committed() {
		t.Fatalf("fixture: a durable pending first-publish intent expected for the absent profile, got %+v", lc.PendingOp)
	}
	if _, exists := pacProfiles.ProfileByID(pacCandidateOnlyID); exists {
		t.Fatal("fixture: the profile must be absent")
	}
	return opX
}

func pacCandidateOnlyPending(t *testing.T, opX string) bool {
	t.Helper()
	lc, ok := pacLifecycle.Get(pacCandidateOnlyID)
	return ok && lc.PendingOp != nil && lc.PendingOp.OperationID == opX
}

func pacCandidateOnlyCreate(t *testing.T, name string) *httptest.ResponseRecorder {
	t.Helper()
	spec := pacCandidateOnlySpec(name)
	spec.Revision = 0
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw[:len(raw)-1]) + fmt.Sprintf(`,"collectionEtag":%q}`, pacContinuityCollectionEtag(t))
	return pacFenceReq(t, "POST", "/api/pac/profiles", body, pacIntentIP)
}

func pacCandidateOnlyCreateAudits(since int64) int {
	n := 0
	ring := auditGet()
	for i := range ring {
		if ring[i].TS >= since && ring[i].Action == "pac.profile_create" && ring[i].Object == pacCandidateOnlyID {
			n++
		}
	}
	return n
}

// ── V1: candidate-only CRUD create ─────────────────────────────────────────

func TestPACBoundary_V1_CandidateOnlyCreateSettlesTheAbsentProfilesIntentFirst(t *testing.T) {
	opX := pacCandidateOnlyPendingIntent(t)
	versions := len(configVersions.List())
	clusterVersion := globalConfigStore.Version()
	since := time.Now().UnixMilli()
	// lifecycle persistence fails AFTER the create preparation
	pacLifecycleStageHook = func(stage string) {
		if stage == "create_prepared" {
			pacSettleArmLifecycleFault(t)
		}
	}
	rec := pacCandidateOnlyCreate(t, "Created by CRUD")
	pacLifecycleStageHook = nil
	if rec.Code != http.StatusServiceUnavailable || pacIntentJSON(t, rec)["code"] != "lifecycle_unsettled" {
		t.Errorf("a create of a profile whose pending intent cannot be settled durably must be refused 503 lifecycle_unsettled: %d %s", rec.Code, rec.Body.String())
	}
	if _, exists := pacProfiles.ProfileByID(pacCandidateOnlyID); exists {
		t.Errorf("no active-profile mutation may land while the earlier intent is unsettled")
	}
	if n := pacCandidateOnlyCreateAudits(since); n != 0 {
		t.Errorf("no success audit may be emitted (got %d)", n)
	}
	if n := len(configVersions.List()); n != versions {
		t.Errorf("no config version may advance (%d → %d)", versions, n)
	}
	if v := globalConfigStore.Version(); v != clusterVersion {
		t.Errorf("no cluster publication may happen (%d → %d)", clusterVersion, v)
	}
	if !pacCandidateOnlyPending(t, opX) {
		t.Errorf("the earlier intent must remain durably recoverable (pending)")
	}
	// Persistence recovers: the earlier intent is settled exactly once (it
	// never wrote: aborted) and the later addition succeeds.
	pac.LifecycleWriteHook = nil
	pacCandidateOnlyAssertSettledOnceAndCreatable(t, opX, since)
}

// pacCandidateOnlyAssertSettledOnceAndCreatable is the recovery control: the
// earlier intent settles exactly once as the decision it earned (aborted —
// it never reached the active store), the create then succeeds, and a
// repeated GET/restart adds nothing.
func pacCandidateOnlyAssertSettledOnceAndCreatable(t *testing.T, opX string, since int64) {
	t.Helper()
	if rec := pacCandidateOnlyCreate(t, "Created by CRUD"); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("the create must succeed once the intent can be settled: %d %s", rec.Code, rec.Body.String())
	}
	if p, ok := pacProfiles.ProfileByID(pacCandidateOnlyID); !ok || p.Name != "Created by CRUD" || p.Revision != 1 {
		t.Fatalf("the created profile must be active: %+v ok=%v", p, ok)
	}
	for _, stage := range []string{"after create", "after restart"} {
		if stage == "after restart" {
			pacIntentRestartComplete(t)
		}
		rec := pacFenceReq(t, "GET", "/api/pac/profiles/"+pacCandidateOnlyID+"/lifecycle?operationId="+opX, "", pacIntentIP)
		if rec.Code != 200 {
			t.Fatalf("%s: lifecycle GET: %d %s", stage, rec.Code, rec.Body.String())
		}
		g := pacIntentJSON(t, rec)
		op, _ := g["operation"].(map[string]any)
		if op == nil || op["found"] != true || op["state"] != pac.OpAborted {
			t.Errorf("%s: the earlier intent must be settled as the decision it earned (aborted — it never wrote): %v", stage, g["operation"])
		}
		if g["ambiguous"] != nil {
			t.Errorf("%s: the earlier intent must never be settled as ambiguous: %v", stage, g["ambiguous"])
		}
		if pacCandidateOnlyPending(t, opX) {
			t.Errorf("%s: the earlier intent must not stay pending", stage)
		}
		if p, ok := pacProfiles.ProfileByID(pacCandidateOnlyID); !ok || p.Name != "Created by CRUD" {
			t.Errorf("%s: the created profile must stay active: %+v ok=%v", stage, p, ok)
		}
		if n := pacCandidateOnlyCreateAudits(since); n != 1 {
			t.Errorf("%s: exactly one create audit (got %d)", stage, n)
		}
	}
}

// ── V2: candidate-only bulk additions ──────────────────────────────────────

func TestPACBoundary_V2a_CandidateOnlyImportDefersWhileSettlementCannotPersist(t *testing.T) {
	opX := pacCandidateOnlyPendingIntent(t)
	pacSettleArmLifecycleFault(t)
	for _, mode := range []string{"merge", "replace"} {
		spec := pacCandidateOnlySpec("Added by import " + mode)
		profiles := []pac.Profile{spec}
		if mode == "replace" {
			// the current profiles WITHOUT the target, so the target stays a
			// candidate-only addition whatever the previous iteration did
			profiles = nil
			for _, p := range pacProfiles.Get().Profiles {
				if p.ID != pacCandidateOnlyID {
					profiles = append(profiles, p)
				}
			}
			profiles = append(profiles, spec)
		}
		b := configBackup{Version: configBackupVersion, PACProfiles: profiles}
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		apiConfigImport(w, adminRequest("POST", "/api/config/import?mode="+mode, string(raw)))
		if w.Code != http.StatusOK {
			t.Fatalf("import %s: %d %s", mode, w.Code, w.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if s, _ := resp["pac_profiles_not_applied"].(string); s == "" {
			t.Errorf("import %s: the PAC slice must be deferred and reported: %s", mode, w.Body.String())
		}
		if _, exists := pacProfiles.ProfileByID(pacCandidateOnlyID); exists {
			t.Errorf("import %s: the target must stay absent while its intent cannot be settled", mode)
		}
		if !pacCandidateOnlyPending(t, opX) {
			t.Errorf("import %s: the earlier intent must remain durably recoverable", mode)
		}
	}
}

func TestPACBoundary_V2b_CandidateOnlyRollbackDefersWhileSettlementCannotPersist(t *testing.T) {
	opX := pacCandidateOnlyPendingIntent(t)
	pacSettleArmLifecycleFault(t)
	cur := pacProfiles.Get()
	rb := configBackup{Version: configBackupVersion, PACProfiles: append(cur.Profiles, pacCandidateOnlySpec("Added by rollback")), PACPools: cur.Pools,
		PACProxyHost: pacStore.Get().ProxyHost, PACProxyPort: pacStore.Get().ProxyPort, PACExclusions: pacStore.Get().Exclusions}
	if err := applyPACFromBackup(&rb); err == nil {
		t.Error("the rollback must report the deferred PAC profiles slice")
	}
	if _, exists := pacProfiles.ProfileByID(pacCandidateOnlyID); exists {
		t.Error("rollback: the target must stay absent while its intent cannot be settled")
	}
	if !pacCandidateOnlyPending(t, opX) {
		t.Error("rollback: the earlier intent must remain durably recoverable")
	}
}

func TestPACBoundary_V2c_CandidateOnlySnapshotDefersWhileSettlementCannotPersist(t *testing.T) {
	opX := pacCandidateOnlyPendingIntent(t)
	pacSettleArmLifecycleFault(t)
	cur := pacProfiles.Get()
	snap := ConfigSnapshot{PACProfiles: append(cur.Profiles, pacCandidateOnlySpec("Added by snapshot")), PACPools: cur.Pools}
	if err := applyConfigSnapshot(snap); err != nil {
		t.Fatalf("snapshot apply: %v", err)
	}
	if _, exists := pacProfiles.ProfileByID(pacCandidateOnlyID); exists {
		t.Error("snapshot: the PAC slice must be deferred — the target must stay absent while its intent cannot be settled")
	}
	if !pacCandidateOnlyPending(t, opX) {
		t.Error("snapshot: the earlier intent must remain durably recoverable")
	}
	// Persistence recovers: the next sync applies the slice, settling the
	// earlier intent exactly once.
	pac.LifecycleWriteHook = nil
	if err := applyConfigSnapshot(snap); err != nil {
		t.Fatalf("snapshot apply once the intent can be settled: %v", err)
	}
	if p, ok := pacProfiles.ProfileByID(pacCandidateOnlyID); !ok || p.Name != "Added by snapshot" {
		t.Fatalf("the deferred slice must apply at the next sync: %+v ok=%v", p, ok)
	}
	if pacCandidateOnlyPending(t, opX) {
		t.Error("the earlier intent must be settled by the successful sync")
	}
}

// ── V3: controls ───────────────────────────────────────────────────────────

func TestPACBoundary_V3_ControlsNewIDUntouchedProfilesAndPoolsStayUnblocked(t *testing.T) {
	opX := pacCandidateOnlyPendingIntent(t)
	pacBoundarySeedOther(t, "Other")
	pacSettleArmLifecycleFault(t)
	// A genuinely new id with no pending intent stays creatable even while
	// the history cannot be written for the OTHER id's intent... except that
	// its own create transition needs the history: so this control runs
	// with persistence working and only newprof's intent outstanding.
	pac.LifecycleWriteHook = nil
	fresh := `{"id":"fresh","name":"Fresh","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"collectionEtag":` + fmt.Sprintf("%q", pacContinuityCollectionEtag(t)) + `}`
	if rec := pacFenceReq(t, "POST", "/api/pac/profiles", fresh, pacIntentIP); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("a genuinely new id with no pending intent must stay creatable: %d %s", rec.Code, rec.Body.String())
	}
	if !pacCandidateOnlyPending(t, opX) {
		t.Fatal("creating an unrelated id must not touch newprof's pending intent")
	}
	// While the history cannot be written, untouched profiles and pool-only
	// mutations stay unblocked.
	pacSettleArmLifecycleFault(t)
	other := `{"id":"other","name":"Other renamed meanwhile","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"revision":1}`
	if rec := pacFenceReq(t, "PUT", "/api/pac/profiles/other", other, pacIntentIP); rec.Code != http.StatusOK {
		t.Fatalf("an untouched-profile write must not be blocked: %d %s", rec.Code, rec.Body.String())
	}
	spare, ok := pacProfiles.PoolByID("spare")
	if !ok {
		t.Fatal("fixture pool spare missing")
	}
	pool := fmt.Sprintf(`{"id":"spare","name":"Spare renamed","endpoints":[{"host":"proxy-spare.example","port":8080}],"etag":%q}`, pac.PoolETag(spare))
	if rec := pacFenceReq(t, "PUT", "/api/pac/pools/spare", pool, pacIntentIP); rec.Code != http.StatusOK {
		t.Fatalf("a pool-only write must not be blocked: %d %s", rec.Code, rec.Body.String())
	}
	if !pacCandidateOnlyPending(t, opX) {
		t.Fatal("unrelated writes must leave newprof's pending intent untouched")
	}
	pac.LifecycleWriteHook = nil
	pacCandidateOnlyAssertSettledOnceAndCreatable(t, opX, time.Now().UnixMilli()-1)
}
