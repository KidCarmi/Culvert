package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// 2F-E correction round 7 — the refusal/deferral half of the pre-write
// settlement rule (pacSettlePendingBeforeWrite): while the node-local
// lifecycle history cannot be written, a writer that would CHANGE a profile
// with an unsettled intent is refused (CRUD 503 lifecycle_unsettled) or
// deferred (import: pac_profiles_not_applied; rollback: returned error) with
// nothing written — X's active content and provenance stay intact — and once
// persistence recovers the same write succeeds and X is still reconciled as
// COMMITTED exactly once. An unrelated write is never blocked.

func pacSettleArmLifecycleFault(t *testing.T) {
	t.Helper()
	pac.LifecycleWriteHook = func(string, map[string]*pac.ProfileLifecycle) error { return errPACTransitionInjected }
}

func TestPACBoundary_W3_TargetPutRefusedWhileSettlementCannotPersist(t *testing.T) {
	opX, spec := pacTargetGenuineCommit(t)
	pacBoundarySeedOther(t, "Other")
	pacSettleArmLifecycleFault(t)
	body := `{"id":"branch-il","name":"` + pacTargetLaterName + `","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"revision":2}`
	rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", body, pacIntentIP)
	if rec.Code != http.StatusServiceUnavailable || pacIntentJSON(t, rec)["code"] != "lifecycle_unsettled" {
		t.Fatalf("a target write while X cannot be settled durably must be refused 503 lifecycle_unsettled: %d %s", rec.Code, rec.Body.String())
	}
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 2 || pac.ProfileSpecDigest(p) != pac.ProfileSpecDigest(spec) {
		t.Fatalf("a refused write must change nothing: %+v ok=%v", p, ok)
	}
	if w := pacProfiles.ProfileWriteID("branch-il"); w != opX {
		t.Fatalf("X's provenance must survive the refused write, got %q", w)
	}
	// An unrelated profile is never blocked by X's unsettled intent.
	other := `{"id":"other","name":"Other renamed meanwhile","enabled":true,"poolId":"spare","privateNetworks":"proxy","availabilityMode":"balanced","rules":[],"revision":1}`
	if rec := pacFenceReq(t, "PUT", "/api/pac/profiles/other", other, pacIntentIP); rec.Code != http.StatusOK {
		t.Fatalf("an unrelated write must not be blocked: %d %s", rec.Code, rec.Body.String())
	}
	// Persistence recovers: the same target write succeeds, settling X first.
	pac.LifecycleWriteHook = nil
	if rec := pacFenceReq(t, "PUT", "/api/pac/profiles/branch-il", body, pacIntentIP); rec.Code != http.StatusOK {
		t.Fatalf("the target write must succeed once X can be settled: %d %s", rec.Code, rec.Body.String())
	}
	pacTargetRestartAndAssert(t, opX, spec, func(t *testing.T, stage string, _ map[string]any) {
		t.Helper()
		if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != pacTargetLaterName || p.Revision != 3 {
			t.Errorf("%s: the later target write must be authoritative: %+v ok=%v", stage, p, ok)
		}
	})
}

func TestPACBoundary_W4_ImportAndRollbackDeferTargetWhileSettlementCannotPersist(t *testing.T) {
	opX, spec := pacTargetGenuineCommit(t)
	later := pacTransitionSpec(pacTargetLaterName, 3)
	pacSettleArmLifecycleFault(t)
	// Replace-mode import: the PAC slice is not applied and the response says so.
	b := configBackup{Version: configBackupVersion, PACProfiles: []pac.Profile{later}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	apiConfigImport(w, adminRequest("POST", "/api/config/import?mode=replace", string(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if s, _ := resp["pac_profiles_not_applied"].(string); s == "" {
		t.Fatalf("the import must report the deferred PAC profiles slice: %s", w.Body.String())
	}
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 2 || pac.ProfileSpecDigest(p) != pac.ProfileSpecDigest(spec) {
		t.Fatalf("a deferred import must change nothing: %+v ok=%v", p, ok)
	}
	// Config rollback: the PAC slice is deferred and the error is returned.
	cur := pacProfiles.Get()
	rb := configBackup{Version: configBackupVersion, PACProfiles: []pac.Profile{later}, PACPools: cur.Pools,
		PACProxyHost: pacStore.Get().ProxyHost, PACProxyPort: pacStore.Get().ProxyPort, PACExclusions: pacStore.Get().Exclusions}
	if err := applyPACFromBackup(&rb); err == nil {
		t.Fatal("the rollback must report the deferred PAC profiles slice")
	}
	if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Revision != 2 || pac.ProfileSpecDigest(p) != pac.ProfileSpecDigest(spec) {
		t.Fatalf("a deferred rollback must change nothing: %+v ok=%v", p, ok)
	}
	if pacProfiles.ProfileWriteID("branch-il") != opX {
		t.Fatal("X's provenance must survive the deferred writes")
	}
	// Persistence recovers: the rollback applies, settling X first.
	pac.LifecycleWriteHook = nil
	if err := applyPACFromBackup(&rb); err != nil {
		t.Fatalf("rollback once X can be settled: %v", err)
	}
	pacTargetRestartAndAssert(t, opX, spec, func(t *testing.T, stage string, _ map[string]any) {
		t.Helper()
		if p, ok := pacBoundaryProfile(t, "branch-il"); !ok || p.Name != pacTargetLaterName || p.Revision != 3 {
			t.Errorf("%s: the rolled-back target must be authoritative: %+v ok=%v", stage, p, ok)
		}
	})
}
