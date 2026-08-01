package main

// configversion_rollback_durability_test.go — CHAOS-27 / F-12 / plan item T4.
//
// Config rollback used to report unqualified success over a partial-durability
// apply: applyConfigBackup discarded every store Save() error (the Save
// signatures return nothing) and returned nothing itself, so a data directory
// that was full or read-only produced a 200 "rolled_back" while nothing
// reached disk. The operator's next restart came up on a MIXED config — some
// stores rolled back, others still on the pre-rollback state — with no record
// anywhere that it had happened.
//
// These tests pin the corrected contract:
//   - the in-memory apply stays UNCONDITIONAL (a half-applied running config
//     would be worse than a fully-applied non-durable one),
//   - a persistence failure is reported: non-2xx, an explicit
//     "rolled_back_not_durable" status, the failing file named, applied=true
//     so the caller knows the running config DID change,
//   - and the healthy path is unchanged.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// breakPolicyStorePersistence points the policy store at a file inside a
// directory that does not exist, so AtomicWrite fails deterministically for
// every uid (root bypasses chmod bits, and CI runs as root).
func breakPolicyStorePersistence(t *testing.T) string {
	t.Helper()
	orig := policyStore.path
	broken := filepath.Join(t.TempDir(), "missing-subdir", "policy.json")
	policyStore.path = broken
	t.Cleanup(func() { policyStore.path = orig })
	return broken
}

// seedRollbackTarget establishes a known baseline, snapshots it as a config
// version, then mutates the live config away from it. The returned version is
// the rollback target.
func seedRollbackTarget(t *testing.T) int {
	t.Helper()
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll(nil)
	setDefaultPolicyAction("deny")
	saveConfigVersion("chaos-test", "test.baseline")
	target := configVersions.Seq()

	// Move the live config away from the snapshot so a successful apply is
	// observable.
	policyStore.ReplaceAll([]PolicyRule{{
		Name: "chaos-t4-rule", Action: ActionAllow, DestFQDN: "*",
	}})
	if len(policyStore.List()) != 1 {
		t.Fatalf("setup: live policy has %d rules, want 1", len(policyStore.List()))
	}
	return target
}

func postRollback(t *testing.T, version int) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"version": version})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/config/versions", strings.NewReader(string(body))))
	rec := httptest.NewRecorder()
	rollbackConfigVersion(rec, req)
	return rec
}

// TestApplyConfigBackup_ReportsPersistenceFailure is the unit-level assertion:
// pre-fix applyConfigBackup returned nothing at all, so this could not compile,
// let alone fail.
func TestApplyConfigBackup_ReportsPersistenceFailure(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)
	snapshotPolicyStoreForTest(t)

	policyStore.ReplaceAll([]PolicyRule{{
		Name: "pre-rollback", Action: ActionAllow, DestFQDN: "*",
	}})
	breakPolicyStorePersistence(t)

	target := &configBackup{
		DefaultAction: "deny",
		PolicyRules: []PolicyRule{{
			Name: "restored", Action: ActionDrop, DestFQDN: "example.com",
		}},
	}
	err := applyConfigBackup(target)
	if err == nil {
		t.Fatal("applyConfigBackup returned nil with an unwritable policy store — the caller cannot tell the rollback is not durable")
	}
	if !strings.Contains(err.Error(), "policy.json") {
		t.Errorf("error %q does not name the file that failed to persist", err)
	}

	// The RUNNING config must still be fully rolled back — persistence failure
	// must never leave a half-applied policy plane.
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "restored" {
		t.Errorf("live rules = %+v, want the snapshot applied in memory despite the write failure", rules)
	}
}

// TestRollbackConfigVersion_PartialDurabilityIsNot200 is T4 proper.
func TestRollbackConfigVersion_PartialDurabilityIsNot200(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	target := seedRollbackTarget(t)
	breakPolicyStorePersistence(t)

	rec := postRollback(t, target)

	if rec.Code == http.StatusOK {
		t.Fatalf("rollback returned 200 over a failed persist — the pre-fix silent-success bug; body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if resp["status"] != "rolled_back_not_durable" {
		t.Errorf("status field = %v, want rolled_back_not_durable", resp["status"])
	}
	if resp["applied"] != true {
		t.Error("applied != true — the caller must know the RUNNING config already changed, so retrying is not the fix")
	}
	if resp["stores_persisted"] != false {
		t.Error("stores_persisted != false")
	}
	pe, _ := resp["persist_errors"].(string)
	if !strings.Contains(pe, "policy.json") {
		t.Errorf("persist_errors = %q, does not name the failing file", pe)
	}

	// The rollback really did apply to the running config.
	if got := len(policyStore.List()); got != 0 {
		t.Errorf("live rules = %d, want 0 (the baseline snapshot) — apply must not abort on a persist failure", got)
	}
	// The failure is RECORDED globally — but assert ONLY that the observer
	// fired, never which file is last and never storageDegraded().
	//
	// Both of those are properties of process-global state that this handler
	// itself keeps changing after the failed store: saveConfigVersion writes to
	// a writable temp dir (a SUCCESS, which legitimately clears degraded — only
	// the target directory was missing, the filesystem is fine), and
	// globalConfigStore.Update writes /data/cp_config_version.json (a FAILURE on
	// a node whose data directory is unwritable, which claims the last-failure
	// slot). Which file THIS rollback failed to persist is the scoped
	// collector's job, and it is already asserted above via persist_errors.
	if snap := storageWriteFailures(); snap.Total < 1 {
		t.Errorf("failure record = %+v, want the failed durable write recorded", snap)
	}
}

// TestRollbackConfigVersion_HealthyPathUnchanged guards against the fix turning
// ordinary rollbacks into 500s.
func TestRollbackConfigVersion_HealthyPathUnchanged(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	target := seedRollbackTarget(t)
	// Persistence points at a real, writable temp file.
	policyStore.path = filepath.Join(t.TempDir(), "policy.json")

	rec := postRollback(t, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp["status"] != "rolled_back" {
		t.Errorf("status = %v, want rolled_back", resp["status"])
	}
	if resp["stores_persisted"] != true {
		t.Error("stores_persisted != true on a healthy rollback")
	}
	// The response must NOT claim blanket durability: several restored surfaces
	// are runtime-only and revert on restart (CHAOS-46). Naming them is the
	// contract; an operator reading only "durable:true" would be misled.
	surfaces, _ := resp["runtime_only_surfaces"].([]any)
	if len(surfaces) == 0 {
		t.Error("runtime_only_surfaces missing — the response would overclaim durability")
	}
	var haveDefaultAction bool
	for _, s := range surfaces {
		if s == "default_action" {
			haveDefaultAction = true
		}
	}
	if !haveDefaultAction {
		t.Errorf("runtime_only_surfaces = %v, want it to name default_action (applied via an atomic int, never persisted by this path)", surfaces)
	}
	if got := len(policyStore.List()); got != 0 {
		t.Errorf("live rules = %d, want 0 (baseline restored)", got)
	}
	// Deliberately NOT asserting !storageDegraded() here. That is a
	// process-global read, and the handler itself performs writes OUTSIDE the
	// rollback scope — saveConfigVersion and globalConfigStore.Update both
	// persist under the data directory. On a node whose data directory is
	// unwritable (which is exactly the CI test environment) those fail and set
	// the global record while THIS rollback persisted perfectly well. The
	// meaningful assertion is the one above: the response says durable:true.
	// Conflating "this operation was durable" with "nothing anywhere has ever
	// failed to write" is what the scoped collector exists to avoid.
}
