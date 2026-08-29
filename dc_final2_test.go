package main

// dc_final2_test.go — recovery trust-boundary correction, green contract
// proofs beyond the red matrix (dc_final2_red_test.go): the settings-owned
// legacy backfill persistence-failure variant (§6, injected through the
// targeted writer's seam) and its recovery.

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// TestDCFin2_LegacyBackfillPersistFailureDegrades (§6 variant): a legacy
// settings file whose one-time stable-ID backfill cannot persist leaves the
// backfilled identities memory-only — a restart would re-mint them, so the
// management surface degrades instead of presenting them as durable. Once
// persistence recovers, the migration lands and identity is restart-stable.
func TestDCFin2_LegacyBackfillPersistFailureDegrades(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if err := os.WriteFile(settingsPath, []byte(
		`{"rewrite_rules":[{"id":1,"host":"bf.example","req_remove":["X-B"]}]}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	prevWrite := rewriteIdentityAtomicWrite
	rewriteIdentityAtomicWrite = func(string, []byte, os.FileMode) error {
		return os.ErrPermission // hard persistence failure
	}
	t.Cleanup(func() { rewriteIdentityAtomicWrite = prevWrite })

	got := dcFinBoot(t, settingsPath, nil)
	if len(got) != 1 || got[0].StableID == "" {
		t.Fatalf("data-plane restore must keep operating with a runtime identity, got %+v", got)
	}
	w := httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 503 {
		t.Fatalf("state with an unpersisted legacy backfill = %d, want the structured 503 degradation", w.Code)
	}
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+got[0].StableID, nil))
	if w.Code != 503 {
		t.Fatalf("StableID mutation while identity is not durable = %d, want 503", w.Code)
	}

	// RECOVERY: persistence restored — the migration lands and the identity
	// is management-usable and restart-stable.
	rewriteIdentityAtomicWrite = fileutil.AtomicWrite
	b1 := dcFinBoot(t, settingsPath, nil)
	if len(b1) != 1 || b1[0].StableID == "" {
		t.Fatalf("recovered boot: %+v", b1)
	}
	w = httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 200 {
		t.Fatalf("recovered state = %d, want 200", w.Code)
	}
	b2 := dcFinBoot(t, settingsPath, nil)
	if b2[0].StableID != b1[0].StableID {
		t.Fatalf("migrated identity must be restart-stable after recovery: %s vs %s", b1[0].StableID, b2[0].StableID)
	}
}
