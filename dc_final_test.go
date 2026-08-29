package main

// dc_final_test.go — 2D-C FINAL correction, green contract proofs beyond the
// red matrix (dc_final_red_test.go): the YAML-seed identity ledger's
// ownership-preservation and re-attachment semantics (§8–§9), the
// sentinel-empty no-resurrection guarantee, the legacy in-file migration's
// ownership neutrality, and the rewrite-rollback restart durability the §17
// operator-truth fix now claims.

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// dcFinYAMLBootEnv isolates rewriter + default action + settings path for a
// simulated boot loop against the given settings file path.
func dcFinYAMLBootEnv(t *testing.T) (settingsPath string) {
	t.Helper()
	dir := t.TempDir()
	settingsPath = filepath.Join(dir, "admin_settings.json")
	prevAction := defaultPolicyAction()
	prevMetricsToken := metricsToken
	prevTrusted := ListTrustedProxyCIDRs()
	t.Cleanup(func() {
		setDefaultPolicyAction(prevAction)
		metricsToken = prevMetricsToken
		_ = SetTrustedProxyCIDRs(prevTrusted)
	})
	restoreRewriter := rewriter.Snapshot()
	t.Cleanup(restoreRewriter)
	swapAdminSettingsPath(t, settingsPath)
	return settingsPath
}

func dcFinBoot(t *testing.T, settingsPath string, yaml []RewriteRule) []RewriteRule {
	t.Helper()
	rewriter.SetRules(nil) // fresh process
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{Rules: yaml, DefaultAction: "allow"}, 0)
	LoadAdminSettings(settingsPath)
	return rewriter.List()
}

// TestDCFin_SeedLedgerPreservesUnrelatedOwnership (§8/§9): the identity-ledger
// migration against an EXISTING settings file must preserve every unrelated
// field and ownership sentinel — it must not flip another YAML/CLI surface to
// saved-authoritative, and it must not claim the rewrite surface itself.
func TestDCFin_SeedLedgerPreservesUnrelatedOwnership(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	// An operator file that owns trusted-proxy config but deliberately NOT
	// upstreams (YAML-driven) and NOT rewrite.
	if err := os.WriteFile(settingsPath, []byte(
		`{"trusted_proxy_cidrs_saved":true,"upstream_proxies_saved":false,"metrics_token":"tok-keep"}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	yaml := []RewriteRule{{Host: "led.example", ReqSet: map[string]string{"X-L": "1"}}}
	got := dcFinBoot(t, settingsPath, yaml)
	if len(got) != 1 || got[0].StableID == "" {
		t.Fatalf("seed must publish with identity, got %+v", got)
	}

	var s AdminSettings
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !s.TrustedProxyCIDRsSaved || s.UpstreamProxiesSaved || s.MetricsToken != "tok-keep" {
		t.Fatalf("identity migration changed unrelated ownership/fields: %+v", s)
	}
	if s.RewriteRulesSaved || len(s.RewriteRules) != 0 {
		t.Fatalf("the ledger migration must NOT claim the rewrite surface itself (sentinel/list must stay unowned), got saved=%v rules=%d", s.RewriteRulesSaved, len(s.RewriteRules))
	}
	if len(s.RewriteSeedIdentities) != 1 || s.RewriteSeedIdentities[0].StableID != got[0].StableID {
		t.Fatalf("ledger must record the seeded identity, got %+v", s.RewriteSeedIdentities)
	}
}

// TestDCFin_LegacyInFileMigrationPreservesOwnership (§9): the one-time
// stable-ID backfill for a LEGACY settings file (rewrite rules persisted
// without stableIds under the len>0 gate) persists the identities while
// leaving every ownership value — including the rewrite sentinel itself —
// exactly as the operator's file carried them.
func TestDCFin_LegacyInFileMigrationPreservesOwnership(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if err := os.WriteFile(settingsPath, []byte(
		`{"trusted_proxy_cidrs_saved":true,"upstream_proxies_saved":false,`+
			`"rewrite_rules":[{"id":1,"host":"leg.example","req_remove":["X-Old"]}]}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}

	got := dcFinBoot(t, settingsPath, nil)
	if len(got) != 1 || got[0].StableID == "" {
		t.Fatalf("legacy persisted rule must be restored with a backfilled identity, got %+v", got)
	}

	var s AdminSettings
	data, _ := os.ReadFile(settingsPath)
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(s.RewriteRules) != 1 || s.RewriteRules[0].StableID != got[0].StableID {
		t.Fatalf("migration must persist the backfilled identity, file carries %+v", s.RewriteRules)
	}
	if s.RewriteRulesSaved {
		t.Fatal("migration must not flip the rewrite ownership sentinel on a legacy len>0 file")
	}
	if !s.TrustedProxyCIDRsSaved || s.UpstreamProxiesSaved {
		t.Fatalf("migration changed unrelated ownership sentinels: %+v", s)
	}

	// And the identity is now restart-stable.
	got2 := dcFinBoot(t, settingsPath, nil)
	if len(got2) != 1 || got2[0].StableID != got[0].StableID {
		t.Fatalf("migrated identity must survive restart, got %+v", got2)
	}
}

// TestDCFin_AdminEmptySentinelDoesNotResurrectYAML (§9): an admin-persisted
// EXPLICIT empty rewrite set (sentinel true) stays authoritative over the
// YAML seed — the ledger machinery must not resurrect seeded rules.
func TestDCFin_AdminEmptySentinelDoesNotResurrectYAML(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if err := os.WriteFile(settingsPath, []byte(`{"rewrite_rules_saved":true}`), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	yaml := []RewriteRule{{Host: "res.example", ReqSet: map[string]string{"X-R": "1"}}}
	if got := dcFinBoot(t, settingsPath, yaml); len(got) != 0 {
		t.Fatalf("admin-owned explicit empty set must win over the YAML seed, got %+v", got)
	}
	var s AdminSettings
	data, _ := os.ReadFile(settingsPath)
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !s.RewriteRulesSaved || len(s.RewriteRules) != 0 {
		t.Fatalf("boot must not disturb the persisted empty ownership, got %+v", s)
	}
}

// TestDCFin_YAMLEditReattachesUnchangedPositions (§7 posture): legacy YAML
// rules carry no inherent identity, so continuity across a YAML EDIT is
// best-effort position+content re-attachment — unchanged positions keep
// their identities, a changed position is a new object with fresh identity,
// and the updated ledger is itself restart-stable.
func TestDCFin_YAMLEditReattachesUnchangedPositions(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	yamlV1 := []RewriteRule{
		{Host: "keep.example", ReqSet: map[string]string{"X-K": "1"}},
		{Host: "edit.example", ReqSet: map[string]string{"X-E": "1"}},
	}
	b1 := dcFinBoot(t, settingsPath, yamlV1)
	if len(b1) != 2 {
		t.Fatalf("boot1: %+v", b1)
	}

	yamlV2 := []RewriteRule{
		{Host: "keep.example", ReqSet: map[string]string{"X-K": "1"}},
		{Host: "edit.example", ReqSet: map[string]string{"X-E": "CHANGED"}},
	}
	b2 := dcFinBoot(t, settingsPath, yamlV2)
	if len(b2) != 2 {
		t.Fatalf("boot2: %+v", b2)
	}
	if b2[0].StableID != b1[0].StableID {
		t.Fatalf("unchanged position must keep its identity: %s vs %s", b2[0].StableID, b1[0].StableID)
	}
	if b2[1].StableID == b1[1].StableID {
		t.Fatal("a content-changed YAML position is a different object and must not inherit the old identity")
	}

	// The edited set's identities are now stable across further restarts.
	b3 := dcFinBoot(t, settingsPath, yamlV2)
	for i := range b2 {
		if b3[i].StableID != b2[i].StableID {
			t.Fatalf("post-edit identities must be restart-stable, pos %d: %s vs %s", i, b3[i].StableID, b2[i].StableID)
		}
	}
}

// TestDCFin_RewriteRollbackSurvivesRestart (§17): the operator-truth fix
// claims a successful rewrite rollback is restart-durable — prove it through
// a real rollback followed by a simulated restart (fresh rewriter restored
// from the settings file).
func TestDCFin_RewriteRollbackSurvivesRestart(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	csrTaxIsolate(t)

	// Interactive create (durable via the settings owner), version captured.
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq("POST", "/api/rewrite",
		map[string]any{"host": "rbres.example", "req_set": map[string]string{"X-T": "1"}}))
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var added RewriteRule
	if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode: %v", err)
	}
	saveConfigVersion("dcfin-test", "seed")
	versions := configVersions.List()
	target := versions[len(versions)-1].Version

	// Delete, then roll back.
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("DELETE", "/api/rewrite?stableId="+added.StableID, nil))
	if w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	w = httptest.NewRecorder()
	apiConfigVersions(w, jsonReq("POST", "/api/config/versions", map[string]any{"version": target}))
	if w.Code != 200 {
		t.Fatalf("rollback: %d %s", w.Code, w.Body.String())
	}

	// Simulated restart: fresh rewriter, state restored from the settings owner.
	rewriter.SetRules(nil)
	LoadAdminSettings(settingsPath)
	got := rewriter.List()
	if len(got) != 1 || got[0].StableID != added.StableID {
		t.Fatalf("a successful rewrite rollback must survive restart with the same identity, got %+v", got)
	}
}
