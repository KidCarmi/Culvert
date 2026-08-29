package main

// secscan_2ea2_yara_delete_test.go — 2E-A-2 §3: YARA rule DELETE is a
// DESTRUCTIVE write and must join the same optimistic-concurrency contract as
// POST/PUT: an OPTIONAL ifRevision assertion (legacy compat when absent; the
// v2 client always asserts), compared and acted on inside the same serialized
// rule-mutation domain (contentSecMu), with the ONE structured 409 on a stale
// token and a truthful 404 for a missing target. At b60d4ed6 DELETE ignores
// any revision (admin A reviews v1, admin B lands v2, A's delete destroys v2)
// and a missing target is a misleading 400.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

const sec2ea2RuleV2 = "rule sec2ea2_v2 { strings: $a = \"sec2ea2-v2-token\" condition: $a }"

// ─── stale delete refused ───────────────────────────────────────────────────

func TestSec2EA2_YARADeleteStaleRevisionRefused(t *testing.T) {
	sec2eaSwapYARA(t)
	if _, err := globalYARA.WriteRule("r2ea2", sec2eaMinimalRule); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	revA := yaraRuleRevision(sec2eaMinimalRule) // admin A reviewed v1
	if _, err := globalYARA.WriteRule("r2ea2", sec2ea2RuleV2); err != nil {
		t.Fatalf("admin B lands v2: %v", err)
	}

	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("DELETE", "/api/security-scan/yara/rules/r2ea2?ifRevision="+revA, nil))
	if w.Code != 409 {
		t.Fatalf("stale DELETE = %d, want structured 409 (a delete reviewed against v1 destroyed v2): %s", w.Code, w.Body.String())
	}
	var conflict struct {
		Error           string `json:"error"`
		CurrentRevision string `json:"currentRevision"`
		YourRevision    string `json:"yourRevision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict decode: %v", err)
	}
	if conflict.Error == "" || conflict.YourRevision != revA ||
		conflict.CurrentRevision != yaraRuleRevision(sec2ea2RuleV2) {
		t.Fatalf("conflict dialect: %+v", conflict)
	}
	// The other admin's rule survives byte-identical.
	src, err := globalYARA.ReadRule("r2ea2")
	if err != nil || src != sec2ea2RuleV2 {
		t.Fatalf("v2 rule must survive a refused stale delete byte-identical: err=%v src=%q", err, src)
	}
}

// ─── missing target is a truthful 404 ───────────────────────────────────────

func TestSec2EA2_YARADeleteMissingTargetIs404(t *testing.T) {
	sec2eaSwapYARA(t)
	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("DELETE", "/api/security-scan/yara/rules/never-existed", nil))
	if w.Code != 404 {
		t.Fatalf("DELETE of a missing rule = %d, want 404: %s", w.Code, w.Body.String())
	}
}

// ─── legacy compat + asserted-current controls ──────────────────────────────

// Absent fence keeps the legacy replacement semantics (green at both trees).
func TestSec2EA2_YARADeleteWithoutRevisionLegacyCompat(t *testing.T) {
	sec2eaSwapYARA(t)
	if _, err := globalYARA.WriteRule("legacydel", sec2eaMinimalRule); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("DELETE", "/api/security-scan/yara/rules/legacydel", nil))
	if w.Code != 200 {
		t.Fatalf("legacy DELETE = %d: %s", w.Code, w.Body.String())
	}
	if _, err := globalYARA.ReadRule("legacydel"); err == nil {
		t.Fatal("legacy DELETE did not remove the rule")
	}
}

// A delete asserting the CURRENT revision proceeds (the v2 flow).
func TestSec2EA2_YARADeleteWithCurrentRevisionProceeds(t *testing.T) {
	sec2eaSwapYARA(t)
	if _, err := globalYARA.WriteRule("freshdel", sec2eaMinimalRule); err != nil {
		t.Fatalf("seed: %v", err)
	}
	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq("DELETE",
		"/api/security-scan/yara/rules/freshdel?ifRevision="+yaraRuleRevision(sec2eaMinimalRule), nil))
	if w.Code != 200 {
		t.Fatalf("current-revision DELETE = %d: %s", w.Code, w.Body.String())
	}
	if _, err := globalYARA.ReadRule("freshdel"); err == nil {
		t.Fatal("current-revision DELETE did not remove the rule")
	}
}

// ─── reload serialization pin ───────────────────────────────────────────────

// TestSec2EA2_YARAReloadSerializedWithRuleCRUD: yara.RuleSet.LoadDir reads the
// rules directory OUTSIDE y.mu and installs the result under it, so two
// concurrent LoadDirs can install a STALE directory read last (reload racing a
// WriteRule/DeleteRule — both of which end in their own LoadDir). The reload
// handler therefore joins contentSecMu, the same narrow domain the rule CRUD
// already serializes under. Pin: with the domain held, a reload issued
// concurrently must observe the mutation completed under the hold (its
// directory read is strictly after the CRUD's at the fixed tree).
func TestSec2EA2_YARAReloadSerializedWithRuleCRUD(t *testing.T) {
	sec2eaSwapYARA(t)
	if _, err := globalYARA.WriteRule("reload1", sec2eaMinimalRule); err != nil {
		t.Fatalf("seed: %v", err)
	}
	contentSecMu.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		apiSecYARAReload(w, jsonReq("POST", "/api/security-scan/yara/reload", nil))
		done <- w
	}()
	// Mutate the directory while the domain is held; the queued reload's
	// directory read must observe the final state.
	if _, err := globalYARA.WriteRule("reload2",
		strings.ReplaceAll(sec2eaMinimalRule, "sec2ea_min", "sec2ea_two")); err != nil {
		contentSecMu.Unlock()
		t.Fatalf("write r2: %v", err)
	}
	contentSecMu.Unlock()
	w := <-done
	if w.Code != 200 {
		t.Fatalf("reload = %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Rules float64 `json:"yara_rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Rules != 2 {
		t.Fatalf("reload reported %v rules — its directory read raced the CRUD mutation instead of serializing behind it", resp.Rules)
	}
	if globalYARA.Count() != 2 {
		t.Fatalf("final rule count %d, want 2", globalYARA.Count())
	}
}
