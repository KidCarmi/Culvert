package main

// dc_final5_red_test.go — 2D-C FINAL two-defect closure: red-before proofs
// against 86c9c17a, written to compile at both trees.
//
//	§1 — the config-version rollback DRY-RUN compared the target against
//	     captureConfigBackup() (which reads rewriter.List()) and returned a
//	     healthy 200 preview whose identity-aware rewrite diff emitted the
//	     live KNOWN-ephemeral StableIDs while the management-identity
//	     degradation was latched.
//	§2 — installRewriteRulesDurable persisted a legacy target AS-IS (empty
//	     StableIDs) and only THEN published it; SetRules backfilled UUIDs
//	     into its internal copy, never the already-persisted slice — so a
//	     "successful durable install" left disk="" vs runtime=UUID-A, and
//	     every restart re-minted a fresh identity (UUID-B, …), violating the
//	     promised one-time legacy migration.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dcFin5SeedVersion stores a config-version artifact carrying exactly the
// given rewrite rules on top of the CURRENT live capture (so a real rollback
// restores everything else unchanged) and returns its version number.
//
// pre2DC additionally strips the SaaS-feed extension fields, making the
// artifact a genuine PRE-EXTENSION historical version: the rollback feed
// slice nil-skips (SaaSFeedProtocol == ""), so no LATER slice in the apply
// performs a settings save that could incidentally re-write the rewrite
// fields — the truthfulness of the rewrite install itself is what is under
// test (an artifact carrying feed fields is repaired at 86c9c17a only by
// that later installSaaSFeedDurable omnibus write, exactly the
// later-save dependency the invariant forbids).
func dcFin5SeedVersion(t *testing.T, rules []RewriteRule, pre2DC bool) int {
	t.Helper()
	snap := captureConfigBackup()
	snap.RewriteRules = rules
	if pre2DC {
		snap.SaaSFeedProtocol = ""
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal artifact: %v", err)
	}
	ver, err := configVersions.SaveWithNote("dcfin5-test", "seed", time.Now().UTC().Format(time.RFC3339), "", raw)
	if err != nil {
		t.Fatalf("seed version: %v", err)
	}
	return ver
}

// ─── §1: rollback dry-run identity leak ─────────────────────────────────────

// TestDCFin5_RollbackDryRunRefusedWhileDegraded (§1 red A–E): a dry-run
// preview against a durable historical version must NOT expose the live
// KNOWN-ephemeral StableIDs while the degradation is latched — it answers
// the ONE structured 503 (authorization still first; no mutation).
func TestDCFin5_RollbackDryRunRefusedWhileDegraded(t *testing.T) {
	snapshotConfigVersionsDir(t)
	// A: a durable historical artifact whose rewrite identity differs from
	// the live rule (a valid modern UUID on another host).
	histRule := RewriteRule{
		StableID: "6b1f6c3e-8a2d-4f1b-9c0d-2e5a7b4c9d10",
		Host:     "hist5.example",
		ReqSet:   map[string]string{"X-H5": "1"},
	}
	// B: latch the degradation (live rule f3.example, ephemeral sid). The
	// artifact is seeded FIRST from a neutral capture so it carries no
	// degraded-boot identity.
	ver := dcFin5SeedVersion(t, []RewriteRule{histRule}, false)
	sid := dcFin3DegradedBoot(t)
	before := rewriter.List()

	// C: Admin dry-run.
	w := httptest.NewRecorder()
	apiConfigVersions(w, dcFin3RoleReq("POST", "/api/config/versions", RoleAdmin,
		fmt.Sprintf(`{"version":%d,"dry_run":true}`, ver)))

	// D/E: against 86c9c17a this is a 200 whose rewrite_rules diff carries
	// the ephemeral StableID (typically removed/changed).
	if w.Code != 503 {
		leak := strings.Contains(w.Body.String(), sid)
		t.Fatalf("rollback dry-run while degraded = %d (ephemeral StableID in body: %v) — a healthy 200 preview exposes KNOWN-ephemeral identity through the identity-aware diff (want the structured 503)", w.Code, leak)
	}
	if !strings.Contains(w.Body.String(), `"rewrite-identity"`) {
		t.Fatalf("dry-run refusal must use the ONE structured dialect, got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "reason") {
		t.Fatalf("dry-run refusal must carry the reason, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), sid) {
		t.Fatalf("dry-run refusal leaked the ephemeral StableID: %s", w.Body.String())
	}
	// No mutation in either shape.
	after := rewriter.List()
	if len(after) != len(before) || after[0].StableID != before[0].StableID {
		t.Fatalf("a dry-run changed the rule set: %+v -> %+v", before, after)
	}
}

// TestDCFin5_HealthyDryRunKeepsIdentityAwareDiff (§1-F CONTROL — green at
// both trees): healthy identity ⇒ dry-run stays a 200 preview with the
// existing identity-aware rewrite diff.
func TestDCFin5_HealthyDryRunKeepsIdentityAwareDiff(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	snapshotConfigVersionsDir(t)
	yaml := []RewriteRule{{Host: "dr5ok.example", ReqSet: map[string]string{"X-OK": "1"}}}
	live := dcFinBoot(t, settingsPath, yaml)
	if len(live) != 1 || live[0].StableID == "" {
		t.Fatalf("healthy boot: %+v", live)
	}
	ver := dcFin5SeedVersion(t, []RewriteRule{{
		StableID: "0d9e8f7a-6b5c-4d3e-8f1a-2b3c4d5e6f70",
		Host:     "dr5hist.example",
	}}, false)

	w := httptest.NewRecorder()
	apiConfigVersions(w, dcFin3RoleReq("POST", "/api/config/versions", RoleAdmin,
		fmt.Sprintf(`{"version":%d,"dry_run":true}`, ver)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"dry_run"`) {
		t.Fatalf("healthy dry-run = %d body=%s, want the normal 200 preview", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "rewrite_rules") || !strings.Contains(w.Body.String(), live[0].StableID) {
		t.Fatalf("healthy dry-run must keep the identity-aware rewrite diff (live durable id present), got %s", w.Body.String())
	}
}

// ─── §2: legacy ID-less bulk install restart stability ──────────────────────

// TestDCFin5_LegacyInstallPersistsPublishedIdentity (§2 red A): a successful
// durable install of a legacy (empty-StableID) target must persist the SAME
// canonical UUID it publishes, and that identity survives restart.
func TestDCFin5_LegacyInstallPersistsPublishedIdentity(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("clean boot: %+v", got)
	}

	target := []RewriteRule{{Host: "legacy5.example", ReqSet: map[string]string{"X-L5": "1"}}}
	if err := installRewriteRulesDurable(target); err != nil {
		t.Fatalf("install: %v", err)
	}
	live := rewriter.List()
	if len(live) != 1 || live[0].StableID == "" {
		t.Fatalf("published target must carry server identity, got %+v", live)
	}
	uuidA := live[0].StableID

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), uuidA) {
		t.Fatalf("install reported success but the persisted settings do not carry the PUBLISHED identity %s — disk holds a different (or empty) stableId that re-mints on every restart: %s", uuidA, string(data))
	}

	// Restart: the SAME identity, not a re-mint.
	b2 := dcFinBoot(t, settingsPath, nil)
	if len(b2) != 1 || b2[0].StableID != uuidA {
		t.Fatalf("legacy migration must be one-time: published %s, after restart %+v", uuidA, b2)
	}
}

// TestDCFin5_HistoricalRollbackIdentitySurvivesRestart (§2 red B): a real
// rollback of a pre-2D-C artifact (rewrite rules WITHOUT stable IDs) must end
// with the generated identity durable — the same UUID after restart.
func TestDCFin5_HistoricalRollbackIdentitySurvivesRestart(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	csrTaxIsolate(t)
	snapshotConfigVersionsDir(t)
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("clean boot: %+v", got)
	}
	ver := dcFin5SeedVersion(t, []RewriteRule{{Host: "hist5b.example", ReqSet: map[string]string{"X-HB": "1"}}}, true)

	w := httptest.NewRecorder()
	apiConfigVersions(w, dcFin3RoleReq("POST", "/api/config/versions",
		RoleAdmin, fmt.Sprintf(`{"version":%d}`, ver)))
	if w.Code != 200 {
		t.Fatalf("rollback: %d %s", w.Code, w.Body.String())
	}
	live := rewriter.List()
	if len(live) != 1 || live[0].StableID == "" || live[0].Host != "hist5b.example" {
		t.Fatalf("rollback must publish the restored rule with server identity, got %+v", live)
	}
	uuidA := live[0].StableID
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), uuidA) {
		t.Fatalf("rollback succeeded but the persisted settings do not carry the published identity %s: %s", uuidA, string(data))
	}
	b2 := dcFinBoot(t, settingsPath, nil)
	if len(b2) != 1 || b2[0].StableID != uuidA {
		t.Fatalf("historical-rollback identity must survive restart: published %s, after restart %+v", uuidA, b2)
	}
}

// TestDCFin5_LegacyImportReplaceAndMergeAreDurable (§2 red C): both import
// semantics — replace with an ID-less rule, then merge-append of another —
// must end with the exact generated identity already durable when the
// handler completes, surviving restart.
func TestDCFin5_LegacyImportReplaceAndMergeAreDurable(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	csrTaxIsolate(t)
	snapshotConfigVersionsDir(t)
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("clean boot: %+v", got)
	}

	// Replace with one ID-less legacy rule.
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", map[string]any{
		"version":      1,
		"rewriteRules": []map[string]any{{"host": "imp5.example", "req_set": map[string]string{"X-I5": "1"}}},
	}))
	if w.Code != 200 {
		t.Fatalf("replace import: %d %s", w.Code, w.Body.String())
	}
	live := rewriter.List()
	if len(live) != 1 || live[0].StableID == "" {
		t.Fatalf("replace import must publish server identity, got %+v", live)
	}
	uuidA := live[0].StableID
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), uuidA) {
		t.Fatalf("replace import completed but disk does not carry the published identity %s: %s", uuidA, string(data))
	}

	// Merge-append a second ID-less rule.
	w = httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import", map[string]any{
		"version":      1,
		"rewriteRules": []map[string]any{{"host": "imp5b.example", "req_add": map[string]string{"X-IB": "1"}}},
	}))
	if w.Code != 200 {
		t.Fatalf("merge import: %d %s", w.Code, w.Body.String())
	}
	live = rewriter.List()
	if len(live) != 2 || live[1].StableID == "" || live[1].Host != "imp5b.example" {
		t.Fatalf("merge import must append with server identity, got %+v", live)
	}
	uuidB := live[1].StableID
	if data, err = os.ReadFile(settingsPath); err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), uuidB) {
		t.Fatalf("merge import completed but disk does not carry the appended identity %s: %s", uuidB, string(data))
	}

	// Restart: both identities preserved exactly.
	b2 := dcFinBoot(t, settingsPath, nil)
	if len(b2) != 2 || b2[0].StableID != uuidA || b2[1].StableID != uuidB {
		t.Fatalf("imported identities must survive restart verbatim (%s, %s), got %+v", uuidA, uuidB, b2)
	}
}

// TestDCFin5_ModernIdentityPreservedVerbatim (§2-D CONTROL — green at both
// trees): modern valid StableIDs pass install + restart byte-for-byte.
func TestDCFin5_ModernIdentityPreservedVerbatim(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	if got := dcFinBoot(t, settingsPath, nil); len(got) != 0 {
		t.Fatalf("clean boot: %+v", got)
	}
	const modern = "3c2b1a09-8d7e-4f6a-9b5c-4d3e2f1a0b9c"
	target := []RewriteRule{{StableID: modern, Host: "mod5.example", ReqSet: map[string]string{"X-M5": "1"}}}
	if err := installRewriteRulesDurable(target); err != nil {
		t.Fatalf("install: %v", err)
	}
	if live := rewriter.List(); len(live) != 1 || live[0].StableID != modern {
		t.Fatalf("modern identity must publish verbatim, got %+v", live)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if !strings.Contains(string(data), modern) {
		t.Fatalf("modern identity must persist verbatim: %s", string(data))
	}
	if b2 := dcFinBoot(t, settingsPath, nil); len(b2) != 1 || b2[0].StableID != modern {
		t.Fatalf("modern identity must survive restart verbatim, got %+v", b2)
	}
}

// TestDCFin5_PersistFailurePublishesNothing (§2-E CONTROL — green at both
// trees): a hard persist failure must leave the runtime unchanged — no
// generated identity ever becomes externally usable as a successful durable
// install (durable-or-nothing preserved by the canonicalization).
func TestDCFin5_PersistFailurePublishesNothing(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	yaml := []RewriteRule{{Host: "pf5.example", ReqSet: map[string]string{"X-P5": "1"}}}
	before := dcFinBoot(t, settingsPath, yaml)
	if len(before) != 1 {
		t.Fatalf("boot: %+v", before)
	}
	// Every AtomicWrite under this path fails (nonexistent directory).
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "no-such-dir", "admin_settings.json"))

	err := installRewriteRulesDurable([]RewriteRule{{Host: "pf5new.example"}})
	if err == nil {
		t.Fatal("install against a broken settings path must fail")
	}
	after := rewriter.List()
	if len(after) != 1 || after[0].StableID != before[0].StableID || after[0].Host != "pf5.example" {
		t.Fatalf("a failed install must publish nothing: %+v -> %+v", before, after)
	}
}
