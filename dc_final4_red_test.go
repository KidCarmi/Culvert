package main

// dc_final4_red_test.go — 2D-C FINAL identity egress & persistence closure:
// red-before proofs against eec0ca44, written to compile at both trees.
//
// The invariant under test: WHILE rewriteIdentityDegraded() IS LATCHED, no
// surface may expose the live KNOWN-ephemeral StableIDs as healthy management
// identity, and no NEW durable artifact may record them as authoritative —
// the accepted state/legacy-GET closures left three egress/persistence paths
// open: config export (§1), config-version capture (§2), and the CP
// publication capture (§5), plus the omnibus settings snapshot as a fourth
// durability path found by the §3 inventory.

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ─── §1: config export ──────────────────────────────────────────────────────

// TestDCFin4_RewriteExportRefusedWhileDegraded (§4-A): the admin rewrite
// export must answer the SAME structured rewrite-identity 503 while degraded
// — never a 200 backup carrying the ephemeral StableID.
func TestDCFin4_RewriteExportRefusedWhileDegraded(t *testing.T) {
	sid := dcFin3DegradedBoot(t)

	w := httptest.NewRecorder()
	apiConfigExport(w, jsonReq("GET", "/api/config/export?section=rewrite", nil))
	if w.Code != 503 {
		t.Fatalf("rewrite export while degraded = %d — a 200 backup records the KNOWN-ephemeral StableID as authoritative (want the structured 503)", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"rewrite-identity"`) {
		t.Fatalf("export refusal must use the ONE structured dialect, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), sid) {
		t.Fatalf("export refusal leaked the ephemeral StableID: %s", w.Body.String())
	}
}

// TestDCFin4_FullExportRefusedWhileDegraded (§4-B): the full/default export
// contains RewriteRules, so it must refuse identically — never a silently
// partial backup that looks complete.
func TestDCFin4_FullExportRefusedWhileDegraded(t *testing.T) {
	sid := dcFin3DegradedBoot(t)
	for _, target := range []string{"/api/config/export", "/api/config/export?section=all"} {
		w := httptest.NewRecorder()
		apiConfigExport(w, jsonReq("GET", target, nil))
		if w.Code != 503 {
			t.Fatalf("%s while degraded = %d, want the structured 503 (the full backup carries RewriteRules)", target, w.Code)
		}
		if strings.Contains(w.Body.String(), sid) {
			t.Fatalf("%s leaked the ephemeral StableID", target)
		}
	}
}

// TestDCFin4_NonRewriteExportStaysHealthy (§4-E, CONTROL — green at both
// trees): sections that carry no RewriteRules remain available and unchanged.
func TestDCFin4_NonRewriteExportStaysHealthy(t *testing.T) {
	dcFin3DegradedBoot(t)
	w := httptest.NewRecorder()
	apiConfigExport(w, jsonReq("GET", "/api/config/export?section=blocklist", nil))
	if w.Code != 200 {
		t.Fatalf("blocklist export while rewrite identity is degraded = %d, want 200 (unrelated sections stay available)", w.Code)
	}
	if strings.Contains(w.Body.String(), "rewriteRules") &&
		strings.Contains(w.Body.String(), "stableId") {
		t.Fatalf("blocklist export must not carry rewrite identities: %s", w.Body.String()[:200])
	}
}

// ─── §2: config-version capture ─────────────────────────────────────────────

// TestDCFin4_ConfigVersionCaptureRefusedWhileDegraded (§4-C/D): an unrelated
// admin mutation's best-effort saveConfigVersion must NOT persist a new
// config-version artifact recording the ephemeral StableIDs — otherwise a
// later rollback (which treats valid UUIDs as authoritative and installs
// through installRewriteRulesDurable) promotes them into durable identity.
// With capture refused, no degraded-created version exists to promote (§4-D
// is the structural corollary, asserted over the whole store).
func TestDCFin4_ConfigVersionCaptureRefusedWhileDegraded(t *testing.T) {
	sid := dcFin3DegradedBoot(t)
	snapshotConfigVersionsDir(t)

	before := len(configVersions.List())
	saveConfigVersion("dcfin4-test", "unrelated.mutation")
	after := configVersions.List()
	if len(after) != before {
		t.Fatalf("config-version capture while rewrite identity is degraded persisted a new artifact (before=%d after=%d) — an alternate durability path around the degradation contract", before, len(after))
	}
	// §4-D corollary: NO stored version anywhere carries the ephemeral ID.
	for _, v := range after {
		_, raw, err := configVersions.Load(v.Version)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), sid) {
			t.Fatalf("stored config version v%d carries the ephemeral StableID — rollback could promote it", v.Version)
		}
	}
}

// ─── §3 inventory row B: the omnibus settings snapshot ─────────────────────

// TestDCFin4_OmnibusSaveDoesNotClaimRewriteWhileDegraded: in the
// refused-corrupt-slice shape (disk HEALTHY, settings-owned rewrite slice
// refused for malformed identity), an UNRELATED admin save snapshots the
// whole runtime — before the fix it wrote the live seed rules (fresh
// ephemeral IDs) plus RewriteRulesSaved=true over the operator's corrupt
// slice: a NEW durable artifact recording ephemeral identity as
// authoritative AND the destruction of the recoverable slice the refusal
// deliberately preserved.
func TestDCFin4_OmnibusSaveDoesNotClaimRewriteWhileDegraded(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	corrupt := `{"trusted_proxy_cidrs_saved":false,"rewrite_rules_saved":true,"rewrite_rules":[` +
		`{"stableId":"hello","host":"x.example","req_set":{"X-Test":"1"}}]}`
	if err := os.WriteFile(settingsPath, []byte(corrupt), 0o600); err != nil {
		t.Fatalf("seed settings: %v", err)
	}
	yaml := []RewriteRule{{Host: "omni.example", ReqSet: map[string]string{"X-O": "1"}}}
	live := dcFinBoot(t, settingsPath, yaml)
	if len(live) != 1 || live[0].StableID == "" {
		t.Fatalf("seed must stay live after the refused slice, got %+v", live)
	}
	sid := live[0].StableID

	// Unrelated omnibus save (any admin mutation's adminSettingsSave).
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("omnibus save: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Contains(string(data), sid) {
		t.Fatalf("the omnibus save persisted the LIVE ephemeral StableID as authoritative settings identity: %s", string(data))
	}
	if !strings.Contains(string(data), `"hello"`) {
		t.Fatalf("the omnibus save destroyed the operator's refused (recoverable) rewrite slice: %s", string(data))
	}
}

// ─── §5: CP→DP publication ─────────────────────────────────────────────────

// TestDCFin4_CPPublishRejectedWhileDegraded (§5): CurrentConfigSnapshot
// captures rewriter.List(), so a degraded CP would distribute the ephemeral
// StableIDs to every DP as authoritative fleet identity. The publish must be
// REJECTED through the existing config-publish rejection mechanism
// (rejectPublish → log/alert/LastPublishError; the fleet keeps the last
// published snapshot) — never silently omitted or re-minted.
func TestDCFin4_CPPublishRejectedWhileDegraded(t *testing.T) {
	sid := dcFin3DegradedBoot(t)
	prevMsg, prevTS := globalConfigStore.LastPublishError()
	t.Cleanup(func() {
		globalConfigStore.mu.Lock()
		globalConfigStore.lastPublishErr = prevMsg
		globalConfigStore.lastPublishTS = prevTS
		globalConfigStore.mu.Unlock()
	})

	err := publishCurrentConfigSnapshot()
	if err == nil {
		t.Fatal("CP publish while rewrite identity is degraded succeeded — the ephemeral StableIDs would be distributed to DPs as authoritative fleet identity")
	}
	if !strings.Contains(err.Error(), "rewrite") {
		t.Fatalf("publish rejection must name the rewrite-identity cause, got %v", err)
	}
	// The committed snapshot never carries the ephemeral identity.
	snap := globalConfigStore.Get()
	for i := range snap.RewriteRules {
		if snap.RewriteRules[i].StableID == sid {
			t.Fatal("the committed snapshot carries the ephemeral StableID")
		}
	}
}

// ─── §4-G: recovery (CONTROL — green at both trees) ─────────────────────────

// TestDCFin4_RecoveryRestoresExportAndVersionCapture: healthy identity ⇒
// rewrite + full export work normally (200 incl. the durable stableId) and
// config-version capture records again.
func TestDCFin4_RecoveryRestoresExportAndVersionCapture(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	snapshotConfigVersionsDir(t)
	yaml := []RewriteRule{{Host: "rec4.example", ReqSet: map[string]string{"X-R": "1"}}}
	b1 := dcFinBoot(t, settingsPath, yaml)
	if len(b1) != 1 || b1[0].StableID == "" {
		t.Fatalf("healthy boot: %+v", b1)
	}
	w := httptest.NewRecorder()
	apiConfigExport(w, jsonReq("GET", "/api/config/export?section=rewrite", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), b1[0].StableID) {
		t.Fatalf("healthy rewrite export = %d (stableId present=%v)", w.Code, strings.Contains(w.Body.String(), b1[0].StableID))
	}
	w = httptest.NewRecorder()
	apiConfigExport(w, jsonReq("GET", "/api/config/export", nil))
	if w.Code != 200 {
		t.Fatalf("healthy full export = %d", w.Code)
	}
	before := len(configVersions.List())
	saveConfigVersion("dcfin4-test", "healthy.capture")
	if len(configVersions.List()) != before+1 {
		t.Fatal("healthy config-version capture must record")
	}
	// Identity stays restart-stable.
	b2 := dcFinBoot(t, settingsPath, yaml)
	if b2[0].StableID != b1[0].StableID {
		t.Fatalf("identity must survive restart: %s vs %s", b1[0].StableID, b2[0].StableID)
	}
}
