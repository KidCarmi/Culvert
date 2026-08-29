package main

// secscan_2ea2_fleet_truth_test.go — 2E-A-2 §4: CP/DP ownership + fleet
// distribution truth for the two CLUSTER-SYNCED content-security surfaces
// (threat-feed domain allowlist and DPI patterns — both captured by
// CurrentConfigSnapshot and applied by the DP snapshot path; config_surfaces
// rows threat_domain_allowlist / content_scan_patterns, ClusterSynced).
//
//  A. OWNERSHIP: on a managed Data Plane the CP is the single writer for
//     synced surfaces (the established F3a-2 posture, isManagedDataPlane) —
//     local mutations are refused BEFORE any mutation with the established
//     409, and the GETs carry the established `editable` ownership signal.
//  B. PUBLISH TRUTH: the allowlist PUT used to discard the
//     publishCurrentConfigSnapshot error, so "locally saved" and "fleet
//     rejected" collapsed into one healthy-looking 200. The established
//     cluster_publish_rejected response fact (saas_feed_api.go /
//     ui_config.go import) must surface the rejection; the valid local
//     mutation is kept (established doctrine — the fleet stays on the last
//     valid snapshot).
//  C. DISTRIBUTION: a successful DPI pattern mutation on an authoritative
//     node must advance the published config (DPs converge by version), and
//     a rejected publish is visible inline.
//
// Determinism: the publish rejection is driven by the rewrite-identity
// degradation latch — ConfigStore.Update Gate 0 rejects every publish while
// it is set (no external cluster required).

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── §4-B: allowlist PUT surfaces a rejected fleet publish ──────────────────

func TestSec2EA2_AllowlistPUTSurfacesPublishRejection(t *testing.T) {
	sec2eaSwapThreatFeed(t)
	prevMsg, prevTS := globalConfigStore.LastPublishError()
	t.Cleanup(func() {
		globalConfigStore.mu.Lock()
		globalConfigStore.lastPublishErr = prevMsg
		globalConfigStore.lastPublishTS = prevTS
		globalConfigStore.mu.Unlock()
	})
	setRewriteIdentityDegraded("2ea2: deterministic publish-rejection vehicle")
	t.Cleanup(clearRewriteIdentityDegraded)

	w := httptest.NewRecorder()
	apiDomainAllowlist(w, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{"pub-fact.example"}}))
	if w.Code != 200 {
		t.Fatalf("PUT = %d (the local mutation is valid and must be kept): %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("local-saved fact missing: %v", resp)
	}
	rej, ok := resp["cluster_publish_rejected"].(string)
	if !ok || rej == "" {
		t.Fatalf("the response hides that the fleet publish was REJECTED — local truth and fleet truth collapsed into one healthy 200: %v", resp)
	}
	if !strings.Contains(rej, "rewrite") {
		t.Fatalf("rejection fact must carry the publish error cause, got %q", rej)
	}
	// The valid local mutation is kept (established doctrine — never rolled
	// back merely because fleet publication failed).
	if cur := globalThreatFeed.DomainAllowlist(); len(cur) != 1 || cur[0] != "pub-fact.example" {
		t.Fatalf("local mutation must be kept: %v", cur)
	}
}

// Control: with a healthy publish the rejection fact is ABSENT (never a
// false alarm).
func TestSec2EA2_AllowlistPUTNoRejectionFactOnHealthyPublish(t *testing.T) {
	t.Cleanup(func() { _ = publishCurrentConfigSnapshot() })
	sec2eaSwapThreatFeed(t)
	w := httptest.NewRecorder()
	apiDomainAllowlist(w, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{"healthy.example"}}))
	if w.Code != 200 {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := resp["cluster_publish_rejected"]; present {
		t.Fatalf("healthy publish must not carry a rejection fact: %v", resp)
	}
}

// ─── §4-C: DPI mutations advance the DP-visible published config ────────────

func TestSec2EA2_DPIMutationAdvancesPublishedConfig(t *testing.T) {
	t.Cleanup(func() { _ = publishCurrentConfigSnapshot() }) // re-commit real state after restores
	snapshotDPIScanner(t)
	snapshotConfigVersionsDir(t)

	v0 := globalConfigStore.Version()
	w := httptest.NewRecorder()
	apiContentScan(w, jsonReq("POST", "/api/dpi", map[string]any{"pattern": "sec2ea2-fleet-pattern"}))
	if w.Code != 200 {
		t.Fatalf("POST = %d: %s", w.Code, w.Body.String())
	}
	if v := globalConfigStore.Version(); v <= v0 {
		t.Fatalf("a successful DPI pattern add did not advance the published config (version %d → %d) — DPs keep enforcing the OLD pattern set until an unrelated mutation publishes", v0, v)
	}
	found := false
	for _, p := range globalConfigStore.Get().DPIPatterns {
		if p == "sec2ea2-fleet-pattern" {
			found = true
		}
	}
	if !found {
		t.Fatal("the committed snapshot does not carry the added DPI pattern")
	}

	v1 := globalConfigStore.Version()
	w2 := httptest.NewRecorder()
	apiContentScan(w2, jsonReq("DELETE", "/api/dpi?pattern=sec2ea2-fleet-pattern", nil))
	if w2.Code != 204 {
		t.Fatalf("DELETE = %d: %s", w2.Code, w2.Body.String())
	}
	if v := globalConfigStore.Version(); v <= v1 {
		t.Fatalf("a successful DPI pattern removal did not advance the published config (version %d → %d)", v1, v)
	}
	for _, p := range globalConfigStore.Get().DPIPatterns {
		if p == "sec2ea2-fleet-pattern" {
			t.Fatal("the committed snapshot still carries the removed DPI pattern")
		}
	}
}

// A rejected publish after a DPI add is visible inline (same fact dialect).
func TestSec2EA2_DPIAddSurfacesPublishRejection(t *testing.T) {
	snapshotDPIScanner(t)
	snapshotConfigVersionsDir(t)
	prevMsg, prevTS := globalConfigStore.LastPublishError()
	t.Cleanup(func() {
		globalConfigStore.mu.Lock()
		globalConfigStore.lastPublishErr = prevMsg
		globalConfigStore.lastPublishTS = prevTS
		globalConfigStore.mu.Unlock()
	})
	setRewriteIdentityDegraded("2ea2: deterministic publish-rejection vehicle")
	t.Cleanup(clearRewriteIdentityDegraded)

	w := httptest.NewRecorder()
	apiContentScan(w, jsonReq("POST", "/api/dpi", map[string]any{"pattern": "rejected-fleet-pattern"}))
	if w.Code != 200 {
		t.Fatalf("POST = %d (the local mutation is valid and durable): %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rej, ok := resp["cluster_publish_rejected"].(string)
	if !ok || rej == "" {
		t.Fatalf("DPI add hides that the fleet publish was rejected: %v", resp)
	}
}

// ─── §4-A: managed-DP ownership through the REAL handlers ───────────────────

func TestSec2EA2_ManagedDPRefusesLocalWritesOnSyncedSurfaces(t *testing.T) {
	swapClusterRole(t, "data-plane")
	snapshotDPIScanner(t)
	sec2eaSwapThreatFeed(t)
	if err := globalThreatFeed.SetDomainAllowlist([]string{"keep.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := dpiScanner.Add("keep-pattern"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// DPI pattern add: refused BEFORE mutation.
	w := httptest.NewRecorder()
	apiContentScan(w, jsonReq("POST", "/api/dpi", map[string]any{"pattern": "dp-local-pattern"}))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "control-plane managed") {
		t.Fatalf("managed-DP DPI add = %d %q, want the established 409 refusal", w.Code, w.Body.String())
	}
	for _, p := range dpiScanner.List() {
		if p == "dp-local-pattern" {
			t.Fatal("managed-DP refusal must happen BEFORE mutation")
		}
	}

	// DPI pattern remove: refused before mutation.
	w2 := httptest.NewRecorder()
	apiContentScan(w2, jsonReq("DELETE", "/api/dpi?pattern=keep-pattern", nil))
	if w2.Code != 409 {
		t.Fatalf("managed-DP DPI remove = %d, want 409", w2.Code)
	}
	if got := dpiScanner.List(); len(got) != 1 || got[0] != "keep-pattern" {
		t.Fatalf("managed-DP refusal must not mutate: %v", got)
	}

	// Allowlist PUT: refused before mutation.
	w3 := httptest.NewRecorder()
	apiDomainAllowlist(w3, jsonReq("PUT", "/api/security-scan/feeds/domain-allowlist",
		map[string]any{"domains": []string{"dp-local.example"}}))
	if w3.Code != 409 || !strings.Contains(w3.Body.String(), "control-plane managed") {
		t.Fatalf("managed-DP allowlist PUT = %d %q, want the established 409 refusal", w3.Code, w3.Body.String())
	}
	if cur := globalThreatFeed.DomainAllowlist(); len(cur) != 1 || cur[0] != "keep.example" {
		t.Fatalf("managed-DP refusal must not mutate: %v", cur)
	}

	// GETs carry the established ownership signal.
	w4 := httptest.NewRecorder()
	apiDomainAllowlist(w4, getReq("/api/security-scan/feeds/domain-allowlist"))
	var al map[string]any
	if err := json.Unmarshal(w4.Body.Bytes(), &al); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ed, ok := al["editable"].(bool); !ok || ed {
		t.Fatalf("allowlist GET on a managed DP must report editable=false: %v", al["editable"])
	}
	w5 := httptest.NewRecorder()
	apiContentScan(w5, getReq("/api/dpi"))
	var dpi map[string]any
	if err := json.Unmarshal(w5.Body.Bytes(), &dpi); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ed, ok := dpi["editable"].(bool); !ok || ed {
		t.Fatalf("DPI GET on a managed DP must report editable=false: %v", dpi["editable"])
	}
}

// Control: a standalone (locally authoritative) node stays editable and the
// node-local surfaces (bypass, exclusions, YARA) remain writable on a managed
// DP — they are NOT ClusterSynced (config_surfaces.go) and the CP never
// distributes them, so the local admin surface is their only writer.
func TestSec2EA2_ManagedDPNodeLocalSurfacesStayWritable(t *testing.T) {
	swapClusterRole(t, "data-plane")
	snapshotDPIScanner(t)
	snapshotConfigVersionsDir(t)
	w := httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq("PUT", "/api/dpi/bypass",
		map[string]any{"hosts": []string{"dp-bypass.example"}}))
	if w.Code != 200 {
		t.Fatalf("bypass PUT on a managed DP = %d (node-local surface must stay writable): %s", w.Code, w.Body.String())
	}
}

func TestSec2EA2_StandaloneStaysEditable(t *testing.T) {
	swapClusterRole(t, "standalone")
	snapshotDPIScanner(t)
	w := httptest.NewRecorder()
	apiContentScan(w, getReq("/api/dpi"))
	var dpi map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &dpi); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ed, ok := dpi["editable"].(bool); !ok || !ed {
		t.Fatalf("standalone DPI GET must report editable=true: %v", dpi["editable"])
	}
}
