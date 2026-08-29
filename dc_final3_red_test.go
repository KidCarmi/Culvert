package main

// dc_final3_red_test.go — 2D-C FINAL management-surface closure: red-before
// proofs against 502ec91f, written to compile at both trees.
//
//	§1 — the LEGACY GET /api/rewrite still returned a healthy 200 list
//	     carrying the KNOWN-ephemeral StableIDs while the rewrite
//	     management-identity degradation was latched (the v2 state surface
//	     correctly answered the structured 503) — the durable-or-degraded
//	     invariant escaped through the legacy read.
//	§2 — apiRewrite POST/DELETE checked the degradation BEFORE
//	     requireRole(RoleOperator), disclosing the degradation marker/reason
//	     to authenticated non-Operators from a mutation surface.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func dcFin3RoleReq(method, target string, role UIRole, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, http.NoBody)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.RemoteAddr = "127.0.0.1:9999"
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

// dcFin3DegradedBoot stages the YAML-seed ledger persistence-failure shape
// (settings path inside a nonexistent directory: clean not-exist read, every
// AtomicWrite fails) and boots. Returns the live rule's ephemeral StableID.
func dcFin3DegradedBoot(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	broken := filepath.Join(dir, "no-such-dir", "admin_settings.json")
	prevAction := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })
	restoreRewriter := rewriter.Snapshot()
	t.Cleanup(restoreRewriter)
	// The latch is otherwise cleared only by the next LoadAdminSettings, so
	// without this it would leak into later tests — and now that the latch
	// gates export/version-capture/omnibus-save/CP-publish process-wide, a
	// leaked latch silently changes unrelated suites' behavior.
	t.Cleanup(clearRewriteIdentityDegraded)
	swapAdminSettingsPath(t, broken)

	rewriter.SetRules(nil)
	loadRewriteAndDefaultAction(rewriteDefaultActionStartupConfig{
		Rules:         []RewriteRule{{Host: "f3.example", ReqSet: map[string]string{"X-F3": "1"}}},
		DefaultAction: "allow",
	}, 0)
	LoadAdminSettings(broken)

	got := rewriter.List()
	if len(got) != 1 || got[0].StableID == "" {
		t.Fatalf("data-plane rewrite must keep operating, got %+v", got)
	}
	return got[0].StableID
}

// TestDCFin3_LegacyGETRefusesEphemeralIdentityWhileDegraded (§1/§3-A): while
// the management-identity degradation is latched, EVERY management read that
// would expose StableIDs must answer the SAME structured 503 — the legacy
// GET /api/rewrite included. No healthy 200 management list may exist.
func TestDCFin3_LegacyGETRefusesEphemeralIdentityWhileDegraded(t *testing.T) {
	sid := dcFin3DegradedBoot(t)

	// v2 state surface: already degraded (accepted behavior).
	w := httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), sid) {
		t.Fatalf("state = %d body=%s, want structured 503 without the ephemeral id", w.Code, w.Body.String())
	}

	// LEGACY read surface: the escape under test.
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("GET", "/api/rewrite", nil))
	if w.Code != 503 {
		t.Fatalf("legacy GET /api/rewrite while degraded = %d body=%s — a healthy 200 list exposes the KNOWN-ephemeral StableIDs the v2 surface refuses (want the same structured 503)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"rewrite-identity"`) {
		t.Fatalf("legacy GET degradation must use the ONE structured dialect, got %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), sid) {
		t.Fatalf("legacy GET leaked the ephemeral StableID: %s", w.Body.String())
	}
}

// TestDCFin3_DegradedMutationAuthorizationPrecedesDisclosure (§2/§3-B/C/D):
// the mutation surface's RBAC boundary is evaluated BEFORE the degradation is
// disclosed — a non-Operator receives the canonical authorization denial with
// no degradation marker or reason; an authorized Operator receives the
// structured 503. No mutation lands in either case.
func TestDCFin3_DegradedMutationAuthorizationPrecedesDisclosure(t *testing.T) {
	sid := dcFin3DegradedBoot(t)
	before := rewriter.List()

	postBody := `{"host":"authz.example","req_remove":["X-Z"]}`

	// B — Viewer POST: canonical denial, zero degradation disclosure.
	w := httptest.NewRecorder()
	apiRewrite(w, dcFin3RoleReq("POST", "/api/rewrite", RoleViewer, postBody))
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST while degraded = %d body=%s, want the canonical 403 authorization denial (RBAC precedes disclosure)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "rewrite-identity") ||
		strings.Contains(w.Body.String(), "could not persist") {
		t.Fatalf("viewer denial leaked the degradation marker/reason: %s", w.Body.String())
	}

	// C — Viewer DELETE: same contract.
	w = httptest.NewRecorder()
	apiRewrite(w, dcFin3RoleReq("DELETE", "/api/rewrite?stableId="+sid, RoleViewer, ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer DELETE while degraded = %d, want 403", w.Code)
	}
	if strings.Contains(w.Body.String(), "rewrite-identity") ||
		strings.Contains(w.Body.String(), "could not persist") {
		t.Fatalf("viewer DELETE denial leaked the degradation marker/reason: %s", w.Body.String())
	}

	// D — Operator POST/DELETE: the structured 503, marker + reason, refused.
	w = httptest.NewRecorder()
	apiRewrite(w, dcFin3RoleReq("POST", "/api/rewrite", RoleOperator, postBody))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"rewrite-identity"`) ||
		!strings.Contains(w.Body.String(), "reason") {
		t.Fatalf("operator POST while degraded = %d body=%s, want the structured 503 with marker + reason", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiRewrite(w, dcFin3RoleReq("DELETE", "/api/rewrite?stableId="+sid, RoleOperator, ""))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"rewrite-identity"`) {
		t.Fatalf("operator DELETE while degraded = %d body=%s, want the structured 503", w.Code, w.Body.String())
	}

	// F — no mutation landed anywhere; the data-plane rule set is unchanged.
	after := rewriter.List()
	if len(after) != len(before) || after[0].StableID != before[0].StableID {
		t.Fatalf("a refused mutation changed the rule set: %+v -> %+v", before, after)
	}
	if after[0].Host != "f3.example" || after[0].ReqSet["X-F3"] != "1" {
		t.Fatal("data-plane enforcement content must remain unchanged while management is degraded")
	}
}

// TestDCFin3_RecoveryRestoresHealthyLegacyContract (§3-E): once persistence
// recovers, BOTH read surfaces return their normal healthy contracts and the
// StableID is the SAME durable identity across another restart.
func TestDCFin3_RecoveryRestoresHealthyLegacyContract(t *testing.T) {
	settingsPath := dcFinYAMLBootEnv(t)
	yaml := []RewriteRule{{Host: "f3ok.example", ReqSet: map[string]string{"X-OK": "1"}}}

	b1 := dcFinBoot(t, settingsPath, yaml)
	if len(b1) != 1 || b1[0].StableID == "" {
		t.Fatalf("healthy boot: %+v", b1)
	}
	w := httptest.NewRecorder()
	apiRewriteState(w, jsonReq("GET", "/api/rewrite/state", nil))
	if w.Code != 200 {
		t.Fatalf("healthy state = %d", w.Code)
	}
	w = httptest.NewRecorder()
	apiRewrite(w, jsonReq("GET", "/api/rewrite", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), b1[0].StableID) {
		t.Fatalf("healthy legacy GET must keep its normal contract (200 incl. stableId), got %d %s", w.Code, w.Body.String())
	}

	b2 := dcFinBoot(t, settingsPath, yaml)
	if b2[0].StableID != b1[0].StableID {
		t.Fatalf("identity must be restart-stable: %s vs %s", b1[0].StableID, b2[0].StableID)
	}
}
