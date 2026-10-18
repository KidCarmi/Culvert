package main

// cluster_token_revoke_audit_test.go — SEC-ENROLLAUDIT-1.
//
// DELETE /api/cluster/tokens destroys cluster trust material: the enrollment
// token a new node needs to join. The POST that MINTS one audits
// (enrollment.token_created), and node revocation audits
// (enrollment.node_revoked), but the DELETE that revokes a token recorded
// nothing — so an admin-session holder could remove enrollment capability and
// leave no trace of who did it or when. The route metadata declared
// "audit delegated" for the method, which was true of POST and had no delegate
// here at all, so C2c's runtime audit-gap check (AuditExpected) never fired
// either.
//
// Assertions are content-based (unique token hash per case), never a length
// delta: the audit ring is bounded and a shuffled full-suite run saturates it.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const auditActionTokenRevoked = "enrollment.token_revoked"

// findAuditByActionObject scans the audit ring for an entry matching both
// action and object. Content-based per the CLAUDE.md audit-ring pitfall.
func findAuditByActionObject(t *testing.T, action, object string) (AuditEntry, bool) {
	t.Helper()
	entries := auditGet()
	for i := range entries { // index-based: AuditEntry is a large struct
		if entries[i].Action == action && entries[i].Object == object {
			return entries[i], true
		}
	}
	return AuditEntry{}, false
}

// deleteClusterToken drives the real handler through the admin context.
func deleteClusterToken(t *testing.T, hash string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/cluster/tokens?hash="+hash, nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiClusterTokens(w, adminCtx(r))
	return w
}

// TestEnrollAudit_TokenRevokeIsAudited is the defect gate: a successful
// revocation must leave an audit record naming the token.
func TestEnrollAudit_TokenRevokeIsAudited(t *testing.T) {
	origStore := globalClusterStore
	t.Cleanup(func() { globalClusterStore = origStore })
	globalClusterStore = newTestClusterStore(t)

	const hash = "sec-enrollaudit-1-revoked-hash"
	globalClusterStore.mu.Lock()
	globalClusterStore.st.Tokens[hash] = &EnrollToken{TokenHash: hash}
	globalClusterStore.mu.Unlock()

	if w := deleteClusterToken(t, hash); w.Code != http.StatusOK {
		t.Fatalf("DELETE returned %d, want 200; body: %s", w.Code, w.Body.String())
	}

	e, ok := findAuditByActionObject(t, auditActionTokenRevoked, hash)
	if !ok {
		t.Fatalf("DEFECT: no %q audit entry for the revoked token %q — "+
			"destroying cluster trust material left no trace", auditActionTokenRevoked, hash)
	}
	if e.Actor == "" {
		t.Error("audit entry has no actor; accountability is the point of the record")
	}
	if e.Detail == "" {
		t.Error("audit entry has no detail")
	}
}

// TestEnrollAudit_FailedRevokeIsNotAudited is the negative control: a
// revocation that changed nothing must not claim one. Without it, a gate that
// audited unconditionally at the top of the branch would still pass.
func TestEnrollAudit_FailedRevokeIsNotAudited(t *testing.T) {
	origStore := globalClusterStore
	t.Cleanup(func() { globalClusterStore = origStore })
	globalClusterStore = newTestClusterStore(t)

	const hash = "sec-enrollaudit-1-absent-hash"
	if w := deleteClusterToken(t, hash); w.Code != http.StatusNotFound {
		t.Fatalf("DELETE of an absent token returned %d, want 404; body: %s", w.Code, w.Body.String())
	}
	if _, ok := findAuditByActionObject(t, auditActionTokenRevoked, hash); ok {
		t.Errorf("audit entry recorded for a token that was never revoked (%q)", hash)
	}
}

// TestEnrollAudit_MissingHashIsNotAudited is the second negative control: a
// 400 must not produce a record either.
func TestEnrollAudit_MissingHashIsNotAudited(t *testing.T) {
	origStore := globalClusterStore
	t.Cleanup(func() { globalClusterStore = origStore })
	globalClusterStore = newTestClusterStore(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/cluster/tokens", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiClusterTokens(w, adminCtx(r))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("DELETE with no hash returned %d, want 400; body: %s", w.Code, w.Body.String())
	}
	if _, ok := findAuditByActionObject(t, auditActionTokenRevoked, ""); ok {
		t.Error("audit entry recorded for a rejected request with no hash")
	}
}

// TestEnrollAudit_RouteMetadataDeclaresTheAudit pins the declaration alongside
// the behaviour: C2c only checks for a missing audit when the method's entry
// says one is expected, so a correct handler with a silent metadata entry
// leaves the runtime gap check switched off.
func TestEnrollAudit_RouteMetadataDeclaresTheAudit(t *testing.T) {
	var found bool
	for i := range uiRoutes {
		if uiRoutes[i].Path != "/api/cluster/tokens" {
			continue
		}
		m, ok := uiRoutes[i].PolicyForMethod(http.MethodDelete)
		if !ok {
			t.Fatal("/api/cluster/tokens declares no DELETE policy")
		}
		found = true
		if !m.AuditExpected {
			t.Error("DELETE entry must declare AuditExpected: true — the handler now audits, " +
				"and C2c's audit-gap check is gated on this flag")
		}
		if m.MinRole != RoleAdmin {
			t.Errorf("DELETE MinRole = %q, want %q", m.MinRole, RoleAdmin)
		}
		if m.Note == "audit delegated" {
			t.Error(`DELETE Note still says "audit delegated"; there is no delegate — this handler audits`)
		}
	}
	if !found {
		t.Fatal("/api/cluster/tokens not present in uiRoutes")
	}
}
