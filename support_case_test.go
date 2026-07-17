package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/support"
)

// TestValidSupportCaseID pins the case-id grammar: bounded LDH+dot/underscore,
// no path/whitespace/control chars, empty rejected.
func TestValidSupportCaseID(t *testing.T) {
	good := []string{"CASE-123", "sn_00001", "ticket.42", "A", strings.Repeat("a", 64)}
	bad := []string{"", "has space", "a/b", "../etc", "x\ny", strings.Repeat("a", 65), "tab\t", "semi;colon"}
	for _, s := range good {
		if !validSupportCaseID(s) {
			t.Errorf("case id %q should be valid", s)
		}
	}
	for _, s := range bad {
		if validSupportCaseID(s) {
			t.Errorf("case id %q should be rejected", s)
		}
	}
}

// TestSupportBundle_CaseIDBinds proves a case id supplied at creation is persisted
// in the state sidecar and surfaced in the list/history, and survives approval.
func TestSupportBundle_CaseIDBinds(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	res, err := createSupportBundle(context.Background(), "standard", support.L1, "CASE-777")
	if err != nil {
		t.Fatalf("createSupportBundle: %v", err)
	}
	// Persisted in the state sidecar.
	if got := readBundleState(res.BundleID).CaseID; got != "CASE-777" {
		t.Fatalf("state case_id=%q want CASE-777", got)
	}
	// Surfaced in the list view.
	var found bool
	for _, s := range listSupportBundles() {
		if s.BundleID == res.BundleID {
			found = true
			if s.CaseID != "CASE-777" {
				t.Fatalf("list case_id=%q want CASE-777", s.CaseID)
			}
		}
	}
	if !found {
		t.Fatal("bundle not in list")
	}
	// Survives approval (state rewrite preserves the binding).
	ar := httptest.NewRequest(http.MethodPost, "/api/support/bundles/"+res.BundleID+"/approve", nil)
	ar.SetPathValue("id", res.BundleID)
	arRec := httptest.NewRecorder()
	apiSupportBundleApprove(arRec, withRoleCtx(ar, RoleAdmin))
	if arRec.Code != http.StatusNoContent {
		t.Fatalf("approve code=%d want 204 (body=%q)", arRec.Code, arRec.Body.String())
	}
	st := readBundleState(res.BundleID)
	if st.State != bundleStateReady || st.CaseID != "CASE-777" {
		t.Fatalf("post-approve state=%q case_id=%q want ready/CASE-777", st.State, st.CaseID)
	}
}

// TestSupportBundle_InvalidCaseIDRejected proves the POST handler 400s a malformed
// case id before building anything.
func TestSupportBundle_InvalidCaseIDRejected(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// Malformed values must 400 BEFORE any build — including whitespace-padded and
	// whitespace-only (Codex #781: the raw value is validated, never trimmed).
	for _, q := range []string{"case=bad%20id", "case=%20CASE-7%20", "case=%20", "case=a%2Fb"} {
		r := httptest.NewRequest(http.MethodPost, "/api/support/bundles?"+q, nil)
		rec := httptest.NewRecorder()
		apiSupportBundles(rec, withRoleCtx(r, RoleAdmin))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("query %q code=%d want 400 (body=%q)", q, rec.Code, rec.Body.String())
		}
	}
	// No bundle was persisted by any of the rejected requests.
	if n := len(listSupportBundles()); n != 0 {
		t.Fatalf("a bundle was created despite the invalid case id (%d listed)", n)
	}
}
