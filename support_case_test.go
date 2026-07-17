package main

import (
	"context"
	"encoding/json"
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
	ar := httptest.NewRequest(http.MethodPost, "/api/support/bundles/"+res.BundleID+"/approve", http.NoBody)
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

// TestSupportBundles_CaseFilter proves GET ?case= narrows history to one case and
// 400s a malformed filter.
func TestSupportBundles_CaseFilter(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	if _, err := createSupportBundle(context.Background(), "standard", support.L1, "CASE-A"); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if _, err := createSupportBundle(context.Background(), "standard", support.L1, "CASE-B"); err != nil {
		t.Fatalf("create B: %v", err)
	}
	if _, err := createSupportBundle(context.Background(), "standard", support.L1, ""); err != nil {
		t.Fatalf("create none: %v", err)
	}

	get := func(q string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/support/bundles"+q, http.NoBody)
		rec := httptest.NewRecorder()
		apiSupportBundles(rec, withRoleCtx(r, RoleViewer))
		return rec
	}

	// No filter → all three.
	var all []supportBundleSummary
	if err := json.Unmarshal(get("").Body.Bytes(), &all); err != nil || len(all) != 3 {
		t.Fatalf("unfiltered len=%d want 3 (err=%v)", len(all), err)
	}
	// ?case=CASE-A → exactly one, the CASE-A bundle.
	var a []supportBundleSummary
	if err := json.Unmarshal(get("?case=CASE-A").Body.Bytes(), &a); err != nil {
		t.Fatalf("filter A: %v", err)
	}
	if len(a) != 1 || a[0].CaseID != "CASE-A" {
		t.Fatalf("filter CASE-A returned %+v", a)
	}
	// ?case=CASE-Z → none.
	var z []supportBundleSummary
	_ = json.Unmarshal(get("?case=CASE-Z").Body.Bytes(), &z)
	if len(z) != 0 {
		t.Fatalf("filter CASE-Z len=%d want 0", len(z))
	}
	// Malformed filter → 400.
	if rec := get("?case=bad%20id"); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed filter code=%d want 400", rec.Code)
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
		r := httptest.NewRequest(http.MethodPost, "/api/support/bundles?"+q, http.NoBody)
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
