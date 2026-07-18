package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDiagnoseSupport reports store health from persisted bundle summaries + the
// retention observability atoms: count, aggregate size, age spread, and the
// within-count-cap check. Deterministic clock; no network, no bundle content.
func TestDiagnoseSupport(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	// Two bundles: one 10 days old, one 1 day old. Each carries a small tgz so
	// TotalBytes is exercised (writeFakeBundle writes only the manifest).
	writeFakeBundle(t, "csb_diagoldbundleaaaa234567abc", now.Add(-10*24*time.Hour).Format(time.RFC3339))
	writeFakeBundle(t, "csb_diagnewbundleaaaa234567abc", now.Add(-1*24*time.Hour).Format(time.RFC3339))
	for _, id := range []string{"csb_diagoldbundleaaaa234567abc", "csb_diagnewbundleaaaa234567abc"} {
		if err := os.WriteFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"), []byte("0123456789"), 0o600); err != nil {
			t.Fatalf("write tgz: %v", err)
		}
	}

	d := diagnoseSupport(now)

	if d.BundleCount != 2 {
		t.Errorf("BundleCount = %d, want 2", d.BundleCount)
	}
	if d.TotalBytes != 20 {
		t.Errorf("TotalBytes = %d, want 20 (2 × 10-byte tgz)", d.TotalBytes)
	}
	if d.OldestAgeHours != 240 { // 10 days
		t.Errorf("OldestAgeHours = %d, want 240", d.OldestAgeHours)
	}
	if d.NewestAgeHours != 24 { // 1 day
		t.Errorf("NewestAgeHours = %d, want 24", d.NewestAgeHours)
	}
	if d.RetentionKeep != supportRetentionKeep {
		t.Errorf("RetentionKeep = %d, want %d", d.RetentionKeep, supportRetentionKeep)
	}
	if d.RetentionMaxAgeDays != int(supportRetentionMaxAge/(24*time.Hour)) {
		t.Errorf("RetentionMaxAgeDays = %d, want %d", d.RetentionMaxAgeDays, int(supportRetentionMaxAge/(24*time.Hour)))
	}
	// 2 bundles ≤ keep cap (10) → within_count_cap ok → overall ok.
	if !d.OK {
		t.Errorf("expected OK=true for a healthy store, got false: %+v", d.Checks)
	}
	var found bool
	for _, c := range d.Checks {
		if c.Name == "within_count_cap" {
			found = true
			if !c.OK {
				t.Errorf("within_count_cap should be OK for 2 bundles under a keep=%d cap", supportRetentionKeep)
			}
		}
	}
	if !found {
		t.Error("within_count_cap check missing")
	}
}

// TestDiagnoseSupport_Empty: a store with no bundles is trivially healthy and
// omits the age fields.
func TestDiagnoseSupport_Empty(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	d := diagnoseSupport(time.Unix(1_800_000_000, 0).UTC())
	if d.BundleCount != 0 || d.TotalBytes != 0 {
		t.Errorf("empty store: count=%d bytes=%d, want 0/0", d.BundleCount, d.TotalBytes)
	}
	if d.OldestAgeHours != 0 || d.NewestAgeHours != 0 {
		t.Errorf("empty store must omit age fields, got oldest=%d newest=%d", d.OldestAgeHours, d.NewestAgeHours)
	}
	if !d.OK {
		t.Error("empty store should be OK")
	}
}

// TestDiagnoseSupport_API exercises the operator-gated POST handler end to end,
// mirroring the RBAC + method contract of the sibling diagnose verbs.
func TestDiagnoseSupport_API(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// GET is rejected (POST-only verb).
	getRec := httptest.NewRecorder()
	apiDiagnoseSupport(getRec, roleReq(RoleOperator, "GET", "/api/diagnose/support", nil))
	if getRec.Code != 405 {
		t.Fatalf("GET code=%d want 405", getRec.Code)
	}

	// Viewer is below operator → 403.
	vRec := httptest.NewRecorder()
	apiDiagnoseSupport(vRec, roleReq(RoleViewer, "POST", "/api/diagnose/support", nil))
	if vRec.Code != 403 {
		t.Fatalf("viewer POST code=%d want 403", vRec.Code)
	}

	// Operator POST → 200 with the typed contract.
	rec := httptest.NewRecorder()
	apiDiagnoseSupport(rec, roleReq(RoleOperator, "POST", "/api/diagnose/support", nil))
	if rec.Code != 200 {
		t.Fatalf("operator POST code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"schema_version"`) || !strings.Contains(rec.Body.String(), `"retention_keep"`) {
		t.Fatalf("body missing typed fields: %s", rec.Body.String())
	}
}
