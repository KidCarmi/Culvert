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

// TestDiagnoseSupport_StaleBundleFailsAgeCap proves a store that sits UNDER the
// count cap but holds a bundle older than max-age (a stopped/failing janitor) is
// flagged not-ok via within_age_cap — the count cap alone can't catch it.
func TestDiagnoseSupport_StaleBundleFailsAgeCap(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	now := time.Unix(1_800_000_000, 0).UTC()
	// One bundle, 60 days old — well under the count cap (10) but past max-age (30d).
	writeFakeBundle(t, "csb_stalediagbundleaaa234567ab", now.Add(-60*24*time.Hour).Format(time.RFC3339))

	d := diagnoseSupport(now)
	if d.OK {
		t.Error("a bundle older than max-age must make the diagnosis not-ok")
	}
	var found bool
	for _, c := range d.Checks {
		if c.Name == "within_age_cap" {
			found = true
			if c.OK {
				t.Error("within_age_cap should fail for a 60d-old bundle under a 30d max-age")
			}
		}
	}
	if !found {
		t.Error("within_age_cap check missing")
	}
}

// TestDiagnoseSupport_CorruptManifestFailsReadable proves that a bundle directory
// present on disk but with an unreadable/corrupt manifest (which listSupportBundles
// silently skips) is caught by bundles_dir_readable — the store is not "healthy
// empty".
func TestDiagnoseSupport_CorruptManifestFailsReadable(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// A csb_-shaped dir with a corrupt manifest → listSupportBundles skips it, but
	// countBundleDirs still sees it → shortfall → not-ok.
	dir := filepath.Join(supportBundlesDir(), "csb_corruptmanifestbundle23456")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt manifest: %v", err)
	}

	d := diagnoseSupport(time.Unix(1_800_000_000, 0).UTC())
	if d.BundleCount != 0 {
		t.Errorf("BundleCount = %d, want 0 (corrupt manifest not parsed)", d.BundleCount)
	}
	if d.OK {
		t.Error("a corrupt bundle dir must make the diagnosis not-ok, not a healthy empty store")
	}
	var found bool
	for _, c := range d.Checks {
		if c.Name == "bundles_dir_readable" {
			found = true
			if c.OK {
				t.Error("bundles_dir_readable should fail when a bundle dir is present but not parsed")
			}
		}
	}
	if !found {
		t.Error("bundles_dir_readable check missing")
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
