package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/support"
)

// TestApiSupportBundleManifest builds a real bundle and confirms the manifest view
// returns its metadata (sections + integrity) without downloading, plus the
// method/RBAC/id gates.
func TestApiSupportBundleManifest(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)

	// POST → 405.
	pRec := httptest.NewRecorder()
	pr := roleReq(RoleViewer, http.MethodPost, "/api/support/bundles/"+id+"/manifest", nil)
	pr.SetPathValue("id", id)
	apiSupportBundleManifest(pRec, pr)
	if pRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d want 405", pRec.Code)
	}
	// Bad id → 400.
	bRec := httptest.NewRecorder()
	br := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/bad/manifest", nil)
	br.SetPathValue("id", "bad")
	apiSupportBundleManifest(bRec, br)
	if bRec.Code != http.StatusBadRequest {
		t.Fatalf("bad id code=%d want 400", bRec.Code)
	}
	// Unknown (well-formed) id → 404.
	nRec := httptest.NewRecorder()
	missing := "csb_missingmanifest2345672abcd" // csb_ + 26 chars [a-z2-7]
	nr := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/"+missing+"/manifest", nil)
	nr.SetPathValue("id", missing)
	apiSupportBundleManifest(nRec, nr)
	if nRec.Code != http.StatusNotFound {
		t.Fatalf("missing id code=%d want 404", nRec.Code)
	}
	// Viewer GET → 200 with a populated manifest.
	gRec := httptest.NewRecorder()
	gr := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/"+id+"/manifest", nil)
	gr.SetPathValue("id", id)
	apiSupportBundleManifest(gRec, gr)
	if gRec.Code != http.StatusOK {
		t.Fatalf("viewer GET code=%d want 200 (body=%q)", gRec.Code, gRec.Body.String())
	}
	var man support.SupportBundleManifest
	if err := json.Unmarshal(gRec.Body.Bytes(), &man); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if man.BundleID != id {
		t.Fatalf("manifest bundle_id=%q want %q", man.BundleID, id)
	}
	if man.Format != support.BundleFormat {
		t.Fatalf("manifest format=%q want %q", man.Format, support.BundleFormat)
	}
	if len(man.Sections) == 0 {
		t.Fatal("manifest has no sections")
	}
	if man.Integrity.ManifestSHA256 == "" {
		t.Fatal("manifest missing integrity anchor")
	}
}
