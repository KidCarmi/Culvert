package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/support"
)

// makeReadyBundle creates a bundle and marks it ready (approved) so the export
// gate is satisfied.
func makeReadyBundle(t *testing.T) string {
	t.Helper()
	res, err := createSupportBundle(context.Background(), "standard", support.L1, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	st := readBundleState(res.BundleID)
	st.State = bundleStateReady
	if err := writeBundleState(res.BundleID, st); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return res.BundleID
}

// TestSupportExportEncrypted_RoundTrip proves the exported blob is a PSCA envelope
// that decrypts (with the same passphrase) back to the exact persisted tar.
func TestSupportExportEncrypted_RoundTrip(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)
	orig, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
	if err != nil {
		t.Fatalf("read orig: %v", err)
	}
	const pass = "correct horse battery staple"

	rec := httptest.NewRecorder()
	apiSupportBundleExportEncrypted(rec, exportReq(t, id, RoleOperator, pass))
	if rec.Code != http.StatusOK {
		t.Fatalf("export code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type=%q", ct)
	}
	blob := rec.Body.Bytes()
	if !ca.HasBundleMagic(blob) {
		t.Fatal("exported blob is not a PSCA envelope")
	}
	// The passphrase must NOT survive anywhere in the ciphertext.
	if bytes.Contains(blob, []byte(pass)) {
		t.Fatal("passphrase leaked into the ciphertext")
	}
	dec, err := ca.DecryptBundle(blob, []byte(pass))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, orig) {
		t.Fatal("decrypted bundle does not match the original tar")
	}
	// A wrong passphrase fails to decrypt.
	if _, err := ca.DecryptBundle(blob, []byte("wrong passphrase here")); err == nil {
		t.Fatal("decrypt succeeded with the wrong passphrase")
	}
}

// TestSupportExportEncrypted_Gates covers RBAC, method, weak passphrase, pending
// bundle, and unknown id.
func TestSupportExportEncrypted_Gates(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)

	// GET → 405.
	gRec := httptest.NewRecorder()
	gr := exportReq(t, id, RoleOperator, "correct horse battery staple")
	gr.Method = http.MethodGet
	apiSupportBundleExportEncrypted(gRec, gr)
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}

	// Viewer < operator → 403.
	vRec := httptest.NewRecorder()
	apiSupportBundleExportEncrypted(vRec, exportReq(t, id, RoleViewer, "correct horse battery staple"))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}

	// Weak passphrase → 400.
	wRec := httptest.NewRecorder()
	apiSupportBundleExportEncrypted(wRec, exportReq(t, id, RoleOperator, "short"))
	if wRec.Code != http.StatusBadRequest {
		t.Fatalf("weak passphrase code=%d want 400", wRec.Code)
	}

	// Pending bundle → 409.
	res, _ := createSupportBundle(context.Background(), "standard", support.L1, "")
	pRec := httptest.NewRecorder()
	apiSupportBundleExportEncrypted(pRec, exportReq(t, res.BundleID, RoleOperator, "correct horse battery staple"))
	if pRec.Code != http.StatusConflict {
		t.Fatalf("pending bundle code=%d want 409", pRec.Code)
	}

	// Unknown-but-well-formed id → ready-gate says pending (no state) is not ready
	// → 409; a malformed id → 400.
	mRec := httptest.NewRecorder()
	mr := exportReq(t, id, RoleOperator, "correct horse battery staple")
	mr.SetPathValue("id", "../etc")
	apiSupportBundleExportEncrypted(mRec, mr)
	if mRec.Code != http.StatusBadRequest {
		t.Fatalf("malformed id code=%d want 400", mRec.Code)
	}
}

// exportReq builds a POST request with the id path value, role context, and a JSON
// passphrase body.
func exportReq(t *testing.T, id string, role UIRole, pass string) *http.Request {
	t.Helper()
	r := roleReq(role, http.MethodPost, "/api/support/bundles/"+id+"/download-encrypted", map[string]any{"passphrase": pass})
	r.SetPathValue("id", id)
	return r
}
