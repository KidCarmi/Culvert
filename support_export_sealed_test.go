package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sealbox"
	"github.com/KidCarmi/Culvert/internal/support"
)

func sealedReq(t *testing.T, id string, role UIRole, pubB64 string) *http.Request {
	t.Helper()
	r := roleReq(role, http.MethodPost, "/api/support/bundles/"+id+"/download-sealed",
		map[string]any{"recipient_public_key": pubB64})
	r.SetPathValue("id", id)
	return r
}

// TestSupportExportSealed_RoundTrip proves the exported blob is a sealbox envelope
// that only the recipient's PRIVATE key can open, back to the exact persisted tar.
func TestSupportExportSealed_RoundTrip(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)
	orig, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
	if err != nil {
		t.Fatalf("read orig: %v", err)
	}
	pub, priv, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])

	rec := httptest.NewRecorder()
	apiSupportBundleExportSealed(rec, sealedReq(t, id, RoleOperator, pubB64))
	if rec.Code != http.StatusOK {
		t.Fatalf("sealed export code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	blob := rec.Body.Bytes()
	if !sealbox.IsSealed(blob) {
		t.Fatal("exported blob is not a sealbox envelope")
	}
	if bytes.Contains(blob, orig[:min(64, len(orig))]) {
		t.Fatal("plaintext bundle bytes present in the sealed blob")
	}
	got, err := sealbox.Open(blob, pub, priv)
	if err != nil {
		t.Fatalf("recipient open: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("opened bundle does not match the original tar")
	}
	// A different key pair cannot open it.
	otherPub, otherPriv, _ := sealbox.GenerateKey()
	if _, err := sealbox.Open(blob, otherPub, otherPriv); err == nil {
		t.Fatal("a foreign key pair opened the sealed bundle")
	}
}

// TestSupportExportSealed_Gates covers RBAC, method, bad key, and pending bundle.
func TestSupportExportSealed_Gates(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)
	pub, _, _ := sealbox.GenerateKey()
	goodKey := base64.StdEncoding.EncodeToString(pub[:])

	// GET → 405.
	gRec := httptest.NewRecorder()
	gr := sealedReq(t, id, RoleOperator, goodKey)
	gr.Method = http.MethodGet
	apiSupportBundleExportSealed(gRec, gr)
	if gRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d want 405", gRec.Code)
	}
	// Viewer < operator → 403.
	vRec := httptest.NewRecorder()
	apiSupportBundleExportSealed(vRec, sealedReq(t, id, RoleViewer, goodKey))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d want 403", vRec.Code)
	}
	// Malformed keys → 400 (not base64, wrong length).
	for _, bad := range []string{"", "!!!notbase64!!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		bRec := httptest.NewRecorder()
		apiSupportBundleExportSealed(bRec, sealedReq(t, id, RoleOperator, bad))
		if bRec.Code != http.StatusBadRequest {
			t.Fatalf("bad key %q code=%d want 400", bad, bRec.Code)
		}
	}
	// Pending bundle → 409.
	res, _ := createSupportBundle(context.Background(), "standard", support.L1, "")
	pRec := httptest.NewRecorder()
	apiSupportBundleExportSealed(pRec, sealedReq(t, res.BundleID, RoleOperator, goodKey))
	if pRec.Code != http.StatusConflict {
		t.Fatalf("pending bundle code=%d want 409", pRec.Code)
	}
}
