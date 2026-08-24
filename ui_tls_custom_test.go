package main

import (
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempDataDirForUITLS(t *testing.T) string {
	t.Helper()
	prev := dataDir
	prevActive := uiCustomTLSActive
	dir := t.TempDir()
	dataDir = dir
	uiCustomTLSActive = false
	t.Cleanup(func() {
		dataDir = prev
		uiCustomTLSActive = prevActive
	})
	return dir
}

func TestCustomUITLSFilesPresent(t *testing.T) {
	withTempDataDirForUITLS(t)
	if customUITLSFilesPresent() {
		t.Fatal("expected no persisted UI cert in a fresh data dir")
	}
	if err := os.WriteFile(customUITLSCertPath(), []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if customUITLSFilesPresent() {
		t.Fatal("expected false with only the cert half present")
	}
	if err := os.WriteFile(customUITLSKeyPath(), []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if !customUITLSFilesPresent() {
		t.Fatal("expected true once both cert and key are on disk")
	}
}

func TestResolveUITLSCertKey_ExplicitWinsOverPersisted(t *testing.T) {
	withTempDataDirForUITLS(t)
	if err := persistCustomUITLS([]byte("cert"), []byte("key")); err != nil {
		t.Fatal(err)
	}
	cert, key := resolveUITLSCertKey("/flag/cert.pem", "/flag/key.pem")
	if cert != "/flag/cert.pem" || key != "/flag/key.pem" {
		t.Errorf("resolveUITLSCertKey ignored explicit flags: got (%q, %q)", cert, key)
	}
	if uiCustomTLSActive {
		t.Error("uiCustomTLSActive must stay false when the explicit flag is used")
	}
}

func TestResolveUITLSCertKey_FallsBackToPersisted(t *testing.T) {
	withTempDataDirForUITLS(t)
	if err := persistCustomUITLS([]byte("cert-bytes"), []byte("key-bytes")); err != nil {
		t.Fatal(err)
	}
	cert, key := resolveUITLSCertKey("", "")
	if cert != customUITLSCertPath() || key != customUITLSKeyPath() {
		t.Errorf("resolveUITLSCertKey did not fall back to the persisted pair: got (%q, %q)", cert, key)
	}
	if !uiCustomTLSActive {
		t.Error("uiCustomTLSActive should be true once the persisted cert is selected")
	}
}

func TestResolveUITLSCertKey_NothingPersisted(t *testing.T) {
	withTempDataDirForUITLS(t)
	cert, key := resolveUITLSCertKey("", "")
	if cert != "" || key != "" {
		t.Errorf("expected empty cert/key with nothing configured or persisted, got (%q, %q)", cert, key)
	}
	if uiCustomTLSActive {
		t.Error("uiCustomTLSActive must stay false with no persisted cert")
	}
}

// TestAPICertsUpload_UI_Persists is the regression test for the finding this
// file exists to fix: uploading a UI cert used to validate-and-discard while
// telling the admin "restart required to activate" — a false recovery
// instruction, since nothing was ever written to disk. It must now persist,
// report persisted:true, and leave a pair a later restart can actually load.
func TestAPICertsUpload_UI_Persists(t *testing.T) {
	withTempDataDirForUITLS(t)
	certPEM, keyPEM, _ := generateSelfSignedECDSA(t)

	var body strings.Builder
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("target", "ui")
	_ = mw.WriteField("cert", string(certPEM))
	_ = mw.WriteField("key", string(keyPEM))
	_ = mw.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/certs/upload", strings.NewReader(body.String()))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiCertsUpload(w, r)
	assertStatus(t, w, http.StatusOK)

	var resp struct {
		Persisted bool   `json:"persisted"`
		Note      string `json:"note"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Persisted {
		t.Fatalf("expected persisted:true, got response %s", w.Body.String())
	}
	if resp.Note == "" {
		t.Error("expected a non-empty activation note")
	}

	gotCert, err := os.ReadFile(filepath.Join(dataDir, customUITLSCertFile))
	if err != nil {
		t.Fatalf("cert not persisted: %v", err)
	}
	if string(gotCert) != string(certPEM) {
		t.Error("persisted cert does not match the uploaded cert")
	}
	if !customUITLSFilesPresent() {
		t.Error("customUITLSFilesPresent should report true after a successful upload")
	}
}
