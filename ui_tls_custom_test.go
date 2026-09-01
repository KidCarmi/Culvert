package main

import (
	"bytes"
	"context"
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
	prevCorrupt := uiCustomTLSCorrupt
	dir := t.TempDir()
	dataDir = dir
	uiCustomTLSActive = false
	uiCustomTLSCorrupt = false
	t.Cleanup(func() {
		dataDir = prev
		uiCustomTLSActive = prevActive
		uiCustomTLSCorrupt = prevCorrupt
	})
	return dir
}

func TestCustomUITLSFilesPresent(t *testing.T) {
	withTempDataDirForUITLS(t)
	if customUITLSFilesPresent() {
		t.Fatal("expected no persisted UI cert in a fresh data dir")
	}
	if err := os.WriteFile(customUITLSCertPath(), []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if customUITLSFilesPresent() {
		t.Fatal("expected false with only the cert half present")
	}
	if err := os.WriteFile(customUITLSKeyPath(), []byte("key"), 0o600); err != nil {
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
	if uiCustomTLSCorrupt {
		t.Error("uiCustomTLSCorrupt must stay false for a valid, merely-unselected persisted pair")
	}
}

func TestResolveUITLSCertKey_FallsBackToPersisted(t *testing.T) {
	withTempDataDirForUITLS(t)
	certPEM, keyPEM, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	cert, key := resolveUITLSCertKey("", "")
	if cert != customUITLSCertPath() || key != customUITLSKeyPath() {
		t.Errorf("resolveUITLSCertKey did not fall back to the persisted pair: got (%q, %q)", cert, key)
	}
	if !uiCustomTLSActive {
		t.Error("uiCustomTLSActive should be true once the persisted cert is selected")
	}
	if uiCustomTLSCorrupt {
		t.Error("uiCustomTLSCorrupt must stay false for a valid persisted pair")
	}
}

// TestResolveUITLSCertKey_IgnoresMismatchedPersistedPair is the regression
// test for the fatal-boot-loop finding: persistCustomUITLS writes the cert
// and key as two SEPARATE atomic writes (persistCustomUITLS in
// ui_tls_custom.go). A process killed between those two writes — a container
// OOM-kill, `docker compose restart`, a host crash, or simply losing the race
// with a second upload — leaves a NEW cert paired with the OLD key (or vice
// versa) on disk. customUITLSFilesPresent() only checks that both files
// EXIST, so resolveUITLSCertKey used to hand this mismatched pair straight to
// startUI, whose ListenAndServeTLS failure is fatal (logFatalf -> os.Exit)
// with no fallback to self-signed — unlike every other TLS failure path in
// startUI. A single interrupted re-upload therefore permanently prevented the
// whole proxy process (not just the admin UI) from starting again, with no
// self-heal short of an operator shelling in to delete the two files.
//
// resolveUITLSCertKey must validate the persisted pair the same way
// ListenAndServeTLS will (tls.LoadX509KeyPair) and degrade to no custom cert
// — exactly as if nothing had been uploaded — when it does not parse.
func TestResolveUITLSCertKey_IgnoresMismatchedPersistedPair(t *testing.T) {
	withTempDataDirForUITLS(t)
	certPEM, _, _ := generateSelfSignedECDSA(t)
	_, otherKeyPEM, _ := generateSelfSignedECDSA(t) // a different, unrelated key
	if err := persistCustomUITLS(certPEM, otherKeyPEM); err != nil {
		t.Fatal(err)
	}
	if !customUITLSFilesPresent() {
		t.Fatal("both files should be on disk even though the pair is mismatched")
	}

	cert, key := resolveUITLSCertKey("", "")
	if cert != "" || key != "" {
		t.Fatalf("resolveUITLSCertKey trusted a mismatched cert/key pair instead of falling back: got (%q, %q) — "+
			"this pair would fail ListenAndServeTLS's tls.LoadX509KeyPair and fatally exit the whole process via logFatalf", cert, key)
	}
	if uiCustomTLSActive {
		t.Error("uiCustomTLSActive must stay false when the persisted pair fails to parse")
	}
	// Regression guard for the "restart will fix it" false recovery message:
	// a mismatched pair is corrupt in a way no restart resolves, and the GUI
	// (loadUICertStatus in static/index.html) must be able to tell this apart
	// from the ordinary "uploaded, not yet restarted" state via this flag.
	if !uiCustomTLSCorrupt {
		t.Error("uiCustomTLSCorrupt should be true when the persisted pair is mismatched — this is what tells the GUI restarting will not help")
	}
}

// TestResolveUITLSCertKey_IgnoresCorruptPersistedPair covers plain on-disk
// corruption (not just a mismatched-but-individually-valid pair): neither
// file even parses as PEM.
func TestResolveUITLSCertKey_IgnoresCorruptPersistedPair(t *testing.T) {
	withTempDataDirForUITLS(t)
	if err := persistCustomUITLS([]byte("not a cert"), []byte("not a key")); err != nil {
		t.Fatal(err)
	}
	cert, key := resolveUITLSCertKey("", "")
	if cert != "" || key != "" {
		t.Fatalf("resolveUITLSCertKey trusted a corrupt persisted pair instead of falling back: got (%q, %q)", cert, key)
	}
	if uiCustomTLSActive {
		t.Error("uiCustomTLSActive must stay false when the persisted pair is corrupt")
	}
	if !uiCustomTLSCorrupt {
		t.Error("uiCustomTLSCorrupt should be true when the persisted pair does not parse as PEM")
	}
}

// TestResolveUITLSCertKey_InvalidPairDoesNotPanicBeforeLoggerInit is the
// regression test for a defect Codex review caught in this same PR:
// resolveUITLSCertKey is called from loadFileConfigAndFlags, which main.go
// runs BEFORE initLogger (main.go: loadFileConfigAndFlags(s) precedes
// initLogger(s)), so the package-level `logger` is still nil at the exact
// call site this function runs from. logger.Printf on a nil *log.Logger
// panics (log.Logger.Output locks a mutex embedded in the receiver), which
// would have reintroduced an unrecoverable boot failure — a DIFFERENT crash,
// but the same class this whole fix exists to close — the very first time
// the invalid-pair branch actually fired on a freshly started process.
func TestResolveUITLSCertKey_InvalidPairDoesNotPanicBeforeLoggerInit(t *testing.T) {
	withTempDataDirForUITLS(t)
	prevLogger := logger
	logger = nil // exactly the pre-initLogger state loadFileConfigAndFlags runs under
	t.Cleanup(func() { logger = prevLogger })

	if err := persistCustomUITLS([]byte("not a cert"), []byte("not a key")); err != nil {
		t.Fatal(err)
	}

	cert, key := resolveUITLSCertKey("", "") // must not panic
	if cert != "" || key != "" {
		t.Fatalf("resolveUITLSCertKey trusted a corrupt persisted pair instead of falling back: got (%q, %q)", cert, key)
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
	if !bytes.Equal(gotCert, certPEM) {
		t.Error("persisted cert does not match the uploaded cert")
	}
	if !customUITLSFilesPresent() {
		t.Error("customUITLSFilesPresent should report true after a successful upload")
	}
}

// TestAPINetworkSettings_SurfacesCustomCertCorrupt is the regression test for
// the finding this file's ui_custom_cert_corrupt field exists to close:
// GET /api/settings/network used to report only ui_custom_cert_uploaded and
// ui_custom_cert_active, which look IDENTICAL (uploaded=true, active=false)
// whether the admin simply hasn't restarted yet (self-resolving) or the
// persisted pair is corrupt/mismatched (every future restart still falls
// back to self-signed — restarting will never help). The GUI's
// loadUICertStatus() cannot tell these apart without a third field.
func TestAPINetworkSettings_SurfacesCustomCertCorrupt(t *testing.T) {
	withTempDataDirForUITLS(t)
	certPEM, _, _ := generateSelfSignedECDSA(t)
	_, otherKeyPEM, _ := generateSelfSignedECDSA(t)
	if err := persistCustomUITLS(certPEM, otherKeyPEM); err != nil {
		t.Fatal(err)
	}
	// resolveUITLSCertKey is what actually detects and latches the corruption
	// (it runs once at boot); exercise it exactly as startup does.
	if cert, key := resolveUITLSCertKey("", ""); cert != "" || key != "" {
		t.Fatalf("expected fallback to self-signed for a mismatched pair, got (%q, %q)", cert, key)
	}

	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/settings/network", http.NoBody)
	w := httptest.NewRecorder()
	apiNetworkSettings(w, r)
	assertStatus(t, w, http.StatusOK)

	var resp struct {
		Uploaded bool `json:"ui_custom_cert_uploaded"`
		Active   bool `json:"ui_custom_cert_active"`
		Corrupt  bool `json:"ui_custom_cert_corrupt"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Uploaded {
		t.Error("ui_custom_cert_uploaded should be true — the files are on disk")
	}
	if resp.Active {
		t.Error("ui_custom_cert_active should be false — the mismatched pair was never selected")
	}
	if !resp.Corrupt {
		t.Error("ui_custom_cert_corrupt should be true so the GUI can warn that a restart will not help, instead of telling the admin to restart")
	}
}
