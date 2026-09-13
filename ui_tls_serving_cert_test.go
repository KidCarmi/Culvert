package main

// ui_tls_serving_cert_test.go — coverage for the admin UI's OWN serving
// certificate expiry (noteAdminUITLSCertExpiry/adminUITLSCertExpiry,
// ui_tls_custom.go), surfaced on GET /api/settings/network.
//
// Before this, Culvert tracked the expiry of two OTHER certificates (the
// MITM inspection root CA, CHAOS-28; the outbound upstream mTLS client
// cert, mtls_ocsp_startup.go) but never the certificate a browser actually
// negotiates against to reach the admin GUI. An operator running a custom
// admin-UI cert (-tls-cert/-tls-key, or uploaded via the Certificates
// panel) had no GUI/API signal of it approaching expiry — only a
// rate-limited log line once it had already failed to load
// (admin_ui_health.go).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resetAdminUITLSCertExpiryForTest isolates adminUITLSCertNotAfter/
// adminUITLSCertKnown for the duration of one test, restoring whatever the
// process-global state was beforehand.
func resetAdminUITLSCertExpiryForTest(t *testing.T) {
	t.Helper()
	adminUITLSCertMu.Lock()
	prevNotAfter := adminUITLSCertNotAfter
	prevKnown := adminUITLSCertKnown
	adminUITLSCertNotAfter = time.Time{}
	adminUITLSCertKnown = false
	adminUITLSCertMu.Unlock()
	t.Cleanup(func() {
		adminUITLSCertMu.Lock()
		adminUITLSCertNotAfter = prevNotAfter
		adminUITLSCertKnown = prevKnown
		adminUITLSCertMu.Unlock()
	})
}

// writeCertKeyPairWithNotAfter writes a self-signed ECDSA cert/key pair with
// an explicit NotAfter, so expiry-reporting tests can assert an exact value
// instead of a loose bound.
func writeCertKeyPairWithNotAfter(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "culvert-admin-ui-expiry-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPath = filepath.Join(dir, "expiry.crt")
	keyPath = filepath.Join(dir, "expiry.key")
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestNoteAdminUITLSCertExpiry_RecordsLeafNotAfter(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)

	if _, known := adminUITLSCertExpiry(); known {
		t.Fatal("expected unknown before any custom cert has bound")
	}

	wantNotAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPath, keyPath := writeCertKeyPairWithNotAfter(t, t.TempDir(), wantNotAfter)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load test pair: %v", err)
	}

	noteAdminUITLSCertExpiry(cert)

	gotNotAfter, known := adminUITLSCertExpiry()
	if !known {
		t.Fatal("expected known=true after noteAdminUITLSCertExpiry")
	}
	if !gotNotAfter.Equal(wantNotAfter) {
		t.Errorf("adminUITLSCertExpiry() NotAfter = %v; want %v", gotNotAfter, wantNotAfter)
	}
}

// apiNetworkSettingsGET drives the real GET handler and decodes its body,
// mirroring the pattern in settings_network_no_versioning_test.go.
func apiNetworkSettingsGET(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/settings/network", nil)
	apiNetworkSettings(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("apiNetworkSettings status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

func TestApiNetworkSettings_OmitsUITLSCertExpiryWhenUnknown(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)

	body := apiNetworkSettingsGET(t)
	if _, ok := body["ui_tls_cert_not_after"]; ok {
		t.Error("ui_tls_cert_not_after must be omitted when no custom admin-UI cert has ever bound")
	}
	if _, ok := body["ui_tls_cert_days_remaining"]; ok {
		t.Error("ui_tls_cert_days_remaining must be omitted when no custom admin-UI cert has ever bound")
	}
}

func TestApiNetworkSettings_ExposesUITLSCertExpiryWhenKnown(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)

	wantNotAfter := time.Now().Add(45 * 24 * time.Hour).Truncate(time.Second)
	certPath, keyPath := writeCertKeyPairWithNotAfter(t, t.TempDir(), wantNotAfter)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load test pair: %v", err)
	}
	noteAdminUITLSCertExpiry(cert)

	body := apiNetworkSettingsGET(t)

	gotNotAfter, ok := body["ui_tls_cert_not_after"].(string)
	if !ok {
		t.Fatalf("ui_tls_cert_not_after missing or not a string: %#v", body["ui_tls_cert_not_after"])
	}
	parsed, err := time.Parse(time.RFC3339, gotNotAfter)
	if err != nil {
		t.Fatalf("ui_tls_cert_not_after %q does not parse as RFC3339: %v", gotNotAfter, err)
	}
	if !parsed.Equal(wantNotAfter.UTC()) {
		t.Errorf("ui_tls_cert_not_after = %v; want %v", parsed, wantNotAfter.UTC())
	}

	daysF, ok := body["ui_tls_cert_days_remaining"].(float64)
	if !ok {
		t.Fatalf("ui_tls_cert_days_remaining missing or not a number: %#v", body["ui_tls_cert_days_remaining"])
	}
	if days := int(daysF); days < 43 || days > 45 {
		t.Errorf("ui_tls_cert_days_remaining = %d; want ~45", days)
	}
}

// TestAdminUIServeOnce_RecordsServingCertExpiry proves the production
// wiring end to end: binding the REAL admin-UI listen path
// (adminUIServeOnce, ui.go) against a custom cert/key pair records that
// pair's expiry, not just the unit-level noteAdminUITLSCertExpiry call.
func TestAdminUIServeOnce_RecordsServingCertExpiry(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)

	certPath, keyPath := writeTestKeyPair(t, t.TempDir()) // NotAfter = now+24h

	port, release := occupyPort(t)
	release()
	addr := fmt.Sprintf(":%d", port)

	srv := newTestAdminServer()
	done := make(chan error, 1)
	go func() { done <- adminUIServeOnce(srv, addr, certPath, keyPath) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	waitForAdminUI(t, 5*time.Second, "the serving cert expiry to be recorded", func() bool {
		_, known := adminUITLSCertExpiry()
		return known
	})

	notAfter, known := adminUITLSCertExpiry()
	if !known {
		t.Fatal("expected admin UI serving cert expiry to be known")
	}
	if remaining := time.Until(notAfter); remaining < 23*time.Hour || remaining > 25*time.Hour {
		t.Fatalf("recorded NotAfter %v is not ~24h out (got %v remaining)", notAfter, remaining)
	}
}
