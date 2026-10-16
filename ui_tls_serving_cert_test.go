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

// TestApiNetworkSettings_UITLSCertDaysRemainingGoesNegativeImmediately pins
// the Codex-review fix (PR #1381): a certificate that expired minutes ago
// must report a NEGATIVE ui_tls_cert_days_remaining, not 0. The shared
// daysUntil helper (cdr_ui.go) truncates toward zero, so int(-0.04) == 0 —
// a cert expired an hour ago would read identically to one expiring today,
// and the Certificates panel (which switches to its EXPIRED banner on
// days < 0) would keep saying "expires" for up to 24h after it already
// didn't.
func TestApiNetworkSettings_UITLSCertDaysRemainingGoesNegativeImmediately(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)

	// Expired one hour ago: daysUntil would truncate this to 0.
	wantNotAfter := time.Now().Add(-1 * time.Hour)
	certPath, keyPath := writeCertKeyPairWithNotAfter(t, t.TempDir(), wantNotAfter)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load test pair: %v", err)
	}
	noteAdminUITLSCertExpiry(cert)

	body := apiNetworkSettingsGET(t)
	daysF, ok := body["ui_tls_cert_days_remaining"].(float64)
	if !ok {
		t.Fatalf("ui_tls_cert_days_remaining missing or not a number: %#v", body["ui_tls_cert_days_remaining"])
	}
	if days := int(daysF); days >= 0 {
		t.Errorf("ui_tls_cert_days_remaining = %d; want negative for a certificate that already expired", days)
	}
}

func TestDaysRemainingFloor_NegativeImmediatelyAfterExpiry(t *testing.T) {
	if got := daysRemainingFloor(time.Now().Add(-time.Minute)); got >= 0 {
		t.Errorf("daysRemainingFloor(1 minute past expiry) = %d; want negative", got)
	}
	if got := daysRemainingFloor(time.Now().Add(-25 * time.Hour)); got >= -1 {
		t.Errorf("daysRemainingFloor(25 hours past expiry) = %d; want <= -2", got)
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

// TestAdminUIServeOnce_ServesTheRecordedCertificate pins that the certificate
// whose expiry is reported is the one actually served. The pair on disk is
// rotated in the window between the pre-bind load and ServeTLS; a ServeTLS
// that re-read the files would serve the rotated pair while the expiry surface
// kept reporting the original one for the listener's lifetime.
func TestAdminUIServeOnce_ServesTheRecordedCertificate(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)

	origNotAfter := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	rotNotAfter := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	certPath, keyPath := writeCertKeyPairWithNotAfter(t, t.TempDir(), origNotAfter)
	rotCert, rotKey := writeCertKeyPairWithNotAfter(t, t.TempDir(), rotNotAfter)

	prevHook := adminUIBeforeServeTLS
	t.Cleanup(func() { adminUIBeforeServeTLS = prevHook })
	adminUIBeforeServeTLS = func() {
		for _, p := range [][2]string{{rotCert, certPath}, {rotKey, keyPath}} {
			b, err := os.ReadFile(p[0])
			if err != nil {
				t.Errorf("read rotated pair: %v", err)
				return
			}
			if err := os.WriteFile(p[1], b, 0o600); err != nil {
				t.Errorf("rotate pair: %v", err)
				return
			}
		}
	}

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

	var served *x509.Certificate
	waitForAdminUI(t, 5*time.Second, "the admin UI to serve TLS", func() bool {
		d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- test inspects the served leaf, no trust decision
		conn, err := d.DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		defer conn.Close() //nolint:errcheck // test teardown
		served = conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		return true
	})

	recorded, known := adminUITLSCertExpiry()
	if !known {
		t.Fatal("expected admin UI serving cert expiry to be known")
	}
	if !served.NotAfter.Equal(recorded) {
		t.Fatalf("served certificate NotAfter %v != recorded %v — the expiry surface describes a certificate that is not being served",
			served.NotAfter, recorded)
	}
	if !recorded.Equal(origNotAfter) {
		t.Fatalf("recorded NotAfter %v, want the pre-bind pair's %v", recorded, origNotAfter)
	}
}

// TestAdminUIServeOnce_CustomCertStillNegotiatesHTTP2 pins that serving the
// pre-loaded pair through ServeTLS(ln, "", "") keeps ALPN h2 on the admin UI.
func TestAdminUIServeOnce_CustomCertStillNegotiatesHTTP2(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)
	certPath, keyPath := writeTestKeyPair(t, t.TempDir())

	port, release := occupyPort(t)
	release()
	srv := newTestAdminServer()
	done := make(chan error, 1)
	go func() { done <- adminUIServeOnce(srv, fmt.Sprintf(":%d", port), certPath, keyPath) }()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	var proto string
	waitForAdminUI(t, 5*time.Second, "the admin UI to serve TLS", func() bool {
		d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}} // #nosec G402 -- test inspects ALPN only
		conn, err := d.DialContext(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		defer conn.Close() //nolint:errcheck // test teardown
		proto = conn.(*tls.Conn).ConnectionState().NegotiatedProtocol
		return true
	})
	if proto != "h2" {
		t.Fatalf("admin UI negotiated ALPN %q, want h2", proto)
	}
}

// TestAdminUIServeOnce_FailedBindDoesNotRecordExpiry pins that a custom pair
// whose attempt could not bind the admin port is never reported as the
// serving certificate, and never overwrites the last served pair's expiry.
func TestAdminUIServeOnce_FailedBindDoesNotRecordExpiry(t *testing.T) {
	resetAdminUITLSCertExpiryForTest(t)
	certPath, keyPath := writeTestKeyPair(t, t.TempDir())

	port, release := occupyPort(t)
	t.Cleanup(release)

	err := adminUIServeOnce(newTestAdminServer(), fmt.Sprintf(":%d", port), certPath, keyPath)
	if err == nil {
		t.Fatal("expected a bind failure against an occupied port")
	}
	if notAfter, known := adminUITLSCertExpiry(); known || !notAfter.IsZero() {
		t.Fatalf("a pair that never bound was recorded as serving (notAfter=%v known=%v)", notAfter, known)
	}

	// A previously served pair's expiry survives a failed attempt with a
	// different (rotated) pair.
	served := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	adminUITLSCertMu.Lock()
	adminUITLSCertNotAfter, adminUITLSCertKnown = served, true
	adminUITLSCertMu.Unlock()
	if err := adminUIServeOnce(newTestAdminServer(), fmt.Sprintf(":%d", port), certPath, keyPath); err == nil {
		t.Fatal("expected a bind failure against an occupied port")
	}
	if notAfter, known := adminUITLSCertExpiry(); !known || !notAfter.Equal(served) {
		t.Fatalf("a failed bind overwrote the served pair's expiry: got %v (known=%v), want %v", notAfter, known, served)
	}
}
