package main

// mtls_ocsp_startup_test.go — PR3 expansion Batch 3 coverage.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var mtlsOCSPLoggerMu sync.Mutex

func ensureMTLSOCSPTestLogger(t *testing.T) {
	t.Helper()
	mtlsOCSPLoggerMu.Lock()
	defer mtlsOCSPLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetMTLSOCSPGlobals snapshots/restores the entire upstream
// transport pointer, the operator's TLS template
// (upstreamOpTLSCfg), and globalOCSP.enabled for isolation under
// -shuffle. P5.3: published transports are read-only; tests
// snapshot via Load() and restore via Store() rather than mutating
// fields on a published transport. The op TLS template is held
// under upstreamTransportWriteMu; we snapshot under the same lock.
func resetMTLSOCSPGlobals(t *testing.T) {
	t.Helper()
	origPtr := upstreamTransportPtr.Load()
	origOCSP := globalOCSP.Enabled()
	upstreamTransportWriteMu.Lock()
	origOpTLS := upstreamOpTLSCfg
	// Clear at start so tests don't inherit state from a prior test.
	upstreamOpTLSCfg = nil
	upstreamTransportWriteMu.Unlock()
	mtlsClientCertMu.Lock()
	origCertStatus := mtlsClientCertState
	mtlsClientCertState = mtlsClientCertStatus{}
	mtlsClientCertMu.Unlock()
	t.Cleanup(func() {
		upstreamTransportPtr.Store(origPtr)
		upstreamTransportWriteMu.Lock()
		upstreamOpTLSCfg = origOpTLS
		upstreamTransportWriteMu.Unlock()
		mtlsClientCertMu.Lock()
		mtlsClientCertState = origCertStatus
		mtlsClientCertMu.Unlock()
		if origOCSP {
			globalOCSP.Enable()
		} else {
			globalOCSP.Disable()
		}
	})
}

// writeTestClientCert generates a self-signed ECDSA cert+key into dir
// and returns (certPath, keyPath).
func writeTestClientCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-mtls-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestResolveMTLSOCSPStartupConfig_CopiesAllFields(t *testing.T) {
	fc := &FileConfig{}
	fc.Proxy.ClientCertFile = "/etc/culvert/client.crt"
	fc.Proxy.ClientKeyFile = "/etc/culvert/client.key"
	fc.Proxy.OCSPCheck = true
	got := resolveMTLSOCSPStartupConfig(fc)
	if got.ClientCertFile != "/etc/culvert/client.crt" {
		t.Errorf("ClientCertFile: got %q", got.ClientCertFile)
	}
	if got.ClientKeyFile != "/etc/culvert/client.key" {
		t.Errorf("ClientKeyFile: got %q", got.ClientKeyFile)
	}
	if !got.OCSPCheck {
		t.Error("OCSPCheck: expected true")
	}
}

func TestLoadMTLSAndOCSP_AllEmptyIsNoop(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	// P5.3: start from a fresh transport with no TLS config; loader
	// must perform no swap for an empty cfg.
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{})
	if getUpstreamTransport().TLSClientConfig != nil {
		t.Error("TLSClientConfig should remain nil when no mTLS configured")
	}
	if globalOCSP.Enabled() {
		t.Error("OCSP should remain disabled")
	}
}

func TestLoadMTLSAndOCSP_LoadsClientCert(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)

	loadMTLSAndOCSP(mtlsOCSPStartupConfig{
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
	})

	tlsCfg := getUpstreamTransport().TLSClientConfig
	if tlsCfg == nil {
		t.Fatal("TLSClientConfig should be initialised")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 client cert; got %d", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion should be TLS1.2; got %v", tlsCfg.MinVersion)
	}
}

func TestLoadMTLSAndOCSP_PreservesExistingTLSConfig(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	// Pre-existing TLS config (e.g. an upstream-trust-anchor config) must
	// not have its FIELD VALUES overwritten — only Certificates is
	// replaced. P5.3 note: the swap clones TLSClientConfig via
	// (*tls.Config).Clone(), so the resulting pointer is a NEW instance;
	// pre-P5.3's "same pointer reused" contract becomes
	// "field values preserved," which is the same operator-visible
	// guarantee.
	existing := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "preset.example"}
	// P5.3: seed the operator's TLS template AND publish a transport
	// carrying the same fields. The next loadMTLSAndOCSP swap will
	// read from upstreamOpTLSCfg, not from the published transport's
	// TLSClientConfig (which the stdlib may lazily mutate).
	upstreamTransportWriteMu.Lock()
	upstreamOpTLSCfg = existing.Clone()
	upstreamTransportWriteMu.Unlock()
	newT := cloneTransport(getUpstreamTransport())
	newT.TLSClientConfig = existing.Clone()
	upstreamTransportPtr.Store(newT)

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})

	tlsCfg := getUpstreamTransport().TLSClientConfig
	if tlsCfg.ServerName != "preset.example" {
		t.Errorf("ServerName clobbered: got %q", tlsCfg.ServerName)
	}
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion clobbered: got %v", tlsCfg.MinVersion)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 client cert after mTLS load; got %d", len(tlsCfg.Certificates))
	}
}

func TestLoadMTLSAndOCSP_BadCertIsNonFatal(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Must not panic; TLSClientConfig must remain nil (no mTLS applied;
	// OCSP not requested, so the swap does not run at all).
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	if getUpstreamTransport().TLSClientConfig != nil {
		t.Error("TLSClientConfig should remain nil after bad-cert load")
	}
}

func TestLoadMTLSAndOCSP_EnablesOCSP(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	globalOCSP.Disable()
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{OCSPCheck: true})
	if !globalOCSP.Enabled() {
		t.Error("OCSP should be enabled after loadMTLSAndOCSP")
	}
}

func TestLoadMTLSAndOCSP_RecordsClientCertHealthOnSuccess(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})

	health := mtlsClientCertHealth()
	if !health.configured || !health.loaded {
		t.Fatalf("expected configured+loaded, got %+v", health)
	}
	if health.file != certPath {
		t.Errorf("file: got %q, want %q", health.file, certPath)
	}
	if health.lastError != "" {
		t.Errorf("lastError: expected empty, got %q", health.lastError)
	}
	if health.notAfter.IsZero() {
		t.Error("notAfter should be populated from the leaf certificate")
	} else if wantAfter := time.Now().Add(time.Hour); health.notAfter.After(wantAfter.Add(time.Minute)) || health.notAfter.Before(wantAfter.Add(-time.Minute)) {
		t.Errorf("notAfter: got %v, want ~%v (writeTestClientCert's NotAfter template)", health.notAfter, wantAfter)
	}
}

func TestLoadMTLSAndOCSP_RecordsClientCertHealthOnFailure(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})

	health := mtlsClientCertHealth()
	if !health.configured {
		t.Fatal("expected configured=true even on a failed load")
	}
	if health.loaded {
		t.Error("expected loaded=false for an unparsable cert")
	}
	if health.lastError == "" {
		t.Error("expected lastError to be populated")
	}
	if !health.notAfter.IsZero() {
		t.Errorf("notAfter should stay zero on a failed load, got %v", health.notAfter)
	}
}

func TestLoadMTLSAndOCSP_ClientCertHealthUnconfiguredByDefault(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{})

	health := mtlsClientCertHealth()
	if health.configured {
		t.Errorf("expected configured=false with no cert files set, got %+v", health)
	}
}

func TestLoadMTLSAndOCSP_OCSPDisabledByDefault(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	globalOCSP.Disable()
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{})
	if globalOCSP.Enabled() {
		t.Error("OCSP should remain disabled when OCSPCheck=false")
	}
}
