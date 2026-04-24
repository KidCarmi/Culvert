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

// resetMTLSOCSPGlobals snapshots/restores upstreamTransport.TLSClientConfig
// and globalOCSP.enabled for isolation under -shuffle.
func resetMTLSOCSPGlobals(t *testing.T) {
	t.Helper()
	origTLS := upstreamTransport.TLSClientConfig
	origOCSP := globalOCSP.Enabled()
	t.Cleanup(func() {
		upstreamTransport.TLSClientConfig = origTLS
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
	upstreamTransport.TLSClientConfig = nil
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{})
	if upstreamTransport.TLSClientConfig != nil {
		t.Error("TLSClientConfig should remain nil when no mTLS configured")
	}
	if globalOCSP.Enabled() {
		t.Error("OCSP should remain disabled")
	}
}

func TestLoadMTLSAndOCSP_LoadsClientCert(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransport.TLSClientConfig = nil

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)

	loadMTLSAndOCSP(mtlsOCSPStartupConfig{
		ClientCertFile: certPath,
		ClientKeyFile:  keyPath,
	})

	if upstreamTransport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should be initialised")
	}
	if len(upstreamTransport.TLSClientConfig.Certificates) != 1 {
		t.Errorf("expected 1 client cert; got %d", len(upstreamTransport.TLSClientConfig.Certificates))
	}
	if upstreamTransport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion should be TLS1.2; got %v", upstreamTransport.TLSClientConfig.MinVersion)
	}
}

func TestLoadMTLSAndOCSP_PreservesExistingTLSConfig(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	// Pre-existing TLS config (e.g. an upstream-trust-anchor config) must
	// not be overwritten — only Certificates is replaced.
	existing := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "preset.example"}
	upstreamTransport.TLSClientConfig = existing

	dir := t.TempDir()
	certPath, keyPath := writeTestClientCert(t, dir)
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})

	if upstreamTransport.TLSClientConfig != existing {
		t.Error("existing TLSClientConfig pointer should be reused")
	}
	if upstreamTransport.TLSClientConfig.ServerName != "preset.example" {
		t.Errorf("ServerName clobbered: got %q", upstreamTransport.TLSClientConfig.ServerName)
	}
}

func TestLoadMTLSAndOCSP_BadCertIsNonFatal(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	upstreamTransport.TLSClientConfig = nil

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(certPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Must not panic; TLSClientConfig must remain nil (no mTLS applied).
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{ClientCertFile: certPath, ClientKeyFile: keyPath})
	if upstreamTransport.TLSClientConfig != nil {
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

func TestLoadMTLSAndOCSP_OCSPDisabledByDefault(t *testing.T) {
	resetMTLSOCSPGlobals(t)
	ensureMTLSOCSPTestLogger(t)
	globalOCSP.Disable()
	loadMTLSAndOCSP(mtlsOCSPStartupConfig{})
	if globalOCSP.Enabled() {
		t.Error("OCSP should remain disabled when OCSPCheck=false")
	}
}
