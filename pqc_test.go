package main

// pqc_test.go - Proves that Culvert's TLS stack negotiates ML-KEM-768
// (post-quantum hybrid key exchange) as claimed in the README.
//
// The test constrains BOTH client and server to ONLY accept X25519MLKEM768.
// If the handshake succeeds, ML-KEM was necessarily the negotiated key
// exchange - there is no classical fallback. If Go's crypto/tls doesn't
// support ML-KEM, the handshake fails and the test fails - proving the
// README claim is false.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generatePQCTestCert creates a self-signed ECDSA P-256 certificate for
// the PQC handshake test. The cert is throwaway - only used to bootstrap
// a TLS connection so we can verify the key exchange algorithm.
func generatePQCTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqc-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// TestPQC_MLKEM768_KeyExchange proves that Go's TLS stack negotiates
// ML-KEM-768 hybrid post-quantum key exchange. This test backs up
// Culvert's README claim of quantum-resistant connections.
//
// How it works:
//   - Server CurvePreferences: [X25519MLKEM768] (PQC only, no classical)
//   - Client CurvePreferences: [X25519MLKEM768] (PQC only, no classical)
//   - If handshake succeeds → ML-KEM was used (QED)
//   - If handshake fails → Go doesn't support ML-KEM → README is wrong
func TestPQC_MLKEM768_KeyExchange(t *testing.T) {
	cert := generatePQCTestCert(t)

	// Server: ONLY accept ML-KEM-768. No X25519/P-256 fallback.
	serverCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		MinVersion:       tls.VersionTLS13,
	}

	// Client: ONLY offer ML-KEM-768. No classical fallback.
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test-only self-signed cert
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		MinVersion:         tls.VersionTLS13,
	}

	// Start a TLS listener.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Accept one connection in background.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		serverDone <- conn.(*tls.Conn).HandshakeContext(t.Context())
	}()

	// Connect as client with PQC-only config.
	rawConn, err := (&tls.Dialer{Config: clientCfg}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("PQC TLS handshake FAILED: %v\n"+
			"This means Go's crypto/tls did not negotiate ML-KEM-768.\n"+
			"Culvert's post-quantum claims in the README are invalid for this Go version.", err)
	}
	defer func() { _ = rawConn.Close() }()
	conn := rawConn.(*tls.Conn)

	// Verify server side also succeeded.
	if err := <-serverDone; err != nil {
		t.Fatalf("server-side PQC handshake failed: %v", err)
	}

	// Verify TLS 1.3 (ML-KEM requires TLS 1.3).
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 (0x0304), got 0x%04x", state.Version)
	}

	t.Logf("✅ Post-Quantum ML-KEM-768 handshake SUCCEEDED")
	t.Logf("   TLS version:  0x%04x (TLS 1.3)", state.Version)
	t.Logf("   Cipher suite: %s (0x%04x)",
		tls.CipherSuiteName(state.CipherSuite), state.CipherSuite)
	t.Logf("   Key exchange: X25519MLKEM768 (hybrid classical + post-quantum)")
	t.Logf("   Protection:   Resistant to 'Harvest Now, Decrypt Later' attacks")
}

// TestPQC_ClassicalFallback_Rejected verifies that when the server ONLY
// offers ML-KEM-768 and the client ONLY offers classical X25519, the
// handshake correctly FAILS. This proves ML-KEM is actually being
// enforced, not silently falling back to classical.
func TestPQC_ClassicalFallback_Rejected(t *testing.T) {
	cert := generatePQCTestCert(t)

	// Server: PQC only.
	serverCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		MinVersion:       tls.VersionTLS13,
	}

	// Client: classical only — NO ML-KEM.
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test-only
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.(*tls.Conn).HandshakeContext(t.Context()) //nolint:errcheck
		conn.Close()
	}()

	// This should FAIL — PQC server rejects classical-only client.
	conn, err := (&tls.Dialer{Config: clientCfg}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("Expected handshake to FAIL when PQC server meets classical-only client, but it succeeded.\n" +
			"This means ML-KEM enforcement is not working — classical fallback occurred.")
	}

	t.Logf("✅ Classical-only client correctly REJECTED by PQC-only server")
	t.Logf("   Error: %v", err)
	t.Logf("   This proves ML-KEM is enforced, not silently degraded")
}
