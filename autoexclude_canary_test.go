package main

// autoexclude_canary_test.go — F5 classifier qualification.
//
// The learn classifier (classify{Origin,Client}InspectFailure) matches on
// crypto/tls + crypto/x509 error *strings*, which are NOT part of Go's stable
// API. A toolchain upgrade that rewords any of them would silently break
// self-healing (fail-safe — it keeps inspecting — but a silent feature
// regression). These canaries drive REAL TLS handshakes that produce each
// security-relevant condition and assert the classifier still returns the
// expected verdict, so a Go-version wording change becomes a RED test instead of
// a silent regression. Paired with FuzzClassifyInspectFailure (property fuzzing,
// nightly) below.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// canarySelfSigned returns a self-signed ECDSA server cert and a pool trusting it.
func canarySelfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "canary.example"},
		NotBefore:    time.Unix(1_600_000_000, 0), // 2020
		NotAfter:     time.Unix(4_000_000_000, 0), // 2096
		DNSNames:     []string{"canary.example"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsecert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// canaryHandshake runs a client↔server TLS handshake over a real loopback TCP
// connection and returns both sides' handshake errors. Real TCP (kernel-buffered)
// is used rather than net.Pipe: net.Pipe is fully synchronous/unbuffered and a
// TLS handshake's interleaved flights deadlock on it. Bounded by a context
// timeout so a determinism-gate run can never hang.
func canaryHandshake(t *testing.T, clientCfg, serverCfg *tls.Config) (clientErr, serverErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, aerr := ln.Accept()
		if aerr != nil {
			serverErr = aerr
			return
		}
		s := tls.Server(conn, serverCfg)
		serverErr = s.HandshakeContext(ctx)
		_ = s.Close()
	}()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := tls.Client(conn, clientCfg)
	clientErr = c.HandshakeContext(ctx)
	_ = c.Close()
	<-done
	return clientErr, serverErr
}

// TestClassifierCanary_RealHandshakes pins the three security-relevant classifier
// verdicts against REAL Go TLS handshakes (not hand-written error strings), so a
// Go-version wording change fails here instead of silently disabling the feature.
func TestClassifierCanary_RealHandshakes(t *testing.T) {
	cert, pool := canarySelfSigned(t)

	// (1) ORIGIN requires a client certificate we cannot supply. WE are the client
	// dialing the origin. IMPORTANT REAL-BEHAVIOR FINDING (recorded by this canary):
	// a Go client's HandshakeContext against a cert-requiring origin does NOT surface
	// the "certificate required" string — in TLS 1.3 the client completes its
	// handshake (returns nil) BEFORE the server's certificate_required alert is sent,
	// and in TLS 1.2 the client sees a generic "handshake failure" (which the
	// classifier deliberately does NOT learn). So classifyOriginInspectFailure's
	// `certificate required` match is NOT reached from a client-side handshake error;
	// the origin-leg client-cert rescue therefore does not fire from this path today.
	//
	// This canary pins that REALITY (fail-closed: no learn, no rescue) so that (a) a
	// regression that wrongly learned on a generic origin handshake_failure would fail
	// here, and (b) if a future Go version DID start surfacing "certificate required"
	// on the client handshake, the flip to learn=true would be caught and reconciled.
	// Whether the rescue path should instead classify the post-handshake alert is a
	// behavior question tracked separately (out of scope for this test-only slice).
	t.Run("origin_cert_required_surfaces_as_handshake_failure_not_learned", func(t *testing.T) {
		// #nosec G402 -- test deliberately pins TLS 1.2 to observe the client-side
		// handshake behavior when an origin requires a client certificate.
		v12 := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
		clientCfg := v12.Clone()
		clientCfg.RootCAs = pool
		clientCfg.ServerName = "canary.example"
		serverCfg := v12.Clone()
		serverCfg.Certificates = []tls.Certificate{cert}
		serverCfg.ClientAuth = tls.RequireAnyClientCert
		clientErr, serverErr := canaryHandshake(t, clientCfg, serverCfg)
		t.Logf("real cert-requiring-origin dial (TLS1.2): clientErr=%v ; serverErr=%v", clientErr, serverErr)
		if clientErr == nil {
			t.Skip("client handshake returned nil (server-timing dependent); nothing to classify on the client leg")
		}
		// The classifier must NOT learn/rescue on this generic client-side error
		// (fail-closed) — a real certificate_required string is not produced here.
		if r, learn, rescue := classifyOriginInspectFailure(clientErr); learn || rescue {
			t.Fatalf("cert-requiring-origin client error %q was learned (%q, learn=%v, rescue=%v); a generic origin handshake failure must stay fail-closed", clientErr.Error(), r, learn, rescue)
		}
	})

	// (2) CLIENT (a pinning app) rejects our forged leaf. WE are the MITM server;
	// the client verifies against an empty pool and aborts with a cert alert that WE
	// observe. Our server-side error is the client-leg pinning signal → must learn.
	t.Run("client_pinned_rejection", func(t *testing.T) {
		_, serverErr := canaryHandshake(t,
			&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), ServerName: "canary.example"},
			&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		)
		if serverErr == nil {
			t.Fatal("expected our server handshake to observe the client's cert rejection")
		}
		t.Logf("real client pinning-rejection error (server side): %q", serverErr.Error())
		cr, ok := classifyClientInspectFailure(serverErr)
		if !ok || cr != autoExReasonClientPinned {
			t.Fatalf("real client cert-rejection classified as (%q, ok=%v); want (client_pinned,true) — the Go TLS alert string may have changed (classifier drift)", cr, ok)
		}
	})

	// (3) ORIGIN presents an untrusted cert and WE verify it → cert-verify failure.
	// This is the poisoning/exfil vector and MUST NEVER learn or rescue, regardless
	// of Go's exact error wording (errors.As on the x509 value types is the primary
	// guard; the string fallback is defense-in-depth).
	t.Run("origin_cert_verify_never_learns", func(t *testing.T) {
		clientErr, _ := canaryHandshake(t,
			&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), ServerName: "canary.example"},
			&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		)
		if clientErr == nil {
			t.Fatal("expected a cert-verify failure against the untrusted origin cert")
		}
		t.Logf("real origin cert-verify error: %q", clientErr.Error())
		if !isOriginCertVerifyErr(clientErr) {
			t.Fatalf("real cert-verify error %q not recognised by isOriginCertVerifyErr — the exfil guard would miss it", clientErr.Error())
		}
		if r, learn, rescue := classifyOriginInspectFailure(clientErr); learn || rescue {
			t.Fatalf("cert-verify failure MUST NOT learn/rescue, got (%q, learn=%v, rescue=%v) — exfil guard regressed", r, learn, rescue)
		}
	})
}

// FuzzClassifyInspectFailure property-fuzzes the classifier over arbitrary error
// strings. Invariants (must hold for ALL inputs): (a) an origin learn only ever
// yields a bounded reason; (b) rescue implies learn AND the client-cert reason;
// (c) a cert-verify-classed input NEVER learns or rescues (the exfil guard); (d)
// a client learn only ever yields client_pinned; (e) no panic. Wired into
// fuzz-nightly.yml.
func FuzzClassifyInspectFailure(f *testing.F) {
	for _, s := range []string{
		"", "remote error: tls: certificate required",
		"x509: certificate signed by unknown authority", "certificate has expired",
		"tls: server selected unsupported protocol version 301",
		"remote error: tls: bad certificate", "remote error: tls: unknown certificate authority",
		"EOF", "read tcp: connection reset by peer", "remote error: tls: handshake failure",
		"tls: no supported versions satisfy MinVersion and MaxVersion",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		err := errors.New(msg)
		r, learn, rescue := classifyOriginInspectFailure(err)
		if learn && r != autoExReasonClientCert && r != autoExReasonUnsupported {
			t.Fatalf("origin learn=true with out-of-set reason %q for %q", r, msg)
		}
		if rescue && (!learn || r != autoExReasonClientCert) {
			t.Fatalf("rescue must imply learn AND client_cert (got reason=%q learn=%v) for %q", r, learn, msg)
		}
		if isOriginCertVerifyErr(err) && (learn || rescue) {
			t.Fatalf("cert-verify-classed input learned/rescued (reason=%q) for %q — exfil guard breach", r, msg)
		}
		if cr, ok := classifyClientInspectFailure(err); ok && cr != autoExReasonClientPinned {
			t.Fatalf("client learn with out-of-set reason %q for %q", cr, msg)
		}
	})
}
