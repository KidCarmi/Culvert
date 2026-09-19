package main

// FE-6B.1 CORRECTION ROUND 2 — RED matrix (Go), committed on the reviewed
// candidate 8960ab53 BEFORE any product change (blocker B1 of the second
// external review).
//
// adminUIServeOnce loads the operator / persisted pair, records its leaf as
// the served identity, DISCARDS the loaded pair and calls ServeTLS with the
// file names — so ServeTLS reads the files a second time. A pair replaced
// between those two reads is SERVED as B while the appliance publishes A, and
// the discrepancy holds until the listener next binds. The window is
// microseconds wide, which bounds how often it happens and not at all what it
// costs, so these rows make it deterministic: a test seam
// (adminUIBeforeServeHook, nil in production) runs between the validation
// read and the serve call, replaces A with B there, and the row compares the
// PUBLISHED served fingerprint with the certificate a REAL TLS handshake
// receives. No sleeps, no timing.
//
//	D01 the persisted GUI pair (tls_custom): published == TLS peer == the
//	    identity that was validated (A) — the listener must serve the material
//	    it loaded, never re-read the files.
//	D02 the explicit -tls-cert/-tls-key pair (tls_configured): the same.
//	D03 CONTROL — ALPN h2 is negotiated on the custom-pair listener and an
//	    HTTP/2 request is answered (the reason the double read used to exist;
//	    the correction must keep ServeTLS's HTTP/2 setup).
//	D04 CONTROL — the evidence is cleared when the serve call returns.
//	D05 CONTROL — a broken pair still fails BEFORE the bind (no listener, no
//	    evidence recorded), so the CHAOS-57 descriptor-leak guarantee and the
//	    tls_certificate classification survive the change.
//
// D01/D02 fail on 8960ab53 (published A, peer B); D03–D05 pass there and
// must keep passing.
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fe6b1dLeafPEM mints a self-signed leaf pair for the admin listener.
func fe6b1dLeafPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func fe6b1dWritePair(t *testing.T, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fe6b1dArmReplaceBetweenLoadAndServe installs the seam: exactly once, between
// adminUIServeOnce's validation read and its serve call, pair B overwrites the
// files the listener was given. The hook runs on the serve goroutine, so it
// touches only the filesystem and reports through a channel.
func fe6b1dArmReplaceBetweenLoadAndServe(t *testing.T, certPath, keyPath string, bCert, bKey []byte) <-chan error {
	t.Helper()
	fired := make(chan error, 1)
	prev := adminUIBeforeServeHook
	adminUIBeforeServeHook = func() {
		adminUIBeforeServeHook = prev
		if err := os.WriteFile(certPath, bCert, 0o600); err != nil {
			fired <- err
			return
		}
		fired <- os.WriteFile(keyPath, bKey, 0o600)
	}
	t.Cleanup(func() { adminUIBeforeServeHook = prev })
	return fired
}

func fe6b1dRequireFired(t *testing.T, fired <-chan error) {
	t.Helper()
	select {
	case err := <-fired:
		if err != nil {
			t.Fatalf("replacing the pair between load and serve: %v", err)
		}
	default:
		t.Fatalf("the seam between the validation read and the serve call did not run")
	}
}

// fe6b1dPublishedServed reads the appliance's own served identity.
func fe6b1dPublishedServed(t *testing.T, mux *http.ServeMux) (fingerprint, posture string) {
	t.Helper()
	l := fe6b1cListener(t, fe6b1cInventory(t, mux), "listener")
	fp, _ := fe6b1cServed(t, l)["fingerprint"].(string)
	p, _ := l["posture"].(string)
	return fp, p
}

// ── D01 ─────────────────────────────────────────────────────────────────────

func TestFE6B1D_D01_PersistedPairServedIsThePairValidated(t *testing.T) {
	_, mux := fe6b1cNode(t)
	fe6b0eSeedPair(t, mux, "ui-a.fe6b1d")
	fpA, _ := fe6b1cUICert(t, fe6b1cInventory(t, mux))["fingerprint"].(string)
	if fpA == "" {
		t.Fatalf("no persisted fingerprint for A")
	}
	certPath, keyPath := fe6b1cBootSelect(t, "", "")
	if certPath != customUITLSCertPath() {
		t.Fatalf("boot selection did not pick the persisted pair: %q", certPath)
	}
	bCert, bKey := fe6b1dLeafPEM(t, "ui-b.fe6b1d")
	fpB := fe6b1cPEMFingerprint(t, bCert)
	fired := fe6b1dArmReplaceBetweenLoadAndServe(t, certPath, keyPath, bCert, bKey)

	addr, stop := fe6b1cServe(t, certPath, keyPath, false)
	defer stop()
	fe6b1dRequireFired(t, fired)

	peer := fe6b1cPeerFingerprint(t, addr)
	published, posture := fe6b1dPublishedServed(t, mux)
	if posture != "tls_custom" {
		t.Fatalf("posture = %q, want tls_custom", posture)
	}
	if published != peer {
		t.Fatalf("the appliance publishes served %s but a TLS client receives %s (A=%s B=%s): the listener served material it did not record", published, peer, fpA, fpB)
	}
	if peer != fpA {
		t.Fatalf("the listener must serve the pair it VALIDATED (A %s), not a later re-read (%s)", fpA, peer)
	}
	// The persisted pair on disk is now B, so the served pair is not the
	// persisted one — and the derived facts must say so.
	inv := fe6b1cInventory(t, mux)
	if got, _ := fe6b1cUICert(t, inv)["fingerprint"].(string); got != fpB {
		t.Fatalf("persisted fingerprint = %s, want B %s", got, fpB)
	}
	if act, _ := fe6b1cUICert(t, inv)["active"].(bool); act {
		t.Fatalf("served A / persisted B must not be reported active")
	}
}

// ── D02 ─────────────────────────────────────────────────────────────────────

func TestFE6B1D_D02_ExplicitPairServedIsThePairValidated(t *testing.T) {
	_, mux := fe6b1cNode(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "op.crt")
	keyPath := filepath.Join(dir, "op.key")
	aCert, aKey := fe6b1dLeafPEM(t, "op-a.fe6b1d")
	fe6b1dWritePair(t, certPath, keyPath, aCert, aKey)
	fpA := fe6b1cPEMFingerprint(t, aCert)
	gotCert, gotKey := fe6b1cBootSelect(t, certPath, keyPath)
	if gotCert != certPath || gotKey != keyPath {
		t.Fatalf("boot selection = %q/%q, want the explicit pair", gotCert, gotKey)
	}
	bCert, bKey := fe6b1dLeafPEM(t, "op-b.fe6b1d")
	fpB := fe6b1cPEMFingerprint(t, bCert)
	fired := fe6b1dArmReplaceBetweenLoadAndServe(t, certPath, keyPath, bCert, bKey)

	addr, stop := fe6b1cServe(t, certPath, keyPath, false)
	defer stop()
	fe6b1dRequireFired(t, fired)

	peer := fe6b1cPeerFingerprint(t, addr)
	published, posture := fe6b1dPublishedServed(t, mux)
	if posture != "tls_configured" {
		t.Fatalf("posture = %q, want tls_configured", posture)
	}
	if published != peer || peer != fpA {
		t.Fatalf("published %s / peer %s / validated A %s (B=%s): the explicitly configured listener must serve the material it validated and recorded", published, peer, fpA, fpB)
	}
}

// ── D03 control: HTTP/2 stays negotiated ────────────────────────────────────

func TestFE6B1D_D03_Control_HTTP2IsNegotiatedOnTheCustomPairListener(t *testing.T) {
	_, mux := fe6b1cNode(t)
	_, addr, stop := fe6b1cServeA(t, mux)
	defer stop()

	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // test peer read
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	proto := conn.ConnectionState().NegotiatedProtocol
	_ = conn.Close()
	if proto != "h2" {
		t.Fatalf("ALPN negotiated %q, want h2 — ServeTLS's HTTP/2 setup was lost", proto)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true} //nolint:gosec // test client
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + addr + "/probe")
	if err != nil {
		t.Fatalf("GET /probe: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || string(body) != "ok" {
		t.Fatalf("GET /probe over %s = %d %q, want HTTP/2 and ok", resp.Proto, resp.StatusCode, body)
	}
}

// ── D04 control: evidence is withdrawn when the serve call returns ─────────

func TestFE6B1D_D04_Control_EvidenceClearedWhenServeReturns(t *testing.T) {
	_, mux := fe6b1cNode(t)
	_, _, stop := fe6b1cServeA(t, mux)
	if rec := adminListenerEvidenceNow(); rec.State != adminListenerServing {
		t.Fatalf("state = %q while bound, want serving", rec.State)
	}
	stop()
	if rec := adminListenerEvidenceNow(); rec.State != adminListenerUnknown || rec.Served != nil {
		t.Fatalf("after the serve returned the evidence must be unknown with no served identity, got %+v", rec)
	}
	if l := fe6b1cListener(t, fe6b1cInventory(t, mux), "listener"); l["state"] != "unknown" {
		t.Fatalf("published state = %v after stop, want unknown", l["state"])
	}
}

// ── D05 control: a broken pair fails before the bind, records nothing ──────

func TestFE6B1D_D05_Control_BrokenPairFailsBeforeBindAndRecordsNothing(t *testing.T) {
	fe6b1cNode(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.crt")
	keyPath := filepath.Join(dir, "bad.key")
	fe6b1dWritePair(t, certPath, keyPath, []byte("nope"), []byte("nope"))
	port, release := occupyPort(t)
	release()
	srv := newTestAdminServer()
	err := adminUIServeOnce(srv, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), certPath, keyPath)
	if err == nil {
		t.Fatalf("expected a certificate failure")
	}
	if got := classifyAdminUIListenError(err); got != "tls_certificate" {
		t.Fatalf("classified %q, want tls_certificate (%v)", got, err)
	}
	if rec := adminListenerEvidenceNow(); rec.State != adminListenerUnknown {
		t.Fatalf("a failed validation must record no evidence, got %+v", rec)
	}
	// Nothing bound: the port is free again for an immediate re-bind.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("the port stayed bound after a validation failure: %v", err)
	}
	_ = ln.Close()
}
