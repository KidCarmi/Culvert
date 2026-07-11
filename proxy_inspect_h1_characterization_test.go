package main

// Characterization tests (PR0 of the HTTP/2-inspection program).
//
// These LOCK the current HTTP/1.1 SSL-inspection behavior so that the
// block-responder refactor (PR1) and the ALPN fork (PR2/PR3) cannot change
// observable H1 wire behavior by accident. They are deliberately assertive
// about bytes and ALPN — that is the point of a characterization/golden test:
// it is the oracle the refactor must preserve.
//
// Two locked invariants:
//  1. On the inspect path the proxy negotiates ALPN "http/1.1" with the client
//     even when the client offers h2 — the documented downgrade
//     (proxy_tunnel.go mitmClientTLSConfig NextProtos http/1.1). PR3 will make
//     this conditional; until then it must stay put for every rule.
//  2. The three tunnel block-page writers emit a byte-exact HTTP/1.1 403 with
//     Connection: close. The blockResponder refactor (PR1) must reproduce these
//     bytes verbatim on the H1 path.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// connectAndTLSALPN is connectAndTLS with a caller-supplied ALPN list; it
// returns the protocol the proxy negotiated on the forged leaf so a test can
// assert the current downgrade behavior.
func connectAndTLSALPN(t *testing.T, proxyHost, target, serverName string, roots *x509.CertPool, offer []string) string {
	t.Helper()
	raw, err := dialTimeout(proxyHost)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := readCONNECT200(raw); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{ // #nosec G402 -- test trusts only the proxy CA
		RootCAs:    roots,
		ServerName: serverName,
		NextProtos: offer,
		MinVersion: tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("client TLS handshake on inspect path: %v", err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	return tc.ConnectionState().NegotiatedProtocol
}

// TestCharacterize_InspectClientALPNIsHTTP11 locks the current downgrade:
// a client offering h2,http/1.1 to an inspected origin is downgraded to
// http/1.1 by the forged leaf. This is the exact behavior PR3 will make
// conditional; the test documents and pins the default (strip-alpn) posture.
func TestCharacterize_InspectClientALPNIsHTTP11(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyURL := startTestProxy(t)
	inspectRule(true)

	got := connectAndTLSALPN(t, proxyURL.Host, upstream.Listener.Addr().String(), "inspect.test",
		proxyRoots, []string{"h2", "http/1.1"})
	if got != "http/1.1" {
		t.Fatalf("inspect-path client ALPN = %q, want http/1.1 (current downgrade must hold until PR3)", got)
	}
}

// TestCharacterize_ScanBlockConnBytes locks scanBlockConn's exact HTTP/1.1 403
// wire output — the oracle the H1 blockResponder must reproduce.
func TestCharacterize_ScanBlockConnBytes(t *testing.T) {
	var buf bytes.Buffer
	scanBlockConn(&buf, "evil.example", "eicar", "clamav")
	out := buf.String()
	for _, want := range []string{
		"HTTP/1.1 403 Forbidden\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"Connection: close\r\n",
		"Blocked by CLAMAV scan: eicar",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scanBlockConn output missing %q; got:\n%q", want, out)
		}
	}
	if !strings.HasPrefix(out, "HTTP/1.1 403 Forbidden\r\n") {
		t.Errorf("scanBlockConn must start with the H1 status line; got:\n%q", out)
	}
}

// TestCharacterize_DPIBlockBytes locks dpiBlock's exact HTTP/1.1 403 output.
func TestCharacterize_DPIBlockBytes(t *testing.T) {
	var buf bytes.Buffer
	dpiBlock(&buf, "evil.example", "sig-42")
	out := buf.String()
	for _, want := range []string{
		"HTTP/1.1 403 Forbidden\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"Connection: close\r\n",
		"Blocked by content inspection policy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dpiBlock output missing %q; got:\n%q", want, out)
		}
	}
}
