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
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileblock"
)

// writeCloseBuf is a Write+Close sink for exercising writers that require both
// (fileblock.BlockConn). It records whether Close was called.
type writeCloseBuf struct {
	bytes.Buffer
	closed bool
}

func (w *writeCloseBuf) Close() error { w.closed = true; return nil }

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
	scanBlockConn(h1BlockResponder{w: &buf}, "evil.example", "eicar", "clamav")
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
	dpiBlock(h1BlockResponder{w: &buf}, "evil.example", "sig-42")
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

// TestCharacterize_FileBlockConnBytes locks fileblock.BlockConn's exact HTTP/1.1
// 403 output (the third block writer, un-migrated in PR1) BEFORE PR2b relocates
// its wire emission into the responder. Also documents the current force-close
// (which PR2b moves to the H1 responder/loop; the H2 path must never close the
// tunnel conn on a per-stream block). Both reviewers flagged this as missing.
func TestCharacterize_FileBlockConnBytes(t *testing.T) {
	w := &writeCloseBuf{}
	fileblock.BlockConn(w, "evil.example", "/x/setup.exe", "exe", "global ext")
	out := w.String()
	for _, want := range []string{
		"HTTP/1.1 403 Forbidden\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"Content-Length: ",
		"Connection: close\r\n",
		"Blocked: file type exe is not allowed (global ext)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fileblock.BlockConn output missing %q; got:\n%q", want, out)
		}
	}
	if !w.closed {
		t.Error("fileblock.BlockConn currently force-closes the conn (documented H1 behavior; PR2b relocates this)")
	}
}

// TestCharacterize_UpstreamInspectLegOffersNoALPN locks the second half of the
// "today == strip" oracle: the upstream inspect leg currently offers NO ALPN, so
// origins fall back to HTTP/1.1. PR3's C1 intersection changes this; lock it now
// so that change is caught. (Reviewer 2, missing test #5.)
func TestCharacterize_UpstreamInspectLegOffersNoALPN(t *testing.T) {
	for _, skip := range []bool{false, true} {
		cfg := upstreamInspectTLSConfig("example.com", skip)
		if len(cfg.NextProtos) != 0 {
			t.Errorf("upstreamInspectTLSConfig(skipVerify=%v).NextProtos = %v, want empty (no ALPN offered today)", skip, cfg.NextProtos)
		}
	}
}

// TestCharacterize_BlockReasonCannotInjectResponse proves a CRLF-laden scan reason
// cannot forge a SECOND HTTP response through blockBeforeResponse: the injected
// bytes land inside the Content-Length-bounded body of the single 403, so a client
// parses exactly one response and a second read hits EOF. Locks the property before
// the H2 impl (where a streamed/unbounded reason would be riskier). Note the string
// "HTTP/1.1 200 OK" DOES appear verbatim in the body — that is safe precisely
// because Content-Length delimits it; the security property is "not parseable as a
// second response," not "string absent."
func TestCharacterize_BlockReasonCannotInjectResponse(t *testing.T) {
	var buf bytes.Buffer
	scanBlockConn(h1BlockResponder{w: &buf}, "evil.example", "sig\r\n\r\nHTTP/1.1 200 OK\r\n\r\ninjected", "clamav")

	br := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("first response must parse: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("HTTP/1.1 200 OK")) {
		t.Fatalf("injected bytes should be contained within the bounded body, got: %q", body)
	}
	// The crux: no SECOND response may be parseable — the injected status line is
	// body, not a new message.
	if resp2, err := http.ReadResponse(br, nil); err == nil {
		resp2.Body.Close()
		t.Fatal("SECURITY: a second HTTP response was injectable via the scan reason")
	}
}
