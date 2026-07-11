package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// inspectRuleNative installs a single allow+inspect rule with StripALPN=false
// (native HTTP/2 inspection) and skip-verify (so the proxy accepts the httptest
// self-signed origin), replacing all rules.
func inspectRuleNative() {
	f := false
	policyStore.rules = nil
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "inspect-native", DestFQDN: "*",
		Action: ActionAllow, SSLAction: SSLInspect, TLSSkipVerify: true, StripALPN: &f,
	})
}

// connectTLSWithProto does CONNECT through the proxy to target, then a client TLS
// handshake offering `offer` ALPN and trusting only `roots`. It returns the
// established tls.Conn and the negotiated ALPN protocol. A successful handshake
// against roots=proxy-CA proves the tunnel is being MITM-inspected (the forged
// leaf chains to the proxy CA), not bypassed.
func connectTLSWithProto(t *testing.T, proxyHost, target, serverName string, roots *x509.CertPool, offer []string) (conn *tls.Conn, negotiatedProto string) {
	t.Helper()
	raw, err := dialTimeout(proxyHost)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := raw.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
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
		t.Fatalf("client TLS handshake: %v", err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	// Clear the dial deadline so subsequent h2/h1 request I/O isn't bounded by it.
	_ = raw.SetDeadline(time.Time{})
	return tc, tc.ConnectionState().NegotiatedProtocol
}

// TestMITM_NativeH2_InspectsAndProxies is the PR3b functional-correctness proof:
// with a StripALPN=false rule, an h2 client through the proxy to an h2 origin
// negotiates h2 on the forged leaf (native inspection, no downgrade), and a real
// h2 request round-trips through the shared inspection pipeline to the origin and
// back. The origin also asserts the client-spoofable X-User-Identity header was
// scrubbed by the pipeline, proving enforcement runs on the H2 path.
func TestMITM_NativeH2_InspectsAndProxies(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	var sawIdentity string
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawIdentity = r.Header.Get("X-User-Identity")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "h2-origin-ok proto="+r.Proto)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	proxyURL := startTestProxy(t)
	inspectRuleNative()

	target := origin.Listener.Addr().String()
	tc, proto := connectTLSWithProto(t, proxyURL.Host, target, "origin.test", proxyRoots, []string{"h2", "http/1.1"})
	if proto != "h2" {
		t.Fatalf("downstream ALPN = %q, want h2 (native inspection must not downgrade)", proto)
	}

	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test/hello", http.NoBody)
	req.Header.Set("X-User-Identity", "spoofed-admin")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round-trip through proxy: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := string(body); got != "h2-origin-ok proto=HTTP/2.0" {
		t.Fatalf("body = %q, want the origin's h2 response", got)
	}
	if sawIdentity != "" {
		t.Fatalf("origin saw X-User-Identity=%q — pipeline scrub did not run on the H2 path", sawIdentity)
	}
}

// TestMITM_NativeH2_BlocksFileDownload proves the shared enforcement pipeline
// BLOCKS on the H2 path (not merely proxies): a native-inspect rule with an
// Executables file profile turns an h2 request for a .exe into a 403 emitted by
// the h2 block responder — the payload is never delivered to the client.
func TestMITM_NativeH2_BlocksFileDownload(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "MZ-executable-payload")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	proxyURL := startTestProxy(t)
	f := false
	policyStore.rules = nil
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "inspect-native-fileblock", DestFQDN: "*",
		Action: ActionAllow, SSLAction: SSLInspect, TLSSkipVerify: true, StripALPN: &f,
		FileFiltering: true, FileProfile: FileProfileExecutables,
	})

	target := origin.Listener.Addr().String()
	tc, proto := connectTLSWithProto(t, proxyURL.Host, target, "origin.test", proxyRoots, []string{"h2", "http/1.1"})
	if proto != "h2" {
		t.Fatalf("downstream ALPN = %q, want h2", proto)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test/downloads/setup.exe", http.NoBody)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round-trip: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (file block on the H2 path)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 || resp.Header.Get("Content-Type") == "" {
		t.Fatalf("expected a 403 block body with content-type, got %q ct=%q", body, resp.Header.Get("Content-Type"))
	}
}

// TestMITM_NativeH2_FallsBackToH1WhenOriginNoH2 proves the ALPN intersection: an
// h2-offering client through a native rule to an HTTP/1.1-only origin negotiates
// http/1.1 on BOTH legs (the origin declined h2, so the forged leaf is
// constrained to http/1.1) and the request is served through the shared H1 loop —
// the client is never stranded.
func TestMITM_NativeH2_FallsBackToH1WhenOriginNoH2(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "h1-origin-ok proto="+r.Proto)
	}))
	defer origin.Close()

	proxyURL := startTestProxy(t)
	inspectRuleNative()

	target := origin.Listener.Addr().String()
	tc, proto := connectTLSWithProto(t, proxyURL.Host, target, "origin.test", proxyRoots, []string{"h2", "http/1.1"})
	if proto != "http/1.1" {
		t.Fatalf("downstream ALPN = %q, want http/1.1 (origin declined h2 → constrained downgrade)", proto)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test/hello", http.NoBody)
	if err := req.Write(tc); err != nil {
		t.Fatalf("write h1 request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		t.Fatalf("read h1 response through proxy: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got != "h1-origin-ok proto=HTTP/1.1" {
		t.Fatalf("body = %q, want the origin's h1 response", got)
	}
}
