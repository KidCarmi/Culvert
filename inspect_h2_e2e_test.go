package main

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
	"strconv"
	"sync"
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
		w.Header().Set("X-Origin-Proto", r.Proto) // proves the proxy→origin leg protocol
		_, _ = io.WriteString(w, "h2-origin-ok")
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
	if got := string(body); got != "h2-origin-ok" {
		t.Fatalf("body = %q, want the origin's response", got)
	}
	if p := resp.Header.Get("X-Origin-Proto"); p != "HTTP/2.0" {
		t.Fatalf("upstream leg proto = %q, want HTTP/2.0 (proxy→origin must be h2)", p)
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

// nativeH2ClientConn wires the common native-h2 fixture: proxy CA, an h2 origin
// running `handler`, a native-inspect rule, and an h2 client conn through the
// proxy CONNECT tunnel. It asserts h2 was negotiated downstream.
func nativeH2ClientConn(t *testing.T, handler http.Handler) *http2.ClientConn {
	t.Helper()
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)
	origin := httptest.NewUnstartedServer(handler)
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	proxyURL := startTestProxy(t)
	inspectRuleNative()
	tc, proto := connectTLSWithProto(t, proxyURL.Host, origin.Listener.Addr().String(), "origin.test", proxyRoots, []string{"h2", "http/1.1"})
	if proto != "h2" {
		t.Fatalf("downstream ALPN = %q, want h2", proto)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	return cc
}

// TestMITM_NativeH2_TrailerForwarding proves gRPC-style un-announced trailers
// (e.g. grpc-status) round-trip through the H2 deliver path to the client.
func TestMITM_NativeH2_TrailerForwarding(t *testing.T) {
	cc := nativeH2ClientConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "grpc-frame")
		// Un-announced trailer set after the body — the gRPC pattern.
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test/svc.Method", http.NoBody)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck // test cleanup
	if string(body) != "grpc-frame" {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer Grpc-Status = %q, want 0 (trailer must forward through the H2 deliver path)", got)
	}
}

// TestMITM_NativeH2_TruncatedBodyResetsStream proves the correctness fix: when the
// origin aborts mid-body, the proxy RESETS the client stream (RST_STREAM) rather
// than delivering a clean-but-truncated 200. The client must observe a read error.
func TestMITM_NativeH2_TruncatedBodyResetsStream(t *testing.T) {
	cc := nativeH2ClientConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// Flush a chunk large enough to force it out to the proxy so the proxy
		// COMMITS response headers+body to the client, THEN abort mid-body — this
		// exercises the deliver-truncation path (not the RST-at-headers path, which
		// correctly yields a 502).
		_, _ = w.Write(bytes.Repeat([]byte("A"), 32*1024))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // origin RSTs its stream mid-body
	}))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test/blob", http.NoBody)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return // an error before/at headers is also an acceptable failure signal
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (headers committed before truncation)", resp.StatusCode)
	}
	_, readErr := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck // test cleanup
	if readErr == nil {
		t.Fatal("truncated upstream body was delivered as a clean success — the stream must be reset")
	}
}

// TestMITM_NativeH2_ConcurrentStreams exercises many multiplexed streams over one
// inspected tunnel (one upstream ClientConn) concurrently; under -race this
// validates the shared-state safety of the H2 path.
func TestMITM_NativeH2_ConcurrentStreams(t *testing.T) {
	cc := nativeH2ClientConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/s/" + strconv.Itoa(i)
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test"+path, http.NoBody)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close() //nolint:errcheck // test cleanup
			if string(body) != "ok:"+path {
				errs <- fmt.Errorf("stream %d body = %q", i, body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestMITM_NativeH2_PostBodyEcho proves request-body streaming on the H2 path: a
// POST body is forwarded upstream and echoed back through the pipeline.
func TestMITM_NativeH2_PostBodyEcho(t *testing.T) {
	cc := nativeH2ClientConn(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}))
	payload := bytes.Repeat([]byte("A"), 64*1024)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://origin.test/upload", bytes.NewReader(payload))
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close() //nolint:errcheck // test cleanup
	if len(body) != len(payload) {
		t.Fatalf("echo len = %d, want %d (POST body must stream upstream on H2)", len(body), len(payload))
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
		w.Header().Set("X-Origin-Proto", r.Proto) // proves the proxy→origin leg protocol
		_, _ = io.WriteString(w, "h1-origin-ok")
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
	if got := string(body); got != "h1-origin-ok" {
		t.Fatalf("body = %q, want the origin's response", got)
	}
	if p := resp.Header.Get("X-Origin-Proto"); p != "HTTP/1.1" {
		t.Fatalf("upstream leg proto = %q, want HTTP/1.1", p)
	}
}
