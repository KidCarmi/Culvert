package main

// SSL-inspection / MITM end-to-end tests through the REAL proxy data plane.
//
// These prove customer-visible TLS-inspection guarantees for a SWG product:
// the proxy terminates the client TLS with a leaf signed by its own CA, so a
// client that trusts ONLY the proxy CA completes the handshake on the inspect
// path and FAILS on the bypass path — that asymmetry is the proof that MITM
// actually happened (not just that a request succeeded). On top of that we
// assert identity-header scrubbing on the decrypted inner request, fail-closed
// behavior on a bad upstream cert, block-before-tunnel, large-body integrity,
// and leaf-cache hit/miss + rotation.
//
// Hermetic: in-process TLS upstream (httptest.NewTLSServer), in-memory CA
// (certMgr.InitCA, ECDSA P-256), loopback only (the loopback CIDRs are relaxed
// for the tunnel via allowLoopbackTunnel, restored on cleanup). No public
// internet, no external certs.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// dialTimeout is the context-aware replacement for net.DialTimeout (noctx),
// with the 5s connect timeout the E2E suites use.
func dialTimeout(addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
}

// setupInspectCA installs a fresh in-memory CA into the global certMgr (saved
// and restored on cleanup) and returns it plus a cert pool a client can use to
// trust the proxy's MITM leaf certs.
func setupInspectCA(t *testing.T) (*CertManager, *x509.CertPool) {
	t.Helper()
	prev := certMgr
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	certMgr = cm
	t.Cleanup(func() { certMgr = prev })

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cm.CACertPEM()) {
		t.Fatal("append proxy CA PEM to pool")
	}
	return cm, pool
}

// readCONNECT200 reads the proxy's CONNECT reply off the raw conn (byte-wise, so
// it cannot over-read into the subsequent TLS stream) and checks for 2xx.
func readCONNECT200(c net.Conn) error {
	buf := make([]byte, 0, 128)
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c, one); err != nil {
			return fmt.Errorf("read CONNECT reply: %w", err)
		}
		buf = append(buf, one[0])
		if len(buf) >= 4 && bytes.Equal(buf[len(buf)-4:], []byte("\r\n\r\n")) {
			break
		}
		if len(buf) > 8192 {
			return fmt.Errorf("CONNECT reply too long")
		}
	}
	if !bytes.HasPrefix(buf, []byte("HTTP/1.1 200")) && !bytes.HasPrefix(buf, []byte("HTTP/1.0 200")) {
		line := buf
		if i := bytes.IndexByte(buf, '\r'); i >= 0 {
			line = buf[:i]
		}
		return fmt.Errorf("CONNECT not 200: %q", line)
	}
	return nil
}

// connectAndTLS does CONNECT through the proxy to target, then performs a client
// TLS handshake using serverName and trusting only `roots`. A handshake error is
// the meaningful signal that distinguishes inspect (succeeds) from bypass
// (fails, because the upstream's real cert is not signed by the proxy CA).
func connectAndTLS(proxyHost, target, serverName string, roots *x509.CertPool) (*tls.Conn, error) {
	raw, err := dialTimeout(proxyHost)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		raw.Close() //nolint:errcheck // best-effort close on write failure
		return nil, err
	}
	if err := readCONNECT200(raw); err != nil {
		raw.Close() //nolint:errcheck // best-effort close on CONNECT failure
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: serverName}) // #nosec G402 -- test trusts only the proxy CA
	if err := tc.HandshakeContext(context.Background()); err != nil {
		tc.Close() //nolint:errcheck // best-effort close on handshake failure
		return nil, fmt.Errorf("client TLS handshake: %w", err)
	}
	return tc, nil
}

// inspectRule installs a single allow+inspect rule (DestFQDN=* so it matches the
// loopback target) with the given skip-verify, replacing all rules.
func inspectRule(tlsSkipVerify bool) {
	policyStore.rules = nil
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "inspect-all", DestFQDN: "*",
		Action: ActionAllow, SSLAction: SSLInspect, TLSSkipVerify: tlsSkipVerify,
	})
}

// TestMITM_InspectMITMsAndScrubsIdentity proves the proxy MITMs the client TLS
// (client trusting only the proxy CA succeeds) AND that the decrypted inner
// request has its client-spoofed identity / private forwarded headers scrubbed
// before reaching the upstream — the SWG's primary (HTTPS) defense.
func TestMITM_InspectMITMsAndScrubsIdentity(t *testing.T) {
	allowLoopbackTunnel(t)
	cm, proxyRoots := setupInspectCA(t)

	type seen struct {
		identity, xff, xrealip string
		hits                   int
	}
	var got seen
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.identity = r.Header.Get("X-User-Identity")
		got.xff = r.Header.Get("X-Forwarded-For")
		got.xrealip = r.Header.Get("X-Real-IP")
		got.hits++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("inspected-ok")) //nolint:errcheck // test I/O; error not actionable
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	inspectRule(true) // skip-verify so the proxy accepts httptest's self-signed upstream

	missBefore := cacheMisses(cm)
	tc, err := connectAndTLS(proxyURL.Host, target, "inspect.test", proxyRoots)
	if err != nil {
		t.Fatalf("inspect handshake must succeed when client trusts the proxy CA: %v", err)
	}
	defer tc.Close() //nolint:errcheck // test cleanup

	// Inner HTTPS request carrying spoofed identity + private forwarded headers.
	_, _ = fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: inspect.test\r\n"+
		"X-User-Identity: attacker@evil.example\r\n"+
		"X-Forwarded-For: 10.1.2.3\r\n"+
		"X-Real-IP: 192.168.5.5\r\n"+
		"Connection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read inspected response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "inspected-ok" {
		t.Fatalf("inspected request: status=%d body=%q, want 200 inspected-ok", resp.StatusCode, body)
	}
	if got.hits != 1 {
		t.Errorf("upstream reached %d times, want 1", got.hits)
	}
	// The fix: identity + private forwarded headers must be scrubbed on the
	// inspect path, exactly as on the plain-HTTP path.
	if got.identity != "" {
		t.Errorf("SECURITY: client-spoofed X-User-Identity LEAKED to upstream through SSL inspection: %q", got.identity)
	}
	if got.xff != "" {
		t.Errorf("SECURITY: private X-Forwarded-For leaked through inspection: %q", got.xff)
	}
	if got.xrealip != "" {
		t.Errorf("SECURITY: private X-Real-IP leaked through inspection: %q", got.xrealip)
	}
	if cacheMisses(cm) <= missBefore {
		t.Errorf("expected a leaf-cert cache miss (a leaf was signed for the MITM)")
	}
}

// TestMITM_BypassDoesNotMITM is the contrast: with SSLAction=Bypass the proxy
// does NOT terminate TLS, so a client trusting only the proxy CA must FAIL the
// handshake (it sees the upstream's real, non-proxy-signed cert). This proves
// bypass really bypasses.
func TestMITM_BypassDoesNotMITM(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "bypass-all", DestFQDN: "*", Action: ActionAllow, SSLAction: SSLBypass})

	tc, err := connectAndTLS(proxyURL.Host, target, "inspect.test", proxyRoots)
	if err == nil {
		tc.Close() //nolint:errcheck // test cleanup
		t.Fatalf("bypass path: handshake unexpectedly SUCCEEDED trusting only the proxy CA — that means the proxy MITM'd a BYPASS rule (inspection leak)")
	}
	// Sanity: trusting the REAL upstream cert, bypass succeeds.
	okTLS, err := connectAndTLS(proxyURL.Host, target, "example.com", upstreamCertPool(t, upstream))
	if err != nil {
		t.Fatalf("bypass path should pass through the real upstream cert: %v", err)
	}
	okTLS.Close() //nolint:errcheck // test cleanup
}

// TestMITM_BlockedHTTPSNotReached proves a block rule denies the CONNECT before
// any tunnel is established, so the upstream is never reached.
func TestMITM_BlockedHTTPSNotReached(t *testing.T) {
	allowLoopbackTunnel(t)
	setupInspectCA(t)

	var reached int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "block-all", DestFQDN: "*", Action: ActionBlockPage, SSLAction: SSLInspect})

	raw, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if err := readCONNECT200(raw); err == nil {
		t.Errorf("blocked CONNECT returned 200 — must be denied before the tunnel")
	}
	time.Sleep(100 * time.Millisecond)
	if reached != 0 {
		t.Errorf("blocked HTTPS reached upstream %d times, want 0", reached)
	}
}

// TestMITM_BadUpstreamCertFailsClosed proves that with verification ON
// (TLSSkipVerify=false), the proxy refuses an untrusted (self-signed) upstream
// cert and fails closed rather than silently MITM-bridging to it.
func TestMITM_BadUpstreamCertFailsClosed(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	inspectRule(false) // verify ON → httptest's self-signed cert is untrusted

	raw, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	// The proxy does its upstream TLS handshake BEFORE replying to CONNECT; an
	// untrusted upstream cert must yield a non-200 (502), not a tunnel.
	if err := readCONNECT200(raw); err == nil {
		// If 200 somehow returned, the client handshake must still not bridge.
		tc := tls.Client(raw, &tls.Config{RootCAs: proxyRoots, ServerName: "inspect.test"})
		if tc.HandshakeContext(context.Background()) == nil {
			t.Errorf("bad upstream cert: proxy established an inspected tunnel anyway — fail-open")
		}
	}
}

// TestMITM_LargeResponseIntegrity streams a large body through the inspected
// tunnel and asserts byte-exact delivery (no relay stall / truncation under the
// inspect HTTP parsing path).
func TestMITM_LargeResponseIntegrity(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	const n = 1 << 20 // 1 MiB
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i * 31) // #nosec G115 -- deterministic test payload; byte truncation is intentional
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", n))
		w.WriteHeader(http.StatusOK)
		w.Write(payload) //nolint:errcheck // test I/O; error not actionable
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	inspectRule(true)

	tc, err := connectAndTLS(proxyURL.Host, target, "inspect.test", proxyRoots)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer tc.Close() //nolint:errcheck // test cleanup
	_, _ = fmt.Fprint(tc, "GET /big HTTP/1.1\r\nHost: inspect.test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != n || !bytes.Equal(body, payload) {
		t.Errorf("large inspected body corrupted: got %d bytes (equal=%v), want %d", len(body), bytes.Equal(body, payload), n)
	}
}

// TestMITM_CertCacheHitThenRotateClears proves leaf-cert caching (second request
// for the same SNI is a cache hit) and that a CA rotation clears the leaf cache
// (so stale leaves are not reused under the new CA).
func TestMITM_CertCacheHitThenRotateClears(t *testing.T) {
	allowLoopbackTunnel(t)
	cm, proxyRoots := setupInspectCA(t)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck // test I/O; error not actionable
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	inspectRule(true)

	doReq := func() {
		tc, err := connectAndTLS(proxyURL.Host, target, "cache.test", proxyRoots)
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		_, _ = fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: cache.test\r\nConnection: close\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err == nil {
			io.Copy(io.Discard, resp.Body) //nolint:errcheck // test I/O; error not actionable
			resp.Body.Close()
		}
		tc.Close() //nolint:errcheck // test cleanup
	}

	_, m0, _ := cm.CacheStats()
	doReq() // same SNI "cache.test": first sign → miss
	h1, m1, sz1 := cm.CacheStats()
	if m1 <= m0 {
		t.Errorf("first inspected request: expected a cache MISS (miss %d→%d)", m0, m1)
	}
	doReq() // second: cached leaf → hit
	h2, _, _ := cm.CacheStats()
	if h2 <= h1 {
		t.Errorf("second inspected request for same SNI: expected a cache HIT (hits %d→%d)", h1, h2)
	}
	if sz1 == 0 {
		t.Errorf("cache size should be >0 after signing a leaf")
	}

	// Rotate the CA — the leaf cache must be cleared so stale leaves aren't reused.
	if err := cm.InitCA(); err != nil {
		t.Fatalf("rotate InitCA: %v", err)
	}
	if _, _, sz := cm.CacheStats(); sz != 0 {
		t.Errorf("after CA rotation the leaf cache must be cleared, size=%d", sz)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func cacheMisses(cm *CertManager) int64 {
	_, m, _ := cm.CacheStats()
	return m
}

// upstreamCertPool returns a pool trusting the httptest server's own cert.
func upstreamCertPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// TestMITM_ForgedLeafTLSPosture is the DAST-grade assertion on the CLIENT-FACING
// side of an inspected tunnel (PANW audit item 3, J2a — hermetic replacement for
// running an external TLS scanner through the CONNECT path, which the shipped
// binary's SSRF loopback guard makes infeasible in CI). It pins the posture the
// SWG presents to clients via its forged leaf: a modern protocol floor, an AEAD
// cipher, and an ECDSA P-256 leaf signed by the proxy CA. It also proves the
// negotiated protocol FLOOR is enforced (a TLS 1.1-max client is refused), which
// guards the explicit MinVersion on proxy.go's client-facing tls.Config.
func TestMITM_ForgedLeafTLSPosture(t *testing.T) {
	allowLoopbackTunnel(t)
	cm, proxyRoots := setupInspectCA(t)
	_ = cm

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck // test I/O
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	inspectRule(true) // skip-verify: accept httptest's self-signed upstream

	// ── Positive: a modern client reflects the forged-leaf server posture ──
	tc, err := connectAndTLS(proxyURL.Host, target, "inspect.test", proxyRoots)
	if err != nil {
		t.Fatalf("inspect handshake must succeed when client trusts the proxy CA: %v", err)
	}
	defer tc.Close() //nolint:errcheck // test cleanup
	cs := tc.ConnectionState()

	if cs.Version < tls.VersionTLS12 {
		t.Errorf("SECURITY: forged leaf negotiated TLS version 0x%04x, want >= TLS 1.2", cs.Version)
	}

	// The negotiated cipher must be a modern AEAD suite — never RC4/3DES/CBC.
	allowedAEAD := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:                        true, // TLS 1.3
		tls.TLS_AES_256_GCM_SHA384:                        true, // TLS 1.3
		tls.TLS_CHACHA20_POLY1305_SHA256:                  true, // TLS 1.3
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       true,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         true,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
	}
	if !allowedAEAD[cs.CipherSuite] {
		t.Errorf("SECURITY: forged leaf negotiated non-AEAD/weak cipher 0x%04x (%s)",
			cs.CipherSuite, tls.CipherSuiteName(cs.CipherSuite))
	}

	if len(cs.PeerCertificates) == 0 {
		t.Fatal("no peer certificate presented on the inspected tunnel")
	}
	leaf := cs.PeerCertificates[0]
	if leaf.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("SECURITY: forged leaf key algorithm = %v, want ECDSA", leaf.PublicKeyAlgorithm)
	}
	if pk, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Errorf("SECURITY: forged leaf is not an ECDSA P-256 key: %T", leaf.PublicKey)
	}

	// ── Negative: a legacy (TLS 1.1-max) client MUST be refused ──
	raw, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer raw.Close() //nolint:errcheck // test cleanup
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := readCONNECT200(raw); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	// MinVersion TLS10 is load-bearing: without it the client's own default
	// minimum (TLS 1.2 since Go 1.22) makes the handshake fail LOCALLY before
	// any ClientHello, so the server floor would never be exercised. Forcing
	// the client to offer 1.0–1.1 makes the SERVER do the refusing.
	legacy := tls.Client(raw, &tls.Config{ //nolint:gosec // G402: versions pinned low ON PURPOSE to prove the server floor
		RootCAs:    proxyRoots,
		ServerName: "inspect.test",
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	})
	if err := legacy.HandshakeContext(context.Background()); err == nil {
		legacy.Close() //nolint:errcheck // test cleanup
		t.Error("SECURITY: forged-leaf server accepted a TLS 1.1 handshake — MinVersion floor not enforced")
	}
}
