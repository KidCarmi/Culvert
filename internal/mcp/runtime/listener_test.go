package runtime

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// startInsecureRuntime binds a Gateway-only insecure runtime on an ephemeral port
// and returns it plus the bound address. It registers cleanup.
func startInsecureRuntime(t *testing.T, k *esKey) (*Runtime, string) {
	t.Helper()
	g := gwListenerConfig(t)
	g.Port = 0 // ephemeral
	cfg := RuntimeConfig{Gateway: g, Deps: testDeps(t, k, NewBoundedSink(64))}
	rt, err := NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rt.Shutdown(ctx)
	})
	return rt, rt.Addr(false)
}

// rawPost writes one HTTP/1.1 POST on conn and returns the parsed response.
func rawPost(t *testing.T, conn net.Conn, br *bufio.Reader, host, token string, body []byte) *http.Response {
	t.Helper()
	var sb strings.Builder
	fmt.Fprintf(&sb, "POST %s HTTP/1.1\r\n", gwResource)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)
	if token != "" {
		fmt.Fprintf(&sb, "Authorization: Bearer %s\r\n", token)
	}
	fmt.Fprintf(&sb, "Content-Type: application/json\r\nContent-Length: %d\r\n\r\n", len(body))
	sb.Write(body)
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		t.Fatalf("write: %v", err)
	}
	req, _ := http.NewRequest("POST", gwResource, nil)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// TestListener_HostRecheckedPerRequestH11 is the MCP-INSP-009 H1.1 reuse proof: a
// valid first request on a keep-alive connection must NOT authorize a malicious
// second request that changes the Host on the SAME connection.
func TestListener_HostRecheckedPerRequestH11(t *testing.T) {
	k := newESKey(t, "k1")
	_, addr := startInsecureRuntime(t, k)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Request 1: valid host + auth → 200 initialize.
	r1 := rawPost(t, conn, br, gwHost, gwToken(k), initializeBody(1))
	if r1.StatusCode != 200 {
		t.Fatalf("first request status = %d, want 200", r1.StatusCode)
	}
	if r1.Header.Get("Mcp-Session-Id") == "" {
		t.Fatal("first request did not assign a session id")
	}

	// Request 2 on the SAME connection with a spoofed Host → 403 host_rejected.
	r2 := rawPost(t, conn, br, "evil.example.com", gwToken(k), initializeBody(2))
	if r2.StatusCode != 403 {
		t.Fatalf("reused-connection spoofed-host request status = %d, want 403", r2.StatusCode)
	}
}

// TestListener_HostRecheckedPerStreamH2 is the MCP-INSP-009 H2 reuse proof: two
// streams on the SAME HTTP/2 connection changing :authority are each re-checked.
func TestListener_HostRecheckedPerStreamH2(t *testing.T) {
	k := newESKey(t, "k1")
	l, err := newListener(gwTLSListenerConfig(t, k), testDeps(t, k, NewBoundedSink(64)), "gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	srv := httptest.NewUnstartedServer(l)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	client := srv.Client()
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = true

	post := func(host string, body []byte) int {
		req, _ := http.NewRequest("POST", srv.URL+gwResource, strings.NewReader(string(body)))
		req.Host = host // becomes :authority on the H2 stream
		req.Header.Set("Authorization", "Bearer "+gwToken(k))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("not HTTP/2 (proto %d.%d) — H2 reuse not exercised", resp.ProtoMajor, resp.ProtoMinor)
		}
		return resp.StatusCode
	}
	if s := post(gwHost, initializeBody(1)); s != 200 {
		t.Fatalf("valid-host H2 stream = %d, want 200", s)
	}
	if s := post("evil.example.com", initializeBody(2)); s != 403 {
		t.Fatalf("spoofed-host H2 stream = %d, want 403 (per-stream recheck)", s)
	}
}

// gwTLSListenerConfig returns a Gateway listener config with a TLS config (for the
// httptest TLS server; httptest supplies its own cert, so TLS here is only present
// so the config validates as a real — non-AllowInsecure — listener).
func gwTLSListenerConfig(t testing.TB, _ *esKey) ListenerConfig {
	t.Helper()
	c := gwListenerConfig(t)
	c.AllowInsecure = false
	c.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	return c
}

// TestPeerThumbprint verifies the mTLS thumbprint derivation: it is the unpadded
// base64url SHA-256 of the peer cert DER and never a client-supplied header.
func TestPeerThumbprint(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("fake-der-bytes-for-hashing")}
	r, _ := http.NewRequest("POST", "/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	r.Header.Set("X-Client-Cert-Thumbprint", "attacker-supplied") // must be ignored

	got := peerThumbprint(r, ClientCertRequire)
	if got == "" {
		t.Fatal("no thumbprint derived from a verified peer cert")
	}
	if got == "attacker-supplied" {
		t.Fatal("thumbprint came from a client-supplied header")
	}
	// None-mode never derives a thumbprint.
	if peerThumbprint(r, ClientCertNone) != "" {
		t.Fatal("thumbprint derived in ClientCertNone mode")
	}
}
