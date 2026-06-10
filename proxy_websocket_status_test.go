package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// handleWebSocket must only hijack the connection into a raw tunnel when the
// upstream actually completes the handshake (HTTP 101). If the upstream
// declines the upgrade, the response is relayed and the connection is NOT
// tunneled — otherwise a client could pipeline arbitrary bytes to the target
// over a keep-alive connection, bypassing per-request HTTP policy and scanning.
//
// httptest.ResponseRecorder does not implement http.Hijacker, so the pre-fix
// code (which reached the hijack path on any status) returned 500
// "Hijacking not supported"; the fixed code relays the upstream's 403.
func TestHandleWebSocket_Non101NotTunneled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		// Drain the forwarded request up to the end of headers.
		br := bufio.NewReader(conn)
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		// Upstream declines the WebSocket upgrade.
		_, _ = io.WriteString(conn,
			"HTTP/1.1 403 Forbidden\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnope!")
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	hostport := "127.0.0.1:" + port

	// Bypass the two SSRF layers for the loopback test target: seed the DNS
	// cache so isPrivateHost passes, and swap the dialer so ssrfControl does
	// not reject the loopback connect. Both are restored on cleanup.
	ssrfDNSCache.Store("127.0.0.1", false)
	origDial := ssrfSafeDialContext
	ssrfSafeDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	t.Cleanup(func() {
		ssrfSafeDialContext = origDial
		ssrfDNSCache.mu.Lock()
		delete(ssrfDNSCache.entries, "127.0.0.1")
		ssrfDNSCache.mu.Unlock()
	})

	r := httptest.NewRequest(http.MethodGet, "http://"+hostport+"/ws", http.NoBody)
	r.Host = hostport
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	w := httptest.NewRecorder()

	handleWebSocket(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (upstream's declined-upgrade response must be relayed, not tunneled); body=%q",
			w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != "nope!" {
		t.Fatalf("body = %q, want %q (upstream response body must be relayed)", got, "nope!")
	}
}
