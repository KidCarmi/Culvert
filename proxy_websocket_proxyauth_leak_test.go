package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Proxy-Authorization is the client's credential FOR THIS PROXY (the local
// account password, an LDAP password, or an OIDC access token — see
// resolveRequestAuth arm 2). It is hop-by-hop and must never reach an origin.
// handleHTTP and the SSL-inspect exchange both strip it via removeHopHeaders;
// handleWebSocket only ran scrubForwardedHeaders, which does not, and then
// serialised the request to the origin with r.Write.
//
// So the two client-chosen headers "Upgrade: websocket" + "Connection: Upgrade"
// were enough to make the proxy hand the user's proxy password, in cleartext,
// to whatever plain-HTTP origin the request named — whether or not that origin
// then upgraded.
//
// The undressed request runs first as a control: it proves the fixture would
// observe the header if it were forwarded, and that the plain path strips it.
func TestWebSocketUpgrade_DoesNotForwardProxyAuthorizationToOrigin(t *testing.T) {
	const user, pass = "alice", "proxy-only-s3cret" //nolint:gosec // G101: fixture credential for a test-local account
	cred := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))

	originAddr, heads := startHeadRecordingOrigin(t)

	allowLoopbackTunnel(t)
	proxyURL := startTestProxy(t) // default-allow, real listener
	// A real local account, so the credential below is one the proxy verifies.
	testCfg := cfg
	if err := cfg.SetAuth(user, pass); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() {
		if cfg == testCfg {
			_ = cfg.SetAuth("", "")
		}
	})

	send := func(t *testing.T, path, extraHeaders string) (originHead, proxyStatus string) {
		t.Helper()
		conn, derr := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", proxyURL.Host)
		if derr != nil {
			t.Fatalf("dial proxy: %v", derr)
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, werr := fmt.Fprintf(conn, "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n%s\r\n",
			originAddr, path, originAddr, cred, extraHeaders); werr != nil {
			t.Fatalf("write request: %v", werr)
		}
		status, rerr := bufio.NewReader(conn).ReadString('\n')
		if rerr != nil {
			t.Fatalf("read proxy status line: %v", rerr)
		}
		select {
		case h := <-heads:
			return h, strings.TrimSpace(status)
		case <-time.After(5 * time.Second):
			t.Fatalf("origin never received the request (proxy answered %q)", strings.TrimSpace(status))
			return "", ""
		}
	}
	const dress = "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"

	// Control: the plain forward path authenticates the user and strips the header.
	head, status := send(t, "/plain", "")
	if !strings.Contains(status, " 200") {
		t.Fatalf("control: plain GET status = %q, want 200 (the credential must be accepted)", status)
	}
	if strings.Contains(strings.ToLower(head), "proxy-authorization") {
		t.Fatalf("control: plain GET forwarded Proxy-Authorization — fixture or baseline is wrong:\n%s", head)
	}

	for _, tc := range []struct{ name, path, wantStatus string }{
		{"origin upgrades (101)", "/accept", " 101"},
		{"origin declines (200)", "/decline", " 200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			head, status := send(t, tc.path, dress)
			if !strings.Contains(status, tc.wantStatus) {
				t.Fatalf("proxy status = %q, want%s", status, tc.wantStatus)
			}
			lower := strings.ToLower(head)
			if strings.Contains(lower, "proxy-authorization") || strings.Contains(head, cred) {
				t.Errorf("Upgrade-dressed request delivered the client's PROXY credential to the origin:\n%s", head)
			}
			// The handshake itself must survive the strip.
			for _, want := range []string{"upgrade: websocket", "connection: upgrade", "sec-websocket-key: dghlihnhbxbszsbub25jzq=="} {
				if !strings.Contains(lower, want) {
					t.Errorf("origin did not receive %q — the upgrade handshake was damaged:\n%s", want, head)
				}
			}
		})
	}
}

// startHeadRecordingOrigin is a raw plain-HTTP origin that reports the request
// head of every request it receives, then answers 101 for /accept and an
// ordinary 200 for everything else.
func startHeadRecordingOrigin(t *testing.T) (addr string, heads <-chan string) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup
	out := make(chan string, 8)
	serve := func(conn net.Conn) {
		defer conn.Close() //nolint:errcheck // test cleanup
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(conn)
		var head strings.Builder
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
			head.WriteString(line)
		}
		out <- head.String()
		if strings.HasPrefix(head.String(), "GET /accept ") {
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serve(conn)
		}
	}()
	return ln.Addr().String(), out
}
