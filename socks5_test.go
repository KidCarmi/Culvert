package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// socks5HandshakeAuth performs a SOCKS5 handshake with username/password auth.
func socks5HandshakeAuth(t *testing.T, conn net.Conn, user, pass string) byte {
	t.Helper()

	// Greeting: VER=5, 1 method, USER/PASS (0x02)
	_, err := conn.Write([]byte{0x05, 0x01, 0x02})
	if err != nil {
		t.Fatalf("socks5 greeting write: %v", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("socks5 greeting read: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("socks5 greeting: unexpected %x", resp)
	}

	// Sub-negotiation: VER=1, ULEN, UNAME, PLEN, PASSWD
	authReq := []byte{0x01, byte(len(user))} // #nosec G115 -- test helper; user/pass always short
	authReq = append(authReq, []byte(user)...)
	authReq = append(authReq, byte(len(pass))) // #nosec G115
	authReq = append(authReq, []byte(pass)...)
	if _, err := conn.Write(authReq); err != nil {
		t.Fatalf("socks5 auth write: %v", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("socks5 auth read: %v", err)
	}
	return authResp[1] // 0x00 = success, 0x01 = failure
}

// startSOCKS5Listener starts a SOCKS5 listener and returns it.
// Caller must defer ln.Close().
func startSOCKS5Listener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5(conn)
		}
	}()
	return ln
}

func TestSOCKS5_Connect_SSRF_Blocks_Loopback(t *testing.T) {
	setupProxyTest(t)

	// Start a target HTTP server on 127.0.0.1.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("SOCKS5-OK"))
	}))
	defer target.Close()

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting
	conn.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	resp := make([]byte, 2)
	io.ReadFull(conn, resp) //nolint:errcheck

	// CONNECT to 127.0.0.1 — should be blocked by SSRF guard.
	tHost, tPort := targetHostPort(t, target.URL)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(tPort)) // #nosec G115 -- test port always < 65535
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(tHost))} // #nosec G115 -- test host always short
	req = append(req, []byte(tHost)...)
	req = append(req, portBuf...)
	conn.Write(req) //nolint:errcheck

	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	io.ReadFull(conn, reply)                               //nolint:errcheck
	if reply[1] != 0x02 { // 0x02 = connection not allowed (SSRF block)
		t.Errorf("expected SOCKS5 reply 0x02 (SSRF blocked), got 0x%02x", reply[1])
	}
}

func TestSOCKS5_Handshake_NoAuth(t *testing.T) {
	setupProxyTest(t)

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting: VER=5, 1 method, NO AUTH
	conn.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Errorf("expected [05 00], got %x", resp)
	}
}

func TestSOCKS5_UnsupportedCommand(t *testing.T) {
	setupProxyTest(t)

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting
	conn.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	resp := make([]byte, 2)
	io.ReadFull(conn, resp) //nolint:errcheck

	// UDP ASSOCIATE (CMD=3) — should be rejected (0x07 = command not supported)
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(req) //nolint:errcheck

	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	io.ReadFull(conn, reply)                               //nolint:errcheck
	if reply[1] != 0x07 {
		t.Errorf("expected SOCKS5 reply 0x07 (command not supported), got 0x%02x", reply[1])
	}
}

func TestSOCKS5_Blocked_Host(t *testing.T) {
	setupProxyTest(t)
	bl.Add("blocked.example.com")

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Greeting
	conn.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	resp := make([]byte, 2)
	io.ReadFull(conn, resp) //nolint:errcheck

	// CONNECT to blocked host
	host := "blocked.example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))} // #nosec G115 -- test host always short
	req = append(req, []byte(host)...)
	req = append(req, 0x00, 0x50) // port 80
	conn.Write(req)               //nolint:errcheck

	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	io.ReadFull(conn, reply)                               //nolint:errcheck
	if reply[1] != 0x02 { // 0x02 = connection not allowed
		t.Errorf("expected SOCKS5 reply 0x02 (blocked), got 0x%02x", reply[1])
	}
}

func TestSOCKS5_Auth_Success(t *testing.T) {
	setupProxyTest(t)
	if err := cfg.SetAuth("testuser", "testpass"); err != nil {
		t.Fatal(err)
	}

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	result := socks5HandshakeAuth(t, conn, "testuser", "testpass")
	if result != 0x00 {
		t.Fatalf("auth failed: 0x%02x", result)
	}
}

func TestSOCKS5_Auth_Failure(t *testing.T) {
	setupProxyTest(t)
	if err := cfg.SetAuth("testuser", "testpass"); err != nil {
		t.Fatal(err)
	}

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	result := socks5HandshakeAuth(t, conn, "testuser", "wrongpass")
	if result != 0x01 {
		t.Fatalf("expected auth failure 0x01, got 0x%02x", result)
	}
}

// targetHostPort extracts host and port from a test server URL.
func targetHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(rawURL[len("http://"):])
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
