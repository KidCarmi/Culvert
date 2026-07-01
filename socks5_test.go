package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
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

// startSOCKS5Listener starts a SOCKS5 listener and returns it. Callers may
// still `defer ln.Close()` (the double-close is harmless); a t.Cleanup also
// drains in-flight handlers.
//
// The drain is load-bearing for determinism, not cosmetic: handleSOCKS5 reads
// the global stores (bl, ipf, cfg). If a handler goroutine outlives its test,
// it races against the NEXT test's setupProxyTest, which rewrites those same
// globals — a real data race surfaced under `-race -shuffle=on`. Cleanup marks
// the listener closed, force-closes every accepted conn (so a handler blocked
// in Read returns promptly), waits for the accept loop to exit, then waits for
// all handlers — guaranteeing no handler can touch globals after the test ends.
func startSOCKS5Listener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu       sync.Mutex
		closed   bool
		conns    []net.Conn
		handlers sync.WaitGroup
	)
	var acceptLoop sync.WaitGroup
	acceptLoop.Add(1)
	go func() {
		defer acceptLoop.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				continue
			}
			conns = append(conns, conn)
			handlers.Add(1) // under mu: never races handlers.Wait (see cleanup)
			mu.Unlock()
			go func(c net.Conn) {
				defer handlers.Done()
				handleSOCKS5(c)
			}(conn)
		}
	}()

	t.Cleanup(func() {
		mu.Lock()
		closed = true
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		_ = ln.Close()
		acceptLoop.Wait() // accept loop has exited → no further handlers.Add
		handlers.Wait()   // all handlers drained → no global reads after this point
	})
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
	binary.BigEndian.PutUint16(portBuf, uint16(tPort))      // #nosec G115 -- test port always < 65535
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(tHost))} // #nosec G115 -- test host always short
	req = append(req, []byte(tHost)...)
	req = append(req, portBuf...)
	conn.Write(req) //nolint:errcheck

	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	io.ReadFull(conn, reply)                              //nolint:errcheck
	if reply[1] != 0x02 {                                 // 0x02 = connection not allowed (SSRF block)
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
	io.ReadFull(conn, reply)                              //nolint:errcheck
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
	io.ReadFull(conn, reply)                              //nolint:errcheck
	if reply[1] != 0x02 {                                 // 0x02 = connection not allowed
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

func TestSOCKS5_IPv6_ATYP04(t *testing.T) {
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

	// CONNECT with ATYP=0x04 (IPv6), address ::1, port 80.
	// The handler should parse 16 bytes and format with brackets.
	// ::1 is loopback so SSRF guard will block it with reply 0x02.
	ipv6 := net.ParseIP("::1").To16()
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, ipv6...)
	req = append(req, 0x00, 0x50) // port 80
	conn.Write(req)               //nolint:errcheck

	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	io.ReadFull(conn, reply)                              //nolint:errcheck
	// 0x02 = connection not allowed (SSRF blocks loopback IPv6)
	if reply[1] != 0x02 {
		t.Errorf("expected SOCKS5 reply 0x02 (SSRF blocked IPv6 loopback), got 0x%02x", reply[1])
	}
}

func TestSOCKS5_UnsupportedAddressType(t *testing.T) {
	setupProxyTest(t)

	for _, atyp := range []byte{0x02, 0xFF} {
		t.Run(fmt.Sprintf("ATYP_0x%02x", atyp), func(t *testing.T) {
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

			// CONNECT with unsupported ATYP
			req := []byte{0x05, 0x01, 0x00, atyp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50}
			conn.Write(req) //nolint:errcheck

			reply := make([]byte, 10)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
			io.ReadFull(conn, reply)                              //nolint:errcheck
			if reply[1] != 0x08 {
				t.Errorf("expected SOCKS5 reply 0x08 (address type not supported), got 0x%02x", reply[1])
			}
		})
	}
}

func TestSOCKS5_AuthRequired_ClientNoAuth(t *testing.T) {
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

	// Greeting: only offer NO_AUTH (0x00) when server requires auth
	conn.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck

	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	// Server should reply {0x05, 0xFF} — no acceptable method
	if resp[0] != 0x05 || resp[1] != 0xFF {
		t.Errorf("expected [05 FF] (no acceptable method), got %x", resp)
	}
}

func TestSOCKS5_BindCommand_Rejected(t *testing.T) {
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

	// BIND (CMD=0x02) — should be rejected with 0x07
	req := []byte{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50}
	conn.Write(req) //nolint:errcheck

	reply := make([]byte, 10)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	io.ReadFull(conn, reply)                              //nolint:errcheck
	if reply[1] != 0x07 {
		t.Errorf("expected SOCKS5 reply 0x07 (command not supported), got 0x%02x", reply[1])
	}
}

func TestSOCKS5_PartialGreeting_CloseCleanly(t *testing.T) {
	setupProxyTest(t)

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Send only the version byte then close the connection.
	// The handler should exit cleanly without panicking.
	conn.Write([]byte{0x05}) //nolint:errcheck
	conn.Close()

	// If the handler panicked, the test runner would catch it.
	// Give a moment for the goroutine to process the partial read.
	time.Sleep(100 * time.Millisecond)
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
