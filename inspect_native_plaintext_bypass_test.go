package main

// SEC-INSPECT-PLAINTEXT-1, native-ALPN leg.
//
// The strip-ALPN inspect path refuses a client whose first byte is not a TLS
// handshake record (0x16). The native-ALPN leg — the one an InspectHTTP2
// profile or an explicit StripALPN=false rule selects — kept the raw-relay
// fallback and a comment calling itself a mirror of the strip path's, which it
// had stopped being. A client that simply did not start TLS therefore turned an
// inspect rule into a bypass: no inner-host pin, no file block, no DPI, no
// scan, no per-request log row, on a destination an operator marked for
// inspection.
//
// It was the MORE reachable of the two. The strip path handshakes the origin
// BEFORE it peeks, so its fallback needed an origin that speaks TLS and a
// client that does not; the native leg must wait for the client's ALPN offer,
// so the upstream handshake is still ahead of the peek and the CLIENT alone
// decided — against any origin, TLS or not. The tests below use a PLAIN TCP
// origin for exactly that reason: on the strip path such an origin is 502'd
// before the peek, so this is the reachability the native leg added.

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// nativeInspectPlaintextProbe runs one non-TLS client through a native-ALPN
// inspect tunnel to a PLAIN TCP origin and reports how many of the client's
// bytes reached that origin and how many bytes the client read back.
func nativeInspectPlaintextProbe(t *testing.T, payload string) (originGot int64, clientGot int) {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received := make(chan int64, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			received <- 0
			return
		}
		defer c.Close() //nolint:errcheck // test cleanup
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		received <- n
	}()

	proxyURL := startTestProxy(t)
	inspectRuleNative() // SSLInspect + StripALPN=false → handleInspectNativeALPN

	target := ln.Addr().String()
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := readCONNECT200(conn); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		// A refusal can close the client leg before this write lands; that is
		// the refusal working, not a test failure.
		t.Logf("write payload (refused leg is expected): %v", err)
	}
	clientGot, _ = io.ReadFull(conn, make([]byte, len(payload)))

	select {
	case originGot = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("the origin leg was neither relayed to nor closed")
	}
	return originGot, clientGot
}

// TestInspectNative_PlaintextClientCannotReachOriginUninspected is the
// regression gate: the client's plaintext must never reach the origin, and the
// client must get nothing back.
func TestInspectNative_PlaintextClientCannotReachOriginUninspected(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	setupInspectCA(t) // certMgr.Ready() ⇒ the inspect path is taken

	const payload = "SSH-2.0-nonTLS-probe-through-native-inspect"
	originGot, clientGot := nativeInspectPlaintextProbe(t, payload)

	if originGot != 0 {
		t.Errorf("the origin received %d of the client's plaintext bytes: a non-TLS client on a native-ALPN "+
			"inspect rule must be refused, never relayed (SEC-INSPECT-PLAINTEXT-1)", originGot)
	}
	if clientGot != 0 {
		t.Errorf("the client read %d bytes back: the refusal must not relay the origin's answer either", clientGot)
	}

	// The refusal is evidence, not a silent drop: it lands as a DECRYPT_FAILED
	// entry, and NO TUNNEL_CLOSED relay entry (nothing was relayed to account).
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := findDecFailEntry(t, "127.0.0.1"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no DECRYPT_FAILED entry recorded for the refused non-TLS client on the native leg")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if entry := findTunnelClose("127.0.0.1"); entry != nil {
		t.Errorf("a TUNNEL_CLOSED relay entry was recorded (%+v): nothing may have been relayed", *entry)
	}
}

// TestInspectNative_RefusalCoversEveryNonTLSFirstByte is the boundary/malformed
// sweep. The guard is a single-byte discriminator, so the bytes that bracket
// 0x16 and the ones a real non-TLS protocol opens with are the cases that
// matter: an off-by-one here is a bypass, not a cosmetic bug.
func TestInspectNative_RefusalCoversEveryNonTLSFirstByte(t *testing.T) {
	allowLoopbackTunnel(t)
	setupInspectCA(t)

	for _, tc := range []struct {
		name  string
		first byte
	}{
		{"nul", 0x00},
		{"below_tls_handshake", 0x15}, // 0x16-1: TLS alert record
		{"above_tls_handshake", 0x17}, // 0x16+1: TLS application data
		{"ssh_banner", 'S'},           // 0x53
		{"http_plaintext_get", 'G'},   // 0x47
		{"rdp_tpkt", 0x03},            // RDP/TPKT version
		{"high_bit", 0xFF},            // malformed / binary junk
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(reqlog.SwapRingForTest())
			payload := string([]byte{tc.first}) + "-payload-that-must-not-be-relayed"
			originGot, clientGot := nativeInspectPlaintextProbe(t, payload)
			if originGot != 0 {
				t.Errorf("first byte 0x%02x: the origin received %d bytes — refused means refused", tc.first, originGot)
			}
			if clientGot != 0 {
				t.Errorf("first byte 0x%02x: the client read %d bytes back", tc.first, clientGot)
			}
		})
	}
}

// TestInspectNative_ConcurrentPlaintextClientsAreAllRefused is the concurrency
// case. The refusal closes both legs and records an outcome from the request
// goroutine; a herd of refusals must not relay a single byte, deadlock, or
// corrupt the shared decrypt-failure plane.
func TestInspectNative_ConcurrentPlaintextClientsAreAllRefused(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	setupInspectCA(t)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	const clients = 8
	relayed := make(chan int64, clients)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck // test cleanup
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				n, _ := io.Copy(io.Discard, c)
				relayed <- n
			}(c)
		}
	}()

	proxyURL := startTestProxy(t)
	inspectRuleNative()
	target := ln.Addr().String()

	done := make(chan int, clients)
	for i := 0; i < clients; i++ {
		go func(i int) {
			conn, derr := dialTimeout(proxyURL.Host)
			if derr != nil {
				done <- -1
				return
			}
			defer conn.Close() //nolint:errcheck // test cleanup
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, werr := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); werr != nil {
				done <- -1
				return
			}
			if rerr := readCONNECT200(conn); rerr != nil {
				done <- -1
				return
			}
			payload := fmt.Sprintf("SSH-2.0-herd-%d", i)
			_, _ = conn.Write([]byte(payload))
			n, _ := io.ReadFull(conn, make([]byte, len(payload)))
			done <- n
		}(i)
	}

	for i := 0; i < clients; i++ {
		select {
		case n := <-done:
			if n > 0 {
				t.Errorf("a concurrent plaintext client read %d bytes back: every one must be refused", n)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("a concurrent refusal never completed — the refusal path deadlocked")
		}
	}

	// Drain whatever origin legs were accepted; none may carry client bytes.
	for {
		select {
		case n := <-relayed:
			if n != 0 {
				t.Errorf("an origin leg received %d relayed bytes under concurrency", n)
			}
		case <-time.After(500 * time.Millisecond):
			return
		}
	}
}
