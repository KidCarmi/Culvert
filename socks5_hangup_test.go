package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// socks5DialAndRequest opens a no-auth SOCKS5 session to ln and sends a CONNECT
// for host:port, returning the client side with the request written.
func socks5DialAndRequest(t *testing.T, ln net.Listener, host string, port uint16) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...) // #nosec G115 -- test host always short
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	return conn
}

// A SOCKS5 client that hangs up while the pre-flight SSRF guard is waiting on
// the resolver must release the guard's lookup — and with it the handler
// goroutine, its descriptor and its per-IP connection-limiter slot — instead of
// holding them for the full tunnelGuardBudget (10 s) and then the 10 s dial.
// The HTTP CONNECT/WebSocket sites get this from r.Context(); SOCKS5 had no
// request context at all. Asserts on WHY the lookup ended, not on elapsed time.
func TestSOCKS5_ClientHangupReleasesWedgedGuardLookup(t *testing.T) {
	setupProxyTest(t)
	w := installWedgedGuardResolver(t)
	ln := startSOCKS5Listener(t)

	conn := socks5DialAndRequest(t, ln, "hangup-socks5.example.test", 443)
	select {
	case <-w.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the guard never reached the resolver")
	}
	_ = conn.Close() // the client goes away while the resolver is silent

	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-w.exited:
		case <-time.After(5 * time.Second):
			close(w.release) // fail rather than hang the package
		}
	}()
	<-done
	p := w.cause.Load()
	if p == nil {
		t.Fatal("the guard's lookup was not cancelled when the SOCKS5 client hung up; it stays parked for the full guard budget")
	}
	if got := *p; !errors.Is(got, errSOCKS5ClientGone) {
		t.Fatalf("guard lookup ended with cause %v, want errSOCKS5ClientGone", got)
	}
}

// A client that sends data before the CONNECT reply ("optimistic data") is
// alive: the watcher must not cancel, and every byte it sent must reach the
// destination in order — the one the watcher consumed included.
func TestSOCKS5_OptimisticDataReachesDestination(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(ssrf.AllowLoopbackForTest())

	// Hold the guard's lookup until the client has written its early payload,
	// so the watcher is parked in Read when the payload arrives.
	payloadSent := make(chan struct{})
	t.Cleanup(ssrf.SetLookupHostForTest(func(ctx context.Context, _ string) ([]string, error) {
		select {
		case <-payloadSent:
			time.Sleep(50 * time.Millisecond) // let the watcher take its byte; correctness holds either way
			return []string{"127.0.0.1"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}))

	dest, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := dest.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b, _ := io.ReadAll(c)
		got <- b
	}()

	ln := startSOCKS5Listener(t)
	_, portStr, _ := net.SplitHostPort(dest.Addr().String())
	port, _ := strconv.Atoi(portStr)
	conn := socks5DialAndRequest(t, ln, "localhost", uint16(port)) // #nosec G115 -- ephemeral port < 65536
	const payload = "early-bytes-then-more"
	if _, err := conn.Write([]byte(payload[:11])); err != nil { // before the reply
		t.Fatal(err)
	}
	close(payloadSent)

	reply := make([]byte, 10)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading SOCKS5 reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS5 reply = 0x%02x, want 0x00 (a client sending early data is not a hang-up)", reply[1])
	}
	if _, err := conn.Write([]byte(payload[11:])); err != nil {
		t.Fatal(err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	select {
	case b := <-got:
		if string(b) != payload {
			t.Fatalf("destination received %q, want %q (an early byte was dropped or reordered)", b, payload)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("destination never received the payload")
	}
}

func TestSOCKS5HangupWatch_PeerCloseCancels(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	ctx, w := watchSOCKS5Hangup(srv, time.Time{})
	_ = cli.Close()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("peer close did not cancel the connect context")
	}
	if !socks5ClientGone(ctx) {
		t.Fatalf("cause = %v, want errSOCKS5ClientGone", context.Cause(ctx))
	}
	if early := w.stop(time.Time{}); early != nil {
		t.Fatalf("stop returned %q after a hang-up, want nil", early)
	}
}

func TestSOCKS5HangupWatch_EarlyByteKeptAndRestIntact(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	ctx, w := watchSOCKS5Hangup(srv, time.Time{})
	go func() { _, _ = cli.Write([]byte("AB")) }()
	<-w.done // the watcher took its byte and exited
	if ctx.Err() != nil {
		t.Fatalf("early data cancelled the connect context: %v", context.Cause(ctx))
	}
	if early := w.stop(time.Time{}); string(early) != "A" {
		t.Fatalf("stop returned %q, want %q", early, "A")
	}
	rest := make([]byte, 1)
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(srv, rest); err != nil || string(rest) != "B" {
		t.Fatalf("after stop, conn read %q, %v; want %q", rest, err, "B")
	}
}

func TestSOCKS5HangupWatch_StopOnSilentClientRestoresReads(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	ctx, w := watchSOCKS5Hangup(srv, time.Time{})
	if early := w.stop(time.Time{}); early != nil {
		t.Fatalf("stop returned %q for a silent client, want nil", early)
	}
	if socks5ClientGone(ctx) {
		t.Fatal("stopping the watch was misreported as a client hang-up")
	}
	// The expired deadline stop used must not leak into the relay.
	go func() { _, _ = cli.Write([]byte("Z")) }()
	b := make([]byte, 1)
	if _, err := io.ReadFull(srv, b); err != nil || b[0] != 'Z' {
		t.Fatalf("read after stop = %q, %v; want %q (read deadline not restored)", b, err, "Z")
	}
}

type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetReadDeadline(time.Time) error { return errors.New("deadlines unsupported") }

// A conn that cannot honour deadlines gets no watcher at all: a reader that
// could not be stopped would race the relay for client bytes.
func TestSOCKS5HangupWatch_NoDeadlineSupportIsInert(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	ctx, w := watchSOCKS5Hangup(noDeadlineConn{srv}, time.Time{})
	_ = cli.Close()
	if early := w.stop(time.Time{}); early != nil {
		t.Fatalf("inert watch returned %q", early)
	}
	if socks5ClientGone(ctx) {
		t.Fatal("inert watch reported a hang-up")
	}
}
