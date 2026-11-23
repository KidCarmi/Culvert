package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
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

// The early byte is part of the upstream byte total: TUNNEL_CLOSED BytesSent
// must count it, not just the bytes the relay copied afterwards.
func TestSOCKS5RelayPrefixed_CountsEarlyBytes(t *testing.T) {
	isolateDrainRegistry(t)
	t.Cleanup(reqlog.SwapRingForTest())
	clientA, clientB := tcpPair(t)
	destA, destB := tcpPair(t)
	const host = "early-count-socks5.test:443"

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		socks5RelayPrefixed(clientB, destA, []byte("A"), "203.0.113.20", host)
	}()
	if _, err := clientA.Write([]byte("B")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 2)
	_ = destB.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(destB, got); err != nil || string(got) != "AB" {
		t.Fatalf("destination read %q, %v; want %q", got, err, "AB")
	}
	_ = clientA.Close()
	_ = destB.Close()
	select {
	case <-relayDone:
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not finish after both peers closed")
	}
	entry := findTunnelClose(host)
	if entry == nil {
		t.Fatal("no TUNNEL_CLOSED entry recorded")
	}
	if entry.BytesSent != 2 {
		t.Fatalf("BytesSent = %d, want 2 (early byte + relayed byte)", entry.BytesSent)
	}
}

// SEC-SOCKS5-ABANDONED-ROW-1. A SOCKS5 client must not be able to erase its
// own request-log row by hanging up.
//
// Before the connect phase became cancellable the guard always ran to
// completion under context.Background(), so EVERY non-nil
// isPrivateHostBounded error wrote one row (status BLOCKED). Making the
// pre-flight cancellable introduced an outcome that is neither blocked nor
// allowed — the client left while the resolver was still working — and waiving
// the row for it let an attacker probe internal hosts over SOCKS5 and leave
// nothing in the request log: on a cache MISS the cancellation surfaces as
// ssrf.lookupAbandoned, which is deliberately never ErrBlocked, so the waiver
// applied on exactly the probes that matter.
//
// The verdict is still withheld (socks5StatusAbandoned, not BLOCKED) because
// nothing was demonstrated about the destination; only the attempt is kept.
func TestSOCKS5_AbandonedPreflightStillRecordsTheAttempt(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(reqlog.SwapRingForTest())
	w := installWedgedGuardResolver(t)
	ln := startSOCKS5Listener(t)

	const probed = "abandoned-preflight.example.test"
	conn := socks5DialAndRequest(t, ln, probed, 443)
	select {
	case <-w.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the guard never reached the resolver")
	}
	_ = conn.Close() // the client goes away mid-check: verdict undecided

	e := awaitSOCKS5Row(t, probed)
	if e.Status != socks5StatusAbandoned {
		t.Fatalf("abandoned pre-flight recorded status %q, want %q — a client that hangs up during an undecided SSRF pre-flight must still leave an attempt row (it previously left a BLOCKED one)",
			e.Status, socks5StatusAbandoned)
	}
	if e.IP == "" {
		t.Error("the abandoned row carries no client IP, so it cannot attribute the probe")
	}
}

// The companion control: when the destination IS demonstrated private, the row
// is still the BLOCKED verdict and not the undecided status, whether or not the
// client is still there. Fails if a fix for the case above were to downgrade a
// real SSRF refusal.
func TestSOCKS5_DemonstratedPrivateDestinationStillRecordsBlocked(t *testing.T) {
	setupProxyTest(t)
	t.Cleanup(reqlog.SwapRingForTest())
	t.Cleanup(ssrf.SetLookupHostForTest(func(_ context.Context, _ string) ([]string, error) {
		return []string{"127.0.0.1"}, nil
	}))
	ln := startSOCKS5Listener(t)

	const probed = "demonstrated-private.example.test"
	_ = socks5DialAndRequest(t, ln, probed, 443)

	e := awaitSOCKS5Row(t, probed)
	if e.Status != "BLOCKED" {
		t.Fatalf("a destination that resolves to a private address recorded status %q, want BLOCKED", e.Status)
	}
}

// awaitSOCKS5Row waits for the SOCKS5 handler to write the request-log row for
// host and returns it. The handler runs detached, so the row appears after the
// client's own call returns.
func awaitSOCKS5Row(t *testing.T, host string) reqlog.Entry {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rows := reqlog.Get()
		for i := range rows { // index-based: Entry is large (conventions.md)
			if rows[i].Method == "SOCKS5" && strings.HasPrefix(rows[i].Host, host) {
				return rows[i]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no SOCKS5 request-log row for %q within the deadline: the attempt was not recorded at all", host)
	return reqlog.Entry{}
}
