package main

// proxy_slowloris_body_test.go — H2 fix coverage.
//
// stallDetectReadCloser wraps an http.Request.Body during SSL-inspect
// forwarding and re-arms the underlying net.Conn's read deadline on
// each Read. A peer that pauses longer than the timeout must trip the
// deadline; a peer that keeps sending bytes — even slowly — must be
// allowed to continue.

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDeadlineConn implements the subset of net.Conn used by
// stallDetectReadCloser (SetReadDeadline only). It tracks the most
// recent deadline so assertions can verify re-arming.
type fakeDeadlineConn struct {
	net.Conn // nil — unused methods would panic if called
	mu       chan struct{}
	last     atomic.Int64 // UnixNano of most recent SetReadDeadline
	calls    atomic.Int64
}

func newFakeDeadlineConn() *fakeDeadlineConn {
	return &fakeDeadlineConn{mu: make(chan struct{}, 1)}
}

func (f *fakeDeadlineConn) SetReadDeadline(t time.Time) error {
	f.calls.Add(1)
	f.last.Store(t.UnixNano())
	return nil
}

// TestStallDetectReadCloser_ReArmsDeadlineOnEachRead verifies the core
// contract: every Read re-arms the deadline, so a continuous transfer
// advances the window instead of running out.
func TestStallDetectReadCloser_ReArmsDeadlineOnEachRead(t *testing.T) {
	conn := newFakeDeadlineConn()
	body := io.NopCloser(bytes.NewReader([]byte("hello world hello world hello world")))
	sr := &stallDetectReadCloser{
		ReadCloser: body,
		conn:       conn,
		timeout:    5 * time.Second,
	}

	buf := make([]byte, 4)
	readsDone := 0
	for {
		n, err := sr.Read(buf)
		if n > 0 {
			readsDone++
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if readsDone < 2 {
		t.Fatalf("expected multiple Reads; got %d", readsDone)
	}
	if got := conn.calls.Load(); got < int64(readsDone) {
		t.Errorf("SetReadDeadline calls %d < Reads %d — deadline not re-armed per Read", got, readsDone)
	}
}

// TestStallDetectReadCloser_DeadlineAdvances verifies the re-armed
// deadline value actually moves forward between Reads — catches a
// regression where we'd use a fixed time.Time instead of time.Now().
func TestStallDetectReadCloser_DeadlineAdvances(t *testing.T) {
	conn := newFakeDeadlineConn()
	body := io.NopCloser(strings.NewReader("abcdefghij"))
	sr := &stallDetectReadCloser{
		ReadCloser: body,
		conn:       conn,
		timeout:    10 * time.Millisecond,
	}

	buf := make([]byte, 1)
	if _, err := sr.Read(buf); err != nil {
		t.Fatalf("first Read: %v", err)
	}
	first := conn.last.Load()
	time.Sleep(2 * time.Millisecond)
	if _, err := sr.Read(buf); err != nil {
		t.Fatalf("second Read: %v", err)
	}
	second := conn.last.Load()
	if second <= first {
		t.Errorf("deadline did not advance: first=%d second=%d", first, second)
	}
}

// TestStallDetectReadCloser_TripsOnStall exercises the real integration
// with a net.Pipe: one half pauses mid-stream, the deadline fires, the
// wrapped reader returns a timeout error. This is the actual attack
// model.
func TestStallDetectReadCloser_TripsOnStall(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	sr := &stallDetectReadCloser{
		ReadCloser: io.NopCloser(server),
		conn:       server,
		timeout:    50 * time.Millisecond,
	}

	// Writer sends one byte, then pauses forever.
	go func() {
		_, _ = client.Write([]byte("A"))
		// deliberately never send again
	}()

	buf := make([]byte, 1)
	n, err := sr.Read(buf)
	if err != nil || n != 1 || buf[0] != 'A' {
		t.Fatalf("first Read: n=%d err=%v buf=%q", n, err, buf[:n])
	}

	// Next Read should trip the deadline.
	start := time.Now()
	_, err = sr.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error; got nil — slowloris bypass still possible")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		// Some pipe errors surface as os.ErrDeadlineExceeded
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("expected net.Error Timeout or ErrDeadlineExceeded; got %v", err)
		}
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

// TestStallDetectReadCloser_SlowButSteadyCompletes verifies legitimate
// slow transfers are not broken: as long as bytes keep flowing inside
// the stall window, the reader delivers the full payload.
func TestStallDetectReadCloser_SlowButSteadyCompletes(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})

	sr := &stallDetectReadCloser{
		ReadCloser: io.NopCloser(server),
		conn:       server,
		timeout:    200 * time.Millisecond,
	}

	const payload = "hello-slow-but-steady"
	go func() {
		for _, b := range []byte(payload) {
			_, _ = client.Write([]byte{b})
			time.Sleep(30 * time.Millisecond) // inside stall window
		}
		_ = client.Close()
	}()

	var got []byte
	buf := make([]byte, 4)
	for {
		n, err := sr.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error after %d bytes: %v", len(got), err)
		}
	}
	if string(got) != payload {
		t.Errorf("payload mismatch: got %q, want %q", got, payload)
	}
}

// TestStallDetectReadCloser_CloseDelegates confirms the embedded
// ReadCloser's Close is still reachable, so the outer http.Request
// shutdown path works unchanged.
func TestStallDetectReadCloser_CloseDelegates(t *testing.T) {
	closed := false
	body := &closeTracker{
		Reader: bytes.NewReader([]byte("x")),
		onClose: func() error {
			closed = true
			return nil
		},
	}
	sr := &stallDetectReadCloser{
		ReadCloser: body,
		conn:       newFakeDeadlineConn(),
		timeout:    time.Second,
	}
	if err := sr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Error("underlying ReadCloser.Close was not called")
	}
}

type closeTracker struct {
	io.Reader
	onClose func() error
}

func (c *closeTracker) Close() error { return c.onClose() }
