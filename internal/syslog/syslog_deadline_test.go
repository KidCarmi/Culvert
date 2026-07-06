package syslog

// Write-deadline tests: a TCP collector that accepts but stops draining
// (SIEM overload, half-open peer) fills the kernel send buffer; without a
// write deadline, fmt.Fprint blocks forever while holding s.mu, stalling
// every request/audit-log caller proxy-wide.

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// deadlineRecordingConn is a fake net.Conn that records SetWriteDeadline
// calls and captures written bytes.
type deadlineRecordingConn struct {
	mu           sync.Mutex
	buf          bytes.Buffer
	deadlineSets int
	lastDeadline time.Time
	closed       bool
}

func (c *deadlineRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *deadlineRecordingConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlineSets++
	c.lastDeadline = t
	return nil
}

func (c *deadlineRecordingConn) Read([]byte) (int, error) { return 0, nil }
func (c *deadlineRecordingConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *deadlineRecordingConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (c *deadlineRecordingConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c *deadlineRecordingConn) SetDeadline(time.Time) error     { return nil }
func (c *deadlineRecordingConn) SetReadDeadline(time.Time) error { return nil }

func TestWriteMsg_SetsWriteDeadline(t *testing.T) {
	fake := &deadlineRecordingConn{}
	w := &Writer{
		network: "tcp",
		addr:    "192.0.2.1:514", // TEST-NET-1, never dialed: conn is pre-injected
		host:    "testhost",
		tag:     "culvert",
		format:  "rfc3164",
		pid:     "1",
		conn:    fake,
	}

	before := time.Now()
	w.writeMsg(14, "hello chaos")

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.deadlineSets == 0 {
		t.Fatal("writeMsg wrote without setting a write deadline; a stalled TCP collector would block the proxy forever")
	}
	if !fake.lastDeadline.After(before) {
		t.Errorf("write deadline %v is not in the future (before=%v)", fake.lastDeadline, before)
	}
	if maxExpected := before.Add(writeTimeout + time.Minute); fake.lastDeadline.After(maxExpected) {
		t.Errorf("write deadline %v unreasonably far out (want ~%v ahead)", fake.lastDeadline, writeTimeout)
	}
	if got := fake.buf.String(); !strings.Contains(got, "hello chaos") {
		t.Errorf("written line %q does not contain the message", got)
	}
}

// failingConn is a fake net.Conn whose writes always fail (a collector that
// accepts the TCP handshake but never drains, surfacing as deadline errors).
type failingConn struct{ deadlineRecordingConn }

func (c *failingConn) Write([]byte) (int, error) {
	return 0, &net.OpError{Op: "write", Err: errWouldBlock}
}

var errWouldBlock = &timeoutErr{}

type timeoutErr struct{}

func (*timeoutErr) Error() string { return "i/o timeout" }
func (*timeoutErr) Timeout() bool { return true }

// TestWriteMsg_RetryWriteFailureArmsBackoff pins the accepting-but-wedged
// collector case: connect() succeeds every time, so without arming the
// backoff on the RETRY write failure, every log call would pay
// ~2×writeTimeout serialized under s.mu (the backoff was only armed on
// connect failure). After one full failure cycle, calls within the backoff
// window must fast-drop.
func TestWriteMsg_RetryWriteFailureArmsBackoff(t *testing.T) {
	dials := 0
	w := &Writer{
		network: "tcp",
		addr:    "192.0.2.1:514", // TEST-NET-1, never dialed: dialFunc injected
		host:    "testhost",
		tag:     "culvert",
		format:  "rfc3164",
		pid:     "1",
		conn:    &failingConn{},
		dialFunc: func() (net.Conn, error) {
			dials++
			return &failingConn{}, nil // handshake accepted, writes wedge
		},
	}

	w.writeMsg(14, "first") // initial write fails → reconnect ok → retry fails
	if dials != 1 {
		t.Fatalf("dials after first call = %d, want 1", dials)
	}
	if w.conn != nil {
		t.Error("conn not cleared after retry-write failure")
	}
	if w.lastReconnErr.IsZero() {
		t.Fatal("backoff not armed after retry-write failure; every log call would pay the full write-timeout cycle")
	}
	if got := w.Drops(); got != 1 {
		t.Errorf("Drops() = %d, want 1", got)
	}

	w.writeMsg(14, "second") // within backoff window → fast drop, no dial
	if dials != 1 {
		t.Errorf("dials after second call = %d, want 1 (backoff window must suppress reconnect)", dials)
	}
	if got := w.Drops(); got != 2 {
		t.Errorf("Drops() after second call = %d, want 2", got)
	}
}
