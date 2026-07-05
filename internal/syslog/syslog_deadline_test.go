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
