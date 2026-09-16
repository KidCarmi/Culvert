package main

// Helpers for the CHAOS-66 gates. Kept apart from the gates themselves so the
// gate file reads as the finding it pins.

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type netListener = net.Listener

func newTestTCPListener() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }

// newObservedCollector is a TCP collector that accepts and drains, and reports
// on `closed` the first time an accepted connection reaches EOF — which is how
// a test observes that the forwarder released it.
func newObservedCollector(t *testing.T) (addr string, closed <-chan struct{}) {
	t.Helper()
	ln, err := newTestTCPListener()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan struct{})
	var once bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			first := !once
			once = true
			go func(c net.Conn, first bool) {
				buf := make([]byte, 512)
				for {
					if _, err := c.Read(buf); err != nil {
						if first {
							close(ch)
						}
						return
					}
				}
			}(c, first)
		}
	}()
	return ln.Addr().String(), ch
}

// reservedClosedPort returns an address nothing is listening on: a port is
// bound, its number captured, and the listener closed, so a dial to it is
// refused rather than hanging.
func reservedClosedPort(t *testing.T) string {
	t.Helper()
	ln, err := newTestTCPListener()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// renderSyslogMetrics captures the SIEM feed's Prometheus block.
func renderSyslogMetrics() string {
	var buf bytes.Buffer
	syslogWritePrometheus(&buf)
	return buf.String()
}

// resetSyslogReconnectForTest clears the reconnect campaign's record. Test
// isolation only; the caller is expected to have stopped any running campaign
// first (stopSyslogReconnect), which the gates' syslogTestReset does.
func resetSyslogReconnectForTest() {
	syslogReconnectState.mu.Lock()
	syslogReconnectState.running = false
	syslogReconnectState.stop = nil
	syslogReconnectState.attempts = 0
	syslogReconnectState.mu.Unlock()
}

var _ = time.Second
