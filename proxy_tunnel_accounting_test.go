package main

// proxy_tunnel_accounting_test.go — raw-relay observability (roadmap-day2
// Finding 11.1). Raw tunnels (WebSocket, CONNECT bypass, SOCKS5) were
// invisible in the structured request log: they emitted only logger.Printf
// system lines, so no LogEntry reached the Live Feed, JSONL export, syslog
// SIEM, or history store, and their bytes never fed the global counters.
//
// These tests drive REAL traffic through the REAL proxy listener/relay and
// assert a TUNNEL_CLOSED accounting entry (with byte counts + a duration)
// lands in the request-log ring — the fix's observable contract.

import (
	"bufio"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// findTunnelClose returns the newest TUNNEL_CLOSED ring entry for host, or
// nil. Polls briefly because the entry is written after both relay goroutines
// drain, which happens slightly after the client observes EOF.
func findTunnelClose(host string) *LogEntry {
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries := logGet()
		for i := range entries {
			if entries[i].Status == "TUNNEL_CLOSED" && entries[i].Host == host {
				return &entries[i]
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProxyE2E_WebSocket_RecordsTunnelClose(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)

	const clientPayload = "WS-CLIENT-BYTES"
	const serverPayload = "WS-SERVER-REPLY-BYTES-longer"

	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		ubr := bufio.NewReader(c)
		for { // drain request headers
			line, err := ubr.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		buf := make([]byte, len(clientPayload))
		if _, err := io.ReadFull(ubr, buf); err != nil {
			return
		}
		_, _ = c.Write([]byte(serverPayload))
	}()

	proxyURL := startTestProxy(t)
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	target := ln.Addr().String()
	req := "GET http://" + target + "/ws HTTP/1.1\r\nHost: " + target +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(req + clientPayload)); err != nil {
		t.Fatalf("write upgrade+payload: %v", err)
	}

	br := bufio.NewReader(conn)
	status, err := readConnectStatus(br)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", status)
	}
	// Read the server's reply so the target→client direction has bytes.
	got := make([]byte, len(serverPayload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read server reply: %v", err)
	}
	// Close the client side so both relay goroutines drain and the tunnel
	// close entry is written.
	_ = conn.Close()

	entry := findTunnelClose(target)
	if entry == nil {
		t.Fatal("no TUNNEL_CLOSED entry recorded for the WebSocket connection")
	}
	if entry.Method != "WS" {
		t.Errorf("Method = %q, want WS", entry.Method)
	}
	if entry.Level != "INFO" {
		t.Errorf("Level = %q, want INFO", entry.Level)
	}
	// client→dest is BytesSent; dest→client is BytesRecv.
	if entry.BytesSent < int64(len(clientPayload)) {
		t.Errorf("BytesSent = %d, want >= %d (client payload)", entry.BytesSent, len(clientPayload))
	}
	if entry.BytesRecv < int64(len(serverPayload)) {
		t.Errorf("BytesRecv = %d, want >= %d (server reply)", entry.BytesRecv, len(serverPayload))
	}
	if entry.DurationMs < 0 {
		t.Errorf("DurationMs = %d, want >= 0", entry.DurationMs)
	}
}

func TestProxyE2E_CONNECT_RecordsTunnelClose(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	echo := startEchoServer(t)
	proxyURL := startTestProxy(t)

	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("CONNECT " + echo.addr + " HTTP/1.1\r\nHost: " + echo.addr + "\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := readConnectStatus(br)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", status)
	}

	payload := []byte("connect-accounting-probe")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = conn.Close()

	entry := findTunnelClose(echo.addr)
	if entry == nil {
		t.Fatal("no TUNNEL_CLOSED entry recorded for the CONNECT bypass tunnel")
	}
	if entry.Method != "CONNECT" || entry.SSLAction != "bypass" {
		t.Errorf("Method/SSLAction = %q/%q, want CONNECT/bypass", entry.Method, entry.SSLAction)
	}
	// Echo server bounces the payload, so both directions must carry it.
	if entry.BytesSent < int64(len(payload)) {
		t.Errorf("BytesSent = %d, want >= %d", entry.BytesSent, len(payload))
	}
	if entry.BytesRecv < int64(len(payload)) {
		t.Errorf("BytesRecv = %d, want >= %d", entry.BytesRecv, len(payload))
	}
}

// TestTunnelClose_RespectsLogTrafficOff proves the per-rule "log traffic off"
// gate suppresses the TUNNEL_CLOSED FEED ENTRY (volume control) — but NOT the
// global byte accounting. A quiet-rule tunnel that transferred data must still
// move statBytesSent/statBytesRecv even though it writes no feed entry (PR
// review, Codex P2: the log gate must not blind the bytes dashboard).
func TestTunnelClose_RespectsLogTrafficOff(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	off := false
	match := &PolicyMatch{Rule: &PolicyRule{Name: "quiet-rule", LogTraffic: &off}}

	sent0 := atomic.LoadInt64(&statBytesSent)
	recv0 := atomic.LoadInt64(&statBytesRecv)
	before := len(logGet())

	recordTunnelCloseGated(match, ProxyIdentity{ClientIP: "203.0.113.5", Identity: "bob"},
		"CONNECT", "quiet.example:443", 900, 1700, time.Now().Add(-time.Second), "bypass")

	// No feed entry (gate suppressed it).
	if got := len(logGet()); got != before {
		t.Errorf("ring grew by %d; a LogTraffic=false tunnel must write no feed entry", got-before)
	}
	if findTunnelClose("quiet.example:443") != nil {
		t.Error("TUNNEL_CLOSED entry written despite LogTraffic=false")
	}
	// But bytes ARE counted globally.
	if got := atomic.LoadInt64(&statBytesSent) - sent0; got != 900 {
		t.Errorf("statBytesSent delta = %d, want 900 (bytes must count even when the entry is gated)", got)
	}
	if got := atomic.LoadInt64(&statBytesRecv) - recv0; got != 1700 {
		t.Errorf("statBytesRecv delta = %d, want 1700 (bytes must count even when the entry is gated)", got)
	}
}

// TestTunnelCloseGated_LogsWhenTrafficOn confirms the complementary case: a
// rule with logging on (or nil match) writes the feed entry AND counts bytes.
func TestTunnelCloseGated_LogsWhenTrafficOn(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	on := true
	match := &PolicyMatch{Rule: &PolicyRule{Name: "loud-rule", LogTraffic: &on}}

	sent0 := atomic.LoadInt64(&statBytesSent)
	recordTunnelCloseGated(match, ProxyIdentity{ClientIP: "203.0.113.6", Identity: "carol"},
		"WS", "loud.example:80", 500, 600, time.Now(), "")

	entry := findTunnelClose("loud.example:80")
	if entry == nil {
		t.Fatal("no TUNNEL_CLOSED entry for a log-enabled rule")
	}
	if entry.RuleMatched != "loud-rule" || entry.Identity != "carol" {
		t.Errorf("entry Rule/Identity = %q/%q, want loud-rule/carol", entry.RuleMatched, entry.Identity)
	}
	if got := atomic.LoadInt64(&statBytesSent) - sent0; got != 500 {
		t.Errorf("statBytesSent delta = %d, want 500", got)
	}
}

// TestRecordTunnelClose_FeedsGlobalByteCounters proves the relayed bytes feed
// the process-wide byte counters (previously only SSL-inspected bodies did).
func TestRecordTunnelClose_FeedsGlobalByteCounters(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	sent0 := atomic.LoadInt64(&statBytesSent)
	recv0 := atomic.LoadInt64(&statBytesRecv)

	recordTunnelClose("198.51.100.7", "WS", "chat.example:80", "alice", "allow-ws", 1200, 3400, time.Now().Add(-2*time.Second), "")

	if got := atomic.LoadInt64(&statBytesSent) - sent0; got != 1200 {
		t.Errorf("statBytesSent delta = %d, want 1200", got)
	}
	if got := atomic.LoadInt64(&statBytesRecv) - recv0; got != 3400 {
		t.Errorf("statBytesRecv delta = %d, want 3400", got)
	}
	entry := findTunnelClose("chat.example:80")
	if entry == nil {
		t.Fatal("no TUNNEL_CLOSED entry recorded")
	}
	if entry.Identity != "alice" || entry.RuleMatched != "allow-ws" {
		t.Errorf("Identity/RuleMatched = %q/%q, want alice/allow-ws", entry.Identity, entry.RuleMatched)
	}
	if entry.DurationMs < 1000 {
		t.Errorf("DurationMs = %d, want >= 1000 (started 2s ago)", entry.DurationMs)
	}
}
