package main

// proxy_tunnel_drain_chaos_test.go — CHAOS-57 gates for register row PX-8:
// hijacked tunnels the shutdown drain could not see, and had no way to end.
//
// Every DEFECT gate below was verified failing against the pre-fix tree. The
// CONTROL gates exist because the two cheapest wrong fixes both pass the defect
// gates: a drain that force-closes everything immediately (no grace at all), and a
// registry whose release is not idempotent (a gauge that drifts negative until the
// drain never waits again).

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// tcpPair returns two ends of a real connected TCP conn. net.Pipe is deliberately
// NOT used: it is synchronous and in-memory, so it cannot exercise the thing under
// test — a relay parked in a deadline-less io.Copy that only a Close can end.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test helper
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err = dialTimeout(ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.c.Close() })
	return client, r.c
}

// withShortDrainWindow shrinks the drain window for the duration of a test so a
// deadline-backstop gate does not cost 15 real seconds.
func withShortDrainWindow(t *testing.T, d time.Duration) {
	t.Helper()
	prev := tunnelDrainWindow
	tunnelDrainWindow = d
	t.Cleanup(func() { tunnelDrainWindow = prev })
}

// isolateDrainRegistry gives a test its own view of the process-global registry and
// counters, and restores nothing to a later test (the PR3d fence-pollution class).
func isolateDrainRegistry(t *testing.T) {
	t.Helper()
	resetTunnelDrainRegistryForTest()
	t.Cleanup(resetTunnelDrainRegistryForTest)
}

// ─────────────────────────────────────────────────────────────────────────────
// DEFECT GATES — each fails against the pre-fix tree.
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos57_SOCKS5TunnelIsVisibleToTheDrain is the headline gate. socks5_shutdown_test.go's
// own header records the deferral this closes: "In-flight SOCKS5 tunnels are NOT
// drained — that is explicitly out of scope for P1.5 (tracked for Phase 2)." Because
// socks5Server.Stop waits only for the ACCEPT LOOP and every session runs in a
// detached `go handleSOCKS5(conn)`, a live SSH-over-SOCKS5 session touched no counter
// the shutdown sequence reads: the drain saw zero and returned instantly.
func TestChaos57_SOCKS5TunnelIsVisibleToTheDrain(t *testing.T) {
	isolateDrainRegistry(t)
	t.Cleanup(reqlog.SwapRingForTest())

	clientA, clientB := tcpPair(t)
	destA, destB := tcpPair(t)

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		socks5Relay(clientB, destA, "203.0.113.7", "chaos57-socks5.test:22")
	}()

	if !waitForActiveConns(t, 1, 2*time.Second) {
		t.Fatalf("activeConns = %d with a live SOCKS5 relay; the shutdown drain cannot see it and severs it with zero grace",
			getActiveConns())
	}
	if got := atomic.LoadInt64(&tunnelClassActive[tunnelClassSOCKS5]); got != 1 {
		t.Errorf("culvert_tunnels_active{class=socks5} = %d, want 1", got)
	}

	_ = clientA.Close()
	_ = destB.Close()
	<-relayDone
}

// TestChaos57_WebSocketTunnelIsVisibleToTheDrain drives a REAL WebSocket upgrade
// through the REAL proxy listener and asserts the established tunnel is counted while
// it is live. A hijacked conn is invisible to http.Server.Shutdown by construction, so
// before this change a live WS session was severed by process exit while a CONNECT
// tunnel on the same node, at the same instant, got the full 15s grace.
func TestChaos57_WebSocketTunnelIsVisibleToTheDrain(t *testing.T) {
	isolateDrainRegistry(t)
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)

	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	upstreamReady := make(chan struct{})
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
		close(upstreamReady)
		// Hold the tunnel open until the client goes away, so the gate observes a
		// LIVE tunnel rather than a closing one.
		_, _ = io.Copy(io.Discard, ubr)
	}()

	proxyURL := startTestProxy(t)
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: " + ln.Addr().String() + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	// A 1xx response is bodyless by construction (net/http's fixLength returns 0
	// for status/100 == 1), so this Close is a no-op that does not touch the
	// hijacked conn the rest of the test relies on — it satisfies bodyclose
	// without draining the tunnel.
	defer resp.Body.Close() //nolint:errcheck // bodyless 1xx; close is a no-op
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	select {
	case <-upstreamReady:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never completed the upgrade")
	}

	if !waitForActiveConns(t, 1, 3*time.Second) {
		t.Fatalf("activeConns = %d with a live WebSocket tunnel; the shutdown drain cannot see it", getActiveConns())
	}
	if got := atomic.LoadInt64(&tunnelClassActive[tunnelClassWebSocket]); got != 1 {
		t.Errorf("culvert_tunnels_active{class=websocket} = %d, want 1", got)
	}

	// Tear the tunnel down and WAIT for the relay to actually release before the
	// test returns. This is not tidiness — it is the determinism contract. The
	// relay releases on its own goroutine some time after the client conn closes,
	// so without this wait `isolateDrainRegistry`'s cleanup can zero activeConns
	// FIRST and the late release then decrements it to -1. A negative activeConns
	// makes `active <= 0` true for every later test, so the next test that expects
	// the drain to WAIT would see it return immediately — this test would silently
	// break a different one, and only under `-shuffle=on`.
	_ = conn.Close()
	if !waitForActiveConnsZero(t, 5*time.Second) {
		t.Fatalf("WebSocket tunnel did not release after the client closed (activeConns = %d)", getActiveConns())
	}
}

// TestChaos57_SeveredTunnelStillRecordsItsAccounting is the data-integrity gate, and
// the one that makes the registry more than a counter. recordTunnelClose runs only
// AFTER both relay goroutines drain, so a tunnel killed by process exit never reaches
// it: every graceful shutdown silently dropped the bytes and duration of every
// in-flight WebSocket and SOCKS5 session from the request log, the JSONL export, the
// SIEM feed and the dashboard totals. Force-closing at the drain deadline unblocks the
// relays so that entry is actually written — and the bounded settle keeps it ahead of
// the flush hooks instead of leaving the ordering to luck.
func TestChaos57_SeveredTunnelStillRecordsItsAccounting(t *testing.T) {
	isolateDrainRegistry(t)
	t.Cleanup(reqlog.SwapRingForTest())
	withShortDrainWindow(t, 200*time.Millisecond)

	const host = "chaos57-accounting.test:22"
	clientA, clientB := tcpPair(t)
	destA, destB := tcpPair(t)
	// Neither peer ever sends or closes: this is the long-lived idle session the
	// drain used to abandon.
	_ = clientA
	_ = destB

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		socks5Relay(clientB, destA, "203.0.113.8", host)
	}()
	if !waitForActiveConns(t, 1, 2*time.Second) {
		t.Fatal("relay never registered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := drainActiveTunnels(ctx); err != nil {
		t.Fatalf("drainActiveTunnels: %v", err)
	}

	select {
	case <-relayDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the drain deadline did not end the tunnel: its relay is still parked in io.Copy")
	}
	if e := findTunnelClose(host); e == nil {
		t.Fatal("no TUNNEL_CLOSED entry for a tunnel the drain severed — the byte accounting for every in-flight raw tunnel is lost on every shutdown")
	}
}

// TestChaos57_DrainWaitsForAHijackedTunnel proves the drain now WAITS on a class it
// used to be blind to, rather than returning instantly and letting process exit reset
// the session.
func TestChaos57_DrainWaitsForAHijackedTunnel(t *testing.T) {
	isolateDrainRegistry(t)
	withShortDrainWindow(t, 10*time.Second)

	c1, _ := tcpPair(t)
	c2, _ := tcpPair(t)
	release := registerDrainableTunnel(tunnelClassWebSocket, c1, c2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = drainActiveTunnels(ctx) }()

	select {
	case <-done:
		t.Fatal("drain returned immediately with a live WebSocket tunnel — it is still blind to the class")
	case <-time.After(700 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("drain did not finish after the tunnel released")
	}
}

// TestChaos57_DrainDeadlineForceClosesEveryClass pins the backstop's coverage. It is
// separate from the accounting gate because a registry that holds only SOME classes
// would still pass that one.
func TestChaos57_DrainDeadlineForceClosesEveryClass(t *testing.T) {
	isolateDrainRegistry(t)
	withShortDrainWindow(t, 150*time.Millisecond)

	classes := []tunnelClass{
		tunnelClassConnectBypass,
		tunnelClassConnectInspect,
		tunnelClassInspectFallback,
		tunnelClassWebSocket,
		tunnelClassSOCKS5,
	}
	peers := make([]net.Conn, 0, len(classes))
	for _, cl := range classes {
		near, far := tcpPair(t)
		registerDrainableTunnel(cl, near)
		peers = append(peers, far)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := drainActiveTunnels(ctx); err != nil {
		t.Fatalf("drainActiveTunnels: %v", err)
	}

	if got := atomic.LoadInt64(&statTunnelForced); got != int64(len(classes)) {
		t.Errorf("culvert_tunnel_drain_forced_total = %d, want %d", got, len(classes))
	}
	// A force-closed near end makes the far end observe EOF. That is the property
	// the accounting depends on: it is what unblocks the relay's io.Copy.
	for i, p := range peers {
		_ = p.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		if _, err := p.Read(buf); err == nil {
			t.Errorf("class %s: peer did not observe the force-close", classes[i])
		}
	}
}

// TestChaos57_NativeInspectFallbackRelayContainsAPanic closes the PX-4 residual this
// sweep found: relayPlaintextInspectFallback was the ONE relay goroutine in the tree
// without a panic guard, so a panic inside it propagated to the runtime and killed an
// in-line security appliance — dropping every OTHER in-flight tunnel with it. The
// panic is injected through the conn, which is where a real one would come from.
func TestChaos57_NativeInspectFallbackRelayContainsAPanic(t *testing.T) {
	isolateDrainRegistry(t)
	t.Cleanup(reqlog.SwapRingForTest())

	clientA, clientB := tcpPair(t)
	upA, upB := tcpPair(t)
	_ = clientA
	_ = upB

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayPlaintextInspectFallback(
			panicOnReadConn{Conn: clientB},
			panicReader{},
			upA,
			"chaos57-native-fallback.test",
			nil,
			ProxyIdentity{ClientIP: "203.0.113.9"},
		)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relayPlaintextInspectFallback did not return after a relay panic")
	}
}

// panicReader panics on the first Read, standing in for any panic raised beneath
// idleCopyCounted.
type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("chaos57: injected relay panic") }

// panicOnReadConn is a net.Conn whose Read panics; the peer direction needs a conn,
// not just a reader.
type panicOnReadConn struct{ net.Conn }

func (c panicOnReadConn) Read([]byte) (int, error) { panic("chaos57: injected relay panic") }

// ─────────────────────────────────────────────────────────────────────────────
// CONTROL GATES — a passing defect gate must not be able to mean something worse.
// ─────────────────────────────────────────────────────────────────────────────

// TestChaos57_ControlDrainStillReturnsImmediatelyWithNoTunnels is the control for the
// waiting gate: making the drain see four more classes must not make a quiet node pay
// the window on every restart.
func TestChaos57_ControlDrainStillReturnsImmediatelyWithNoTunnels(t *testing.T) {
	isolateDrainRegistry(t)
	withShortDrainWindow(t, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	if err := drainActiveTunnels(ctx); err != nil {
		t.Fatalf("drainActiveTunnels: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("drain took %v on an idle node; it must return immediately", elapsed)
	}
}

// TestChaos57_ControlGraceIsRealNotImmediateForceClose is the control that separates
// this fix from the cheapest wrong one. Force-closing every registered tunnel the
// moment the drain starts would satisfy every gate above while being strictly worse
// than the defect: a session that WOULD have finished inside the window is killed. The
// tunnel here closes on its own well before the deadline and must never be force-closed.
func TestChaos57_ControlGraceIsRealNotImmediateForceClose(t *testing.T) {
	isolateDrainRegistry(t)
	withShortDrainWindow(t, 5*time.Second)

	c1, _ := tcpPair(t)
	release := registerDrainableTunnel(tunnelClassConnectBypass, c1)
	go func() {
		time.Sleep(300 * time.Millisecond)
		release()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := drainActiveTunnels(ctx); err != nil {
		t.Fatalf("drainActiveTunnels: %v", err)
	}
	if got := atomic.LoadInt64(&statTunnelForced); got != 0 {
		t.Errorf("force-closed %d tunnel(s) that drained gracefully; the drain window is not a grace period any more", got)
	}
}

// TestChaos57_ReleaseIsIdempotent pins the gauge invariant. An entry released twice —
// a defer plus an explicit call on some future error path — must not drive activeConns
// negative: a negative count makes `active <= 0` true forever, so the drain silently
// stops waiting for EVERY tunnel, which is the original defect restored by accident.
func TestChaos57_ReleaseIsIdempotent(t *testing.T) {
	isolateDrainRegistry(t)

	c1, _ := tcpPair(t)
	release := registerDrainableTunnel(tunnelClassSOCKS5, c1)
	release()
	release()
	release()

	if got := getActiveConns(); got != 0 {
		t.Errorf("activeConns = %d after repeated release, want 0", got)
	}
	if got := atomic.LoadInt64(&tunnelClassActive[tunnelClassSOCKS5]); got != 0 {
		t.Errorf("class gauge = %d after repeated release, want 0", got)
	}
}

// TestChaos57_RegistryKeysOnTheEntryNotTheConn pins the map-key decision. Two tunnels
// can legitimately hold the same conn value (the strip-path fallback registers
// rawClient while the inspect path registers the tls.Conn wrapping it). A conn-keyed
// registry would let one release evict the other's registration, so the surviving
// tunnel would never be force-closed — a leak in the direction that matters.
func TestChaos57_RegistryKeysOnTheEntryNotTheConn(t *testing.T) {
	isolateDrainRegistry(t)

	shared, _ := tcpPair(t)
	releaseA := registerDrainableTunnel(tunnelClassConnectBypass, shared)
	registerDrainableTunnel(tunnelClassInspectFallback, shared)

	releaseA()
	if got := getActiveConns(); got != 1 {
		t.Fatalf("activeConns = %d after releasing one of two tunnels sharing a conn, want 1", got)
	}
	n, breakdown := forceCloseDrainableTunnels()
	if n != 1 {
		t.Errorf("force-closed %d tunnels, want 1 (the surviving registration)", n)
	}
	if !strings.Contains(breakdown, "inspect_fallback=1") {
		t.Errorf("breakdown = %q, want the surviving class", breakdown)
	}
}

// TestChaos57_SettleIsClampedToTheBudget pins the rule that keeps the settle from
// borrowing time it does not own. With the phase budget already spent, the settle must
// not linger — the flush reserve behind it is what CHAOS-56 exists to protect.
func TestChaos57_SettleIsClampedToTheBudget(t *testing.T) {
	isolateDrainRegistry(t)
	atomic.StoreInt64(&activeConns, 1)
	defer atomic.StoreInt64(&activeConns, 0)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)

	start := time.Now()
	settleAfterForceClose(ctx)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("settle took %v with no budget left; it must be clamped to the phase deadline", elapsed)
	}
}

// TestChaos57_SettleWaitsForTheAccountingWhenItHasBudget is the control for the gate
// above: a settle clamped to nothing in every case would pass it while restoring the
// accounting loss the settle exists to prevent.
func TestChaos57_SettleWaitsForTheAccountingWhenItHasBudget(t *testing.T) {
	isolateDrainRegistry(t)
	atomic.StoreInt64(&activeConns, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		atomic.StoreInt64(&activeConns, 0)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if remaining := settleAfterForceClose(ctx); remaining != 0 {
		t.Errorf("settle returned with %d tunnel(s) outstanding; it gave up before the relays could record their accounting", remaining)
	}
}

// TestChaos57_ClassNamesAreAMonitoringContract pins the label values. Renaming one
// silently breaks an operator's dashboard, which is exactly the kind of change a test
// should make loud.
func TestChaos57_ClassNamesAreAMonitoringContract(t *testing.T) {
	want := map[tunnelClass]string{
		tunnelClassConnectBypass:   "connect_bypass",
		tunnelClassConnectInspect:  "connect_inspect",
		tunnelClassInspectFallback: "inspect_fallback",
		tunnelClassWebSocket:       "websocket",
		tunnelClassSOCKS5:          "socks5",
	}
	if len(want) != int(tunnelClassCount) {
		t.Fatalf("tunnelClassCount = %d but %d names pinned — a new class needs a pinned label", tunnelClassCount, len(want))
	}
	for c, name := range want {
		if got := c.String(); got != name {
			t.Errorf("class %d = %q, want %q", int(c), got, name)
		}
	}
	if got := tunnelClass(99).String(); got != "unknown" {
		t.Errorf("out-of-range class = %q, want %q", got, "unknown")
	}
}

// TestChaos57_MetricsExposeEveryClass pins that the gauge actually reaches /metrics —
// a per-class counter nothing scrapes is not observability.
func TestChaos57_MetricsExposeEveryClass(t *testing.T) {
	isolateDrainRegistry(t)

	c1, _ := tcpPair(t)
	defer registerDrainableTunnel(tunnelClassSOCKS5, c1)()

	out := renderMetrics(t)
	for i := tunnelClass(0); i < tunnelClassCount; i++ {
		if !strings.Contains(out, `culvert_tunnels_active{class="`+tunnelClassNames[i]+`"}`) {
			t.Errorf("/metrics is missing culvert_tunnels_active for class %s", tunnelClassNames[i])
		}
	}
	if !strings.Contains(out, `culvert_tunnels_active{class="socks5"} 1`) {
		t.Error("/metrics does not report the live SOCKS5 tunnel")
	}
	if !strings.Contains(out, "culvert_tunnel_drain_forced_total") {
		t.Error("/metrics is missing culvert_tunnel_drain_forced_total")
	}
}

// TestChaos57_BreakdownFormatting pins the operator log line's shape without driving
// the process-global registry.
func TestChaos57_BreakdownFormatting(t *testing.T) {
	var none [tunnelClassCount]int
	if got := formatTunnelClassBreakdown(none); got != "none" {
		t.Errorf("empty breakdown = %q, want %q", got, "none")
	}
	var mixed [tunnelClassCount]int
	mixed[tunnelClassSOCKS5] = 12
	mixed[tunnelClassWebSocket] = 3
	if got, want := formatTunnelClassBreakdown(mixed), "websocket=3, socks5=12"; got != want {
		t.Errorf("breakdown = %q, want %q", got, want)
	}
}

// waitForActiveConnsZero polls until activeConns drains to zero. Any test that leaves
// a tunnel to be released by a goroutine it does not join MUST call this before
// returning, or its late release lands after the registry reset and drives the gauge
// negative for every test that follows.
func waitForActiveConnsZero(t *testing.T, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if getActiveConns() <= 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// waitForActiveConns polls until activeConns reaches at least want, or the deadline
// passes. Polling (rather than a single read) is required because the tunnel registers
// on a goroutine the test does not synchronise with.
func waitForActiveConns(t *testing.T, want int64, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if getActiveConns() >= want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
