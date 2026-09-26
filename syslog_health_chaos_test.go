package main

// syslog_health_chaos_test.go — CHAOS-72 gates for the SIEM forwarding plane.
//
// Every DEFECT gate here was verified failing against the pre-fix tree before
// the fix was written; the two headline ones were reproduced against the real
// handler and the real engine, not a model of them. The CONTROLS exist because
// the cheapest ways to satisfy the defect gates are all worse than the defect:
// a plane that reports every feed as degraded passes "sees a runtime outage",
// and a plane that never reports degraded passes "does not page an idle node".

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslogTestCollector is a TCP collector the test can kill.
//
// stop() must DETERMINISTICALLY sever every accepted connection. The first
// shape kept accepted conns in a buffered channel and drained whatever was in
// it, which loses any connection the accept goroutine has taken from Accept()
// but not yet handed over — and then the writer keeps delivering happily to a
// live socket, no drops ever occur, and a waitForDrops gate burns its whole
// budget. Observed once under the CPU contention of a concurrent -race build,
// which is exactly when that interleaving gets likely. The conns are tracked
// under a mutex with a `stopped` flag instead, so a connection accepted at any
// instant relative to stop() is closed by whichever side sees it last.
type syslogTestCollector struct {
	ln   net.Listener
	addr string

	mu      sync.Mutex
	stopped bool
	conns   []net.Conn
	// accepted is signalled on every accepted connection so a test can wait
	// for the writer to actually connect rather than guessing.
	accepted chan struct{}
}

// track registers an accepted connection, or closes it immediately when the
// collector has already stopped.
func (c *syslogTestCollector) track(conn net.Conn) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		_ = conn.Close()
		return
	}
	c.conns = append(c.conns, conn)
	c.mu.Unlock()
	select {
	case c.accepted <- struct{}{}:
	default:
	}
}

func startSyslogCollector(t *testing.T) *syslogTestCollector {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := newSyslogTestCollector(ln)
	t.Cleanup(c.stop)
	return c
}

func newSyslogTestCollector(ln net.Listener) *syslogTestCollector {
	c := &syslogTestCollector{ln: ln, addr: ln.Addr().String(), accepted: make(chan struct{}, 16)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.track(conn)
			go func(cn net.Conn) { _, _ = cn.Read(make([]byte, 4096)) }(conn)
		}
	}()
	return c
}

// stop closes the listener and every connection this collector has accepted,
// including one accepted concurrently with the stop itself.
func (c *syslogTestCollector) stop() {
	_ = c.ln.Close()
	c.mu.Lock()
	c.stopped = true
	conns := c.conns
	c.conns = nil
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// firstConn returns the collector's side of the first accepted connection, so
// a test can observe whether the writer closed it.
func (c *syslogTestCollector) firstConn(t *testing.T) net.Conn {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.conns) == 0 {
		t.Fatal("collector has no accepted connection")
	}
	return c.conns[0]
}

// waitForConnection blocks until the writer has connected, so a test that is
// about to kill the collector knows there is something to kill.
func (c *syslogTestCollector) waitForConnection(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	n := len(c.conns)
	c.mu.Unlock()
	if n > 0 {
		return
	}
	select {
	case <-c.accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("the writer never connected to the collector")
	}
}

// armSyslogFeed points the process at a collector exactly as InitSyslog does
// on both the startup and the admin path, and isolates the health record.
func armSyslogFeed(t *testing.T, addr string) {
	t.Helper()
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	syslogConfiguredAddr = addr
	if err := InitSyslog(addr, "rfc3164"); err != nil {
		t.Fatalf("InitSyslog(%q): %v", addr, err)
	}
	syslogConfigured = addr

	// CLOSE the writer this gate installed. snapshotObservabilityGlobals
	// restores the POINTER (setActiveSyslog(old)) and nothing closes what it
	// displaces, so without this every gate leaves a live drain goroutine
	// behind — and the ones whose collector the gate then kills sit in the
	// engine's 5 s reconnect loop re-dialling a dead address for the rest of
	// the process. One leaked writer is invisible; this file installs ~19, and
	// the determinism contract runs the package TWICE, so the tail of the root
	// suite was executing against a background of steady dial churn that no
	// test asked for. That is the `swapAutoExclude` fence-pollution rule in a
	// new costume: a global a test installs is a global the test must take
	// back, not merely stop pointing at.
	//
	// Cleanups run LIFO and this one is registered after the snapshot's, so it
	// runs BEFORE the pointer is restored — the writer being closed is always
	// the one this call installed, never a predecessor the suite still needs.
	if installed := activeSyslog(); installed != nil {
		t.Cleanup(func() { _ = installed.Close() })
	}
}

// waitForDrops blocks until the writer has recorded at least n drops.
//
// The budget is deliberately generous. Delivery is asynchronous, so this waits
// on the drain goroutine being scheduled and on the engine's own 5 s reconnect
// backoff — both wall-clock, both stretched by whatever else the machine is
// doing. A 10 s budget flaked once on a loaded box; the assertion is about
// WHETHER drops are recorded, never about how fast, so a tight budget buys
// nothing and costs a false failure. On timeout the full snapshot is printed,
// because "no drops" and "drops attributed to the wrong reason" need different
// answers.
func waitForDrops(t *testing.T, n uint64) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if activeSyslog().Stats().Drops >= n {
			return
		}
		activeSyslog().WriteAudit(map[string]string{"evt": "policy.change"})
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("writer recorded %d drops; want >= %d (stats: %+v)", activeSyslog().Stats().Drops, n, activeSyslog().Stats())
}

// ---------------------------------------------------------------------------
// DEFECT GATES
// ---------------------------------------------------------------------------

// The headline defect. Pre-fix, checkSyslogFeed decided on two strings fixed at
// init time and reported `ok` / "remote syslog/SIEM forwarding is active" for a
// collector that had been swallowing every audit event for as long as the
// process had been up. Measured against the pre-fix tree: 49 of 49 audit lines
// dropped, row still ok.
func TestChaos72_ContractRowSeesARuntimeCollectorOutage(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Fatalf("precondition: healthy feed row = %v (%s); want ok", row.Status, row.Message)
	}

	col.stop() // the SIEM goes away mid-life
	waitForDrops(t, 5)

	// Degradation is a DURATION, not a count: a handful of drops is a blip the
	// reconnect machine absorbs, and the row must still not page.
	if row := checkSyslogFeed(); row.Status == diagFail {
		t.Errorf("row failed on a brief drop burst: %s — degradation must be a duration, not a count", row.Message)
	}

	// Push past the degradation window on the clock seam.
	base := time.Now()
	setSyslogHealthNowForTest(func() time.Time { return base.Add(syslogDegradedAfter + time.Minute) })

	row := checkSyslogFeed()
	if row.Status != diagFail {
		t.Fatalf("syslog_feed = %v (%q) with a dead collector and %d drops; want fail — the pre-CHAOS-72 row reported \"forwarding is active\" here",
			row.Status, row.Message, activeSyslog().Stats().Drops)
	}
	if strings.Contains(row.Message, "is active") {
		t.Errorf("row still claims the feed is active: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Error("a fail row must carry an OperatorAction")
	}
}

// Pre-fix the ONLY consumer of Drops() in the whole tree was an admin-only JSON
// blob: no Prometheus series existed, so no alerting rule could exist, and the
// compliance feed could be dark indefinitely with every scrape green.
func TestChaos72_DropsReachMetricsAndHealthz(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	col.stop()
	waitForDrops(t, 3)

	var b strings.Builder
	syslogWritePrometheus(&b)
	out := b.String()
	for _, want := range []string{
		"culvert_syslog_drops_total",
		"culvert_syslog_up",
		"culvert_syslog_degraded",
		"culvert_syslog_last_success_timestamp_seconds",
		"culvert_syslog_stale_seconds",
		"culvert_syslog_delivered_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %s — without a series no alerting rule can see a dark SIEM feed", want)
		}
	}

	resp := map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["syslogDrops"]; !ok {
		t.Error("/healthz carries no syslogDrops field; its two siblings (auditLogWriteErrors, auditClusterPushDrops) both report there")
	}
}

// The emission rule every gauge in this tree follows: a `culvert_syslog_up 0`
// on a node that forwards nowhere is indistinguishable from a dark feed, and
// the documented paging rule is `== 0`.
func TestChaos72_NoSeriesWhenNoCollectorConfigured(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	var b strings.Builder
	syslogWritePrometheus(&b)
	if b.Len() != 0 {
		t.Errorf("emitted %q with no collector configured; want nothing", b.String())
	}
	resp := map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["syslogDrops"]; ok {
		t.Error("/healthz carries syslogDrops on a node that forwards nowhere")
	}
}

// InitSyslog used to overwrite globalSyslog and strand the previous Writer's
// drain goroutine parked forever on an unreachable queue, holding its collector
// socket OPEN. Measured pre-fix: +1 goroutine and an ESTABLISHED connection at
// the abandoned collector (a read on the far end timed out instead of seeing
// EOF). Reached on EVERY boot of an appliance that has both a YAML target and a
// persisted admin target, not only on an admin re-point.
func TestChaos72_InitSyslogClosesTheWriterItReplaces(t *testing.T) {
	first := startSyslogCollector(t)
	second := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+first.addr)

	first.waitForConnection(t)
	farEnd := first.firstConn(t)

	runtime.GC()
	before := runtime.NumGoroutine()

	// Re-point, exactly as POST /api/syslog and applyAdminServices do.
	syslogConfiguredAddr = "tcp://" + second.addr
	if err := InitSyslog("tcp://"+second.addr, "rfc3164"); err != nil {
		t.Fatalf("re-point: %v", err)
	}
	syslogConfigured = "tcp://" + second.addr

	// The abandoned collector must see EOF, i.e. our side closed the socket.
	_ = farEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := farEnd.Read(make([]byte, 1)); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("the replaced Writer still holds its collector connection ESTABLISHED — one leaked goroutine and one leaked descriptor per re-init")
		}
	}

	// And the goroutine must be gone, not merely idle.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("goroutine count %d did not return to %d after the replaced Writer was released", runtime.NumGoroutine(), before)
}

// Recovery is declared on OBSERVED evidence only. A feed that stopped dropping
// because nothing is being logged looks identical to a feed that started
// delivering again — the discipline ca_health.go and storage_health.go both
// record by name.
func TestChaos72_RecoveryRequiresADeliveredEvent(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	col.stop()
	waitForDrops(t, 3)

	base := time.Now()
	setSyslogHealthNowForTest(func() time.Time { return base.Add(syslogDegradedAfter + time.Minute) })
	if !syslogFeedState().Degraded {
		t.Fatal("precondition: feed should be degraded")
	}

	// Elapsed time alone must NOT clear it.
	setSyslogHealthNowForTest(func() time.Time { return base.Add(24 * time.Hour) })
	if !syslogFeedState().Degraded {
		t.Error("degradation cleared on elapsed time alone — a quiet dead feed would report healthy")
	}

	// A delivered event does. Both clocks move together: the engine stamps the
	// delivery and the plane measures its age, so driving only one of them
	// would measure the gap between two clocks rather than the age of an
	// event.
	restore := syslog.SetNowForTest(func() time.Time { return base.Add(24 * time.Hour) })
	defer restore()

	// The baseline is captured, not assumed to be zero: the FIRST write after
	// a TCP peer closes still succeeds (the RST arrives later), so a collector
	// that has already gone away can leave Delivered at 1. Waiting for
	// "Delivered > 0" would then observe that stale success and conclude the
	// feed recovered without a single byte having reached anything.
	beforeDelivered := activeSyslog().Stats().Delivered

	revived := startSyslogCollectorOn(t, col.addr)
	defer revived.stop()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		activeSyslog().WriteAudit(map[string]string{"evt": "policy.change"})
		if activeSyslog().Stats().Delivered > beforeDelivered {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if activeSyslog().Stats().Delivered <= beforeDelivered {
		t.Skip("collector could not be revived on the same port in this environment")
	}
	setSyslogHealthNowForTest(func() time.Time { return base.Add(24*time.Hour + time.Second) })
	if syslogFeedState().Degraded {
		t.Error("still degraded after an event was delivered — recovery on observed evidence did not fire")
	}
}

// startSyslogCollectorOn rebinds a collector on a specific address so a test
// can revive the one it killed.
func startSyslogCollectorOn(t *testing.T, addr string) *syslogTestCollector {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	return newSyslogTestCollector(ln)
}

// The alert Detail reaches the alert store's dedup key (event + ":" + Detail).
// A raw transport error embeds the collector address and, for a dial failure,
// the ephemeral local port — a per-failure-unique Detail defeats the dedup
// window by construction and evicts real threat alerts from the bounded retry
// queue (WK-12/RS-5, recorded twice already in this tree).
func TestChaos72_AlertDetailCarriesOnlyABoundedReason(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	host, port, _ := net.SplitHostPort(col.addr)
	col.stop()
	waitForDrops(t, 3)

	var details []string
	old := fireSyslogFeedDownAlert
	fireSyslogFeedDownAlert = func(d string) { details = append(details, d) }
	t.Cleanup(func() { fireSyslogFeedDownAlert = old })

	base := time.Now()
	setSyslogHealthNowForTest(func() time.Time { return base.Add(syslogDegradedAfter + time.Minute) })
	noteSyslogDelivery(false)
	noteSyslogDelivery(false)
	noteSyslogDelivery(false)

	if len(details) != 1 {
		t.Fatalf("alert fired %d times for one episode; want exactly 1 (fire-once per episode, never per dropped event)", len(details))
	}
	d := details[0]
	if strings.Contains(d, host+":"+port) || strings.Contains(d, port) {
		t.Errorf("alert Detail embeds the collector address (%q): %q", col.addr, d)
	}
	found := false
	for _, r := range syslogReasonClasses {
		if strings.Contains(d, r) {
			found = true
		}
	}
	if !found {
		t.Errorf("alert Detail carries no bounded reason class: %q", d)
	}
}

// POST /api/syslog/test answered {"ok": true} unconditionally once delivery
// became asynchronous — it confirmed only that a channel send succeeded, and
// checkSyslogFeed's own OperatorAction pointed operators at it to "confirm
// connectivity". A probe that cannot fail is worse than no probe.
func TestChaos72_ProbeReportsTheRealOutcome(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	if outcome, detail := syslogDeliveryProbe(activeSyslog()); outcome != "delivered" {
		t.Errorf("healthy probe outcome = %q (%s); want \"delivered\"", outcome, detail)
	}

	col.stop()
	waitForDrops(t, 1)
	outcome, detail := syslogDeliveryProbe(activeSyslog())
	if outcome == "delivered" || outcome == "sent" {
		t.Errorf("probe reported %q against a dead collector (%s) — the pre-CHAOS-72 endpoint answered ok:true here", outcome, detail)
	}
}

// The metrics gate above calls syslogWritePrometheus directly, which proves the
// series EXIST but not that /metrics emits them — a writer nobody calls passes
// it. The exposition builder is one long function that reaches a dozen
// subsystem writers, so this pins the WIRING structurally (source scan, the
// convention the C1 route-parity tests use) rather than by standing up a
// scrape. Deterministic on any hardware, under -race, at any load.
func TestChaos72_MetricsExpositionCallsTheSyslogWriter(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "metrics.go"))
	if err != nil {
		t.Fatalf("read metrics.go: %v", err)
	}
	if !strings.Contains(string(src), "syslogWritePrometheus(&ruleMetBuf)") {
		t.Error("metrics.go does not call syslogWritePrometheus — the culvert_syslog_* series exist but /metrics never emits them, so no alerting rule can see a dark SIEM feed")
	}
	// Not vacuous: the same scan must find a writer known to be wired.
	if !strings.Contains(string(src), "threatFeedWritePrometheus(&ruleMetBuf)") {
		t.Error("control: the scan no longer matches a known-wired writer, so it proves nothing")
	}
}

// Walling the PROBE FUNCTION is not walling the PATH. The gate above exercises
// syslogDeliveryProbe directly, so it passes unchanged against a handler that
// never calls it — verified: reverting apiSyslogTest to its pre-CHAOS-72 body
// left that gate green. This one drives the real handler an operator reaches,
// which is the only thing that proves the endpoint stopped lying. Same lesson
// the SOCKS5 log-injection note records one subsystem over: sanitising one
// argument does not sanitise the call, and walling one call shape does not wall
// the path.
func TestChaos72_TestEndpointReportsFailureAgainstADeadCollector(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	col.stop()
	waitForDrops(t, 1)

	w := httptest.NewRecorder()
	apiSyslogTest(w, jsonReq(http.MethodPost, "/api/syslog/test", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (the probe reports an outcome, it does not error)", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok, _ := body["ok"].(bool); ok {
		t.Errorf("POST /api/syslog/test answered ok:true against a dead collector: %v — checkSyslogFeed's own OperatorAction points operators here to \"confirm connectivity\"", body)
	}
	if body["outcome"] == nil {
		t.Errorf("response carries no outcome field: %v", body)
	}
}

// The writer handle is MUTATED AT RUNTIME by the admin plane while the request
// path reads it, and before CHAOS-72 it was a bare package-level pointer with
// no synchronisation at all. Confirmed under -race against the real
// apiSyslogConfig and recordRequest shapes: nothing in the suite happened to
// exercise both at once, which is the only reason it had never been reported.
// This gate is that exercise, and it is the reason the handle is now an
// atomic.Pointer.
func TestChaos72_WriterHandleIsSafeUnderConcurrentRepointAndTraffic(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Request path: store.go's recordRequest and audit fan-out shapes.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if sw := activeSyslog(); sw != nil {
					sw.WriteRequest(map[string]string{"host": "example.com"})
					sw.WriteAudit(map[string]string{"evt": "policy.change"})
				}
			}
		}()
	}
	// Admin path: repeated re-points, as POST /api/syslog performs them.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 25; i++ {
			if err := InitSyslog("tcp://"+col.addr, "rfc3164"); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	// And the surfaces that read it from their own handler goroutines.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = checkSyslogFeed()
			var b strings.Builder
			syslogWritePrometheus(&b)
			_ = syslogDropCount()
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	// No assertion beyond "the race detector saw nothing": a torn handle is
	// the defect, and -race is the only instrument that observes it.
}

// ---------------------------------------------------------------------------
// CONTROLS — each of these passes trivially against a plane that is broken in
// the opposite direction, which is why the defect gates alone are not enough.
// ---------------------------------------------------------------------------

// A plane that reported every feed as degraded would satisfy every defect gate
// above while being far worse than the defect.
func TestChaos72_HealthyFeedStillReportsActive(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	for i := 0; i < 20; i++ {
		activeSyslog().WriteAudit(map[string]string{"evt": "policy.change"})
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && activeSyslog().Stats().Delivered == 0 {
		time.Sleep(20 * time.Millisecond)
	}

	snap := syslogFeedState()
	if snap.Degraded {
		t.Errorf("healthy feed reported degraded: %+v", snap)
	}
	if snap.Drops != 0 {
		t.Errorf("healthy feed recorded %d drops", snap.Drops)
	}
	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Errorf("healthy feed row = %v (%q); want ok", row.Status, row.Message)
	}
	var b strings.Builder
	syslogWritePrometheus(&b)
	if !strings.Contains(b.String(), "culvert_syslog_up 1") {
		t.Errorf("culvert_syslog_up is not 1 on a healthy feed:\n%s", b.String())
	}
}

// The predicate must require BOTH halves. An idle gateway forwards nothing, so
// its last-success timestamp ages without limit — inventing a fault from
// silence is how a health plane loses its audience.
func TestChaos72_IdleNodeIsNeverDegraded(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	base := time.Now()
	setSyslogHealthNowForTest(func() time.Time { return base.Add(30 * 24 * time.Hour) })

	snap := syslogFeedState()
	if snap.Drops != 0 {
		t.Fatalf("precondition: idle feed recorded %d drops", snap.Drops)
	}
	if snap.Degraded {
		t.Error("an idle node with a healthy collector was reported degraded after 30 days of silence")
	}
	if row := checkSyslogFeed(); row.Status == diagFail {
		t.Errorf("idle node row = fail: %q", row.Message)
	}
}

// A UDP feed cannot prove delivery; every surface that reports one as healthy
// must say so, or a green gauge is read as proof the SIEM has the events.
func TestChaos72_UDPFeedCarriesTheUnprovableDeliveryCaveat(t *testing.T) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	armSyslogFeed(t, "udp://"+pc.LocalAddr().String())

	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Fatalf("udp feed row = %v (%q); want ok", row.Status, row.Message)
	}
	if !strings.Contains(row.Message, "UDP") {
		t.Errorf("udp feed row does not state that delivery is unprovable: %q", row.Message)
	}
}

// CONTROL, not a defect gate, and labelled as such because it was written as
// one and does not earn the title: it passes against the tree WITHOUT the
// observer detach in releaseReplacedSyslogWriter, verified. The isolation holds
// by construction — syslogFeedState reads its counters from whichever writer is
// live, so a displaced writer's final-flush drops land on its own Stats and can
// never move the successor's. The detach is hygiene (it stops an abandoned
// writer doing pointless work through a stale callback) and this test does not
// prove it; what it does pin is the property an operator depends on, which is
// that re-pointing a collector does not make the new target look broken.
func TestChaos72_ReplacedWriterDoesNotCorruptTheSuccessorsState(t *testing.T) {
	first := startSyslogCollector(t)
	second := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+first.addr)

	// Fill the displaced writer's queue against a dead collector, then replace
	// it: its flush window expires and it charges drops on its own counters.
	first.stop()
	for i := 0; i < 50; i++ {
		activeSyslog().WriteAudit(map[string]string{"evt": "policy.change"})
	}
	// Captured BEFORE the re-point. How many of those 50 lines have already
	// been charged as drops depends on when the queue fills, so the assertion
	// below is monotonicity, not a count — the deterministic preservation gate
	// is TestChaos72_RePointDoesNotResetTheLossHistory, which waits for drops
	// first.
	beforeDrops := syslogFeedState().Drops
	syslogConfiguredAddr = "tcp://" + second.addr
	if err := InitSyslog("tcp://"+second.addr, "rfc3164"); err != nil {
		t.Fatalf("re-point: %v", err)
	}
	syslogConfigured = "tcp://" + second.addr

	// Give the displaced writer time to finish flushing and dropping.
	//
	// What must NOT be inherited is the displaced writer's EPISODE: its
	// failures, its degraded verdict, its claim on the row. The cumulative
	// DROP TOTAL is a different thing and is carried deliberately — a
	// re-point must not reset the loss history, or `culvert_syslog_drops_total`
	// goes backwards and the evidence disappears at the moment an operator
	// remediates (Codex P2, PR #1494). This test asserted the total instead of
	// the episode, so it was pinning the reset as if it were the contract.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snap := syslogFeedState()
		if snap.ConsecutiveFailures > 0 {
			t.Fatalf("the replacement inherited %d consecutive failures from the writer it displaced", snap.ConsecutiveFailures)
		}
		if snap.Degraded {
			t.Fatal("the replacement is reported DOWN on the strength of the displaced writer's outage")
		}
		if snap.WriterDrops > 0 {
			t.Fatalf("the replacement's OWN drop count is %d; the displaced writer's losses must not be attributed to this target", snap.WriterDrops)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The history survives, and the row reports it AS history rather than
	// blaming the collector that has just been installed.
	if snap := syslogFeedState(); snap.Drops < beforeDrops {
		t.Errorf("the process-lifetime drop total went backwards across the re-point: %d -> %d", beforeDrops, snap.Drops)
	}
	row := checkSyslogFeed()
	if row.Status == diagFail {
		t.Errorf("row on a healthy replacement = fail (%q)", row.Message)
	}
	if strings.Contains(row.Message, "NEVER delivered an event since this target was configured") {
		t.Errorf("row blames the freshly installed target for the predecessor's losses: %q", row.Message)
	}
}

// Disabling forwarding must make the feature ABSENT again on every surface. A
// switched-off feed that keeps exporting culvert_syslog_up 1 and a clean row is
// the same class of false statement this plane exists to remove, pointing the
// other way.
func TestChaos72_DisablingForwardingRemovesEverySurface(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	var armed strings.Builder
	syslogWritePrometheus(&armed)
	if !strings.Contains(armed.String(), "culvert_syslog_up") {
		t.Fatalf("precondition: armed feed emits no series:\n%s", armed.String())
	}

	w := httptest.NewRecorder()
	apiSyslogConfig(w, jsonReq(http.MethodPost, "/api/syslog", map[string]string{"addr": ""}))
	if w.Code != http.StatusOK {
		t.Fatalf("disable returned %d", w.Code)
	}

	var off strings.Builder
	syslogWritePrometheus(&off)
	if off.Len() != 0 {
		t.Errorf("still emitting series after forwarding was disabled:\n%s", off.String())
	}
	if n := syslogDropCount(); n != 0 {
		t.Errorf("syslogDropCount() = %d after disable; want 0 so /healthz drops the field", n)
	}
	if row := checkSyslogFeed(); row.Status != diagOK || !strings.Contains(row.Message, "not configured") {
		t.Errorf("row after disable = %v (%q); want ok/not configured", row.Status, row.Message)
	}
}

// ---------------------------------------------------------------------------
// Codex P1 round (PR #1494)
// ---------------------------------------------------------------------------

// P1-B. `Drops` is CUMULATIVE and never resets, so keying degradation on it
// meant one transient loss armed half the predicate permanently: the node then
// only had to go quiet for the window for Age to cross the threshold and every
// surface to report a perfectly healthy feed as DOWN. A false page on a working
// SIEM, from a blip that already healed.
//
// The original IdleNodeIsNeverDegraded control did not catch this because it
// used a feed with ZERO drops — the control was too weak, which is exactly what
// the reviewer pointed out.
func TestChaos72_AHealedBlipDoesNotDegradeAnIdleFeed(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	// Produce a real, historical loss, then let the feed recover.
	sw := activeSyslog()
	sw.SetDeliveryObserver(nil) // isolate: this test is about the predicate
	restore := syslog.SetNowForTest(nil)
	defer restore()

	// Force one drop through the closed-writer path, which is a genuine loss
	// the engine counts exactly as a collector-down loss would be.
	probe := &syslogTestCollector{}
	_ = probe
	for i := 0; i < 3; i++ {
		sw.WriteAudit(map[string]string{"evt": "policy.change"})
	}
	// Drive a loss by pointing the writer at a collector that is gone, then
	// bringing it back so a delivery resolves it.
	col.stop()
	waitForDrops(t, 1)
	revived := startSyslogCollectorOn(t, col.addr)
	defer revived.stop()

	deadline := time.Now().Add(20 * time.Second)
	base := activeSyslog().Stats().Delivered
	for time.Now().Before(deadline) {
		activeSyslog().WriteAudit(map[string]string{"evt": "policy.change"})
		if activeSyslog().Stats().Delivered > base {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	st := activeSyslog().Stats()
	if st.Delivered <= base {
		t.Skip("collector could not be revived on the same port in this environment")
	}
	if st.Drops == 0 {
		t.Fatal("precondition: no historical drop was recorded")
	}
	if st.ConsecutiveFailures != 0 {
		t.Fatalf("precondition: ConsecutiveFailures = %d after a delivery; want 0", st.ConsecutiveFailures)
	}

	// Now the node goes quiet for a month. The feed is HEALTHY — the last thing
	// it did was deliver — and must not be reported down.
	now := time.Now()
	setSyslogHealthNowForTest(func() time.Time { return now.Add(30 * 24 * time.Hour) })

	snap := syslogFeedState()
	if snap.Degraded {
		t.Errorf("a healed feed with %d historical drops was reported DOWN after going idle (ConsecutiveFailures=%d, Age=%s) — degradation must key on UNRESOLVED failure, not cumulative history",
			snap.Drops, snap.ConsecutiveFailures, snap.Age)
	}
	if row := checkSyslogFeed(); row.Status == diagFail {
		t.Errorf("row = fail on a healed, idle feed: %q", row.Message)
	}
}

// P1-A. The drop observer is driven by traffic, and traffic stops. A collector
// that dies, produces a couple of minutes of losses and is then followed by a
// quiet period crosses the threshold with nothing left to fire the alert: the
// metrics and the row compute the truth on READ, but the paging surfaces never
// fired. The watchdog is the independent driver.
func TestChaos72_WatchdogFiresTheAlertWhenTrafficHasStopped(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	col.stop()
	waitForDrops(t, 2)

	var fired []string
	old := fireSyslogFeedDownAlert
	fireSyslogFeedDownAlert = func(d string) { fired = append(fired, d) }
	t.Cleanup(func() { fireSyslogFeedDownAlert = old })

	// Traffic stops here: no further drops, so the observer will never run
	// again. Only elapsed time moves the feed across the threshold.
	now := time.Now()
	setSyslogHealthNowForTest(func() time.Time { return now.Add(syslogDegradedAfter + time.Minute) })

	if !syslogFeedState().Degraded {
		t.Fatal("precondition: the feed should be degraded once the window has passed")
	}
	if len(fired) != 0 {
		t.Fatalf("precondition: alert fired %d times before any evaluator ran", len(fired))
	}

	// One watchdog tick's worth of work, called directly so the gate does not
	// wait out a 30s ticker.
	evaluateSyslogDegradation()

	if len(fired) != 1 {
		t.Fatalf("alert fired %d times after the evaluator ran; want exactly 1 — without an independent driver the page never lands on a node that went quiet mid-outage", len(fired))
	}
	// And still exactly once: the episode latch must hold across ticks.
	evaluateSyslogDegradation()
	evaluateSyslogDegradation()
	if len(fired) != 1 {
		t.Errorf("alert fired %d times across three ticks; want 1 (fire-once per episode)", len(fired))
	}
}

// The P1-A gate above proves the evaluator does the right thing WHEN CALLED.
// The actual fix is that something calls it on a timer, and no behavioural test
// can observe that without waiting out a real ticker. Pinned structurally
// instead (source scan, the convention the C1 route-parity tests use), with its
// own not-vacuous control — the same treatment the metrics-exposition wiring
// gets, and for the same reason: a watchdog nobody starts satisfies a test that
// calls its body directly.
func TestChaos72_BackgroundServicesStartsTheHealthWatchdog(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "background_services_startup.go"))
	if err != nil {
		t.Fatalf("read background_services_startup.go: %v", err)
	}
	if !strings.Contains(string(src), "go startSyslogHealthWatchdog(ctx)") {
		t.Error("the SIEM health watchdog is never started — the degradation transition would then depend entirely on traffic, and a node that goes quiet mid-outage never pages")
	}
	// Not vacuous: the same scan must find a goroutine known to be started here.
	if !strings.Contains(string(src), "go startDecCoverageSampler(ctx)") {
		t.Error("control: the scan no longer matches a known-started worker, so it proves nothing")
	}
}

// P1-C. The probe used to infer its answer from writer-wide counters, so a
// concurrent line's delivery could be reported as the probe's own success while
// the probe's message was still queued behind a collector about to drop it.
// WriteProbe reports the outcome of THAT message, from the drain goroutine.
func TestChaos72_ProbeTracksItsOwnMessageNotTheWriterTotals(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	sw := activeSyslog()

	// Healthy: the probe's own line is delivered.
	ack, queued := sw.WriteProbe("probe-1")
	if !queued {
		t.Fatal("probe could not be queued against a healthy collector")
	}
	select {
	case ok := <-ack:
		if !ok {
			t.Error("probe reported its own line as lost against a healthy collector")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no per-message outcome within 5s")
	}

	// Dead collector: the probe's own line is lost, and says so — even while
	// other traffic is moving the writer's aggregate counters underneath it.
	col.stop()
	waitForDrops(t, 1)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sw.WriteAudit(map[string]string{"evt": "policy.change"})
			time.Sleep(time.Millisecond)
		}
	}()

	ack2, queued2 := sw.WriteProbe("probe-2")
	outcome := "not-queued"
	if queued2 {
		select {
		case ok := <-ack2:
			if ok {
				outcome = "delivered"
			} else {
				outcome = "dropped"
			}
		case <-time.After(10 * time.Second):
			outcome = "timeout"
		}
	}
	close(stop)
	wg.Wait()

	if outcome == "delivered" {
		t.Error("probe reported its own line as DELIVERED against a dead collector — the outcome was inferred from another line's success")
	}
}

// waitDelivered waits until sw has delivered more than base lines.
func waitDelivered(t *testing.T, sw *syslogWriter, base uint64, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if sw.Stats().Delivered > base {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// Codex P1 (second round, PR #1494): degradation must be timed from the start
// of the CURRENT failure episode, not only from the last delivery. A feed that
// was healthy but idle for longer than the window used to page on its very
// next transient drop — the episode was seconds old, Age was already past the
// threshold, and the fire-once alert went out for a blip.
func TestChaos72_IdleFeedDoesNotPageOnItsFirstFreshDrop(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	sw := activeSyslog()
	sw.SetDeliveryObserver(nil) // isolate: this test is about the predicate

	sw.WriteAudit(map[string]string{"evt": "policy.change"})
	if !waitDelivered(t, sw, 0, 10*time.Second) {
		t.Fatal("precondition: nothing was delivered to a live collector")
	}

	// The node then sits idle for an hour; the next line is lost.
	idleUntil := time.Now().Add(time.Hour)
	restore := syslog.SetNowForTest(func() time.Time { return idleUntil })
	defer restore()
	_ = sw.Close() // no successor: the next send is a counted closed-writer loss
	sw.WriteAudit(map[string]string{"evt": "policy.change"})
	if sw.Stats().ConsecutiveFailures == 0 {
		t.Fatal("precondition: the post-idle line was not counted as a loss")
	}

	setSyslogHealthNowForTest(func() time.Time { return idleUntil.Add(time.Second) })
	if snap := syslogFeedState(); snap.Degraded {
		t.Fatalf("a feed idle for %s was reported DOWN one second into its first failure (FailingFor=%s) — "+
			"the episode itself must last the window", snap.Age, snap.FailingFor)
	}

	// Once the episode HAS lasted the window, the same feed is down.
	setSyslogHealthNowForTest(func() time.Time { return idleUntil.Add(syslogDegradedAfter + time.Second) })
	if snap := syslogFeedState(); !snap.Degraded {
		t.Fatalf("an unresolved failure lasting %s was not reported down (Age=%s)", snap.FailingFor, snap.Age)
	}
}

// Codex P1 (second round, PR #1494): a caller that loaded the writer just
// before a runtime re-point can call WriteAudit on it after it was closed. The
// event used to be dropped against the displaced writer — whose observer is
// detached and whose counters no surface reads — so it was lost AND invisible.
// It must instead reach the writer that replaced it.
func TestChaos72_LateWriteOnADisplacedWriterReachesItsSuccessor(t *testing.T) {
	first := startSyslogCollector(t)
	second := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+first.addr)

	stale := activeSyslog() // loaded "just before the swap"
	syslogConfiguredAddr = "tcp://" + second.addr
	if err := InitSyslog("tcp://"+second.addr, "rfc3164"); err != nil {
		t.Fatalf("re-point: %v", err)
	}
	syslogConfigured = "tcp://" + second.addr
	_ = stale.Close() // make the race deterministic: the stale handle is closed
	live := activeSyslog()
	if live == stale {
		t.Fatal("precondition: re-point did not install a new writer")
	}

	staleDrops := stale.Drops()
	base := live.Stats().Delivered
	stale.WriteAudit(map[string]string{"evt": "policy.change"})

	if !waitDelivered(t, live, base, 10*time.Second) {
		t.Fatalf("a security event written through the displaced writer never reached its successor "+
			"(displaced drops %d -> %d)", staleDrops, stale.Drops())
	}
	if stale.Drops() != staleDrops {
		t.Errorf("the displaced writer charged the handed-off event as its own drop (%d -> %d)", staleDrops, stale.Drops())
	}
}

// TestChaos72_RowNeverClaimsDeliveryItCannotShow pins the contract row's
// message against the two states it used to describe with the same sentence it
// uses for a healthy feed.
//
// The `Drops > 0` warn branch said "remote syslog/SIEM forwarding is delivering
// (last event %s ago, %d delivered)". For a target whose very first events were
// lost that renders as "is delivering (last event 3s ago, 0 delivered)" — a
// delivery claim, and a last-event timestamp, for a feed that has never got a
// single line out. For a feed failing RIGHT NOW it describes the last success
// while the current events are being destroyed (Codex P2, PR #1494).
//
// Both became reachable when P1-D moved the degradation window from
// time-since-delivery to the failure episode: before that they were already
// FAIL. Moving a boundary in one place changes what every branch downstream of
// it has to say.
func TestChaos72_RowNeverClaimsDeliveryItCannotShow(t *testing.T) {
	// The state under test is "drops recorded, nothing ever delivered, episode
	// still young". Reaching it needs care: InitSyslog refuses a target it
	// cannot dial, and the FIRST write to a TCP socket whose peer has gone
	// still succeeds locally (the RST arrives later), which would move
	// Delivered off zero and describe a different state. Closing the writer
	// before any write makes every send a counted loss with no delivery.
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	col.stop()

	sw := activeSyslog()
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for i := 0; i < 3; i++ {
		sw.WriteAudit(map[string]string{"evt": "policy.change"})
	}
	waitForDrops(t, 1)

	snap := syslogFeedState()
	if !snap.NeverDelivered || snap.Delivered != 0 {
		t.Fatalf("fixture did not produce a never-delivered feed: neverDelivered=%v delivered=%d",
			snap.NeverDelivered, snap.Delivered)
	}
	if snap.Degraded {
		t.Skip("episode already past the degradation window; this gate is about the branch BELOW it")
	}

	row := checkSyslogFeed()
	if row.Status != diagWarn {
		t.Errorf("never-delivered feed with drops = %v; want warn", row.Status)
	}
	// The defect, stated as the thing the row must not say.
	if strings.Contains(row.Message, "is delivering") {
		t.Errorf("row claims delivery for a feed that has never delivered: %q", row.Message)
	}
	if strings.Contains(row.Message, "0 delivered") {
		t.Errorf("row reports a delivery count of zero as evidence of delivery: %q", row.Message)
	}
	if !strings.Contains(row.Message, "NEVER delivered") {
		t.Errorf("row does not say the feed has never delivered: %q", row.Message)
	}
	// CONTROL: it must still name the loss, or the cheapest way to pass the
	// assertions above is to stop reporting anything an operator can act on.
	if !strings.Contains(row.Message, "dropped") {
		t.Errorf("row no longer names the dropped events: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Error("row carries no operator action")
	}
}

// TestChaos72_OverlappingRePointsLeaveRecordDescribingTheActiveWriter pins
// that publishing the active writer and installing the health record that
// describes it are ONE transition. As two steps, overlapping admin re-points
// could end with the active writer C while target/installedAt/the alert latch
// described B (Codex review, PR #1494). The interleaving is a race, so this is
// a correctness gate for the serialized shape, not a deterministic defect gate.
func TestChaos72_OverlappingRePointsLeaveRecordDescribingTheActiveWriter(t *testing.T) {
	first := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+first.addr)
	const n = 8
	cols := make([]*syslogTestCollector, n)
	for i := range cols {
		cols[i] = startSyslogCollector(t)
	}
	for round := 0; round < 5; round++ {
		var wg sync.WaitGroup
		for i := range cols {
			wg.Add(1)
			go func(addr string) {
				defer wg.Done()
				_ = InitSyslog("tcp://"+addr, "rfc3164")
			}(cols[i].addr)
		}
		wg.Wait()
		syslogHealth.mu.Lock()
		rec := syslogHealth.writer
		syslogHealth.mu.Unlock()
		if live := activeSyslog(); rec != live {
			t.Fatalf("round %d: health record describes a displaced writer, not the active one", round)
		}
	}
	t.Cleanup(func() {
		if sw := activeSyslog(); sw != nil {
			_ = sw.Close()
		}
	})
	disableActiveSyslog()
	syslogHealth.mu.Lock()
	defer syslogHealth.mu.Unlock()
	if activeSyslog() != nil || syslogHealth.writer != nil || syslogHealth.configured {
		t.Fatal("disable did not clear the writer and the record together")
	}
}

// A collector an operator configured but that could NOT be connected exports
// every series, reporting the feed down (CHAOS-72 P1-F).
//
// Pre-fix, every surface in the plane gated on `configured`, which is set only
// once a Writer is installed — so the boot path's own tolerated failure
// ("Syslog: connect failed … continuing without syslog") left the node
// exporting NO culvert_syslog_* series at all. The documented paging rule is
// `culvert_syslog_up == 0` and an absent series cannot satisfy it, so the one
// node whose SIEM feed never came up was also the one node monitoring could
// not see, while a node that connected and then died was fully visible. The
// contract row did report it, which is why this survived: the plane disagreed
// with itself and only the surface nobody scrapes was right.
//
// The condition is reported down IMMEDIATELY rather than after the degradation
// window, matching what the row has always done: nothing retries a failed
// InitSyslog, so there is no transient to wait out.
func TestChaos72_ConfiguredButNeverConnectedIsExportedAsDown(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	// Exactly what loadObservability does when the dial fails: intent is
	// recorded, no Writer is published.
	noteSyslogIntent("tcp://collector.invalid:601")
	if activeSyslog() != nil {
		t.Fatal("fixture published a writer; this gate is about the case where none exists")
	}

	var b strings.Builder
	syslogWritePrometheus(&b)
	out := b.String()
	if out == "" {
		t.Fatal("a configured-but-unreachable collector exported NO culvert_syslog_* series at all — `culvert_syslog_up == 0` cannot fire for the one feed that never came up")
	}
	for _, want := range []string{"culvert_syslog_up 0", "culvert_syslog_degraded 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition is missing %q:\n%s", want, out)
		}
	}
	// Line-anchored: the HELP text for culvert_syslog_up contains the literal
	// "culvert_syslog_up 1 when …", so a substring check matches the
	// documentation rather than the sample.
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "culvert_syslog_up 1" {
			t.Errorf("reported the feed UP with nothing serving it:\n%s", out)
		}
	}

	// And the alert plane agrees, with its own sentence: the general one dates
	// the outage from a delivery that never happened and names a drop count
	// that is structurally zero.
	var fired []string
	prev := fireSyslogFeedDownAlert
	fireSyslogFeedDownAlert = func(d string) { fired = append(fired, d) }
	t.Cleanup(func() { fireSyslogFeedDownAlert = prev })

	evaluateSyslogDegradation()
	if len(fired) != 1 {
		t.Fatalf("fired %d alerts for a feed that was never connected; want exactly 1", len(fired))
	}
	if strings.Contains(fired[0], "events dropped") {
		t.Errorf("alert blames dropped events for a feed that never had a connection: %q", fired[0])
	}
	if !strings.Contains(fired[0], "no connection was ever established") {
		t.Errorf("alert does not name the actual fault: %q", fired[0])
	}
	// Fire-once per episode, as everywhere else in this plane.
	evaluateSyslogDegradation()
	if len(fired) != 1 {
		t.Errorf("fired %d alerts; the latch must hold until an operator re-points", len(fired))
	}
}

// CONTROL for the gate above. The cheapest way to make a configured-but-dead
// feed visible is to drop the emission gate altogether — which exports
// `culvert_syslog_up 0` from every deployment that does not use the feature
// and pages all of them. The rule is "was this feature ASKED for", so intent
// must be the only thing that opens the gate, and disabling forwarding must
// close it again.
func TestChaos72_UnmetIntentDoesNotWidenTheEmissionRule(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	var none strings.Builder
	syslogWritePrometheus(&none)
	if none.Len() != 0 {
		t.Fatalf("emitted %q on a node that never configured a collector", none.String())
	}

	noteSyslogIntent("tcp://collector.invalid:601")
	var armed strings.Builder
	syslogWritePrometheus(&armed)
	if armed.Len() == 0 {
		t.Fatal("fixture did not arm the intent; the rest of this control proves nothing")
	}

	noteSyslogForwardingDisabled()
	var off strings.Builder
	syslogWritePrometheus(&off)
	if off.Len() != 0 {
		t.Errorf("still exporting after forwarding was disabled:\n%s", off.String())
	}
}

// A degradation decision snapshotted against one Writer must not be committed
// into the record of another (CHAOS-72 P1-G).
//
// evaluateSyslogDegradation reads the snapshot and then takes the lock to fire.
// An admin re-point landing between the two installs a fresh record, and the
// stale callback would then page describing the OLD target AND set the NEW
// record's fire-once latch — which nothing clears, because ordinary deliveries
// do not invoke the observer. The replacement's first real outage would be
// silent. The window is microseconds wide and cannot be scheduled through the
// public entry point, so the commit half is its own function and is driven
// directly.
func TestChaos72_StaleDegradationSnapshotNeitherPagesNorLatches(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	var fired []string
	prev := fireSyslogFeedDownAlert
	fireSyslogFeedDownAlert = func(d string) { fired = append(fired, d) }
	t.Cleanup(func() { fireSyslogFeedDownAlert = prev })

	displaced, err := newSyslogWriter("tcp", "collector.invalid:601", "rfc3164")
	if err == nil {
		t.Cleanup(func() { _ = displaced.Close() })
	}
	successor, err := newSyslogWriter("udp", "127.0.0.1:65533", "rfc3164")
	if err != nil {
		t.Fatalf("building the successor writer: %v", err)
	}
	t.Cleanup(func() { _ = successor.Close() })

	// The record describes the SUCCESSOR; the in-flight snapshot describes the
	// writer it displaced, and was therefore taken from an EARLIER generation.
	noteSyslogWriterInstalled(successor, "udp://127.0.0.1:65533")
	syslogHealth.mu.Lock()
	liveGen := syslogHealth.gen
	syslogHealth.mu.Unlock()
	if liveGen == 0 {
		t.Fatal("precondition: installing a writer must advance the record generation")
	}
	stale := syslogFeedSnapshot{Configured: true, Degraded: true, writer: displaced, gen: liveGen - 1, Age: 10 * time.Minute}

	commitSyslogDegradation(stale)
	if len(fired) != 0 {
		t.Errorf("a snapshot of a displaced writer paged about it: %q", fired)
	}
	syslogHealth.mu.Lock()
	latched := syslogHealth.alerted
	syslogHealth.mu.Unlock()
	if latched {
		t.Fatal("the stale commit latched the SUCCESSOR's record — its first real outage would now be silent, and nothing but a re-point clears the latch")
	}

	// CONTROL: the live writer's own snapshot still pages. A commit half that
	// refused everything would pass every assertion above while deleting the
	// alert.
	live := syslogFeedSnapshot{Configured: true, Degraded: true, writer: successor, gen: liveGen, Age: 10 * time.Minute}
	commitSyslogDegradation(live)
	if len(fired) != 1 {
		t.Fatalf("the live writer's own degradation fired %d alerts; want 1", len(fired))
	}
}

// A runtime re-point must not make the exported counters go BACKWARDS
// (CHAOS-72, Codex P2).
//
// InitSyslog installs a brand-new Writer whose counters start at zero. The
// plane read them straight off that Writer, so `culvert_syslog_drops_total`
// decreased without a process restart — the one thing a Prometheus counter may
// not do, since `rate()` reads a decrease as a counter reset and discards the
// interval. The same reset removed `syslogDrops` from /healthz and turned the
// `syslog_feed` row's "N dropped since startup" back to clean, erasing the
// loss history at exactly the moment an operator re-points the collector to
// remediate the outage that produced it.
func TestChaos72_RePointDoesNotResetTheLossHistory(t *testing.T) {
	dead := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+dead.addr)
	dead.waitForConnection(t)
	dead.stop()
	waitForDrops(t, 3)

	before := syslogFeedState()
	if before.Drops == 0 {
		t.Fatal("fixture recorded no drops; the rest of this gate proves nothing")
	}
	var beforeExposition strings.Builder
	syslogWritePrometheus(&beforeExposition)
	if !strings.Contains(beforeExposition.String(), fmt.Sprintf("culvert_syslog_drops_total %d", before.Drops)) {
		t.Fatalf("exposition does not carry the pre-re-point drop count %d:\n%s", before.Drops, beforeExposition.String())
	}

	// The remediation an operator actually performs: point at a collector that
	// works.
	healthy := startSyslogCollector(t)
	if err := InitSyslog("tcp://"+healthy.addr, "rfc3164"); err != nil {
		t.Fatalf("re-point: %v", err)
	}
	t.Cleanup(func() {
		if sw := activeSyslog(); sw != nil {
			_ = sw.Close()
		}
	})

	after := syslogFeedState()
	if after.Drops < before.Drops {
		t.Errorf("drops went BACKWARDS across a re-point: %d -> %d — a Prometheus counter reset with no process restart, and the loss history is gone from every surface",
			before.Drops, after.Drops)
	}
	if n := syslogDropCount(); n < before.Drops {
		t.Errorf("/healthz syslogDrops went backwards across a re-point: %d -> %d", before.Drops, n)
	}
	var afterExposition strings.Builder
	syslogWritePrometheus(&afterExposition)
	if !strings.Contains(afterExposition.String(), fmt.Sprintf("culvert_syslog_drops_total %d", after.Drops)) {
		t.Errorf("exposition does not carry the post-re-point total %d:\n%s", after.Drops, afterExposition.String())
	}

	// CONTROL: the per-episode state is NOT carried across. The new writer is
	// serving a live collector, so the feed must not be reported as failing —
	// the cheapest way to pass the assertions above is to carry the whole
	// previous Writer's state forward, which would report the replacement as
	// broken from its first byte.
	if after.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after re-pointing at a live collector; the episode belongs to the displaced writer", after.ConsecutiveFailures)
	}
	if after.Degraded {
		t.Error("the replacement feed is reported DOWN on the strength of the displaced writer's outage")
	}
}

// GET /api/syslog answers from the delivery snapshot, never from the live
// Writer (CHAOS-72, Codex P2 ×2 on `ecfb906`).
//
// Two defects, one cause — the handler had its own idea of where the numbers
// come from:
//
//   - `drops`/`panics` were read straight off `activeSyslog()`, so a runtime
//     re-point reset them here while `/metrics` and the adjacent `delivered`
//     field kept the process-lifetime totals. Reloading the admin UI erased
//     the loss history at exactly the moment an operator re-points to
//     remediate, and contradicted the contract's own "cumulative and
//     monotonic" wording.
//   - `neverDelivered` and `deliveryProvable` were gated on `Configured`,
//     which is set only once a Writer exists — so a target whose boot dial
//     failed was reported `degraded:true, neverDelivered:false`, denying the
//     one fact that verdict rests on.
func TestChaos72_AdminAPIAnswersFromTheDeliverySnapshot(t *testing.T) {
	t.Run("a re-point does not reset the counters", func(t *testing.T) {
		dead := startSyslogCollector(t)
		armSyslogFeed(t, "tcp://"+dead.addr)
		dead.waitForConnection(t)
		dead.stop()
		waitForDrops(t, 3)

		before := readSyslogAdminAPI(t)
		if before["drops"].(float64) == 0 {
			t.Fatal("fixture recorded no drops; the rest of this gate proves nothing")
		}

		healthy := startSyslogCollector(t)
		if err := InitSyslog("tcp://"+healthy.addr, "rfc3164"); err != nil {
			t.Fatalf("re-point: %v", err)
		}
		syslogConfigured = "tcp://" + healthy.addr
		t.Cleanup(func() {
			if sw := activeSyslog(); sw != nil {
				_ = sw.Close()
			}
		})

		after := readSyslogAdminAPI(t)
		if after["drops"].(float64) < before["drops"].(float64) {
			t.Errorf("GET /api/syslog drops went BACKWARDS across a re-point: %v -> %v — the admin UI erases the loss history while /metrics keeps it",
				before["drops"], after["drops"])
		}
	})

	t.Run("a configured but never connected feed reports never-delivered", func(t *testing.T) {
		ensureObservabilityStartupTestLogger(t)
		snapshotObservabilityGlobals(t)
		resetSyslogHealthForTest()
		t.Cleanup(resetSyslogHealthForTest)

		// Exactly what loadObservability leaves behind when the dial fails.
		noteSyslogIntent("tcp://collector.invalid:601")
		syslogConfiguredAddr = "tcp://collector.invalid:601"

		body := readSyslogAdminAPI(t)
		if body["degraded"] != true {
			t.Fatalf("fixture is not in the unmet-intent state (degraded=%v)", body["degraded"])
		}
		if body["neverDelivered"] != true {
			t.Errorf("neverDelivered=%v beside degraded=true for a target that never connected — the response denies the fact the verdict rests on", body["neverDelivered"])
		}
		// CONTROL on the same field: the transport claim must follow the same
		// predicate, so a tcp:// target the operator asked for is still
		// reported as delivery-provable rather than silently downgraded.
		if body["deliveryProvable"] != true {
			t.Errorf("deliveryProvable=%v for a configured tcp:// target", body["deliveryProvable"])
		}
	})

	t.Run("an unconfigured node claims nothing", func(t *testing.T) {
		ensureObservabilityStartupTestLogger(t)
		snapshotObservabilityGlobals(t)
		resetSyslogHealthForTest()
		t.Cleanup(resetSyslogHealthForTest)

		body := readSyslogAdminAPI(t)
		for _, k := range []string{"degraded", "neverDelivered", "deliveryProvable"} {
			if body[k] != false {
				t.Errorf("%s=%v on a node that forwards nowhere; want false", k, body[k])
			}
		}
	})
}

// readSyslogAdminAPI drives the REAL handler and decodes its body. Calling
// syslogFeedState directly would pin the snapshot and say nothing about the
// handler, which is where both of these defects lived — walling the function
// is not walling the path.
func readSyslogAdminAPI(t *testing.T) map[string]any {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/syslog", http.NoBody)
	w := httptest.NewRecorder()
	apiSyslogConfig(w, adminCtx(r))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/syslog = %d, body %q", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the response: %v (%q)", err, w.Body.String())
	}
	return body
}

// TestChaos72_EventsLostToAnUnmetIntentAreCounted closes the last hole in the
// compliance-loss series this sweep exists to publish.
//
// P1-F made a configured-but-never-connected collector VISIBLE
// (`culvert_syslog_up 0`, a degraded row). It did not make the loss
// COUNTABLE: with no Writer installed, both fan-outs in store.go skip at
// `if sw := activeSyslog(); sw != nil` and charge the skipped event to
// nothing, so `culvert_syslog_drops_total` read 0 and `/healthz` carried no
// `syslogDrops` throughout the worst outage the plane can report. An operator
// asking "how much did I lose?" was answered "nothing" while the answer was
// "everything" (Codex P2, PR #1494).
//
// A Writer's counters structurally cannot hold this loss: it happens because
// there is no Writer. It belongs to the process-lifetime total, which is the
// one series meaning "events that did not reach the SIEM".
func TestChaos72_EventsLostToAnUnmetIntentAreCounted(t *testing.T) {
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	// An operator asked for a collector and the boot dial failed: intent
	// recorded, no Writer installed.
	noteSyslogIntent("tcp://siem.invalid:514")

	const lost = 7
	for i := 0; i < lost; i++ {
		noteSyslogEventSkipped()
	}

	snap := syslogFeedState()
	if !snap.Intended || snap.Configured {
		t.Fatalf("precondition: want an unmet intent (Intended=true, Configured=false), got Intended=%v Configured=%v", snap.Intended, snap.Configured)
	}
	if snap.Drops != lost {
		t.Errorf("Drops = %d after %d events found no writer; want %d — the series that measures compliance loss read clean through a total outage", snap.Drops, lost, lost)
	}

	// It reaches the exported series, not just the snapshot.
	var b strings.Builder
	syslogWritePrometheus(&b)
	if !strings.Contains(b.String(), fmt.Sprintf("culvert_syslog_drops_total %d", lost)) {
		t.Errorf("culvert_syslog_drops_total did not report the %d lost events:\n%s", lost, b.String())
	}

	// CONTROL: a node nobody asked to forward anywhere counts NOTHING. The
	// cheapest way to pass the assertions above is to count every skipped
	// event unconditionally, which would accrue a large, permanent and
	// meaningless "loss" on every appliance that does not use the feature —
	// the same emission rule the metrics plane already applies.
	resetSyslogHealthForTest()
	for i := 0; i < 100; i++ {
		noteSyslogEventSkipped()
	}
	if got := syslogFeedState().Drops; got != 0 {
		t.Errorf("an unconfigured node counted %d lost event(s); it asked for no collector, so it is losing nothing", got)
	}
}

// TestChaos72_InstallingAWriterStopsCountingSkips is the other half of the
// arming rule: once a Writer exists the events go THROUGH it and are counted
// (or not) by its own machinery. Continuing to charge skips here would
// double-count every loss.
func TestChaos72_InstallingAWriterStopsCountingSkips(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr) // installs a Writer (and resets the plane)

	if snap := syslogFeedState(); !snap.Configured {
		t.Fatalf("precondition: want a configured feed with a live writer, got Configured=%v", snap.Configured)
	}
	before := syslogFeedState().Drops
	noteSyslogEventSkipped()
	noteSyslogEventSkipped()
	if got := syslogFeedState().Drops; got != before {
		t.Errorf("Drops moved from %d to %d while a writer was installed — skips must stop being charged once events have a writer to go through, or every loss is counted twice", before, got)
	}
}

// TestChaos72_DisablingAnUnmetFeedStopsCountingSkips covers the transition the
// gate above CANNOT reach, and the reason it could not is the point.
//
// That gate disables forwarding too, but it installs a Writer first — which
// already disarms skip accounting — so its disable assertion passes whether or
// not the disable path clears the gate. It was vacuous for this transition,
// and the code it was meant to protect was in fact missing: the
// `syslogIntentArmedWithoutWriter.Store(false)` intended for
// noteSyslogForwardingDisabled silently applied nowhere (Codex P2, PR #1494).
//
// The reachable shape is the one with NO writer ever installed: intent
// recorded, dial failed, accounting armed — then the operator gives up and
// turns forwarding off. Every later audit and request event, starting with the
// disable's own audit entry, would otherwise be charged as a SIEM loss for the
// life of the process, and those bogus drops surface the moment forwarding is
// enabled again.
func TestChaos72_DisablingAnUnmetFeedStopsCountingSkips(t *testing.T) {
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	noteSyslogIntent("tcp://siem.invalid:514")
	noteSyslogEventSkipped()
	if got := syslogFeedState().Drops; got != 1 {
		t.Fatalf("precondition: Drops = %d, want 1 — skip accounting must be ARMED for this gate to prove anything", got)
	}

	noteSyslogForwardingDisabled()

	before := syslogFeedState().Drops
	for i := 0; i < 5; i++ {
		noteSyslogEventSkipped()
	}
	if got := syslogFeedState().Drops; got != before {
		t.Errorf("Drops moved from %d to %d after forwarding was disabled — a node that forwards nowhere is not losing anything, and these bogus drops reappear the moment a collector is configured again", before, got)
	}
}

// TestChaos72_HealthzReportsTheLossMetricsReports pins that the two surfaces
// answer the same question with the same predicate.
//
// /metrics exports the skipped-event total for a configured collector that
// never connected; /healthz gated its `syslogDrops` field on `Configured`,
// which is set only once a Writer exists — so it omitted exactly those losses,
// for exactly the outage where every event is being lost (Codex P2, PR #1494).
// Third instance in this sweep of establishing a rule and not enumerating the
// other readers of the same fact.
func TestChaos72_HealthzReportsTheLossMetricsReports(t *testing.T) {
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	noteSyslogIntent("tcp://siem.invalid:514")
	const lost = 4
	for i := 0; i < lost; i++ {
		noteSyslogEventSkipped()
	}

	var b strings.Builder
	syslogWritePrometheus(&b)
	if !strings.Contains(b.String(), fmt.Sprintf("culvert_syslog_drops_total %d", lost)) {
		t.Fatalf("precondition: /metrics did not report the %d lost events", lost)
	}
	if got := syslogDropCount(); got != lost {
		t.Errorf("syslogDropCount() = %d, want %d — /healthz omits the loss that /metrics reports, for the one outage where everything is being lost", got, lost)
	}

	// CONTROL: a node that was never asked to forward anywhere still reports
	// nothing. The cheapest way to pass the above is to drop the gate.
	resetSyslogHealthForTest()
	for i := 0; i < 20; i++ {
		noteSyslogEventSkipped()
	}
	if got := syslogDropCount(); got != 0 {
		t.Errorf("syslogDropCount() = %d on a node with no collector configured; want 0", got)
	}
}

// TestChaos72_TheRealFanOutChargesEventsLostToAnUnmetIntent drives the REAL
// audit and request-log paths, not the counter behind them.
//
// This section has had to record "walling the function is not walling the
// path" three times already. The skip happens at
// `if sw := activeSyslog(); sw != nil` inside store.go's two fan-outs, so a
// gate that calls noteSyslogEventSkipped directly proves the counter works
// and says nothing about whether either fan-out reaches it — which is exactly
// where the defect lived.
func TestChaos72_TheRealFanOutChargesEventsLostToAnUnmetIntent(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	// An operator asked for a collector; the dial failed, so no Writer exists.
	setActiveSyslog(nil)
	noteSyslogIntent("tcp://siem.invalid:514")
	if activeSyslog() != nil {
		t.Fatal("precondition: want no active writer")
	}

	before := syslogFeedState().Drops

	// The audit fan-out (audit.SetSIEM, wired in store.go's init).
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/policy", http.NoBody)
	req.RemoteAddr = "198.51.100.77:5555"
	auditEvent(req, "policy.update", "rule-1", "chaos72 unmet-intent path gate")

	// The request-log fan-out.
	recordRequest("198.51.100.77", http.MethodGet, "example.com", "200", "", "allow", "", "")

	got := syslogFeedState().Drops
	if got != before+2 {
		t.Errorf("Drops = %d after one audit event and one request-log entry found no writer; want %d.\n"+
			"Both fan-outs in store.go skip silently at `if sw := activeSyslog(); sw != nil`, so the "+
			"compliance-loss series reads clean while every event is being lost.", got, before+2)
	}
}

// The operator surface an admin actually reads must name the MAGNITUDE, not
// just the state. "Events are not reaching the collector" is the diagnosis;
// "how much have I lost?" is the next question, and the answer was
// structurally zero until the loss was counted.
func TestChaos72_FailedToConnectRowNamesTheLoss(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	setActiveSyslog(nil)
	syslogConfigured = ""
	syslogConfiguredAddr = "tcp://siem.invalid:514"
	noteSyslogIntent(syslogConfiguredAddr)

	row := checkSyslogFeed()
	if row.Status != diagFail {
		t.Fatalf("precondition: row = %v (%s); want fail", row.Status, row.Message)
	}
	if strings.Contains(row.Message, "lost so far") {
		t.Errorf("the row claimed a loss before any event was skipped: %q", row.Message)
	}

	for i := 0; i < 3; i++ {
		noteSyslogEventSkipped()
	}
	row = checkSyslogFeed()
	if !strings.Contains(row.Message, "3 event(s) lost so far") {
		t.Errorf("row message = %q; want it to name the 3 events lost to a collector that never came up", row.Message)
	}
}

// TestChaos72_SnapshotReadsTheWriterItCaptured pins that syslogFeedState reads
// its Writer stats from the generation it captured under the lock, never from
// a fresh activeSyslog() load.
//
// The record's retired totals and the writer it describes are copied together
// under syslogHealth.mu. Re-loading the active writer AFTER releasing that lock
// reads a possibly LATER generation: a re-point landing in between retires the
// displaced writer's finals into a `retiredDrops` this snapshot has already
// copied, so that whole generation vanishes from the sum and
// `culvert_syslog_drops_total` DECREASES for one scrape — a counter reset to
// Prometheus, and exactly the defect P2-4 exists to prevent, re-entering
// through a reader that does not participate in syslogPublishMu (Codex P2).
//
// The interleaving is a few instructions wide and cannot be scheduled through
// the public entry point, so the MECHANISM is pinned by source scan — the
// convention this file already uses for wiring — rather than by a race gate
// that would pass against the defect most of the time.
func TestChaos72_SnapshotReadsTheWriterItCaptured(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "syslog_health.go"))
	if err != nil {
		t.Fatalf("read syslog_health.go: %v", err)
	}
	body := syslogFuncBody(t, string(src), "func syslogFeedState() syslogFeedSnapshot {")
	if strings.Contains(body, "activeSyslog()") {
		t.Error("syslogFeedState loads activeSyslog() after releasing syslogHealth.mu — " +
			"a re-point in that window pairs a NEW writer's counters with retired totals that " +
			"already absorbed the OLD one, so the process-lifetime totals lose a whole generation " +
			"and culvert_syslog_drops_total goes backwards")
	}
	if !strings.Contains(body, "sw := described") {
		t.Error("syslogFeedState no longer reads the captured writer; the snapshot is only " +
			"internally consistent if the stats and the retired totals come from one capture")
	}

	// Not vacuous: the extractor must really be returning this function's body,
	// and that body must contain something only it contains.
	if !strings.Contains(body, "retiredDrops") {
		t.Fatal("control: the extracted body is not syslogFeedState's, so the scan proves nothing")
	}
	// Control: activeSyslog() is still used elsewhere in the file — the rule is
	// about THIS reader, not a ban on the accessor.
	if !strings.Contains(string(src), "activeSyslog()") {
		t.Error("control: activeSyslog() vanished from the file entirely, which is not the fix")
	}
}

// syslogFuncBody returns the source between a function's opening line and its
// closing brace at column 0.
func syslogFuncBody(t *testing.T, src, decl string) string {
	t.Helper()
	i := strings.Index(src, decl)
	if i < 0 {
		t.Fatalf("declaration not found: %s", decl)
	}
	rest := src[i+len(decl):]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		rest = rest[:j]
	}
	// Strip line comments: the scan is about what the function CALLS, and the
	// rationale comments in this file name the very accessor being banned.
	// Scanning prose would make the gate assert the absence of an explanation.
	var code strings.Builder
	for _, line := range strings.Split(rest, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	return code.String()
}

// TestChaos72_SupersededTargetIsNotReportedAsNeverConnected pins that the
// unmet-intent alert tells the truth in BOTH shapes it can reach.
//
// A boot that connects target A and then fails to connect the persisted
// target B leaves the writer for A live while the record's intent is B. That
// is an unmet intent — correctly reported degraded — but the alert said "no
// connection was ever established" and "NOTHING is serving it". Both are
// FALSE there: a connection was established, something is serving, and events
// are reaching a collector, just not the configured one. A false statement on
// an operator surface, inside the alert this sweep added to remove exactly
// that (Codex P2, PR #1494).
//
// The two shapes are distinguished by `Configured`, which is true only once a
// Writer is installed. Neither sentence names a target: Detail is the alert
// dedup key and an operator-supplied address there is WK-12/RS-5.
func TestChaos72_SupersededTargetIsNotReportedAsNeverConnected(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr) // target A connects

	// The operator's persisted target B never connects: intent moves, the
	// writer for A stays live.
	noteSyslogIntent("tcp://siem-b.invalid:514")

	snap := syslogFeedState()
	if !snap.IntentUnmet || !snap.Configured {
		t.Fatalf("precondition: want an unmet intent WITH a live writer, got IntentUnmet=%v Configured=%v", snap.IntentUnmet, snap.Configured)
	}
	if !snap.Degraded {
		t.Error("a superseded target must still report degraded")
	}

	detail := captureSyslogAlertDetail(t, snap)
	if strings.Contains(detail, "no connection was ever established") ||
		strings.Contains(detail, "NOTHING is serving") {
		t.Errorf("the alert claims nothing ever connected, but target A is connected and serving:\n%s", detail)
	}
	if !strings.Contains(detail, "PREVIOUS target") {
		t.Errorf("the alert does not tell the operator events are going to the previous collector:\n%s", detail)
	}
	// Bounded: never the operator-supplied address, which is the dedup key.
	if strings.Contains(detail, col.addr) || strings.Contains(detail, "siem-b.invalid") {
		t.Errorf("the alert Detail names a collector address, which is the dedup key (WK-12/RS-5):\n%s", detail)
	}

	// CONTROL: with NO writer ever installed, the original sentence is the
	// correct one and must be kept. The cheapest way to pass the assertions
	// above is to use the superseded wording unconditionally, which would be
	// just as false in the other direction.
	resetSyslogHealthForTest()
	noteSyslogIntent("tcp://siem-b.invalid:514")
	snap2 := syslogFeedState()
	if snap2.Configured {
		t.Fatalf("control precondition: want no writer, got Configured=true")
	}
	detail2 := captureSyslogAlertDetail(t, snap2)
	if !strings.Contains(detail2, "no connection was ever established") {
		t.Errorf("control: a feed that never connected must still say so:\n%s", detail2)
	}
}

// captureSyslogAlertDetail drives the real commit half and returns the Detail
// it would page with, so a gate reads the operator-facing sentence rather than
// a model of it.
func captureSyslogAlertDetail(t *testing.T, snap syslogFeedSnapshot) string {
	t.Helper()
	var got []string
	old := fireSyslogFeedDownAlert
	fireSyslogFeedDownAlert = func(d string) { got = append(got, d) }
	defer func() { fireSyslogFeedDownAlert = old }()

	// Force the alert edge: the commit half fires once per episode.
	syslogHealth.mu.Lock()
	syslogHealth.alerted = false
	syslogHealth.logAt = time.Time{}
	syslogHealth.mu.Unlock()

	snap.Degraded = true
	commitSyslogDegradation(snap)
	if len(got) == 0 {
		t.Fatal("no alert Detail was produced, so this gate reads nothing")
	}
	return got[len(got)-1]
}

// TestChaos72_RecordWriterPairingIsAnInvariant pins that the health record's
// `configured` flag and its `writer` pointer are set and cleared TOGETHER.
//
// Three consumers read `Configured` as "a writer exists": the metrics plane's
// emission gate, `/healthz`'s drop field (via `Configured || Intended`), and
// the admin API. A fourth used to be the unmet-intent alert's branch, which
// round 9 moved onto `snap.writer` directly once this pairing was recognised
// as an unstated assumption rather than a stated rule — CHAOS-66 records
// `configured` for the SOCKS5 listener BEFORE its first bind, deliberately,
// so the move is one this repo has already made once in a sibling plane.
//
// This wall states the rule so the remaining three consumers keep their
// meaning. It is BEHAVIOURAL over every transition that touches either field,
// because a source scan would pass against an install path that set them in
// two separate critical sections — which is the shape that actually breaks it.
func TestChaos72_RecordWriterPairingIsAnInvariant(t *testing.T) {
	check := func(stage string) {
		t.Helper()
		syslogHealth.mu.Lock()
		configured, writer := syslogHealth.configured, syslogHealth.writer
		syslogHealth.mu.Unlock()
		if configured != (writer != nil) {
			t.Errorf("%s: configured=%v but writer!=nil is %v — the record's two "+
				"halves disagree, so every consumer reading Configured as "+
				"\"a writer exists\" is now wrong", stage, configured, writer != nil)
		}
	}

	resetSyslogHealthForTest()
	check("after reset")

	noteSyslogIntent("tcp://siem.invalid:514")
	check("intent recorded, no writer")

	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	check("writer installed")

	// A superseded target: intent moves, the writer stays.
	noteSyslogIntent("tcp://siem-b.invalid:514")
	check("intent superseded")

	noteSyslogForwardingDisabled()
	check("forwarding disabled")

	// CONTROL: the wall must be able to see a violation, or it proves nothing.
	syslogHealth.mu.Lock()
	syslogHealth.configured = true // writer is nil here
	syslogHealth.mu.Unlock()
	violated := false
	func() {
		syslogHealth.mu.Lock()
		configured, writer := syslogHealth.configured, syslogHealth.writer
		syslogHealth.mu.Unlock()
		violated = configured != (writer != nil)
	}()
	if !violated {
		t.Fatal("control: the pairing check cannot observe a divergence, so it proves nothing")
	}
	resetSyslogHealthForTest()
}

// A degradation snapshotted against a configured-but-unreachable feed must not
// be committed into the record of a feed the operator has since DISABLED
// (CHAOS-72, Codex P2 round 10).
//
// Round 9 closed the stale-commit window with a pointer comparison against the
// snapshot's Writer. That answered the question everywhere except the one case
// that matters most here: a boot dial that FAILED leaves `writer == nil`, and
// `noteSyslogForwardingDisabled` also sets `writer = nil`, so
// `syslogHealth.writer != snap.writer` is `nil != nil` — false, and the stale
// callback committed anyway. It paged `syslog_feed_down` for a feature the
// operator had just switched off, and set `alerted` on the fresh record, so
// the next time forwarding is enabled its first real outage is silent. That is
// the P1-G defect surviving in the one shape a pointer cannot see, on exactly
// the transition an operator makes to remediate an unreachable collector.
//
// The window is microseconds wide and cannot be scheduled through the public
// entry point, so the commit half is driven directly — the same reason the
// round-9 gate above does.
func TestChaos72_DisabledFeedDoesNotInheritAnInFlightDegradation(t *testing.T) {
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	var fired []string
	prev := fireSyslogFeedDownAlert
	fireSyslogFeedDownAlert = func(d string) { fired = append(fired, d) }
	t.Cleanup(func() { fireSyslogFeedDownAlert = prev })

	// An operator asks for a collector whose dial fails: intent recorded, no
	// Writer installed. Nothing retries, so the plane reports it degraded
	// immediately — this is the snapshot that goes in flight.
	noteSyslogIntent("tcp://siem.invalid:601")
	snap := syslogFeedState()
	if !snap.IntentUnmet || snap.writer != nil {
		t.Fatalf("precondition: want an unmet intent with NO writer, got IntentUnmet=%v writer=%v", snap.IntentUnmet, snap.writer)
	}
	if !snap.Degraded {
		t.Fatal("precondition: an unmet intent must report degraded, or this gate commits nothing")
	}

	// The operator gives up and turns forwarding off.
	noteSyslogForwardingDisabled()

	commitSyslogDegradation(snap)
	if len(fired) != 0 {
		t.Errorf("a snapshot taken before the operator disabled forwarding paged about the disabled feed: %q", fired)
	}
	syslogHealth.mu.Lock()
	latched := syslogHealth.alerted
	syslogHealth.mu.Unlock()
	if latched {
		t.Fatal("the stale commit latched the record of a DISABLED feed — the next enabled collector's first real outage would be silent, and nothing but an install clears the latch")
	}

	// CONTROL: the same shape, committed against the generation it was taken
	// from, must still page. The cheapest way to pass every assertion above is
	// a commit half that refuses everything, which would delete the alert this
	// whole plane exists to produce.
	resetSyslogHealthForTest()
	noteSyslogIntent("tcp://siem.invalid:601")
	fresh := syslogFeedState()
	if !fresh.Degraded {
		t.Fatal("control precondition: the control snapshot is not degraded")
	}
	commitSyslogDegradation(fresh)
	if len(fired) != 1 {
		t.Fatalf("a live unmet intent fired %d alerts; want 1", len(fired))
	}
}

// The probe must classify its transport from the WRITER that served the line,
// never from an address string read separately (CHAOS-72, Codex P2 round 10).
//
// syslogDeliveryProbe took the Writer as a parameter and then read
// `syslogHealth.target` in its own critical section afterwards. Those are two
// reads of two different things, so an admin re-point landing between them
// made the endpoint describe a UDP datagram with the TCP sentence — "the
// collector accepted the test event" — for a send nothing may have received.
// UDP's inability to prove delivery is register row SL-1 and is stated on
// every other surface in this plane; the one endpoint an operator is told to
// use to CONFIRM connectivity was the one that could contradict it.
func TestChaos72_ProbeClassifiesTransportFromTheWriterThatServedIt(t *testing.T) {
	armSyslogFeed(t, "udp://127.0.0.1:65533")
	sw := activeSyslog()
	if sw == nil {
		t.Fatal("precondition: no writer was installed")
	}

	// Simulate the re-point window: the record now names a TCP collector while
	// the Writer the probe was handed is still the UDP one.
	syslogHealth.mu.Lock()
	syslogHealth.target = "tcp://siem-b.invalid:601"
	syslogHealth.mu.Unlock()

	outcome, detail := syslogDeliveryProbe(sw)
	if outcome == "delivered" {
		t.Errorf("the probe reported %q for a UDP datagram because the record named a tcp:// target: %s", outcome, detail)
	}
	if outcome != "sent" {
		t.Fatalf("probe outcome = %q (%s); want \"sent\" for a UDP writer", outcome, detail)
	}

	// CONTROL: a TCP writer must still report delivery, and must do so even
	// when the record names a udp:// target. The cheapest way to pass the
	// assertion above is to answer "sent" unconditionally, which would delete
	// the only affirmative delivery evidence this endpoint can give.
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)
	tcpWriter := activeSyslog()
	if tcpWriter == nil {
		t.Fatal("control precondition: no TCP writer was installed")
	}
	syslogHealth.mu.Lock()
	syslogHealth.target = "udp://siem-c.invalid:514"
	syslogHealth.mu.Unlock()
	if outcome, detail := syslogDeliveryProbe(tcpWriter); outcome != "delivered" {
		t.Errorf("control: a TCP writer reported %q (%s); want \"delivered\" regardless of what the record names", outcome, detail)
	}
}

// Every transition that CHANGES what the health record describes must advance
// its generation (CHAOS-72, Codex P2 round 10).
//
// The stale-commit guard is now `syslogHealth.gen != snap.gen`, so a future
// transition that swaps `writer` without bumping `gen` silently reopens the
// defect: a snapshot from before it would commit into the record after it,
// paging about the old feed and latching the new one. No behavioural gate can
// reach that — the sites are correct today and a new one would simply not be
// exercised by any existing test — so the invariant is pinned over the real
// transitions rather than left to review.
//
// Stated as "writer changed ⇒ gen advanced", not as an exact bump count: the
// point is that the identity cannot be reused, and extra bumps are harmless
// (they only ever refuse a stale commit that would have been refused anyway).
func TestChaos72_EveryRecordTransitionAdvancesTheGeneration(t *testing.T) {
	read := func() (*syslogWriter, uint64) {
		syslogHealth.mu.Lock()
		defer syslogHealth.mu.Unlock()
		return syslogHealth.writer, syslogHealth.gen
	}
	// The invariant, named once so the control below applies literally the
	// same rule rather than a hand-negated restatement of it — a control that
	// re-derives the predicate can pass while the predicate it is meant to
	// vouch for has drifted.
	violates := func(beforeW, afterW *syslogWriter, beforeG, afterG uint64) bool {
		return beforeW != afterW && afterG <= beforeG
	}
	step := func(stage string, fn func()) {
		t.Helper()
		beforeW, beforeG := read()
		fn()
		afterW, afterG := read()
		if violates(beforeW, afterW, beforeG, afterG) {
			t.Errorf("%s: the record's writer changed (%p -> %p) but the generation did not advance (%d -> %d) — "+
				"a snapshot taken before this transition would still be accepted by commitSyslogDegradation, "+
				"which is the stale-commit defect reopened", stage, beforeW, afterW, beforeG, afterG)
		}
	}

	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)

	// The transitions are driven DIRECTLY, not through armSyslogFeed: that
	// helper resets the record first, and the reset's own bump would mask a
	// missing one at the install site — the wall would then pass against a
	// tree that had dropped it. (Verified: it did, before this was changed.)
	sw1, err := newSyslogWriter("udp", "127.0.0.1:65533", "rfc3164")
	if err != nil {
		t.Fatalf("building the first writer: %v", err)
	}
	t.Cleanup(func() { _ = sw1.Close() })
	sw2, err := newSyslogWriter("udp", "127.0.0.1:65532", "rfc3164")
	if err != nil {
		t.Fatalf("building the second writer: %v", err)
	}
	t.Cleanup(func() { _ = sw2.Close() })

	step("install", func() { noteSyslogWriterInstalled(sw1, "udp://127.0.0.1:65533") })
	step("re-point", func() { noteSyslogWriterInstalled(sw2, "udp://127.0.0.1:65532") })
	// An intent that does not change the writer need not bump; the invariant
	// is one-directional and this exercises that it does not over-claim.
	step("intent superseded", func() { noteSyslogIntent("tcp://siem-b.invalid:514") })
	// The reset is stepped while a writer is INSTALLED. Stepping it after the
	// disable would observe no writer change at all, so a tree that had
	// dropped its bump would pass — the same masking the install site had.
	// It is not test-only plumbing: a snapshot from one gate committing into
	// the next gate's record is exactly the cross-test pollution this record's
	// isolation exists to prevent.
	step("reset while installed", resetSyslogHealthForTest)
	step("re-install", func() { noteSyslogWriterInstalled(sw1, "udp://127.0.0.1:65533") })
	step("disable", func() { noteSyslogForwardingDisabled() })

	// CONTROL: the wall must be able to SEE a violation, or a selector that
	// matched nothing would pass forever.
	sw, err := newSyslogWriter("udp", "127.0.0.1:65533", "rfc3164")
	if err != nil {
		t.Fatalf("building a writer for the control: %v", err)
	}
	t.Cleanup(func() { _ = sw.Close() })
	beforeW, beforeG := read()
	syslogHealth.mu.Lock()
	syslogHealth.writer = sw // deliberately without bumping gen
	syslogHealth.mu.Unlock()
	afterW, afterG := read()
	if !violates(beforeW, afterW, beforeG, afterG) {
		t.Fatal("control: the invariant cannot observe a writer swap that skips the bump, so it proves nothing")
	}
	syslogHealth.mu.Lock()
	syslogHealth.writer = nil
	syslogHealth.mu.Unlock()
}

// The transport claim must have ONE source (CHAOS-72, round 10 self-review).
//
// Round 10's P2-14 was the probe deriving "can this transport prove delivery"
// from the health record's target string while the Writer that served the line
// was right there as a parameter. The contract row and `GET /api/syslog` read
// the same fact off `snap.UDP`, which was derived the same way.
//
// Both derivations agree today: `InitSyslog` is the only installer and hands
// the record the very address it parsed the network from. That is what makes
// the string form a latent trap rather than a live defect — and this repo's
// own rule is that two answers to one question IS the defect (CHAOS-61), so
// the agreement is walled rather than left to the next person to notice.
//
// The fallback is deliberately kept and is not a second answer: a feed with no
// Writer has no transport to ask, and the operator's intended address is the
// only thing that can describe what they asked for.
func TestChaos72_TransportClaimHasOneSource(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		wantUDP bool
	}{
		{"udp://127.0.0.1:65533", true},
		{"tcp://%s", false},
	} {
		addr := tc.addr
		if strings.Contains(addr, "%s") {
			col := startSyslogCollector(t)
			addr = fmt.Sprintf(addr, col.addr)
		}
		armSyslogFeed(t, addr)
		sw := activeSyslog()
		if sw == nil {
			t.Fatalf("%s: no writer installed", addr)
		}
		snap := syslogFeedState()
		if snap.UDP != tc.wantUDP {
			t.Errorf("%s: snapshot UDP=%v, want %v", addr, snap.UDP, tc.wantUDP)
		}
		if snap.UDP == sw.DeliveryProvable() {
			t.Errorf("%s: the snapshot's transport claim (UDP=%v) contradicts the writer that serves it "+
				"(DeliveryProvable=%v) — the contract row, /api/syslog and POST /api/syslog/test would "+
				"disagree about whether this feed can prove delivery", addr, snap.UDP, sw.DeliveryProvable())
		}
	}

	// The record's address string must not be able to override the writer.
	// This is the shape P2-14 had, checked on the surface that still holds a
	// string: a rewritten or re-pointed target cannot silently flip the caveat.
	armSyslogFeed(t, "udp://127.0.0.1:65533")
	syslogHealth.mu.Lock()
	syslogHealth.target = "tcp://siem-b.invalid:601"
	syslogHealth.mu.Unlock()
	if snap := syslogFeedState(); !snap.UDP {
		t.Error("a tcp:// address on the record overrode a UDP writer's own transport — " +
			"the contract row would drop the 'delivery cannot be confirmed' caveat for a feed that cannot confirm it")
	}

	// CONTROL: with NO writer, the operator's intended address still decides.
	// The cheapest way to pass the assertions above is to hardwire UDP, which
	// would put the caveat on a TCP feed that never came up and tell an
	// operator their evidence-capable collector cannot give evidence.
	resetSyslogHealthForTest()
	noteSyslogIntent("tcp://siem.invalid:601")
	if snap := syslogFeedState(); snap.UDP {
		t.Error("control: a configured-but-unconnected tcp:// collector must not carry the UDP caveat")
	}
	resetSyslogHealthForTest()
	noteSyslogIntent("udp://siem.invalid:514")
	if snap := syslogFeedState(); !snap.UDP {
		t.Error("control: a configured-but-unconnected udp:// collector must still carry the UDP caveat")
	}
}
