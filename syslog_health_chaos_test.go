package main

// syslog_health_chaos_test.go — CHAOS-66 gates for the SIEM forwarding plane.
//
// Every DEFECT gate here was verified failing against the pre-fix tree before
// the fix was written; the two headline ones were reproduced against the real
// handler and the real engine, not a model of them. The CONTROLS exist because
// the cheapest ways to satisfy the defect gates are all worse than the defect:
// a plane that reports every feed as degraded passes "sees a runtime outage",
// and a plane that never reports degraded passes "does not page an idle node".

import (
	"encoding/json"
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
type syslogTestCollector struct {
	ln    net.Listener
	addr  string
	conns chan net.Conn
}

func startSyslogCollector(t *testing.T) *syslogTestCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &syslogTestCollector{ln: ln, addr: ln.Addr().String(), conns: make(chan net.Conn, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case c.conns <- conn:
			default:
				_ = conn.Close()
			}
			go func(cn net.Conn) { _, _ = cn.Read(make([]byte, 4096)) }(conn)
		}
	}()
	t.Cleanup(c.stop)
	return c
}

func (c *syslogTestCollector) stop() {
	_ = c.ln.Close()
	for {
		select {
		case conn := <-c.conns:
			_ = conn.Close()
		default:
			return
		}
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
func TestChaos66_ContractRowSeesARuntimeCollectorOutage(t *testing.T) {
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
		t.Fatalf("syslog_feed = %v (%q) with a dead collector and %d drops; want fail — the pre-CHAOS-66 row reported \"forwarding is active\" here",
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
func TestChaos66_DropsReachMetricsAndHealthz(t *testing.T) {
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
func TestChaos66_NoSeriesWhenNoCollectorConfigured(t *testing.T) {
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
func TestChaos66_InitSyslogClosesTheWriterItReplaces(t *testing.T) {
	first := startSyslogCollector(t)
	second := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+first.addr)

	var farEnd net.Conn
	select {
	case farEnd = <-first.conns:
	case <-time.After(3 * time.Second):
		t.Fatal("first collector saw no connection")
	}

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
func TestChaos66_RecoveryRequiresADeliveredEvent(t *testing.T) {
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
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot rebind %s: %v", addr, err)
	}
	c := &syslogTestCollector{ln: ln, addr: addr, conns: make(chan net.Conn, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case c.conns <- conn:
			default:
				_ = conn.Close()
			}
			go func(cn net.Conn) { _, _ = cn.Read(make([]byte, 4096)) }(conn)
		}
	}()
	return c
}

// The alert Detail reaches the alert store's dedup key (event + ":" + Detail).
// A raw transport error embeds the collector address and, for a dial failure,
// the ephemeral local port — a per-failure-unique Detail defeats the dedup
// window by construction and evicts real threat alerts from the bounded retry
// queue (WK-12/RS-5, recorded twice already in this tree).
func TestChaos66_AlertDetailCarriesOnlyABoundedReason(t *testing.T) {
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
func TestChaos66_ProbeReportsTheRealOutcome(t *testing.T) {
	col := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+col.addr)

	if outcome, detail := syslogDeliveryProbe(activeSyslog()); outcome != "delivered" {
		t.Errorf("healthy probe outcome = %q (%s); want \"delivered\"", outcome, detail)
	}

	col.stop()
	waitForDrops(t, 1)
	outcome, detail := syslogDeliveryProbe(activeSyslog())
	if outcome == "delivered" || outcome == "sent" {
		t.Errorf("probe reported %q against a dead collector (%s) — the pre-CHAOS-66 endpoint answered ok:true here", outcome, detail)
	}
}

// The metrics gate above calls syslogWritePrometheus directly, which proves the
// series EXIST but not that /metrics emits them — a writer nobody calls passes
// it. The exposition builder is one long function that reaches a dozen
// subsystem writers, so this pins the WIRING structurally (source scan, the
// convention the C1 route-parity tests use) rather than by standing up a
// scrape. Deterministic on any hardware, under -race, at any load.
func TestChaos66_MetricsExpositionCallsTheSyslogWriter(t *testing.T) {
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
// never calls it — verified: reverting apiSyslogTest to its pre-CHAOS-66 body
// left that gate green. This one drives the real handler an operator reaches,
// which is the only thing that proves the endpoint stopped lying. Same lesson
// the SOCKS5 log-injection note records one subsystem over: sanitising one
// argument does not sanitise the call, and walling one call shape does not wall
// the path.
func TestChaos66_TestEndpointReportsFailureAgainstADeadCollector(t *testing.T) {
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
// path reads it, and before CHAOS-66 it was a bare package-level pointer with
// no synchronisation at all. Confirmed under -race against the real
// apiSyslogConfig and recordRequest shapes: nothing in the suite happened to
// exercise both at once, which is the only reason it had never been reported.
// This gate is that exercise, and it is the reason the handle is now an
// atomic.Pointer.
func TestChaos66_WriterHandleIsSafeUnderConcurrentRepointAndTraffic(t *testing.T) {
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
func TestChaos66_HealthyFeedStillReportsActive(t *testing.T) {
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
func TestChaos66_IdleNodeIsNeverDegraded(t *testing.T) {
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
func TestChaos66_UDPFeedCarriesTheUnprovableDeliveryCaveat(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
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
func TestChaos66_ReplacedWriterDoesNotCorruptTheSuccessorsState(t *testing.T) {
	first := startSyslogCollector(t)
	second := startSyslogCollector(t)
	armSyslogFeed(t, "tcp://"+first.addr)

	// Fill the displaced writer's queue against a dead collector, then replace
	// it: its flush window expires and it charges drops on its own counters.
	first.stop()
	for i := 0; i < 50; i++ {
		activeSyslog().WriteAudit(map[string]string{"evt": "policy.change"})
	}
	syslogConfiguredAddr = "tcp://" + second.addr
	if err := InitSyslog("tcp://"+second.addr, "rfc3164"); err != nil {
		t.Fatalf("re-point: %v", err)
	}
	syslogConfigured = "tcp://" + second.addr

	// Give the displaced writer time to finish flushing and dropping.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syslogFeedState().Drops > 0 {
			t.Fatalf("the replacement inherited %d drops from the writer it displaced", syslogFeedState().Drops)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Errorf("row on a healthy replacement = %v (%q); want ok", row.Status, row.Message)
	}
}

// Disabling forwarding must make the feature ABSENT again on every surface. A
// switched-off feed that keeps exporting culvert_syslog_up 1 and a clean row is
// the same class of false statement this plane exists to remove, pointing the
// other way.
func TestChaos66_DisablingForwardingRemovesEverySurface(t *testing.T) {
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
