package main

// syslog_feed_chaos_test.go — CHAOS-66 gates for the SIEM forwarding path.
//
// Every DEFECT gate here was verified failing against the pre-fix tree before
// the fix was written; the evidence is recorded per gate. The CONTROLS exist
// because the cheapest way to pass most of these gates is to make the feed
// report failure more readily, or to stop forwarding at all — both of which
// are worse than the defect.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// ─── harness ────────────────────────────────────────────────────────────────

// fakeCollector is a TCP syslog collector that can be made to die.
type fakeCollector struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	lines []string
	dead  bool
}

func newFakeCollector(t *testing.T) *fakeCollector {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fc := &fakeCollector{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fc.mu.Lock()
			fc.conns = append(fc.conns, c)
			fc.mu.Unlock()
			go fc.read(c)
		}
	}()
	t.Cleanup(fc.kill)
	return fc
}

func (fc *fakeCollector) read(c net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			fc.mu.Lock()
			fc.lines = append(fc.lines, string(buf[:n]))
			fc.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (fc *fakeCollector) addr() string { return "tcp://" + fc.ln.Addr().String() }

func (fc *fakeCollector) received() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.lines)
}

// kill takes the collector away the way a real one goes away: the listener
// stops accepting AND every established connection is reset.
func (fc *fakeCollector) kill() {
	fc.mu.Lock()
	if fc.dead {
		fc.mu.Unlock()
		return
	}
	fc.dead = true
	conns := fc.conns
	fc.mu.Unlock()
	_ = fc.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

// withSyslogTestEnv isolates the process-global syslog state for one test.
//
// adminSettingsPath is redirected to a per-test file because the two gates that
// drive apiSyslogConfig reach adminSettingsSave(), which writes the process-wide
// admin settings on a DETACHED goroutine. Left alone, those gates would persist
// a syslog target into whatever path the shuffled run happened to leave set, and
// a later test would load it — an order-dependent failure that only appears
// under -shuffle, which is precisely what the determinism gate exists to catch.
// The cleanup waits on adminSettingsSaveWG before restoring the path, or the
// detached save lands after the restore and writes to the real file anyway.
func withSyslogTestEnv(t *testing.T) {
	t.Helper()
	prevW := setActiveSyslog(nil)
	prevCfg, prevIntent := syslogConfiguredTarget(), syslogIntent()
	prevAlert := fireSyslogFeedAlert
	prevSettingsPath := adminSettingsPath
	adminSettingsPath = filepath.Join(t.TempDir(), "admin_settings.json")
	resetSyslogFeedHealth()
	t.Cleanup(func() {
		adminSettingsSaveWG.Wait()
		adminSettingsPath = prevSettingsPath
		releaseSyslogWriter(setActiveSyslog(prevW))
		setSyslogConfiguredTarget(prevCfg)
		setSyslogIntent(prevIntent)
		fireSyslogFeedAlert = prevAlert
		resetSyslogFeedHealth()
	})
}

// driveUntil forwards audit lines until cond holds or the budget expires.
func driveUntil(t *testing.T, budget time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if sw := activeSyslog(); sw != nil {
			sw.WriteAudit(map[string]string{"evt": "compliance"})
		}
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// scrapedCounter pulls one unlabelled series' value out of a /metrics body.
func scrapedCounter(t *testing.T, body, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(strings.TrimPrefix(line, name+" "), "%g", &v); err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		return v
	}
	t.Fatalf("series %q absent from scrape", name)
	return 0
}

func syslogAdminReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
}

func syslogAdminJSONReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
}

// ─── DEFECT GATES ───────────────────────────────────────────────────────────

// TestChaos66_ContractRowReportsDeliveryNotStartupConnect pins that the
// syslog_feed row answers "is the collector receiving", not "did we connect
// once at startup".
//
// PRE-FIX EVIDENCE: with the collector killed and 200 audit events forwarded,
// Drops() reached 200 and checkSyslogFeed still returned
// diagOK / "remote syslog/SIEM forwarding is active". The row verified that
// the process connected once at startup, not that anything is being received.
func TestChaos66_ContractRowReportsDeliveryNotStartupConnect(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)

	setSyslogIntent(fc.addr())
	setSyslogConfiguredTarget(fc.addr())
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !driveUntil(t, 2*time.Second, func() bool { return fc.received() > 0 }) {
		t.Fatal("collector never received a line while healthy")
	}
	t.Logf("health record: %+v", syslogFeedState())
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Fatalf("healthy feed should be ok, got %v: %s", row.Status, row.Message)
	}

	fc.kill()

	sw := activeSyslog()
	if !driveUntil(t, 5*time.Second, func() bool { return sw.Drops() > 0 }) {
		t.Fatalf("no drops recorded after the collector died (drops=%d)", sw.Drops())
	}
	row := checkSyslogFeed()
	if row.Status == diagOK {
		t.Fatalf("DEFECT: %d message(s) lost and syslog_feed still reports ok: %q", sw.Drops(), row.Message)
	}
	if strings.Contains(row.Message, "active") {
		t.Fatalf("row must not claim the feed is active while dropping: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Fatal("a failing feed must carry an operator action")
	}
}

// TestChaos66_InitDoesNotLeakItsPredecessor pins that installing a forwarder
// releases the one it displaced.
//
// PRE-FIX EVIDENCE: five InitSyslog calls left five drain goroutines running
// and five TCP connections open — the predecessor was overwritten, never
// closed, and nothing else held the pointer. Reachable twice on an ordinary
// boot (YAML slice, then persisted admin settings) and once per
// POST /api/syslog, i.e. unbounded by operator action.
func TestChaos66_InitDoesNotLeakItsPredecessor(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)

	// Settle, then measure.
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	before := runtime.NumGoroutine()

	const installs = 6
	for i := 0; i < installs; i++ {
		if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
	}
	releaseSyslogWriter(setActiveSyslog(nil)) // release the last one too

	deadline := time.Now().Add(10 * time.Second)
	var after int
	for time.Now().Before(deadline) {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("DEFECT: %d goroutine(s) leaked across %d installs (before=%d after=%d)",
		after-before, installs, before, after)
}

// TestChaos66_ConnectFailureAtBootStillArmsForwarding pins that a collector
// unreachable at boot leaves forwarding ARMED and self-healing, not off.
//
// PRE-FIX EVIDENCE: InitSyslog fails closed on its first dial, and both boot
// callers log-and-continue with globalSyslog nil. Nothing ever constructs a
// second writer, so a collector that was down at boot — or merely slower to
// start than the proxy beside it in the same compose file — meant SIEM
// forwarding was OFF for the life of the process.
func TestChaos66_ConnectFailureAtBootStillArmsForwarding(t *testing.T) {
	withSyslogTestEnv(t)

	// Bind and immediately release a port so the address is well-formed and
	// routable but nothing is listening on it.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	setSyslogIntent("tcp://" + addr)
	setSyslogConfiguredTarget("tcp://" + addr)
	if err := InitSyslogResilient("tcp://"+addr, "rfc3164"); err == nil {
		t.Skip("port was re-bound by another process; the dial unexpectedly succeeded")
	}
	if activeSyslog() == nil {
		t.Fatal("DEFECT: a failed first dial left no forwarder — forwarding is off for the life of the process")
	}

	// The collector comes back. Recovery must be automatic: no restart, no
	// operator re-save.
	ln2, err := lc.Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Skipf("could not re-bind %s to simulate the collector returning: %v", addr, err)
	}
	defer ln2.Close()
	got := make(chan struct{}, 1)
	go func() {
		c, err := ln2.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		if n, _ := c.Read(buf); n > 0 {
			select {
			case got <- struct{}{}:
			default:
			}
		}
	}()

	// deliverLine's reconnect backoff is 5s, so allow more than one window.
	if !driveUntil(t, 20*time.Second, func() bool {
		select {
		case <-got:
			return true
		default:
			return false
		}
	}) {
		t.Fatal("DEFECT: forwarding never recovered after the collector returned")
	}
	// Recovery is reported on OBSERVED evidence: the row clears the moment a
	// line lands. The historical gap is still named in the message — severity
	// must NOT latch on a cumulative counter (the ca_health.go rule), or one
	// transient SIEM restart would leave the row amber until process restart.
	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Fatalf("row should clear on OBSERVED delivery, got %v: %s", row.Status, row.Message)
	}
	if !strings.Contains(row.Message, "lost earlier") {
		t.Fatalf("a recovered feed must still name the gap it left: %q", row.Message)
	}
}

// TestChaos66_TestEndpointCannotReportSuccessAgainstADeadCollector pins that
// the connectivity probe is able to FAIL.
//
// PRE-FIX EVIDENCE: POST /api/syslog/test answered
// `200 {"ok":true,"message":"test message sent"}` against udp://192.0.2.77:514
// (TEST-NET-1 — a collector that cannot exist), because since delivery became
// asynchronous Write only enqueues on a bounded channel. checkSyslogFeed's own
// operator action told the operator to use this endpoint to "confirm
// connectivity", so the documented way to verify the documented remedy could
// not fail.
func TestChaos66_TestEndpointCannotReportSuccessAgainstADeadCollector(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	fc.kill()

	rec := httptest.NewRecorder()
	apiSyslogTest(rec, syslogAdminReq(http.MethodPost, "/api/syslog/test"))
	if rec.Code == http.StatusOK {
		t.Fatalf("DEFECT: probe reported success against a dead collector: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("probe failure must answer JSON, got Content-Type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"ok":false`) {
		t.Fatalf("probe failure body must say ok=false: %s", rec.Body.String())
	}
}

// TestChaos66_UDPFeedNeverClaimsVerifiedDelivery pins that no surface reports
// delivery over a transport on which delivery cannot be observed.
//
// PRE-FIX EVIDENCE: a UDP writer aimed at 192.0.2.77:514 connected
// successfully and reported drops=0 forever, so checkSyslogFeed said
// "forwarding is active" and the test endpoint said "test message sent"
// against a collector that does not exist. udp:// is what an address with no
// scheme resolves to, i.e. the default posture.
func TestChaos66_UDPFeedNeverClaimsVerifiedDelivery(t *testing.T) {
	withSyslogTestEnv(t)
	const dead = "udp://192.0.2.77:514" // TEST-NET-1

	setSyslogIntent(dead)
	setSyslogConfiguredTarget(dead)
	if err := InitSyslogResilient(dead, "rfc5424"); err != nil {
		t.Fatalf("a UDP connect is local and must not fail: %v", err)
	}
	sw := activeSyslog()
	for i := 0; i < 50; i++ {
		sw.WriteAudit(map[string]string{"evt": "compliance"})
	}
	time.Sleep(200 * time.Millisecond)

	if sw.DeliveryVerifiable() {
		t.Fatal("UDP delivery must not be reported as verifiable")
	}
	row := checkSyslogFeed()
	if strings.Contains(row.Message, "delivering") {
		t.Fatalf("DEFECT: UDP row claims delivery it cannot observe: %q", row.Message)
	}
	if !strings.Contains(row.Message, "NOT verifiable") {
		t.Fatalf("UDP row must state that delivery is unverifiable: %q", row.Message)
	}

	rec := httptest.NewRecorder()
	apiSyslogTest(rec, syslogAdminReq(http.MethodPost, "/api/syslog/test"))
	if !strings.Contains(rec.Body.String(), `"verified":false`) {
		t.Fatalf("DEFECT: UDP probe must report verified=false: %s", rec.Body.String())
	}
}

// TestChaos66_DropsReachMetricsAndHealthz pins that lost compliance events are
// visible to an automated monitor, not just to an admin opening a panel.
//
// PRE-FIX EVIDENCE: Drops() reached exactly one surface in the process — the
// admin-only GET /api/syslog. No metric existed at all (a 2026-07-07 security
// review recommended culvert_syslog_dropped_total by name), no /healthz field,
// no contract row consulted it. A SIEM outage was invisible to every automated
// monitor the product ships.
func TestChaos66_DropsReachMetricsAndHealthz(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)
	setSyslogIntent(fc.addr())
	setSyslogConfiguredTarget(fc.addr())
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	// Wait for a line to actually LAND before killing the collector. A dial
	// completes at the TCP handshake, i.e. before the server calls Accept, so
	// killing straight after install can leave the connection alive in the
	// listen backlog — writes then succeed into the kernel buffer forever and
	// no drop is ever recorded. Establishing delivery first removes that race.
	if !driveUntil(t, 3*time.Second, func() bool { return fc.received() > 0 }) {
		t.Fatal("collector never received a line while healthy")
	}
	fc.kill()
	sw := activeSyslog()
	if !driveUntil(t, 10*time.Second, func() bool { return sw.Drops() > 0 }) {
		t.Fatalf("no drops recorded (drops=%d)", sw.Drops())
	}

	body := renderMetricsForTest(t)
	for _, want := range []string{
		"culvert_syslog_up 0",
		"culvert_syslog_dropped_total",
		"culvert_syslog_delivery_verifiable 1",
		"culvert_syslog_queue_dropped_total",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("DEFECT: /metrics is missing %q", want)
		}
	}
	// The counter is asserted as a LOWER BOUND, not an equality: the drain
	// goroutine is still running, so the exact value moves between the read
	// above and the scrape. Pinning equality would be a flaky gate, and a
	// gate that can flake gets muted.
	if got := scrapedCounter(t, body, "culvert_syslog_dropped_total"); got < 1 {
		t.Fatalf("dropped_total must carry the real loss (observed %d); scrape:\n%s", sw.Drops(), body)
	}
}

// TestChaos66_MetricsAbsentWhenNoCollectorConfigured is the emission rule every
// health plane in this tree follows: a flat `culvert_syslog_up 0` from an
// appliance that never had a SIEM is indistinguishable from one whose feed is
// dead, and the documented paging rule is `== 0`.
func TestChaos66_MetricsAbsentWhenNoCollectorConfigured(t *testing.T) {
	withSyslogTestEnv(t)
	setSyslogIntent("")
	setSyslogConfiguredTarget("")
	if body := renderMetricsForTest(t); strings.Contains(body, "culvert_syslog_") {
		t.Fatal("DEFECT: syslog series emitted on a node with no SIEM configured")
	}
}

// TestChaos66_GlobalWriterIsNotRacedByAReconfigure drives the request path and
// an admin reconfigure concurrently.
//
// PRE-FIX EVIDENCE: `go test -race` reported
//
//	Write at 0x... by goroutine N: Culvert.InitSyslog() syslog.go:65
//	Previous read at 0x... by goroutine M: <the request path>
//
// The plain package pointer was written by the admin goroutine and read on
// every proxied request (store.go recordRequest) and every audit event.
// Meaningful only under -race; harmless and fast otherwise.
func TestChaos66_GlobalWriterIsNotRacedByAReconfigure(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // the request path
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if sw := activeSyslog(); sw != nil {
				sw.WriteRequest(map[string]string{"host": "example.com"})
			}
		}
	}()
	for i := 0; i < 12; i++ { // the admin goroutine
		if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
			t.Fatalf("install %d: %v", i, err)
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// TestChaos66_RefusedTargetLeavesTheWorkingForwarderInPlace pins that a
// rejected reconfigure does not take the feed down with it.
//
// A reconfigure that is REJECTED must not take the feed down with it. The
// probe-then-install order is what makes this true; installing first and
// rolling back on failure would leave a window with no forwarder and, worse,
// would have replaced the previous target before knowing the new one works.
func TestChaos66_RefusedTargetLeavesTheWorkingForwarderInPlace(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)
	setSyslogIntent(fc.addr())
	setSyslogConfiguredTarget(fc.addr())
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	good := activeSyslog()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	rec := httptest.NewRecorder()
	apiSyslogConfig(rec, syslogAdminJSONReq(http.MethodPost, "/api/syslog", `{"addr":"tcp://`+deadAddr+`","format":"rfc3164"}`))

	if rec.Code == http.StatusOK {
		t.Skip("the released port was re-bound; the target was legitimately reachable")
	}
	if activeSyslog() != good {
		t.Fatal("DEFECT: a refused reconfigure replaced the working forwarder")
	}
	if got := syslogConfiguredTarget(); got != fc.addr() {
		t.Fatalf("DEFECT: a refused reconfigure moved the live target to %q", got)
	}
}

// ─── CONTROLS ───────────────────────────────────────────────────────────────

// TestChaos66Control_HealthyFeedStaysGreenAndDelivers is the control against
// over-reporting failure.
//
// The cheapest way to pass the defect gates above is to report failure more
// readily. This is the gate that makes that a losing move: a working collector
// must be reported as delivering, with no drops and no degradation, and the
// lines must actually arrive.
func TestChaos66Control_HealthyFeedStaysGreenAndDelivers(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)
	setSyslogIntent(fc.addr())
	setSyslogConfiguredTarget(fc.addr())
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !driveUntil(t, 3*time.Second, func() bool { return fc.received() >= 5 }) {
		t.Fatalf("healthy collector received only %d batches", fc.received())
	}
	sw := activeSyslog()
	if sw.Drops() != 0 {
		t.Fatalf("DEFECT: healthy feed recorded %d drops", sw.Drops())
	}
	row := checkSyslogFeed()
	if row.Status != diagOK || !strings.Contains(row.Message, "delivering") {
		t.Fatalf("healthy feed must report as delivering: %v %q", row.Status, row.Message)
	}
	if body := renderMetricsForTest(t); !strings.Contains(body, "culvert_syslog_up 1") ||
		!strings.Contains(body, "culvert_syslog_degraded 0") {
		t.Fatal("healthy feed must scrape up=1 degraded=0")
	}

	rec := httptest.NewRecorder()
	apiSyslogTest(rec, syslogAdminReq(http.MethodPost, "/api/syslog/test"))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"verified":true`) {
		t.Fatalf("probe against a healthy TCP collector must verify: %d %s", rec.Code, rec.Body.String())
	}
}

// TestChaos66Control_ForwardingIsNotSilentlyDisabled is the other losing move:
// every defect gate would also pass if the process simply stopped forwarding.
// Configuring a target must install a forwarder and lines must reach it.
func TestChaos66Control_ForwardingIsNotSilentlyDisabled(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)
	rec := httptest.NewRecorder()
	apiSyslogConfig(rec, syslogAdminJSONReq(http.MethodPost, "/api/syslog", `{"addr":"`+fc.addr()+`","format":"rfc5424"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("configuring a reachable collector must succeed: %d %s", rec.Code, rec.Body.String())
	}
	if activeSyslog() == nil {
		t.Fatal("DEFECT: a successful configure installed no forwarder")
	}
	if !driveUntil(t, 3*time.Second, func() bool { return fc.received() > 0 }) {
		t.Fatal("DEFECT: nothing reached the collector after a successful configure")
	}
}

// TestChaos66Control_DegradationIsADurationNotACount pins that a collector that blips
// must NOT page. The entry rate of a gateway is thousands of lines a minute,
// so any count threshold is crossed inside an ordinary SIEM restart.
func TestChaos66Control_DegradationIsADurationNotACount(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)
	var alerts int
	fireSyslogFeedAlert = func(string) { alerts++ }

	setSyslogIntent(fc.addr())
	setSyslogConfiguredTarget(fc.addr())
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !driveUntil(t, 3*time.Second, func() bool { return fc.received() > 0 }) {
		t.Fatal("collector never received a line while healthy")
	}
	fc.kill()
	sw := activeSyslog()
	if !driveUntil(t, 10*time.Second, func() bool { return sw.Drops() > 200 }) {
		t.Fatalf("expected a large drop count, got %d", sw.Drops())
	}
	if alerts != 0 {
		t.Fatalf("DEFECT: paged after %d drops, well inside the %s degradation window",
			sw.Drops(), syslogFeedDegradedAfter)
	}
	if row := checkSyslogFeed(); row.Status != diagWarn {
		t.Fatalf("a brief outage should WARN, not FAIL: %v %q", row.Status, row.Message)
	}
}

// TestChaos66_AlertDetailIsABoundedReasonClass: Store.Dispatch dedups on
// `event + ":" + Detail`, so a raw transport error — which embeds the
// collector address and the ephemeral local port — would mint one dedup key
// per failure and let a SIEM outage evict real threat alerts from the bounded
// retry queue (the WK-12/RS-5 defect).
func TestChaos66_AlertDetailIsABoundedReasonClass(t *testing.T) {
	allowed := map[string]bool{
		syslog.ReasonConnectFailed: true,
		syslog.ReasonWriteFailed:   true,
		syslog.ReasonPanic:         true,
	}
	for _, r := range []string{syslog.ReasonConnectFailed, syslog.ReasonWriteFailed, syslog.ReasonPanic} {
		if !allowed[r] {
			t.Fatalf("reason %q is not in the bounded set", r)
		}
		if strings.ContainsAny(r, " :/@.") {
			t.Fatalf("reason class %q looks like it carries an address or a raw error", r)
		}
	}
}

// TestChaos66_DisplacedWriterCannotWriteTheHealthRecord pins that only the
// ACTIVE forwarder may write the delivery-health record.
//
// A displaced writer is not finished when it is displaced: releaseSyslogWriter
// closes it asynchronously and Close keeps draining what is already queued, so
// its drain goroutine is still delivering to the OLD collector while the record
// already describes the new one. Letting it write meant a reconfigure away from
// a dead collector reported the dead one's trailing failures against its healthy
// replacement — attributing one target's state to another, which is the
// reporting error this sweep exists to remove. Introduced BY the CHAOS-66 fix
// and caught in self-review.
//
// The gate calls the observer DIRECTLY rather than racing two live writers.
// The first two attempts did the latter and both passed against the unguarded
// observer, for two different reasons worth recording: the active writer's own
// successful delivery called noteSyslogDeliveryRecovered and scrubbed the
// pollution before the assertion ran, and the fields the assertions read
// (row.Status, snap.Up) are derived from the ACTIVE writer rather than from the
// record being polluted. A gate whose subject repairs or masks the damage it is
// meant to detect proves nothing. Driving the seam directly makes the invariant
// deterministic — no sleeps, no ports, no scheduling.
func TestChaos66_DisplacedWriterCannotWriteTheHealthRecord(t *testing.T) {
	withSyslogTestEnv(t)
	fc := newFakeCollector(t)

	setSyslogIntent(fc.addr())
	setSyslogConfiguredTarget(fc.addr())
	if err := InitSyslogResilient(fc.addr(), "rfc3164"); err != nil {
		t.Fatalf("install: %v", err)
	}
	active := activeSyslog()
	if active == nil {
		t.Fatal("no forwarder installed")
	}
	resetSyslogFeedHealth()

	// A writer that is NOT the active one — exactly what a predecessor is
	// between its displacement and the end of its flush window.
	displaced, _ := syslog.NewWriterDeferred("tcp", "192.0.2.77:514", "rfc3164")
	t.Cleanup(func() { _ = displaced.Close() })
	if displaced == active {
		t.Fatal("test setup: the displaced writer must not be the active one")
	}

	for i := 0; i < 5; i++ {
		noteSyslogDeliveryState(displaced, false, syslog.ReasonConnectFailed, i == 0)
	}

	snap := syslogFeedState()
	if snap.Episodes != 0 || snap.LastReason != "" || snap.FailingFor != 0 {
		t.Fatalf("DEFECT: a displaced writer wrote the health record: episodes=%d lastReason=%q failingFor=%v",
			snap.Episodes, snap.LastReason, snap.FailingFor)
	}
	if syslogFeedDown.Load() {
		t.Fatal("DEFECT: a displaced writer moved the fast-path down gate")
	}
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Fatalf("DEFECT: the displaced writer's failures reached the contract row: %v %q", row.Status, row.Message)
	}

	// CONTROL: the ACTIVE writer must still be able to write the record, or
	// the guard above would have disabled the whole health plane.
	noteSyslogDeliveryState(active, false, syslog.ReasonWriteFailed, true)
	if snap := syslogFeedState(); snap.Episodes != 1 || snap.LastReason != syslog.ReasonWriteFailed {
		t.Fatalf("the ACTIVE writer must still record: episodes=%d lastReason=%q", snap.Episodes, snap.LastReason)
	}
}
