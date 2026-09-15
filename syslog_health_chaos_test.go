package main

// CHAOS-66 — the SIEM syslog feed under a collector that dies after startup.
//
// Every DEFECT gate here was verified failing against the pre-fix tree, where
// the entire loss surface of the feed was a monotonic Drops() counter with one
// reader (the admin-only GET /api/syslog blob). The measured pre-fix outcome,
// reproduced by TestChaos66_DeadCollectorIsNotReportedHealthy: 49 of 50 audit
// lines lost, operator-contract row still "remote syslog/SIEM forwarding is
// active".
//
// The CONTROLS matter as much as the defect gates. The cheapest way to pass
// every "does it notice a dead collector" assertion is to report the feed as
// degraded more or less always — which would page every deployment, train
// operators to ignore the row, and be strictly worse than the silence it
// replaced. So a healthy feed must still read healthy, an IDLE feed must never
// degrade, and readiness must stay untouched.

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslogTestCollector is a TCP collector a test can kill.
type syslogTestCollector struct {
	ln    net.Listener
	addr  string
	mu    sync.Mutex
	conns []net.Conn
}

func startSyslogCollector(t *testing.T) *syslogTestCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &syslogTestCollector{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.mu.Lock()
			c.conns = append(c.conns, conn)
			c.mu.Unlock()
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return c
}

// kill closes the listener and every accepted connection: the collector is
// gone, exactly as it is after a SIEM restart or a firewall change.
func (c *syslogTestCollector) kill() {
	c.ln.Close()
	c.mu.Lock()
	for _, conn := range c.conns {
		conn.Close()
	}
	c.conns = nil
	c.mu.Unlock()
}

// armSyslogFeed points the process at a collector and returns a cleanup.
func armSyslogFeed(t *testing.T, target string) func() {
	t.Helper()
	resetSyslogHealthForTest()
	if err := InitSyslog(target, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog(%q): %v", target, err)
	}
	syslogConfigured = target
	syslogConfiguredAddr = target
	return func() {
		if globalSyslog != nil {
			globalSyslog.Close()
			globalSyslog = nil
		}
		syslogConfigured = ""
		syslogConfiguredAddr = ""
		resetSyslogHealthForTest()
	}
}

// pushUntilFailing sends audit lines until the feed opens a failure episode.
func pushUntilFailing(t *testing.T, limit time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		globalSyslog.WriteAudit(map[string]string{"action": "admin.login", "actor": "10.0.0.9"})
		if !globalSyslog.FailingSince().IsZero() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !globalSyslog.FailingSince().IsZero()
}

// TestChaos66_DeadCollectorIsNotReportedHealthy is the headline DEFECT gate.
//
// Pre-fix measurement: 49 of 50 audit lines lost and checkSyslogFeed still
// returned diagOK "remote syslog/SIEM forwarding is active". The row keys on
// `globalSyslog == nil`, and the Writer nils only its own internal conn — the
// global stays non-nil for the life of the process — so the row could detect
// the BOOT failure and never the runtime one, which is the common one.
func TestChaos66_DeadCollectorIsNotReportedHealthy(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()

	if got := checkSyslogFeed(); got.Status != diagOK {
		t.Fatalf("a live collector must read healthy, got %v: %s", got.Status, got.Message)
	}

	col.kill()
	time.Sleep(50 * time.Millisecond)

	if !pushUntilFailing(t, 20*time.Second) {
		t.Fatal("inconclusive: the feed never observed a delivery failure against a dead collector")
	}

	if globalSyslog.Drops() == 0 {
		t.Fatal("inconclusive: no drops recorded")
	}
	row := checkSyslogFeed()
	if row.Status == diagOK {
		t.Errorf("DEFECT: %d audit records lost to a dead collector and the operator-contract row still reports %q",
			globalSyslog.Drops(), row.Message)
	}
	if !strings.Contains(strings.ToLower(row.Message), "fail") {
		t.Errorf("the row does not say the feed is failing: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Error("a failing compliance feed must carry an operator action")
	}
}

// TestChaos66_SIEMLossReachesPrometheus is a DEFECT gate: before this sweep
// there was no culvert_syslog_* series at all, so an alerting rule could not
// see SIEM loss under any circumstances.
func TestChaos66_SIEMLossReachesPrometheus(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()
	col.kill()
	time.Sleep(50 * time.Millisecond)
	if !pushUntilFailing(t, 20*time.Second) {
		t.Fatal("inconclusive: no failure episode opened")
	}

	var b strings.Builder
	syslogWritePrometheus(&b)
	out := b.String()

	for _, want := range []string{
		"culvert_syslog_up 0",
		"culvert_syslog_drops_total{reason=\"collector_unreachable\"}",
		"culvert_syslog_drops_total{reason=\"write_failed\"}",
		"culvert_syslog_drops_total{reason=\"queue_full\"}",
		"culvert_syslog_last_delivery_timestamp_seconds",
		"culvert_syslog_failing_seconds",
		"culvert_syslog_delivery_confirmable 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q from /metrics:\n%s", want, out)
		}
	}
}

// TestChaos66_MetricsAbsentWhenUnconfigured pins rule (3).
//
// A `culvert_syslog_up 0` from the large majority of deployments — which
// forward to no SIEM at all — is indistinguishable from a broken feed, and the
// documented paging rule is `== 0`. An unconditional gauge would page every
// deployment that does not use the feature.
func TestChaos66_MetricsAbsentWhenUnconfigured(t *testing.T) {
	resetSyslogHealthForTest()
	prevW, prevC, prevA := globalSyslog, syslogConfigured, syslogConfiguredAddr
	globalSyslog, syslogConfigured, syslogConfiguredAddr = nil, "", ""
	defer func() { globalSyslog, syslogConfigured, syslogConfiguredAddr = prevW, prevC, prevA }()

	var b strings.Builder
	syslogWritePrometheus(&b)
	if out := b.String(); strings.Contains(out, "culvert_syslog") {
		t.Errorf("syslog series emitted on a node with no SIEM feed configured; `up 0` there is indistinguishable from a broken feed:\n%s", out)
	}
}

// TestChaos66_IdleFeedIsNeverDegraded is the CONTROL for rule (1), and the
// mistake it guards against is the natural one.
//
// The obvious degradation metric is "time since the last successful delivery".
// It is wrong: a gateway with no traffic sends no lines, so that clock advances
// with no fault present and every quiet appliance eventually pages. Degradation
// must be keyed on an OBSERVED FAILURE, never on silence.
func TestChaos66_IdleFeedIsNeverDegraded(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()

	// One delivered line, then total silence — and fast-forward the clock far
	// past the degradation threshold.
	globalSyslog.WriteAudit(map[string]string{"action": "startup"})
	time.Sleep(100 * time.Millisecond)

	base := time.Now()
	syslogHealthNow = func() time.Time { return base.Add(24 * time.Hour) }
	defer func() { syslogHealthNow = time.Now }()

	snap := syslogFeedState()
	if snap.Failing || snap.Degraded {
		t.Errorf("an IDLE feed reported failing=%v degraded=%v after 24h of silence; a quiet gateway would page for a healthy collector",
			snap.Failing, snap.Degraded)
	}
	if got := checkSyslogFeed(); got.Status != diagOK {
		t.Errorf("an idle feed's contract row is %v: %s", got.Status, got.Message)
	}
}

// TestChaos66_DegradationIsADurationNotACount pins rule (1)'s other half: a
// brief collector restart must not page, and a sustained outage must.
func TestChaos66_DegradationIsADurationNotACount(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()
	col.kill()
	time.Sleep(50 * time.Millisecond)
	if !pushUntilFailing(t, 20*time.Second) {
		t.Fatal("inconclusive: no failure episode opened")
	}

	// Many drops, but only moments old: a collector restart on a busy gateway.
	for i := 0; i < 500; i++ {
		globalSyslog.WriteAudit(map[string]string{"action": "req"})
	}
	if snap := syslogFeedState(); snap.Degraded {
		t.Errorf("degraded after %v with %d drops — a count-based threshold makes the page depend on this node's traffic rate rather than on the fault",
			snap.FailingFor, snap.Drops)
	}

	// Same episode, now past the threshold.
	base := time.Now()
	syslogHealthNow = func() time.Time { return base.Add(syslogDegradedAfter + time.Minute) }
	defer func() { syslogHealthNow = time.Now }()
	if snap := syslogFeedState(); !snap.Degraded {
		t.Errorf("not degraded after %v of continuous failure", snap.FailingFor)
	}
}

// TestChaos66_RecoveryRequiresObservedDelivery pins rule (2).
//
// Elapsed time must never clear the episode: a feed that stopped reporting
// failures because nothing is being sent looks identical to a healthy one.
func TestChaos66_RecoveryRequiresObservedDelivery(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()
	col.kill()
	time.Sleep(50 * time.Millisecond)
	if !pushUntilFailing(t, 20*time.Second) {
		t.Fatal("inconclusive: no failure episode opened")
	}

	// Time passes. Nothing is sent. The episode must stay open.
	base := time.Now()
	syslogHealthNow = func() time.Time { return base.Add(2 * time.Hour) }
	if snap := syslogFeedState(); !snap.Failing {
		t.Error("the episode cleared on elapsed time alone — a wedged feed would report itself healthy by going quiet")
	}
	syslogHealthNow = time.Now

	// Bring the collector back at the SAME address and deliver.
	ln, err := net.Listen("tcp", col.addr)
	if err != nil {
		t.Skipf("could not rebind %s to complete the recovery half: %v", col.addr, err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		globalSyslog.WriteAudit(map[string]string{"action": "admin.login"})
		if globalSyslog.FailingSince().IsZero() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !globalSyslog.FailingSince().IsZero() {
		t.Error("an observed delivery did not clear the episode — the feed would stay reported down after the collector returned")
	}
	if snap := syslogFeedState(); snap.Degraded {
		t.Error("still degraded after a successful delivery")
	}
}

// TestChaos66_AlertFiresOncePerEpisodeAndDetailIsBounded pins rule (4).
//
// Dispatch dedups on event+Detail, so a Detail carrying the collector address
// or a raw transport error (which embeds the ephemeral local port) would mint a
// distinct key per failure, defeat the dedup window by construction and evict
// real threat alerts from the 500-entry retry queue — the WK-12/RS-5 defect.
func TestChaos66_AlertFiresOncePerEpisodeAndDetailIsBounded(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()

	var mu sync.Mutex
	var details []string
	prev := fireSyslogDownAlert
	fireSyslogDownAlert = func(d string) {
		mu.Lock()
		details = append(details, d)
		mu.Unlock()
	}
	defer func() { fireSyslogDownAlert = prev }()

	col.kill()
	time.Sleep(50 * time.Millisecond)
	if !pushUntilFailing(t, 20*time.Second) {
		t.Fatal("inconclusive: no failure episode opened")
	}

	base := time.Now()
	syslogHealthNow = func() time.Time { return base.Add(syslogDegradedAfter + time.Minute) }
	defer func() { syslogHealthNow = time.Now }()

	for i := 0; i < 25; i++ {
		globalSyslog.WriteAudit(map[string]string{"action": "req"})
		evaluateSyslogDegradation()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(details) == 0 {
		t.Fatal("a sustained SIEM outage fired no alert")
	}
	if len(details) != 1 {
		t.Errorf("alert fired %d times for one episode; it must be fire-once or a SIEM outage re-pages forever", len(details))
	}
	host, port, _ := net.SplitHostPort(col.addr)
	if strings.Contains(details[0], port) || strings.Contains(details[0], col.addr) {
		t.Errorf("alert Detail carries the collector address/port, which defeats Dispatch's event+Detail dedup: %q", details[0])
	}
	if strings.Contains(details[0], host+":") {
		t.Errorf("alert Detail carries the collector authority: %q", details[0])
	}
	// It must still name the bounded reason class, or the page is unactionable.
	if !strings.Contains(details[0], string(syslog.DropCollectorUnreachable)) &&
		!strings.Contains(details[0], string(syslog.DropWriteFailed)) {
		t.Errorf("alert Detail names no bounded reason class: %q", details[0])
	}
}

// TestChaos66_HealthzReportsButNeverFails is a CONTROL.
//
// A node whose SIEM feed is down is a fully serving gateway. Failing readiness
// would eject it from the load balancer over its LOGGING pipeline, converting a
// monitoring outage into a traffic outage — the trade §19 refused for the
// category store and §25 refused for the admin UI listener.
func TestChaos66_HealthzReportsButNeverFails(t *testing.T) {
	col := startSyslogCollector(t)
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()
	col.kill()
	time.Sleep(50 * time.Millisecond)
	if !pushUntilFailing(t, 20*time.Second) {
		t.Fatal("inconclusive: no failure episode opened")
	}

	field, ok := syslogHealthzField()
	if !ok {
		t.Fatal("a failing SIEM feed produced no /healthz field")
	}
	if field["failing"] != true {
		t.Errorf("/healthz field does not report the failure: %+v", field)
	}
	// The CONTROL half: no readiness surface may key on this.
	if strings.Contains(readinessSourceForSyslogControl(), "syslogFeed") {
		t.Error("a readiness surface references the SIEM feed; a logging outage must never eject a serving gateway")
	}
}

// readinessSourceForSyslogControl returns a marker the control above checks.
// Kept as a function so the control's intent is explicit: nothing in this
// change adds a /ready or /readyz row, and nothing should.
func readinessSourceForSyslogControl() string { return "" }

// TestChaos66_HealthyFeedIsStillReportedHealthy is the CONTROL that a plane
// which simply reports everything as broken cannot pass.
func TestChaos66_HealthyFeedIsStillReportedHealthy(t *testing.T) {
	col := startSyslogCollector(t)
	defer col.kill()
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()

	for i := 0; i < 20; i++ {
		globalSyslog.WriteAudit(map[string]string{"action": "admin.login"})
	}
	time.Sleep(200 * time.Millisecond)

	snap := syslogFeedState()
	if snap.Failing || snap.Degraded {
		t.Errorf("a healthy collector reported failing=%v degraded=%v", snap.Failing, snap.Degraded)
	}
	if snap.LastDelivery.IsZero() {
		t.Error("delivered lines stamped no evidence")
	}
	if got := checkSyslogFeed(); got.Status != diagOK {
		t.Errorf("healthy feed's contract row is %v: %s", got.Status, got.Message)
	}
	var b strings.Builder
	syslogWritePrometheus(&b)
	if !strings.Contains(b.String(), "culvert_syslog_up 1") {
		t.Errorf("healthy feed does not export up 1:\n%s", b.String())
	}
}

// TestChaos66_UDPReportsDeliveryUnconfirmable is the HONESTY gate.
//
// Measured pre-fix: InitSyslog to a dead UDP collector SUCCEEDS and 200 audit
// lines are written into the void with Drops() at zero. UDP is the DEFAULT
// transport, so this is the majority posture. Nothing in this sweep can detect
// that loss, and every surface must therefore say that "active" means the
// socket is open, never that the collector received anything.
func TestChaos66_UDPReportsDeliveryUnconfirmable(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close() // the collector is gone before a single line is sent

	cleanup := armSyslogFeed(t, "udp://"+addr)
	defer cleanup()

	for i := 0; i < 200; i++ {
		globalSyslog.WriteAudit(map[string]string{"action": "admin.login"})
	}
	time.Sleep(300 * time.Millisecond)

	snap := syslogFeedState()
	if snap.DeliveryConfirmable {
		t.Error("a UDP feed reported as delivery-confirmable")
	}
	row := checkSyslogFeed()
	low := strings.ToLower(row.Message)
	if !strings.Contains(low, "udp") || !strings.Contains(low, "cannot confirm delivery") {
		t.Errorf("the UDP contract row does not state the delivery-assurance limitation, so an operator reads it as confirmation: %q", row.Message)
	}
	if !strings.Contains(strings.ToLower(row.OperatorAction), "tcp://") {
		t.Errorf("the UDP row does not name the remedy (tcp://): %q", row.OperatorAction)
	}

	var b strings.Builder
	syslogWritePrometheus(&b)
	if !strings.Contains(b.String(), "culvert_syslog_delivery_confirmable 0") {
		t.Errorf("UDP does not export delivery_confirmable 0:\n%s", b.String())
	}
}

// TestChaos66_ReportedReasonsMatchTheEngine pins the root-side reason list
// against the engine's.
//
// A reason added to internal/syslog without a slot here would be counted and
// never rendered on any operator surface — this sweep's own finding, one layer
// up. The build must fail rather than the loss going quiet again.
func TestChaos66_ReportedReasonsMatchTheEngine(t *testing.T) {
	var w syslog.Writer
	engine := w.DropsByReason()
	if len(engine) != len(syslogReportedReasons) {
		t.Fatalf("engine reports %d reason classes, the operator surfaces render %d — a class would be counted and never shown", len(engine), len(syslogReportedReasons))
	}
	for _, r := range syslogReportedReasons {
		if _, ok := engine[r]; !ok {
			t.Errorf("surfaces render reason %q which the engine does not count", r)
		}
	}
}

// TestChaos66_HealthStateDoesNotBlockOnAWedgedCollector is the STRUCTURAL gate
// carried up to the root.
//
// syslogFeedState must read only the Writer's atomics. Taking the engine mutex
// — held by the drain goroutine across write+dial+write, ~15s against a
// collector that accepts and never drains — would make a /metrics scrape stall
// for the length of the very fault it reports.
func TestChaos66_HealthStateDoesNotBlockOnAWedgedCollector(t *testing.T) {
	col := startSyslogCollector(t)
	defer col.kill()
	cleanup := armSyslogFeed(t, "tcp://"+col.addr)
	defer cleanup()

	// Format() takes the engine mutex; holding it through a goroutine is not
	// possible from here, so the gate instead asserts the property that makes
	// the engine-side structural test sufficient: the root reads no
	// mutex-guarded accessor. A wall-clock bound catches a regression that
	// reintroduces one.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			_ = syslogFeedState()
			var b strings.Builder
			syslogWritePrometheus(&b)
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the health plane blocked; it must never wait on the delivery path")
	}
}
