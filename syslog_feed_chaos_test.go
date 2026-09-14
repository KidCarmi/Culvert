package main

// CHAOS-66 — the reporting half of the SIEM forwarding sweep.
//
// The defect gates here were verified FAILING against the pre-fix tree. Two of
// them are the sweep's headline, and both were measured against the real
// InitSyslog path rather than a mock:
//
//	UDP (the DEFAULT transport) to a collector that does not exist:
//	  drops=0, syslog_feed = ok, "remote syslog/SIEM forwarding is active"
//	TCP collector taken away after a successful boot dial:
//	  19 audit events dropped, syslog_feed = ok, same message
//
// The CONTROLS exist because the cheapest way to pass both is to make the row
// permanently red, which would page every appliance in the fleet forever.

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// withSyslogFeedIsolation saves and restores every piece of process-global
// syslog state this file touches.
func withSyslogFeedIsolation(t *testing.T) {
	t.Helper()
	prevAddr, prevOK, prevSW := syslogConfiguredAddr, syslogConfigured, activeSyslog()
	t.Cleanup(func() {
		if cur := activeSyslog(); cur != nil && cur != prevSW {
			_ = cur.Close()
		}
		syslogConfiguredAddr, syslogConfigured = prevAddr, prevOK
		setActiveSyslog(prevSW)
		// Restored through the atomics, not by assigning the package vars: a
		// writer retired by an earlier test in this binary may still be draining
		// and reading them (caught by `-race -shuffle=on -count=2`, which is the
		// Deep gate's determinism run).
		resetSyslogFeedHealth()
	})
	t.Cleanup(func() { setSyslogDegradedAfterForTest(syslogFeedDegradedAfter) })
	t.Cleanup(func() { setSyslogFeedAlertSinkForTest(defaultSyslogFeedAlert) })
	resetSyslogFeedHealth()
}

// deadTCPCollector starts a listener, wires syslog to it, then takes it away —
// a SIEM that was up when the appliance booted and is not up any more.
func deadTCPCollector(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := "tcp://" + ln.Addr().String()
	if err := InitSyslog(addr, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addr, addr
	_ = ln.Close()
	return addr
}

// driveFailures pushes lines until the feed reports a failing run, so the test
// does not depend on how many attempts the collector's death takes to surface.
func driveFailures(t *testing.T, n int) {
	t.Helper()
	sw := activeSyslog()
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; i < n || !syslogFeedState().Failing; i++ {
		sw.WriteAudit(map[string]string{"event": "auth.login.fail"})
		time.Sleep(2 * time.Millisecond)
		if time.Now().After(deadline) {
			t.Fatal("setup: delivery never started failing against a dead collector")
		}
	}
	for !syslogFeedState().Failing && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}

// ── defect gates ────────────────────────────────────────────────────────────

// DEFECT (headline): the syslog_feed row reported the BOOT DIAL and nothing
// else, so a collector that went away after boot left it green while every
// event was dropped. Measured pre-fix: 19 audit events lost, row ok.
func TestChaos66_TCPCollectorLostAfterBootIsReported(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)
	deadTCPCollector(t)
	driveFailures(t, 20)

	snap := syslogFeedState()
	if snap.Drops == 0 {
		t.Fatal("setup produced no drops")
	}
	row := checkSyslogFeed()
	if row.Status == diagOK {
		t.Errorf("syslog_feed = ok (%q) with %d events dropped; the row is blind to a collector that died after boot",
			row.Message, snap.Drops)
	}
	if !strings.Contains(row.Message, "failing") {
		t.Errorf("row message %q does not say the feed is failing", row.Message)
	}
	if st := syslogFeedStatus(); st == "ready" || st == "disabled" {
		t.Errorf("/healthz posture = %q while delivery is failing", st)
	}
}

// DEFECT (headline): UDP is the DEFAULT transport and a UDP dial exchanges no
// packets, so InitSyslog cannot fail for any resolvable target. The row
// therefore reported a collector that has never existed as active — measured
// pre-fix: drops=0, status ok, forever.
func TestChaos66_UDPFeedThatHasNeverDeliveredIsNotReportedActive(t *testing.T) {
	withSyslogFeedIsolation(t)
	// TEST-NET-2: resolvable, routable nowhere, nothing listening.
	addr := "udp://198.51.100.9:514"
	if err := InitSyslog(addr, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog to a nonexistent UDP collector failed: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addr, addr

	row := checkSyslogFeed()
	if row.Status == diagOK && strings.Contains(row.Message, "active") {
		t.Errorf("syslog_feed = ok/%q for a UDP collector that has never received anything", row.Message)
	}
	if !strings.Contains(row.Message, "UDP") {
		t.Errorf("row message %q does not name the transport whose delivery cannot be verified", row.Message)
	}
	if row.OperatorAction == "" {
		t.Error("the row gives the operator no way to resolve the ambiguity")
	}
}

// Even once a UDP feed IS delivering, the row must not claim verified delivery:
// the socket accepting a datagram is not evidence the collector received it.
// Overstating that is what made the pre-fix row unreliable.
func TestChaos66_UDPDeliveryIsReportedAsUnverifiable(t *testing.T) {
	withSyslogFeedIsolation(t)
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	addr := "udp://" + pc.LocalAddr().String()
	if err := InitSyslog(addr, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addr, addr

	activeSyslog().WriteAudit(map[string]string{"event": "settings.change"})
	waitForSyslogFeed(t, func() bool { return syslogFeedState().EverDelivered })

	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Errorf("a delivering UDP feed should be ok, got %v (%q)", row.Status, row.Message)
	}
	if !strings.Contains(row.Message, "not verifiable") {
		t.Errorf("row message %q claims delivery UDP cannot prove", row.Message)
	}
}

// DEFECT: drops reached exactly one admin-role JSON blob. /metrics carried no
// syslog series at all, so no monitoring system could see a dead SIEM feed.
func TestChaos66_MetricsExposeTheFeed(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)
	deadTCPCollector(t)
	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })

	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_syslog_up 0",
		"culvert_syslog_drops_total",
		"culvert_syslog_degraded 1",
		"culvert_syslog_delivered_total",
		"culvert_syslog_queue_full_total",
		"culvert_syslog_backoff_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing %q; a dead SIEM feed is invisible to monitoring", want)
		}
	}
}

// A feed that has never delivered must NOT export an age of zero — that reads
// as "delivered just now", the exact inversion this sweep exists to remove. The
// state is carried by `up 0` instead.
func TestChaos66_MetricsOmitLastSuccessAgeUntilFirstDelivery(t *testing.T) {
	withSyslogFeedIsolation(t)
	addr := "udp://198.51.100.9:514" // TEST-NET-2: accepts writes, receives nothing
	if err := InitSyslog(addr, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addr, addr

	body := renderMetrics(t)
	if strings.Contains(body, "culvert_syslog_last_success_age_seconds") {
		t.Error("last_success_age_seconds exported for a feed that has never delivered; a 0 there reads as a healthy feed")
	}
	if !strings.Contains(body, "culvert_syslog_up 0") {
		t.Error("a feed that has never delivered anything does not export culvert_syslog_up 0")
	}
}

// The emission rule: a node that forwards nowhere must export NO syslog series.
// A flat `culvert_syslog_up 0` from every appliance is indistinguishable from a
// dead collector, and the documented paging rule is `== 0`.
func TestChaos66_MetricsAbsentWhenNoFeedConfigured(t *testing.T) {
	withSyslogFeedIsolation(t)
	syslogConfiguredAddr, syslogConfigured = "", ""
	setActiveSyslog(nil)

	if body := renderMetrics(t); strings.Contains(body, "culvert_syslog_") {
		t.Error("syslog series exported on a node with no SIEM feed configured; `up == 0` would page on every appliance")
	}
}

// The alert must fire ONCE per degradation episode, not once per dropped line —
// a gateway drops one per proxied request.
func TestChaos66_AlertFiresOncePerEpisode(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)
	fired := make(chan string, 64)
	setSyslogFeedAlertSinkForTest(func(detail string) { fired <- detail })

	deadTCPCollector(t)
	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })
	for i := 0; i < 40; i++ { // keep failing well past the threshold
		activeSyslog().WriteAudit(map[string]string{"event": "policy.rule.update"})
		time.Sleep(2 * time.Millisecond)
	}

	if len(fired) == 0 {
		t.Fatal("no alert fired for a feed dark past the degradation threshold")
	}
	if n := len(fired); n > 1 {
		t.Errorf("%d alerts fired for one episode; the latch is not holding", n)
	}
	detail := <-fired
	if strings.Contains(detail, "127.0.0.1") {
		t.Errorf("alert detail %q carries the collector address; the dedup key must stay bounded", detail)
	}
}

// ── controls ────────────────────────────────────────────────────────────────

// CONTROL: the cheapest way to pass every gate above is a permanently red row.
// A healthy delivering feed must report ok — and must say how much it has
// delivered, which is the evidence the pre-fix row never had.
func TestChaos66_Control_HealthyTCPFeedReportsOK(t *testing.T) {
	withSyslogFeedIsolation(t)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()

	addr := "tcp://" + ln.Addr().String()
	if err := InitSyslog(addr, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addr, addr

	for i := 0; i < 5; i++ {
		activeSyslog().WriteAudit(map[string]string{"event": "settings.change"})
	}
	waitForSyslogFeed(t, func() bool { return syslogFeedState().EverDelivered })

	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Errorf("healthy TCP feed reports %v (%q)", row.Status, row.Message)
	}
	if !strings.Contains(row.Message, "delivered") {
		t.Errorf("row message %q does not report the delivery evidence", row.Message)
	}
	if st := syslogFeedStatus(); st != "ready" {
		t.Errorf("/healthz posture = %q for a healthy feed", st)
	}
	if body := renderMetrics(t); !strings.Contains(body, "culvert_syslog_up 1") {
		t.Error("a healthy feed does not export culvert_syslog_up 1")
	}
}

// CONTROL: a node that never configured a SIEM feed must stay ok and silent.
// A permanent row on every appliance is noise, and noise gets muted.
func TestChaos66_Control_UnconfiguredFeedIsOKAndQuiet(t *testing.T) {
	withSyslogFeedIsolation(t)
	syslogConfiguredAddr, syslogConfigured = "", ""
	setActiveSyslog(nil)

	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Errorf("unconfigured feed reports %v (%q)", row.Status, row.Message)
	}
	if st := syslogFeedStatus(); st != "disabled" {
		t.Errorf("/healthz posture = %q with no feed configured", st)
	}
	resp := map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["syslogFeed"]; ok {
		t.Error("/healthz carries a syslogFeed field on a node that forwards nowhere")
	}
}

// CONTROL: recovery is declared on OBSERVED delivery only. This feed's traffic
// is generated by proxied requests, so a feed that "stopped failing" on an idle
// node is indistinguishable from a working one — elapsed time must clear
// nothing.
func TestChaos66_Control_RecoveryNeedsObservedDelivery(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)
	deadTCPCollector(t)
	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })

	time.Sleep(100 * time.Millisecond) // idle: nothing is logged, nothing recovers
	if !syslogFeedState().Degraded {
		t.Error("the feed reported itself recovered after merely going quiet")
	}
	if checkSyslogFeed().Status == diagOK {
		t.Error("syslog_feed went green on elapsed time with no delivery evidence")
	}
}

// Reconfiguring onto a new collector must clear the previous target's latches,
// or a feed that was degraded before the change would never page again.
func TestChaos66_ReconfigureClearsTheAlertLatch(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)
	fired := make(chan string, 64)
	setSyslogFeedAlertSinkForTest(func(detail string) { fired <- detail })

	deadTCPCollector(t)
	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })
	for i := 0; i < 20; i++ {
		activeSyslog().WriteAudit(map[string]string{"event": "x"})
		time.Sleep(2 * time.Millisecond)
	}
	if len(fired) == 0 {
		t.Fatal("setup: first episode did not alert")
	}
	drain := len(fired)
	for i := 0; i < drain; i++ {
		<-fired
	}
	_ = activeSyslog().Close()

	deadTCPCollector(t) // a different dead collector, freshly configured
	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })
	for i := 0; i < 20; i++ {
		activeSyslog().WriteAudit(map[string]string{"event": "y"})
		time.Sleep(2 * time.Millisecond)
	}
	if len(fired) == 0 {
		t.Error("the second collector's outage never paged; the latch survived a reconfigure")
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// renderMetrics is shared with storage_health_test.go.

func waitForSyslogFeed(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached within the timeout")
}

// A collector that comes BACK must clear the episode: the latch resets, a
// recovery line is emitted, and a LATER outage pages again. Without this the
// first SIEM outage of a process's life would be the only one it ever reported.
//
// Recovery is driven by an OBSERVED delivery, which is the only thing that
// clears it — see TestChaos66_Control_RecoveryNeedsObservedDelivery for the
// other half.
func TestChaos66_RecoveryClearsTheEpisodeAndASecondOutagePagesAgain(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)
	fired := make(chan string, 64)
	setSyslogFeedAlertSinkForTest(func(detail string) { fired <- detail })

	// Stand a collector up so InitSyslog succeeds and a writer exists, then take
	// it away — the shape the sweep is about. The address is kept so the
	// collector can come back on it.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()
	if err := InitSyslog("tcp://"+addr, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = "tcp://"+addr, "tcp://"+addr
	_ = ln.Close()

	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })
	for i := 0; i < 20; i++ {
		activeSyslog().WriteAudit(map[string]string{"event": "a"})
		time.Sleep(2 * time.Millisecond)
	}
	if len(fired) == 0 {
		t.Fatal("setup: the first outage never paged")
	}
	for len(fired) > 0 {
		<-fired
	}

	// The collector comes back on the same address.
	back, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		t.Skipf("could not rebind %s to stage the recovery: %v", addr, err)
	}
	defer back.Close()
	var connMu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := back.Accept()
			if err != nil {
				return
			}
			connMu.Lock()
			conns = append(conns, c)
			connMu.Unlock()
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()

	// Wait for a NEW delivery, not for EverDelivered: that flag is sticky, and a
	// line can legitimately have landed before the collector went away, so it is
	// true throughout the outage. The recovery signal is the failing run
	// clearing, which only an accepted write can do.
	before := syslogFeedState().Delivered
	waitForSyslogFeed(t, func() bool {
		activeSyslog().WriteAudit(map[string]string{"event": "b"})
		snap := syslogFeedState()
		return snap.Delivered > before && !snap.Failing
	})
	if snap := syslogFeedState(); snap.Degraded || snap.Failing {
		t.Errorf("feed still reports degraded/failing after an observed delivery: %+v", snap)
	}
	if checkSyslogFeed().Status != diagOK {
		t.Errorf("syslog_feed did not go green after recovery: %q", checkSyslogFeed().Message)
	}

	// Second outage: the latch must have cleared, so this pages again. Closing
	// the LISTENER is not enough — it stops new accepts but leaves the writer's
	// established connection draining, so the accepted conns must go too.
	_ = back.Close()
	connMu.Lock()
	for _, c := range conns {
		_ = c.Close()
	}
	connMu.Unlock()
	driveFailures(t, 20)
	waitForSyslogFeed(t, func() bool { return syslogFeedState().Degraded })
	for i := 0; i < 20; i++ {
		activeSyslog().WriteAudit(map[string]string{"event": "c"})
		time.Sleep(2 * time.Millisecond)
	}
	if len(fired) == 0 {
		t.Error("the second outage never paged; the alert latch survived recovery, so a process only ever reports its first SIEM outage")
	}
}

// CODEX P1 REPRODUCTION (round 1): the alert is evaluated ONLY inside the
// delivery observer, which is only called when a line is submitted. A collector
// that dies and is followed by an IDLE node therefore leaves the last failure
// event carrying FailingFor≈0, so nothing ever re-evaluates the threshold —
// while syslogFeedState(), which derives degradation from the wall clock,
// starts reporting the feed degraded at the threshold anyway.
//
// The contract row and the culvert_syslog_degraded gauge say degraded; the page
// never fires. That is precisely the disagreement this file's own design note
// claims is impossible, and it is the mirror image of the rule the sweep got
// right on the other side: recovery must not be declared by silence, and
// neither may degradation be suppressed by it.
func TestChaos66_IdleNodePastTheThresholdStillPages(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(150 * time.Millisecond)
	fired := make(chan string, 8)
	setSyslogFeedAlertSinkForTest(func(detail string) { fired <- detail })

	deadTCPCollector(t)

	// Get the feed into a failing run, then let the node go quiet — no more
	// proxied requests, so no more syslog lines, so no more observer callbacks.
	driveFailures(t, 1)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(fired) > 0 {
			return // paged without further traffic: correct
		}
		time.Sleep(10 * time.Millisecond)
	}
	snap := syslogFeedState()
	t.Errorf("no alert after %s of an idle degraded feed (degraded=%v, failingFor=%s); the contract row and the gauge report degraded while the page never fires",
		time.Since(deadline.Add(-3*time.Second)).Round(time.Millisecond), snap.Degraded, snap.FailingFor.Round(time.Millisecond))
}

// CODEX P2 REPRODUCTION (round 1): a reconfigure publishes the new writer
// without retiring the old one. The old drain goroutine keeps running with its
// delivery observer still attached, so its callbacks land in the health record
// AFTER armSyslogFeedHealth has reset it for the NEW collector — attributing
// the old collector's failures to the new one and, worse, able to set the new
// episode's alert latch so a real outage on the new feed never pages (healthy
// deliveries do not invoke the observer, so nothing clears it).
//
// It is also a plain resource leak that predates this sweep: nothing closed the
// previous writer on the reconfigure path, so every re-save left a drain
// goroutine and a socket behind.
func TestChaos66_ReconfigureRetiresThePreviousWriter(t *testing.T) {
	withSyslogFeedIsolation(t)
	setSyslogDegradedAfterForTest(20 * time.Millisecond)

	// Feed one: a collector that is going away, with a deep backlog queued so
	// its drain goroutine still has work when the reconfigure happens.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addrOne := "tcp://" + ln.Addr().String()
	if err := InitSyslog(addrOne, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addrOne, addrOne
	_ = ln.Close()
	old := activeSyslog()
	for i := 0; i < 500; i++ {
		old.WriteAudit(map[string]string{"event": "backlog"})
	}

	// Feed two: a healthy collector the operator moves to.
	good, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer good.Close()
	go func() {
		for {
			c, err := good.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	addrTwo := "tcp://" + good.Addr().String()
	if err := InitSyslog(addrTwo, "rfc5424"); err != nil {
		t.Fatalf("InitSyslog (second): %v", err)
	}
	syslogConfigured, syslogConfiguredAddr = addrTwo, addrTwo

	if activeSyslog() == old {
		t.Fatal("setup: the writer was not replaced")
	}

	// Drive the RETIRED writer directly. Racing its backlog against the
	// reconfigure is not reproducible — a few hundred fast-drops complete in
	// microseconds — so the property is pinned structurally instead: whatever
	// the old writer does after being retired must not reach the health record,
	// which is now reporting on a different collector.
	for i := 0; i < 200; i++ {
		old.WriteAudit(map[string]string{"event": "from-the-retired-writer"})
	}
	time.Sleep(200 * time.Millisecond)

	syslogFeed.mu.Lock()
	latched := syslogFeed.alerted
	gated := !syslogFeed.logAt.IsZero()
	syslogFeed.mu.Unlock()
	if latched || gated {
		t.Errorf("the retired writer's delivery events reached the NEW feed's health record (alerted=%v, logGateArmed=%v); a real outage on the new collector could then never page, because healthy deliveries never invoke the observer that would clear it",
			latched, gated)
	}

	// And it must actually be retired, not merely ignored: nothing closed the
	// previous writer on this path before CHAOS-66, so every re-save left a
	// drain goroutine and a socket behind.
	//
	// Note what is NOT asserted. A retired writer flushing the backlog it
	// already holds is CORRECT — those lines were destined for the old
	// collector, and discarding them would lose audit data on every re-save.
	// What must stop is accepting NEW work, which is what being closed means.
	closed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		d0 := old.Stats().Delivered
		old.WriteAudit(map[string]string{"event": "after-retirement"})
		time.Sleep(20 * time.Millisecond)
		if old.Stats().Delivered == d0 {
			closed = true
			break
		}
	}
	if !closed {
		t.Errorf("the retired writer is still accepting and delivering new lines; it was never closed, so every re-save leaks a drain goroutine and a socket")
	}

	// The new feed is healthy and says so.
	waitForSyslogFeed(t, func() bool {
		activeSyslog().WriteAudit(map[string]string{"event": "new-feed"})
		return syslogFeedState().EverDelivered
	})
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Errorf("the new, healthy feed does not report ok: %v %q", row.Status, row.Message)
	}
}

// The threshold re-evaluation must RE-ARM when it fires without the threshold
// having actually elapsed, instead of spending its one shot.
//
// This is reachable under clock rollback and is not theoretical: FirstFail is
// reconstructed from stored nanoseconds, so it carries no monotonic reading and
// `time.Since` on it reads the WALL clock. An NTP step backwards between arming
// the timer and its firing lands exactly here — and on an idle node, where the
// timer is the only thing that would ever look again, giving up would silently
// cost the operator the page that the whole Codex-P1 fix exists to deliver.
func TestChaos66_ThresholdTimerReArmsWhenItFiresEarly(t *testing.T) {
	withSyslogFeedIsolation(t)
	// A threshold far longer than the test: any fire is necessarily "early".
	setSyslogDegradedAfterForTest(1 * time.Hour)
	fired := make(chan string, 8)
	setSyslogFeedAlertSinkForTest(func(detail string) { fired <- detail })

	deadTCPCollector(t)
	driveFailures(t, 1)

	syslogFeed.mu.Lock()
	armed := syslogFeed.degradeTimer != nil
	syslogFeed.mu.Unlock()
	if !armed {
		t.Fatal("setup: no threshold timer was armed for a failing, not-yet-degraded feed")
	}

	// Fire it by hand, standing in for the early wake a clock step produces.
	evaluateSyslogFeedDegradation()

	syslogFeed.mu.Lock()
	stillArmed := syslogFeed.degradeTimer != nil
	syslogFeed.mu.Unlock()
	if !stillArmed {
		t.Error("the timer fired early and was not re-armed; on an idle node nothing would ever re-evaluate, so a clock correction silently costs the page")
	}
	if len(fired) != 0 {
		t.Errorf("alerted before the threshold elapsed: %q", <-fired)
	}

	// And it must still stop on recovery rather than re-arming forever.
	resetSyslogFeedHealth()
	syslogFeed.mu.Lock()
	leftover := syslogFeed.degradeTimer != nil
	syslogFeed.mu.Unlock()
	if leftover {
		t.Error("a re-armed timer outlived the health record reset")
	}
}
