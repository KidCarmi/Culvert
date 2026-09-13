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
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// withSyslogFeedIsolation saves and restores every piece of process-global
// syslog state this file touches.
func withSyslogFeedIsolation(t *testing.T) {
	t.Helper()
	prevAddr, prevOK, prevSW := syslogConfiguredAddr, syslogConfigured, activeSyslog()
	prevThreshold := syslogFeedDegradedAfter
	prevAlert := fireSyslogFeedAlert
	t.Cleanup(func() {
		if cur := activeSyslog(); cur != nil && cur != prevSW {
			_ = cur.Close()
		}
		syslogConfiguredAddr, syslogConfigured = prevAddr, prevOK
		setActiveSyslog(prevSW)
		syslogFeedDegradedAfter = prevThreshold
		fireSyslogFeedAlert = prevAlert
		resetSyslogFeedHealth()
	})
	resetSyslogFeedHealth()
}

// deadTCPCollector starts a listener, wires syslog to it, then takes it away —
// a SIEM that was up when the appliance booted and is not up any more.
func deadTCPCollector(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	syslogFeedDegradedAfter = 20 * time.Millisecond
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
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
	syslogFeedDegradedAfter = 20 * time.Millisecond
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
	syslogFeedDegradedAfter = 20 * time.Millisecond
	fired := make(chan string, 64)
	fireSyslogFeedAlert = func(detail string) { fired <- detail }

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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	syslogFeedDegradedAfter = 20 * time.Millisecond
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
	syslogFeedDegradedAfter = 20 * time.Millisecond
	fired := make(chan string, 64)
	fireSyslogFeedAlert = func(detail string) { fired <- detail }

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
