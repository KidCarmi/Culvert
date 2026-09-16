package main

// syslog_feed_chaos_test.go — CHAOS-66 gates: the SIEM forwarding feed under a
// collector that is unreachable, that accepts and then stops draining, and that
// is down at boot.
//
// Gate inventory (D = defect gate, verified FAILING against the pre-fix tree;
// C = control, which fails against a "fix" that is worse than the defect):
//
//	D1  ConnectedButNotDeliveringIsNotReportedActive
//	D2  DeliveryFailureDegradesTheFeedAfterTheThreshold
//	D3  ReconfigureClosesThePredecessor
//	D4  ActiveWriterIsPublishedAtomically              (-race)
//	D5  StartupConnectFailureArmsARecoveryCampaign
//	D6  DropsAreVisibleOnMetrics
//	D7  QueueOverflowIsCountedApartFromCollectorLoss
//	C1  HealthyFeedStillReportsActive                  (a plane that always said
//	                                                    "down" would pass D1/D2)
//	C2  DisabledFeedNeverDegradesOrAlerts              (a disabled feed must not
//	                                                    page)
//	C3  RecoveryRequiresAnObservedDelivery             (elapsed time must never
//	                                                    clear a degradation)
//	C4  CampaignNeverOverwritesANewerOperatorChoice    (the generation fence)
//	C5  MetricsAreSilentOnAnUnconfiguredNode           (the socks5/cluster_ca
//	                                                    emission rule)

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// deadCollector returns an address that accepted once and is then gone
// entirely: the ordinary "the SIEM went away after we booted" shape.
func deadCollector(t *testing.T) string {
	t.Helper()
	ln := mustListen(t)
	addr := ln.Addr().String()
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
		close(accepted)
	}()
	t.Cleanup(func() { ln.Close() })
	return addr
}

func mustListen(t *testing.T) netListener {
	t.Helper()
	ln, err := newTestTCPListener()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

// syslogTestReset isolates the process-global SIEM state for one test.
func syslogTestReset(t *testing.T) {
	t.Helper()
	prevAddr, prevOK, prevSW := syslogConfiguredAddr, syslogConfigured, activeSyslog()
	stopSyslogReconnect()
	publishSyslogWriter(nil)
	resetSyslogFeedHealthForTest()
	resetSyslogReconnectForTest()
	syslogConfiguredAddr, syslogConfigured = "", ""
	t.Cleanup(func() {
		stopSyslogReconnect()
		publishSyslogWriter(prevSW)
		resetSyslogFeedHealthForTest()
		resetSyslogReconnectForTest()
		syslogConfiguredAddr, syslogConfigured = prevAddr, prevOK
	})
}

// ── D1 ──────────────────────────────────────────────────────────────────────
//
// The headline defect. Reproduced against the pre-fix tree as:
//
//	drops=1  contract status=ok  message="remote syslog/SIEM forwarding is active"
//
// A collector that is gone leaves the writer non-nil and the configured target
// matching intent, so every surface reported a healthy feed while 100% of
// events were dropped.
func TestChaos66_ConnectedButNotDeliveringIsNotReportedActive(t *testing.T) {
	syslogTestReset(t)

	noteSyslogConfigured()
	noteSyslogConnected()
	syslogConfiguredAddr = "tcp://collector.example:601"
	syslogConfigured = syslogConfiguredAddr
	_ = syslogConfigured
	// A writer must be published or checkSyslogFeed short-circuits on the
	// never-connected branch, which is NOT the state under test.
	addr, _ := newObservedCollector(t)
	sw, err := newSyslogWriter("tcp", addr, "rfc3164")
	if err != nil {
		t.Fatalf("newSyslogWriter: %v", err)
	}
	publishSyslogWriter(sw)
	t.Cleanup(func() { publishSyslogWriter(nil) })

	// One failed delivery: not yet degraded, but no longer "active".
	noteSyslogDelivery(false)
	if v := checkSyslogFeed(); v.Status == diagOK {
		t.Errorf("after a failed delivery the row is %v %q; a feed that is not delivering must not report OK",
			v.Status, v.Message)
	}

	// Past the threshold it is a FAILURE, and the message must say so plainly.
	// The timeline is driven explicitly from a fixed origin: the episode opened
	// on the real clock above, so mixing in a back-dated failure would leave
	// firstFailure at "now" and measure a zero-length outage.
	resetSyslogFeedHealthForTest()
	noteSyslogConfigured()
	noteSyslogConnected()
	origin := time.Now()
	noteSyslogFailure(origin)
	noteSyslogFailure(origin.Add(syslogFeedDegradedAfter + time.Second))
	v := checkSyslogFeed()
	if v.Status != diagFail {
		t.Fatalf("status = %v; want fail once the feed has been dark past the threshold (message %q)", v.Status, v.Message)
	}
	if !strings.Contains(v.Message, "NOT delivering") {
		t.Errorf("message = %q; must state that the feed is not delivering", v.Message)
	}
	if v.OperatorAction == "" {
		t.Error("a failing contract row must carry an operator action")
	}
}

// ── D2 ──────────────────────────────────────────────────────────────────────
//
// Degradation is a DURATION, not a count: a busy gateway produces one line per
// request, so a count threshold measures traffic volume rather than fault
// severity and pages on every collector restart.
func TestChaos66_DeliveryFailureDegradesTheFeedAfterTheThreshold(t *testing.T) {
	syslogTestReset(t)
	noteSyslogConfigured()

	start := time.Now()
	// A thousand failures inside one second must NOT degrade the feed: volume
	// is not severity.
	for i := 0; i < 1000; i++ {
		noteSyslogFailure(start.Add(time.Duration(i) * time.Millisecond))
	}
	if snap := syslogFeedState(); snap.Degraded {
		t.Errorf("1000 failures within %v degraded the feed; degradation must be a duration, not a count", time.Second)
	}
	// One more, past the window, and it is degraded.
	noteSyslogFailure(start.Add(syslogFeedDegradedAfter + time.Second))
	if snap := syslogFeedState(); !snap.Degraded {
		t.Fatal("feed not degraded after continuous failure past the threshold")
	}
}

// ── D3 ──────────────────────────────────────────────────────────────────────
//
// Reproduced against the pre-fix tree: reconfiguring never closed the writer it
// replaced, stranding a drain goroutine and an open TCP connection to the old
// collector for the life of the process. The boot sequence itself re-inits when
// a target is present in both the YAML config and the persisted admin settings,
// so an ordinary appliance leaked one on EVERY boot.
func TestChaos66_ReconfigureClosesThePredecessor(t *testing.T) {
	syslogTestReset(t)

	first, firstClosed := newObservedCollector(t)
	second, _ := newObservedCollector(t)

	if err := InitSyslog("tcp://"+first, "rfc3164"); err != nil {
		t.Fatalf("first InitSyslog: %v", err)
	}
	prev := activeSyslog()
	if prev == nil {
		t.Fatal("no writer published")
	}
	if err := InitSyslog("tcp://"+second, "rfc3164"); err != nil {
		t.Fatalf("second InitSyslog: %v", err)
	}
	if activeSyslog() == prev {
		t.Fatal("the active writer did not change")
	}
	select {
	case <-firstClosed:
	case <-time.After(10 * time.Second):
		t.Fatal("the predecessor's connection to the old collector was never closed — its drain goroutine and socket leak for the life of the process")
	}
}

// ── D4 ──────────────────────────────────────────────────────────────────────
//
// Run this under -race. The pre-fix tree reported two races: on the pointer
// itself, and on Writer.queue between NewWriter and send() — the second is the
// dangerous one, because a reader that sees a nil queue on a published writer
// takes the SYNCHRONOUS path and performs the collector write on the REQUEST
// goroutine.
func TestChaos66_ActiveWriterIsPublishedAtomically(t *testing.T) {
	syslogTestReset(t)
	addr, _ := newObservedCollector(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // the request path
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
					sw.WriteRequest(map[string]string{"h": "example.com"})
				}
			}
		}()
	}
	for i := 0; i < 5; i++ { // the admin path
		if err := InitSyslog("tcp://"+addr, "rfc3164"); err != nil {
			t.Fatalf("InitSyslog: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}

// ── D5 ──────────────────────────────────────────────────────────────────────
//
// A connect failure at BOOT used to be permanent for the life of the process,
// while the identical failure mid-life self-heals through the engine's own
// reconnect state machine.
func TestChaos66_StartupConnectFailureArmsARecoveryCampaign(t *testing.T) {
	syslogTestReset(t)

	// A collector that is not there yet.
	addr := reservedClosedPort(t)
	loadObservability(observabilityStartupConfig{SyslogAddr: "tcp://" + addr, SyslogFormat: "rfc3164"})
	t.Cleanup(stopSyslogReconnect)

	if activeSyslog() != nil {
		t.Fatal("a failed dial must not publish a writer")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if running, attempts := syslogReconnectActive(); running && attempts > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	running, attempts := syslogReconnectActive()
	t.Fatalf("no reconnect campaign made progress (running=%t attempts=%d) — a SIEM feed that could not connect at boot stays dark for the life of the process",
		running, attempts)
}

// ── D6 ──────────────────────────────────────────────────────────────────────
//
// Before this change the ONLY loss signal was a field on one admin-only JSON
// readback. /metrics carried nothing, so nothing could alert on a dark feed.
func TestChaos66_DropsAreVisibleOnMetrics(t *testing.T) {
	syslogTestReset(t)
	noteSyslogConfigured()
	noteSyslogConnected()
	noteSyslogDelivery(false)

	out := renderSyslogMetrics()
	for _, want := range []string{
		"culvert_syslog_up",
		"culvert_syslog_degraded",
		"culvert_syslog_delivered_total",
		"culvert_syslog_drops_total",
		"culvert_syslog_queue_drops_total",
		"culvert_syslog_last_success_timestamp_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %s — a dark SIEM feed must be alertable from /metrics", want)
		}
	}
	if !strings.Contains(out, "culvert_syslog_up 0") {
		t.Errorf("culvert_syslog_up must be 0 while deliveries are failing; got:\n%s", out)
	}
}

// ── D7 ──────────────────────────────────────────────────────────────────────
//
// Queue overflow and an unreachable collector are different operator actions —
// capacity versus a network path — so they are counted apart, and the contract
// row says which one happened. The engine-level half (that overflow is actually
// charged to QueueDrops) is pinned in
// internal/syslog/syslog_delivery_evidence_test.go, where a blocking connection
// can be injected deterministically.
func TestChaos66_QueueOverflowIsReportedAsCapacityNotReachability(t *testing.T) {
	syslogTestReset(t)
	addr, _ := newObservedCollector(t)
	syslogConfiguredAddr = "tcp://" + addr
	noteSyslogConfigured()
	if err := InitSyslog(syslogConfiguredAddr, "rfc3164"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured = syslogConfiguredAddr

	sw := activeSyslog()
	_ = sw.Close() // post-close sends are charged to the queue, not the network
	for i := 0; i < 10; i++ {
		sw.WriteRequest(map[string]int{"i": i})
	}
	if sw.QueueDrops() == 0 {
		t.Fatal("precondition: expected queue-side drops")
	}
	v := checkSyslogFeed()
	if v.Status != diagWarn || !strings.Contains(v.Message, "queue overflowed") {
		t.Errorf("row = %v %q; queue-side loss must be reported as a capacity problem, not as an unreachable collector",
			v.Status, v.Message)
	}
	if !strings.Contains(v.OperatorAction, "capacity") {
		t.Errorf("operator action = %q; must point at collector capacity", v.OperatorAction)
	}
}

// ── C1 ──────────────────────────────────────────────────────────────────────
//
// Control. The cheapest way to pass D1 and D2 is a plane that reports the feed
// as broken all the time, which would page every operator who has a perfectly
// healthy collector.
func TestChaos66_Control_HealthyFeedStillReportsActive(t *testing.T) {
	syslogTestReset(t)
	addr, _ := newObservedCollector(t)
	syslogConfiguredAddr = "tcp://" + addr
	noteSyslogConfigured()
	if err := InitSyslog(syslogConfiguredAddr, "rfc3164"); err != nil {
		t.Fatalf("InitSyslog: %v", err)
	}
	syslogConfigured = syslogConfiguredAddr

	noteSyslogDelivery(true)
	if v := checkSyslogFeed(); v.Status != diagOK {
		t.Errorf("a delivering feed reports %v %q; want ok", v.Status, v.Message)
	}
	if got := syslogFeedStatus(); got != "ready" {
		t.Errorf("/health siem_feed = %q; want ready", got)
	}
}

// ── C2 ──────────────────────────────────────────────────────────────────────
//
// Control. A feed the operator switched off must never degrade or page.
func TestChaos66_Control_DisabledFeedNeverDegradesOrAlerts(t *testing.T) {
	syslogTestReset(t)
	noteSyslogConfigured()
	noteSyslogFailure(time.Now().Add(-2 * syslogFeedDegradedAfter))
	noteSyslogFailure(time.Now())
	if !syslogFeedState().Degraded {
		t.Fatal("precondition: feed should be degraded before the disable")
	}

	noteSyslogDisabled()
	snap := syslogFeedState()
	if snap.Degraded || snap.Failing || snap.Configured {
		t.Errorf("a disabled feed still reports degraded=%t failing=%t configured=%t",
			snap.Degraded, snap.Failing, snap.Configured)
	}
	if got := syslogFeedStatus(); got != "disabled" {
		t.Errorf("/health siem_feed = %q; want disabled", got)
	}
	if out := renderSyslogMetrics(); out != "" {
		t.Errorf("a node with no SIEM configured must emit no syslog series; got:\n%s", out)
	}
}

// ── C3 ──────────────────────────────────────────────────────────────────────
//
// Control for the house rule: recovery is established by EVIDENCE — a line that
// actually reached the collector — never by elapsed time. A feed that stopped
// failing because nothing is being written to it has not recovered.
func TestChaos66_Control_RecoveryRequiresAnObservedDelivery(t *testing.T) {
	syslogTestReset(t)
	noteSyslogConfigured()
	noteSyslogFailure(time.Now().Add(-2 * syslogFeedDegradedAfter))
	noteSyslogFailure(time.Now())
	if !syslogFeedState().Degraded {
		t.Fatal("precondition: degraded")
	}

	// Time passing, and reads happening, clear nothing.
	for i := 0; i < 5; i++ {
		_ = syslogFeedState()
		_ = checkSyslogFeed()
	}
	if !syslogFeedState().Degraded {
		t.Fatal("degradation cleared without any observed delivery")
	}

	noteSyslogDelivery(true)
	snap := syslogFeedState()
	if snap.Degraded || snap.Failing || snap.Consecutive != 0 {
		t.Errorf("an observed delivery did not clear the episode: degraded=%t failing=%t consecutive=%d",
			snap.Degraded, snap.Failing, snap.Consecutive)
	}
}

// ── C4 ──────────────────────────────────────────────────────────────────────
//
// Control for the generation fence. A retry that finally connects must never
// install itself over a target the operator has since changed or switched off —
// that would resurrect forwarding to a collector they deliberately stopped
// using.
func TestChaos66_Control_CampaignNeverOverwritesANewerOperatorChoice(t *testing.T) {
	syslogTestReset(t)

	addr, _ := newObservedCollector(t)
	gen := syslogGeneration.Load()
	stop := make(chan struct{})
	defer close(stop)

	// The operator moves on BEFORE the campaign's round runs.
	publishSyslogWriter(nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSyslogReconnect("tcp://"+addr, "rfc3164", gen, stop)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("campaign did not exit after the generation moved")
	}
	if activeSyslog() != nil {
		t.Error("the campaign published over an operator choice made after it was armed")
	}
}

// ── C5 ──────────────────────────────────────────────────────────────────────
//
// Control for the emission rule (socks5/cluster_ca/dns precedent): a flat block
// of zeros from every appliance that never configured a collector is
// indistinguishable from one whose feed is dead, and the documented paging rule
// is `culvert_syslog_up == 0`.
func TestChaos66_Control_MetricsAreSilentOnAnUnconfiguredNode(t *testing.T) {
	syslogTestReset(t)
	if out := renderSyslogMetrics(); out != "" {
		t.Errorf("unconfigured node emitted syslog series:\n%s", out)
	}
}
