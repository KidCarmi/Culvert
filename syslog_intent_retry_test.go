package main

// syslog_intent_retry_test.go — the SIEM boot-dial retry (syslog_intent_retry.go).
//
// The gates come in two halves on purpose. ACTION: a collector that was down
// at boot is connected without an operator. RESTRAINT: the retry publishes
// nothing once the operator has disabled forwarding, re-pointed it, or the
// node is shutting down — including when its own dial has already succeeded.

import (
	"context"
	"net"
	"testing"
	"time"
)

// reserveClosedSyslogAddr returns a loopback address nothing is listening on:
// a boot dial to it is refused immediately, and a collector can be started on
// it later to play "the SIEM came up after the gateway".
func reserveClosedSyslogAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}
	return addr
}

// isolateSyslogRetry gives a gate a clean syslog plane and takes it back.
func isolateSyslogRetry(t *testing.T) {
	t.Helper()
	ensureObservabilityStartupTestLogger(t)
	snapshotObservabilityGlobals(t)
	resetSyslogHealthForTest()
	t.Cleanup(resetSyslogHealthForTest)
}

// bootSyslogWithDeadCollector runs the REAL startup slice against a collector
// that is not listening, and asserts the pre-existing contract: the node
// carries on, no Writer exists, and the feed is reported down at once.
func bootSyslogWithDeadCollector(t *testing.T, format string) (target, addr string) {
	t.Helper()
	addr = reserveClosedSyslogAddr(t)
	target = "tcp://" + addr
	loadObservability(observabilityStartupConfig{SyslogAddr: target, SyslogFormat: format})
	if sw := syslogHandle(); sw != nil {
		t.Fatalf("precondition: the boot dial to a dead collector installed a writer")
	}
	if row := checkSyslogFeed(); row.Status != diagFail {
		t.Fatalf("precondition: syslog_feed = %q after a failed boot dial; want %q", row.Status, diagFail)
	}
	if snap := syslogFeedState(); !snap.IntentUnmet || !snap.Degraded {
		t.Fatalf("precondition: want an unmet, degraded intent; got IntentUnmet=%v Degraded=%v", snap.IntentUnmet, snap.Degraded)
	}
	return target, addr
}

// startSyslogRetryLoop runs the production loop with an injected backoff and
// joins it on cleanup, so no gate leaves a dialling goroutine behind.
func startSyslogRetryLoop(t *testing.T, delay func(int) time.Duration) (cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	ctx, cancelCtx := context.WithCancel(context.Background())
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		runSyslogIntentRetry(ctx, delay)
	}()
	t.Cleanup(func() {
		cancelCtx()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Error("the retry loop did not exit after its context was cancelled")
		}
	})
	return cancelCtx, exited
}

func waitSyslogCondition(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// ACTION. The manual-intervention requirement, and its removal: a collector
// that is down while the node boots stays unserved — and, once it is
// listening, is connected by the retry with no re-save and no restart.
func TestSyslogIntentRetry_ConnectsACollectorThatWasDownAtBoot(t *testing.T) {
	isolateSyslogRetry(t)
	startTS := time.Now().UnixMilli()
	target, addr := bootSyslogWithDeadCollector(t, "rfc5424")

	if got := syslogRetryPendingSnapshot(); got != (syslogRetryIntent{addr: target, format: "rfc5424"}) {
		t.Fatalf("the failed boot dial was not handed to the retry: pending = %+v", got)
	}

	// The collector is still down: attempts fail, the backoff advances, and
	// nothing is published. The delay func is the loop's only clock, so the
	// failure counts it is asked about ARE the observed attempt history.
	asked := make(chan int, 64)
	startSyslogRetryLoop(t, func(failed int) time.Duration {
		select {
		case asked <- failed:
		default:
		}
		return time.Millisecond
	})
	sawFailures := false
	for !sawFailures {
		select {
		case n := <-asked:
			sawFailures = n >= 2
		case <-time.After(15 * time.Second):
			t.Fatal("the loop never recorded two failed attempts against a dead collector")
		}
	}
	if sw := syslogHandle(); sw != nil {
		t.Fatal("a writer was published while the collector was still unreachable")
	}
	if snap := syslogFeedState(); !snap.IntentUnmet || !snap.Degraded {
		t.Fatalf("failed attempts changed the verdict: IntentUnmet=%v Degraded=%v; the feed must stay reported down", snap.IntentUnmet, snap.Degraded)
	}

	// The SIEM comes up.
	collector := startSyslogCollectorOn(t, addr)
	t.Cleanup(collector.stop)

	waitSyslogCondition(t, "the retry to install a writer", func() bool { return syslogHandle() != nil })
	collector.waitForConnection(t)

	connected, intended, sw := syslogConfiguredSnapshot()
	if connected != target || intended != target {
		t.Errorf("connected=%q intended=%q; want both %q", connected, intended, target)
	}
	if sw == nil || sw.Format() != "rfc5424" {
		t.Errorf("the retry did not keep the configured wire format: writer=%v", sw)
	}
	if snap := syslogFeedState(); snap.IntentUnmet {
		t.Error("the intent is still reported unmet after the retry installed its writer")
	}
	if syslogSkipArmed() {
		t.Error("events are still being charged as skipped-for-want-of-a-writer after the install")
	}
	if got := syslogRetryPendingSnapshot(); got != (syslogRetryIntent{}) {
		t.Errorf("the pending record survived the install: %+v", got)
	}
	// The recovery is attributed to the system, never to an admin. WAITED
	// for, not read once: the retry goroutine releases the publication lock
	// before it logs and audits, so the published writer observed above does
	// not order this entry before the assertion.
	waitSyslogCondition(t, "a system-attributed audit entry for the automatic connect", func() bool {
		return hasMatchingAuditEntry(auditGet(), "system", "settings.syslog.auto_connect", target, startTS)
	})
	// The init-time branch of the contract row no longer fails. (The delivery
	// branch may still add a warning for events lost while the feed was down;
	// that loss is real and is deliberately not erased.)
	if row := checkSyslogFeed(); row.Status == diagFail {
		t.Errorf("syslog_feed still fails after the automatic connect: %q", row.Message)
	}
}

// A failed attempt must not move the health plane: no pending-dial grace is
// re-opened and the outage's age is not re-anchored, or `culvert_syslog_up`
// would flap up once per attempt and the page would look newer than it is.
func TestSyslogIntentRetry_FailedAttemptLeavesTheVerdictAlone(t *testing.T) {
	isolateSyslogRetry(t)
	target, _ := bootSyslogWithDeadCollector(t, "")

	syslogHealth.mu.Lock()
	intentAt, verdictBy, gen := syslogHealth.intentAt, syslogHealth.dialVerdictBy, syslogHealth.gen
	syslogHealth.mu.Unlock()

	want := syslogRetryIntent{addr: target}
	if got := attemptSyslogIntentRetry(context.Background(), want, 1); got != syslogRetryFailed {
		t.Fatalf("attempt against a dead collector = %v; want failed", got)
	}

	syslogHealth.mu.Lock()
	defer syslogHealth.mu.Unlock()
	if !syslogHealth.intentAt.Equal(intentAt) || !syslogHealth.dialVerdictBy.Equal(verdictBy) || syslogHealth.gen != gen {
		t.Error("a failed retry attempt wrote the health record; the verdict must be untouched until a writer is installed")
	}
	if !syslogIntentUnmetLocked() {
		t.Error("the intent is no longer reported unmet after a FAILED attempt")
	}
}

// RESTRAINT. The operator switched forwarding off while the retry was
// pending — and, in the sharper shape, while its dial had already succeeded.
// Neither may re-enable a collector nobody wants any more.
func TestSyslogIntentRetry_DisableWinsOverAPendingAndAnInFlightRetry(t *testing.T) {
	isolateSyslogRetry(t)
	startTS := time.Now().UnixMilli()
	target, addr := bootSyslogWithDeadCollector(t, "")
	want := syslogRetryIntent{addr: target}

	// The collector is reachable now, so only the retry's own restraint
	// stands between this gate and a published writer.
	collector := startSyslogCollectorOn(t, addr)
	t.Cleanup(collector.stop)

	// In flight: the dial has returned a live writer, and THEN the operator
	// disables forwarding, before the retry reaches its publish section.
	sw, err := newSyslogWriter("tcp", addr, "")
	if err != nil {
		t.Fatalf("dial the revived collector: %v", err)
	}
	t.Cleanup(func() { _ = sw.Close() })
	disableActiveSyslog()

	if publishRetriedSyslogWriter(context.Background(), sw, want) {
		t.Fatal("a retry whose dial was in flight published its writer after the operator disabled forwarding")
	}
	// Pending: a later tick finds nothing left to do, and does not dial.
	if got := attemptSyslogIntentRetry(context.Background(), want, 2); got != syslogRetrySuperseded {
		t.Fatalf("attempt after a disable = %v; want superseded", got)
	}

	connected, intended, live := syslogConfiguredSnapshot()
	if live != nil || connected != "" || intended != "" {
		t.Errorf("forwarding came back after a disable: writer=%v connected=%q intended=%q", live, connected, intended)
	}
	if syslogFeedState().Intended {
		t.Error("the health plane reports a collector as configured after the operator disabled it")
	}
	if hasMatchingAuditEntry(auditGet(), "system", "settings.syslog.auto_connect", target, startTS) {
		t.Error("an automatic connect was audited although nothing was published")
	}
}

// RESTRAINT. A manual re-point racing the retry: the operator's target wins,
// in the order where the retry's dial for the OLD target lands afterwards.
func TestSyslogIntentRetry_ManualRepointSupersedesTheBootTarget(t *testing.T) {
	isolateSyslogRetry(t)
	bootTarget, bootAddr := bootSyslogWithDeadCollector(t, "")
	want := syslogRetryIntent{addr: bootTarget}

	// The operator re-points at a different, working collector (the admin
	// handler's own call).
	chosen := startSyslogCollector(t)
	chosenTarget := "tcp://" + chosen.addr
	if err := InitSyslog(chosenTarget, "rfc3164"); err != nil {
		t.Fatalf("InitSyslog(%q): %v", chosenTarget, err)
	}
	operatorWriter := syslogHandle()

	// The boot collector comes up too, and the retry's dial for it succeeds.
	revived := startSyslogCollectorOn(t, bootAddr)
	t.Cleanup(revived.stop)
	stale, err := newSyslogWriter("tcp", bootAddr, "")
	if err != nil {
		t.Fatalf("dial the revived boot collector: %v", err)
	}
	t.Cleanup(func() { _ = stale.Close() })

	if publishRetriedSyslogWriter(context.Background(), stale, want) {
		t.Fatal("the retry replaced the collector the operator had just chosen with the boot target")
	}
	if got := attemptSyslogIntentRetry(context.Background(), want, 1); got != syslogRetrySuperseded {
		t.Fatalf("attempt after a manual re-point = %v; want superseded", got)
	}
	connected, intended, live := syslogConfiguredSnapshot()
	if live != operatorWriter || connected != chosenTarget || intended != chosenTarget {
		t.Errorf("the operator's re-point did not survive: connected=%q intended=%q sameWriter=%v", connected, intended, live == operatorWriter)
	}
}

// RESTRAINT. Shutdown: a dial that returns after the lifecycle cancel is not
// published (the syslog-close hook has no later chance to release it), and
// the loop itself exits.
func TestSyslogIntentRetry_PublishesNothingAfterShutdown(t *testing.T) {
	isolateSyslogRetry(t)
	target, addr := bootSyslogWithDeadCollector(t, "")
	collector := startSyslogCollectorOn(t, addr)
	t.Cleanup(collector.stop)

	sw, err := newSyslogWriter("tcp", addr, "")
	if err != nil {
		t.Fatalf("dial the revived collector: %v", err)
	}
	t.Cleanup(func() { _ = sw.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if publishRetriedSyslogWriter(ctx, sw, syslogRetryIntent{addr: target}) {
		t.Fatal("a writer was published after the lifecycle context was cancelled")
	}
	if syslogHandle() != nil {
		t.Fatal("a writer is live after shutdown began")
	}

	// The loop, armed and with an hour-long backoff, still exits promptly.
	stop, done := startSyslogRetryLoop(t, func(int) time.Duration { return time.Hour })
	stop()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop did not exit on cancellation while waiting out its backoff")
	}
}

// The retry is armed ONLY for a boot dial that is still the unserved intent.
func TestSyslogIntentRetry_ArmsOnlyForTheUnservedConfiguredTarget(t *testing.T) {
	isolateSyslogRetry(t)

	// Nothing configured.
	armSyslogIntentRetry("", "rfc3164")
	armSyslogIntentRetry("tcp://127.0.0.1:1", "rfc3164") // not the recorded intent
	if got := syslogRetryPendingSnapshot(); got != (syslogRetryIntent{}) {
		t.Fatalf("armed for a target nobody configured: %+v", got)
	}

	// A live admin re-point that FAILS is refused with a 400 and records no
	// intent; it must not start a background retry either.
	dead := "tcp://" + reserveClosedSyslogAddr(t)
	if err := InitSyslog(dead, ""); err == nil {
		t.Fatal("precondition: InitSyslog to a dead collector succeeded")
	}
	if got := syslogRetryPendingSnapshot(); got != (syslogRetryIntent{}) {
		t.Fatalf("a refused admin re-point left a retry pending: %+v", got)
	}

	// The target is already served (the YAML slice connected it; a second
	// boot dial of the same target failing must not churn a working writer).
	live := startSyslogCollector(t)
	liveTarget := "tcp://" + live.addr
	if err := InitSyslog(liveTarget, ""); err != nil {
		t.Fatalf("InitSyslog(%q): %v", liveTarget, err)
	}
	armSyslogIntentRetry(liveTarget, "")
	if got := syslogRetryPendingSnapshot(); got != (syslogRetryIntent{}) {
		t.Fatalf("armed for a target that is already being served: %+v", got)
	}
}

// A boot that connected the YAML collector and then failed to connect the
// PERSISTED one keeps serving the first — and the retry completes the boot's
// own intended end state once the persisted collector is reachable.
func TestSyslogIntentRetry_CompletesASupersededBootTarget(t *testing.T) {
	isolateSyslogRetry(t)

	first := startSyslogCollector(t)
	loadObservability(observabilityStartupConfig{SyslogAddr: "tcp://" + first.addr})
	if syslogHandle() == nil {
		t.Fatal("precondition: the YAML collector did not connect")
	}

	persistedAddr := reserveClosedSyslogAddr(t)
	persisted := "tcp://" + persistedAddr
	applyAdminServices(&AdminSettings{SyslogAddr: persisted, SyslogFormat: "rfc5424"})
	if _, intended, sw := syslogConfiguredSnapshot(); intended != persisted || sw == nil {
		t.Fatalf("precondition: want intent %q served by the previous writer; intended=%q writer=%v", persisted, intended, sw)
	}
	want := syslogRetryIntent{addr: persisted, format: "rfc5424"}
	if got := syslogRetryPendingSnapshot(); got != want {
		t.Fatalf("the failed persisted-settings dial was not handed to the retry: %+v", got)
	}

	second := startSyslogCollectorOn(t, persistedAddr)
	t.Cleanup(second.stop)
	if got := attemptSyslogIntentRetry(context.Background(), want, 1); got != syslogRetryInstalled {
		t.Fatalf("attempt against the now-reachable persisted collector = %v; want installed", got)
	}
	connected, intended, sw := syslogConfiguredSnapshot()
	if connected != persisted || intended != persisted || sw == nil || sw.Format() != "rfc5424" {
		t.Errorf("connected=%q intended=%q writer=%v; want the persisted target in rfc5424", connected, intended, sw)
	}
	if syslogFeedState().IntentUnmet {
		t.Error("the persisted target is still reported unmet after the retry installed it")
	}
}

// The cadence bound: 10s doubling to a two-minute cap, never more than 25%
// over, for any attempt count (including ones that would overflow a shift).
func TestSyslogIntentRetry_BackoffIsBounded(t *testing.T) {
	for _, tc := range []struct {
		failed int
		base   time.Duration
	}{
		{0, 10 * time.Second},
		{1, 20 * time.Second},
		{3, 80 * time.Second},
		{4, 2 * time.Minute},
		{7, 2 * time.Minute},
		{8, 2 * time.Minute},
		{1 << 20, 2 * time.Minute},
		{-1, 2 * time.Minute},
	} {
		for range 50 {
			got := syslogRetryDelay(tc.failed)
			if got < tc.base || got > tc.base+tc.base/4 {
				t.Fatalf("syslogRetryDelay(%d) = %v; want within [%v, %v]", tc.failed, got, tc.base, tc.base+tc.base/4)
			}
		}
	}
}
