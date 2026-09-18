package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/syslog"
)

// syslog_health_chaos_test.go — CHAOS-66 gates for the SIEM delivery health
// plane in package main.
//
// The headline DEFECT gate is TestChaos66_UnverifiableFeedIsNotReportedActive:
// against the pre-fix checkSyslogFeed it FAILS, because that function verdicted
// on whether InitSyslog's dial returned nil and reported
// `ok — "remote syslog/SIEM forwarding is active"` for a UDP target, where a
// dial sends nothing and succeeds against an address nobody is listening on.
//
// The CONTROLS matter as much as the defect gates: the cheapest way to pass a
// "loss must be visible" suite is to report every feed as broken, which would
// page every healthy deployment and put an amber row on every appliance that
// does not use SIEM forwarding at all.

// withSyslogTestState saves and restores every global these surfaces read, so
// the gates are order-independent under -shuffle and -count=2.
func withSyslogTestState(t *testing.T) {
	t.Helper()
	prevWriter, prevCfg, prevAddr := globalSyslog, syslogConfigured, syslogConfiguredAddr
	// Copy the FIELDS, never the record: syslogHealthRecord embeds a mutex, and
	// copying it by value is a vet error (and would restore a snapshot of lock
	// state, which is meaningless).
	syslogHealth.mu.Lock()
	prevConfigured, prevFailing := syslogHealth.configured, syslogHealth.failingSince
	prevAlerted, prevLogAt, prevSuppressed := syslogHealth.alerted, syslogHealth.logAt, syslogHealth.suppressed
	syslogHealth.mu.Unlock()
	t.Cleanup(func() {
		globalSyslog, syslogConfigured, syslogConfiguredAddr = prevWriter, prevCfg, prevAddr
		setSyslogNow(nil)
		setSyslogAlert(nil)
		syslogHealth.mu.Lock()
		syslogHealth.configured = prevConfigured
		syslogHealth.failingSince = prevFailing
		syslogHealth.alerted = prevAlerted
		syslogHealth.logAt = prevLogAt
		syslogHealth.suppressed = prevSuppressed
		syslogHealth.mu.Unlock()
	})
	noteSyslogUnconfigured()
}

// newLiveCollector starts a real local collector of the given network and
// returns a Writer pointed at it, wired exactly as production wires one.
// Deliberately a real socket rather than a mock: the property under test is
// what the TRANSPORT can and cannot tell us, which a mock would define away.
func newLiveCollector(t *testing.T, network string) (writer *syslog.Writer, stop func()) {
	t.Helper()
	var addr string
	var closeFn func()
	switch network {
	case "tcp":
		// (*net.ListenConfig).Listen, not net.Listen — repo lint policy (noctx).
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback TCP in this environment: %v", err)
		}
		// Accepted conns are tracked so stop() can SEVER them. Closing the
		// listener alone is not enough and that is not a detail: an established
		// connection outlives its listener, which is exactly why CHAOS-57 needed
		// a drain registry for hijacked tunnels. A test that only closed the
		// listener would keep writing into a live socket and prove nothing.
		var accepted struct {
			mu    sync.Mutex
			conns []net.Conn
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.mu.Lock()
				accepted.conns = append(accepted.conns, c)
				accepted.mu.Unlock()
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
		addr = ln.Addr().String()
		closeFn = func() {
			ln.Close()
			accepted.mu.Lock()
			for _, c := range accepted.conns {
				c.Close()
			}
			accepted.conns = nil
			accepted.mu.Unlock()
		}
	default:
		// (*net.ListenConfig).ListenPacket, not net.ListenPacket — same policy.
		pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Skipf("no loopback UDP in this environment: %v", err)
		}
		addr, closeFn = pc.LocalAddr().String(), func() { pc.Close() }
	}
	w, err := syslog.NewWriter(network, addr, "rfc3164")
	if err != nil {
		closeFn()
		t.Fatalf("NewWriter(%s): %v", network, err)
	}
	// Wire the observer exactly as newSyslogWriter does — a closure binding
	// this writer's identity — so the gates exercise the production fence
	// rather than a shape only tests use.
	w.SetDeliveryObserver(func(ok bool, reason string, consecutive int64) {
		noteSyslogDelivery(w, ok, reason, consecutive)
	})
	t.Cleanup(func() { w.Close(); closeFn() })
	return w, closeFn
}

// arm points the process globals at w as though the operator had configured it.
func arm(w *syslog.Writer, addr string) {
	globalSyslog = w
	syslogConfigured, syslogConfiguredAddr = addr, addr
	noteSyslogConfigured(w)
}

// TestChaos66_UnverifiableFeedIsNotReportedActive — THE defect gate.
//
// A UDP collector is working perfectly here, and that is the point: the row
// must still refuse to claim delivery, because on this transport it could not
// tell the difference if the collector vanished. Against the pre-fix
// checkSyslogFeed this fails — it returned diagOK with "forwarding is active".
func TestChaos66_UnverifiableFeedIsNotReportedActive(t *testing.T) {
	withSyslogTestState(t)
	w, _ := newLiveCollector(t, "udp")
	arm(w, "udp://collector.test:514")

	row := checkSyslogFeed()
	if row.Status == diagOK {
		t.Fatalf("UDP feed reported ok — a green row here is the absence of evidence, not evidence of delivery: %+v", row)
	}
	if row.Status != diagWarn {
		t.Errorf("Status = %q, want %q (a fail row would overstate a feed that is probably fine)", row.Status, diagWarn)
	}
	if !strings.Contains(strings.ToLower(row.Message), "unverifiable") {
		t.Errorf("row does not state the limitation: %q", row.Message)
	}
	if row.OperatorAction == "" {
		t.Error("a warn row with no operator action is a dead end")
	}
	if !strings.Contains(row.OperatorAction, "tcp://") {
		t.Errorf("operator action does not name the remedy: %q", row.OperatorAction)
	}
}

// TestChaos66_RuntimeCollectorLossTurnsTheRowRed — DEFECT gate. A collector
// that goes away AFTER startup left globalSyslog non-nil and syslogConfigured
// equal to intent, so every pre-fix branch passed and the row stayed green
// while every line was discarded.
func TestChaos66_RuntimeCollectorLossTurnsTheRowRed(t *testing.T) {
	withSyslogTestState(t)
	w, stop := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")

	// Healthy first — the row must be green before the outage, or the gate
	// proves nothing about the transition.
	w.Write([]byte("pre-outage")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	waitForDelivery(t, w, 1)
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Fatalf("healthy TCP feed not green: %+v", row)
	}

	// The collector goes away, and the clock says the failure run is old enough
	// to be a real outage rather than a blip.
	stop()
	base := time.Now()
	setSyslogNow(func() time.Time { return base })
	forceFailureEpisode(t, w)
	setSyslogNow(func() time.Time { return base.Add(2 * syslogDeliveryDegradedAfter) })

	row := checkSyslogFeed()
	if row.Status != diagFail {
		t.Fatalf("collector gone but row = %q: %+v", row.Status, row)
	}
	if !strings.Contains(row.Message, "FAILING") {
		t.Errorf("row does not say the feed is failing: %q", row.Message)
	}
	// The local audit trail is NOT gone, and an operator must not conclude it is.
	if !strings.Contains(row.Message, "local audit log is unaffected") {
		t.Errorf("row does not scope the loss to the forwarded copy: %q", row.Message)
	}
	// Bounded reason only: never the collector address or a raw net error.
	if strings.Contains(row.Message, "collector.test") || strings.Contains(row.Message, "127.0.0.1") {
		t.Errorf("row leaks the collector address into a viewer-visible surface: %q", row.Message)
	}
}

// TestChaos66_DegradationIsADurationNotACount — a busy node loses thousands of
// lines a second during an outage and a quiet one loses a handful; a count
// threshold would page instantly on the first and never on the second for the
// identical fault. socks5_health.go and admin_ui_health.go both record this.
func TestChaos66_DegradationIsADurationNotACount(t *testing.T) {
	withSyslogTestState(t)
	w, stop := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	stop()

	base := time.Now()
	setSyslogNow(func() time.Time { return base })

	var paged int
	setSyslogAlert(func(string) { paged++ })

	// A large burst of losses, all inside the window.
	for i := 0; i < 5000; i++ {
		noteSyslogDelivery(w, false, "write_failed", int64(i+1))
	}
	if paged != 0 {
		t.Fatalf("paged %d times on volume alone, inside the degradation window", paged)
	}
	if checkSyslogFeed().Status == diagFail {
		t.Fatal("row went red on volume alone, inside the degradation window")
	}

	// One more failure, now past the window.
	setSyslogNow(func() time.Time { return base.Add(syslogDeliveryDegradedAfter + time.Second) })
	noteSyslogDelivery(w, false, "write_failed", 5001)
	if paged != 1 {
		t.Fatalf("pages = %d after crossing the duration threshold, want exactly 1", paged)
	}

	// Still failing: the latch must hold, or a down collector re-pages per line.
	for i := 0; i < 100; i++ {
		noteSyslogDelivery(w, false, "write_failed", int64(5002+i))
	}
	if paged != 1 {
		t.Errorf("pages = %d — the fire-once latch did not hold for the episode", paged)
	}
}

// TestChaos66_RecoveryRequiresObservedDelivery — elapsed time never clears the
// episode. A feed that stopped reporting failures because nothing is being
// logged looks identical to a healthy one.
func TestChaos66_RecoveryRequiresObservedDelivery(t *testing.T) {
	withSyslogTestState(t)
	w, _ := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	base := time.Now()
	setSyslogNow(func() time.Time { return base })
	setSyslogAlert(func(string) {})

	noteSyslogDelivery(w, false, "dial_failed", 1)
	setSyslogNow(func() time.Time { return base.Add(2 * syslogDeliveryDegradedAfter) })
	noteSyslogDelivery(w, false, "dial_failed", 2)

	syslogHealth.mu.Lock()
	failing, alerted := !syslogHealth.failingSince.IsZero(), syslogHealth.alerted
	syslogHealth.mu.Unlock()
	if !failing || !alerted {
		t.Fatalf("episode did not arm (failing=%v alerted=%v)", failing, alerted)
	}

	// Hours pass with no further failures — that is NOT recovery.
	setSyslogNow(func() time.Time { return base.Add(6 * time.Hour) })
	syslogHealth.mu.Lock()
	stillFailing := !syslogHealth.failingSince.IsZero()
	syslogHealth.mu.Unlock()
	if !stillFailing {
		t.Fatal("episode cleared by elapsed time alone")
	}

	// A delivered line is the only thing that clears it.
	noteSyslogDelivery(w, true, "", 0)
	syslogHealth.mu.Lock()
	cleared := syslogHealth.failingSince.IsZero() && !syslogHealth.alerted
	syslogHealth.mu.Unlock()
	if !cleared {
		t.Error("observed delivery did not clear the episode")
	}
}

// TestChaos66_MetricsAreEmittedOnlyWhenConfigured — the CHAOS-54 rule. A
// `culvert_syslog_up 0` on an appliance that has never used SIEM forwarding is
// indistinguishable from one whose collector is dead, and the documented
// paging rule is `== 0`, so an unconditional gauge pages every deployment that
// does not use the feature.
func TestChaos66_MetricsAreEmittedOnlyWhenConfigured(t *testing.T) {
	withSyslogTestState(t)

	var b strings.Builder
	syslogWritePrometheus(&b)
	if b.Len() != 0 {
		t.Fatalf("unconfigured node exported syslog series:\n%s", b.String())
	}

	w, _ := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	w.Write([]byte("line")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	waitForDelivery(t, w, 1)

	b.Reset()
	syslogWritePrometheus(&b)
	out := b.String()
	for _, want := range []string{
		"culvert_syslog_up 1",
		"culvert_syslog_delivery_verifiable 1",
		"culvert_syslog_delivering 1",
		"culvert_syslog_delivered_total",
		`culvert_syslog_drops_total{reason="collector_down"}`,
		`culvert_syslog_drops_total{reason="queue_full"}`,
		"culvert_syslog_last_delivery_timestamp_seconds",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing series %q in:\n%s", want, out)
		}
	}
}

// TestChaos66_NoLivenessGaugeOnAnUnverifiableTransport — the OCSP-8 lesson:
// "found nothing wrong" and "never checked" must not render identically. A
// `culvert_syslog_delivering 1` on UDP would be a fiction an operator would
// reasonably alert on.
func TestChaos66_NoLivenessGaugeOnAnUnverifiableTransport(t *testing.T) {
	withSyslogTestState(t)
	w, _ := newLiveCollector(t, "udp")
	arm(w, "udp://collector.test:514")

	var b strings.Builder
	syslogWritePrometheus(&b)
	out := b.String()
	if strings.Contains(out, "culvert_syslog_delivering") {
		t.Errorf("liveness gauge emitted on UDP, where it cannot mean anything:\n%s", out)
	}
	if !strings.Contains(out, "culvert_syslog_delivery_verifiable 0") {
		t.Errorf("the unverifiable fact itself was not exported — an operator has no way to know:\n%s", out)
	}
}

// TestChaos66_DisablingClearsThePlane — CONTROL. A disabled feed must stop
// exporting series and must not hold a latched alert episode for a collector
// nobody forwards to any more.
func TestChaos66_DisablingClearsThePlane(t *testing.T) {
	withSyslogTestState(t)
	w, _ := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	setSyslogAlert(func(string) {})
	noteSyslogDelivery(w, false, "write_failed", 1)

	globalSyslog, syslogConfigured, syslogConfiguredAddr = nil, "", ""
	noteSyslogUnconfigured()

	var b strings.Builder
	syslogWritePrometheus(&b)
	if b.Len() != 0 {
		t.Errorf("disabled feed still exports series:\n%s", b.String())
	}
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Errorf("disabled feed row = %+v, want ok/not-configured", row)
	}
	syslogHealth.mu.Lock()
	latched := syslogHealth.alerted
	syslogHealth.mu.Unlock()
	if latched {
		t.Error("alert episode survived disabling the feed")
	}
	_ = w
}

// TestChaos66_HealthyTCPFeedStaysGreen — CONTROL. The cheapest way to pass
// every gate above is to report everything as degraded.
func TestChaos66_HealthyTCPFeedStaysGreen(t *testing.T) {
	withSyslogTestState(t)
	w, _ := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	for i := 0; i < 10; i++ {
		w.Write([]byte("routine")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
	}
	waitForDelivery(t, w, 10)

	row := checkSyslogFeed()
	if row.Status != diagOK {
		t.Fatalf("healthy TCP feed not green: %+v", row)
	}
	if !strings.Contains(row.Message, "delivering") {
		t.Errorf("green row does not state the evidence: %q", row.Message)
	}
	if row.OperatorAction != "" {
		t.Errorf("healthy row carries an operator action: %q", row.OperatorAction)
	}
}

// TestChaos66_UnconnectedTargetStillFails — CONTROL for the one pre-existing
// verdict this change must not regress: an operator target that never
// connected is still a hard failure, and nothing retries it.
func TestChaos66_UnconnectedTargetStillFails(t *testing.T) {
	withSyslogTestState(t)
	globalSyslog = nil
	syslogConfigured, syslogConfiguredAddr = "", "tcp://unreachable.test:601"

	row := checkSyslogFeed()
	if row.Status != diagFail {
		t.Fatalf("configured-but-never-connected target = %q, want fail: %+v", row.Status, row)
	}
	if !strings.Contains(row.OperatorAction, "NOT retried automatically") {
		t.Errorf("row does not tell the operator the state is terminal without action: %q", row.OperatorAction)
	}
}

// waitForDelivery polls the writer's own evidence rather than sleeping a fixed
// amount: delivery is asynchronous, so a fixed sleep is either flaky or slow.
func waitForDelivery(t *testing.T, w *syslog.Writer, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if w.Health().Delivered >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("delivered %d lines, want %d", w.Health().Delivered, want)
}

// forceFailureEpisode drives lines until the writer reports a
// collector-attributable failure, so the gate depends on observed state rather
// than on how fast the OS notices a closed listener.
func forceFailureEpisode(t *testing.T, w *syslog.Writer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		w.Write([]byte("post-outage")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
		if w.Health().ConsecutiveFailures > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("collector was closed but no delivery failure was ever observed")
}

// ─── Structural wall: the observer must never be able to feed itself ────────

// TestChaos66_Wall_DeliveryObserverCannotRecurse pins the one invariant that
// makes it safe for the delivery observer to LOG.
//
// noteSyslogDelivery runs ON the syslog drain goroutine and calls
// logger.Printf. That is safe today only because the process logger's
// destinations are stdout and the rotating file — the syslog writer is NOT one
// of them, and receives only structured audit/request entries from store.go.
// If anyone ever adds the writer to setupLogger's MultiWriter, a failing
// collector becomes an unbounded feedback loop: a dropped line logs, the log
// line is enqueued, the drain fails it, which logs again.
//
// This is the same rule internal/audit states for SetWriteFailureObserver
// ("the observer MUST NOT call Add, directly or transitively"), and it is
// enforced here rather than left as a comment because the failure mode is
// silent until a collector goes down in production.
//
// Two halves, both source-level: prose cannot hold an invariant this cheap to
// break from an unrelated file.
func TestChaos66_Wall_DeliveryObserverCannotRecurse(t *testing.T) {
	// (1) The process logger's composition must not reference the syslog writer.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "logger.go"))
	if err != nil {
		t.Fatalf("read logger.go: %v", err)
	}
	if strings.Contains(string(src), "globalSyslog") || strings.Contains(string(src), "syslogWriter") {
		t.Error("logger.go references the syslog writer — if the process logger writes to the collector, " +
			"noteSyslogDelivery's failure log line re-enters the syslog queue and a collector outage becomes " +
			"an unbounded feedback loop. Route SIEM forwarding through store.go's WriteAudit/WriteRequest only.")
	}

	// (2) The observer itself must not call back into the writer.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(pkgSourceDir(), "syslog_health.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse syslog_health.go: %v", err)
	}
	var checked int
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		switch fn.Name.Name {
		case "noteSyslogDelivery", "noteSyslogDeliveryRecovered":
		default:
			continue
		}
		checked++
		ast.Inspect(fn, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "globalSyslog" {
				t.Errorf("%s calls globalSyslog.%s — the observer runs ON the drain goroutine; "+
					"calling back into the writer re-enters the path that invoked it",
					fn.Name.Name, sel.Sel.Name)
			}
			return true
		})
	}
	// Not vacuous: if the functions are renamed, the wall must fail loudly
	// rather than silently stop checking anything.
	if checked != 2 {
		t.Fatalf("wall matched %d observer functions, want 2 — the selector has drifted and is proving nothing", checked)
	}
}

// TestChaos66_SupersededWriterCannotDriveTheHealthPlane — DEFECT gate for a
// bug this sweep's own observer would otherwise have introduced.
//
// InitSyslog used to overwrite globalSyslog without releasing the previous
// writer. As a leak that was minor and admin-rate; with a delivery observer
// attached it is a CORRECTNESS bug, because a superseded writer still pointed
// at a DEAD collector keeps failing, keeps calling noteSyslogDelivery, and
// drives the health plane — which now describes the NEW writer — into a
// permanent failure episode. The operator fixes their SIEM target and the
// appliance reports the new, working feed as down.
//
// Reachable on an ordinary boot, not just an admin edit: observability
// initialises from YAML/flags and admin settings then applies a persisted
// override, so a node with a saved target builds two writers.
//
// A DIFFERENTIAL, so neither arm can pass vacuously: the first arm reproduces
// the hazard (an un-retired writer DOES move the plane — if this ever stops
// being true the second arm is proving nothing), the second shows retirement
// closing it.
func TestChaos66_SupersededWriterCannotDriveTheHealthPlane(t *testing.T) {
	// Arm A — the hazard is real: an un-retired writer whose collector died
	// drives the health plane.
	t.Run("unretired writer moves the plane", func(t *testing.T) {
		withSyslogTestState(t)
		old, stopOld := newLiveCollector(t, "tcp")
		arm(old, "tcp://old.test:601")
		// Deliver one line first: it forces the collector to ACCEPT, so severing
		// actually severs an established connection rather than discarding a
		// backlog entry the writer has not noticed yet.
		old.Write([]byte("pre-outage")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
		waitForDelivery(t, old, 1)
		noteSyslogConfigured(old) // clear the episode the successful delivery left

		stopOld()
		driveUntilFailing(t, old)

		syslogHealth.mu.Lock()
		failing := !syslogHealth.failingSince.IsZero()
		syslogHealth.mu.Unlock()
		if !failing {
			t.Fatal("an un-retired writer pointed at a dead collector did NOT move the health plane — " +
				"the hazard this gate exists to close is not reachable, so the paired arm proves nothing")
		}
	})

	// Arm B — retirement closes it.
	t.Run("retired writer cannot", func(t *testing.T) {
		withSyslogTestState(t)
		old, stopOld := newLiveCollector(t, "tcp")
		arm(old, "tcp://old.test:601")

		// The operator re-points at a working collector.
		old.Write([]byte("pre-outage")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
		waitForDelivery(t, old, 1)

		retireSyslogWriter(old)
		fresh, _ := newLiveCollector(t, "tcp")
		arm(fresh, "tcp://new.test:601")
		fresh.Write([]byte("on the new feed")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
		waitForDelivery(t, fresh, 1)

		// The OLD collector now dies. None of that may reach the health plane,
		// which describes the new feed.
		stopOld()
		for i := 0; i < 50; i++ {
			old.Write([]byte("into the void")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
		}
		time.Sleep(50 * time.Millisecond)

		syslogHealth.mu.Lock()
		failing := !syslogHealth.failingSince.IsZero()
		syslogHealth.mu.Unlock()
		if failing {
			t.Error("a superseded writer drove the health plane into a failure episode — " +
				"the live feed is healthy and would be reported as down")
		}
		if row := checkSyslogFeed(); row.Status != diagOK {
			t.Errorf("live feed reported as %q because a retired writer was still failing: %+v", row.Status, row)
		}
	})
}

// driveUntilFailing writes until the health plane records a failure episode, so
// the gate depends on observed state rather than on how fast the OS notices a
// severed connection.
func driveUntilFailing(t *testing.T, w *syslog.Writer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		w.Write([]byte("post-outage")) //nolint:errcheck // syslog Write never fails by contract (it enqueues); the delivery outcome is read through Health()
		syslogHealth.mu.Lock()
		failing := !syslogHealth.failingSince.IsZero()
		syslogHealth.mu.Unlock()
		if failing {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ─── Codex review gates (PR #1430) ─────────────────────────────────────────

// TestChaos66_RetiredWriterCallbackIsFenced — DEFECT gate for the RACE half of
// SL-8, which clearing the observer pointer does not close.
//
// retireSyslogWriter stores nil into the old writer's observer pointer, but a
// drain goroutine already past notifyDelivery's Load holds the old function
// and can be descheduled there arbitrarily long — past the swap, past
// noteSyslogConfigured. When it resumes it writes into a record that now
// describes a DIFFERENT writer.
//
// The window is nanoseconds wide and cannot be hit reliably by racing
// goroutines, so the gate reproduces it deterministically: capture the
// callback the way a descheduled goroutine holds it, reconfigure, then let it
// land. The fence must make it a no-op in BOTH directions — a stale failure
// must not mark a healthy feed down, and a stale recovery must not clear a
// real outage.
func TestChaos66_RetiredWriterCallbackIsFenced(t *testing.T) {
	withSyslogTestState(t)
	setSyslogAlert(func(string) {})

	oldW, _ := newLiveCollector(t, "tcp")
	arm(oldW, "tcp://old.test:601")

	// The callback a descheduled drain goroutine of oldW would be holding.
	stale := func(ok bool, reason string, consecutive int64) {
		noteSyslogDelivery(oldW, ok, reason, consecutive)
	}

	// The operator re-points at a working collector.
	retireSyslogWriter(oldW)
	fresh, _ := newLiveCollector(t, "tcp")
	arm(fresh, "tcp://new.test:601")

	// Direction 1: a stale FAILURE must not mark the healthy new feed down.
	stale(false, "write_failed", 7)
	syslogHealth.mu.Lock()
	failing := !syslogHealth.failingSince.IsZero()
	syslogHealth.mu.Unlock()
	if failing {
		t.Error("a retired writer's in-flight failure callback opened an episode on the live feed")
	}
	if row := checkSyslogFeed(); row.Status != diagOK {
		t.Errorf("live healthy feed reported as %q by a retired writer's callback: %+v", row.Status, row)
	}

	// Direction 2: a stale RECOVERY must not clear a real outage on the live
	// feed. This is the direction a one-way fence would miss.
	base := time.Now()
	setSyslogNow(func() time.Time { return base })
	noteSyslogDelivery(fresh, false, "dial_failed", 1)
	syslogHealth.mu.Lock()
	realOutage := !syslogHealth.failingSince.IsZero()
	syslogHealth.mu.Unlock()
	if !realOutage {
		t.Fatal("the live feed's own failure did not open an episode — the gate cannot prove anything")
	}

	stale(true, "", 0)
	syslogHealth.mu.Lock()
	stillFailing := !syslogHealth.failingSince.IsZero()
	syslogHealth.mu.Unlock()
	if !stillFailing {
		t.Error("a retired writer's in-flight recovery callback cleared a REAL outage on the live feed")
	}
}

// TestChaos66_SparseGatewayStillPages — DEFECT gate. `alertNow` used to be
// evaluated only while processing another failed line, so a gateway that loses
// one line and then produces no further syslog traffic — a standby node, a
// quiet night — crossed the threshold with /metrics and /api/diagnostics both
// reporting the episode as degraded while the webhook never fired. Two
// surfaces disagreeing about one condition is the defect CHAOS-61 rule (2)
// names by hand.
//
// The episode timer drives the evaluation instead. The gate invokes what the
// timer invokes, because arming a real 60s timer in a unit test would trade a
// determinism defect for a slow one.
func TestChaos66_SparseGatewayStillPages(t *testing.T) {
	withSyslogTestState(t)
	w, stop := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	stop()

	base := time.Now()
	setSyslogNow(func() time.Time { return base })
	var paged int
	var detail string
	setSyslogAlert(func(d string) { paged++; detail = d })

	// ONE failure, and then the gateway goes completely quiet.
	noteSyslogDelivery(w, false, "write_failed", 1)
	if paged != 0 {
		t.Fatalf("paged %d times immediately — the threshold is a duration", paged)
	}

	// The threshold passes with no further traffic at all.
	setSyslogNow(func() time.Time { return base.Add(syslogDeliveryDegradedAfter + time.Second) })

	// Both surfaces already call this degraded; the page must agree.
	if !syslogState().Degraded {
		t.Fatal("the episode is not reported degraded — the gate is not testing the disagreement")
	}
	if row := checkSyslogFeed(); row.Status != diagFail {
		t.Fatalf("contract row = %q while degraded: %+v", row.Status, row)
	}

	fireArmedEpisodeTimer(t) // only fires if a timer was actually armed
	if paged != 1 {
		t.Fatalf("pages = %d — a quiet gateway crossed the threshold with every read-surface red and no webhook", paged)
	}
	if !strings.Contains(detail, "write_failed") {
		t.Errorf("the timer-driven page did not carry the bounded reason it never observed itself: %q", detail)
	}

	// Still latched: the timer must not re-page an episode it already paged.
	evaluateSyslogEpisode()
	if paged != 1 {
		t.Errorf("pages = %d — the fire-once latch did not hold across timer re-evaluation", paged)
	}
}

// TestChaos66_EpisodeTimerIsDisarmedOnRecovery — CONTROL for the timer. A timer
// that outlived its episode would page for an outage that has ended, which is
// worse than the silence it replaces.
func TestChaos66_EpisodeTimerIsDisarmedOnRecovery(t *testing.T) {
	withSyslogTestState(t)
	w, _ := newLiveCollector(t, "tcp")
	arm(w, "tcp://collector.test:601")
	setSyslogAlert(func(string) {})

	noteSyslogDelivery(w, false, "write_failed", 1)
	syslogHealth.mu.Lock()
	armed := syslogHealth.alertTimer != nil
	syslogHealth.mu.Unlock()
	if !armed {
		t.Fatal("no episode timer was armed on the first failure")
	}

	noteSyslogDelivery(w, true, "", 0) // observed recovery
	syslogHealth.mu.Lock()
	stillArmed := syslogHealth.alertTimer != nil
	syslogHealth.mu.Unlock()
	if stillArmed {
		t.Error("the episode timer survived recovery — it would page for an outage that has ended")
	}

	// And a page evaluated after recovery decides nothing.
	var paged int
	setSyslogAlert(func(string) { paged++ })
	base := time.Now()
	setSyslogNow(func() time.Time { return base.Add(10 * syslogDeliveryDegradedAfter) })
	evaluateSyslogEpisode()
	if paged != 0 {
		t.Errorf("paged %d times for a recovered feed", paged)
	}
}

// fireArmedEpisodeTimer invokes the evaluation ONLY if an episode timer is
// actually armed, so the gate measures whether the timer exists rather than
// calling the evaluation unconditionally.
func fireArmedEpisodeTimer(t *testing.T) {
	t.Helper()
	syslogHealth.mu.Lock()
	armed := syslogHealth.alertTimer != nil
	syslogHealth.mu.Unlock()
	if !armed {
		return
	}
	evaluateSyslogEpisode()
}
