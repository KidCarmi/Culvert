package main

// scan_svc_listener_chaos_test.go — CHAOS-113 gates for the scan sidecar's
// BIND and SERVE loop. Closes the scan-sidecar half of the 2026-10-13
// backlog's L-5.
//
// The finding. `startScanServiceSidecar` bound ONCE and, on failure, logged
// one line and returned a service that would never serve again — no retry,
// ever. If the bind succeeded, `go func(){ if err := svc.Start(); err != nil
// { logger.Printf } }()` logged one line if the serve loop ended and the
// goroutine exited. Measured before the fix: killing the listener under the
// serve loop returned `accept tcp 127.0.0.1:38541: use of closed network
// connection`, the goroutine was gone, the PROCESS was alive, and the
// sidecar's own address was FREE — nothing rebound it, and no counter, gauge,
// health row or alert existed anywhere in the tree to say so.
//
// Why this listener and not the other three. For the admin UI (CHAOS-57),
// SOCKS5 (CHAOS-66/102) and the Control-Plane gRPC listener (CHAOS-71) a dead
// listener costs availability of that surface. For this one it costs a
// SECURITY control on every node pointed at it: `internal/secscan`'s
// remoteScanFail is fail-OPEN (WK-2b), so a sidecar that is not serving means
// the fleet forwards bodies UNSCANNED.
//
// The CONTROLS are load-bearing. The cheapest way to pass "a dead sidecar is
// visible" is to report it down whenever it is not serving, which would page
// on every ordinary redeploy; and the cheapest way to pass "it rebinds" is to
// rebind forever with no ceiling and no stop.
// TestChaos113_ControlRebindingSidecarDoesNotPage,
// TestChaos113_ControlHealthySidecarIsSilent and
// TestChaos113_BackoffLadderIsBoundedAndResets pin all three directions.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// scanSvcChaosSetup resets the global listener health and restores the clock
// and alert seams. Global-test cleanup per the repository's conventions.
func scanSvcChaosSetup(t *testing.T) {
	t.Helper()
	resetScanSvcHealthForTest()
	prevNow, prevAlert := scanSvcHealthNow, fireScanSvcListenerAlert
	t.Cleanup(func() {
		scanSvcHealthNow = prevNow
		fireScanSvcListenerAlert = prevAlert
		resetScanSvcHealthForTest()
	})
}

// captureScanSvcAlerts replaces the alert seam and returns the recorded
// details. The seam, not globalAlertStore: these gates are about WHEN the
// alert fires and how often, not about webhook delivery.
func captureScanSvcAlerts() *scanSvcAlertLog {
	log := &scanSvcAlertLog{}
	fireScanSvcListenerAlert = log.record
	return log
}

type scanSvcAlertLog struct {
	n       atomic.Int64
	details atomic.Value // []string, written under the single supervisor goroutine
}

func (l *scanSvcAlertLog) record(detail string) {
	l.n.Add(1)
	prev, _ := l.details.Load().([]string)
	l.details.Store(append(append([]string{}, prev...), detail))
}

func (l *scanSvcAlertLog) count() int64 { return l.n.Load() }

func (l *scanSvcAlertLog) last() string {
	d, _ := l.details.Load().([]string)
	if len(d) == 0 {
		return ""
	}
	return d[len(d)-1]
}

// superviseForTest runs the real production supervisor for the life of the
// test and guarantees it stops, so a gate can never leak a rebind loop into
// whichever test runs next.
func superviseForTest(t *testing.T, addr string) *ScanService {
	t.Helper()
	svc := NewScanService(addr)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		superviseScanSvcListener(ctx, svc)
	}()
	t.Cleanup(func() {
		cancel()
		_ = svc.Shutdown(context.Background())
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("supervisor did not stop")
		}
	})
	return svc
}

// ── Defect gates ─────────────────────────────────────────────────────────────

// TestChaos113_ServeDeathRebinds is the defect gate for the SERVE half. A
// listener that dies under the serve loop must come back on the same address.
func TestChaos113_ServeDeathRebinds(t *testing.T) {
	scanSvcChaosSetup(t)
	port, release := occupyPort(t)
	release() // the address was bindable a moment ago
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	svc := superviseForTest(t, addr)
	waitForScanSvc(t, addr)
	if got := scanSvcListenerStatus(); got != "ready" {
		t.Fatalf("status %q before the fault, want ready", got)
	}

	// Kill the socket under the serve loop: the shape a lost socket, an
	// interface teardown or descriptor exhaustion takes.
	svc.mu.Lock()
	ln := svc.listener
	svc.mu.Unlock()
	_ = ln.Close()

	// The pre-fix shape left the address free forever. The supervisor must
	// serve it again — one backoff step (1 s ±25%) plus scheduling.
	waitForScanSvcWithin(t, addr, 15*time.Second)

	if snap := scanSvcListenerState(); snap.ServeExits < 1 {
		t.Errorf("serve_exits = %d after a serve-loop death, want ≥ 1", snap.ServeExits)
	}
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_up 1") {
		t.Error("a recovered sidecar does not export listener_up 1")
	}
}

// TestChaos113_NeverBoundIsVisibleAndAlerts is the defect gate for the BIND
// half, and the boot-time case: an address that never binds used to be one log
// line and then permanent silence on every surface the product exposes.
func TestChaos113_NeverBoundIsVisibleAndAlerts(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	port, release := occupyPort(t) // held for the whole gate
	defer release()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// Age the episode past the unavailability threshold without sleeping it.
	start := time.Now()
	var advanced atomic.Bool
	scanSvcHealthNow = func() time.Time {
		if advanced.Load() {
			return start.Add(scanSvcUnavailableAfter + 10*time.Second)
		}
		return start
	}

	superviseForTest(t, addr)
	waitForScanSvcCond(t, 10*time.Second, func() bool {
		return scanSvcListenerState().BindFailures >= 1
	})

	// Inside the threshold: retrying, NOT down. (Control direction.)
	if row := checkScanSvcListener(); row.Status != diagFail {
		// A never-bound sidecar is a FAIL row from the first failure: unlike a
		// redeploy, there is no previous socket that was serving.
		t.Errorf("never-bound row status = %q, want %q (%s)", row.Status, diagFail, row.Message)
	}

	advanced.Store(true)
	waitForScanSvcCond(t, 15*time.Second, func() bool { return alerts.count() >= 1 })

	if got := alerts.last(); got != "port_in_use" {
		t.Errorf("alert detail = %q, want the bounded class %q", got, "port_in_use")
	}
	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_scan_svc_listener_up 0",
		"culvert_scan_svc_listener_down 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q for a sidecar that never bound", want)
		}
	}
	if row := checkScanSvcListener(); !strings.Contains(row.Message, "UNSCANNED") {
		t.Errorf("the contract row does not say what a down sidecar COSTS: %q", row.Message)
	}
}

// TestChaos113_DownAlertFiresOncePerEpisode pins the rate contract. The
// supervisor retries for as long as the fault lasts; an alert per retry would
// fan out into the 500-entry retry queue where a scanner fault evicts real
// threat alerts (the defect remoteScanFail's doc records).
func TestChaos113_DownAlertFiresOncePerEpisode(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured(":8484")

	start := time.Now()
	for i := 0; i < 20; i++ {
		failingFor := noteScanSvcBindFailure("port_in_use", time.Second,
			start.Add(time.Duration(i)*scanSvcUnavailableAfter))
		maybeAlertScanSvcDown("port_in_use", failingFor)
	}
	if got := alerts.count(); got != 1 {
		t.Errorf("20 failed binds in one episode fired %d alerts, want 1", got)
	}

	// A recovery closes the episode, so the NEXT outage is allowed to alert —
	// once it has itself aged past the threshold. The first failure of the new
	// episode must NOT alert, or a flapping listener pages on every flap.
	noteScanSvcBound()
	second := start.Add(100 * scanSvcUnavailableAfter)
	maybeAlertScanSvcDown("port_in_use", noteScanSvcBindFailure("port_in_use", time.Second, second))
	if got := alerts.count(); got != 1 {
		t.Errorf("the first failure of a new episode alerted immediately (%d total) — a flap pages", got)
	}
	maybeAlertScanSvcDown("port_in_use",
		noteScanSvcBindFailure("port_in_use", time.Second, second.Add(scanSvcUnavailableAfter+time.Second)))
	if got := alerts.count(); got != 2 {
		t.Errorf("a second sustained episode after recovery fired %d alerts total, want 2", got)
	}
}

// ── Controls ─────────────────────────────────────────────────────────────────

// TestChaos113_ControlRebindingSidecarDoesNotPage is the control for the
// gauge. The documented paging rule for culvert_scan_svc_listener_up is
// `== 0`; an ordinary redeploy in which a predecessor still holds the port
// must not trip it.
func TestChaos113_ControlRebindingSidecarDoesNotPage(t *testing.T) {
	scanSvcChaosSetup(t)
	noteScanSvcConfigured(":8484")
	start := time.Now()
	scanSvcHealthNow = func() time.Time { return start.Add(time.Second) }

	// A sidecar that HAS served and is now rebinding, inside the threshold.
	noteScanSvcBound()
	noteScanSvcServeEnded("listen_failed", start)

	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_scan_svc_listener_up 1") {
		t.Error("a sidecar one second into a rebind already exports listener_up 0 — this pages on every redeploy")
	}
	if !strings.Contains(body, "culvert_scan_svc_listener_down 0") {
		t.Error("a sidecar one second into a rebind is already reported down")
	}
	if row := checkScanSvcListener(); row.Status != diagWarn {
		t.Errorf("rebinding row status = %q, want %q", row.Status, diagWarn)
	}

	// Sustained is a different answer.
	scanSvcHealthNow = func() time.Time { return start.Add(scanSvcUnavailableAfter + time.Second) }
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_up 0") {
		t.Error("a sidecar down past the threshold does not export listener_up 0")
	}
	if row := checkScanSvcListener(); row.Status != diagFail {
		t.Errorf("sustained-down row status = %q, want %q", row.Status, diagFail)
	}
}

// TestChaos113_ControlHealthySidecarIsSilent is the other control: nothing
// about a working sidecar may look like a fault, and a sidecar that was never
// configured must add no row and no metric at all.
func TestChaos113_ControlHealthySidecarIsSilent(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()

	if row := checkScanSvcListener(); row.Status != diagOK || !strings.Contains(row.Message, "not configured") {
		t.Errorf("unconfigured sidecar row = %+v, want an ok/not-configured row", row)
	}
	if strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_up") {
		t.Error("a node that never ran a sidecar exports the gauge — up 0 there is indistinguishable from a dead one")
	}

	svc := superviseForTest(t, "127.0.0.1:0")
	// The supervisor binds on its own goroutine, so Addr() is the CONFIGURED
	// address until it lands. Wait for the bind, then probe the real port.
	waitForScanSvcCond(t, 10*time.Second, func() bool { return scanSvcListenerState().Bound })
	waitForScanSvc(t, svc.Addr())
	if row := checkScanSvcListener(); row.Status != diagOK {
		t.Errorf("healthy sidecar row status = %q (%s), want %q", row.Status, row.Message, diagOK)
	}
	if got := alerts.count(); got != 0 {
		t.Errorf("a healthy sidecar fired %d alerts", got)
	}
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_up 1") {
		t.Error("a healthy sidecar does not export listener_up 1")
	}
}

// TestChaos113_GracefulStopIsNotAnOutage is the shutdown control. An operator
// stopping the process must not page anyone, and the row must say so rather
// than reporting a fail on every clean stop.
func TestChaos113_GracefulStopIsNotAnOutage(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:0")

	svc := NewScanService("127.0.0.1:0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	noteScanSvcBound()
	if err := svc.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if got := scanSvcListenerStatus(); got != "stopped" {
		t.Errorf("status after a graceful stop = %q, want stopped", got)
	}
	if row := checkScanSvcListener(); row.Status != diagOK {
		t.Errorf("graceful-stop row status = %q (%s), want %q", row.Status, row.Message, diagOK)
	}
	if got := alerts.count(); got != 0 {
		t.Errorf("a graceful stop fired %d alerts", got)
	}
}

// ── Policy (pure) ────────────────────────────────────────────────────────────

// TestChaos113_BackoffLadderIsBoundedAndResets pins the retry policy without a
// clock, with a negative control against the two shapes that look right and
// are not: a ladder with no ceiling, and one that resets on every attempt.
func TestChaos113_BackoffLadderIsBoundedAndResets(t *testing.T) {
	cur := time.Duration(0)
	var seen []time.Duration
	for i := 0; i < 12; i++ {
		cur = nextScanSvcBindBackoff(cur)
		seen = append(seen, cur)
	}
	if seen[0] != scanSvcBindBackoffInitial {
		t.Errorf("first backoff = %s, want %s", seen[0], scanSvcBindBackoffInitial)
	}
	for i, d := range seen {
		if d > scanSvcBindBackoffMax {
			t.Fatalf("attempt %d escalated to %s, past the %s ceiling", i+1, d, scanSvcBindBackoffMax)
		}
	}
	if seen[len(seen)-1] != scanSvcBindBackoffMax {
		t.Errorf("the ladder never reaches its ceiling: last = %s", seen[len(seen)-1])
	}

	// A serve that proved stable resets the ladder; one that died immediately
	// must NOT, or a listener that dies after every bind hammers at 1 s forever.
	if got := scanSvcBackoffAfterServe(scanSvcBindBackoffMax, scanSvcServeStableAfter); got != 0 {
		t.Errorf("a stable serve left the backoff at %s, want a reset", got)
	}
	if got := scanSvcBackoffAfterServe(scanSvcBindBackoffMax, time.Millisecond); got != scanSvcBindBackoffMax {
		t.Errorf("a serve that died immediately reset the backoff to %s", got)
	}

	// Jitter must spread but never collapse to zero (a zero wait is a spin).
	lo, hi := 4*time.Second, 4*time.Second
	for i := 0; i < 2000; i++ {
		got := jitterScanSvcBackoff(4 * time.Second)
		if got < 3*time.Second || got >= 5*time.Second {
			t.Fatalf("jitter(4s) = %s, outside the ±25%% band [3s,5s)", got)
		}
		lo, hi = min(lo, got), max(hi, got)
	}
	// A "jitter" that always returns d is in band and spreads nothing — the
	// negative control for the shape that looks right and keeps a fleet in
	// phase. 2000 draws over a 2 s span make a narrower spread than 1 s
	// astronomically unlikely.
	if hi-lo < time.Second {
		t.Errorf("jitter spread only %s over 2000 draws — it is not spreading the fleet", hi-lo)
	}
	if got := jitterScanSvcBackoff(0); got != 0 {
		t.Errorf("jitter(0) = %s, want 0", got)
	}
}

// TestChaos113_BindErrorClassesAreBounded pins the alert-detail vocabulary.
// The raw bind error embeds the listen address, and the dedup key is
// "event:detail" — a per-attempt address there is a key that cannot dedup.
func TestChaos113_BindErrorClassesAreBounded(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{&net.OpError{Op: "listen", Err: syscall.EADDRINUSE}, "port_in_use"},
		{&net.OpError{Op: "listen", Err: syscall.EACCES}, "permission_denied"},
		{&net.OpError{Op: "listen", Err: syscall.EPERM}, "permission_denied"},
		{&net.OpError{Op: "listen", Err: syscall.EADDRNOTAVAIL}, "address_unavailable"},
		{&net.OpError{Op: "listen", Err: syscall.EMFILE}, "descriptors_exhausted"},
		{&net.OpError{Op: "listen", Err: syscall.ENFILE}, "descriptors_exhausted"},
		// The branch both siblings had to narrow: *net.OpError satisfies
		// net.Error unconditionally, so an unqualified errors.As would call
		// this a network error and send the operator to the wrong subsystem.
		{&net.OpError{Op: "listen", Err: syscall.EINVAL}, "listen_failed"},
		{errors.New("something else"), "listen_failed"},
		{http.ErrServerClosed, "listen_failed"},
	} {
		if got := classifyScanSvcBindError(tc.err); got != tc.want {
			t.Errorf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// ── Small helpers ────────────────────────────────────────────────────────────

func waitForScanSvcWithin(t *testing.T, addr string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if code, err := scanSvcProbe(t, addr); err == nil && code == http.StatusOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sidecar never came back on %s within %s", addr, d)
}

func waitForScanSvcCond(t *testing.T, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}
