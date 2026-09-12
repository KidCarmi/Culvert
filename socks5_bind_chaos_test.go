package main

// socks5_bind_chaos_test.go — CHAOS-66 gates for the SOCKS5 listener's BIND.
//
// The finding: `startSOCKS5` used to `logFatalf` on a bind failure, which
// os.Exit(1)s the process, from `initSOCKS5` — which main.go runs BEFORE the
// admin UI and the proxy listener exist. So an occupied SOCKS5 port took down
// the whole appliance. See socks5_bind.go for the reproduction against the real
// binary.
//
// On the defect gates here, "verified failing against the pre-fix shape" has a
// stronger meaning than usual and it is worth stating once: the pre-fix shape
// calls os.Exit(1), which kills the TEST BINARY mid-run and takes the whole
// package with it. The defect therefore cannot be reintroduced and kept green —
// the same property CHAOS-57's admin-UI gates rely on (§33).
//
// The two CONTROLS matter as much as the defect gates. The cheapest way to pass
// every "it did not exit" assertion is to delete the fatal and report the
// listener healthy, which would be strictly worse than the defect: a SOCKS5
// service that is silently absent forever, on a node whose every probe reads
// green. TestChaos66_ControlUnboundListenerIsNeverReportedReady and
// TestChaos66_ControlHealthyBindIsSilent pin both directions.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// These gates reuse occupyPort from admin_ui_listener_chaos_test.go rather
// than defining a second one: it holds 127.0.0.1:<port>, and a loopback-held
// port makes the supervisor's wildcard `:<port>` bind fail with EADDRINUSE —
// the exact production trigger (a predecessor container still draining, a host
// service, a second Culvert). Verified empirically, not assumed.

// freeSOCKS5Port returns a port that was bindable a moment ago. Inherently racy
// in the abstract; in practice the window is microseconds, and every gate that
// depends on the port being FREE re-checks by observing the supervisor actually
// bind it.
func freeSOCKS5Port(t *testing.T) int {
	t.Helper()
	port, release := occupyPort(t)
	release()
	return port
}

// startSupervisedSOCKS5 starts the real production entry point and guarantees
// it is stopped when the test ends, so a gate can never leak a rebind loop into
// the next test.
func startSupervisedSOCKS5(t *testing.T, port int) *socks5Supervisor {
	t.Helper()
	srv := startSOCKS5(port)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})
	return srv
}

// waitFor polls cond until it holds or the deadline passes.
func waitForSOCKS5(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

// assertPortHeld proves something is really listening on port, by attempting
// the same bind the supervisor made and requiring the kernel to refuse it.
//
// Deliberately NOT a dial. An accepted connection spawns a DETACHED
// handleSOCKS5 goroutine that reads the global stores (bl, ipf, cfg), and a
// handler outliving its test races the next test's setupProxyTest, which
// rewrites those same globals — a real `-race` failure, observed while writing
// these gates. socks5_test.go's startSOCKS5Listener documents that exact hazard
// and drains its handlers to avoid it, but the production supervisor detaches
// its sessions by design (the PX-8 residual) and offers no join to wait on. So
// these gates prove the port is HELD rather than opening a session on it; that
// a bound listener ACCEPTS is what CHAOS-54's 18 accept-loop gates are for, and
// the real-binary run in §36 shows a served request after a rebind.
func assertPortHeld(t *testing.T, port int) {
	t.Helper()
	ln, err := ctxListen(fmt.Sprintf(":%d", port))
	if err == nil {
		_ = ln.Close()
		t.Fatalf("port %d is free: the listener recorded as bound is not actually listening", port)
	}
}

// bindErr builds a bind error in the exact shape the net package produces:
// *net.OpError wrapping *os.SyscallError wrapping a syscall.Errno. Matching the
// real wrapping matters — classifySOCKS5BindError uses errors.As, and a gate
// that handed it a bare Errno would not prove it sees through the wrapper the
// kernel path actually produces.
func bindErr(errno syscall.Errno) error {
	return &net.OpError{
		Op:  "listen",
		Net: "tcp",
		Err: os.NewSyscallError("bind", errno),
	}
}

// ── The finding: a bind failure used to kill the appliance ───────────────────

// TestChaos66_BindFailureIsNotFatal is the headline gate.
//
// Reaching the end of this function at all is the assertion: against the
// pre-fix shape startSOCKS5 calls logFatalf → os.Exit(1) and the test binary
// dies here, failing this and every other test in the package.
func TestChaos66_BindFailureIsNotFatal(t *testing.T) {
	socks5ChaosSetup(t)

	port, release := occupyPort(t)
	defer release()

	srv := startSupervisedSOCKS5(t, port)
	if srv == nil {
		t.Fatal("startSOCKS5 returned no handle for an unbindable port")
	}

	waitForSOCKS5(t, 5*time.Second, "a recorded bind failure", func() bool {
		return socks5ListenerState().BindTotal > 0
	})

	snap := socks5ListenerState()
	if !snap.BindFailing {
		t.Error("an unbindable listener is not recorded as failing to bind")
	}
	if snap.BindLastReason != "port_in_use" {
		t.Errorf("bind reason = %q, want %q", snap.BindLastReason, "port_in_use")
	}
	if snap.EverBound {
		t.Error("a listener that never bound is recorded as having bound")
	}
}

// TestChaos66_ConfiguredIsRecordedBeforeTheFirstBind pins the observability
// half of the fix.
//
// noteSOCKS5Configured gates EVERY SOCKS5 surface. Called after a successful
// bind — where it used to sit — a listener that has never come up reports
// "SOCKS5 listener not configured", which is byte-identical to the ordinary
// appliance that never asked for SOCKS5. That is the wrong answer on precisely
// the node where an operator is trying to find out why SOCKS5 is unreachable.
func TestChaos66_ConfiguredIsRecordedBeforeTheFirstBind(t *testing.T) {
	socks5ChaosSetup(t)

	port, release := occupyPort(t)
	defer release()

	startSupervisedSOCKS5(t, port)

	waitForSOCKS5(t, 5*time.Second, "a recorded bind failure", func() bool {
		return socks5ListenerState().BindTotal > 0
	})

	if !socks5ListenerState().Configured {
		t.Fatal("a listener that cannot bind reports the SOCKS5 feature as not configured")
	}
	if got := checkSOCKS5Listener(); strings.Contains(got.Message, "not configured") {
		t.Errorf("contract row reports an unbindable listener as absent: %q", got.Message)
	}
	checks := map[string]*readinessCheck{}
	appendSOCKS5ReadinessCheck(checks)
	if _, ok := checks["socks5"]; !ok {
		t.Error("/readyz omits the socks5 row on a node whose SOCKS5 listener cannot bind")
	}
}

// TestChaos66_StartSOCKS5ResolvesItsFirstBindBeforeReturning closes the window
// Codex review found on PR #1376.
//
// `noteSOCKS5Configured` runs before the bind, because it gates every SOCKS5
// surface and a listener that has never come up must not report as "not
// configured". But if startSOCKS5 returned while the supervisor goroutine had
// not yet run, `configured` would be true with no failure recorded and nothing
// bound — and every surface would then describe a listener that does not exist:
// `/healthz` ready, the /readyz row ok, the contract row "accepting
// connections", `culvert_socks5_listener_up` 1. That is the same class of lie
// this whole change exists to remove, so the fix is to not have the window
// rather than to report it accurately.
//
// Both arms assert with NO waiting: whatever startSOCKS5 returns, the state is
// already truthful. The bind case is the one that would regress silently — a
// listener that binds fast enough in practice hides the defect on most runs.
func TestChaos66_StartSOCKS5ResolvesItsFirstBindBeforeReturning(t *testing.T) {
	t.Run("bound", func(t *testing.T) {
		socks5ChaosSetup(t)
		port := freeSOCKS5Port(t)
		startSupervisedSOCKS5(t, port)

		snap := socks5ListenerState()
		if snap.Binds == 0 || !snap.EverBound {
			t.Fatalf("startSOCKS5 returned before its first bind resolved: %+v", snap)
		}
		if got := socks5ListenerStatus(); got != "ready" {
			t.Errorf("/healthz socks5 = %q immediately after startSOCKS5, want \"ready\"", got)
		}
		assertPortHeld(t, port)
	})

	t.Run("unbindable", func(t *testing.T) {
		socks5ChaosSetup(t)
		port, release := occupyPort(t)
		defer release()
		startSupervisedSOCKS5(t, port)

		snap := socks5ListenerState()
		if snap.BindTotal == 0 {
			t.Fatal("startSOCKS5 returned before its first bind attempt was recorded — " +
				"every SOCKS5 surface would report a listener that does not exist")
		}
		if got := socks5ListenerStatus(); got == "ready" {
			t.Error("/healthz socks5 reports \"ready\" immediately after a failed first bind")
		}
		if body := renderMetrics(t); !strings.Contains(body, "culvert_socks5_bind_failures_total 1") {
			t.Error("the first failed bind is not reflected in /metrics when startSOCKS5 returns")
		}
	})
}

// TestChaos66_ListenerRebindsOnceThePortIsFree is the recovery gate: the whole
// point of retrying is that the operator does not have to restart a gateway
// carrying production traffic to get SOCKS5 back.
func TestChaos66_ListenerRebindsOnceThePortIsFree(t *testing.T) {
	socks5ChaosSetup(t)

	port, release := occupyPort(t)

	srv := startSupervisedSOCKS5(t, port)
	waitForSOCKS5(t, 5*time.Second, "a recorded bind failure", func() bool {
		return socks5ListenerState().BindTotal > 0
	})

	// Release the port. No restart, no operator action.
	release()

	waitForSOCKS5(t, 20*time.Second, "the listener to rebind", func() bool {
		return socks5ListenerState().Binds > 0
	})

	snap := socks5ListenerState()
	if snap.BindFailing {
		t.Error("a bound listener is still recorded as failing to bind")
	}
	if !snap.EverBound {
		t.Error("a bound listener is not recorded as having bound")
	}
	if srv.Addr() == nil {
		t.Error("a bound listener reports no address")
	}
	if socks5ListenerStatus() != "ready" {
		t.Errorf("/healthz socks5 = %q after recovery, want \"ready\"", socks5ListenerStatus())
	}

	// And it really holds the socket, not merely a record saying so.
	assertPortHeld(t, port)
}

// ── Rate, duration and evidence discipline ───────────────────────────────────

// TestChaos66_UnavailabilityIsADurationNotACount pins the paging threshold.
//
// A redeploy in which a predecessor still holds the port produces a burst of
// failures within seconds. Paging on a COUNT would page on every ordinary
// restart; paging on sustained DURATION does not.
func TestChaos66_UnavailabilityIsADurationNotACount(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	for i := range 50 {
		noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(time.Duration(i)*100*time.Millisecond))
	}
	if snap := socks5ListenerState(); snap.BindUnavailable {
		t.Error("a 5s burst of bind failures was reported as unavailable")
	}
	if len(*fired) != 0 {
		t.Errorf("a transient bind burst paged %d time(s)", len(*fired))
	}

	noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(socks5BindUnavailableAfter+time.Second))
	if snap := socks5ListenerState(); !snap.BindUnavailable {
		t.Error("a sustained bind outage was not reported as unavailable")
	}
	if len(*fired) != 1 {
		t.Errorf("sustained bind outage fired %d alerts, want 1", len(*fired))
	}
}

// TestChaos66_BindAlertFiresOncePerEpisode pins the fire-once latch and, just
// as importantly, that a SECOND incident pages again — a latch that never
// clears silences every future outage.
func TestChaos66_BindAlertFiresOncePerEpisode(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	// The episode's clock starts at its FIRST failure, so the run has to open
	// at `start` and then cross the threshold — driving every failure from
	// past the threshold would never accumulate any elapsed time at all.
	start := time.Now()
	for i := range 10 {
		noteSOCKS5BindFailure("port_in_use", time.Second,
			start.Add(time.Duration(i)*10*time.Second))
	}
	if len(*fired) != 1 {
		t.Fatalf("one episode fired %d alerts, want 1", len(*fired))
	}

	// Recovery, then a second outage.
	noteSOCKS5Bound()
	later := start.Add(time.Hour)
	for i := range 10 {
		noteSOCKS5BindFailure("port_in_use", time.Second,
			later.Add(time.Duration(i)*10*time.Second))
	}
	if len(*fired) != 2 {
		t.Errorf("a second episode fired a total of %d alerts, want 2", len(*fired))
	}
}

// TestChaos66_BindAlertDetailIsBoundedForDedup pins the WK-12/RS-5 rule.
//
// alerts.Store.Dispatch dedups on `event + ":" + Detail`. A detail carrying the
// raw error would embed the listener address and mint one dedup key per
// failure, which the 30 s window cannot suppress by construction — and the
// fan-out lands in the 500-entry retry queue where it evicts real threat
// alerts.
func TestChaos66_BindAlertDetailIsBoundedForDedup(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5BindFailure("port_in_use", time.Second, start)
	noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(socks5BindUnavailableAfter+time.Second))
	if len(*fired) != 1 {
		t.Fatalf("expected exactly one alert, got %d", len(*fired))
	}
	first := (*fired)[0]

	for _, leak := range []string{"address already in use", "0.0.0.0", "127.0.0.1", "listen tcp"} {
		if strings.Contains(first, leak) {
			t.Errorf("alert detail leaks raw error material %q: %s", leak, first)
		}
	}
	if !strings.Contains(first, "port_in_use") {
		t.Errorf("alert detail does not name the bounded reason class: %s", first)
	}

	// The same reason class must produce a byte-identical detail, or the dedup
	// key is unstable no matter how bounded each individual string looks.
	resetSOCKS5HealthForTest()
	noteSOCKS5Configured(1080)
	second := time.Now()
	noteSOCKS5BindFailure("port_in_use", 7*time.Second, second)
	noteSOCKS5BindFailure("port_in_use", 29*time.Second, second.Add(socks5BindUnavailableAfter+2*time.Second))
	if len(*fired) != 2 {
		t.Fatalf("expected a second alert, got %d total", len(*fired))
	}
	if (*fired)[1] != first {
		t.Errorf("same reason class produced different alert details:\n  %q\n  %q", first, (*fired)[1])
	}
}

// TestChaos66_BindFailureLoggingIsRateLimited pins that the mitigation for a
// crash loop is not itself a log flood: onset immediately, then at most one
// line per interval.
func TestChaos66_BindFailureLoggingIsRateLimited(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	if !noteSOCKS5BindFailure("port_in_use", time.Second, start) {
		t.Error("the first bind failure of an episode was not logged")
	}
	for i := 1; i < 20; i++ {
		if noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("failure %d inside the rate window was logged", i)
		}
	}
	if !noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(socks5BindLogInterval+time.Second)) {
		t.Error("a failure past the rate window was not logged")
	}
}

// TestChaos66_RecoveryRequiresAnObservedBind is the house rule from
// storage_health.go / ca_health.go: a loop that stops failing because it stopped
// attempting looks identical to a bound one, so only evidence clears the state.
func TestChaos66_RecoveryRequiresAnObservedBind(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5BindFailure("port_in_use", time.Second, start)
	for i := 1; i < 6; i++ {
		noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(time.Duration(i)*time.Second))
	}

	// Time passing is not evidence.
	if snap := socks5ListenerState(); !snap.BindFailing {
		t.Fatal("the bind-failure episode cleared without an observed bind")
	}

	suppressed, recovered := noteSOCKS5Bound()
	if !recovered {
		t.Error("an observed bind after failures did not report a recovery")
	}
	if suppressed != 5 {
		t.Errorf("recovery reported %d suppressed lines, want 5", suppressed)
	}
	snap := socks5ListenerState()
	if snap.BindFailing || snap.BindUnavailable {
		t.Error("an observed bind did not clear the failure episode")
	}
	if snap.BindTotal != 6 {
		t.Errorf("cumulative bind failures = %d, want 6 (history must survive recovery)", snap.BindTotal)
	}

	// A bind with no preceding failure is not a "recovery" and must not emit a
	// recovery log line.
	if _, recovered := noteSOCKS5Bound(); recovered {
		t.Error("a bind with no preceding failure was reported as a recovery")
	}
}

// TestChaos66_BindReasonClassesAreMapped pins the bounded vocabulary, matched
// through the real net wrapper rather than on a bare errno.
func TestChaos66_BindReasonClassesAreMapped(t *testing.T) {
	cases := []struct {
		errno syscall.Errno
		want  string
	}{
		{syscall.EADDRINUSE, "port_in_use"},
		{syscall.EACCES, "permission_denied"},
		{syscall.EPERM, "permission_denied"},
		{syscall.EADDRNOTAVAIL, "address_unavailable"},
		{syscall.EMFILE, "descriptors_exhausted"},
		{syscall.ENFILE, "descriptors_exhausted"},
		{syscall.EINVAL, "listen_failed"},
	}
	for _, tc := range cases {
		if got := classifySOCKS5BindError(bindErr(tc.errno)); got != tc.want {
			t.Errorf("classify(%v) = %q, want %q", tc.errno, got, tc.want)
		}
	}
	if got := classifySOCKS5BindError(nil); got != "none" {
		t.Errorf("classify(nil) = %q, want %q", got, "none")
	}
	if got := classifySOCKS5BindError(fmt.Errorf("something unrecognised")); got != "listen_failed" {
		t.Errorf("classify(unknown) = %q, want %q", got, "listen_failed")
	}
}

// TestChaos66_UnrecognisedErrnoIsNotCalledANetworkError pins the classifier
// narrowing this sweep made in BOTH listeners.
//
// Every bind failure arrives wrapped in *net.OpError, which satisfies net.Error
// unconditionally, so an unqualified `errors.As(err, &ne) → "network_error"`
// branch swallowed every unrecognised errno into a class naming the wrong
// subsystem — and made "listen_failed" unreachable for any error the net
// package produced. The admin UI's gate only ever passed a bare errors.New,
// the one shape that does reach "listen_failed", so the branch looked correct.
//
// The premise is asserted first: if a future Go release changes either fact,
// this gate should say which, not merely fail.
func TestChaos66_UnrecognisedErrnoIsNotCalledANetworkError(t *testing.T) {
	err := bindErr(syscall.EINVAL)

	var ne net.Error
	if !errors.As(err, &ne) {
		t.Fatal("premise changed: *net.OpError no longer satisfies net.Error")
	}
	if ne.Timeout() {
		t.Fatal("premise changed: a bind EINVAL now reports Timeout() true")
	}

	if got := classifySOCKS5BindError(err); got != "listen_failed" {
		t.Errorf("SOCKS5 classify(EINVAL) = %q, want %q", got, "listen_failed")
	}
	if got := classifyAdminUIListenError(err); got != "listen_failed" {
		t.Errorf("admin UI classify(EINVAL) = %q, want %q", got, "listen_failed")
	}
}

// TestChaos66_BindBackoffScheduleMatchesTheDocumentedShape pins the constants
// the rate bound is derived from.
func TestChaos66_BindBackoffScheduleMatchesTheDocumentedShape(t *testing.T) {
	if got := nextSOCKS5BindBackoff(0); got != socks5BindBackoffInitial {
		t.Errorf("first backoff = %s, want %s", got, socks5BindBackoffInitial)
	}
	d := socks5BindBackoffInitial
	for range 20 {
		d = nextSOCKS5BindBackoff(d)
		if d > socks5BindBackoffMax {
			t.Fatalf("backoff %s exceeded the ceiling %s", d, socks5BindBackoffMax)
		}
	}
	if d != socks5BindBackoffMax {
		t.Errorf("backoff settled at %s, want the ceiling %s", d, socks5BindBackoffMax)
	}
	if socks5BindBackoffInitial <= 0 || socks5BindBackoffMax <= socks5BindBackoffInitial {
		t.Error("the bind backoff schedule is not a widening one")
	}
}

// ── Shutdown ─────────────────────────────────────────────────────────────────

// TestChaos66_StopIsPromptDuringBindBackoff pins that the shutdown sequence's
// 2 s `socks5-listener-stop` budget is never spent waiting out a rebind sleep.
//
// Many trials, on the TestChaos54_StopIsPromptDuringAcceptBackoff precedent:
// where Stop lands inside a sleep is uniform, so a single trial passes a broken
// build most of the time.
func TestChaos66_StopIsPromptDuringBindBackoff(t *testing.T) {
	for trial := range 5 {
		socks5ChaosSetup(t)
		port, release := occupyPort(t)

		srv := startSOCKS5(port)
		waitForSOCKS5(t, 5*time.Second, "a recorded bind failure", func() bool {
			return socks5ListenerState().BindTotal > 0
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		began := time.Now()
		err := srv.Stop(ctx)
		took := time.Since(began)
		cancel()
		release()

		if err != nil {
			t.Fatalf("trial %d: Stop: %v", trial, err)
		}
		if took > 500*time.Millisecond {
			t.Fatalf("trial %d: Stop took %s during a bind backoff of at least %s — the sleep is not interruptible",
				trial, took, socks5BindBackoffInitial)
		}
	}
}

// TestChaos66_StopIsIdempotentAndNilSafe pins the contract the shutdown hook
// was written against and preserves socks5Server.Stop's own guarantees.
func TestChaos66_StopIsIdempotentAndNilSafe(t *testing.T) {
	socks5ChaosSetup(t)

	var nilSrv *socks5Supervisor
	if err := nilSrv.Stop(context.Background()); err != nil {
		t.Errorf("nil supervisor Stop = %v, want nil", err)
	}
	if nilSrv.Addr() != nil {
		t.Error("nil supervisor reports an address")
	}

	port := freeSOCKS5Port(t)
	srv := startSOCKS5(port)
	waitForSOCKS5(t, 5*time.Second, "the listener to bind", func() bool {
		return socks5ListenerState().Binds > 0
	})

	for i := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := srv.Stop(ctx); err != nil {
			t.Errorf("Stop call %d = %v, want nil", i, err)
		}
		cancel()
	}
}

// TestChaos66_AdoptRefusesAListenerBoundAfterStop pins the adopt/Stop race
// DETERMINISTICALLY.
//
// The window is real: `go s.run()` can be scheduled onto another P and be
// inside lc.Listen while the caller is already in Stop. If adopt published that
// listener anyway, the loop would serve on a socket Stop has already stopped
// waiting for — Stop blocks until its context expires, the listener leaks, and
// the port is held against the successor process.
//
// It is pinned here as a unit rather than by racing the real loop because the
// window is microseconds wide and cannot be scheduled from a test: an
// end-to-end version passes against the broken build most of the time, and a
// gate that can flake gets muted (the house rule from
// TestBenchGate_DistinctIPsDoNotShareALock). The invariant adopt encodes —
// Stop sets `stopped` under the same lock BEFORE it reads `cur` — is what makes
// the two sides mutually exclusive, and that is exactly what this asserts.
func TestChaos66_AdoptRefusesAListenerBoundAfterStop(t *testing.T) {
	socks5ChaosSetup(t)

	s := &socks5Supervisor{
		port:     0,
		stopping: make(chan struct{}),
		done:     make(chan struct{}),
	}
	close(s.done) // stand in for a loop that has already exited

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	if s.adopt(newSOCKS5Server(ln)) {
		t.Error("adopt published a listener bound after Stop — it would serve on a socket nobody waits for")
	}
	if s.Addr() != nil {
		t.Error("a stopped supervisor reports a current listener address")
	}
}

// TestChaos66_StopDuringStartupLeavesNothingServing is the end-to-end companion
// to the unit gate above: whichever side wins, the port must be free again
// afterwards. It exercises the ordinary path (Stop before the first bind
// completes), not the microsecond race, which is why the invariant itself is
// pinned separately.
func TestChaos66_StopDuringStartupLeavesNothingServing(t *testing.T) {
	for trial := range 10 {
		socks5ChaosSetup(t)
		port := freeSOCKS5Port(t)

		srv := startSOCKS5(port)
		// No wait: Stop deliberately races the very first bind.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := srv.Stop(ctx); err != nil {
			cancel()
			t.Fatalf("trial %d: Stop: %v", trial, err)
		}
		cancel()

		// The port must be free again: nothing may still be listening.
		ln, err := ctxListen(fmt.Sprintf(":%d", port))
		if err != nil {
			t.Fatalf("trial %d: port %d still held after Stop — a bind raced Stop and was left serving: %v",
				trial, port, err)
		}
		_ = ln.Close()
	}
}

// TestChaos66_CleanStopIsNotReportedAsAFault pins that a node on its way out
// never pages. A shutdown that alerted would make every rolling upgrade a page.
func TestChaos66_CleanStopIsNotReportedAsAFault(t *testing.T) {
	fired := socks5ChaosSetup(t)

	port := freeSOCKS5Port(t)
	srv := startSOCKS5(port)
	waitForSOCKS5(t, 5*time.Second, "the listener to bind", func() bool {
		return socks5ListenerState().Binds > 0
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	snap := socks5ListenerState()
	if !snap.Stopped {
		t.Error("a clean Stop was not recorded as stopped")
	}
	if snap.Down {
		t.Errorf("a clean Stop recorded the listener as down (%q)", snap.DownReason)
	}
	if snap.BindFailing {
		t.Error("a clean Stop recorded a bind failure")
	}
	if len(*fired) != 0 {
		t.Errorf("a clean Stop fired %d alerts", len(*fired))
	}
}

// ── Interaction with the CHAOS-54 accept plane ───────────────────────────────

// TestChaos66_AnObservedBindClearsTheAcceptDownState pins the one semantic
// CHAOS-66 changes in the accept plane.
//
// CHAOS-54 recorded `down` as terminal for the process — correct then, because
// nothing re-opened the socket. Something does now, and a fresh socket is
// exactly the recovery for an unrecoverable one, so a bind must clear it. If it
// did not, a listener that recovered would keep reporting a fail row, a
// `listener_up 0` gauge and a page until the node restarted — reporting an
// outage that is over.
func TestChaos66_AnObservedBindClearsTheAcceptDownState(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	noteSOCKS5ListenerDown("listener_socket_invalid")
	if snap := socks5ListenerState(); !snap.Down {
		t.Fatal("the accept plane did not record the listener down")
	}

	noteSOCKS5Bound()
	snap := socks5ListenerState()
	if snap.Down {
		t.Errorf("an observed bind did not clear the down state (%q)", snap.DownReason)
	}
	if socks5ListenerStatus() != "ready" {
		t.Errorf("/healthz socks5 = %q after a rebind, want \"ready\"", socks5ListenerStatus())
	}
	if got := checkSOCKS5Listener(); got.Status == diagFail {
		t.Errorf("contract row still fails after a rebind: %q", got.Message)
	}
}

// TestChaos66_DownOperatorActionNoLongerDemandsARestart pins that the advice
// moved with the behaviour. Telling an operator to restart a gateway carrying
// production traffic, to achieve something that now happens on its own, costs
// an outage for nothing.
func TestChaos66_DownOperatorActionNoLongerDemandsARestart(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)
	noteSOCKS5ListenerDown("listener_socket_invalid")

	got := checkSOCKS5Listener()
	if strings.Contains(strings.ToLower(got.OperatorAction), "restart this node") {
		t.Errorf("the down row still tells the operator to restart the node: %q", got.OperatorAction)
	}
	if !strings.Contains(strings.ToLower(got.OperatorAction), "no restart required") {
		t.Errorf("the down row does not state that the rebind is automatic: %q", got.OperatorAction)
	}
}

// ── Gauge semantics ──────────────────────────────────────────────────────────

// TestChaos66_RetryingStaysUpButSustainedGoesDown pins the metric contract.
//
// The documented paging rule for culvert_socks5_listener_up is `== 0`. A
// listener that is merely retrying its bind — an ordinary redeploy — must not
// trip it; a sustained outage must.
func TestChaos66_RetryingStaysUpButSustainedGoesDown(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5BindFailure("port_in_use", time.Second, start)
	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_socks5_listener_up 1") {
		t.Error("a listener that is merely retrying its bind already exports listener_up 0")
	}
	if !strings.Contains(body, "culvert_socks5_unavailable 0") {
		t.Error("a listener that is merely retrying its bind is already reported unavailable")
	}

	noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(socks5BindUnavailableAfter+time.Second))
	body = renderMetrics(t)
	if !strings.Contains(body, "culvert_socks5_listener_up 0") {
		t.Error("a sustained unbindable listener does not export listener_up 0")
	}
	if !strings.Contains(body, "culvert_socks5_unavailable 1") {
		t.Error("a sustained unbindable listener does not export unavailable 1")
	}
	if !strings.Contains(body, "culvert_socks5_bind_failures_total 2") {
		t.Error("/metrics does not carry the bind-failure counter")
	}
}

// TestChaos66_BindMetricsAppearOnlyWhenConfigured preserves the CHAOS-54 rule
// for the new series: a flat 0 from every appliance that never enabled SOCKS5
// is indistinguishable from a broken listener, and the paging rule is `== 0`.
func TestChaos66_BindMetricsAppearOnlyWhenConfigured(t *testing.T) {
	socks5ChaosSetup(t)

	body := renderMetrics(t)
	for _, name := range []string{
		"culvert_socks5_unavailable",
		"culvert_socks5_bind_failures_total",
		"culvert_socks5_binds_total",
		"culvert_socks5_bind_backoff_seconds",
	} {
		if strings.Contains(body, name) {
			t.Errorf("/metrics exports %s on a node with no SOCKS5 listener", name)
		}
	}

	noteSOCKS5Configured(1080)
	body = renderMetrics(t)
	for _, name := range []string{
		"culvert_socks5_unavailable",
		"culvert_socks5_bind_failures_total",
		"culvert_socks5_binds_total",
		"culvert_socks5_bind_backoff_seconds",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics is missing %s on a node with a configured SOCKS5 listener", name)
		}
	}
}

// ── CONTROLS ─────────────────────────────────────────────────────────────────

// TestChaos66_ControlUnboundListenerIsNeverReportedReady is the control for the
// cheapest wrong fix.
//
// Deleting the fatal and reporting the listener healthy passes every "the
// process survived" assertion above while being strictly WORSE than the defect
// it replaces: before, an operator got a loud crash loop; after, they would get
// a SOCKS5 service that is silently absent forever on a node whose every probe
// reads green. Every surface must say so.
func TestChaos66_ControlUnboundListenerIsNeverReportedReady(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5BindFailure("port_in_use", time.Second, start)
	noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(socks5BindUnavailableAfter+time.Second))

	if got := socks5ListenerStatus(); got != "down" {
		t.Errorf("/healthz socks5 = %q for a sustained unbindable listener, want \"down\"", got)
	}
	if got := checkSOCKS5Listener(); got.Status != diagFail {
		t.Errorf("contract row = %q for a sustained unbindable listener, want %q", got.Status, diagFail)
	}
	checks := map[string]*readinessCheck{}
	appendSOCKS5ReadinessCheck(checks)
	if row, ok := checks["socks5"]; !ok || row.Status != "fail" {
		t.Errorf("/readyz socks5 row = %+v for a sustained unbindable listener, want fail", row)
	}

	// And the transient state must be visible too — not silently "ready".
	resetSOCKS5HealthForTest()
	noteSOCKS5Configured(1080)
	noteSOCKS5BindFailure("port_in_use", time.Second, time.Now())
	if got := socks5ListenerStatus(); got != "degraded" {
		t.Errorf("/healthz socks5 = %q while retrying a bind, want \"degraded\"", got)
	}
}

// TestChaos66_ControlHealthyBindIsSilent is the other control: the fault plane
// must not tax the healthy plane. A listener that binds first try must look
// exactly as it did before CHAOS-66 — no alert, no warn row, no counter
// movement.
func TestChaos66_ControlHealthyBindIsSilent(t *testing.T) {
	fired := socks5ChaosSetup(t)

	port := freeSOCKS5Port(t)
	startSupervisedSOCKS5(t, port)
	waitForSOCKS5(t, 5*time.Second, "the listener to bind", func() bool {
		return socks5ListenerState().Binds > 0
	})

	snap := socks5ListenerState()
	if snap.BindTotal != 0 || snap.BindFailing || snap.BindUnavailable || snap.Down {
		t.Errorf("a healthy bind recorded a fault: %+v", snap)
	}
	if len(*fired) != 0 {
		t.Errorf("a healthy bind fired %d alerts", len(*fired))
	}
	if socks5ListenerStatus() != "ready" {
		t.Errorf("/healthz socks5 = %q, want \"ready\"", socks5ListenerStatus())
	}
	if got := checkSOCKS5Listener(); got.Status != diagOK {
		t.Errorf("healthy contract row status = %q, want %q", got.Status, diagOK)
	}
	if body := renderMetrics(t); !strings.Contains(body, "culvert_socks5_listener_up 1") {
		t.Error("a healthy listener does not export culvert_socks5_listener_up 1")
	}

	assertPortHeld(t, port)
}

// ── Structural wall ──────────────────────────────────────────────────────────

// TestChaos66_TheSOCKS5ListenerPathHasNoFatal is the wall against
// reintroduction.
//
// Behavioural coverage cannot catch this directly — a reintroduced logFatalf
// kills the test binary rather than failing an assertion, so the signal would
// be an unexplained package-wide crash rather than a named failure. The scan
// names it.
//
// It deliberately does NOT cover main.go's `logFatalf("Proxy error")`, which is
// correct and must stay: the proxy IS the product, and a gateway that cannot
// serve must exit loudly rather than linger as a black hole. The asymmetry
// between an optional listener and the primary one is the whole finding.
func TestChaos66_TheSOCKS5ListenerPathHasNoFatal(t *testing.T) {
	files := []string{"socks5.go", "socks5_bind.go", "socks5_health.go"}
	checked := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if strings.Contains(code, "logFatalf(") || strings.Contains(code, "log.Fatal") {
				t.Errorf("%s:%d reintroduces a fatal on the SOCKS5 listener path: %s",
					f, i+1, strings.TrimSpace(line))
			}
			checked++
		}
	}
	// Not-vacuous check: if the selector stops matching real files the gate
	// would pass forever while proving nothing.
	if checked < 500 {
		t.Fatalf("the fatal scan only examined %d lines — it is not reading the listener sources", checked)
	}
}
