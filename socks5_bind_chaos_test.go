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
	"sync"
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
	if logged, _ := noteSOCKS5BindFailure("port_in_use", time.Second, start); !logged {
		t.Error("the first bind failure of an episode was not logged")
	}
	for i := 1; i < 20; i++ {
		if logged, _ := noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(time.Duration(i)*time.Second)); logged {
			t.Fatalf("failure %d inside the rate window was logged", i)
		}
	}
	if logged, _ := noteSOCKS5BindFailure("port_in_use", time.Second, start.Add(socks5BindLogInterval+time.Second)); !logged {
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

// TestChaos66_ListenerIsPublishedBeforeTheBindIsRecorded pins the ORDER of the
// two steps that make a bind observable: the supervisor's handle (`adopt`) and
// the health plane's record (`noteSOCKS5Bound`).
//
// The first shipped order was record → log → adopt. Between those statements
// `Binds` was already 1 — `/healthz` `ready`, `culvert_socks5_listener_up` 1,
// `EverBound` true — while `Addr()` still answered nil, and one scheduler
// preemption in that window failed ListenerRebindsOnceThePortIsFree under the
// contended full `-race` suite (`a bound listener reports no address`). The
// window cannot be scheduled from a test, and a many-trial gate would be a
// gate that flakes, so it is pinned DETERMINISTICALLY through the
// socks5BindRecordedHook seam: the hook runs on the supervisor goroutine at the
// exact instant the record lands, before startSOCKS5 is released, and asserts
// what the handle answers at that instant. Against the record-first order the
// hook observes Addr() == nil every time, not once in a thousand runs.
func TestChaos66_ListenerIsPublishedBeforeTheBindIsRecorded(t *testing.T) {
	socks5ChaosSetup(t)

	var (
		mu       sync.Mutex
		observed int
		unbound  int
	)
	// Registered BEFORE startSupervisedSOCKS5 so it runs AFTER its Stop:
	// cleanups are LIFO, and the seam must not be cleared while the loop can
	// still read it.
	t.Cleanup(func() { socks5BindRecordedHook = nil })
	socks5BindRecordedHook = func(s *socks5Supervisor) {
		mu.Lock()
		defer mu.Unlock()
		observed++
		if s.Addr() == nil || socks5ListenerState().Binds == 0 {
			unbound++
		}
	}

	port := freeSOCKS5Port(t)
	srv := startSupervisedSOCKS5(t, port)

	mu.Lock()
	defer mu.Unlock()
	if observed == 0 {
		t.Fatal("the bind-recorded seam never fired: the gate is vacuous")
	}
	if unbound != 0 {
		t.Errorf("%d of %d bind record(s) were observable before the listener was published — "+
			"Binds > 0 with Addr() == nil is the window this gate exists to close", unbound, observed)
	}
	if srv.Addr() == nil {
		t.Error("a bound listener reports no address after startSOCKS5 returned")
	}
}

// TestChaos66_ABindRefusedByStopIsNotRecordedAsABind pins the other half of
// adopting first: a socket that Stop refuses is closed without ever serving,
// so it must not be counted as a bind, must not set EverBound, and must not
// clear a failure episode — the state noteSOCKS5ListenerStopped leaves is the
// truth for a node on its way out. The record-first order counted it (Binds
// 1, EverBound true) for a listener nothing ever accepted on.
//
// Driven synchronously: `stopped` is set under the lock without closing
// `stopping`, so the loop passes its top check, binds, and is refused by adopt
// — the refused branch reached deterministically, without racing Stop.
func TestChaos66_ABindRefusedByStopIsNotRecordedAsABind(t *testing.T) {
	socks5ChaosSetup(t)

	port := freeSOCKS5Port(t)
	s := &socks5Supervisor{
		port:         port,
		stopping:     make(chan struct{}),
		done:         make(chan struct{}),
		firstAttempt: make(chan struct{}),
	}
	noteSOCKS5Configured(port)
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()

	s.run()
	<-s.done

	snap := socks5ListenerState()
	if snap.Binds != 0 || snap.EverBound {
		t.Errorf("a listener Stop refused was recorded as a bind: Binds=%d EverBound=%v", snap.Binds, snap.EverBound)
	}
	if !snap.Stopped {
		t.Error("a refused adoption was not recorded as stopped")
	}
	if s.Addr() != nil {
		t.Error("a refused listener was published")
	}
	select {
	case <-s.firstAttempt:
	default:
		t.Error("startSOCKS5 would never have been released after a refused adoption")
	}
	// And the socket really was closed, not leaked against the successor.
	if ln, err := ctxListen(fmt.Sprintf(":%d", port)); err != nil {
		t.Errorf("port %d is still held after the refused listener should have been closed: %v", port, err)
	} else {
		_ = ln.Close()
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

// TestChaos66_RestartGuidanceMatchesWhetherARebindIsPending pins the SECOND
// Codex round on PR #1376.
//
// CHAOS-66 made the accept plane's `down` recoverable but updated only ONE of
// the three surfaces that carried the old "unavailable until restart"
// instruction: the contract row's operator action. The alert Detail and both
// accept-loop log lines still told operators to restart a gateway that was
// already rebinding — the same class of miss this PR's own SOCKS5 log-injection
// note records one level up (*fixing one surface does not fix the call*).
//
// And a blanket reword would have been wrong in the OTHER direction: the
// supervisor's own contained panic is still terminal, so promising an automatic
// rebind there sends an operator away from the one restart that is genuinely
// needed. Hence two named recorders, and this gate asserts BOTH directions —
// an inverted pair passes any single-direction assertion.
func TestChaos66_RestartGuidanceMatchesWhetherARebindIsPending(t *testing.T) {
	// Both directions run through ONE symmetric helper on purpose. Each surface
	// is asserted against the polarity the recorder claims, so an inverted
	// recoveryPending fails on whichever arm it lands in — a pair of
	// hand-written single-direction subtests can be satisfied by an inverted
	// implementation as long as each only checks its own happy phrase.
	for _, tc := range []struct {
		name            string
		note            func(string)
		reason          string
		recoveryPending bool
	}{
		{"accept plane stopped — rebind pending", noteSOCKS5ListenerDown, "listener_socket_invalid", true},
		{"supervisor stopped — genuinely terminal", noteSOCKS5SupervisorDown, "bind loop panicked", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertDownGuidanceMatchesRecovery(t, tc.note, tc.reason, tc.recoveryPending)
		})
	}

	// The two subtests above exercise the RECORDERS. They cannot catch the
	// wiring regressing — swapping which recorder the supervisor's panic guard
	// calls leaves both of them passing, verified by mutation. The panic guard
	// is a defensive path with no injection seam, so the wiring is pinned
	// structurally: the supervisor file records TERMINAL, the accept-loop file
	// records RECOVERABLE, and neither reaches for the other's recorder.
	t.Run("each plane is wired to its own recorder", assertEachPlaneUsesItsOwnRecorder)
	t.Run("the alert Detail stays bounded in both directions", assertDownAlertDetailIsBounded)
}

// assertDownGuidanceMatchesRecovery pins that every operator-facing surface
// agrees with whether a rebind is actually pending. A restart is the remedy
// exactly when it is NOT — so each check is an equality against
// recoveryPending rather than a one-sided substring assertion.
func assertDownGuidanceMatchesRecovery(t *testing.T, note func(string), reason string, recoveryPending bool) {
	t.Helper()
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)
	note(reason)

	snap := socks5ListenerState()
	if !snap.Down || snap.DownRecoveryPending != recoveryPending {
		t.Fatalf("down state does not record recoveryPending=%v: %+v", recoveryPending, snap)
	}

	row := checkSOCKS5Listener()
	demandsRestart := strings.Contains(strings.ToLower(row.OperatorAction), "restart this node")
	if demandsRestart == recoveryPending {
		t.Errorf("contract row restart guidance is inverted (recoveryPending=%v): %q",
			recoveryPending, row.OperatorAction)
	}

	if len(*fired) != 1 {
		t.Fatalf("expected one alert, got %d", len(*fired))
	}
	alert := strings.ToLower((*fired)[0])
	if strings.Contains(alert, "until this node restarts") == recoveryPending {
		t.Errorf("alert restart guidance is inverted (recoveryPending=%v): %s",
			recoveryPending, (*fired)[0])
	}
	if strings.Contains(alert, "no restart required") != recoveryPending {
		t.Errorf("alert automatic-rebind guidance is inverted (recoveryPending=%v): %s",
			recoveryPending, (*fired)[0])
	}
}

func assertEachPlaneUsesItsOwnRecorder(t *testing.T) {
	for _, tc := range []struct{ file, want, reject string }{
		{"socks5_bind.go", "noteSOCKS5SupervisorDown(", "noteSOCKS5ListenerDown("},
		{"socks5.go", "noteSOCKS5ListenerDown(", "noteSOCKS5SupervisorDown("},
	} {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		body := string(src)
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s does not call %s", tc.file, tc.want)
		}
		if strings.Contains(body, tc.reject) {
			t.Errorf("%s calls %s — the two planes' down states point at opposite operator actions",
				tc.file, tc.reject)
		}
	}
}

func assertDownAlertDetailIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name string
		note func(string)
	}{
		{"recoverable", noteSOCKS5ListenerDown},
		{"terminal", noteSOCKS5SupervisorDown},
	} {
		fired := socks5ChaosSetup(t)
		noteSOCKS5Configured(1080)
		tc.note("listener_socket_invalid")
		if len(*fired) != 1 {
			t.Fatalf("%s: expected one alert, got %d", tc.name, len(*fired))
		}
		// Detail is the `event + ":" + Detail` dedup key (WK-12/RS-5).
		for _, leak := range []string{"0.0.0.0", "127.0.0.1", "listen tcp", "accept tcp"} {
			if strings.Contains((*fired)[0], leak) {
				t.Errorf("%s: alert detail leaks %q: %s", tc.name, leak, (*fired)[0])
			}
		}
	}
}

// TestChaos66_NoListenerSourceStillPromisesARestart is the wall for the class.
//
// The finding was three surfaces carrying one stale instruction, so a
// behavioural gate on the two that a test can reach still leaves the log lines
// — which need a live socket fault to emit — unguarded. This scans the listener
// sources for the phrase instead, allowing it only where a restart really is
// the remedy.
func TestChaos66_NoListenerSourceStillPromisesARestart(t *testing.T) {
	checked := 0
	for _, f := range []string{"socks5.go", "socks5_bind.go", "socks5_health.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			checked++
			code, _, _ := strings.Cut(line, "//")
			low := strings.ToLower(code)
			if !strings.Contains(low, "until restart") && !strings.Contains(low, "until this node restarts") {
				continue
			}
			// The one legitimate use: the terminal supervisor-down branch.
			if strings.Contains(code, "outlook =") {
				continue
			}
			t.Errorf("%s:%d still promises a restart on a path the supervisor rebinds: %s",
				f, i+1, strings.TrimSpace(line))
		}
	}
	if checked < 500 {
		t.Fatalf("the restart-guidance scan only examined %d lines — it is not reading the listener sources", checked)
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

// ── Codex round 3: the outage clock, and the remedy that matches the fault ───

// swapSOCKS5HealthClock points the health READ path at a clock the test drives,
// so an episode can age without recording another attempt — which is the whole
// condition under test.
func swapSOCKS5HealthClock(t *testing.T, now func() time.Time) {
	t.Helper()
	prev := socks5HealthNow
	socks5HealthNow = now
	t.Cleanup(func() { socks5HealthNow = prev })
}

// TestChaos66_UnavailabilityIsObservedWhileWaitingBetweenRetries is the defect
// gate for Codex round 3's first finding.
//
// Both episode durations were `lastFailure - firstFailure`, which stops
// advancing the instant an attempt returns. At the 30 s ceiling with ±20%
// jitter the next attempt can be 36 s away, so an outage that crossed its
// threshold stayed reported as "merely retrying" — `/healthz` degraded,
// `culvert_socks5_listener_up` 1, the contract row not failing — for the whole
// gap. Nothing here records a second failure: the point is that the passage of
// time alone must move the verdict.
func TestChaos66_UnavailabilityIsObservedWhileWaitingBetweenRetries(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	clock := start
	swapSOCKS5HealthClock(t, func() time.Time { return clock })

	// The episode opens, then its LAST attempt lands one second short of the
	// threshold — the shape the retry schedule actually produces at the ceiling.
	noteSOCKS5BindFailure("port_in_use", socks5BindBackoffInitial, start)
	noteSOCKS5BindFailure("port_in_use", socks5BindBackoffMax, start.Add(socks5BindUnavailableAfter-time.Second))
	clock = start.Add(socks5BindUnavailableAfter - time.Second)

	if snap := socks5ListenerState(); snap.BindUnavailable {
		t.Fatalf("reported unavailable before the threshold elapsed: failingFor=%s", snap.BindFailingFor)
	}

	// No further attempt — only the clock moves, as it does during a backoff.
	clock = start.Add(socks5BindUnavailableAfter + 2*time.Second)

	snap := socks5ListenerState()
	if !snap.BindUnavailable {
		t.Errorf("threshold elapsed during a backoff but the listener is still reported as merely retrying (failingFor=%s)", snap.BindFailingFor)
	}
	if snap.BindFailingFor < socks5BindUnavailableAfter {
		t.Errorf("BindFailingFor froze at the last attempt: %s", snap.BindFailingFor)
	}
	if row := checkSOCKS5Listener(); row.Status != diagFail {
		t.Errorf("contract row is %q during an outage past its threshold, want fail", row.Status)
	}
	if body := renderMetrics(t); !strings.Contains(body, "culvert_socks5_listener_up 0") {
		t.Error("culvert_socks5_listener_up is not 0 during an outage past its threshold — the documented paging rule is `== 0`")
	}
}

// TestChaos66_AcceptDegradationIsObservedWhileWaitingToo pins the same fix on
// the accept plane, whose ceiling is 1 s so its exposure was ~1 s rather than
// 36 s. It is gated anyway: the two planes must not disagree about what an
// episode duration means.
func TestChaos66_AcceptDegradationIsObservedWhileWaitingToo(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	clock := start
	swapSOCKS5HealthClock(t, func() time.Time { return clock })

	noteSOCKS5AcceptFailure("resource_exhausted", time.Second, start)
	clock = start.Add(socks5AcceptDegradedAfter + time.Second)

	if snap := socks5ListenerState(); !snap.Degraded {
		t.Errorf("accept degradation froze at the last attempt: failingFor=%s", snap.FailingFor)
	}
}

// TestChaos66_AnObservedFailureIsAFloorOnTheEpisode pins the clock-rollback
// direction. An NTP correction or a VM restore must never SHRINK an outage that
// has already been observed, because under-reporting is what silences a page.
func TestChaos66_AnObservedFailureIsAFloorOnTheEpisode(t *testing.T) {
	first := time.Now()
	last := first.Add(socks5BindUnavailableAfter + 5*time.Second)

	// Clock rolled back to before the episode even started.
	if got := socks5ElapsedSince(first, last, first.Add(-time.Hour)); got < socks5BindUnavailableAfter {
		t.Errorf("a rolled-back clock shrank an observed %s episode to %s", last.Sub(first), got)
	}
	// Forward clock with no new attempt: the clock wins.
	if got := socks5ElapsedSince(first, first, first.Add(90*time.Second)); got != 90*time.Second {
		t.Errorf("elapsed = %s, want 90s from the clock", got)
	}
	// A first-failure stamped in the future must not read as negative.
	if got := socks5ElapsedSince(first.Add(time.Hour), first.Add(time.Hour), first); got != 0 {
		t.Errorf("elapsed = %s, want 0 for a future episode start", got)
	}
}

// TestChaos66_BindSleepNeverStraddlesTheThreshold pins the second half of the
// same finding: the read surfaces age against the clock, but the ALERT is
// produced by an attempt, so the retry cadence must not carry the supervisor
// past the threshold without one. CHAOS-55's recoveryPollCeiling rule.
func TestChaos66_BindSleepNeverStraddlesTheThreshold(t *testing.T) {
	// The shape that produced the finding: one second short of the threshold,
	// sleeping the jittered ceiling.
	justShort := socks5BindUnavailableAfter - time.Second
	for _, wait := range []time.Duration{socks5BindBackoffMax, time.Duration(float64(socks5BindBackoffMax) * 1.2)} {
		got := clampSOCKS5BindSleep(wait, justShort)
		if justShort+got > socks5BindUnavailableAfter+socks5BindClampFloor {
			t.Errorf("a %s sleep at %s into an episode lands %s in, past the %s threshold — the alert cannot fire until it does",
				wait, justShort, justShort+got, socks5BindUnavailableAfter)
		}
	}

	// Once the threshold is crossed the clamp must stop applying, or a long
	// outage would retry far more often than the ceiling allows — the cost the
	// 30 s ceiling exists to bound.
	if got := clampSOCKS5BindSleep(socks5BindBackoffMax, socks5BindUnavailableAfter+time.Minute); got != socks5BindBackoffMax {
		t.Errorf("clamp still applies past the threshold: %s, want %s", got, socks5BindBackoffMax)
	}
	// A sleep already inside the remaining window is untouched.
	if got := clampSOCKS5BindSleep(time.Second, time.Second); got != time.Second {
		t.Errorf("clamped a sleep that already fits: %s", got)
	}
	// It never degenerates into a spin.
	if got := clampSOCKS5BindSleep(socks5BindBackoffMax, socks5BindUnavailableAfter-time.Nanosecond); got < socks5BindClampFloor {
		t.Errorf("clamped sleep %s is below the %s floor — that is a busy loop", got, socks5BindClampFloor)
	}
}

// TestChaos66_BindRemedyMatchesTheFailureReason is the defect gate for Codex
// round 3's second finding: every reason class got the port-ownership advice,
// so a node out of descriptors or with an interface that is not up was sent to
// hunt the owner of a port nobody holds.
func TestChaos66_BindRemedyMatchesTheFailureReason(t *testing.T) {
	// Each class must name its OWN remedy and must not name the wrong one.
	for _, tc := range []struct {
		reason string
		want   []string
		reject []string
	}{
		{"port_in_use", []string{"port 1080"}, []string{"descriptor", "interface"}},
		{"permission_denied", []string{"CAP_NET_BIND_SERVICE"}, []string{"descriptor", "already holds"}},
		{"address_unavailable", []string{"interface"}, []string{"descriptor", "already holds"}},
		{"descriptors_exhausted", []string{"file descriptors", "LimitNOFILE"}, []string{"already holds", "CAP_NET_BIND_SERVICE"}},
		{"listen_failed", []string{"server logs"}, []string{"descriptor", "CAP_NET_BIND_SERVICE"}},
		{"network_error", []string{"server logs"}, []string{"descriptor", "CAP_NET_BIND_SERVICE"}},
	} {
		got := socks5BindRemedy(tc.reason, 1080)
		low := strings.ToLower(got)
		for _, want := range tc.want {
			if !strings.Contains(low, strings.ToLower(want)) {
				t.Errorf("%s remedy omits %q: %s", tc.reason, want, got)
			}
		}
		for _, reject := range tc.reject {
			if strings.Contains(low, strings.ToLower(reject)) {
				t.Errorf("%s remedy points at the wrong fault (%q): %s", tc.reason, reject, got)
			}
		}
		// The two invariant clauses, in EVERY branch.
		if !strings.Contains(low, "no restart required") {
			t.Errorf("%s remedy drops the automatic-rebind clause: %s", tc.reason, got)
		}
		if !strings.Contains(low, "admin ui are unaffected") {
			t.Errorf("%s remedy drops the proxy/admin-UI clause — this row used to mean the whole appliance was gone: %s", tc.reason, got)
		}
	}

	// CONTROL: the remedies must be DISTINCT, or a switch that returns one
	// string per branch would satisfy every assertion above.
	seen := map[string]string{}
	for _, reason := range []string{"port_in_use", "permission_denied", "address_unavailable", "descriptors_exhausted"} {
		got := socks5BindRemedy(reason, 1080)
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s share one remedy — the classifier's distinctions are being discarded", prev, reason)
		}
		seen[got] = reason
	}
}

// TestChaos66_ContractRowCarriesTheReasonSpecificRemedy pins that the row
// actually consumes socks5BindRemedy. Testing the helper alone would pass with
// the row still hard-coding one action — the vacuous-gate lesson from round 2.
func TestChaos66_ContractRowCarriesTheReasonSpecificRemedy(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	clock := start
	swapSOCKS5HealthClock(t, func() time.Time { return clock })
	noteSOCKS5BindFailure("descriptors_exhausted", time.Second, start)
	clock = start.Add(socks5BindUnavailableAfter + time.Second)

	row := checkSOCKS5Listener()
	if row.Status != diagFail {
		t.Fatalf("row status %q, want fail", row.Status)
	}
	if want := socks5BindRemedy("descriptors_exhausted", 1080); row.OperatorAction != want {
		t.Errorf("contract row action does not come from the classifier:\n got: %s\nwant: %s", row.OperatorAction, want)
	}
}

// TestChaos66_HealthSnapshotDependsOnlyOnTheInjectedClock is the wall for the
// class that broke the determinism gate on this PR.
//
// Round 3 gave the health READ path a clock. Every other gate in this file
// drives the WRITE path with synthetic stamps, so if the read clock stays real
// the two are MIXED: a gate that records failures 19 s apart synthetically and
// then asserts "not yet degraded" is also asserting that under 30 s of WALL
// time passed between two of its own statements. That is true in milliseconds
// locally and false on a shared runner under `-count=2` — the failure was green
// locally under CI's own shuffle seed, which is what ruled out ordering and
// pointed at wall time.
//
// So the snapshot must be a pure function of (recorded state, injected clock).
// This gate holds the clock still across real elapsed time and requires the
// reported duration not to move, then advances the injected clock alone and
// requires that it does.
func TestChaos66_HealthSnapshotDependsOnlyOnTheInjectedClock(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	// Anchor the episode in the past so the CLOCK term dominates the stored
	// span — otherwise a real-clock read would be masked by `observed` and this
	// gate would pass against the defect.
	base := time.Now()
	clock := base
	swapSOCKS5HealthClock(t, func() time.Time { return clock })
	noteSOCKS5BindFailure("port_in_use", time.Second, base.Add(-20*time.Second))

	first := socks5ListenerState().BindFailingFor
	if first < 20*time.Second {
		t.Fatalf("episode not aged against the injected clock: %s", first)
	}

	// Real time passes; the injected clock does not move.
	time.Sleep(150 * time.Millisecond)

	if second := socks5ListenerState().BindFailingFor; second != first {
		t.Errorf("reported duration moved with WALL time while the injected clock was still (%s -> %s): "+
			"every synthetic-stamp gate in this file then silently depends on how long it takes to run",
			first, second)
	}

	// Advancing the injected clock MUST move it, or the gate above would pass
	// against a read path that ignores the clock entirely.
	clock = base.Add(time.Minute)
	if third := socks5ListenerState().BindFailingFor; third <= first {
		t.Errorf("advancing the injected clock did not age the episode: %s -> %s", first, third)
	}
}

// TestChaos66_RecoverableDownEscalatingToTerminalPagesAgain pins that the
// supervisor dying AFTER a recoverable accept-plane down still pages: the only
// alert sent so far said "no restart required", which is now false.
func TestChaos66_RecoverableDownEscalatingToTerminalPagesAgain(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	noteSOCKS5ListenerDown("listener_socket_invalid")
	if len(*fired) != 1 {
		t.Fatalf("recoverable down fired %d alerts, want 1", len(*fired))
	}
	noteSOCKS5SupervisorDown("bind loop panicked")
	if len(*fired) != 2 {
		t.Fatalf("recoverable->terminal escalation fired %d alerts in total, want 2 — the operator is left with the no-restart instruction", len(*fired))
	}
	if !strings.Contains((*fired)[1], "until this node restarts") {
		t.Errorf("escalation alert does not carry the restart instruction: %s", (*fired)[1])
	}

	// The latch still holds for a repeat of the same terminal state.
	noteSOCKS5SupervisorDown("bind loop panicked")
	if len(*fired) != 2 {
		t.Errorf("a repeated terminal down re-paged (%d alerts)", len(*fired))
	}
}

// TestChaos66_TerminalDownOutranksAnAgingBindEpisode pins that a supervisor
// that died during a bind outage is reported as terminal, not as a listener
// that is "still rebinding".
func TestChaos66_TerminalDownOutranksAnAgingBindEpisode(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	clock := start
	swapSOCKS5HealthClock(t, func() time.Time { return clock })
	noteSOCKS5BindFailure("port_in_use", time.Second, start)
	noteSOCKS5SupervisorDown("bind loop panicked")
	clock = start.Add(socks5BindUnavailableAfter + time.Second)

	row := checkSOCKS5Listener()
	if row.Status != diagFail {
		t.Fatalf("row status %q, want fail", row.Status)
	}
	if !strings.Contains(strings.ToLower(row.OperatorAction), "restart this node") {
		t.Errorf("terminal supervisor stop reported with rebind guidance: %q", row.OperatorAction)
	}
}
