package main

// socks5_accept_chaos_test.go — CHAOS-54 gates for the SOCKS5 accept loop.
//
// Every gate here was verified FAILING against the pre-fix loop (log-and-retry
// with no delay, no classification, no health record). The pre-fix shape is
// kept in-tree as replaySOCKS5PreFixServe so the comparison stays reproducible
// and the spin gate can prove it is measuring a real difference rather than a
// number that happens to pass.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ── Test doubles ─────────────────────────────────────────────────────────────

// faultListener is a net.Listener whose Accept is scripted. It counts calls so
// a gate can measure the loop's retry RATE, which is the whole point of the
// finding: the pre-fix loop's failure was not that it retried, it was how fast.
//
// Queued conns are handed out first. After they run out it returns `err`
// forever — or, when `quiet` is set, blocks until Close, which is what the
// healthy-path control needs so that a successful accept is not immediately
// followed by a scripted failure.
type faultListener struct {
	calls  atomic.Int64
	err    error
	quiet  bool
	closed atomic.Bool

	closeOnce sync.Once
	done      chan struct{}

	mu    sync.Mutex
	conns []net.Conn
}

func newFaultListener(err error) *faultListener {
	return &faultListener{err: err, done: make(chan struct{})}
}

func (l *faultListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	l.mu.Lock()
	if len(l.conns) > 0 {
		c := l.conns[0]
		l.conns = l.conns[1:]
		l.mu.Unlock()
		return c, nil
	}
	l.mu.Unlock()
	if l.quiet {
		<-l.done
		return nil, net.ErrClosed
	}
	return nil, l.err
}

func (l *faultListener) Close() error {
	l.closed.Store(true)
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *faultListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}

func (l *faultListener) push(c net.Conn) {
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
}

// stubConn is a net.Conn whose Read returns EOF immediately, so handleSOCKS5
// abandons the greeting and returns without touching the dial path. Close
// closes `closed`, which is how the healthy-path control knows the handler
// goroutine is finished with the process-global stores (see that test).
type stubConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stubConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *stubConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *stubConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *stubConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}
}
func (c *stubConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 45000}
}
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

// acceptErr builds an accept error in the exact shape the net package produces:
// *net.OpError wrapping *os.SyscallError wrapping a syscall.Errno. Matching the
// real wrapping matters — socks5AcceptFatal/Reason classify with errors.As, and
// a gate that handed them a bare Errno would not prove they see through the
// wrapper the kernel path actually produces.
func acceptErr(errno syscall.Errno) error {
	return &net.OpError{
		Op:  "accept",
		Net: "tcp",
		Err: os.NewSyscallError("accept", errno),
	}
}

// socks5ChaosSetup isolates the process-global SOCKS5 health record and the
// alert seam for one test.
func socks5ChaosSetup(t *testing.T) *[]string {
	t.Helper()
	resetSOCKS5HealthForTest()
	t.Cleanup(resetSOCKS5HealthForTest)

	var mu sync.Mutex
	var fired []string
	prev := fireSOCKS5ListenerAlert
	fireSOCKS5ListenerAlert = func(detail string) {
		mu.Lock()
		fired = append(fired, detail)
		mu.Unlock()
	}
	t.Cleanup(func() { fireSOCKS5ListenerAlert = prev })
	return &fired
}

// ── The finding: FD exhaustion used to spin the accept loop ──────────────────

// replaySOCKS5PreFixServe is the accept loop EXACTLY as it stood before
// CHAOS-54, minus the logging (which would flood the test output with the same
// hundreds of thousands of lines it floods the process log with in production).
// It exists so TestChaos54_AcceptBackoffBoundsTheRetryRate can state its margin
// against a measured baseline on the same hardware in the same run, rather than
// against a constant that drifts.
func replaySOCKS5PreFixServe(ln net.Listener, done chan struct{}) {
	defer close(done)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		_ = conn.Close()
	}
}

// TestChaos54_AcceptBackoffBoundsTheRetryRate is the headline gate.
//
// accept(2) returns EMFILE/ENFILE when the process or the system is out of
// descriptors, and Go surfaces it straight out of FD.Accept without blocking.
// The pre-fix loop retried immediately and logged every attempt: measured
// ~870,000 attempts per second, one log line each, which pins a core and
// rotates the entire 50 MB process log away in seconds — destroying the
// evidence of whatever exhausted the descriptors in the first place.
//
// The gate is a RATIO against the pre-fix shape measured in the same run, so it
// is machine-independent and immune to a loaded CI runner. It also asserts an
// absolute ceiling derived from the backoff schedule itself.
func TestChaos54_AcceptBackoffBoundsTheRetryRate(t *testing.T) {
	socks5ChaosSetup(t)

	const window = 300 * time.Millisecond

	// Baseline: the pre-fix loop against the same fault.
	base := newFaultListener(acceptErr(syscall.EMFILE))
	baseDone := make(chan struct{})
	go replaySOCKS5PreFixServe(base, baseDone)
	time.Sleep(window)
	base.Close()
	<-baseDone
	preFix := base.calls.Load()

	// Fixed loop against the identical fault.
	ln := newFaultListener(acceptErr(syscall.EMFILE))
	srv := newSOCKS5Server(ln)
	srv.Start()
	time.Sleep(window)
	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop while backing off: %v", err)
	}
	fixed := ln.calls.Load()

	t.Logf("accept attempts in %s — pre-fix: %d, with backoff: %d", window, preFix, fixed)

	// Absolute bound from the schedule: 5,10,20,40,80,160,320,640 ms sums past
	// 300 ms by the 7th attempt. Allow generous slack for a slow scheduler and
	// still catch any return to unbounded spinning by orders of magnitude.
	const maxExpected = 32
	if fixed > maxExpected {
		t.Errorf("accept loop made %d attempts in %s; backoff should bound it to ~%d",
			fixed, window, maxExpected)
	}
	// Ratio gate: prove the baseline really did spin, so a passing absolute
	// bound cannot mean the harness simply never ran.
	if preFix < 1000 {
		t.Fatalf("pre-fix baseline only made %d attempts; the harness is not reproducing the spin", preFix)
	}
	if fixed*100 > preFix {
		t.Errorf("backoff bought less than 100x: pre-fix %d vs fixed %d", preFix, fixed)
	}
}

// TestChaos54_AcceptErrorLoggingIsRateLimited pins the second half of the
// flood: even bounded to one attempt per second, an un-gated log line is one
// line per attempt forever. The rate gate must emit the FIRST error
// immediately (an operator has to see the onset) and then suppress, counting
// what it suppressed.
func TestChaos54_AcceptErrorLoggingIsRateLimited(t *testing.T) {
	socks5ChaosSetup(t)

	start := time.Now()
	logged := 0
	for i := 0; i < 500; i++ {
		// All within one interval: 500 failures spread over 10 seconds.
		at := start.Add(time.Duration(i) * 20 * time.Millisecond)
		if noteSOCKS5AcceptFailure("process_fd_limit", time.Second, at) {
			logged++
		}
	}
	if logged != 1 {
		t.Errorf("500 failures inside one %s window produced %d log lines; want exactly 1 (the onset)",
			socks5AcceptLogInterval, logged)
	}

	// Crossing the interval must produce exactly one more line, not a burst.
	if !noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start.Add(socks5AcceptLogInterval+time.Second)) {
		t.Error("no log line emitted after the rate-limit interval elapsed")
	}

	if snap := socks5ListenerState(); snap.Total != 501 {
		t.Errorf("counter lost failures to the log gate: Total=%d, want 501", snap.Total)
	}
}

// TestChaos54_SuppressedLinesAreReportedOnRecovery proves the magnitude is not
// lost: the operator gets one recovery line naming how much was swallowed.
func TestChaos54_SuppressedLinesAreReportedOnRecovery(t *testing.T) {
	socks5ChaosSetup(t)

	start := time.Now()
	for i := 0; i < 50; i++ {
		noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start.Add(time.Duration(i)*time.Millisecond))
	}
	suppressed := noteSOCKS5AcceptSuccess()
	if suppressed != 49 {
		t.Errorf("recovery reported %d suppressed lines; want 49 (50 failures, 1 logged)", suppressed)
	}
	// A second success on a healthy loop must report nothing — the recovery
	// line is per-EPISODE, not per-accept.
	if again := noteSOCKS5AcceptSuccess(); again != 0 {
		t.Errorf("recovery reported %d on an already-healthy listener; want 0", again)
	}
}

// ── Recovery is on evidence, never on elapsed time ───────────────────────────

// TestChaos54_RecoveryRequiresAnObservedAccept is the house rule from
// storage_health.go / ca_health.go applied here: a listener that stops failing
// because nobody is dialling it has not recovered. Only an Accept that returned
// a connection clears the degraded state.
func TestChaos54_RecoveryRequiresAnObservedAccept(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start)
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start.Add(socks5AcceptDegradedAfter+time.Second))

	if snap := socks5ListenerState(); !snap.Degraded {
		t.Fatalf("listener not degraded after %s of consecutive failures", socks5AcceptDegradedAfter)
	}
	if got := checkSOCKS5Listener(); got.Status != diagWarn {
		t.Errorf("degraded listener contract row status = %q, want %q", got.Status, diagWarn)
	}

	// Time passing is NOT recovery.
	if snap := socks5ListenerState(); !snap.Degraded {
		t.Error("degraded state cleared without an observed accept")
	}

	noteSOCKS5AcceptSuccess()
	snap := socks5ListenerState()
	if snap.Degraded || snap.Failing {
		t.Errorf("observed accept did not clear the degraded state: %+v", snap)
	}
	if got := checkSOCKS5Listener(); got.Status != diagOK {
		t.Errorf("recovered listener contract row status = %q, want %q", got.Status, diagOK)
	}
	// The cumulative counter must survive recovery — a history of transient
	// failures is exactly what an operator needs after the fact.
	if snap.Total != 2 {
		t.Errorf("cumulative accept-error count reset on recovery: Total=%d, want 2", snap.Total)
	}
}

// ── The alert: once per episode, bounded detail ──────────────────────────────

// TestChaos54_DegradedAlertFiresOncePerEpisode pins the fire-once latch. The
// fault repeats at the backoff rate; an un-latched producer would page once per
// second for the duration of a descriptor incident and evict real alerts from
// the 500-entry retry queue (the WK-12 class).
func TestChaos54_DegradedAlertFiresOncePerEpisode(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start)
	for i := 0; i < 100; i++ {
		at := start.Add(socks5AcceptDegradedAfter + time.Duration(i)*time.Second)
		noteSOCKS5AcceptFailure("process_fd_limit", time.Second, at)
	}
	if len(*fired) != 1 {
		t.Fatalf("degradation fired %d alerts; want exactly 1 per episode", len(*fired))
	}

	// A new episode after a real recovery pages again.
	noteSOCKS5AcceptSuccess()
	second := start.Add(time.Hour)
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, second)
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, second.Add(socks5AcceptDegradedAfter+time.Second))
	if len(*fired) != 2 {
		t.Errorf("a second degradation episode fired %d alerts total; want 2", len(*fired))
	}
}

// TestChaos54_DegradationDoesNotSwallowTheDownPage pins the SEPARATE latches.
//
// Degraded ("retrying, self-heals when descriptors free up") and down ("socket
// gone, restart required") are different operator states with different
// actions, and the second can follow the first. A shared fire-once latch would
// swallow the page for a dead listener whenever it had already been degraded —
// silencing the more urgent of the two. Same rule storage_health.go states for
// its log and alert gates.
func TestChaos54_DegradationDoesNotSwallowTheDownPage(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start)
	noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start.Add(socks5AcceptDegradedAfter+time.Second))
	if len(*fired) != 1 {
		t.Fatalf("degradation fired %d alerts; want 1", len(*fired))
	}

	// The listener now dies outright. That MUST page again.
	noteSOCKS5ListenerDown("listener_socket_invalid")
	if len(*fired) != 2 {
		t.Fatalf("a listener that died while already degraded fired %d alerts total; want 2", len(*fired))
	}
	if !strings.Contains((*fired)[1], "STOPPED") {
		t.Errorf("second alert does not name the stopped state: %q", (*fired)[1])
	}

	// Down is terminal for the process, so repeating it must not re-page.
	noteSOCKS5ListenerDown("listener_socket_invalid")
	if len(*fired) != 2 {
		t.Errorf("a repeated down report fired %d alerts total; want 2", len(*fired))
	}
}

// TestChaos54_TransientBurstDoesNotPage is the control for the gate above: the
// backoff exists to absorb short descriptor spikes, so a burst that clears
// inside the threshold must be counted and logged but must NOT page.
func TestChaos54_TransientBurstDoesNotPage(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	start := time.Now()
	for i := 0; i < 20; i++ {
		noteSOCKS5AcceptFailure("process_fd_limit", time.Second, start.Add(time.Duration(i)*time.Second))
	}
	if len(*fired) != 0 {
		t.Errorf("a %s burst paged %d times; the degradation threshold is %s",
			19*time.Second, len(*fired), socks5AcceptDegradedAfter)
	}
	if snap := socks5ListenerState(); snap.Total != 20 {
		t.Errorf("transient burst not counted: Total=%d, want 20", snap.Total)
	}
}

// TestChaos54_AlertDetailIsBoundedForDedup pins the RS-5/WK-12 lesson: the
// alert Detail is part of the dedup key, so it must be built from a bounded
// reason class and must never carry the raw accept error (which embeds the
// listener address and would defeat dedup by construction).
func TestChaos54_AlertDetailIsBoundedForDedup(t *testing.T) {
	socks5ChaosSetup(t)

	seen := map[string]struct{}{}
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ECONNABORTED, syscall.EBADF, syscall.ENOTSOCK, syscall.EINVAL,
		syscall.EFAULT, syscall.ENOTCONN, syscall.EAGAIN, syscall.EIO,
	} {
		seen[socks5AcceptReason(acceptErr(errno))] = struct{}{}
	}
	// Errors that are not syscall-shaped at all must also collapse.
	seen[socks5AcceptReason(errors.New("something entirely unexpected"))] = struct{}{}

	if len(seen) > 6 {
		t.Errorf("accept reasons produced %d distinct dedup keys: %v; the class must stay bounded", len(seen), seen)
	}
	for reason := range seen {
		if len(reason) > 40 {
			t.Errorf("reason %q is too long to be a bounded class", reason)
		}
	}
}

// ── Classification: what may be retried forever, and what must not ───────────

// TestChaos54_TransientErrorsAreRetriedNotFatal is the availability half of the
// classification. EMFILE/ENFILE/ENOBUFS/ENOMEM clear on their own, and treating
// them as fatal would turn a descriptor spike into a permanent SOCKS5 outage
// that only a restart fixes.
func TestChaos54_TransientErrorsAreRetriedNotFatal(t *testing.T) {
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED,
	} {
		if socks5AcceptFatal(acceptErr(errno)) {
			t.Errorf("%v classified as fatal; it is a transient resource condition", errno)
		}
	}
	// An UNRECOGNISED error must also be retryable. That is the fail-safe
	// direction: backed off to 1/s, retrying an unknown error costs nothing,
	// while misclassifying a transient fault as fatal is a customer-visible
	// outage.
	if socks5AcceptFatal(errors.New("unrecognised accept failure")) {
		t.Error("an unrecognised accept error was classified as fatal; the fail-safe default is to retry")
	}
}

// TestChaos54_UnrecoverableSocketStopsTheLoopLoudly is the other half. When the
// descriptor is no longer a listening socket, every Accept returns the same
// error instantly — retrying is a pure spin that can never succeed. The loop
// must stop, close the listener so clients get connection-refused instead of
// hanging against a black hole, and report the service DOWN on every surface.
func TestChaos54_UnrecoverableSocketStopsTheLoopLoudly(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	ln := newFaultListener(acceptErr(syscall.EBADF))
	srv := newSOCKS5Server(ln)
	srv.Start()

	select {
	case <-srv.done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept loop did not exit on an unrecoverable listener error; it is spinning")
	}

	if calls := ln.calls.Load(); calls > 4 {
		t.Errorf("loop made %d accept attempts on an unrecoverable error; it must stop, not retry", calls)
	}
	if !ln.closed.Load() {
		t.Error("listener not closed after a fatal accept error: clients hang against a bound port that never accepts")
	}

	snap := socks5ListenerState()
	if !snap.Down {
		t.Fatal("listener not recorded as down after a fatal accept error")
	}
	if snap.DownReason != "listener_socket_invalid" {
		t.Errorf("down reason = %q, want %q", snap.DownReason, "listener_socket_invalid")
	}
	if len(*fired) != 1 {
		t.Errorf("a dead listener fired %d alerts; want exactly 1", len(*fired))
	}
	if got := checkSOCKS5Listener(); got.Status != diagFail {
		t.Errorf("dead-listener contract row status = %q, want %q", got.Status, diagFail)
	}
	if socks5ListenerStatus() != "down" {
		t.Errorf("/healthz socks5 = %q, want \"down\"", socks5ListenerStatus())
	}

	checks := map[string]*readinessCheck{}
	appendSOCKS5ReadinessCheck(checks)
	row, ok := checks["socks5"]
	if !ok || row.Status != "fail" {
		t.Errorf("/readyz socks5 row = %+v, want a failing row", row)
	}
}

// TestChaos54_ListenerClosedWithoutStopIsReportedDown pins the distinction
// between "the listener is gone" and "we were asked to shut down".
//
// net.ErrClosed says only the first. Treating every ErrClosed as an expected
// stop leaves exactly the hole this change exists to close: the loop exits,
// nothing is recorded, and every probe keeps reporting a healthy node
// (`socks5: ready`, `culvert_socks5_listener_up 1`) while the service is dead —
// PX-18 in a narrower costume. Raised by Codex review on PR #1208.
//
// The paired control below proves the ordinary Stop path is unaffected, so a
// passing gate cannot mean the loop simply reports DOWN on every exit.
func TestChaos54_ListenerClosedWithoutStopIsReportedDown(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	ln := newFaultListener(acceptErr(syscall.EMFILE))
	ln.quiet = true // block in Accept until something closes the listener
	srv := newSOCKS5Server(ln)
	srv.Start()

	// Close the listener directly — NOT through Stop. This is the shape of any
	// path that ends the listener without going through the shutdown sequence.
	_ = ln.Close()

	select {
	case <-srv.done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept loop did not exit after the listener was closed")
	}

	snap := socks5ListenerState()
	if !snap.Down {
		t.Fatal("listener closed without a shutdown request was not recorded as down; every probe still reports a healthy node")
	}
	if snap.DownReason != "listener_closed_unexpectedly" {
		t.Errorf("down reason = %q, want %q", snap.DownReason, "listener_closed_unexpectedly")
	}
	if len(*fired) != 1 {
		t.Errorf("unexpected listener closure fired %d alerts; want 1", len(*fired))
	}
	if socks5ListenerStatus() != "down" {
		t.Errorf("/healthz socks5 = %q, want \"down\"", socks5ListenerStatus())
	}
	if body := renderMetrics(t); !strings.Contains(body, "culvert_socks5_listener_up 0") {
		t.Error("a listener closed without a shutdown request still exports culvert_socks5_listener_up 1")
	}
}

// TestChaos54_OrdinaryStopIsNotReportedDown is the control for the gate above.
// A normal shutdown must stay silent: no DOWN record, no alert, no
// `listener_up 0`, or every clean restart would page the operator.
func TestChaos54_OrdinaryStopIsNotReportedDown(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	ln := newFaultListener(acceptErr(syscall.EMFILE))
	ln.quiet = true
	srv := newSOCKS5Server(ln)
	srv.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if snap := socks5ListenerState(); snap.Down {
		t.Errorf("an ordinary Stop recorded the listener as down (%q)", snap.DownReason)
	}
	if len(*fired) != 0 {
		t.Errorf("an ordinary Stop fired %d alerts; want 0", len(*fired))
	}
	if socks5ListenerStatus() != "ready" {
		t.Errorf("/healthz socks5 = %q after an ordinary Stop, want \"ready\"", socks5ListenerStatus())
	}
}

// ── Shutdown stays prompt while backing off ──────────────────────────────────

// TestChaos54_StopIsPromptDuringAcceptBackoff pins the shutdown half. The
// backoff sleep is interruptible; if it were a bare time.Sleep, a Stop landing
// mid-sleep would wait out the REMAINDER of a backoff that has climbed to
// socks5AcceptBackoffMax, inside a 2 s shutdown budget that also has to cover
// the listener close.
//
// Measured over several independent servers and asserted on the WORST one. A
// single trial is not a gate: where Stop lands inside a non-interruptible sleep
// is uniform, so one run of a broken build passes a quarter of the time. Every
// trial of the correct build returns in microseconds, so the many-trial form
// adds no risk of a flaky FAILURE — only of a flaky pass, which N reduces
// geometrically (0.025^4 ≈ 4e-7 against the 25 ms bound below).
func TestChaos54_StopIsPromptDuringAcceptBackoff(t *testing.T) {
	socks5ChaosSetup(t)

	const trials = 4
	var worst time.Duration
	for i := 0; i < trials; i++ {
		ln := newFaultListener(acceptErr(syscall.EMFILE))
		srv := newSOCKS5Server(ln)
		srv.Start()

		// Let the backoff climb to its ceiling so a non-interruptible sleep is
		// maximally visible: 5+10+20+40+80+160+320+640 ms exceeds 1 s.
		time.Sleep(1300 * time.Millisecond)

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := srv.Stop(ctx)
		cancel()
		if err != nil {
			t.Fatalf("trial %d: Stop during accept backoff: %v", i, err)
		}
		if elapsed := time.Since(start); elapsed > worst {
			worst = elapsed
		}
	}
	t.Logf("worst Stop latency during accept backoff over %d trials: %s", trials, worst)
	if worst > 25*time.Millisecond {
		t.Errorf("Stop took %s while the accept loop was backing off; the sleep is not interruptible", worst)
	}
}

// TestChaos54_StopStaysIdempotent guards the sync.Once around the stopping
// channel: a double Stop must not panic on a second close.
func TestChaos54_StopStaysIdempotent(t *testing.T) {
	socks5ChaosSetup(t)

	ln := newFaultListener(acceptErr(syscall.EMFILE))
	srv := newSOCKS5Server(ln)
	srv.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// ── Controls: a healthy listener is byte-identical to before ─────────────────

// TestChaos54_HealthyListenerIsUnchanged is the control. On the ordinary path
// — accepts succeeding — nothing new must be recorded, no backoff must be
// taken, and no surface must report anything but "ready".
//
// The accepted connection is a stub whose Read returns EOF immediately, NOT a
// real dial, and the test WAITS for the handler to close it before returning.
// Both halves are load-bearing, and the reason is a property of the system
// rather than of the test: `Stop` closes the listener but does NOT drain
// in-flight `handleSOCKS5` goroutines (register row PX-8, called out in
// socks5_shutdown_test.go). A handler that outlives its test races the next
// test's `setupProxyTest` over the `ipf` / `rl` / `connLimiter` globals — which
// is exactly what the first version of this gate did, and what the race
// detector caught. Waiting on Close is sufficient: `handleSOCKS5` defers
// `connLimiter.Release` INSIDE `conn.Close`'s defer (LIFO ⇒ Release runs
// first), and the outermost `recoverGoroutine` reads no globals on the
// non-panic path, so once Close has run the handler touches nothing shared.
func TestChaos54_HealthyListenerIsUnchanged(t *testing.T) {
	fired := socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	handled := make(chan struct{})
	ln := newFaultListener(acceptErr(syscall.EMFILE))
	ln.quiet = true // after the one accepted conn, block rather than fail
	ln.push(&stubConn{closed: handled})

	srv := newSOCKS5Server(ln)
	srv.Start()

	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("the accepted connection was never handled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	snap := socks5ListenerState()
	if snap.Total != 0 || snap.Failing || snap.Degraded || snap.Down {
		t.Errorf("healthy listener recorded a fault: %+v", snap)
	}
	if len(*fired) != 0 {
		t.Errorf("healthy listener fired %d alerts", len(*fired))
	}
	if socks5ListenerStatus() != "ready" {
		t.Errorf("/healthz socks5 = %q, want \"ready\"", socks5ListenerStatus())
	}
	if got := checkSOCKS5Listener(); got.Status != diagOK {
		t.Errorf("healthy contract row status = %q, want %q", got.Status, diagOK)
	}
}

// TestChaos54_UnconfiguredListenerReportsNothing pins the absent-feature
// posture. SOCKS5 is off by default (-socks5-port 0), so a permanently-present
// row or a `listener_up 0` gauge on every appliance would be noise that an
// alerting rule keyed on `== 0` reads as a fault.
func TestChaos54_UnconfiguredListenerReportsNothing(t *testing.T) {
	socks5ChaosSetup(t)

	if got := checkSOCKS5Listener(); got.Status != diagOK {
		t.Errorf("unconfigured contract row status = %q, want %q", got.Status, diagOK)
	}
	if socks5ListenerStatus() != "disabled" {
		t.Errorf("/healthz socks5 = %q, want \"disabled\"", socks5ListenerStatus())
	}
	checks := map[string]*readinessCheck{}
	appendSOCKS5ReadinessCheck(checks)
	if _, ok := checks["socks5"]; ok {
		t.Error("/readyz carries a socks5 row on a node with no SOCKS5 listener")
	}
	if body := renderMetrics(t); strings.Contains(body, "culvert_socks5_listener_up") {
		t.Error("/metrics exports culvert_socks5_listener_up on a node with no SOCKS5 listener")
	}
}

// TestChaos54_MetricsAppearOnlyWhenConfigured is the other side of the gauge
// contract: once a listener exists, the series must be present so a paging rule
// has something to key on.
func TestChaos54_MetricsAppearOnlyWhenConfigured(t *testing.T) {
	socks5ChaosSetup(t)
	noteSOCKS5Configured(1080)

	body := renderMetrics(t)
	for _, name := range []string{
		"culvert_socks5_listener_up",
		"culvert_socks5_accept_errors_total",
		"culvert_socks5_accept_degraded",
		"culvert_socks5_accept_backoff_seconds",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("/metrics is missing %s on a node with a configured SOCKS5 listener", name)
		}
	}
	if !strings.Contains(body, "culvert_socks5_listener_up 1") {
		t.Error("a healthy configured listener does not export culvert_socks5_listener_up 1")
	}

	noteSOCKS5ListenerDown("listener_socket_invalid")
	if body := renderMetrics(t); !strings.Contains(body, "culvert_socks5_listener_up 0") {
		t.Error("a dead listener does not export culvert_socks5_listener_up 0")
	}
}

// TestChaos54_BackoffScheduleMatchesTheDocumentedShape pins the constants that
// the rate gate's absolute bound is derived from.
func TestChaos54_BackoffScheduleMatchesTheDocumentedShape(t *testing.T) {
	if got := nextSOCKS5AcceptBackoff(0); got != socks5AcceptBackoffInitial {
		t.Errorf("first backoff = %s, want %s", got, socks5AcceptBackoffInitial)
	}
	d := time.Duration(0)
	for i := 0; i < 32; i++ {
		next := nextSOCKS5AcceptBackoff(d)
		if next <= d && d < socks5AcceptBackoffMax {
			t.Fatalf("backoff did not grow: %s -> %s", d, next)
		}
		d = next
	}
	if d != socks5AcceptBackoffMax {
		t.Errorf("backoff settled at %s, want the %s ceiling", d, socks5AcceptBackoffMax)
	}
	// The ceiling must stay under the shutdown budget for socks5-listener-stop.
	if socks5AcceptBackoffMax >= 2*time.Second {
		t.Errorf("backoff ceiling %s is not below the 2s socks5-listener-stop budget", socks5AcceptBackoffMax)
	}
}
