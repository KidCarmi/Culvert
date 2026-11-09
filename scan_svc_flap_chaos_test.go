package main

// scan_svc_flap_chaos_test.go — CHAOS-114 gates for a scan sidecar that binds
// and then DIES, over and over. Closes CHAOS-113 §8.7/§10.4, which recorded
// this as that round's sharpest open gap in its own new surface.
//
// THE FINDING. CHAOS-113 gave the sidecar a supervisor, a gauge, a contract row
// and an alert, all keyed on `Unavailable()` — "not bound, for longer than the
// threshold". A flapping sidecar is bound on every cycle, so:
//
//   - `Unavailable()` short-circuits on `Bound` and reads healthy for the whole
//     of every serve generation, and
//   - `maybeAlertScanSvcDown` is only called from the bind-FAILURE path, which
//     a flap never reaches, because the bind SUCCEEDS every time.
//
// Measured on the pre-fix tree, 20 flap cycles over ~10 minutes of virtual time
// with a sidecar whose serve died after 10 ms:
//
//	alerts fired            = 0
//	serve_exits             = 20
//	/healthz word mid-serve = ready in 20/20 samples
//	listener_up=1 mid-serve = 20/20 samples
//	contract row, cycles 1-5 = ok mid-serve, warn in the gap   (up=1 throughout)
//	contract row, cycles 6+  = ok mid-serve, fail in the gap   (up=0 only there)
//
// The `fail` from cycle 6 on is luck, not design: it appears only because the
// 30 s backoff ceiling happens to equal the 30 s unavailability threshold, and
// the real ±25% jitter puts the gap at 22.5–37.5 s, so even at the ceiling the
// gap-sampled row is `warn` about half the time. Through all of it every caller
// pointed at this address forwarded bodies UNSCANNED on every gap
// (`internal/secscan` remoteScanFail, fail-OPEN, WK-2b).
//
// WHY THE PRESCRIBED FIX WAS NOT TAKEN AS WRITTEN. CHAOS-113 §10.4 prescribed
// moving the `firstFailure`/`alerted` reset out of `noteScanSvcBound` into the
// post-serve path. Measured, that is nearly a no-op — `Unavailable()`
// short-circuits on `Bound`, so a slow redeploy still read ok/up=1/ready an
// hour in, and so did a flap mid-serve. The obvious next step, dropping the
// `Bound` arm so a bound-but-unstable sidecar counts as unavailable, pages
// FOREVER: a predecessor holding the port for 45 s opens an episode nothing
// closes, and the row read `fail`, up read 0 and /healthz read `down` an hour
// into a perfectly healthy serve. Both measurements are in §2.3 of the round.
// So the flap is tracked as its OWN episode, bounded by a minimum exit count
// and cleared by a serve that proves stable, and `Unavailable()` keeps its
// documented contract untouched.
//
// THE CONTROLS ARE LOAD-BEARING. The cheapest way to pass "a flap is visible"
// is to report any serve exit as a fault — which pages on the one-off lost
// socket CHAOS-113's supervisor exists to heal — or to let the unavailability
// episode run on wall-clock time, which is the slow-redeploy regression above.
// TestChaos114_ControlOneOffSocketLossIsNotAFlap,
// TestChaos114_ControlSlowRedeployNeverPages and
// TestChaos114_ControlStableServeEndsTheFlap pin all three directions.

import (
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// scanSvcFlapClock is a virtual clock for these gates. A flap is defined over
// tens of seconds of sidecar lifetime and the real supervisor sleeps its
// backoff ladder, so driving the clock is the only way to gate the CONDITION
// rather than the scheduler. It installs itself over scanSvcHealthNow;
// scanSvcChaosSetup restores the seam.
type scanSvcFlapClock struct{ now time.Time }

func newScanSvcFlapClock() *scanSvcFlapClock {
	c := &scanSvcFlapClock{now: time.Now()}
	scanSvcHealthNow = func() time.Time { return c.now }
	return c
}

func (c *scanSvcFlapClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// scanSvcAddrForPort is the loopback address for a port occupyPort handed back.
func scanSvcAddrForPort(port int) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// scanSvcCurrentListener reads the service's live listener under its own mutex.
// Closing it is how these gates inject a serve-loop death, which is the shape a
// lost socket, an interface teardown or descriptor exhaustion takes.
func scanSvcCurrentListener(svc *ScanService) net.Listener {
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.listener
}

// flapOneCycle replays exactly what superviseScanSvcListener does for one
// bind → short serve → serve-exit → backoff cycle, against the real production
// state functions. It returns the ladder's new value.
//
// Replaying the loop body rather than running the supervisor is deliberate: the
// supervisor's own sleeps are the thing a virtual clock cannot shorten, and the
// integration gate below runs the real supervisor to prove this sequence is the
// one production actually performs.
func flapOneCycle(c *scanSvcFlapClock, backoff, serve time.Duration) time.Duration {
	noteScanSvcBound()
	c.advance(serve)
	noteScanSvcServeEnded("listen_failed", serve, c.now)
	maybeAlertScanSvcFlapping()
	backoff = scanSvcBackoffAfterServe(backoff, serve)
	backoff = nextScanSvcBindBackoff(backoff)
	c.advance(backoff)
	return backoff
}

// ── Defect gates ─────────────────────────────────────────────────────────────

// TestChaos114_FlappingSidecarPages is the defect gate for the alert. The one
// alert built for "this node cannot serve scans" must fire for a sidecar that
// binds and dies in a loop — measured at 0 alerts over ~10 minutes pre-fix.
func TestChaos114_FlappingSidecarPages(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	backoff, serve := time.Duration(0), 10*time.Millisecond
	for i := 0; i < 20; i++ {
		backoff = flapOneCycle(c, backoff, serve)
	}

	if got := alerts.count(); got != 1 {
		t.Fatalf("20 flap cycles fired %d alerts, want exactly 1 — 0 is the pre-fix measurement and means a fleet fails open unheard", got)
	}
	if got := alerts.last(); got != "flapping" {
		t.Errorf("alert detail = %q, want %q: the detail is the dedup key's second half and has to tell a flap from a dead socket", got, "flapping")
	}
	if snap := scanSvcListenerState(); snap.UnstableExits < scanSvcFlapMinExits {
		t.Errorf("unstable_serves = %d after 20 flap cycles, want ≥ %d", snap.UnstableExits, scanSvcFlapMinExits)
	}
}

// TestChaos114_FlapIsVisibleMidServe is the defect gate for every READ surface.
// A flapping sidecar is bound at the instant of about half the scrapes, and
// pre-fix all of them reported health: ready in 20/20 mid-serve samples and
// up=1 in 20/20.
func TestChaos114_FlapIsVisibleMidServe(t *testing.T) {
	scanSvcChaosSetup(t)
	captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	// Establish the flap, then sample strictly INSIDE a serve generation.
	backoff, serve := time.Duration(0), 10*time.Millisecond
	for i := 0; i < 10; i++ {
		backoff = flapOneCycle(c, backoff, serve)
	}
	noteScanSvcBound()
	c.advance(serve)

	snap := scanSvcListenerState()
	if !snap.Bound {
		t.Fatal("the sample is not inside a serve generation; the gate is not testing what it claims")
	}
	if snap.Unavailable() {
		t.Fatal("Unavailable() is true mid-serve — the unavailability predicate's documented contract has changed, which is the slow-redeploy regression in §2.3")
	}
	if !snap.Flapping() {
		t.Fatal("Flapping() is false for a sidecar 10 cycles into a flap, sampled mid-serve")
	}

	if got := scanSvcListenerStatus(); got != "flapping" {
		t.Errorf("/healthz word mid-flap = %q, want %q (pre-fix: %q in 20/20 samples)", got, "flapping", "ready")
	}
	if row := checkScanSvcListener(); row.Status != diagFail {
		t.Errorf("contract row mid-flap = %q, want %q", row.Status, diagFail)
	} else {
		if !strings.Contains(row.Message, "FLAPPING") {
			t.Errorf("row message does not name the fault: %q", row.Message)
		}
		if !strings.Contains(row.Message, "UNSCANNED") {
			t.Errorf("row message does not state the fail-open consequence: %q", row.Message)
		}
		// The remedy must not send an operator after a bind problem: the bind
		// succeeded on every one of these cycles.
		if strings.Contains(row.OperatorAction, "another process holds") {
			t.Errorf("flap remedy routes through the bind remedies: %q", row.OperatorAction)
		}
	}

	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_scan_svc_listener_up 0",
		"culvert_scan_svc_listener_down 1",
		"culvert_scan_svc_listener_flapping 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("mid-flap /metrics is missing %q — the documented `up == 0` paging rule cannot see the fault", want)
		}
	}

	// /ready stays report-only, but it must not say "ok".
	checks := map[string]*readinessCheck{}
	appendScanSvcReadinessCheck(checks)
	if got := checks["scan_svc"]; got == nil || got.Status != "fail" {
		t.Errorf("/ready scan_svc row mid-flap = %+v, want a fail row", got)
	}
}

// TestChaos114_FlapAlertFiresOncePerRun pins the rate. A flap is a loop, so an
// alert per cycle is a pager loop — and the store's dedup window is 30 s while
// the ladder settles at a 30 s cadence, so the latch, not the dedup, is what
// has to hold here.
func TestChaos114_FlapAlertFiresOncePerRun(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	backoff, serve := time.Duration(0), 10*time.Millisecond
	for i := 0; i < 40; i++ {
		backoff = flapOneCycle(c, backoff, serve)
	}
	if got := alerts.count(); got != 1 {
		t.Fatalf("40 flap cycles fired %d alerts, want 1", got)
	}

	// A serve that proves stable ends the run and clears the latch, so a LATER
	// flap is allowed to page again. Without this a sidecar pages once per
	// process lifetime and every later flap is silent.
	noteScanSvcBound()
	c.advance(scanSvcServeStableAfter + time.Second)
	noteScanSvcServeEnded("listen_failed", scanSvcServeStableAfter+time.Second, c.now)
	maybeAlertScanSvcFlapping()
	if got := alerts.count(); got != 1 {
		t.Fatalf("a stable serve generation itself alerted (%d total)", got)
	}

	backoff = 0
	for i := 0; i < 20; i++ {
		backoff = flapOneCycle(c, backoff, serve)
	}
	if got := alerts.count(); got != 2 {
		t.Errorf("a second flap run after a stable serve fired %d alerts total, want 2 — the latch never cleared", got)
	}
}

// TestChaos114_RealSupervisorReachesTheFlapVerdict is the integration gate: the
// deterministic gates above replay the loop body, and this one proves the
// production supervisor performs that sequence — that `served` reaches
// noteScanSvcServeEnded and that the flap verdict is evaluated on the
// serve-exit path, which is the half of the defect no bind-failure gate can
// reach.
func TestChaos114_RealSupervisorReachesTheFlapVerdict(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()

	// The clock advances on every READ, so the sidecar's virtual lifetime runs
	// far ahead of the real backoff sleeps and a flap accumulates in seconds of
	// wall time. The step stays under scanSvcServeStableAfter so each serve
	// generation is genuinely sub-stable, which is what makes it a flap.
	start := time.Now()
	var reads atomic.Int64 // the supervisor goroutine and this one both read it
	scanSvcHealthNow = func() time.Time {
		return start.Add(time.Duration(reads.Add(1)) * 20 * time.Second)
	}

	port, release := occupyPort(t)
	release() // bindable
	addr := scanSvcAddrForPort(port)

	svc := superviseForTest(t, addr)
	// Kill each serve generation as soon as it binds. Three sub-stable
	// generations plus the age threshold is the flap condition; the ladder puts
	// them at 1 s + 2 s + 4 s of real sleeping.
	deadline := time.Now().Add(45 * time.Second)
	for alerts.count() == 0 && time.Now().Before(deadline) {
		if ln := scanSvcCurrentListener(svc); ln != nil {
			_ = ln.Close()
		}
		time.Sleep(25 * time.Millisecond)
	}

	if got := alerts.count(); got < 1 {
		snap := scanSvcListenerState()
		t.Fatalf("the production supervisor never reached the flap verdict: alerts=%d serve_exits=%d unstable_serves=%d unstable_for=%s",
			got, snap.ServeExits, snap.UnstableExits, snap.UnstableFor)
	}
	if got := alerts.last(); got != "flapping" {
		t.Errorf("supervisor fired detail %q, want %q", got, "flapping")
	}
}

// ── Controls ─────────────────────────────────────────────────────────────────

// TestChaos114_ControlOneOffSocketLossIsNotAFlap is the control for the exit
// COUNT. A single serve generation that dies and is replaced by one that lasts
// is precisely the fault CHAOS-113's supervisor exists to heal; paging on it
// would convert a self-healed fault into an outage page.
func TestChaos114_ControlOneOffSocketLossIsNotAFlap(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	// One serve generation lasts an hour and then loses its socket.
	noteScanSvcBound()
	c.advance(time.Hour)
	noteScanSvcServeEnded("listen_failed", time.Hour, c.now)
	maybeAlertScanSvcFlapping()

	// It rebinds one backoff step later and serves on.
	c.advance(scanSvcBindBackoffInitial)
	noteScanSvcBound()
	c.advance(10 * time.Minute)
	maybeAlertScanSvcFlapping()

	if got := alerts.count(); got != 0 {
		t.Errorf("a one-off lost socket fired %d flap alerts, want 0 — this pages on the fault the supervisor heals", got)
	}
	if snap := scanSvcListenerState(); snap.Flapping() {
		t.Error("a one-off lost socket reports Flapping()")
	}
	if got := scanSvcListenerStatus(); got != "ready" {
		t.Errorf("/healthz word after a healed socket loss = %q, want ready", got)
	}
	if row := checkScanSvcListener(); row.Status != diagOK {
		t.Errorf("contract row after a healed socket loss = %q, want %q", row.Status, diagOK)
	}
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_flapping 0") {
		t.Error("a healed socket loss exports listener_flapping 1")
	}

	// Two sub-stable generations must still not be a flap: the count exists so
	// one fault plus one retry cannot reach the verdict.
	backoff := time.Duration(0)
	for i := 0; i < scanSvcFlapMinExits-1; i++ {
		backoff = flapOneCycle(c, backoff, 10*time.Millisecond)
	}
	if got := alerts.count(); got != 0 {
		t.Errorf("%d sub-stable serve generations fired %d alerts, want 0", scanSvcFlapMinExits-1, got)
	}
}

// TestChaos114_ControlSingleExitThenAStuckBindIsNotAFlap is the second control
// for the exit COUNT, and it is the one that makes the count load-bearing: it
// pins which of two FAIL rows a sustained outage gets, and therefore which
// remedy the operator is handed.
//
// A sidecar that serves briefly, loses its socket ONCE and then cannot rebind
// is a port conflict, not a crash loop. With no minimum exit count the run is
// one exit old and more than the threshold old, so the flap verdict wins the
// switch and the operator is told to go read the sidecar's log for a
// scanner-engine init failure — while the actual fault is another process
// holding the address, which the bind remedy names exactly. A wrong remedy on a
// fail-open security control is worse than a vague one.
//
// Found by mutating scanSvcFlapMinExits to 1 and watching the whole CHAOS-114
// suite still pass (round §9.3, mutation D).
func TestChaos114_ControlSingleExitThenAStuckBindIsNotAFlap(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	// One short serve generation, then the address is taken for five minutes.
	noteScanSvcBound()
	c.advance(10 * time.Millisecond)
	noteScanSvcServeEnded("listen_failed", 10*time.Millisecond, c.now)
	maybeAlertScanSvcFlapping()

	start, backoff := c.now, time.Duration(0)
	for c.now.Sub(start) < 5*time.Minute {
		backoff = nextScanSvcBindBackoff(backoff)
		maybeAlertScanSvcDown("port_in_use", noteScanSvcBindFailure("port_in_use", backoff, c.now))
		c.advance(backoff)
	}

	snap := scanSvcListenerState()
	if snap.Flapping() {
		t.Errorf("one serve exit plus a %s stuck bind is reported as a flap (exits=%d, run age %s) — the operator is sent after a crash loop instead of a port conflict",
			snap.FailingFor.Round(time.Second), snap.UnstableExits, snap.UnstableFor.Round(time.Second))
	}
	if !snap.Unavailable() {
		t.Fatal("a five-minute stuck bind is not reported unavailable; the gate's premise is wrong")
	}
	if got := scanSvcListenerStatus(); got != "down" {
		t.Errorf("/healthz = %q, want down", got)
	}
	row := checkScanSvcListener()
	if row.Status != diagFail {
		t.Fatalf("contract row = %q, want %q", row.Status, diagFail)
	}
	if strings.Contains(row.Message, "FLAPPING") {
		t.Errorf("a stuck bind gets the flap row: %q", row.Message)
	}
	if !strings.Contains(row.OperatorAction, "another process holds") {
		t.Errorf("remedy does not name the port conflict: %q", row.OperatorAction)
	}
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_flapping 0") {
		t.Error("a stuck bind exports listener_flapping 1")
	}
	// The down alert is the right one here, and exactly one of it.
	if got := alerts.count(); got != 1 {
		t.Errorf("alerts fired = %d, want 1 (the down alert)", got)
	}
	if got := alerts.last(); got != "port_in_use" {
		t.Errorf("alert detail = %q, want the bind class %q", got, "port_in_use")
	}
}

// TestChaos114_SustainedRebindFailureAfterAFlapReadsDown is the gate for the
// transition the stuck-bind control above cannot reach: the flap PREMISES are
// met (three short serve generations, a run older than the threshold) and THEN
// the address stops binding. The flap run is history — nothing clears it while
// no generation serves — so before this gate `Flapping()` stayed true for as
// long as the port stayed taken, and every surface told the operator "the
// address binds … not the port" about a port conflict. A sustained run of
// failed rebinds past the same threshold the down shape uses is the CURRENT
// fault and takes precedence.
func TestChaos114_SustainedRebindFailureAfterAFlapReadsDown(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	// Three short serve generations, then another process takes the port.
	backoff := time.Duration(0)
	for i := 0; i < scanSvcFlapMinExits; i++ {
		backoff = flapOneCycle(c, backoff, 10*time.Millisecond)
	}
	start := c.now
	for c.now.Sub(start) < 5*time.Minute {
		backoff = nextScanSvcBindBackoff(backoff)
		maybeAlertScanSvcDown("port_in_use", noteScanSvcBindFailure("port_in_use", backoff, c.now))
		c.advance(backoff)
	}

	snap := scanSvcListenerState()
	if snap.UnstableExits < scanSvcFlapMinExits || snap.UnstableFor < scanSvcUnavailableAfter {
		t.Fatalf("the gate's premise is wrong: the flap run is exits=%d age=%s, which the flap verdict alone would not count",
			snap.UnstableExits, snap.UnstableFor)
	}
	if !snap.Unavailable() {
		t.Fatal("a five-minute stuck bind is not reported unavailable; the gate's premise is wrong")
	}
	if snap.Flapping() {
		t.Errorf("five minutes of failed rebinds after %d short serves still reports Flapping() — the stale flap run hides a port conflict", snap.UnstableExits)
	}
	if got := scanSvcListenerStatus(); got != "down" {
		t.Errorf("/healthz = %q, want down", got)
	}
	row := checkScanSvcListener()
	if row.Status != diagFail {
		t.Fatalf("contract row = %q, want %q", row.Status, diagFail)
	}
	if strings.Contains(row.Message, "FLAPPING") {
		t.Errorf("a sustained bind failure gets the flap row: %q", row.Message)
	}
	if !strings.Contains(row.OperatorAction, "another process holds") {
		t.Errorf("remedy does not name the port conflict: %q", row.OperatorAction)
	}
	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_scan_svc_listener_up 0",
		"culvert_scan_svc_listener_down 1",
		"culvert_scan_svc_listener_flapping 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sustained bind failure after a flap: /metrics is missing %q", want)
		}
	}
	checks := map[string]*readinessCheck{}
	appendScanSvcReadinessCheck(checks)
	if got := checks["scan_svc"]; got == nil || got.Status != "fail" || strings.Contains(got.Detail, "flapping") {
		t.Errorf("/ready scan_svc row = %+v, want the not-serving fail row", got)
	}
	if got := alerts.last(); got != "port_in_use" {
		t.Errorf("last alert detail = %q, want the bind class %q", got, "port_in_use")
	}

	// The port is released and the sidecar binds again: the run of failed
	// rebinds is over, the flap run is not, so a generation that is still
	// short reads as flapping once more. The precedence is about the CURRENT
	// shape, not an amnesty for the history.
	noteScanSvcBound()
	c.advance(10 * time.Millisecond)
	if !scanSvcListenerState().Flapping() {
		t.Error("a short serve after the port conflict cleared does not read as flapping again")
	}
}

// TestChaos114_ControlRetryGapStaysFlapping is the control for the rule above:
// an ordinary backoff gap between short serves is NOT a sustained bind
// failure. At the 30 s ladder ceiling the gap alone reaches the unavailability
// threshold with no bind attempt failing at all, and that must still read as
// the flap it is — otherwise the verdict flickers to `down` and a port remedy
// on every slow cycle.
func TestChaos114_ControlRetryGapStaysFlapping(t *testing.T) {
	scanSvcChaosSetup(t)
	captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	backoff := time.Duration(0)
	for i := 0; i < 10; i++ {
		backoff = flapOneCycle(c, backoff, 10*time.Millisecond)
	}
	// flapOneCycle ends after sleeping the backoff, i.e. at the next bind
	// attempt — the far end of the gap, 30 s past the last exit.
	snap := scanSvcListenerState()
	if snap.Bound || !snap.Unavailable() {
		t.Fatalf("the gate's premise is wrong: bound=%v failing_for=%s", snap.Bound, snap.FailingFor)
	}
	if !snap.Flapping() {
		t.Error("a retry gap at the ladder ceiling between short serves no longer reads as flapping")
	}
	if got := scanSvcListenerStatus(); got != "flapping" {
		t.Errorf("/healthz in a retry gap = %q, want flapping", got)
	}
	if row := checkScanSvcListener(); !strings.Contains(row.Message, "FLAPPING") {
		t.Errorf("contract row in a retry gap is not the flap row: %q", row.Message)
	}
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_flapping 1") {
		t.Error("a retry gap exports listener_flapping 0")
	}

	// A failed rebind INSIDE the threshold is not yet sustained either: one
	// more short generation, then a bind that fails a second after it ends.
	noteScanSvcBound()
	c.advance(10 * time.Millisecond)
	noteScanSvcServeEnded("listen_failed", 10*time.Millisecond, c.now)
	c.advance(time.Second)
	maybeAlertScanSvcDown("port_in_use", noteScanSvcBindFailure("port_in_use", scanSvcBindBackoffMax, c.now))
	if !scanSvcListenerState().Flapping() {
		t.Error("one failed rebind a second into the gap already overrides the flap verdict — the threshold arm is missing")
	}
}

// TestChaos114_ControlSlowRedeployNeverPages is the control for the REGRESSION
// the obvious fix introduces. A draining predecessor that holds the port past
// the unavailability threshold, followed by a serve that lasts, must be silent
// on every surface — measured at row=fail / up=0 / healthz=down an hour into
// the healthy serve when the unavailability episode is left on wall-clock time
// (§2.3).
func TestChaos114_ControlSlowRedeployNeverPages(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()
	start := c.now

	// 45 s of EADDRINUSE — longer than scanSvcUnavailableAfter, so this node
	// does legitimately page while it lasts.
	backoff := time.Duration(0)
	for c.now.Sub(start) < 45*time.Second {
		backoff = nextScanSvcBindBackoff(backoff)
		maybeAlertScanSvcDown("port_in_use", noteScanSvcBindFailure("port_in_use", backoff, c.now))
		c.advance(backoff)
	}
	if alerts.count() != 1 {
		t.Fatalf("a 45 s bind outage fired %d alerts, want 1 — the gate's premise is wrong", alerts.count())
	}

	// The predecessor lets go and this generation serves for an hour.
	noteScanSvcBound()
	for _, age := range []time.Duration{time.Second, 30 * time.Second, 2 * time.Minute, time.Hour} {
		c.advance(age)
		snap := scanSvcListenerState()
		if snap.Flapping() {
			t.Errorf("%s into a healthy serve the sidecar reports Flapping()", age)
		}
		if got := scanSvcListenerStatus(); got != "ready" {
			t.Errorf("%s into a healthy serve /healthz = %q, want ready", age, got)
		}
		if row := checkScanSvcListener(); row.Status != diagOK {
			t.Errorf("%s into a healthy serve the contract row = %q, want %q", age, row.Status, diagOK)
		}
		if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_up 1") {
			t.Errorf("%s into a healthy serve listener_up = 0 — this pages forever after a slow redeploy", age)
		}
	}
	if got := alerts.count(); got != 1 {
		t.Errorf("the healthy serve added %d alerts", got-1)
	}
}

// TestChaos114_ControlStableServeEndsTheFlap is the control for the arm that
// clears the verdict while a generation is still RUNNING. Without it the run
// only resets when a generation ENDS, so a sidecar that flapped and has since
// served for hours keeps paging for those hours.
func TestChaos114_ControlStableServeEndsTheFlap(t *testing.T) {
	scanSvcChaosSetup(t)
	captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	backoff := time.Duration(0)
	for i := 0; i < 10; i++ {
		backoff = flapOneCycle(c, backoff, 10*time.Millisecond)
	}

	// The sidecar recovers and this generation keeps serving. It is still
	// flapping until the generation proves stable — the operator cannot yet
	// tell this from another cycle, and reporting recovery early is the whole
	// failure this round is about.
	noteScanSvcBound()
	c.advance(scanSvcServeStableAfter - time.Second)
	if !scanSvcListenerState().Flapping() {
		t.Error("the flap verdict cleared before the serve generation proved stable")
	}

	c.advance(2 * time.Second) // now past scanSvcServeStableAfter
	if scanSvcListenerState().Flapping() {
		t.Fatal("a serve generation that has proven stable still reports Flapping() — the verdict latches for the life of the serve")
	}
	if got := scanSvcListenerStatus(); got != "ready" {
		t.Errorf("/healthz after a stable serve = %q, want ready", got)
	}
	if row := checkScanSvcListener(); row.Status != diagOK {
		t.Errorf("contract row after a stable serve = %q, want %q", row.Status, diagOK)
	}
	if !strings.Contains(renderMetrics(t), "culvert_scan_svc_listener_flapping 0") {
		t.Error("a sidecar serving stably again exports listener_flapping 1")
	}

	c.advance(3 * time.Hour)
	if scanSvcListenerState().Flapping() {
		t.Error("three hours into a stable serve the sidecar still reports Flapping()")
	}
}

// TestChaos114_ControlGracefulStopIsNotAFlap keeps the one terminal path that
// must never alert out of the new verdict. An operator stopping a sidecar
// mid-flap is not a new page, and a rolling restart must not become one.
func TestChaos114_ControlGracefulStopIsNotAFlap(t *testing.T) {
	scanSvcChaosSetup(t)
	captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	backoff := time.Duration(0)
	for i := 0; i < 10; i++ {
		backoff = flapOneCycle(c, backoff, 10*time.Millisecond)
	}
	if !scanSvcListenerState().Flapping() {
		t.Fatal("the gate's premise is wrong: no flap established")
	}

	noteScanSvcListenerStopped()
	if scanSvcListenerState().Flapping() {
		t.Error("a gracefully stopped sidecar reports Flapping()")
	}
	if got := scanSvcListenerStatus(); got != "stopped" {
		t.Errorf("/healthz after a graceful stop = %q, want stopped", got)
	}
	if row := checkScanSvcListener(); row.Status != diagOK {
		t.Errorf("contract row after a graceful stop = %q, want %q", row.Status, diagOK)
	}
	checks := map[string]*readinessCheck{}
	appendScanSvcReadinessCheck(checks)
	if _, ok := checks["scan_svc"]; ok {
		t.Error("a gracefully stopped sidecar still contributes a /ready row")
	}
}

// TestChaos114_ControlUnconfiguredSidecarHasNoFlapSurface keeps the new gauges
// off a node that never ran a sidecar. `flapping 0` there is indistinguishable
// from a healthy sidecar's, which is the asymmetry every gauge in this family
// is absent for.
func TestChaos114_ControlUnconfiguredSidecarHasNoFlapSurface(t *testing.T) {
	scanSvcChaosSetup(t)
	if scanSvcListenerState().Flapping() {
		t.Error("an unconfigured sidecar reports Flapping()")
	}
	body := renderMetrics(t)
	for _, unwanted := range []string{
		"culvert_scan_svc_listener_flapping",
		"culvert_scan_svc_unstable_serves",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("a node that never ran a sidecar exports %s", unwanted)
		}
	}
}

// TestChaos114_FlapRunAgeIsDatedFromTheGenerationStart pins the run's age to
// when the sidecar became unreliable rather than to when the first generation
// happened to end, and pins the threshold itself: three exits inside a few
// seconds are not yet a flap, because a flap is a condition that PERSISTS.
func TestChaos114_FlapRunAgeIsDatedFromTheGenerationStart(t *testing.T) {
	scanSvcChaosSetup(t)
	alerts := captureScanSvcAlerts()
	noteScanSvcConfigured("127.0.0.1:8484")
	c := newScanSvcFlapClock()

	// Three generations of 20 s each: enough exits, but only 60 s of run — and
	// each generation's own 20 s has to COUNT toward the run, or a sidecar that
	// dies every 20 s never accumulates an age at all.
	served := 20 * time.Second
	noteScanSvcBound()
	c.advance(served)
	noteScanSvcServeEnded("listen_failed", served, c.now)
	if got := scanSvcListenerState().UnstableFor; got < served {
		t.Errorf("run age after one %s generation = %s, want ≥ %s: the run is dated from the exit, so a slow flap never ages", served, got, served)
	}

	// Three fast exits with no elapsed time are not a flap: the age threshold
	// is what keeps a brief stumble off the pager.
	resetScanSvcHealthForTest()
	noteScanSvcConfigured("127.0.0.1:8484")
	for i := 0; i < scanSvcFlapMinExits+2; i++ {
		noteScanSvcBound()
		noteScanSvcServeEnded("listen_failed", time.Millisecond, c.now)
		maybeAlertScanSvcFlapping()
	}
	if snap := scanSvcListenerState(); snap.Flapping() {
		t.Errorf("%d exits inside a millisecond is reported as a flap (run age %s, threshold %s)",
			snap.UnstableExits, snap.UnstableFor, scanSvcUnavailableAfter)
	}
	if got := alerts.count(); got != 0 {
		t.Errorf("a sub-threshold stumble fired %d alerts, want 0", got)
	}
}
