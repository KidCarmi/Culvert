package main

// Scan-sidecar listener supervision and health — CHAOS-113.
//
// WHY THIS FILE EXISTS. `-scan-svc-listen` was the last listener in the tree
// with no supervision at all. The other three got the full treatment, each in
// its own round and each for the same reason:
//
//   - the admin UI listener  — CHAOS-57  (admin_ui_health.go)
//   - the SOCKS5 listener    — CHAOS-66/102 (socks5_health.go)
//   - the Control-Plane gRPC — CHAOS-71  (cp_grpc_bind.go, cp_grpc_health.go)
//
// The scan sidecar had a `logger.Printf` and a goroutine that returned. A bind
// failure logged one line and the process served nothing for its entire life,
// with no retry ever; a `Serve` that ended on its own logged one line and the
// goroutine exited, leaving a live process with no scanning plane, a free port
// and nothing anywhere that said so — no counter, no gauge, no health row, no
// alert. That is the scan-sidecar half of the 2026-10-13 backlog's `L-5`.
//
// WHY IT IS THE SHARP INSTANCE RATHER THAN THE LEFTOVER ONE. For the other
// three a dead listener costs availability of that surface. For this one it
// costs a SECURITY CONTROL on every node pointed at it: a sidecar that is not
// listening is the deployment in which `internal/secscan`'s remoteScanFail
// takes its fail-OPEN branch (WK-2b) and the fleet forwards bodies UNSCANNED.
// The socket nobody watched is the socket that decides whether a fleet scans.
//
// POSTURE. Supervision here is RECOVERY, not refusal: the sidecar's own
// process keeps serving its proxy, and rebinding is what gets the scanning
// plane back. The fail-open decision at the far end is the recorded owner
// decision (WK-2b) and this round does not change it — it makes the condition
// that triggers it observable and self-healing, which is the half that was
// missing.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	// scanSvcBindBackoffInitial is the first rebind delay, doubling to
	// scanSvcBindBackoffMax. Same ladder shape as the Control-Plane listener's
	// (nextCPGRPCBindBackoff): bounded, so a permanently unbindable address
	// costs one attempt per ceiling rather than a spin.
	scanSvcBindBackoffInitial = 1 * time.Second
	scanSvcBindBackoffMax     = 30 * time.Second

	// scanSvcServeStableAfter is how long a serve generation must last before
	// the ladder resets to its floor. A listener that dies immediately after
	// every bind keeps escalating instead of hammering at 1 s forever.
	scanSvcServeStableAfter = 60 * time.Second

	// scanSvcUnavailableAfter is how long the sidecar must be unable to serve
	// before the operator-contract row fails and the alert fires. It is the
	// same 30 s the Control-Plane listener uses, for the same reason: shorter
	// than that and an ordinary restart of a colocated predecessor holding the
	// port would page someone.
	scanSvcUnavailableAfter = 30 * time.Second

	// scanSvcFlapMinExits is how many consecutive sub-stable serve generations
	// a flap must contain before it is called one (CHAOS-114).
	//
	// WHY A COUNT AND NOT JUST AN AGE. The one-off lost socket CHAOS-113 exists
	// to recover from is a SINGLE serve exit followed by a serve that lasts.
	// Calling that a flap would page on the exact fault the supervisor already
	// heals on its own, so the flap condition needs a shape a single exit
	// cannot have. Three is the smallest count that cannot be reached by one
	// fault plus one retry, and the ladder puts the third exit at ~7 s, so the
	// age threshold below is what actually sets the time to page.
	scanSvcFlapMinExits = 3
)

// scanSvcHealthNow is the clock seam for this file's thresholds (tests drive
// the episode ages without sleeping). Mirrors socks5HealthNow.
var scanSvcHealthNow = time.Now

// scanSvcListenerHealth is the sidecar listener's health state.
//
// Guarded by one mutex rather than atomics: every reader is a human-facing
// surface (the contract row, /metrics, a log line) sampled at human rates, and
// the fields have to be consistent WITH EACH OTHER — "unbound for 40 s after 6
// attempts" is a sentence, not six independent numbers.
type scanSvcListenerHealth struct {
	mu sync.Mutex

	configured bool   // -scan-svc-listen was set
	addr       string // the configured listen address, as given
	bound      bool   // a listener is currently bound AND being served
	everBound  bool   // a bind has succeeded at least once in this process
	stopped    bool   // terminal: Shutdown() was called (a graceful stop)

	bindFailures int64 // cumulative failed bind attempts
	serveExits   int64 // cumulative serve generations that ended on their own
	lastClass    string

	// rebindFailures counts failed bind attempts since the last SUCCESSFUL
	// bind. Non-zero means the current gap is a bind that is failing, not an
	// ordinary backoff wait — the input Flapping() needs to tell a port
	// conflict that follows a flap from the flap's own retry gaps.
	rebindFailures int64

	firstFailure time.Time // start of the current unavailability episode
	lastFailure  time.Time
	backoff      time.Duration

	alerted bool // one alert per episode, never per retry

	// boundSince is when the CURRENT serve generation bound; zero when not
	// bound. It is what lets a reader tell a serve that has proven stable from
	// one that is 10 ms old, which is the whole difference between a recovery
	// and a flap (CHAOS-114).
	boundSince time.Time

	// unstableSince / unstableExits describe the current RUN of serve
	// generations that died before proving stable, and flapAlerted latches one
	// alert per run. This is a SEPARATE episode from firstFailure above, and
	// the separation is the load-bearing part of CHAOS-114 — see Flapping().
	unstableSince time.Time
	unstableExits int64
	flapAlerted   bool
}

var scanSvcListener scanSvcListenerHealth

// scanSvcListenerSnapshot is a consistent read of the state above.
type scanSvcListenerSnapshot struct {
	Configured   bool
	Addr         string
	Bound        bool
	EverBound    bool
	Stopped      bool
	BindFailures int64
	ServeExits   int64
	LastClass    string
	FailingFor   time.Duration
	Backoff      time.Duration

	// RebindFailures is failed bind attempts since the last successful bind.
	RebindFailures int64

	// ServingFor is how long the current serve generation has lasted; 0 when
	// not bound. UnstableFor / UnstableExits describe the current run of
	// sub-stable serve generations (CHAOS-114).
	ServingFor    time.Duration
	UnstableFor   time.Duration
	UnstableExits int64
}

// Unavailable reports whether the sidecar has been unable to serve for longer
// than the threshold, or has stopped without a graceful Shutdown.
//
// `s.Bound` short-circuits DELIBERATELY, and CHAOS-114 measured what happens
// without it. Dropping that arm so a bound-but-unstable sidecar counts as
// unavailable — the obvious second step after CHAOS-113 §10.4's prescription —
// makes a SLOW REDEPLOY page forever: a predecessor that holds the port for
// 45 s opens an episode that firstFailure never closes, and the row then reads
// `fail`, up reads 0 and /healthz reads `down` an HOUR into a serve that is
// perfectly healthy (measured: CHAOS-114 §2.3). This predicate is instantaneous
// sustained unavailability and its paging contract is correct. The flap is a
// different condition and gets its own predicate below.
func (s scanSvcListenerSnapshot) Unavailable() bool {
	if !s.Configured || s.Bound || s.Stopped {
		return false
	}
	return s.FailingFor >= scanSvcUnavailableAfter
}

// Flapping reports a sidecar that keeps binding and then dying — the condition
// CHAOS-113 §8.7/§10.4 recorded as its sharpest open gap and CHAOS-114 closes.
//
// WHY IT CANNOT REUSE THE UNAVAILABILITY EPISODE. A flapping sidecar BINDS
// successfully every cycle, so `Unavailable()` is false whenever a scrape lands
// inside a serve generation, and `maybeAlertScanSvcDown` — which only runs on
// the bind-FAILURE path — is never reached at all. Measured on the pre-fix
// tree: 20 flap cycles over ~10 minutes of a sidecar that is effectively down
// produced 0 alerts, `/healthz` = `ready` in 20/20 mid-serve samples and
// `culvert_scan_svc_listener_up` = 1 in 20/20, while every caller pointed at it
// forwarded bodies UNSCANNED through every gap (CHAOS-114 §2.1).
//
// The three conditions, each of which is load-bearing:
//
//   - scanSvcFlapMinExits consecutive serve generations died before proving
//     stable. One exit plus a lasting serve is the one-off lost socket
//     CHAOS-113 already heals; calling that a flap pages on a healed fault.
//   - the run is at least scanSvcUnavailableAfter old, the same threshold the
//     siblings use so an ordinary redeploy cannot trip it.
//   - the CURRENT serve generation has not itself proven stable. Without this
//     arm a sidecar that flapped five times and has since served for three
//     hours stays "flapping" for those three hours, because the run only
//     resets when a generation ENDS.
//   - the sidecar is not DOWN on a failing rebind. The flap run is history:
//     nothing clears it while no generation serves, so without this arm three
//     short serves followed by another process taking the port kept this
//     verdict true for as long as the port stayed taken, and every surface
//     sent the operator after the sidecar process ("not the port") for a port
//     conflict. Once rebinds have failed (no successful bind since) and the
//     outage has crossed the same Unavailable() threshold the down shape and
//     the down alert use, the sustained bind failure is the CURRENT fault and
//     wins. An ordinary backoff gap between short serves has no failed rebind
//     — even a ceiling gap that is itself past the threshold — so it still
//     reads as the flap. The run is deliberately NOT cleared: once the port
//     frees, a serve that is still short reads as flapping again.
//
// Every surface — the contract row, /healthz, /ready and the gauges — reads
// this one predicate, so the shape decision is made here and nowhere else.
func (s scanSvcListenerSnapshot) Flapping() bool {
	if !s.Configured || s.Stopped {
		return false
	}
	if s.UnstableExits < scanSvcFlapMinExits || s.UnstableFor < scanSvcUnavailableAfter {
		return false
	}
	if s.Bound && s.ServingFor >= scanSvcServeStableAfter {
		return false
	}
	if s.RebindFailures > 0 && s.Unavailable() {
		return false
	}
	return true
}

// fireScanSvcListenerAlert is the alert seam (tests replace it).
//
// detail is a BOUNDED class, never a raw bind error: the error text embeds the
// listen address, the alert store dedups on "event:detail" within 30 s, and a
// per-attempt address in the key is exactly the defect remoteScanFail's doc
// records — a key that cannot dedup, fanning out into the 500-entry retry
// queue where a scanner fault evicts real threat alerts.
var fireScanSvcListenerAlert = func(detail string) {
	if !globalAlertStore.HasSubscriber("scan_svc_listener_down") {
		return
	}
	go fireAlert("scan_svc_listener_down", AlertPayload{
		Detail: detail,
		Source: "scan_svc",
	})
}

// noteScanSvcConfigured records that a sidecar listener was asked for. Called
// before the first bind attempt, so an address that NEVER binds is still a
// configured-and-down sidecar rather than an absent feature.
func noteScanSvcConfigured(addr string) {
	scanSvcListener.mu.Lock()
	scanSvcListener.configured = true
	scanSvcListener.addr = addr
	scanSvcListener.mu.Unlock()
}

// noteScanSvcBound records a successful bind, closing any unavailability
// episode. It reports whether this bind RECOVERED one (so the caller logs the
// recovery rather than another "listening on" line).
//
// The unavailability episode closes HERE, at bind time, and that is correct for
// what `Unavailable()` means — the socket is answering again. CHAOS-113
// §8.7/§10.4 recorded this reset as the cause of the flap blindness and
// prescribed moving it to the post-serve path; CHAOS-114 measured that
// prescription and did NOT take it, because on its own it changes almost
// nothing (`Unavailable()` short-circuits on `Bound`, so every mid-serve
// reader still reads healthy) and the step after it pages forever on a slow
// redeploy (§2.3). The flap is tracked as its own episode instead — see
// Flapping() and noteScanSvcServeEnded — which is why this function now only
// has to record WHEN the generation bound.
func noteScanSvcBound() (recovered bool) {
	scanSvcListener.mu.Lock()
	defer scanSvcListener.mu.Unlock()
	recovered = scanSvcListener.everBound && !scanSvcListener.firstFailure.IsZero()
	scanSvcListener.bound = true
	scanSvcListener.everBound = true
	scanSvcListener.boundSince = scanSvcHealthNow()
	scanSvcListener.firstFailure = time.Time{}
	scanSvcListener.lastFailure = time.Time{}
	scanSvcListener.backoff = 0
	scanSvcListener.alerted = false
	scanSvcListener.lastClass = ""
	scanSvcListener.rebindFailures = 0
	return recovered
}

// noteScanSvcBindFailure records one failed bind attempt and returns how long
// the current episode has been running, so the caller can decide whether the
// episode has crossed the unavailability threshold.
func noteScanSvcBindFailure(class string, backoff time.Duration, now time.Time) (failingFor time.Duration) {
	scanSvcListener.mu.Lock()
	defer scanSvcListener.mu.Unlock()
	scanSvcListener.bound = false
	scanSvcListener.bindFailures++
	scanSvcListener.rebindFailures++
	scanSvcListener.lastClass = class
	scanSvcListener.backoff = backoff
	if scanSvcListener.firstFailure.IsZero() {
		scanSvcListener.firstFailure = now
	}
	scanSvcListener.lastFailure = now
	return now.Sub(scanSvcListener.firstFailure)
}

// noteScanSvcServeEnded records a serve generation that ended on its own (not
// via Shutdown), opens an unavailability episode if none is open, and advances
// or clears the flap run depending on whether the generation proved stable.
//
// `served` is how long THIS generation lasted. It decides the flap run and
// nothing else, using the same scanSvcServeStableAfter the backoff ladder
// already uses for the same judgement (scanSvcBackoffAfterServe) — one
// definition of "stable", so the ladder and the alert can never disagree about
// whether a serve counted.
//
// A generation that DID prove stable clears the run, including the latch: a
// sidecar that has worked properly for a minute is allowed to page again if it
// starts flapping later. That is the recovery path, and it is the reason the
// run is kept here rather than derived from the monotonic serveExits counter,
// which can never go down.
func noteScanSvcServeEnded(class string, served time.Duration, now time.Time) {
	scanSvcListener.mu.Lock()
	defer scanSvcListener.mu.Unlock()
	scanSvcListener.bound = false
	scanSvcListener.boundSince = time.Time{}
	scanSvcListener.serveExits++
	scanSvcListener.lastClass = class
	if scanSvcListener.firstFailure.IsZero() {
		scanSvcListener.firstFailure = now
	}
	scanSvcListener.lastFailure = now

	if served >= scanSvcServeStableAfter {
		scanSvcListener.unstableSince = time.Time{}
		scanSvcListener.unstableExits = 0
		scanSvcListener.flapAlerted = false
		return
	}
	scanSvcListener.unstableExits++
	if scanSvcListener.unstableSince.IsZero() {
		// Dated from the generation's START, not its end, so the run's age is
		// how long the sidecar has actually been unreliable rather than how
		// long ago someone noticed.
		scanSvcListener.unstableSince = now.Add(-served)
	}
}

// noteScanSvcListenerStopped records a graceful stop. Called from
// ScanService.Shutdown, which is the ONLY terminal path that must not alert:
// an operator stopping the process is not an outage.
func noteScanSvcListenerStopped() {
	scanSvcListener.mu.Lock()
	scanSvcListener.bound = false
	scanSvcListener.boundSince = time.Time{}
	scanSvcListener.stopped = true
	scanSvcListener.mu.Unlock()
}

// scanSvcListenerState returns a consistent snapshot.
func scanSvcListenerState() scanSvcListenerSnapshot {
	scanSvcListener.mu.Lock()
	defer scanSvcListener.mu.Unlock()
	snap := scanSvcListenerSnapshot{
		Configured:   scanSvcListener.configured,
		Addr:         scanSvcListener.addr,
		Bound:        scanSvcListener.bound,
		EverBound:    scanSvcListener.everBound,
		Stopped:      scanSvcListener.stopped,
		BindFailures: scanSvcListener.bindFailures,
		ServeExits:   scanSvcListener.serveExits,
		LastClass:    scanSvcListener.lastClass,
		Backoff:      scanSvcListener.backoff,

		RebindFailures: scanSvcListener.rebindFailures,
		UnstableExits:  scanSvcListener.unstableExits,
	}
	// One clock read for every derived duration, so FailingFor, ServingFor and
	// UnstableFor are all measured from the SAME instant. Three separate reads
	// would let a row say "serving for 0s" and "unstable for 31s" about two
	// different moments, which is the class of inconsistency this struct's one
	// mutex exists to prevent.
	now := scanSvcHealthNow()
	if !scanSvcListener.firstFailure.IsZero() {
		snap.FailingFor = now.Sub(scanSvcListener.firstFailure)
	}
	if !scanSvcListener.boundSince.IsZero() {
		snap.ServingFor = now.Sub(scanSvcListener.boundSince)
	}
	if !scanSvcListener.unstableSince.IsZero() {
		snap.UnstableFor = now.Sub(scanSvcListener.unstableSince)
	}
	return snap
}

// resetScanSvcHealthForTest clears the global state. Global-test cleanup per
// the repository's conventions: every test that drives this state registers it.
func resetScanSvcHealthForTest() {
	scanSvcListener.mu.Lock()
	defer scanSvcListener.mu.Unlock()
	// Field-by-field, NOT `scanSvcListener = scanSvcListenerHealth{}`: that
	// assigns a fresh zero mutex over the one this call is holding, and the
	// deferred Unlock then releases an unlocked mutex — "fatal error: sync:
	// unlock of unlocked mutex", which is unrecoverable and takes the whole
	// test binary with it. Caught by this round's own gates.
	scanSvcListener.configured = false
	scanSvcListener.addr = ""
	scanSvcListener.bound = false
	scanSvcListener.everBound = false
	scanSvcListener.stopped = false
	scanSvcListener.bindFailures = 0
	scanSvcListener.rebindFailures = 0
	scanSvcListener.serveExits = 0
	scanSvcListener.lastClass = ""
	scanSvcListener.firstFailure = time.Time{}
	scanSvcListener.lastFailure = time.Time{}
	scanSvcListener.backoff = 0
	scanSvcListener.alerted = false
	scanSvcListener.boundSince = time.Time{}
	scanSvcListener.unstableSince = time.Time{}
	scanSvcListener.unstableExits = 0
	scanSvcListener.flapAlerted = false
}

// classifyScanSvcBindError maps a bind error to a BOUNDED class.
//
// A third copy of the same errno switch socks5_health.go
// (classifySOCKS5BindError) and admin_ui_health.go
// (classifyAdminUIListenError) carry. Converging the three is a real
// improvement and deliberately NOT done here: both existing copies are
// load-bearing for hardened rows with their own tests, and a chaos round
// should not refactor two other listeners' classifiers to add a third
// listener. Recorded as the open half.
//
// The `network_error` branch requires an actual TIMEOUT. Every bind failure
// arrives as *net.OpError, which satisfies net.Error unconditionally, so an
// unqualified errors.As would swallow every unrecognised errno into a class
// naming the wrong subsystem — the defect already narrowed in both siblings.
func classifyScanSvcBindError(err error) string {
	if err == nil {
		return "none"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EADDRINUSE:
			return "port_in_use"
		case syscall.EACCES, syscall.EPERM:
			return "permission_denied"
		case syscall.EADDRNOTAVAIL:
			return "address_unavailable"
		case syscall.EMFILE, syscall.ENFILE:
			return "descriptors_exhausted"
		}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "network_error"
	}
	return "listen_failed"
}

// nextScanSvcBindBackoff advances the ladder: 1 s on the first failure,
// doubling, capped at scanSvcBindBackoffMax. Pure, so the policy is pinned
// without a clock.
func nextScanSvcBindBackoff(cur time.Duration) time.Duration {
	if cur <= 0 {
		return scanSvcBindBackoffInitial
	}
	cur *= 2
	if cur > scanSvcBindBackoffMax {
		return scanSvcBindBackoffMax
	}
	return cur
}

// scanSvcBackoffAfterServe resets the ladder once a serve has proven stable,
// and leaves it untouched otherwise. Mirrors cpGRPCBackoffAfterServe.
func scanSvcBackoffAfterServe(cur, served time.Duration) time.Duration {
	if served >= scanSvcServeStableAfter {
		return 0
	}
	return cur
}

// jitterScanSvcBackoff spreads the rebind across ±25% so a fleet restarted
// together does not retry in phase — the property internal/feedsched exists to
// hold for feed loops, applied to this listener for the same reason.
func jitterScanSvcBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	span := int64(d) / 2 // ±25% of d
	if span <= 0 {
		return d
	}
	return d*3/4 + time.Duration(rand.Int64N(span)) // #nosec G404 -- cadence spreading, not crypto
}

// superviseScanSvcListener runs the sidecar's bind → serve → rebind loop until
// ctx is cancelled or Shutdown is called.
//
// It replaces `go func() { if err := svc.Start(); err != nil { log } }()`. The
// loop is the recovery path; noteScanSvc* are the observability.
func superviseScanSvcListener(ctx context.Context, svc *ScanService) {
	noteScanSvcConfigured(svc.addr)
	var backoff time.Duration
	for {
		if ctx.Err() != nil || svc.stoppedByShutdown() {
			return
		}
		if !scanSvcBindOnce(ctx, svc, &backoff) {
			if !scanSvcWaitBackoff(ctx, svc, backoff) {
				return
			}
			continue
		}

		servedFrom := scanSvcHealthNow()
		serveErr := svc.Start()
		served := scanSvcHealthNow().Sub(servedFrom)

		if ctx.Err() != nil || svc.stoppedByShutdown() {
			// A requested stop. Shutdown already recorded it; nothing to
			// alert, nothing to rebind.
			return
		}

		class := classifyScanSvcBindError(serveErr)
		noteScanSvcServeEnded(class, served, scanSvcHealthNow())
		logger.Printf("ScanSvc: serve loop on %q ended after %s (%s): %v — rebinding",
			sanitizeLog(svc.addr), served.Round(time.Millisecond), class, serveErr)
		// CHAOS-114: the flap verdict belongs here and nowhere else. The
		// bind-failure path cannot see this fault, because the bind SUCCEEDS
		// on every cycle of it.
		maybeAlertScanSvcFlapping()
		backoff = scanSvcBackoffAfterServe(backoff, served)
		backoff = nextScanSvcBindBackoff(backoff)
		if !scanSvcWaitBackoff(ctx, svc, backoff) {
			return
		}
	}
}

// scanSvcBindOnce performs one bind attempt, recording the outcome and
// advancing the ladder on failure. It reports whether the sidecar is bound.
func scanSvcBindOnce(ctx context.Context, svc *ScanService, backoff *time.Duration) bool {
	// ctx-aware bind: a shutdown during address resolution aborts it rather
	// than parking the supervisor in the kernel while the drain budget runs.
	err := svc.listen(ctx)
	if err == nil {
		if recovered := noteScanSvcBound(); recovered {
			logger.Printf("ScanSvc: listener on %q recovered", sanitizeLog(svc.addr))
		}
		return true
	}
	if svc.stoppedByShutdown() {
		return false
	}
	class := classifyScanSvcBindError(err)
	*backoff = nextScanSvcBindBackoff(*backoff)
	failingFor := noteScanSvcBindFailure(class, *backoff, scanSvcHealthNow())
	// Logged on EVERY attempt, with no separate throttle, because the LADDER
	// is the rate limit: ~6 lines in the first 30 s and 2 lines/minute at the
	// ceiling thereafter. The siblings need a `shouldLog` CAS because their
	// producers are driven by TRAFFIC (an accept error per connection); this
	// one is driven by the retry cadence this function itself chooses, and a
	// second throttle on top would hide the escalation an operator reads to
	// tell a redeploy from an outage.
	logger.Printf("ScanSvc: bind %q failed (%s) after %s of retrying: %v — retrying in %s",
		sanitizeLog(svc.addr), class, failingFor.Round(time.Second), err, *backoff)
	maybeAlertScanSvcDown(class, failingFor)
	return false
}

// maybeAlertScanSvcDown fires the down alert once per episode, after the
// episode has crossed the unavailability threshold.
func maybeAlertScanSvcDown(class string, failingFor time.Duration) {
	if failingFor < scanSvcUnavailableAfter {
		return
	}
	scanSvcListener.mu.Lock()
	if scanSvcListener.alerted {
		scanSvcListener.mu.Unlock()
		return
	}
	scanSvcListener.alerted = true
	scanSvcListener.mu.Unlock()
	fireScanSvcListenerAlert(class)
}

// maybeAlertScanSvcFlapping fires the down alert once per FLAP run.
//
// It reuses the `scan_svc_listener_down` event with a distinct bounded detail
// rather than introducing a new one, deliberately. An operator who subscribed
// to "this node's sidecar listener cannot serve" wants to hear about a sidecar
// that binds and dies every two seconds; a separate event would leave them
// unsubscribed from the worse half of the same fault, and CHAOS-113 §8.1
// already measured what an unsubscribable event is worth — it never fires. The
// dedup key is "event:detail", so the distinct detail keeps the two causes from
// suppressing each other inside the store's 30 s window while the latch below
// keeps one page per run.
//
// Called from the SERVE-EXIT path, which is the other half of the defect: a
// flapping sidecar binds successfully every cycle, so maybeAlertScanSvcDown's
// bind-failure call site is never reached (CHAOS-114 §2.1).
func maybeAlertScanSvcFlapping() {
	if !scanSvcListenerState().Flapping() {
		return
	}
	scanSvcListener.mu.Lock()
	if scanSvcListener.flapAlerted {
		scanSvcListener.mu.Unlock()
		return
	}
	scanSvcListener.flapAlerted = true
	scanSvcListener.mu.Unlock()
	fireScanSvcListenerAlert("flapping")
}

// scanSvcWaitBackoff sleeps for d, returning false when the wait was
// interrupted by cancellation or a Shutdown (so the caller stops).
func scanSvcWaitBackoff(ctx context.Context, svc *ScanService, d time.Duration) bool {
	if svc.stoppedByShutdown() {
		return false
	}
	wait := jitterScanSvcBackoff(d)
	if wait <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return !svc.stoppedByShutdown()
	}
}

// appendScanSvcReadinessCheck adds the report-only `scan_svc` row to /ready on
// the PROXY port, completing the set alongside `socks5`, `admin_ui` and
// `cp_grpc`.
//
// REPORT-ONLY, and the reasoning is the cp_grpc row's: a node whose sidecar
// listener cannot bind is proxying its own traffic perfectly, so gating the
// default readiness verdict on it would pull a fully-functional gateway out of
// the load balancer because the plane that scans for OTHER nodes is down —
// converting a scanning outage into a traffic outage. Operators who want such
// nodes ejected opt in via /ready?strict=1.
//
// Note what that means and does not mean: report-only is the right call for
// THIS node's rotation, and it is NOT a judgement that unscanned traffic is
// acceptable. The fail-open consequence is carried by the role-gated
// operator-contract row, the alert and culvert_scan_svc_listener_up, which is
// where a security decision belongs — not by a load-balancer probe.
//
// Absent entirely on a node that never asked for a sidecar, so an ordinary
// proxy never grows a permanently-green row.
//
// The detail is a FIXED string per branch. /ready is served UNAUTHENTICATED on
// the proxy port, so the bind reason class and attempt count — which would tell
// an unauthenticated caller exactly why this node's scanning plane is down —
// stay on the role-gated row, the alert and the logs.
func appendScanSvcReadinessCheck(checks map[string]*readinessCheck) {
	snap := scanSvcListenerState()
	if !snap.Configured || snap.Stopped {
		return
	}
	switch {
	case snap.Flapping():
		// Before Flapping() existed this landed on `snap.Bound` → "ok"
		// whenever the probe arrived inside a serve generation, which is where
		// a flapping sidecar spends part of every cycle.
		checks["scan_svc"] = &readinessCheck{
			Status: "fail",
			Detail: "scan sidecar listener is flapping — see server logs",
		}
	case snap.Bound:
		checks["scan_svc"] = &readinessCheck{Status: "ok"}
	case snap.Unavailable():
		checks["scan_svc"] = &readinessCheck{
			Status: "fail",
			Detail: "scan sidecar listener is not serving — see server logs",
		}
	default:
		checks["scan_svc"] = &readinessCheck{
			Status: "fail",
			Detail: "scan sidecar listener is rebinding — see server logs",
		}
	}
}

// scanSvcHealthFieldValue is the /healthz `scan_svc` field: the status word on
// a node that asked for a sidecar, and "" (omitted) on one that did not.
//
// Mirrors mcpHealthFieldValue's omission rule rather than socks5's
// always-present field, for the reason the cp_grpc field documents: an
// always-present value would make every ordinary proxy look like a sidecar host
// whose listener is down.
func scanSvcHealthFieldValue() string {
	if !scanSvcListenerState().Configured {
		return ""
	}
	return scanSvcListenerStatus()
}

// scanSvcListenerStatus is the one-word status for /healthz and the support
// bundle. Fixed enum: disabled / stopped / flapping / down / degraded / ready.
//
// `flapping` is ordered BEFORE `down` because it is the more specific and more
// actionable of the two: "has not been serving for 30s" sent an operator
// looking for a bind problem when the truth was a sidecar that binds fine and
// then dies. It is as bounded as the other words — no address, no errno class —
// which is what keeps it suitable for this surface.
func scanSvcListenerStatus() string {
	snap := scanSvcListenerState()
	switch {
	case !snap.Configured:
		return "disabled"
	case snap.Stopped:
		return "stopped"
	case snap.Flapping():
		return "flapping"
	case snap.Unavailable():
		return "down"
	case !snap.Bound, snap.Configured && !snap.EverBound:
		return "degraded"
	default:
		return "ready"
	}
}

// checkScanSvcListener is the `scan_svc_listener` operator-contract row.
//
// Severity policy, and the one place it differs from its three siblings: a
// sidecar that is not serving is not merely an unavailable surface, it is the
// condition under which every proxy pointed at this address forwards bodies
// UNSCANNED (internal/secscan remoteScanFail, fail-open, WK-2b). The row
// therefore says so in the message, because an operator reading "scan sidecar
// down" must not have to know the far end's posture to understand that
// scanning is off.
//
//   - not configured → ok. The sidecar is opt-in; a permanent row would be noise.
//   - gracefully stopped → ok. The process is shutting down.
//   - never bound, or down past the threshold → FAIL.
//   - unbound but inside the threshold → warn. The supervisor is retrying and
//     recovers on its own, so failing here would report a self-healing state.
//   - healthy → ok, carrying the cumulative counts so a HISTORY of transient
//     faults stays visible after recovery.
func checkScanSvcListener() OperatorContractCheck {
	snap := scanSvcListenerState()
	switch {
	case !snap.Configured:
		return OperatorContractCheck{
			Code: "scan_svc_listener", Status: diagOK,
			Message: "scan sidecar not configured",
		}
	case snap.Stopped:
		return OperatorContractCheck{
			Code: "scan_svc_listener", Status: diagOK,
			Message: "scan sidecar stopped (graceful shutdown)",
		}
	case snap.Flapping():
		// Ahead of BOTH Unavailable() and !Bound: during a flap this row used
		// to read `ok` mid-serve and either `warn` or "has not been serving for
		// 30s" in the gap, and neither sentence names the fault an operator has
		// to fix.
		return scanSvcFlappingRow(snap)
	case snap.Unavailable():
		// EverBound chooses WHICH fail row and remedy, never WHETHER there is
		// one: both go through Unavailable()'s threshold. Failing a never-bound
		// sidecar on its FIRST bind failure would page on every ordinary
		// redeploy in which a draining predecessor still holds the port —
		// which is the condition CHAOS-66 added the threshold for on SOCKS5,
		// where checkSOCKS5Listener's never-bound branch is likewise gated on
		// BindUnavailable rather than on the first attempt. This round got it
		// wrong in its first form (immediate FAIL plus up=0) and the bug was
		// invisible because the only control covered the EverBound path;
		// TestChaos113_ControlNeverBoundInsideThresholdDoesNotPage is the
		// missing direction.
		if !snap.EverBound {
			return scanSvcNeverBoundRow(snap)
		}
		return scanSvcDownRow(snap)
	case !snap.Bound:
		return OperatorContractCheck{
			Code: "scan_svc_listener", Status: diagWarn,
			Message: fmt.Sprintf("scan sidecar listener on %s is rebinding (%s, %s of retrying); callers fail OPEN and forward bodies unscanned while it is down",
				snap.Addr, snap.LastClass, snap.FailingFor.Round(time.Second)),
			OperatorAction: "no action yet — the supervisor rebinds automatically; investigate if this does not clear",
		}
	}
	return OperatorContractCheck{
		Code: "scan_svc_listener", Status: diagOK,
		Message: fmt.Sprintf("scan sidecar serving on %s (%d bind failure(s), %d serve exit(s) since startup)",
			snap.Addr, snap.BindFailures, snap.ServeExits),
	}
}

// scanSvcFlappingRow is the row for a sidecar that binds and then dies, over
// and over. It is the only row here that reports a fault the socket's CURRENT
// state cannot show, so it leads with the rate rather than with a duration.
//
// The remedy deliberately does NOT route through scanSvcBindRemedy: every
// string there is about a bind that failed, and in this fault the bind
// SUCCEEDED every time. Sending an operator to check `scan_svc.listen` for a
// port conflict when the port is bindable on every cycle is the wrong page.
func scanSvcFlappingRow(snap scanSvcListenerSnapshot) OperatorContractCheck {
	return OperatorContractCheck{
		Code: "scan_svc_listener", Status: diagFail,
		Message: fmt.Sprintf("scan sidecar on %s is FLAPPING — it has bound and died %d time(s) over %s, with no serve generation lasting %s; every caller pointed here is forwarding bodies UNSCANNED (fail-open) through every gap",
			snap.Addr, snap.UnstableExits, snap.UnstableFor.Round(time.Second), scanSvcServeStableAfter),
		OperatorAction: "the address binds and the serve then ends, so this is the sidecar process, not the port — check its log for a scanner-engine init failure (ClamAV socket, YARA rule compile), an OOM kill or a supervisor restart loop, and culvert_scan_svc_serve_exits_total for the rate",
	}
}

// scanSvcNeverBoundRow is the row for an address that has never bound in this
// process — the boot-time case that used to be one log line and silence.
func scanSvcNeverBoundRow(snap scanSvcListenerSnapshot) OperatorContractCheck {
	return OperatorContractCheck{
		Code: "scan_svc_listener", Status: diagFail,
		Message: fmt.Sprintf("scan sidecar has NEVER bound %s (%s) after %s of retrying (%d attempts) — every caller pointed here is forwarding bodies UNSCANNED (fail-open)",
			snap.Addr, snap.LastClass, snap.FailingFor.Round(time.Second), snap.BindFailures),
		OperatorAction: scanSvcBindRemedy(snap.LastClass, snap.Addr),
	}
}

// scanSvcDownRow is the row for a sidecar that bound once and is now down past
// the unavailability threshold.
func scanSvcDownRow(snap scanSvcListenerSnapshot) OperatorContractCheck {
	return OperatorContractCheck{
		Code: "scan_svc_listener", Status: diagFail,
		Message: fmt.Sprintf("scan sidecar on %s has not been serving for %s (%s; %d serve exit(s)) — every caller pointed here is forwarding bodies UNSCANNED (fail-open)",
			snap.Addr, snap.FailingFor.Round(time.Second), snap.LastClass, snap.ServeExits),
		OperatorAction: scanSvcBindRemedy(snap.LastClass, snap.Addr),
	}
}

// scanSvcBindRemedy maps a bounded bind class to the operator action for it.
func scanSvcBindRemedy(class, addr string) string {
	switch class {
	case "port_in_use":
		return fmt.Sprintf("another process holds %s — stop it, or set a different scan_svc.listen", addr)
	case "permission_denied":
		return fmt.Sprintf("the process may not bind %s — use a port above 1024 or grant CAP_NET_BIND_SERVICE", addr)
	case "address_unavailable":
		return fmt.Sprintf("the interface in %s does not exist on this host — correct scan_svc.listen", addr)
	case "descriptors_exhausted":
		return "the process is out of file descriptors — raise LimitNOFILE and investigate the leak"
	}
	return fmt.Sprintf("check scan_svc.listen (%s) and the process log for the bind error", addr)
}
