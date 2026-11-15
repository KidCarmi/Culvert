package main

// chaos118_worker_guard_lockpairing_test.go — CHAOS-118.
//
// CHAOS-116 §8.2 listed five `go`-detached background rounds still outside
// CHAOS-24's per-iteration panic guard, and CHAOS-117 §8.2 carried the list
// forward unchanged. Go terminates the process on an unrecovered panic in ANY
// goroutine, so each of them was a total outage of an in-line security gateway
// — every in-flight tunnel dropped — triggered by a fault in a round that, in
// three of the five cases, exists only to REPORT on the thing it killed.
//
// This round closes all five. The interesting half is not the guard, it is the
// pairing rule CHAOS-117 §8.2a established and this round had to apply four
// more times:
//
//	A guard added over a critical section that releases its lock with a
//	TRAILING Unlock is strictly WORSE than the crash it replaces.
//
// The panic is then contained into a permanently held mutex: no crash, no
// restart, no alert, and no recovery path at all. Two of the five rounds had
// exactly that shape, in locks that sit on live paths —
// `syslogHealth.mu` is taken by the delivery observer on the LOGGING path,
// `/healthz` and the diagnostics surfaces; `idpServedMu` is taken by every IdP
// metadata publish and by retirement; `idpMetadata.mu` by the fetch path.
//
// The fix is NOT a function-level `defer` in either case, and that is the
// second half of the rule: both functions do work AFTER the release that must
// not hold the lock (commitSyslogDegradation dispatches an alert that reaches a
// webhook; idpStaleCeilingSweep's result is acted on with the lock released,
// because retirement takes the registry write lock). Promoting the release to
// the function scope would hold one subsystem's lock into another's call — the
// CHAOS-50 cluster-CA inversion. So each critical section is SCOPED, with a
// deferred release inside the scope, and the released-before-alert boundary is
// unchanged.
//
// Coverage is in three parts:
//
//  1. behavioural containment and lock-release, driven through the injectable
//     alert seams, for the two rounds that carried the §8.2a trap. Each fails
//     by DETECTING and REPORTING the stall on a deadline rather than hanging
//     the test binary, which is the correct report for a silent wedge.
//  2. a source gate over the four refactored critical sections, so a future
//     edit cannot reintroduce a bare trailing Unlock underneath a guard.
//  3. the fail-closed reading of the one round whose caller BRANCHES on its
//     result: a panicked Root CA recovery attempt must be charged as a FAILED
//     attempt, never as "an operator already fixed it" or "recovered".

import (
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/idpmeta"
)

// chaos118ProbeDeadline bounds every lock probe and bounded-reset below. Long
// enough that a loaded shared CI runner cannot flake it, short enough that a
// genuine wedge is REPORTED rather than waited on.
const chaos118ProbeDeadline = 10 * time.Second

// chaos118ProbeLock reports whether the lock could be acquired within the
// deadline. It probes from another goroutine and returns a verdict instead of
// calling t.Fatal, which matters because every mutex it is pointed at is a
// PACKAGE-level global: a wedged one would otherwise deadlock this test's own
// t.Cleanup and hang the whole binary with no diagnosis — the exact silent
// stall these tests exist to report. On a false verdict the caller reports and
// returns early, leaving the probe goroutine parked on a lock the process has
// already been shown to have broken.
func chaos118ProbeLock(t *testing.T, name string, lock func(), unlock func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		lock()
		unlock()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(chaos118ProbeDeadline):
		t.Errorf("%s is still held after a contained panic: the guard converted a loud crash into a permanent silent stall of every path that takes it", name)
		return false
	}
}

// chaos118BoundedReset runs a global-state reset that TAKES one of the probed
// locks, giving up on the deadline instead of blocking forever. Registered as
// the cleanup so a failing run of these tests still terminates: in the mutant
// world the lock is wedged, so the reset can never complete and a plain
// t.Cleanup(reset) would convert a clean failure into a hung package.
func chaos118BoundedReset(t *testing.T, name string, reset func()) {
	done := make(chan struct{})
	go func() { reset(); close(done) }()
	select {
	case <-done:
	case <-time.After(chaos118ProbeDeadline):
		t.Logf("%s could not be reset: the lock is wedged, so later tests touching it will fail on the same lock", name)
	}
}

// ── 1. containment + lock release, driven behaviourally ─────────────────────

// TestCHAOS118_SyslogWatchdogRoundPanicDoesNotWedgeTheHealthRecord is the
// §8.2a pairing gate for the syslog plane, and the fault is injected INSIDE the
// critical section on purpose.
//
// That placement is the whole point of the test. A panic that happens after the
// release cannot distinguish the fix from the defect, and neither can one
// contained by a FUNCTION-level defer, because deferred calls still run while a
// panic unwinds. The §8.2a trap is specifically a panic raised BETWEEN a Lock
// and a trailing, non-deferred Unlock: that is the shape that leaks the mutex,
// and the only shape that does. So the fault has to land there.
//
// The injected fault is the real one: a nil Writer handle on the retirement
// list makes settleRetiredSyslogWritersLocked nil-dereference at
// `r.w.CumulativeStats()` while `syslogHealth.mu` is held — the same nil-VALUE
// class CHAOS-117 fixed in the cluster roster, in a list this process builds
// itself. Pre-fix that panic killed the gateway. With a guard but a trailing
// Unlock it leaves syslogHealth.mu held forever, wedging the delivery observer
// on the LOGGING path, `/healthz` and the diagnostics row — no crash, no
// restart, no alert.
func TestCHAOS118_SyslogWatchdogRoundPanicDoesNotWedgeTheHealthRecord(t *testing.T) {
	resetCrashGuardStateForTest()
	resetSyslogHealthForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	t.Cleanup(func() { chaos118BoundedReset(t, "syslogHealth", resetSyslogHealthForTest) })

	// A nil handle on the retirement list: settleRetiredSyslogWritersLocked
	// walks it under syslogHealth.mu and calls a method on every entry.
	syslogHealth.mu.Lock()
	syslogHealth.retiring = append(syslogHealth.retiring, retiringSyslogWriter{w: nil})
	syslogHealth.mu.Unlock()

	if panicked := runGuarded(crashComponentSyslogHealth, evaluateSyslogDegradation); !panicked {
		t.Fatal("the round did not panic — this test no longer exercises containment; re-derive the injected fault")
	}

	// The lock must be free. A direct Lock() would hang the test binary with no
	// diagnosis, so probe it on a deadline and report the stall instead.
	if !chaos118ProbeLock(t, "syslogHealth.mu",
		func() { syslogHealth.mu.Lock() }, func() { syslogHealth.mu.Unlock() }) {
		return // wedged: every assertion below would block on the same lock
	}

	// Unlocked is not enough: the record must still be READABLE, which is what
	// every surface depends on. Clear the poison first — this asserts
	// recoverability, not that a nil handle becomes harmless.
	syslogHealth.mu.Lock()
	syslogHealth.retiring = nil
	syslogHealth.mu.Unlock()
	_ = syslogFeedState()

	// And the crash is observable rather than silent.
	if rec, ok := lastCrashSnapshot(); !ok || rec.Component != crashComponentSyslogHealth {
		t.Errorf("contained syslog watchdog panic was not recorded under %q (got %+v, stored=%v)",
			crashComponentSyslogHealth, rec, ok)
	}
}

// TestCHAOS118_IdPWatchdogRoundPanicDoesNotWedgeTheMetadataLocks is the §8.2a
// pairing gate for the IdP metadata plane, which holds TWO locks across the
// round: `idpMetadata.mu` (the degradation sweep) and `idpServedMu` (the
// staleness-ceiling sweep). Both released with a trailing Unlock before this
// round. The panic is injected in the alert, which the round reaches with both
// sweeps' locks already released — so a stall here is unambiguously a leaked
// lock rather than a lock still legitimately held.
func TestCHAOS118_IdPWatchdogRoundPanicDoesNotWedgeTheMetadataLocks(t *testing.T) {
	resetCrashGuardStateForTest()
	resetIdPMetadataHealthForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	t.Cleanup(func() { chaos118BoundedReset(t, "idpMetadata", resetIdPMetadataHealthForTest) })

	// The fault is injected in the RETIREMENT, not the alert, so that both
	// sweeps have actually run before the round panics: an alert-side panic
	// aborts the round before the ceiling sweep ever acquires idpServedMu, and
	// probing a lock that was never taken proves nothing at all.
	//
	// BE PRECISE ABOUT WHAT THIS PROVES. The probes show the round as a whole
	// leaks neither lock, and the counter assertions below keep that from being
	// vacuous. They do NOT discriminate a deferred release from a trailing one,
	// because neither sweep has an injectable call inside its critical section
	// — both iterate their own in-memory state, and idpStaleCeilingSweep's only
	// in-section call is a method on a VALUE — so a sweep that returns normally
	// runs its trailing Unlock either way. The deferred release in these two
	// sweeps is pinned by TestCHAOS118_GuardedRoundCriticalSectionsReleaseDeferred
	// instead, which is mutation-validated. The syslog gate above does not have
	// this gap: its fault lands inside the section.
	var alerts, retires int
	prevAlert := fireIdPMetadataAlert
	fireIdPMetadataAlert = func(string) { alerts++ }
	t.Cleanup(func() { fireIdPMetadataAlert = prevAlert })

	prevRetire := idpRetireStaleProvider
	idpRetireStaleProvider = func(string, string, time.Time) bool {
		retires++
		panic("idp stale-provider retirement exploded")
	}
	t.Cleanup(func() { idpRetireStaleProvider = prevRetire })

	now := time.Now()
	// Seed BOTH halves of the round: an episode past the degradation threshold
	// (so the degradation sweep takes idpMetadata.mu and selects it) and a
	// served document past the staleness ceiling (so the ceiling sweep takes
	// idpServedMu and selects it).
	seed := func() {
		idpMetadata.mu.Lock()
		ep := idpMetadataEpisodeLocked(idpEpisodeKey("corp", chaos87Ref(chaos87Source("corp"))))
		ep.firstFailure = now.Add(-2 * idpMetadataDegradedAfter)
		ep.alerted = false
		ep.lastOutcome = idpMetaUnavailable
		idpMetadata.mu.Unlock()

		idpServedMu.Lock()
		if idpServed == nil {
			idpServed = make(map[string]idpServedDoc)
		}
		idpServed["corp"] = idpServedDoc{
			source:    chaos87Source("corp"),
			fetchedAt: now.Add(-2 * idpmeta.StaleMaxAge), // past the ceiling
		}
		idpServedMu.Unlock()
	}
	seed()

	if panicked := runGuarded(crashComponentIdPMetadataWatchdog, func() {
		idpMetadataDegradationWatchdogRound(t.Context())
	}); !panicked {
		t.Fatal("the round did not panic — this test no longer exercises containment; re-derive the injected fault")
	}
	// Both sweeps must actually have run, or the probes below are vacuous: a
	// round that selected nothing never takes either lock, and the test would
	// pass no matter how those locks are released.
	if alerts == 0 {
		t.Fatal("the degradation sweep selected nothing, so idpMetadata.mu was never taken and its probe proves nothing; re-derive the seeded episode")
	}
	if retires == 0 {
		t.Fatal("the ceiling sweep selected nothing, so idpServedMu was never taken and its probe proves nothing; re-derive the seeded served document")
	}

	metaFree := chaos118ProbeLock(t, "idpMetadata.mu",
		func() { idpMetadata.mu.Lock() }, func() { idpMetadata.mu.Unlock() })
	servedFree := chaos118ProbeLock(t, "idpServedMu",
		func() { idpServedMu.Lock() }, func() { idpServedMu.Unlock() })
	if !metaFree || !servedFree {
		return // wedged: every assertion below would block on the same lock
	}

	if rec, ok := lastCrashSnapshot(); !ok || rec.Component != crashComponentIdPMetadataWatchdog {
		t.Errorf("contained IdP watchdog panic was not recorded under %q (got %+v, stored=%v)",
			crashComponentIdPMetadataWatchdog, rec, ok)
	}

	// Self-heal: with the fault cleared the very next round must do real work
	// again. This is the property a goroutine-level recover would destroy —
	// the watchdog is the SUPERVISOR that re-arms IdP recovery, so a loop that
	// returned would leave SSO down with nothing retrying it.
	idpRetireStaleProvider = func(string, string, time.Time) bool {
		retires++
		return false // selected, but decline to retire: keeps this test out of the registry
	}
	beforeAlerts, beforeRetires := alerts, retires
	seed()
	idpMetadataDegradationWatchdogRound(t.Context())
	if alerts <= beforeAlerts || retires <= beforeRetires {
		t.Errorf("the watchdog round did not fully resume once the fault cleared (alerts %d->%d, retires %d->%d) — containment must cost one interval, not the worker",
			beforeAlerts, alerts, beforeRetires, retires)
	}
}

// ── 2. the pairing rule, pinned at the source ───────────────────────────────

// chaos118DeferredReleases are the critical sections this round rescoped. Each
// is reached from a now-guarded detached round, so each must release its lock
// through a `defer` — a bare trailing Unlock under a guard is the §8.2a
// inversion, and it cannot be caught behaviourally for every section without a
// fault injected into each one's production dependencies.
var chaos118DeferredReleases = []struct {
	file   string
	fn     string
	defers string // the exact deferred release that must be present
	bare   string // the trailing release that must NOT reappear
}{
	{"syslog_health.go", "commitSyslogDegradation", "defer syslogHealth.mu.Unlock()", "syslogHealth.mu.Unlock()"},
	{"syslog_health.go", "syslogFeedState", "defer syslogHealth.mu.Unlock()", "syslogHealth.mu.Unlock()"},
	{"idp_metadata_health.go", "idpMetadataDegradationSweep", "defer idpMetadata.mu.Unlock()", "idpMetadata.mu.Unlock()"},
	{"idp_metadata_health.go", "idpStaleCeilingSweep", "defer idpServedMu.Unlock()", "idpServedMu.Unlock()"},
}

func TestCHAOS118_GuardedRoundCriticalSectionsReleaseDeferred(t *testing.T) {
	for _, c := range chaos118DeferredReleases {
		t.Run(c.fn, func(t *testing.T) {
			body := funcSource(t, c.file, c.fn)
			if !strings.Contains(body, c.defers) {
				t.Errorf("%s does not release its lock with %q: it is reached from a panic-guarded detached round, so a contained panic would hold the lock forever — a silent permanent stall in place of a crash",
					c.fn, c.defers)
			}
			for _, line := range strings.Split(body, "\n") {
				if strings.TrimSpace(line) == c.bare {
					t.Errorf("%s still has a bare trailing %q: under a guard this is the CHAOS-117 §8.2a inversion, strictly worse than the crash it replaces",
						c.fn, c.bare)
				}
			}
		})
	}
}

// TestCHAOS118_NewlyGuardedWorkersDoNotRecoverAtGoroutineLevel pins the OTHER
// half of runGuarded's contract for the five loops this round added. A recover
// at the top of the goroutine would let the worker RETURN on a panic, turning
// a loud crash into a silent permanent stall with every surface still green.
// Two of these five make that inversion actively dangerous: the IdP watchdog
// is the supervisor that re-arms IdP recovery, and the Root CA recovery loop is
// the only thing that re-enables SSL inspection after a failed bundle load.
func TestCHAOS118_NewlyGuardedWorkersDoNotRecoverAtGoroutineLevel(t *testing.T) {
	for _, w := range []struct{ file, fn string }{
		{"syslog_health.go", "startSyslogHealthWatchdog"},
		{"idp_metadata_health.go", "runIdPMetadataDegradationWatchdog"},
		{"rootca_recovery.go", "runInspectionCARecoveryLoop"},
		{"mcp_telemetry.go", "flushLoop"},
		{"mcp_telemetry.go", "exportLoop"},
	} {
		t.Run(w.fn, func(t *testing.T) {
			body := funcSource(t, w.file, w.fn)
			if strings.Contains(body, "recover()") {
				t.Errorf("%s recovers inside the worker itself: containment is per-ROUND via runGuarded, never per-goroutine — a goroutine-level recover makes the loop exit on the first panic and it never runs again",
					w.fn)
			}
			if !strings.Contains(body, "runGuarded(") {
				t.Errorf("%s runs its round unguarded: an unrecovered panic in ANY goroutine terminates the gateway", w.fn)
			}
		})
	}
}

// ── 3. the one round whose caller branches on its result ────────────────────

// TestCHAOS118_CARecoveryPanicIsChargedAsAFailedAttempt pins the fail-closed
// reading of the Root CA recovery loop, the one newly-guarded round where
// "keep going" is NOT the default answer. Both of its exits are terminal:
// `!attempted` means an operator already recovered the CA by hand, and
// `err == nil` means recovery succeeded. A contained panic is neither, so
// inheriting the zero values would pick one of them — silently abandoning the
// retry budget, or declaring SSL inspection recovered while it stays disabled
// and inspect-matched TLS is forwarded uninspected.
//
// This is a source gate because tryInspectionCARecovery is called directly
// rather than through a seam: the loop takes no injectable attempt function, so
// the branch cannot be driven without widening production code for the test.
// It asserts the shape of the panic branch, which is the property at issue.
func TestCHAOS118_CARecoveryPanicIsChargedAsAFailedAttempt(t *testing.T) {
	body := funcSource(t, "rootca_recovery.go", "runInspectionCARecoveryLoop")

	guard := strings.Index(body, "runGuarded(crashComponentInspectionCARecovery")
	if guard < 0 {
		t.Fatal("runInspectionCARecoveryLoop no longer guards its attempt under crashComponentInspectionCARecovery")
	}
	// The panic branch must charge a FAILED attempt: attempted true (so the
	// loop does not take the operator-recovered exit) and err non-nil (so it
	// does not take the success exit).
	branch := body[guard:]
	end := strings.Index(branch, "if !attempted")
	if end < 0 {
		t.Fatal("the attempted/err branch structure changed; re-derive this gate against the current loop")
	}
	branch = branch[:end]
	if !strings.Contains(branch, "attempted = true") {
		t.Error("a contained Root CA recovery panic does not set attempted = true: the loop would take the 'an operator recovered it' exit and silently abandon the retry budget while SSL inspection stays disabled")
	}
	if !strings.Contains(branch, "err = fmt.Errorf(") {
		t.Error("a contained Root CA recovery panic does not synthesise an error: with err nil the loop returns as if recovery SUCCEEDED, leaving SSL inspection disabled and inspect-matched TLS forwarded uninspected")
	}
	// And it must not short-circuit the loop itself.
	if strings.Contains(branch, "return") {
		t.Error("the contained-panic branch returns from the recovery loop: a panicking attempt must be retried on backoff, not treated as terminal")
	}
}
