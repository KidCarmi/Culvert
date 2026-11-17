package main

// auth_cost_health.go — CHAOS-57: credential verification as a bounded,
// observable resource.
//
// Why this file exists.
//
// `internal/authcost` bounds how much CPU a presented proxy credential may
// consume; this file is the composition-root half — the singleton, the two
// wrappers the authentication path calls, and the observability plane that
// makes a fail-closed refusal something an operator can see.
//
// The defect the governor closes is recorded in full in the package comment.
// The short version, all measured on the pre-fix tree (4 cores):
//
//	one wrong-username proxy-auth attempt   79.6 ms of exclusive CPU
//	one cached successful authentication     1.5 µs
//	amplification                           51,631x
//	rate that saturates all four cores      66 req/s (~13 KB/s on the wire)
//	degradation to other CPU work           15.6x, at 64 attacker connections
//
// reachable with no credentials, no knowledge of the deployment, and — because
// the connection limiter, the request rate limiter and the IP filter all ship
// DISABLED — nothing in front of it in the shipped default posture.
//
// # Why a refusal has to be loud
//
// A refusal DENIES an authentication attempt whose credential was never
// checked. That is the fail-closed direction and it is the right one, but it
// means the governor can deny a VALID credential when it is saturated. If that
// were silent, the operator-visible symptom would be "some users intermittently
// get 407" with a perfectly healthy directory, a perfectly healthy proxy, and
// nothing anywhere saying why — which is the silent-failure class this whole
// review series exists to remove.
//
// So every refusal is counted by reason, saturation is a gauge, the first
// refusal of an episode is logged immediately and then rate-limited, and a
// sustained episode fires one alert. The vocabulary is the existing one:
// counters + an evidence-cleared gauge + an operator-contract row + a
// HasSubscriber-gated alert, exactly as storage_health.go, ca_health.go,
// auth_backend_health.go and socks5_health.go do it.
//
// # Recovery needs evidence of BOTH halves
//
// The episode clears only when a verification is admitted ON THE FAST PATH
// (with a slot free and no queueing) AND no refusal has been recorded for
// authCostRecoveryQuiet.
//
// Neither half is sufficient. A queued admission means the ceiling was still
// full and the caller only got in because somebody else finished. And a fast
// admission on its own proves a slot was free at that instant, nothing more —
// during a sustained flood that is true constantly, so clearing on it alone
// restarted the episode every ~80 ms and the saturation alert could never fire
// for the attack this governor exists to expose (Codex review, PR #1328). The
// quiet window supplies the missing half: that the refusals themselves have
// stopped.
//
// Elapsed time alone still never clears anything — an admission is required, so
// a gateway nobody is authenticating against stays reported as refusing rather
// than being declared healthy by silence. That is the ca_health.go /
// storage_health.go rule, with the evidence corrected to match the fault.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/authcost"
)

const (
	// authCostLogInterval rate-limits the refusal log line. Under a credential
	// flood the refusal repeats at machine speed, so the log carries the
	// SIGNAL (onset, recovery, and the suppressed count) while the counters
	// carry the MAGNITUDE — the storage_health.go discipline.
	authCostLogInterval = 30 * time.Second

	// authCostDegradedAfter is how long refusals must persist before the
	// episode is reported degraded and alerted. Degradation is a DURATION and
	// not a count for CHAOS-54's reason: a handful of refusals during a
	// legitimate synchronised burst (a fleet whose cached results expired
	// together) is exactly the transient the bounded queue exists to absorb,
	// and paging on it would page on a healthy appliance.
	authCostDegradedAfter = 30 * time.Second

	// authCostAlertInterval bounds re-alerting within one long episode. The
	// fire-once latch below is the primary control; this is the backstop for
	// an episode that clears and re-arms repeatedly.
	authCostAlertInterval = 5 * time.Minute

	// authCostRecoveryQuiet is how long refusals must have STOPPED before an
	// admission is accepted as recovery. See noteAuthCostAdmitted for why an
	// admission alone is not sufficient evidence.
	//
	// It sits between the two timescales that matter: comfortably longer than
	// the governor's own wait budget (a client that times out once per second
	// keeps the episode alive), and far shorter than authCostDegradedAfter, so
	// a genuine recovery is reported long before the degradation threshold
	// would have been crossed.
	authCostRecoveryQuiet = 5 * time.Second
)

// globalAuthCostGate is the process-wide credential-verification governor.
//
// It is constructed eagerly at package init rather than wired through a
// startup slice, and that is deliberate: an unconstructed gate would have to
// fail OPEN (there is nothing to ask), so a wiring mistake would silently
// restore the unbounded behaviour. Its bounds are derived from GOMAXPROCS and
// need no configuration, so there is nothing for a startup slice to resolve.
var globalAuthCostGate = authcost.New(0, 0, 0)

// authCostHealth is the process-wide record of the governor's refusal episodes.
// Mutex-guarded rather than atomic-per-field because every reporting surface
// needs a consistent view across all of it.
type authCostHealthRecord struct {
	mu sync.Mutex

	// firstRefusal starts the current episode; zero when nothing is being
	// refused. Degradation is measured from here, so an appliance that refuses,
	// recovers, and refuses again never accumulates toward the threshold across
	// healthy periods.
	firstRefusal time.Time
	lastRefusal  time.Time
	lastReason   string

	// logAt gates the log line; suppressed counts what the gate swallowed since
	// the last emitted line so the recovery line can state it.
	logAt      time.Time
	suppressed int64

	// alerted is a fire-once latch per episode: one page when credential
	// verification starts refusing persistently, not one per denied request.
	// Cleared by observed evidence of recovery.
	alerted  bool
	alertAt  time.Time
	episodes int64
}

var authCostHealth authCostHealthRecord

// authCostEverRefused short-circuits the recovery observer until the first
// refusal, so an admitted verification on a healthy appliance costs one atomic
// load rather than a mutex acquire (the storageEverFailed pattern). Credential
// verification is not a benchgate hot path — it is about to spend 80 ms in
// bcrypt — but the fault plane must not tax the healthy plane.
var authCostEverRefused atomic.Bool

// Cumulative counters. Separate from the engine's own Stats so the metrics
// surface can be read without taking the gate's mutex on every scrape, and so
// a future gate swap in a test cannot rewrite process history.
var (
	authCostRefusedTotal     atomic.Int64
	authCostRefusedPerClient atomic.Int64
	authCostRefusedQueueFull atomic.Int64
	authCostRefusedTimeout   atomic.Int64
	authCostAdmittedTotal    atomic.Int64
	authCostWaitedTotal      atomic.Int64
)

// fireAuthCostAlert delivers the `auth_verify_saturated` alert.
//
// Package-level seam so tests observe transitions SYNCHRONOUSLY instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI determinism gate catches). HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the
// default posture, and the state of every test binary — this must not spawn a
// goroutine at all.
var fireAuthCostAlert = func(detail string) {
	if !alertStore().HasSubscriber("auth_verify_saturated") {
		return
	}
	go fireAlert("auth_verify_saturated", AlertPayload{
		Detail: detail,
		Source: "auth",
	})
}

// authCostAdmit asks the governor for permission to run one bcrypt comparison
// on behalf of client, and reports whether it was granted.
//
// The caller MUST call authCostRelease(client) on every path out of a granted
// admission, including panics — use `defer`.
//
// CRITICAL CALLER CONTRACT: the decision must be taken BEFORE the presented
// username is compared against the configured one, and must not depend on it
// in any way. RISK-008 equalises the wrong-username and wrong-password paths
// so that neither is distinguishable by timing; a gate consulted only on one
// of them — or consulted with a budget that differed between them — would hand
// back exactly the username-enumeration oracle that equalisation removed. See
// verifyAuthFrom in store.go, where this is pinned by test.
func authCostAdmit(client string) bool {
	r, queued := globalAuthCostGate.Admit(client)
	if r != authcost.Admitted {
		noteAuthCostRefused(r)
		return false
	}
	authCostAdmittedTotal.Add(1)
	if queued {
		authCostWaitedTotal.Add(1)
	}
	noteAuthCostAdmitted(queued)
	return true
}

// authCostRelease returns a slot taken by a granted authCostAdmit.
func authCostRelease(client string) { globalAuthCostGate.Release(client) }

// noteAuthCostRefused records one fail-closed refusal.
//
// reason is the engine's BOUNDED classification, never a free-form string: it
// reaches a metric label and the alert's dedup key, and an unbounded value
// there is the WK-12/RS-5 defect (Dispatch dedups on event+Detail, so a
// per-request-distinct detail defeats the 30 s window by construction and
// evicts real threat alerts from the retry queue).
func noteAuthCostRefused(reason authcost.Refusal) {
	authCostEverRefused.Store(true)
	authCostRefusedTotal.Add(1)
	switch reason {
	case authcost.RefusedPerClient:
		authCostRefusedPerClient.Add(1)
	case authcost.RefusedQueueFull:
		authCostRefusedQueueFull.Add(1)
	case authcost.RefusedTimeout:
		authCostRefusedTimeout.Add(1)
	case authcost.Admitted:
		// Not a refusal; recorded here only so the switch is exhaustive.
		return
	}

	now := time.Now()
	authCostHealth.mu.Lock()
	if authCostHealth.firstRefusal.IsZero() {
		authCostHealth.firstRefusal = now
		authCostHealth.episodes++
	}
	authCostHealth.lastRefusal = now
	authCostHealth.lastReason = reason.String()

	shouldLog := false
	if authCostHealth.logAt.IsZero() || now.Sub(authCostHealth.logAt) >= authCostLogInterval {
		authCostHealth.logAt = now
		shouldLog = true
	} else {
		authCostHealth.suppressed++
	}

	degraded := now.Sub(authCostHealth.firstRefusal) >= authCostDegradedAfter
	alertNow := degraded && (!authCostHealth.alerted ||
		now.Sub(authCostHealth.alertAt) >= authCostAlertInterval)
	if alertNow {
		authCostHealth.alerted = true
		authCostHealth.alertAt = now
	}
	since := now.Sub(authCostHealth.firstRefusal)
	authCostHealth.mu.Unlock()

	total := authCostRefusedTotal.Load()
	if shouldLog {
		s := globalAuthCostGate.Stats()
		logger.Printf("AUTH_VERIFY_REFUSED reason=%s in_flight=%d/%d queued=%d refused_total=%d {action=deny}",
			reason.String(), s.InFlight, s.MaxConcurrent, s.Queued, total)
	}
	if alertNow {
		fireAuthCostAlert(fmt.Sprintf(
			"Credential verification has been refusing authentication attempts for over %s (%d refused since boot; most recent reason: %s). "+
				"Proxy authentication is failing closed for affected clients — valid credentials may be denied.",
			since.Round(time.Second), total, reason.String()))
	}
}

// noteAuthCostAdmitted records an admission and clears a refusal episode when
// — and only when — the admission is evidence that the episode is over.
//
// TWO conditions, and both are load-bearing.
//
//  1. The admission came on the FAST path. A queued admission means the ceiling
//     was still fully occupied and the caller only got in because somebody else
//     finished; capacity has not returned.
//
//  2. No refusal has been recorded for authCostRecoveryQuiet. A fast admission
//     on its own proves a slot was free AT THAT INSTANT — nothing more — and
//     during a sustained flood that is true constantly: every in-flight bcrypt
//     eventually releases its slot, so some arrival wins the fast path roughly
//     once per comparison while its siblings keep being refused. Clearing on
//     that alone made the episode restart every ~80 ms, so it could never reach
//     authCostDegradedAfter: the contract row flapped between "refusing" and
//     "recovered", an AUTH_VERIFY_RECOVERED line was emitted per comparison,
//     and `auth_verify_saturated` would NEVER have fired for the very attack
//     this governor exists to expose. (Codex review, PR #1328.)
//
// The quiet window is not "recovery on elapsed time" — the house rule this
// file follows elsewhere. Elapsed time alone never clears anything here: an
// ADMISSION is still required, so a gateway nobody is authenticating against
// stays reported as refusing. The window only adds the second half of the
// evidence, that the refusals themselves have stopped.
func noteAuthCostAdmitted(queued bool) {
	if queued || !authCostEverRefused.Load() {
		return
	}
	authCostHealth.mu.Lock()
	if authCostHealth.firstRefusal.IsZero() {
		authCostHealth.mu.Unlock()
		return
	}
	if time.Since(authCostHealth.lastRefusal) < authCostRecoveryQuiet {
		// Refusals are still happening; this admission says only that one slot
		// happened to be free.
		authCostHealth.mu.Unlock()
		return
	}
	suppressed := authCostHealth.suppressed
	since := time.Since(authCostHealth.firstRefusal)
	authCostHealth.firstRefusal = time.Time{}
	authCostHealth.suppressed = 0
	authCostHealth.logAt = time.Time{}
	authCostHealth.alerted = false
	authCostHealth.mu.Unlock()

	logger.Printf("AUTH_VERIFY_RECOVERED credential verification has spare capacity again after %s (%d refusal log line(s) suppressed during the episode)",
		since.Round(time.Second), suppressed)
}

// authCostStatus is the lock-free view handed to the reporting surfaces.
type authCostStatus struct {
	MaxConcurrent int
	MaxPerClient  int
	InFlight      int
	Queued        int
	PeakInFlight  int
	PeakQueued    int

	Admitted         int64
	Waited           int64
	Refused          int64
	RefusedPerClient int64
	RefusedQueueFull int64
	RefusedTimeout   int64

	// Degraded is true while a refusal episode has persisted past the
	// degradation threshold. Refusing is true for any live episode.
	Degraded    bool
	Refusing    bool
	LastReason  string
	Last        time.Time
	RefusingFor time.Duration
	Episodes    int64
	Saturated   bool
}

// authCostHealthStatus snapshots the governor for /metrics, /api/diagnostics
// and the tests. Side-effect-free: it never probes and never mutates.
func authCostHealthStatus() authCostStatus {
	s := globalAuthCostGate.Stats()
	st := authCostStatus{
		MaxConcurrent:    s.MaxConcurrent,
		MaxPerClient:     s.MaxPerClient,
		InFlight:         s.InFlight,
		Queued:           s.Queued,
		PeakInFlight:     s.PeakInFlight,
		PeakQueued:       s.PeakQueued,
		Admitted:         authCostAdmittedTotal.Load(),
		Waited:           authCostWaitedTotal.Load(),
		Refused:          authCostRefusedTotal.Load(),
		RefusedPerClient: authCostRefusedPerClient.Load(),
		RefusedQueueFull: authCostRefusedQueueFull.Load(),
		RefusedTimeout:   authCostRefusedTimeout.Load(),
		Saturated:        globalAuthCostGate.Saturated(),
	}

	authCostHealth.mu.Lock()
	defer authCostHealth.mu.Unlock()
	st.LastReason = authCostHealth.lastReason
	st.Last = authCostHealth.lastRefusal
	st.Episodes = authCostHealth.episodes
	if !authCostHealth.firstRefusal.IsZero() {
		st.Refusing = true
		st.RefusingFor = time.Since(authCostHealth.firstRefusal)
		st.Degraded = st.RefusingFor >= authCostDegradedAfter
	}
	return st
}

// resetAuthCostHealthForTest restores the process-global record so a test that
// drives refusals cannot leak state into an unrelated one. Folded into the
// shared diagnostics reset alongside resetAuthBackendHealthForTest.
func resetAuthCostHealthForTest() {
	// Fields individually, never `authCostHealth = authCostHealthRecord{}`:
	// assigning the whole struct replaces the mutex mid-critical-section, so
	// the deferred Unlock lands on a fresh, unlocked one and the runtime kills
	// the process with "unlock of unlocked mutex".
	authCostHealth.mu.Lock()
	authCostHealth.firstRefusal = time.Time{}
	authCostHealth.lastRefusal = time.Time{}
	authCostHealth.lastReason = ""
	authCostHealth.logAt = time.Time{}
	authCostHealth.suppressed = 0
	authCostHealth.alerted = false
	authCostHealth.alertAt = time.Time{}
	authCostHealth.episodes = 0
	authCostHealth.mu.Unlock()
	authCostEverRefused.Store(false)
	authCostRefusedTotal.Store(0)
	authCostRefusedPerClient.Store(0)
	authCostRefusedQueueFull.Store(0)
	authCostRefusedTimeout.Store(0)
	authCostAdmittedTotal.Store(0)
	authCostWaitedTotal.Store(0)
	globalAuthCostGate = authcost.New(0, 0, 0)
}

// swapAuthCostGate installs g as the process-wide governor and returns a
// restore func. Tests use it to drive the ceiling deterministically instead of
// racing GOMAXPROCS (the swapAutoExclude / swapPolicyLearn convention — the
// PR3d fence-pollution class).
func swapAuthCostGate(g *authcost.Gate) func() {
	prev := globalAuthCostGate
	globalAuthCostGate = g
	return func() { globalAuthCostGate = prev }
}
