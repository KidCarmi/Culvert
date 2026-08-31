package main

// auth_verify_cost.go — bounded admission control for password hashing
// (CHAOS-57).
//
// bcrypt is expensive ON PURPOSE. That is the right property for a credential
// store and the wrong property for something an unauthenticated stranger can
// invoke at will, and on the proxy data path they can: `handleRequest` reaches
// `Config.verifyAuthWithSnapshot` for any request carrying a
// `Proxy-Authorization: Basic` header, and SOCKS5 reaches the same function
// through `cfg.VerifyAuth` during RFC 1929 sub-negotiation. Neither presents a
// credential that has been validated yet — that IS the validation — so the cost
// is paid before the requester has proved anything at all.
//
// Measured on the 4-core Xeon this repository's benchgates run on, one
// `bcrypt.CompareHashAndPassword` at `bcrypt.DefaultCost` costs **73.8 ms**.
// Four cores divided by 73.8 ms is **~54 requests per second to saturate the
// entire gateway** — reachable from a single client over a single keep-alive
// connection, with no credentials and no privilege. Every proxied request in
// the process then competes for whatever CPU is left.
//
// Three things that look like they would stop it do not:
//
//   - The per-IP RATE LIMITER ships disabled (`-rate-limit` defaults to 0) and,
//     even when armed, counts REQUESTS. It cannot tell a 74 ms request from a
//     100 us one, so a limit generous enough for real browsing traffic still
//     admits enough hashing to pin the box.
//   - The per-IP CONNECTION LIMITER also ships disabled, and bounds concurrent
//     connections rather than work: one keep-alive connection is enough.
//   - The LOCKOUT engine (`loginLimiter`, internal/lockout) — the one component
//     that exists to make repeated credential failures expensive for the
//     CALLER — is wired into `ui_auth.go` ONLY. The proxy and SOCKS5 credential
//     paths have never had any failure accounting at all.
//
// The shape of the fix is taken from `internal/clamav`, which solved the same
// problem class (a bounded expensive resource reached from the request path)
// and whose vocabulary this file deliberately reuses rather than inventing a
// second dialect: a small semaphore, a wait bounded by the caller, saturation
// reported as its own distinguishable condition, and a fail-CLOSED posture on
// running out of the resource.
//
// Four rules hold here and must not be relaxed.
//
//  1. THE GATE WRAPS THE HASH, NOTHING ELSE. An external provider
//     (LDAP bind, OIDC introspection) is a NETWORK call, not a CPU one; it is
//     already bounded by the CHAOS-47 probe gate, and routing it through a
//     CPU-sized semaphore would make one slow directory throttle a resource it
//     does not consume. `verifyAuthWithSnapshot` returns on the provider branch
//     before ever reaching this file.
//
//  2. SATURATION FAILS CLOSED, AND IS NOT A VERDICT. Running out of slots
//     denies the request — it never admits one unauthenticated — but the denial
//     is NOT written to the auth cache. This is the CHAOS-47 rule applied to a
//     local resource instead of a remote one: only an AUTHORITATIVE answer
//     ("that credential is wrong") may be remembered. Caching a saturation
//     denial would let a burst of load deny a VALID credential for the full
//     five-minute TTL after the burst passed — trading a CPU exhaustion bug for
//     a stale-deny bug, which is precisely the defect CHAOS-47 closed.
//
//  3. SATURATION IS COUNTED SEPARATELY FROM REJECTION. "This node is at its
//     hashing capacity" and "that password is wrong" need different operator
//     responses and look identical in an auth-failure count — the `ErrQueueFull`
//     lesson from CHAOS-52, where a saturated scanner was reported as a broken
//     daemon.
//
//  4. THE CAP IS ABSOLUTE, NOT PROPORTIONAL. Slots are capped at
//     `authVerifyMaxSlots` rather than scaling with core count, so the bound is
//     on how much of the MACHINE credential hashing may consume. A proportional
//     cap (say, half the cores) leaves the data plane starved on exactly the
//     large hosts this appliance ships to: half of 32 cores is still 16 cores
//     of bcrypt.

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// authVerifyWaitBudget bounds how long a request may queue for a hashing
	// slot before it is refused.
	//
	// It is a real queue, not a spin: legitimate credential checks arrive in
	// bursts (a fleet of agents restarting, a cache TTL expiring across a user
	// population) and rejecting those outright would turn a normal burst into
	// an authentication outage. It is also SHORT, because a queue is only a
	// shock absorber: at authVerifyMaxSlots slots and ~74 ms per hash this
	// admits a backlog of roughly forty requests, after which the honest answer
	// to a caller is "not now" rather than a connection held open indefinitely.
	//
	// A request that waits out this budget has cost the node no CPU — that is
	// the whole point. The flood is answered from the gate, not from bcrypt.
	authVerifyWaitBudget = 750 * time.Millisecond

	// authVerifyMaxSlots caps concurrent password hashing regardless of how
	// many cores the host has. See rule 4 in the file comment: the bound that
	// matters is "how much of this machine may credential hashing consume",
	// and that must not grow with the machine.
	authVerifyMaxSlots = 4

	// authVerifySaturationAlertInterval rate-limits the saturation alert and
	// its log line. A sustained flood saturates the gate on EVERY request, so
	// an ungated producer would emit one alert per rejected request — the
	// WK-12 defect, aimed at the alert plane precisely when the node is
	// already under load.
	authVerifySaturationAlertInterval = 5 * time.Minute
)

// authVerifyGate is the bounded admission gate for password hashing.
//
// The zero value is not usable; construct with newAuthVerifyGate. `sem` is a
// counting semaphore over slots and `waitBudget` bounds the queue; both are
// immutable after construction, so the hot path reads no locks.
type authVerifyGate struct {
	sem        chan struct{}
	waitBudget time.Duration
}

// newAuthVerifyGate builds a gate with `slots` concurrent hashes and a queue
// bounded by `budget`. Both are floored so a misconfigured caller (or a test)
// can never produce a gate that admits nothing — a zero-slot gate would fail
// EVERY authentication closed, which is a far worse outage than the exhaustion
// this file exists to bound.
func newAuthVerifyGate(slots int, budget time.Duration) *authVerifyGate {
	if slots < 1 {
		slots = 1
	}
	if budget < 0 {
		budget = 0
	}
	return &authVerifyGate{sem: make(chan struct{}, slots), waitBudget: budget}
}

// defaultAuthVerifySlots sizes the gate for this host: one slot per core, so a
// small node is not throttled below what it can actually run in parallel, hard
// capped at authVerifyMaxSlots so a large node does not hand credential
// hashing an unbounded share of itself.
func defaultAuthVerifySlots() int {
	n := runtime.GOMAXPROCS(0)
	if n > authVerifyMaxSlots {
		n = authVerifyMaxSlots
	}
	if n < 1 {
		n = 1
	}
	return n
}

// authVerifyGateSingleton is the process-wide gate. Swapped only by
// swapAuthVerifyGate (tests).
var authVerifyGateSingleton atomic.Pointer[authVerifyGate]

func init() {
	authVerifyGateSingleton.Store(newAuthVerifyGate(defaultAuthVerifySlots(), authVerifyWaitBudget))
}

// swapAuthVerifyGate installs g as the process gate and returns a restore
// func. The singleton is process-global, so a test that narrows the gate must
// put the previous one back or it leaks its narrowing into every later test in
// the binary — the fence-pollution class swapAutoExclude exists to prevent.
func swapAuthVerifyGate(g *authVerifyGate) func() {
	prev := authVerifyGateSingleton.Load()
	authVerifyGateSingleton.Store(g)
	return func() { authVerifyGateSingleton.Store(prev) }
}

// ── Counters ─────────────────────────────────────────────────────────────────

var (
	// authVerifyHashTotal counts password hash comparisons actually performed.
	// This is the CPU bill: multiply by the per-hash cost to get the core-time
	// credential verification consumed.
	authVerifyHashTotal atomic.Int64

	// authVerifySaturatedTotal counts verifications refused because no slot
	// came free within the budget. Deliberately NOT folded into statAuthFail:
	// a saturation denial says the node is at capacity, a credential failure
	// says someone typed the wrong password, and an operator seeing only the
	// second would go looking for a brute-force attack that is not there.
	authVerifySaturatedTotal atomic.Int64

	// authVerifyInFlight is the number of hashes running right now. Exported
	// as a gauge so "the gate is pinned" is visible before it is alerting.
	authVerifyInFlight atomic.Int64
)

// authVerifySaturationLog rate-limits the saturation log line and alert, and
// carries the count suppressed between emissions so magnitude is never lost —
// signal in the log, magnitude in the counter (the CHAOS-54 convention).
var authVerifySaturationLog struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int64
}

// resetAuthVerifyCostForTest restores the counters and the rate-limit gate to
// their zero state. The counters are process-global, so a test that asserts on
// a delta must isolate itself or it reads another test's traffic.
func resetAuthVerifyCostForTest() {
	authVerifyHashTotal.Store(0)
	authVerifySaturatedTotal.Store(0)
	authVerifyInFlight.Store(0)
	authVerifySaturationLog.mu.Lock()
	authVerifySaturationLog.last = time.Time{}
	authVerifySaturationLog.suppressed = 0
	authVerifySaturationLog.mu.Unlock()
}

// ── The chokepoint ───────────────────────────────────────────────────────────

// comparePasswordHashGated is the ONLY place the proxy credential path may
// compare a presented password against a stored hash.
//
// It returns (match, admitted). `admitted` false means the node was at its
// hashing capacity and NO comparison was performed: the caller must fail
// closed and must NOT cache the result (rule 2 in the file comment). `match`
// is meaningful only when `admitted` is true.
//
// Splitting the two is what keeps "wrong password" and "no capacity"
// distinguishable all the way up to the operator's dashboard. A single bool
// would collapse them at the first return statement, which is exactly how the
// remote scanner turned saturation into a fail-open verdict (CHAOS-53).
func comparePasswordHashGated(hash []byte, pass string) (match, admitted bool) {
	g := authVerifyGateSingleton.Load()
	if g == nil { // defensive: init() always installs one
		g = newAuthVerifyGate(defaultAuthVerifySlots(), authVerifyWaitBudget)
	}

	release, ok := g.acquire()
	if !ok {
		noteAuthVerifySaturated()
		return false, false
	}
	defer release()

	authVerifyInFlight.Add(1)
	defer authVerifyInFlight.Add(-1)
	authVerifyHashTotal.Add(1)

	return bcrypt.CompareHashAndPassword(hash, []byte(pass)) == nil, true
}

// acquire takes a hashing slot, waiting at most g.waitBudget. The returned
// release is safe to defer and releases exactly one slot.
//
// A timer is allocated only on the CONTENDED path: the non-blocking select
// below succeeds outright whenever a slot is free, which is every request on a
// node that is not under a credential flood. That ordering matters — the
// uncontended cost of this gate is one channel send.
func (g *authVerifyGate) acquire() (release func(), ok bool) {
	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem }, true
	default:
	}

	if g.waitBudget <= 0 {
		return nil, false
	}
	t := time.NewTimer(g.waitBudget)
	defer t.Stop()
	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem }, true
	case <-t.C:
		return nil, false
	}
}

// noteAuthVerifySaturated records one refused verification and emits a
// rate-limited log line plus a HasSubscriber-gated alert.
//
// The alert Detail carries a BOUNDED description — no username, no client
// address, no error text. `Store.Dispatch` dedups on `event + ":" + Detail`,
// so a per-request value would defeat the dedup window by construction and
// push real threat alerts out of the bounded retry queue (the WK-12/RS-5
// defect). The magnitude lives in the counter, which is where an operator can
// actually graph it.
func noteAuthVerifySaturated() {
	authVerifySaturatedTotal.Add(1)

	now := time.Now()
	authVerifySaturationLog.mu.Lock()
	emit := authVerifySaturationLog.last.IsZero() ||
		now.Sub(authVerifySaturationLog.last) >= authVerifySaturationAlertInterval
	suppressed := authVerifySaturationLog.suppressed
	if emit {
		authVerifySaturationLog.last = now
		authVerifySaturationLog.suppressed = 0
	} else {
		authVerifySaturationLog.suppressed++
	}
	authVerifySaturationLog.mu.Unlock()

	if !emit {
		return
	}

	slots := 0
	if g := authVerifyGateSingleton.Load(); g != nil {
		slots = cap(g.sem)
	}
	logger.Printf("AUTH_VERIFY_SATURATED all %d credential-hashing slots busy for %s; "+
		"authentication is failing closed (suppressed=%d total=%d)",
		slots, authVerifyWaitBudget, suppressed, authVerifySaturatedTotal.Load())

	fireAuthVerifySaturatedAlert()
}

// fireAuthVerifySaturatedAlert delivers the `auth_verify_saturated` alert.
//
// Package-level seam so tests observe the transition SYNCHRONOUSLY instead of
// racing the process-global alerts sink, and HasSubscriber-gated for the reason
// documented on fireStorageWriteAlert: with no webhook configured — the default
// posture, and the state of every test binary — this must not spawn a goroutine
// at all.
var fireAuthVerifySaturatedAlert = func() {
	if !globalAlertStore.HasSubscriber("auth_verify_saturated") {
		return
	}
	go fireAlert("auth_verify_saturated", AlertPayload{
		Detail: "credential hashing at capacity: authentication failing closed",
		Source: "auth",
	})
}
