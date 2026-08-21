package main

// auth_backend_health.go — external identity-backend availability (CHAOS-47).
//
// The legacy LDAP and OIDC proxy-auth backends both cache the OUTCOME of an
// authentication attempt (5 min / 2 min respectively) so that a gateway which
// authenticates on every request does not re-bind or re-introspect per request.
// Before this file, every one of their failure branches — TCP dial refused,
// STARTTLS handshake error, service-account bind failure, search error,
// introspection transport error, identity-backend HTTP 5xx, malformed response — collapsed
// into the same `false` that a genuinely wrong password produces, and that
// `false` was written into the cache.
//
// The consequence is a recovery failure, not just a visibility gap: the
// degradation OUTLIVES the fault. A one-second directory restart denies every
// user who happened to authenticate during it for the FULL cache TTL after the
// directory is healthy again, and on a per-request-auth gateway that is very
// nearly the entire active user population. The proxy answers 407, the
// operator's directory dashboard is green, and nothing recovers until the TTL
// expires entry by entry.
//
// The fix has two halves, and both are needed:
//
//  1. An infrastructure failure is no longer cached. Only an AUTHORITATIVE
//     answer from a reachable backend ("that credential is wrong", "that token
//     is inactive", "that user is not in the required group") is allowed into
//     the cache. Denial for the in-flight request is unchanged — the posture
//     stays fail-closed — but the deny is not remembered.
//
//  2. Not caching the negative would, on its own, trade a stale-deny bug for a
//     stampede: with the backend hard-down, every request would pay a full dial
//     timeout against it. So an unreachable backend arms a short cooldown
//     during which requests are denied WITHOUT contacting it, and exactly one
//     probe per cooldown is allowed through. Recovery is therefore bounded by
//     the cooldown (seconds) instead of by the cache TTL (minutes), and it is
//     driven by evidence — one successful reach clears the gate for everyone.
//
// Observability mirrors storage_health.go (CHAOS-45): a counter for the
// magnitude, an evidence-based gauge for "is a backend unreachable right now",
// a counter for the blast radius (requests denied without a probe), and a
// rate-limited `identity_backend_unreachable` alert. This also closes the
// long-standing AU-7 gap — an identity-backend outage was previously indistinguishable
// from a brute-force spike, because both showed up only as auth failures.

import (
	"sync"
	"time"
)

const (
	// authBackendProbeCooldown bounds how long a backend stays gated after an
	// unreachable outcome, and therefore bounds recovery latency. It is
	// deliberately short: the gate exists to stop a stampede against a
	// recovering directory, not to remember a verdict. Seconds of extra denial
	// after the fault clears is the cost; the pre-fix behaviour was minutes.
	authBackendProbeCooldown = 3 * time.Second

	// authBackendAlertInterval rate-limits the identity_backend_unreachable
	// alert and its log line. A down directory fails EVERY authentication, so
	// an ungated producer would emit one alert per request.
	authBackendAlertInterval = 5 * time.Minute
)

// authProbeGate is the per-backend half-open gate. Zero value = healthy, so a
// backend that has never failed costs one uncontended mutex acquisition per
// authentication — negligible next to the bind/introspection it guards.
type authProbeGate struct {
	mu    sync.Mutex
	down  bool
	until time.Time

	// now is an injectable clock. Nil in production; tests set it to drive the
	// cooldown deterministically instead of sleeping.
	now func() time.Time
}

func (g *authProbeGate) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// allow reports whether this caller should attempt to reach the backend.
//
// While the gate is armed it returns false to everyone until the cooldown
// elapses, then grants ONE probe and immediately re-arms. Re-arming on grant
// (rather than on the probe's result) is what makes the gate safe when a probe
// never reports back — a caller that panics or is cancelled cannot leave the
// gate wide open against a still-dead backend.
func (g *authProbeGate) allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.down {
		return true
	}
	now := g.clock()
	if now.Before(g.until) {
		return false
	}
	g.until = now.Add(authBackendProbeCooldown)
	return true
}

// recordUnavailable arms (or re-arms) the gate after an infrastructure failure.
func (g *authProbeGate) recordUnavailable() {
	g.mu.Lock()
	g.down = true
	g.until = g.clock().Add(authBackendProbeCooldown)
	g.mu.Unlock()
}

// recordReachable clears the gate. The backend answered — authoritatively, in
// either direction — so it is up, and every waiting caller is released at once.
func (g *authProbeGate) recordReachable() {
	g.mu.Lock()
	g.down = false
	g.until = time.Time{}
	g.mu.Unlock()
}

// gated reports whether the gate is currently denying without probing.
func (g *authProbeGate) gated() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.down
}

// ── Process-wide record ──────────────────────────────────────────────────────

// authBackendHealthRecord is the process-wide view exported to /metrics and the
// operator. Per-backend gates arbitrate traffic; this aggregates for humans.
type authBackendHealthRecord struct {
	mu sync.Mutex

	// unavailable counts DETECTED unreachable outcomes (one per failed probe),
	// not denied requests — the gate suppresses most of those.
	unavailable int64

	// gatedDenials counts requests denied during a cooldown WITHOUT contacting
	// the backend. This is the blast radius of an outage: how many users the
	// gate turned away while it waited to re-probe.
	gatedDenials int64

	last        time.Time
	lastBackend string
	lastErr     string

	// down is the set of backends currently in cooldown. Membership, not a
	// timer, decides the gauge: a backend is considered recovered only when a
	// reach is OBSERVED, matching the evidence-based rule storage_health.go
	// established for durable writes.
	down map[string]bool

	alertAt time.Time
	logAt   time.Time
}

var authBackendHealth authBackendHealthRecord

// fireIdentityBackendUnreachableAlert delivers the identity_backend_unreachable
// alert. Package-level seam so tests observe the transition synchronously
// instead of racing the process-global sink.
//
// The HasSubscriber gate is mandatory, not cosmetic: this producer sits on the
// proxy request path and its rate is set by an EXTERNAL fault. During a
// directory outage every authenticated request reaches it, so without the gate
// a node with no webhooks configured — the default posture, and the state of
// every test binary — would spawn a delivery goroutine per request for an alert
// with no recipient, adding goroutine churn on top of the outage.
var fireIdentityBackendUnreachableAlert = func(backend, detail string) {
	if !globalAlertStore.HasSubscriber("identity_backend_unreachable") {
		return
	}
	go fireAlert("identity_backend_unreachable", AlertPayload{
		Detail: detail,
		Source: backend,
	})
}

// noteAuthBackendUnavailable records that backend could not be reached.
//
// The CWE-117 barrier is applied ONCE here, where the values enter shared
// state, so every downstream sink (log line, alert detail) is fed clean text
// and a future consumer of the record cannot reintroduce the hazard. The
// detail itself carries the endpoint identity (an LDAP URL, an introspection
// host), so it is deliberately routed only to admin-scoped sinks — the log and
// the webhook alert. The viewer-visible operator-contract row names the backend
// and the counts, never the cause text (see checkIdentityBackend).
func noteAuthBackendUnavailable(backend, detail string) {
	backend = sanitizeLog(backend)
	detail = sanitizeLog(detail)
	now := time.Now()

	authBackendHealth.mu.Lock()
	authBackendHealth.unavailable++
	authBackendHealth.last = now
	authBackendHealth.lastBackend = backend
	authBackendHealth.lastErr = detail
	if authBackendHealth.down == nil {
		authBackendHealth.down = map[string]bool{}
	}
	authBackendHealth.down[backend] = true
	total := authBackendHealth.unavailable
	doLog := authBackendHealth.logAt.IsZero() || now.Sub(authBackendHealth.logAt) >= authBackendAlertInterval
	if doLog {
		authBackendHealth.logAt = now
	}
	doAlert := authBackendHealth.alertAt.IsZero() || now.Sub(authBackendHealth.alertAt) >= authBackendAlertInterval
	if doAlert {
		authBackendHealth.alertAt = now
	}
	authBackendHealth.mu.Unlock()

	if doLog && logger != nil {
		logger.Printf("Auth: identity backend %q UNREACHABLE (%d since boot) — authentication is failing closed and the result is NOT cached: %q",
			backend, total, detail)
	}
	if doAlert {
		fireIdentityBackendUnreachableAlert(backend,
			"identity backend "+backend+" unreachable ("+detail+") — authentication failing closed")
	}
}

// noteAuthBackendReachable records an OBSERVED reach. This is the only thing
// that clears the degraded gauge for a backend — elapsed time never does, for
// the same reason it does not for durable writes: a backend nobody happens to
// query looks identical to a healthy one under a timer.
func noteAuthBackendReachable(backend string) {
	backend = sanitizeLog(backend)
	authBackendHealth.mu.Lock()
	if authBackendHealth.down[backend] {
		delete(authBackendHealth.down, backend)
	}
	authBackendHealth.mu.Unlock()
}

// noteAuthBackendGatedDenial counts one request denied during a cooldown.
func noteAuthBackendGatedDenial() {
	authBackendHealth.mu.Lock()
	authBackendHealth.gatedDenials++
	authBackendHealth.mu.Unlock()
}

// authBackendHealthSnapshot is a consistent read of the record.
type authBackendHealthSnapshot struct {
	Unavailable  int64
	GatedDenials int64
	Degraded     bool
	Last         time.Time
	Backend      string
	Err          string
}

func authBackendHealthStatus() authBackendHealthSnapshot {
	authBackendHealth.mu.Lock()
	defer authBackendHealth.mu.Unlock()
	return authBackendHealthSnapshot{
		Unavailable:  authBackendHealth.unavailable,
		GatedDenials: authBackendHealth.gatedDenials,
		Degraded:     len(authBackendHealth.down) > 0,
		Last:         authBackendHealth.last,
		Backend:      authBackendHealth.lastBackend,
		Err:          authBackendHealth.lastErr,
	}
}

// resetAuthBackendHealthForTest clears the record. Any test that asserts on the
// aggregate counters MUST call this first — the record is process-global and
// the suite runs shuffled.
func resetAuthBackendHealthForTest() {
	authBackendHealth.mu.Lock()
	defer authBackendHealth.mu.Unlock()
	authBackendHealth.unavailable = 0
	authBackendHealth.gatedDenials = 0
	authBackendHealth.last = time.Time{}
	authBackendHealth.lastBackend = ""
	authBackendHealth.lastErr = ""
	authBackendHealth.down = nil
	authBackendHealth.alertAt = time.Time{}
	authBackendHealth.logAt = time.Time{}
}
