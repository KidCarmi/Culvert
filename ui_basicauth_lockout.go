package main

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// SEC-BASICAUTH-1 — the admin plane had FOUR credential entry points and a
// brute-force bound on ONE of them.
//
// POST /api/auth/login is guarded by the two-tier lockout (RISK-012): it
// resolves the real client behind a trusted proxy, calls loginLimiter.Check
// BEFORE any credential verification, records every failure, audits the trip,
// and sleeps 300 ms on the way out. That is the whole brute-force barrier for
// the admin plane.
//
// It was not the only way to present a password. THREE other paths called
// cfg.VerifyUIUser directly, with no lockout check, no failure record, no
// audit entry and no rate limit:
//
//  1. uiAuthMiddleware's HTTP Basic Auth fallback (ui_middleware.go) — the
//     documented "programmatic / CLI access" path, reachable on EVERY /api/
//     route that is not on the public allowlist;
//  2. apiAuthStatus (ui_auth.go) — and this one is the serious half, because
//     /api/auth/status is ON isPublicUIAuthPath. uiAuthMiddleware waves it
//     through with no credentials at all, and the handler then verifies
//     caller-supplied Basic credentials and REPORTS THE VERDICT in loggedIn.
//     An unauthenticated attacker had a password-checking oracle;
//  3. sseAuthStillValid (events.go) — the mid-stream revalidation.
//
// None of the three is a mutating request, and securityMiddleware's per-IP API
// rate limit applies ONLY to POST/PUT/DELETE (`isMutating`), so nothing
// throttled them either. The consequences, each independent of the others:
//
//   - BRUTE FORCE / CREDENTIAL STUFFING (CWE-307, OWASP A07:2021). RISK-012's
//     lockout is bypassed by choosing a different URL. An attacker never needs
//     to touch the endpoint that counts.
//   - CPU EXHAUSTION (CWE-770). Every attempt is one bcrypt at
//     bcrypt.DefaultCost — the ~80 ms/attempt constant CHAOS-57 measured, and
//     the same 12.5 x GOMAXPROCS requests/second saturation arithmetic. CHAOS-57
//     bounded that for the PROXY credential path and recorded the admin plane as
//     "deliberately left: bounded by loginLimiter instead". That rationale was
//     true of /api/auth/login and false of these three, which is exactly the
//     shape of gap a recorded deferral is supposed to prevent.
//   - NO EVIDENCE (CWE-778, OWASP A09:2021). A complete brute-force run against
//     the admin plane produced ZERO audit entries and moved no counter. The
//     attack and a quiet appliance were the same scrape.
//
// THE FIX IS A CHOKEPOINT, NOT A FOURTH MECHANISM. verifyUIBasicAuth below is
// the one place an admin-plane Basic Auth credential is verified, and it
// applies the SAME loginLimiter the login form uses — same tiers, same window,
// same trusted-IP bypass, same auth.lockout audit action and auth_lockout
// alert. No new operator vocabulary, no new configuration, and no second
// dialect for one question (the internal/audit + CHAOS-53 rule).
//
// Four properties are load-bearing and must not be relaxed:
//
//  1. THE CHECK RUNS BEFORE VERIFICATION. A locked pair is refused without
//     reaching bcrypt, which is what makes this a CPU bound and not merely a
//     guessing bound. Verifying first and refusing after would close the
//     brute-force hole and leave the exhaustion one wide open.
//  2. THE STATE IS SHARED WITH THE LOGIN ENDPOINT. Failures here count toward
//     the same tier-1 (ip, user) pair and tier-2 account entries, so an attacker
//     cannot refresh their budget by alternating endpoints. A private limiter
//     for this path would have been a second mechanism with a second bypass.
//  3. THE AUDIT ENTRY IS PER TRIP, NEVER PER ATTEMPT, and its actor is bounded
//     by truncateForAudit. A per-attempt entry would rebuild the CHAOS-63
//     write amplifier — an unauthenticated caller driving the durable audit
//     JSONL — inside the fix for a different unauthenticated-caller defect. The
//     username also reaches the lockout maps, where internal/lockout's own
//     boundUsername clamp (injective, MaxUsernameKeyLen) bounds the key.
//  4. A SUCCESSFUL VERIFICATION CLEARS ITS PAIR. That is what keeps a
//     legitimate CLI or monitoring client — which may make hundreds of Basic
//     Auth calls — from ever being throttled, and it is pinned as a control
//     rather than assumed.
//
// Deliberately NOT done here, and recorded rather than silently changed:
//
//   - TOTP IS STILL NOT REQUIRED ON THE BASIC AUTH PATH. apiAuthLogin enforces
//     it via verifyLoginTOTP; these paths never did. Closing that is a posture
//     decision that breaks every CLI/automation client belonging to a
//     TOTP-enrolled admin, so it needs an owner and a migration (an API token,
//     or a per-user "allow basic auth" flag), not a drive-by change inside a
//     lockout fix. Reported as a finding.
//   - NO RATE LIMIT ON NON-MUTATING /api/ REQUESTS. Extending securityMiddleware's
//     limiter to GET would change the behaviour of every read endpoint and of
//     the dashboard's own polling; the lockout bounds the credential path,
//     which is the part an unauthenticated caller can reach.
//   - THE SESSION RE-AUTH IN apiAuthChangePassword (ui_auth.go) IS NOT ROUTED
//     HERE. It takes its username from the session, not the caller, is a
//     mutating POST (so the 60/min per-IP limiter already applies), and needs a
//     valid admin session to reach at all — it is a re-authentication, not an
//     entry point.
// ---------------------------------------------------------------------------

// basicAuthLockoutRefused counts admin-plane Basic Auth attempts refused by the
// lockout without reaching credential verification. Exported on /metrics as
// culvert_admin_basic_auth_lockout_refused_total: the caller only ever sees a
// 429, so a climbing counter is the operator's signal that a source is
// grinding credentials against the admin API rather than the login form.
var basicAuthLockoutRefused atomic.Int64

// basicAuthLockoutLog rate-limits the refusal log line to one per window —
// onset immediately, then at most one line, with the magnitude in the counter.
// A mitigation for a flood must not be a log-bandwidth flood itself (the
// CHAOS-54/63 rule).
var (
	basicAuthLockoutLogMu   sync.Mutex
	basicAuthLockoutLogLast time.Time
)

const basicAuthLockoutLogWindow = time.Minute

// basicAuthOutcome is the verdict verifyUIBasicAuth returns.
//
// It is a three-state answer on purpose: "refused without being verified" is
// not the same fact as "verified and wrong", and a caller that collapsed them
// would answer 401 to a locked-out client and lose the only signal that the
// limiter did its job.
type basicAuthOutcome int

const (
	// basicAuthInvalid — the backend answered: these credentials are wrong.
	basicAuthInvalid basicAuthOutcome = iota
	// basicAuthValid — the backend answered: these credentials are correct.
	basicAuthValid
	// basicAuthLockedOut — the limiter refused the attempt. NOTHING was
	// verified, so this says nothing about the credentials themselves.
	basicAuthLockedOut
)

// basicAuthResult carries the verdict plus the retry hint a locked-out caller
// is owed.
type basicAuthResult struct {
	Outcome    basicAuthOutcome
	Role       UIRole
	RetryAfter int // seconds; meaningful only for basicAuthLockedOut
}

// OK reports an affirmative verification. It is the ONLY predicate a call site
// may admit on: reading Outcome != basicAuthInvalid would admit a locked-out
// attempt, which was never verified.
func (b basicAuthResult) OK() bool { return b.Outcome == basicAuthValid }

// Locked reports that the limiter refused the attempt before verification.
func (b basicAuthResult) Locked() bool { return b.Outcome == basicAuthLockedOut }

// verifyUIBasicAuth is THE ONE PLACE an admin-plane HTTP Basic Auth credential
// is verified. Every caller that reads r.BasicAuth() for admin access MUST go
// through it — see the file header for why, and the two structural walls that
// keep it true: TestSecBasicAuthWall_EveryCredentialVerifierIsBounded and
// TestSecBasicAuthWall_EveryBasicAuthReaderUsesTheChokepoint.
//
// The client is resolved with realClientIP (RISK-019) so an L7 reverse proxy
// that collapses every peer onto one address cannot make one attacker's
// failures land on every admin's key — the same resolution apiAuthLogin uses,
// for the same reason.
func verifyUIBasicAuth(r *http.Request, user, pass string) basicAuthResult {
	clientIP := realClientIP(r)

	// Check BEFORE verification: a locked attempt must cost no bcrypt.
	if locked, secs := loginLimiter.Check(clientIP, user); locked {
		basicAuthLockoutRefused.Add(1)
		if noteBasicAuthLockoutLog() {
			logWarnf("Auth: refused admin API basic-auth from %s — credential lockout active (%ds remaining); %d refused since boot",
				sanitizeLog(clientIP), secs, basicAuthLockoutRefused.Load())
		}
		return basicAuthResult{Outcome: basicAuthLockedOut, RetryAfter: secs}
	}

	role, valid := cfg.VerifyUIUser(user, pass)
	if valid {
		// Clears the tier-1 pair and marks this IP trusted for the user, so a
		// legitimate client making many API calls is never throttled and stays
		// exempt from the tier-2 account lock an attacker flood can trip.
		loginLimiter.RecordSuccess(clientIP, user)
		return basicAuthResult{Outcome: basicAuthValid, Role: role}
	}

	if loginLimiter.RecordFailure(clientIP, user) {
		// ONE entry per trip (RecordFailure reports only the transition), with
		// the same action apiAuthLogin uses. truncateForAudit bounds the
		// attacker-chosen username so the durable record cannot be flooded
		// through this path — the CHAOS-63 rule. The audit ACTOR is resolved
		// from the request by auditEvent itself; this is the OBJECT, i.e. the
		// account name the attempt claimed.
		subject := truncateForAudit(user)
		auditEvent(r, "auth.lockout", subject,
			"admin API basic-auth credential lockout — repeated failures from this client")
		go fireAlert("auth_lockout", AlertPayload{
			Actor: subject,
			// BOUNDED detail: Store.Dispatch dedups on event+Detail, so a value
			// that varied per attempt would defeat the window by construction
			// and evict real alerts from the retry queue (WK-12/RS-5).
			Detail: "admin API credential lockout",
			Source: "auth",
		})
	}
	return basicAuthResult{Outcome: basicAuthInvalid}
}

// writeBasicAuthLockout writes the 429 a refused attempt is owed, with the
// same message the login endpoint uses so an operator meets one vocabulary.
//
// Retry-After is set because these are PROGRAMMATIC callers: a CLI or
// monitoring client that has locked itself out on a rotated password should
// back off rather than keep hammering, and the header is the only way to tell
// it how long. It discloses nothing the message body does not already carry.
func writeBasicAuthLockout(w http.ResponseWriter, res basicAuthResult) {
	if res.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(res.RetryAfter))
	}
	http.Error(w, LockoutMsg(res.RetryAfter), http.StatusTooManyRequests)
}

// noteBasicAuthLockoutLog reports whether this refusal may emit a log line,
// arming the window when it does.
func noteBasicAuthLockoutLog() bool {
	now := time.Now()
	basicAuthLockoutLogMu.Lock()
	defer basicAuthLockoutLogMu.Unlock()
	if !basicAuthLockoutLogLast.IsZero() && now.Sub(basicAuthLockoutLogLast) < basicAuthLockoutLogWindow {
		return false
	}
	basicAuthLockoutLogLast = now
	return true
}

// resetBasicAuthLockoutStateForTest clears the process-global counter and log
// gate so tests do not inherit each other's state. Production never calls it.
func resetBasicAuthLockoutStateForTest() {
	basicAuthLockoutRefused.Store(0)
	basicAuthLockoutLogMu.Lock()
	basicAuthLockoutLogLast = time.Time{}
	basicAuthLockoutLogMu.Unlock()
}
