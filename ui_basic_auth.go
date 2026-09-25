package main

// ui_basic_auth.go — THE single verification chokepoint for HTTP Basic
// credentials on the admin plane (SEC-BASIC-1).
//
// THE DEFECT THIS CLOSES. The admin API accepts HTTP Basic Auth as a fallback
// for CLI/API clients, and three call sites did that by calling
// cfg.VerifyUIUser directly — uiAuthMiddleware (which grants the account's
// FULL role to any /api/ request), apiAuthStatus (which is on the PUBLIC
// allowlist, so it is reachable with no session at all), and the SSE
// authorizer. cfg.VerifyUIUser is a bare bcrypt compare: it consults no
// lockout, no rate limiter, no second factor, and records nothing. Everything
// that makes POST /api/auth/login safe lives in the HANDLER, not in the
// verifier, so presenting the same credentials over Basic skipped all of it:
//
//   - TOTP. verifyLoginTOTP (ui_auth.go) refuses the login when the account has
//     a second factor enrolled. Basic never consulted it, so an enrolled
//     account was fully usable — every admin mutation included — with the
//     password alone. A second factor that can be skipped by changing the
//     transport is not a second factor.
//   - Account lockout. loginLimiter.Check / RecordFailure implement the
//     two-tier (IP, user) brute-force lock (RISK-012). Basic recorded no
//     failures and consulted no lock, so the control was bypassed by moving
//     the guess from the login endpoint to any GET.
//   - Rate limiting. securityMiddleware's apiLimiter only gates MUTATING
//     methods, so Basic guessing over GET was unbounded — and each guess costs
//     a full bcrypt (~80 ms of exclusive CPU; see CHAOS-57), on the same
//     process that serves the data plane.
//   - Audit. No auth.login.fail entry was ever written, so a sustained
//     password-guessing campaign against the admin plane left no trace in the
//     compliance record.
//
// THE RULE. Every Basic credential on the admin plane goes through
// verifyUIBasicAuth, which applies the SAME controls as the login handler and
// in the same order. Do not call cfg.VerifyUIUser from a request path again —
// verifyUIBasicAuth is the only admin-plane caller, and
// TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller walls that.
//
// TOTP IS A REFUSAL, NOT A PROMPT. The Basic scheme carries exactly one
// credential, so an enrolled second factor cannot be satisfied over it. The
// only two options are "ignore the factor" (the defect) and "refuse the
// scheme"; there is no third, so an account with TOTP enrolled cannot
// authenticate with Basic at all and must use the session-cookie login flow.
// This is a deliberate, breaking posture change for any operator who scripts
// against a TOTP-enrolled account — see docs/operator/admin-basic-auth.md.
//
// ORDER IS LOAD-BEARING, and the TOTP refusal comes AFTER the password check.
// Refusing on "this account has TOTP" before verifying the password would
// answer a question an unauthenticated caller may not ask: it turns the
// endpoint into an enrolment oracle that distinguishes a real account with 2FA
// from an unknown name, for free. Checking the password first means only a
// caller who ALREADY holds the correct credential learns that the account is
// enrolled, which tells them nothing they could not confirm by logging in.
//
// A TOTP REFUSAL IS NOT A FAILED GUESS. The password was correct, so charging
// it to loginLimiter would let an attacker who does not know the password lock
// the account out by replaying any Basic request — and would lock the real
// operator out of the login flow as a side effect of their own misconfigured
// script. It is audited (so the operator sees why their tooling broke) and
// left uncharged to the per-account lockout — but it IS charged to the per-IP
// Basic failure budget, which locks no account and bounds the bcrypt + audit
// cost of replaying a compromised first factor.

import (
	"fmt"
	"net/http"
)

// verifyUIBasicAuth verifies HTTP Basic credentials for the admin plane under
// the full login-path control set. It returns the caller's role and true only
// when the credential is valid AND the account may use this scheme.
//
// It never writes to the ResponseWriter: the three call sites answer
// differently (401, a loggedIn:false document, a dropped SSE connection), so
// the response stays theirs. Callers MUST treat false as unauthenticated.
func verifyUIBasicAuth(r *http.Request, user, pass string) (UIRole, bool) {
	// CHAOS-63: bound the name before it can reach the lockout maps or the
	// audit ring. Basic is reachable unauthenticated on the public
	// /api/auth/status, so an unbounded name here is the same unauthenticated
	// write amplifier that endpoint's login sibling already closes. A
	// CONFIGURED account is never refused for its length, mirroring
	// rejectOversizeLoginUser.
	if len(user) > maxUsernameLen && !cfg.LoginNameConfigured(user) {
		loginOversizeRejected.Add(1)
		return "", false
	}

	// RISK-019: resolve the real client behind a configured trusted proxy, so
	// an L7 proxy that collapses peer IPs cannot let one attacker lock out
	// every admin.
	clientIP := realClientIP(r)

	// Per-IP FAILURE budget, RESERVED before anything retains state or costs
	// a bcrypt. The two-tier lockout below is keyed by (IP, username), so a
	// caller rotating a fresh username per request never trips it, and
	// apiLimiter gates only mutating methods — without this, GET
	// /api/auth/status would let one unauthenticated client mint unbounded
	// lockout-map entries and durable auth.basic.fail audit lines. The unit
	// is claimed atomically up front (a probe-then-charge pair lets a
	// concurrent wave all pass the probe before any bcrypt finishes) and
	// REFUNDED on success and on a lockout refusal, so only outcomes that cost
	// a bcrypt without granting access are charged — a correctly-configured
	// script is never throttled. The refusal itself is silent (auditing it
	// would rebuild the write amplifier this bounds).
	resv, reserved := basicAuthFailLimiter.Reserve(clientIP)
	if !reserved {
		return "", false
	}

	// Two-tier lockout BEFORE any credential verification — same order as
	// apiAuthLogin, and the reason the ~80 ms bcrypt is no longer reachable at
	// an unbounded rate. A locked refusal costs no bcrypt and retains
	// nothing, so it does not consume the failure budget.
	if locked, _ := loginLimiter.Check(clientIP, user); locked {
		basicAuthFailLimiter.Refund(resv)
		return "", false
	}

	role, ok := cfg.VerifyUIUser(user, pass)
	if !ok {
		// The reserved unit stays charged.
		loginLimiter.RecordFailure(clientIP, user)
		auditEvent(r, "auth.basic.fail", truncateForAudit(user),
			fmt.Sprintf("invalid credentials over HTTP Basic, attempts_left=%d",
				loginLimiter.AttemptsLeft(clientIP, user)))
		return "", false
	}

	// Correct password, but the account carries a second factor the Basic
	// scheme cannot carry. Refuse rather than silently downgrade. Deliberately
	// NOT charged to the per-ACCOUNT lockout — see the header — but the
	// reserved per-IP unit stays charged: the refusal still cost a bcrypt and
	// a durable audit line, and the compromised-first-factor case is exactly
	// the one 2FA must keep bounded.
	if cfg.UserHasTOTP(user) {
		auditEvent(r, "auth.basic.refused", truncateForAudit(user),
			"HTTP Basic refused: account has TOTP enrolled — use the session login flow")
		return "", false
	}

	basicAuthFailLimiter.Refund(resv)
	loginLimiter.RecordSuccess(clientIP, user)
	return role, true
}
