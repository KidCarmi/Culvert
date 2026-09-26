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

// basicAuthIntent distinguishes a credential SUBMISSION from a liveness
// RE-CHECK of a credential this process has already admitted (SEC-BASICAUTH-5).
//
// It decides one thing only — whether the attempt is RECORDED against the
// two-tier lockout. Both intents apply every refusal: the oversize bound, the
// lockout Check before any bcrypt, the password verification and the TOTP
// posture. They differ only in what they write.
type basicAuthIntent int

const (
	// basicAuthSubmission is a caller presenting credentials to be admitted:
	// the middleware fallback and the public status endpoint. This is the
	// guessing surface, so it records success and failure.
	basicAuthSubmission basicAuthIntent = iota
	// basicAuthLiveness is a re-check of credentials captured when a
	// long-lived connection was ESTABLISHED, and it records NOTHING. See
	// revalidateUIBasicAuth.
	basicAuthLiveness
)

// verifyUIBasicAuth verifies an admin-plane HTTP Basic credential SUBMISSION
// under the full login-path control set. It returns the caller's role and true
// only when the credential is valid AND the account may use this scheme.
//
// It never writes to the ResponseWriter: the call sites answer differently
// (401, a loggedIn:false document, a dropped SSE connection), so the response
// stays theirs. Callers MUST treat false as unauthenticated.
func verifyUIBasicAuth(r *http.Request, user, pass string) (UIRole, bool) {
	return checkUIBasicAuth(r, user, pass, basicAuthSubmission)
}

// revalidateUIBasicAuth re-checks credentials that were already verified when a
// long-lived connection was established, and deliberately records NOTHING
// against the lockout (SEC-BASICAUTH-5).
//
// It is NOT a relaxation. Every refusal still applies — the lockout Check still
// runs first, so a locked pair costs no bcrypt and its live streams are cut; the
// credential is still verified, so a rotated password or a deleted user still
// terminates the stream; and a TOTP-enrolled account is still refused. What is
// removed is the WRITE, because a re-check is not an attempt and recording it as
// one is wrong in both directions.
//
// Recording a FAILURE turned a password rotation into a self-inflicted lockout.
// The captured headers cannot change mid-stream, so every open stream still
// carries the OLD password: at the next tick each charges a failure against the
// same (IP, username) pair, MaxAttempts of them trip tier 1, and the
// administrator who just rotated the password is refused from that IP for
// Duration — at the exact moment they performed the security action.
//
// Recording a SUCCESS was the more serious half, and it is a weakening of
// RISK-012 rather than an availability defect. RecordSuccess deletes the tier-1
// pair entry and refreshes the tier-2 trusted-IP grant, so one legitimate
// Basic-auth stream held open from a shared egress — a NAT, a CGNAT range, or an
// L7 proxy with no trusted_proxy_cidrs configured — clears a co-located
// attacker's counter, and an already-tripped pair lock, once per interval.
//
// Neither loss costs anything, because this path cannot be a guessing oracle by
// construction: reaching it requires an established connection, establishing one
// requires passing requireRole through the SUBMISSION path, and the credential is
// then fixed for the life of the connection. One connection is one already-valid
// credential, never a new guess.
func revalidateUIBasicAuth(r *http.Request, user, pass string) (UIRole, bool) {
	return checkUIBasicAuth(r, user, pass, basicAuthLiveness)
}

// checkUIBasicAuth is THE ONE PLACE an admin-plane Basic credential is verified
// — the single cfg.VerifyUIUser call site behind both wrappers.
func checkUIBasicAuth(r *http.Request, user, pass string, intent basicAuthIntent) (UIRole, bool) {
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

	// THE ONLY REFUSAL BEFORE VERIFICATION IS THE LOCKOUT, and that is
	// deliberate (SEC-BASICAUTH-4). A per-IP FAILURE budget stood here and was
	// REMOVED: keyed on the client alone, it let an unauthenticated caller
	// exhaust the allowance with ~60 unknown-username probes — a map miss each,
	// no bcrypt — and every administrator sharing that address (a NAT, a CGNAT
	// range, an L7 proxy with no trusted_proxy_cidrs) was then refused while
	// presenting a CORRECT password, repeatable once per window. That is the
	// lockout-as-DoS the two-tier design (RISK-012) exists to prevent, and it
	// was worse than the lockout beside it on every axis: username-independent,
	// no bcrypt, no knowledge of any account, no trusted-IP bypass. Refunding on
	// success cannot help, because the refusal necessarily precedes knowing the
	// credential is valid.
	//
	// Every cheap alternative reopens something already closed (gate only
	// unknown usernames ⇒ an enumeration oracle; exempt clients with a recent
	// success ⇒ still denies first contact, and anyone holding any valid
	// credential exempts themselves; key on the username ⇒ enumeration plus a
	// targeted denial), so the rule for this path is: ANY BOUND MUST DELAY OR
	// EVICT, NEVER DENY A REQUEST WHOSE CREDENTIALS WERE NEVER CHECKED.
	//
	// The budget's stated job was bounding unauthenticated lockout-map growth
	// and durable audit lines. The audit half is closed properly below, by
	// writing PER LOCKOUT TRIP instead of per attempt. The map-growth half is
	// recorded OPEN as AU-17b — bounded per key by boundUsername's injective
	// clamp, in time by Cleanup's window, and visible as
	// culvert_login_limiter_entries — with fair-share eviction as the designed
	// fix, because it bounds state without refusing anybody.

	// Two-tier lockout BEFORE any credential verification — same order as
	// apiAuthLogin, and the reason the ~80 ms bcrypt is no longer reachable at
	// an unbounded rate. Applies on BOTH intents: a liveness re-check is exempt
	// from recording, never from being refused.
	if locked, _ := loginLimiter.Check(clientIP, user); locked {
		return "", false
	}

	role, ok := cfg.VerifyUIUser(user, pass)
	if !ok {
		// SUBMISSION ONLY (SEC-BASICAUTH-5): a re-check carrying a credential
		// that was valid when the connection opened is not a guess, and
		// charging one failure per open connection turns a password rotation
		// into an administrator lockout.
		if intent != basicAuthSubmission {
			return "", false
		}
		// ONE audit entry per lockout TRIP, never one per attempt. Basic is
		// reachable unauthenticated on the public /api/auth/status, so a
		// per-attempt entry is the CHAOS-63 durable-log amplifier: an
		// unauthenticated caller writing a line per request into a rotating
		// file that keeps one archive. RecordFailure reports only the
		// transition, so the entry is bounded by the lockout itself.
		if loginLimiter.RecordFailure(clientIP, user) {
			auditEvent(r, "auth.basic.fail", truncateForAudit(user),
				fmt.Sprintf("HTTP Basic credential lockout after repeated invalid credentials, attempts_left=%d",
					loginLimiter.AttemptsLeft(clientIP, user)))
		}
		return "", false
	}

	// Correct password, but the account carries a second factor the Basic
	// scheme cannot carry. Refuse rather than silently downgrade. Deliberately
	// NOT charged to the per-ACCOUNT lockout — see the header. Audited on both
	// intents, because it is the compromised-first-factor signal and it is
	// bounded by the number of accounts with TOTP enrolled rather than by
	// anything a caller chooses.
	if cfg.UserHasTOTP(user) {
		auditEvent(r, "auth.basic.refused", truncateForAudit(user),
			"HTTP Basic refused: account has TOTP enrolled — use the session login flow")
		return "", false
	}

	// SUBMISSION ONLY (SEC-BASICAUTH-5): a liveness re-check must not clear a
	// counter it did not earn — on a shared egress that hands a co-located
	// attacker an unlock once per interval, and re-arms the tier-2 bypass.
	if intent == basicAuthSubmission {
		loginLimiter.RecordSuccess(clientIP, user)
	}
	return role, true
}
