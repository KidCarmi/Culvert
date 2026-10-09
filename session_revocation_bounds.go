package main

// session_revocation_bounds.go — CHAOS-73. The admission plane for the
// session revocation list's one PUBLIC entry point.
//
// `/api/auth/logout` is on uiAuthMiddleware's public allowlist, deliberately
// and correctly: an expired or already-revoked session must still be able to
// clear its own cookie, and it has no valid session with which to authenticate
// the request. What was NOT correct is what the handler then did with the
// cookie it was handed. `revokeSessionCookie` is called UNCONDITIONALLY — the
// `sess != nil` guard above it covers only the audit entry — so the handler
// base64-decoded whatever arrived, read the expiry out of the decoded payload,
// and inserted the payload bytes into the process-wide revocation list. The
// HMAC was never checked, and the call site's own comment asserted the
// opposite: "HMAC already verified by decodeSession" is true of Decode and
// false here.
//
// So an UNAUTHENTICATED caller chose the key, its LENGTH and its EXPIRY.
// Measured against the real handler (see session_revocation_chaos_test.go):
//
//   * a 524,389-byte forged cookie answered HTTP 200 over a real net/http
//     server and was retained with a 100-year expiry — which the lazy
//     evictor, keyed on that same attacker-chosen expiry, can never reclaim;
//   * the handler rewrites the ENTIRE revocation file after every insert, so
//     200 requests carrying 16 KiB each (3.2 MB in) wrote 441 MB to disk:
//     amplification 17x → 34x → 68x → 135x as the request count doubled,
//     i.e. QUADRATIC in request count, not linear. CHAOS-63's login defect
//     was the linear form of this and was rated on 4 MB from 8 requests;
//   * in a cluster the entry is exported to the Control Plane every 3 s
//     (`revocationSyncLoop`), stored in an uncapped per-node aggregator,
//     merged by every OTHER node and persisted there too — so one
//     unauthenticated request to one node's admin port becomes durable
//     fleet-wide state.
//
// THE FIX AUTHENTICATES RATHER THAN BOUNDS, AND THAT IS THE INTERESTING PART.
// A revocation key is the payload half of a cookie THIS appliance signed, so a
// cookie whose HMAC does not verify cannot name a session of ours and there is
// nothing for it to revoke. Refusing it is therefore free — there is no
// legitimate caller on the far side of the check, which is the one thing
// CHAOS-63 could not say about its own bound (an over-long CONFIGURED username
// was a real admin and had to keep working). And it costs no availability for
// the case the public route exists to serve: `Decode` verifies the MAC BEFORE
// it checks the expiry, so an EXPIRED cookie still verifies here and still
// logs out.
//
// WHAT A BOUND ALONE WOULD HAVE MISSED. Capping the cookie length — the
// obvious CHAOS-63-shaped fix, and the first one considered — bounds the bytes
// per request and leaves every other property of the defect intact: the caller
// still chooses the key and the expiry, so the entries are still immortal,
// still gossiped fleet-wide, still persisted, and the disk amplification is
// still quadratic, merely with a smaller constant. The engine-side bounds in
// internal/session/revocation_bounds.go are the structural half for the paths
// authentication cannot reach (a peer node, an on-disk file); they are not the
// primary control and must not be mistaken for it.
//
// THE WRITE IS GATED ON AN ACTUAL CHANGE. `revokeSessionCookie` used to call
// SaveRevocations() after every insert attempt. The quadratic term is the
// product of (bytes retained) × (writes), so removing the unauthenticated
// insert removes most of it and persisting only on a real change removes the
// rest: a replayed logout of an already-revoked cookie, and every refused one,
// now writes nothing. This is the roster rule from CHAOS-70 — "a mutation
// reporting NO change issues no write" — applied one plane over.

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// sessionRevokeRefused counts logout requests whose cookie was refused before
// anything was retained. It is the operator's ONLY signal that a source is
// probing the public logout endpoint: the caller still gets its 200 and its
// cleared cookie (a refusal must not tell an unauthenticated prober whether a
// cookie was genuine), and nothing else moves.
var sessionRevokeRefused atomic.Int64

// sessionRevokeLogWindow rate-limits the refusal log line to one per window,
// with the cumulative count on every line. A mitigation for a write-
// amplification defect must not be one itself (CHAOS-63/69), and this gate
// sits on a PUBLIC endpoint.
const sessionRevokeLogWindow = time.Minute

// sessionRevokeLogLast holds the UnixNano of the last emitted line.
//
// An atomic with a CAS claim, not a mutex: the read/compare/store shape lets
// every concurrent caller observe the same expired stamp and all emit, which
// is the TOCTOU CHAOS-70 round 1 had to fix on exactly this pattern. A mutex
// would also serialise an unauthenticated endpoint on one process-wide lock.
var sessionRevokeLogLast atomic.Int64

// noteSessionRevokeLog reports whether this refusal may emit a line, arming
// the window when it does. A clock that went BACKWARDS re-arms rather than
// suppressing — the CHAOS-61 rule that a negative age fails toward the safe
// answer, which here is still reporting.
func noteSessionRevokeLog() bool {
	now := time.Now().UnixNano()
	last := sessionRevokeLogLast.Load()
	if last != 0 {
		if d := now - last; d >= 0 && d < int64(sessionRevokeLogWindow) {
			return false
		}
	}
	return sessionRevokeLogLast.CompareAndSwap(last, now)
}

// noteSessionRevokeRefusal charges the counter and emits the rate-limited line.
//
// The counter is charged FIRST, before any decision about logging and before
// the client address is resolved — "charge before you reply, on every path"
// (CHAOS-69 round 3). The reason is a BOUNDED class from internal/session,
// never a caller-supplied string: this value reaches a metric label and a log
// line, and an unbounded one gives a dedup key and a label set one value per
// request (the WK-12/RS-5 defect).
//
// NOTHING here echoes the cookie, not even a prefix. Logging a truncated copy
// would reopen the amplification on the rate-limited path and is worth less to
// an operator than the LENGTH, which is the fact that distinguishes a probe
// from a browser replaying a stale cookie.
//
// r is taken rather than a resolved address because function arguments are
// evaluated EAGERLY: `realClientIP(r)` at the call site would run on every
// refusal including the suppressed ones, and behind a configured trusted proxy
// that joins and splits the whole X-Forwarded-For header — an allocation
// amplifier in front of an unauthenticated endpoint, which is the same
// correction request_tracing_bounds.go and proxy_host_bounds.go each needed.
func noteSessionRevokeRefusal(r *http.Request, reason session.RevokeReason, cookieLen int) {
	sessionRevokeRefused.Add(1)
	if !noteSessionRevokeLog() {
		return
	}
	logger.Printf("SESSION_REVOKE_REFUSED %s {reason=%s bytes=%d total=%d action=none}",
		sanitizeLog(realClientIP(r)), sanitizeLog(string(reason)), cookieLen,
		sessionRevokeRefused.Load())
}

// sessionRevocationRefusedTotal reports the cumulative refusal count for the
// metrics surface.
func sessionRevocationRefusedTotal() int64 { return sessionRevokeRefused.Load() }

// resetSessionRevokeCountersForTest isolates the process-global counters and
// the log window. A leaked armed window suppresses the line in a later test.
func resetSessionRevokeCountersForTest() {
	sessionRevokeRefused.Store(0)
	sessionRevokeLogLast.Store(0)
	session.ResetRefusalCountersForTest()
}

// ── operator contract ────────────────────────────────────────────────────────

// checkSessionRevocation is the `session_revocation` operator-contract row.
//
// It reports on TWO things an operator cannot otherwise see, and it is
// deliberately WARN-only in both cases:
//
//   - Probing of the public logout endpoint. A refusal is invisible by design
//     (the caller gets its 200 and its cleared cookie, because a refusal must
//     not tell a prober whether a cookie was genuine), so the count is the
//     only evidence. Ordinary traffic cannot produce one — an expired genuine
//     cookie and a replayed logout are both excluded — so any non-zero value
//     is somebody sending cookies this appliance did not sign.
//
//   - Revocation entries DROPPED on the untrusted-origin paths. That one is
//     the more serious of the two: a dropped entry means a session an operator
//     deliberately killed may still authenticate, here or on another node.
//
// WARN and never FAIL, for the reason every other row of this family records:
// a node being probed is a fully serving gateway, and a dropped remote
// revocation is a cluster-wide condition, so failing would eject healthy
// nodes from the load balancer over something a restart cannot fix. It is also
// deliberately NOT on `/readyz` for the same reason.
//
// The row carries COUNTS ONLY — never a client address, never a cookie or any
// prefix of one, never a token key. `/api/diagnostics` is a viewer-role
// surface, and the bytes in question are attacker-chosen.
func checkSessionRevocation() OperatorContractCheck {
	refused := sessionRevocationRefusedTotal()
	dropped := session.Refused(session.RevokeOversize) +
		session.Refused(session.RevokeCapacity) +
		clusterRevocationDropTotal()
	tracked := sessionRevoked.Tracked()

	// The dropped case outranks the probe case: one is an attacker being
	// refused (working as intended), the other is a security decision that did
	// not take effect everywhere.
	if dropped > 0 {
		return OperatorContractCheck{
			Code:   "session_revocation",
			Status: diagWarn,
			Message: fmt.Sprintf("%d session-revocation entries were dropped on an untrusted-origin path "+
				"(over-long key, or past the entry cap); %d entries currently tracked", dropped, tracked),
			OperatorAction: "A dropped entry means a revoked admin session may still authenticate on this " +
				"or another node. Force a re-login for the affected administrators (change the session " +
				"secret to invalidate every session at once), and check whether a cluster peer is pushing " +
				"malformed revocation state.",
		}
	}
	if refused > 0 {
		return OperatorContractCheck{
			Code:   "session_revocation",
			Status: diagWarn,
			Message: fmt.Sprintf("%d logout requests carried a session cookie this appliance did not sign "+
				"(refused before anything was retained); %d entries currently tracked", refused, tracked),
			OperatorAction: "Ordinary traffic does not produce this. Treat it as probing of the public " +
				"/api/auth/logout endpoint: confirm the admin port is not reachable from untrusted " +
				"networks, and check the rate-limited SESSION_REVOKE_REFUSED log lines for the source.",
		}
	}
	return OperatorContractCheck{
		Code:    "session_revocation",
		Status:  diagOK,
		Message: fmt.Sprintf("session revocation healthy (%d entries tracked, no refusals, no drops)", tracked),
	}
}
