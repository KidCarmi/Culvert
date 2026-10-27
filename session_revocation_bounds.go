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
	"sync"
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

// sessionRevocationsDirty records that the in-memory revocation list is AHEAD
// of the file because a durable write failed.
//
// Persisting only when the list actually changes is what removes most of the
// quadratic amplification (CHAOS-70's rule), but it also means a failed write
// has no second chance: the browser's retry reports RevokeAlreadyKnown, the
// caller returns without saving, and nothing repairs the file unless an
// UNRELATED revocation happens to be recorded later. A restart before that
// resurrects the revoked session (Codex P1, PR #1591).
var sessionRevocationsDirty atomic.Bool

// persistMu serializes the whole persist — the save AND the dirty-flag update
// that records whether it landed.
//
// internal/session's saveMu already orders snapshot-and-write, so the file
// that lands last is the newest one. What it cannot order is anything AFTER
// SaveRevocations returns, and the flag lives out here in main: a goroutine
// whose write SUCCEEDED can be descheduled before its Store(false) and land
// it after a later goroutine whose write FAILED stored true. The flag then
// reads "in step" while the file is behind memory, nothing retries, and a
// restart inside that window resurrects the revoked session — the exact P1
// the flag exists to prevent (CodeRabbit, PR #1591).
//
// With the save and the store under one lock, Store(false) is only ever
// reached by the goroutine that just wrote the newest snapshot, so the
// invariant holds: not dirty means the file is current as of the last
// completed persist. That is what lets persistRevocationsIfDirty read the
// flag without the lock.
var persistMu sync.Mutex

// persistOutcome is what one coordinated save did. It is NOT an error type on
// purpose: most callers only need to know whether the save was REFUSED (a
// write fence, which they count) or had RECOVERED from an earlier failure
// (which the cluster merge path announces), and a returned error would invite
// each caller to log it again — the per-attempt amplification the coordinator
// exists to prevent.
type persistOutcome int

const (
	// persistLanded — the save wrote the complete live list (or persistence is
	// not configured, which writes nothing and is not a failure).
	persistLanded persistOutcome = iota
	// persistRecovered — persistLanded, and the file had been behind memory.
	persistRecovered
	// persistFailed — the write failed; the file is behind memory and a retry
	// is owed (sessionRevocationsDirty).
	persistFailed
	// persistFenced — the save was REFUSED by internal/session's write fence
	// (CHAOS-68 AU-37/AU-38): this boot could not read, or could not
	// quarantine, the revocations file, so nothing may be renamed over it.
	// Not a failure, and deliberately NOT marked dirty: no retry can land until
	// a restart clears the fence, so owing one would only turn every replayed
	// logout and every sync tick into a refused "repair" (AU-47).
	persistFenced
)

// persistRevocations saves and tracks whether the file is in step with memory.
//
// It is the ONLY production caller of sessionRevoked.SaveRevocations
// (TestChaos73_WallSavesGoThroughTheCoordinator): the logout path, the
// account-deletion path and all three cluster merge paths (CHAOS-68's
// mergeAndPersistRevocations) go through it, so the dirty flag describes every
// writer rather than the one that happened to call it.
//
// The failure line is keyed on the TRANSITION into dirty, not on the attempt
// (CHAOS-68). The cluster merge path retries an owed save on every sync tick —
// 3 s on a Data Plane, 5 s on an HA standby — so a per-attempt line is hundreds
// an hour while a volume is broken, and a mitigation for a durability defect
// must not become a write-amplification one (CHAOS-63's rule). The magnitude
// stays in culvert_session_revocation_persist_failures_total, which the
// internal/session failure observer counts on every attempt.
func persistRevocations() persistOutcome {
	persistMu.Lock()
	defer persistMu.Unlock()
	wasDirty := sessionRevocationsDirty.Load()
	err := sessionRevoked.SaveRevocations()
	if err == nil {
		sessionRevocationsDirty.Store(false)
		if wasDirty {
			return persistRecovered
		}
		return persistLanded
	}
	if session.IsWriteFenced(err) {
		return persistFenced
	}
	sessionRevocationsDirty.Store(true)
	if !wasDirty {
		// sanitizeLog + %q, not a bare %v: this error is object-derived and
		// carries untrusted content. SaveRevocations marshals the entries,
		// whose tokens come from cluster gossip and the on-disk file, so a
		// marshal failure can fold a peer-supplied token into the message and
		// forge log lines (CWE-117, CodeQL alert 418 on PR #1591).
		logger.Printf("Session: failed to persist revocations: %q", sanitizeLog(err.Error()))
	}
	return persistFailed
}

// revocationSaveOwed reports whether the file may be BEHIND the in-memory list
// and a save could repair it. It is the union of every doubt either plane can
// prove, because each one alone misses a case the other sees:
//
//   - sessionRevocationsDirty (CHAOS-73) — a coordinated save failed.
//   - sessionRevocationPersistDegraded (CHAOS-68 AU-25) — ANY save failed,
//     including the boot probe, which internal/session runs directly before
//     any coordinated save exists.
//   - the backing file VANISHED after it was written (CHAOS-68 AU-35): no save
//     was attempted, so neither flag above ever moved, and a restart loads a
//     file that never received the revocations in force. Not counted while
//     saves are write-fenced (AU-47): no save can land there.
//
// Every one of them self-clears on the first save that lands (the flags) or
// re-creates the file (vanished), so a caller that retries on this predicate
// writes at most once per episode in the healthy-again case.
func revocationSaveOwed() bool {
	if sessionRevocationsDirty.Load() {
		return true
	}
	failing, vanished := revocationDurabilityDoubt()
	return failing || vanished
}

// persistRevocationsIfDirty retries a previously failed (or silently lost)
// write. Callers reach it on a no-change revocation, so it must do nothing at
// all in the healthy case — the point of not writing when nothing changed.
//
// It is reached only from a MAC-VERIFIED replay (RevokeAlreadyKnown), so an
// unauthenticated caller cannot drive the retry, and the predicate it keys on
// clears itself, so a replaying caller cannot turn it into a per-request write.
func persistRevocationsIfDirty() {
	if !revocationSaveOwed() {
		return
	}
	persistRevocations()
}

// resetSessionRevocationsDirtyForTest clears the flag between tests.
func resetSessionRevocationsDirtyForTest() { sessionRevocationsDirty.Store(false) }

// sessionRevocationRefusedTotal reports the cumulative refusal count for the
// metrics surface.
func sessionRevocationRefusedTotal() int64 { return sessionRevokeRefused.Load() }

// resetSessionRevokeCountersForTest isolates the process-global counters and
// the log window. A leaked armed window suppresses the line in a later test.
func resetSessionRevokeCountersForTest() {
	sessionRevokeRefused.Store(0)
	sessionRevokeLogLast.Store(0)
	sessionRevocationsDirty.Store(false)
	// clusterRevocationDrops is a process-global the CP aggregator feeds, and
	// checkSessionRevocation reads it: without this reset, ONE earlier test
	// that exercised the aggregator makes the contract row take its drop
	// branch for every later test in the binary, so a gate asserting on the
	// refusal branch silently examines the wrong row.
	clusterRevocationDrops.Store(0)
	// AU-50/AU-71: the gossip-deferral counters and their log window, for the
	// same reason — a later gate asserting "nothing deferred" must not read an
	// earlier gate's backlog.
	revocationSyncRequestDeferred.Store(0)
	revocationSyncResponseDeferred.Store(0)
	revocationSyncDeferLogged.Store(0)
	session.ResetRefusalCountersForTest()
}

// ── operator contract ────────────────────────────────────────────────────────

// revocationAdmissionRow is the CHAOS-73 half of the `session_revocation`
// operator-contract row (checkSessionRevocation, session_revocation_health.go,
// composes it after CHAOS-68's durability branches). It returns ok=false when
// neither of its conditions holds, so the composed row falls through to the
// persistence-posture and healthy branches.
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
func revocationAdmissionRow() (OperatorContractCheck, bool) {
	refused := sessionRevocationRefusedTotal()
	// Every untrusted-origin refusal admitUntrustedLocked counts, plus the
	// Control Plane's per-node drop. SEC-REVDIAG-1: RevokeFarFuture was missing
	// from this sum, so a node that dropped ONLY far-future entries reported
	// "no drops" while a revocation an operator believed had taken effect had
	// not. It is the one reason here with a benign, non-adversarial trigger —
	// see the operator action below — which is exactly why it must be counted
	// rather than assumed hostile and ignored. Any new RevokeReason charged in
	// admitUntrustedLocked belongs here too; TestChaos73_DefectEveryUntrusted
	// DropReachesTheContractRow fails if one is added and not added here.
	dropped := session.Refused(session.RevokeOversize) +
		session.Refused(session.RevokeCapacity) +
		session.Refused(session.RevokeFarFuture) +
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
				"(over-long key, past the entry cap, or an expiry beyond the maximum session lifetime); "+
				"%d entries currently tracked", dropped, tracked),
			OperatorAction: "A dropped entry means a revoked admin session may still authenticate on this " +
				"or another node. Check the benign cause FIRST: the expiry bound is the maximum session " +
				"lifetime plus one hour of clock skew, so with session_timeout at or near its 168-hour " +
				"maximum, a peer whose clock runs more than an hour ahead has its legitimate revocations " +
				"dropped here — verify time sync across the cluster before suspecting a peer. Then force " +
				"a re-login for the affected administrators (change the session secret to invalidate every " +
				"session at once), and check whether a cluster peer is pushing malformed revocation state.",
		}, true
	}
	if refused > 0 {
		return OperatorContractCheck{
			Code:   "session_revocation",
			Status: diagWarn,
			Message: fmt.Sprintf("%d logout requests carried a session cookie this appliance could not "+
				"verify (refused before anything was retained); %d entries currently tracked", refused, tracked),
			OperatorAction: "Check the benign cause FIRST: a session-secret rotation, or a restart that " +
				"minted a fresh random key, makes every cookie issued under the previous key unverifiable, " +
				"and ordinary browsers logging out will produce this until they re-authenticate. A count " +
				"that keeps climbing with no recent key change is probing of the public /api/auth/logout " +
				"endpoint: confirm the admin port is not reachable from untrusted networks, and check the " +
				"rate-limited SESSION_REVOKE_REFUSED log lines for the source.",
		}, true
	}
	return OperatorContractCheck{}, false
}
