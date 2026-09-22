package main

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// CHAOS-66 — durable-or-refused admin-roster mutations.
//
// ui_users.json is the ONLY durable home of the admin roster: every account,
// password hash, role, TOTP secret, consumed-backup-code list and TOTP replay
// counter. Every mutation changes MEMORY first and persists second, so the two
// can disagree, and the disagreement is resolved at the next restart — when the
// file wins.
//
// That makes "mutate memory, log the persist error, answer 2xx" a wrong answer
// rather than a degraded success. The three mutations an operator reaches for
// during a security incident are exactly the ones it breaks:
//
//   - deleting a compromised or departing administrator (204 No Content, audited
//     as done, account returns on the next restart with its original hash+role),
//   - downgrading a role (200 {"ok":true}, privilege restored on restart),
//   - rotating a leaked password (200 {"ok":true}, the old password still works
//     after a restart).
//
// The rule already exists in this file's neighbour: apiSetupComplete refuses to
// report first-time setup as complete when the credential was not durably saved,
// rolls the in-memory change back, and is pinned for it twice. These helpers
// apply that same rule to the ongoing-administration handlers.
//
// The split with the LOGIN path is deliberate and is a posture decision, not an
// oversight — see noteRosterPersistBestEffort.

// msgRosterNotPersisted is the operator-facing refusal. It names the remedy
// (fix the volume, retry) and states plainly that nothing changed, because the
// failure mode this replaces is an operator believing a revocation took effect.
const msgRosterNotPersisted = "the change was NOT applied: the admin roster could not be written to disk " +
	"(check disk space and the data volume's permissions, then retry). " +
	"Nothing was changed — no account, role, password or TOTP enrolment was modified."

var (
	// rosterPersistRefused counts admin-roster mutations rolled back and
	// refused because their durable write did not land. Exported as
	// culvert_admin_roster_persist_failures_total. Non-zero means an operator's
	// administrative change was rejected and must be retried once the volume is
	// writable — a different remedy from the storage plane's generic
	// storage_write_failed, which says only that some durable write failed.
	rosterPersistRefused atomic.Int64

	// rosterPersistBestEffort counts LOGIN-path roster writes that failed while
	// the login was still allowed to proceed (see noteRosterPersistBestEffort).
	// Exported as culvert_admin_roster_persist_degraded_total. Non-zero means a
	// single-use credential or a replay counter may not have survived a restart.
	rosterPersistBestEffort atomic.Int64

	rosterPersistLogLast  atomic.Int64 // unix nanos of the last emitted line
	rosterPersistSuppress atomic.Int64
)

// rosterPersistLogInterval rate-limits the best-effort line. A failing volume
// fails every write, and the login path can be driven by an attacker; the
// magnitude lives in the counter, the signal in the log. Same discipline as
// CHAOS-63's oversize-login line.
const rosterPersistLogInterval = time.Minute

// rosterChangeCommitted reports whether a mutateRosterDurably error still left
// the change on disk.
//
// fileutil.ErrReplacedNotSynced means the rename ALREADY landed the new content
// and only the best-effort parent-directory fsync failed. Every future reader,
// including a restart, sees the new roster, so refusing the request would be a
// false negative — and rolling the change back (which mutateRosterDurably
// deliberately does not do for this error) would leave memory contradicting the
// file. Report it loudly and proceed: the change is durable across a process
// crash, and at risk only across a power loss in the next moments.
func rosterChangeCommitted(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, fileutil.ErrReplacedNotSynced) {
		logger.Printf("UIUsers: roster change landed on disk but the parent directory fsync failed "+
			"(durable across a process crash, at risk across power loss): %v", err)
		return true
	}
	return false
}

// refuseRosterChange writes the refusal for a mutation that was rolled back
// because it could not be persisted, and records it. Returns true when it
// handled the error (so the caller returns immediately), false when the error
// is the mutation's own (validation, the "last admin" guard) and the caller
// should map it to its own status code.
func refuseRosterChange(w http.ResponseWriter, r *http.Request, action, object string, err error) bool {
	if !errors.Is(err, ErrRosterNotPersisted) {
		return false
	}
	n := rosterPersistRefused.Add(1)
	logger.Printf("UIUsers: REFUSED %q for %q — roster not persisted (%d since boot): %v",
		sanitizeLog(action), sanitizeLog(object), n, err)
	// Audit the refusal. The success entry is written only on success, so
	// without this the compliance record would carry no trace of an attempted
	// revocation that did not take effect.
	auditEvent(r, action+".refused", object, "not persisted: admin roster write failed; change rolled back")
	http.Error(w, msgRosterNotPersisted, http.StatusInternalServerError)
	return true
}

// noteRosterPersistBestEffort records a LOGIN-path roster write that failed
// while the login itself was still allowed to proceed.
//
// POSTURE, recorded deliberately. Two login-path writes persist security state:
// the TOTP replay counter (SetTOTPLastCounter) and backup-code consumption
// (ConsumeBackupCode). Both previously discarded their error entirely
// (//nolint:errcheck), so a failed write silently weakened a security property:
// after a restart a consumed single-use backup code is valid again, and the
// replay window for an already-used OTP reopens — the same shape the register
// recorded as CA-14 for the session revocation list, closed there and never
// checked for the credential store beside it.
//
// They are NOT made fail-closed. Refusing the login would mean that an operator
// whose TOTP device is lost, on an appliance whose volume has just gone
// read-only, cannot reach the admin UI at all — during the incident they need it
// to diagnose. That is the terminal state CHAOS-55 and CHAOS-57 both refuse: an
// appliance nobody can manage. The weakening is bounded by the outage and
// requires the attacker to already hold a valid backup code or a live OTP;
// locking the legitimate administrator out is the larger harm.
//
// So the posture is fail-open, but never silent: counted, and logged at onset
// then at most once a minute with the magnitude carried by the counter. The
// storage plane's storage_write_failed alert fires underneath from
// fileutil.AtomicWrite's observer.
func noteRosterPersistBestEffort(what string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, fileutil.ErrReplacedNotSynced) {
		// Content landed; nothing was weakened.
		return
	}
	n := rosterPersistBestEffort.Add(1)
	now := time.Now()
	// CHAOS-66 (Codex P2): CLAIM the interval atomically. A plain load/compare/
	// store lets every caller that finishes concurrently read the same expired
	// stamp and all emit a line — which is the log amplification this gate
	// exists to prevent, arriving exactly when the volume is already failing
	// and the login path can be driven by an attacker. Exactly one caller wins
	// the CAS; the losers re-read and land in the suppressed branch.
	for {
		last := rosterPersistLogLast.Load()
		if last != 0 && now.Sub(time.Unix(0, last)) < rosterPersistLogInterval {
			rosterPersistSuppress.Add(1)
			return
		}
		if rosterPersistLogLast.CompareAndSwap(last, now.UnixNano()) {
			break
		}
	}
	suppressed := rosterPersistSuppress.Swap(0)
	logger.Printf("UIUsers: DEGRADED — %s could not be persisted (%d since boot, %d suppressed since the last line); "+
		"login allowed to proceed, but this state does not survive a restart: %v",
		sanitizeLog(what), n, suppressed, err)
}

// resetRosterPersistCountersForTest isolates the process-global counters.
func resetRosterPersistCountersForTest() {
	rosterPersistRefused.Store(0)
	rosterPersistBestEffort.Store(0)
	rosterPersistLogLast.Store(0)
	rosterPersistSuppress.Store(0)
}
