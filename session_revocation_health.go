package main

// session_revocation_health.go — CHAOS-66: observability for the one control
// that can withdraw authority from a session that has already been issued.
//
// A Culvert session cookie is SELF-CONTAINED: it carries the subject, the
// groups and the admin role, and it is trusted on the strength of its HMAC
// alone (`internal/session.Decode`). Nothing re-consults the roster on a
// request — `ui_middleware.go` reads the role out of the cookie, and
// `proxy.go`'s identity arm reads the subject and groups out of it. So the
// revocation list is not one security control among many: it is the ONLY way an
// operator can take a live session's authority away before it expires, and the
// TTL it would otherwise run to is up to seven days (`internal/session`'s
// maxTTL).
//
// The sweep found that plane failing silently in four ways at once, and the
// common shape is that none of them moved a single number an operator can
// watch. This file is the other half of the fix: three surfaces, all reusing
// vocabulary that already exists, so no new operator dialect is introduced.
//
//   - `/api/diagnostics` — the `session_revocation` operator-contract row.
//   - `/metrics` — culvert_session_revocation_{durable,tokens,users,
//     persist_failures_total}.
//   - alerts + `/readyz` — via the EXISTING state_file_corrupt event and the
//     existing `state_file_session_revocations` row, which
//     `quarantineCorruptStateFile` already produces for ui_users.json and
//     cluster.json. A corrupt revocations file means the same thing and wants
//     the same operator action, so it gets the same name.
//
// Deliberately NOT wired into `/readyz` as a row of its own. A node whose
// revocations are not durable is proxying perfectly and authenticating
// correctly; failing readiness would eject a healthy gateway from a
// load-balancer rotation over a management-plane degradation — the trade §19
// refused for the category store and §25 refused for the admin UI listener.
// The corrupt-file case DOES reach /readyz, but through the shared state-file
// row, which is report-only by the same reasoning.

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/session"
)

// sessionRevocationPersistFailures counts revocations that could not be made
// durable. A counter rather than a flag because the operator question is "is
// this still happening?", and because the first failure is the interesting one
// while the hundredth is the magnitude.
var sessionRevocationPersistFailures atomic.Uint64

type sessionRevocationHealth struct {
	// Configured is true when --revocations-file / config supplies a path.
	// False is not an error — persistence is opt-in — but it IS the posture in
	// which no revocation survives a restart, which is worth stating out loud.
	Configured bool
	// Path is the configured persistence path ("" when unconfigured).
	Path string
	// LoadDegraded is true when this boot could not load the persisted list.
	LoadDegraded bool
	// LoadDetail is the operator-facing reason the load failed.
	LoadDetail string
}

var (
	sessionRevocationHealthMu sync.RWMutex
	sessionRevocationHealthy  sessionRevocationHealth
)

// noteRevocationPersistenceConfigured records that a persistence path is armed.
func noteRevocationPersistenceConfigured(path string) {
	sessionRevocationHealthMu.Lock()
	sessionRevocationHealthy.Configured = true
	sessionRevocationHealthy.Path = path
	sessionRevocationHealthMu.Unlock()
}

// noteRevocationLoadDegraded records that the persisted list did not load, so
// this process is running with fewer revocations than the operator applied.
func noteRevocationLoadDegraded(err error) {
	sessionRevocationHealthMu.Lock()
	sessionRevocationHealthy.LoadDegraded = true
	sessionRevocationHealthy.LoadDetail = err.Error()
	sessionRevocationHealthMu.Unlock()
}

// noteRevocationPersistFailure is the internal/session observer: a revocation
// was applied in memory and could not be written down.
//
// It must not revoke, persist, or log unboundedly — a failing volume fails
// every write, so the magnitude belongs in the counter (the internal/audit
// observer contract, and the reason that observer is documented as
// audit-free).
func noteRevocationPersistFailure(error) {
	sessionRevocationPersistFailures.Add(1)
}

func init() {
	session.SetPersistFailureObserver(noteRevocationPersistFailure)
}

// sessionRevocationState returns a copy of the recorded posture.
func sessionRevocationState() sessionRevocationHealth {
	sessionRevocationHealthMu.RLock()
	defer sessionRevocationHealthMu.RUnlock()
	return sessionRevocationHealthy
}

// revocationsAreDurable reports whether a revocation applied right now would
// survive this process.
//
// Evaluated, never latched — the ca_health.go `Usable()` discipline: a
// persistence path that is removed, a volume that fills, and a volume that is
// repaired all show up on the next read without a clearing path to maintain.
func revocationsAreDurable() bool {
	h := sessionRevocationState()
	return h.Configured && !h.LoadDegraded && sessionRevocationPersistFailures.Load() == 0
}

// resetSessionRevocationHealthForTest clears the record. Test isolation only.
func resetSessionRevocationHealthForTest() {
	sessionRevocationHealthMu.Lock()
	sessionRevocationHealthy = sessionRevocationHealth{}
	sessionRevocationHealthMu.Unlock()
	sessionRevocationPersistFailures.Store(0)
}

// checkSessionRevocation is the `session_revocation` operator-contract row.
//
// Severity policy, in descending order of how badly the operator is being
// misled:
//
//   - persist failures observed → FAIL. An admin was told a session was
//     withdrawn and it was not written down. This is the only row in the sweep
//     that fails rather than warns, because the operator's belief and the
//     node's state actively disagree.
//   - the persisted list did not load → FAIL. Revocations the operator already
//     applied are not in force on this node, and nothing else will tell them.
//   - no persistence configured → WARN. Not a fault — it is the DEFAULT, and
//     that is exactly why it needs saying: a logout or an account deletion is
//     undone by the next restart. It is a warn and not a fail because it is a
//     deliberate configuration, and because it is harmless on the one posture
//     where the signing key is also per-restart (every cookie breaks anyway).
//     The message names the coupling, since the shipped docker-compose sets
//     CULVERT_SESSION_SECRET — a stable key is what makes a non-durable
//     revocation list dangerous.
//   - otherwise → OK, naming the live counts so an operator can tell a node
//     that is enforcing revocations from one that merely has the file.
func checkSessionRevocation() OperatorContractCheck {
	h := sessionRevocationState()
	tokens, users := sessionRevoked.Count(), sessionRevoked.UserCount()

	if failures := sessionRevocationPersistFailures.Load(); failures > 0 {
		return OperatorContractCheck{
			Code:   "session_revocation",
			Status: diagFail,
			Message: fmt.Sprintf("%d session revocation(s) could not be written to disk — a logout or account deletion reported as complete will be undone by the next restart",
				failures),
			OperatorAction: "Check free space, permissions and the mount backing the revocations file, then re-apply the affected logouts/deletions. Until then, treat any session revoked on this node as still live after a restart.",
		}
	}
	if h.LoadDegraded {
		return OperatorContractCheck{
			Code:           "session_revocation",
			Status:         diagFail,
			Message:        "the persisted session-revocation list did not load — revocations applied before this restart are NOT in force on this node",
			OperatorAction: "See the state_file_session_revocations row and the server logs. Restore the quarantined .corrupt.* file or a backup and restart; until then, re-apply any logout or account deletion that must hold.",
		}
	}
	if !h.Configured {
		return OperatorContractCheck{
			Code:   "session_revocation",
			Status: diagWarn,
			Message: fmt.Sprintf("session revocations are not persisted (no revocations file configured) — the %d token and %d account revocation(s) in force are lost on restart",
				tokens, users),
			OperatorAction: "Set -revocations-file (e.g. /data/revocations.json) so logouts and deleted accounts stay revoked across restarts. This matters whenever the session signing key is stable (CULVERT_SESSION_SECRET / session_secret, which every clustered deployment sets): a stable key means a cookie outlives the restart that discards its revocation.",
		}
	}
	return OperatorContractCheck{
		Code:   "session_revocation",
		Status: diagOK,
		Message: fmt.Sprintf("session revocations are durable (%d token, %d account revocation(s) in force)",
			tokens, users),
	}
}
