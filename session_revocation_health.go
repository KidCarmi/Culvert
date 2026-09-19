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
// durable, cumulatively for the life of the process. It is the MAGNITUDE of an
// incident and is never reset.
//
// sessionRevocationPersistDegraded is the CURRENT state: are writes failing
// right now? Set on a failed save, cleared by a successful one.
//
// The two are deliberately separate, and conflating them is a specific known
// bug this repository has already fixed once. `ca_health.go` records it: the
// persistence warning there is keyed on `caRotationPersistDegraded()`, NOT on
// the cumulative counter, because "a counter-keyed row would latch until
// process restart even after the operator fixed the volume and re-rotated."
// The first version of this file keyed `revocationsAreDurable` on the counter
// and made exactly that mistake — while its own comment claimed the opposite
// (Codex review, PR #1437).
//
// A successful save is a genuine recovery rather than merely a fresh write:
// SaveRevocations persists the COMPLETE live list, so once one succeeds every
// revocation still in memory is durable again.
var (
	sessionRevocationPersistFailures atomic.Uint64
	sessionRevocationPersistDegraded atomic.Bool
)

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
	sessionRevocationPersistDegraded.Store(true)
}

// noteRevocationPersistSuccess clears the degradation on OBSERVED evidence — a
// write that actually landed. Elapsed time never clears it (the
// ca_health.go/storage_health.go discipline), and the cumulative counter is
// deliberately left alone so the incident stays on /metrics.
func noteRevocationPersistSuccess() {
	sessionRevocationPersistDegraded.Store(false)
}

func init() {
	session.SetPersistFailureObserver(noteRevocationPersistFailure)
	session.SetPersistSuccessObserver(noteRevocationPersistSuccess)
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
// Evaluated from CURRENT state, never from the cumulative counter: a volume
// that fills and a volume that is then repaired both show up on the next read.
// See the comment on sessionRevocationPersistDegraded for why that distinction
// is load-bearing rather than cosmetic.
func revocationsAreDurable() bool {
	h := sessionRevocationState()
	return h.Configured && !h.LoadDegraded && !sessionRevocationPersistDegraded.Load()
}

// resetSessionRevocationHealthForTest clears the record. Test isolation only.
func resetSessionRevocationHealthForTest() {
	sessionRevocationHealthMu.Lock()
	sessionRevocationHealthy = sessionRevocationHealth{}
	sessionRevocationHealthMu.Unlock()
	sessionRevocationPersistFailures.Store(0)
	sessionRevocationPersistDegraded.Store(false)
}

// checkSessionRevocation is the `session_revocation` operator-contract row.
//
// Severity policy, in descending order of how badly the operator is being
// misled:
//
//   - writes are FAILING RIGHT NOW → FAIL. An admin was told a session was
//     withdrawn and it was not written down. This is the only row in the sweep
//     that fails rather than warns, because the operator's belief and the
//     node's state actively disagree. It clears on a successful write, not on
//     elapsed time and not on a restart — see sessionRevocationPersistDegraded.
//   - the persisted list did not load → FAIL. Revocations the operator already
//     applied are not in force on this node, and nothing else will tell them.
//   - no persistence configured → WARN. Not a fault — it is the DEFAULT, and
//     that is exactly why it needs saying: a logout or an account deletion is
//     undone by the next restart. It is a warn and not a fail because it is a
//     deliberate configuration, and because it is harmless on the one posture
//     where the signing key is also per-restart (every cookie breaks anyway).
//     The message names the coupling — a stable key is what makes a
//     non-durable revocation list dangerous.
//
// WORDING CONSTRAINT: /api/diagnostics is viewer-reachable and is walled
// against echoing secret names and raw filesystem paths
// (TestApiDiagnostics_NoSensitiveValues). So these strings must not contain a
// "/data/" path or the session-secret environment variable's name, however
// natural it is to spell the remedy that way — the substance goes in the
// runbook instead. The first draft of this row named both and tripped that
// wall, which is itself order-dependent (it only fires when this row reaches
// its warn branch), so TestChaos66_ContractRowNeverEchoesSensitiveTokens
// drives every branch deterministically.
//   - otherwise → OK, naming the live counts so an operator can tell a node
//     that is enforcing revocations from one that merely has the file.
func checkSessionRevocation() OperatorContractCheck {
	h := sessionRevocationState()
	tokens, users := sessionRevoked.Count(), sessionRevoked.UserCount()

	if sessionRevocationPersistDegraded.Load() {
		failures := sessionRevocationPersistFailures.Load()
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
			OperatorAction: "Set the -revocations-file flag so logouts and deleted accounts stay revoked across restarts; see docs/operator/session-revocation.md. This matters most when the admin session signing key is configured rather than generated per restart — which every clustered deployment does — because a stable key means a cookie outlives the restart that discards its revocation.",
		}
	}
	return OperatorContractCheck{
		Code:   "session_revocation",
		Status: diagOK,
		Message: fmt.Sprintf("session revocations are durable (%d token, %d account revocation(s) in force)",
			tokens, users),
	}
}
