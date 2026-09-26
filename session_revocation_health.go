package main

// session_revocation_health.go — CHAOS-68: observability for the one control
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
	"errors"
	"fmt"
	"os"
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
	// LoadCorrupt distinguishes the TWO ways a load fails, because they have
	// DIFFERENT operator actions and only one of them leaves any evidence.
	//
	// A file that was READ and could not be PARSED is quarantined (moved
	// aside as .corrupt.*) and records a state_file_session_revocations
	// readiness row. A file that could not be READ at all — EACCES after a
	// permission change, EIO on a failing volume, a mount that went away — is
	// deliberately NOT quarantined (session_startup.go says why: the content
	// may be intact behind a transient fault, and moving a healthy
	// security-critical file aside is the worse error).
	//
	// The load path already made that distinction to decide the quarantine
	// and then DISCARDED it, so the row printed the quarantine remedy for
	// both and sent an operator hunting a .corrupt.* file and a readiness row
	// that only exist in the other case. Same defect class as CHAOS-66's
	// socks5BindRemedy: a bounded classifier is worth nothing if one remedy
	// is printed for every class.
	LoadCorrupt bool
	// LoadDetail is the operator-facing reason the load failed.
	//
	// It is err.Error(), which embeds the configured PATH, so it belongs in
	// the log and nowhere else: /api/diagnostics is viewer-reachable and
	// walled against raw filesystem paths (TestApiDiagnostics_NoSensitiveValues).
	// Do not surface it on the contract row.
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

// revocationLoadIsCorrupt is the ONE predicate that separates a parse failure
// from a read failure. Both the QUARANTINE decision (session_startup.go) and
// the REMEDY selection (checkSessionRevocation) consult it, so the action
// taken and the action advertised cannot disagree — a call site classifying
// the error itself is how they would drift apart.
func revocationLoadIsCorrupt(err error) bool {
	return errors.Is(err, session.ErrRevocationsCorrupt)
}

// noteRevocationLoadDegraded records that the persisted list did not load, so
// this process is running with fewer revocations than the operator applied.
func noteRevocationLoadDegraded(err error) {
	corrupt := revocationLoadIsCorrupt(err)
	sessionRevocationHealthMu.Lock()
	sessionRevocationHealthy.LoadDegraded = true
	sessionRevocationHealthy.LoadCorrupt = corrupt
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

// revocationBackingFileIsGone reports that persistence is armed and the file
// it writes to is DEFINITIVELY absent right now.
//
// It exists because durability here has two propositions, not one, and only a
// boot-time proof ever covered the second:
//
//   - "a revocation applied right now would survive" — what
//     revocationsAreDurable and culvert_session_revocation_durable state.
//     Deleting the file does NOT falsify it: SaveRevocations writes the
//     COMPLETE live list through AtomicWrite, which creates the file, so the
//     next revocation re-materialises everything.
//   - "the revocations ALREADY in force are on disk" — what the contract row's
//     OK message states, and what a restart actually depends on. That one IS
//     falsified the moment the file disappears, and nothing observed it: no
//     write was attempted, so no failure observer fired, so the persist-degraded
//     flag stayed clear and every surface kept reporting the boot-time answer.
//
// Reported by Codex on PR #1437 as a P2 (AU-35), against the merge primitive's
// early return — which is where it bites, because a cluster sync carrying only
// already-known entries adds nothing, returned before the save, and therefore
// never put the in-memory list back on disk. A restart then loaded a file that
// had never received those revocations and the cookies were live again: the
// fail-OPEN direction this plane exists to prevent.
//
// It keys on session.RevocationsPath() — the path SaveRevocations actually
// writes to — and NOT on the recorded health Path. The two are the same value
// in production (one startup slice sets both), and using the writer's path is
// what makes "the file is gone" and "a save would recreate it" the same
// question. Keying on the recorded path instead would let a caller loop: stat a
// path that is missing, call a save that writes somewhere else (or nowhere),
// find it still missing on the next tick, forever.
//
// ONLY a definitively absent file counts. Any other stat error — EACCES on the
// parent, EIO, a stale NFS handle — is NOT treated as missing, because it is
// not evidence the file is gone, and the content may be perfectly intact behind
// a transient fault. That is the same rule LoadRevocations already applies to
// an unreadable file ("do NOT probe … a write attempt is the one action that
// could destroy it"); a second, stricter posture for the same question in the
// same file is the divergence class this sweep keeps closing.
//
// A contract row doing filesystem I/O is established practice here, not a new
// departure: checkPlaintextKeyBackups stats its candidate paths on the same
// surface and says so, and checkMemoryBackstop reads cgroup files. The stat is
// read-only and on a path the appliance already touches, so it inherits that
// surface's existing exposure to a wedged mount rather than adding one.
func revocationBackingFileIsGone() bool {
	path := session.RevocationsPath()
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err != nil && os.IsNotExist(err)
}

// revocationsAreDurable reports whether a revocation applied right now would
// survive this process.
//
// Evaluated from CURRENT state, never from the cumulative counter: a volume
// that fills and a volume that is then repaired both show up on the next read.
// See the comment on sessionRevocationPersistDegraded for why that distinction
// is load-bearing rather than cosmetic.
//
// It deliberately does NOT consult revocationBackingFileIsGone, and that is not
// an oversight: this predicate and the contract row state DIFFERENT
// propositions. A deleted file does not falsify "a revocation applied right now
// would survive" — SaveRevocations writes the complete live list through
// AtomicWrite, which creates the file — so the gauge stays honest and matches
// its own /metrics help text. What a deleted file falsifies is "the revocations
// ALREADY in force are on disk", which is the row's claim, and the row is where
// AU-35 is reported. Folding the check in here would make the gauge contradict
// its published meaning to report a condition the row already names.
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
//   - the backing file is GONE → FAIL. Persistence is armed and the file it
//     writes to is not there, so the revocations listed as "in force" exist in
//     RAM only and a restart resurrects every one of them. Nothing observed the
//     disappearance — no write was attempted, so no failure fired — which is
//     why this needs its own branch rather than falling out of the flag above
//     (AU-35). It is a FAIL and not a warn for the same reason the first branch
//     is: the operator was told these revocations were applied.
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
// its warn branch), so TestChaos68_ContractRowNeverEchoesSensitiveTokens
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
		if h.LoadCorrupt {
			return OperatorContractCheck{
				Code:           "session_revocation",
				Status:         diagFail,
				Message:        "the persisted session-revocation list could not be PARSED — revocations applied before this restart are NOT in force on this node, and the damaged file has been quarantined",
				OperatorAction: "See the state_file_session_revocations row and the server logs. Restore the quarantined .corrupt.* copy or a backup and restart; until then, re-apply any logout or account deletion that must hold.",
			}
		}
		return OperatorContractCheck{
			Code:           "session_revocation",
			Status:         diagFail,
			Message:        "the persisted session-revocation list could not be READ — revocations applied before this restart are NOT in force on this node",
			OperatorAction: "Check the permissions and the mount backing the revocations file, then restart. The file was left in place and has not been overwritten, so its contents may still be intact — but the next logout or account deletion on this node REPLACES it with the list this process could not read, so restart before applying new revocations. Until the node restarts with the list loaded, re-apply any logout or account deletion that must hold.",
		}
	}
	if h.Configured && revocationBackingFileIsGone() {
		return OperatorContractCheck{
			Code:   "session_revocation",
			Status: diagFail,
			Message: fmt.Sprintf("the revocations file is missing — the %d token and %d account revocation(s) in force on this node are held in memory only and are lost on the next restart",
				tokens, users),
			OperatorAction: "Check the mount backing the revocations file and whether it was deleted or restored over. A clustered node rewrites it on the next config sync; on a standalone node the next logout or account deletion recreates it with the full list. Until one of those lands, treat every revocation shown here as lost on restart.",
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

// mergeAndPersistRevocations merges a peer's revocation entries into the live
// list and persists the result, RETRYING a previously failed save even when the
// merge adds nothing new.
//
// All three cluster merge sites — the HA standby bundle (ha.go), the CP's
// SyncRevocations handler (controlplane_server.go) and the DP sync loop
// (controlplane_client.go) — used to persist only inside `if added > 0`.
// MergeRevocations returns 0 once an entry is already in memory, so ONE
// transient persist failure was PERMANENT: every later sync carried the same
// entry, added nothing, and never retried. Repairing the volume did not make
// that revocation durable, and a restart then loaded a file that had never
// received it — the revoked cookie is accepted again, which is the fail-OPEN
// direction this whole plane exists to prevent.
//
// It bites hardest on the HA STANDBY, which is why the reviewer found it there:
// a standby is fenced out of SyncRevocations by haIssuanceAllowed (that is what
// AU-24 exists for), so the bundle is its ONLY writer — nothing else on that
// node would ever retry. The boot probe does not help either, because by the
// time it runs the in-memory list is gone and it writes the file WITHOUT the
// revocation.
//
// sessionRevocationPersistDegraded (AU-25) is already exactly the dirty bit the
// retry needs — set by a failed save, cleared only by one that lands — so this
// reuses it rather than adding a second, parallel answer to "are writes failing
// right now". SaveRevocations always writes the COMPLETE live list, so a retry
// is idempotent by construction and needs no record of WHICH entry was lost.
//
// The log is keyed on the TRANSITION, not on the attempt. The standby syncs
// every 5s and the DP loop every 3s, so logging each failure would emit
// hundreds of lines an hour while a volume is broken — a mitigation for a
// durability defect must not become a write-amplification one (CHAOS-63's rule,
// and CHAOS-61's one-line-per-transition precedent). The magnitude stays in
// culvert_session_revocation_persist_failures_total.
//
// A node with no persistence configured pays nothing: SaveRevocations returns
// early without writing and never sets the flag, so an unconfigured standby
// with no new entries returns before attempting anything.
//
// Reported by Codex on PR #1437 as a P1 (AU-34).
func mergeAndPersistRevocations(entries []RevocationEntry, who string) int {
	added := sessionRevoked.MergeRevocations(entries)
	// "Durability is in doubt" is TWO conditions, not one. The flag covers a
	// save that was attempted and failed; revocationBackingFileIsGone covers a
	// file that was never written down again because nobody attempted anything
	// — deleted by hand, or carried off by a replaced mount. The second leaves
	// every observer clear, so keying the retry on the flag alone meant a node
	// whose file had vanished kept taking this early return on every sync while
	// holding revocations that existed only in RAM (AU-35).
	//
	// Checking it here costs one stat per sync tick (3-5s) and self-limits: the
	// forced save recreates the file, so the next tick finds it present and
	// returns early again. Exactly one extra write per disappearance. If the
	// save fails instead — the mount is gone, not just the file — the flag is
	// set and the pre-existing retry below takes over unchanged.
	//
	// The two causes are kept SEPARATE rather than folded into one boolean,
	// because they produce different operator lines. Reporting a repaired
	// vanished file as "durable again" would claim a recovery from a
	// degradation that was never reported, leaving an operator hunting for a
	// failure line that does not exist. `vanished` is computed only when the
	// flag is clear, so a node whose save is already failing does not also
	// announce a missing file every tick — the flag's own onset line already
	// said what is wrong.
	failing := sessionRevocationPersistDegraded.Load()
	vanished := !failing && revocationBackingFileIsGone()
	if added == 0 && !failing && !vanished {
		return 0
	}
	if vanished {
		logger.Printf("%s: the revocations file is missing — rewriting the %d token and %d account revocation(s) held in memory",
			who, sessionRevoked.Count(), sessionRevoked.UserCount())
	}
	if err := sessionRevoked.SaveRevocations(); err != nil {
		// Onset only. While degraded the counter carries the magnitude.
		if !failing {
			logger.Printf("%s: failed to persist merged revocations: %v", who, err)
		}
		return added
	}
	if failing {
		logger.Printf("%s: merged session revocations are durable again", who)
	}
	return added
}
