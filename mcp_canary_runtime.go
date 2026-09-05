package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Canary activation RUNTIME — generation lifecycle + durable budget/abort state (§3/§4/§7/§8,
// Canary Activation Gate). This is the composition-layer owner that ties the pure engines together:
//
//   - an ACTIVATION GENERATION (monotonic, bumped on each Shadow→Canary activation) that keys the
//     budget enforcer and the abort controller, so a demotion/reactivation structurally invalidates
//     the previous generation's runtime state;
//   - canary.BudgetEnforcer (§3): the per-activation blast-radius budget, spend persisted BEFORE the
//     side-effect boundary so a restart never replays it;
//   - canary.AbortController (§4): the per-activation whole-Canary abort latch, persisted so an abort
//     survives a restart.
//
// DORMANT BY CONSTRUCTION. This file composes NO LiveExecutor, contacts NO upstream, materializes NO
// credential, and calls NO arming hook. beginCanaryActivation is the seam a FUTURE, separately-
// reviewed live activation would call once the live tier is armed and the §2 preflight passes; NO
// production path invokes it in this build (mirroring the uncalled markGatewayExecDepsReady), so no
// generation is ever bumped, no budget is ever armed, and no execution is ever reserved in
// production. It exists so the budget/abort/generation contract is real, durable, and restart-safe —
// exercised through a controlled test seam — before the engine that changes the outside world is
// ever composed.

// canaryRuntimeSchemaVersion is the durable-state schema version (fail-closed on any other value).
const canaryRuntimeSchemaVersion = 1

// canaryRuntimeState is the restart-durable, node-local DTO for one capability's Canary activation
// runtime. It carries ONLY the generation, build identity, the active budget, and the scalar
// budget/abort snapshots — never a tenant/subject/secret.
type canaryRuntimeState struct {
	SchemaVersion  int                   `json:"schema_version"`
	Capability     string                `json:"capability"`
	BuildVersion   string                `json:"build_version"`
	Generation     uint64                `json:"generation"`
	Active         bool                  `json:"active"` // an enforcer/controller are armed for Generation
	Budget         canary.Budget         `json:"budget"`
	BudgetSnapshot canary.BudgetSnapshot `json:"budget_snapshot"`
	AbortSnapshot  canary.AbortSnapshot  `json:"abort_snapshot"`
	// HealthSnapshot carries the elevated-error-rate / latency-pathology counters. It is durable
	// for the same reason the budget is: a detector that resets on restart is one a crash can
	// silently disarm, handing a misbehaving Canary a clean slate.
	HealthSnapshot canary.HealthSnapshot `json:"health_snapshot"`
}

// canaryCapRuntime is one capability's in-memory activation runtime.
type canaryCapRuntime struct {
	mu         sync.Mutex
	generation uint64
	active     bool
	budget     canary.Budget
	enforcer   *canary.BudgetEnforcer
	aborter    *canary.AbortController
	health     *canary.HealthMonitor
	// windowStop cancels this activation's traffic-independent window watchdog. It is a
	// convenience for a RUNNING process only: the authoritative expiry check is the derived
	// deadline (enforcer.WindowDeadline), re-evaluated on restore, so losing this timer can
	// never restore authority the clock has already taken away.
	windowStop func()
}

// canaryRuntime holds the two isolated capability runtimes.
type canaryRuntime struct {
	gateway    canaryCapRuntime
	management canaryCapRuntime
}

var globalCanaryRuntime = &canaryRuntime{}

func (rt *canaryRuntime) capRuntime(capb rollout.Capability) *canaryCapRuntime {
	if capb == rollout.CapabilityManagement {
		return &rt.management
	}
	return &rt.gateway
}

// canaryRuntimeStatePath is the per-capability durable state path under dataDir.
func canaryRuntimeStatePath(capb rollout.Capability) string {
	name := "mcp_canary_runtime_gateway.json"
	if capb == rollout.CapabilityManagement {
		name = "mcp_canary_runtime_management.json"
	}
	return filepath.Join(dataDir, name)
}

// errCanaryBudgetInvalid marks an activation refused because its budget is not first-Canary valid.
var errCanaryBudgetInvalid = errors.New("canary_budget_invalid")

// canarySyncParentDir is the parent-directory fsync seam for the runtime fail-closed cleanup, so a
// test can inject a dir-sync failure and prove the cleanup reports the pre-rename-revival risk as
// UNRESOLVED rather than claiming a durable removal. Production is the real syncParentDir.
var canarySyncParentDir = syncParentDir

// removeRuntimeStateAfterSafetyPersistFailure DURABLY removes the runtime file after a FAIL-CLOSED
// safety mutation (a whole-Canary abort, a demotion, or a failed begin) could not be persisted, so a
// restart cannot restore the pre-mutation record and revive an execution-eligible activation the
// mutation was meant to stop. A missing file restores to the dormant default (the safe direction). It
// returns nil ONLY when the fail-closed removal is confirmed crash-durable; a non-nil return names an
// UNRESOLVED durability risk (the caller has already disarmed the in-memory activation, so the running
// process is safe — the residual is a crash in this window).
//
// The safety-mutation persist that just failed with fileutil.ErrReplacedNotSynced RENAMED a new record
// over the prior Active:true file but could not fsync the parent directory, so there are TWO crash-
// revert windows, and each needs a distinct guard:
//   - a revert to the JUST-RENAMED inode — covered by invalidating the CONTENT first (truncate + fsync
//     the FILE inode): that inode is then durably empty, so restore quarantines it → dormant, even if
//     the directory can never be synced;
//   - a revert PAST the rename to the PRE-rename inode (the stale Active:true record the rename
//     displaced) — NOT covered by the content invalidation, because that stale inode was never
//     truncated (it is not the one `path` currently names). Only a CONFIRMED parent-directory fsync
//     makes the rename + the removal durable and that stale inode permanently unreachable.
//
// So the removal is treated as fail-closed-COMPLETE only when the dir sync is confirmed; a dir-sync
// failure is reported UNRESOLVED (the stale record could revive on a crash), not silently logged as a
// durable removal — Codex round-23 P1 ("require the directory mutation to be confirmed before treating
// cleanup as fail-closed"). Caller holds cr.mu.
func (rt *canaryRuntime) removeRuntimeStateAfterSafetyPersistFailure(capb rollout.Capability, what string, persistErr error) error {
	path := canaryRuntimeStatePath(capb)
	if ierr := invalidateFileContentDurably(path); ierr != nil {
		logger.Printf("MCP canary runtime: %s persist failed and the record for %s could not be durably invalidated; a restart may revive the activation: persist=%q invalidate=%q",
			what, capb.String(), sanitizeLog(persistErr.Error()), sanitizeLog(ierr.Error()))
		return ierr
	}
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		// The empty record could not be removed. A crash-restored entry to THIS inode decodes empty →
		// dormant, but the removal is not durable and a revert past the rename to the stale inode stays
		// possible — report unresolved.
		logger.Printf("MCP canary runtime: %s persist for %s failed; record content invalidated but its removal failed (a crash could revive the pre-rename record): persist=%q remove=%q",
			what, capb.String(), sanitizeLog(persistErr.Error()), sanitizeLog(rerr.Error()))
		return rerr
	}
	// CONFIRM the directory mutation: only a successful parent-dir fsync makes the rename + removal
	// crash-durable and the displaced pre-rename inode permanently unreachable.
	if serr := canarySyncParentDir(path); serr != nil {
		logger.Printf("MCP canary runtime: %s persist for %s failed; record content invalidated and removed but the directory sync is UNCONFIRMED — a crash could revive the pre-rename record: persist=%q dirsync=%q",
			what, capb.String(), sanitizeLog(persistErr.Error()), sanitizeLog(serr.Error()))
		return serr
	}
	logger.Printf("MCP canary runtime: %s persist for %s failed; durably removed the state to fail closed to dormant: %q", what, capb.String(), sanitizeLog(persistErr.Error()))
	return nil
}

// removeVisibleFileAfterNotSyncedWrite eliminates a record that AtomicWrite REPLACED but could not
// crash-sync (fileutil.ErrReplacedNotSynced is a POST-rename error: the new content is already
// visible at the target, only the parent-dir fsync failed). For a durable PREREQUISITE that grants
// capability (the attestation, the rehearsal evidence), a write reported as FAILED must not leave a
// readable record that a gate could consume, so the possibly-installed record is removed and the
// parent dir fsynced. The original write error is returned UNCHANGED so the caller still reports the
// failure. Any other write error left the target unchanged (pre-rename) and is returned as-is without
// touching it — never destroying a valid prior record on a transient failure (Codex P1).
func removeVisibleFileAfterNotSyncedWrite(path string, writeErr error) error {
	if errors.Is(writeErr, fileutil.ErrReplacedNotSynced) {
		// DURABLY INVALIDATE THE CONTENT FIRST. ErrReplacedNotSynced means the replacement's DATA is
		// fsynced (AtomicWrite fsyncs the temp file before the rename) but the directory entry may not
		// be crash-durable. Truncating the target to empty and fsyncing the FILE inode makes the record
		// fail-closed against a crash WITHOUT relying on another directory fsync — the one that just
		// failed: a crash-restored directory entry then points to an EMPTY file that strictDecode
		// rejects (quarantined → not attested), so a record the API reported as not persisted can never
		// satisfy the gate. Only a total filesystem failure (even the file-inode fsync fails) defeats
		// this, and then the runtime fail-closed (the returned error) is the sole remaining guarantee
		// (Codex P1).
		if ierr := invalidateFileContentDurably(path); ierr != nil {
			logger.Printf("MCP canary: not-synced write for %s could not be durably invalidated; a crash could expose a record reported as not persisted: write=%q invalidate=%q",
				filepath.Base(path), sanitizeLog(writeErr.Error()), sanitizeLog(ierr.Error()))
		}
		// Then best-effort remove the (now empty) file + dir sync for cleanliness. A failure here no
		// longer risks exposing a VALID record — the content was already durably invalidated above.
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			logger.Printf("MCP canary: not-synced write left %s and its removal failed (content already invalidated): write=%q remove=%q",
				filepath.Base(path), sanitizeLog(writeErr.Error()), sanitizeLog(rerr.Error()))
			return writeErr
		}
		_ = syncParentDir(path)
	}
	return writeErr
}

// invalidateFileContentDurably truncates the file at path to empty and fsyncs the FILE inode, making
// its content durably invalid (an empty file fails every strict JSON decode → quarantined → treated
// as absent). The file-content fsync is independent of the parent-directory fsync, so this fails a
// not-durably-linked record closed even when the directory cannot be synced. A missing file is
// success (nothing to invalidate).
func invalidateFileContentDurably(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	serr := f.Sync()
	cerr := f.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// syncParentDir fsyncs the directory containing path so a preceding unlink (or rename) is
// crash-durable before the caller reports the fail-closed removal complete.
func syncParentDir(path string) error {
	d, err := os.Open(filepath.Dir(path)) // #nosec G304 -- fixed operator-owned dir under dataDir
	if err != nil {
		return err
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return serr
	}
	return cerr
}

// canaryRuntimePersist is the durable persist step for every canary-runtime mutation (begin,
// reserve, abort trip, demote), isolated as a seam so a test can inject a durable-write failure and
// exercise the fail-closed paths (disarm on begin failure; remove-durable-record on demote/abort
// failure) that prevent a non-durable activation from reviving on restart (Codex P1). Production is
// the real persistLocked.
var canaryRuntimePersist = (*canaryRuntime).persistLocked

// canaryAtomicWrite is the durable-write seam for the canary runtime state. Production is
// fileutil.AtomicWrite; tests inject failures (including fileutil.ErrReplacedNotSynced) to prove the
// persist fails closed.
var canaryAtomicWrite = fileutil.AtomicWrite

// beginCanaryActivation bumps the activation generation and arms a fresh budget enforcer + abort
// controller for it, then persists. It is the FUTURE-arming seam (never invoked in this build). It
// composes no executor and reaches no upstream — it only initialises the accounting a live Canary
// would consult. A budget that is not first-Canary valid is refused fail-closed. Returns the new
// generation.
func (rt *canaryRuntime) beginCanaryActivation(capb rollout.Capability, budget canary.Budget, now time.Time) (uint64, error) {
	if canary.ValidateBudget(budget) != canary.BudgetOK {
		return 0, errCanaryBudgetInvalid
	}
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.generation++ // monotonic — a re-activation NEVER reuses a prior generation
	gen := cr.generation
	cr.active = true
	cr.budget = budget
	cr.enforcer = canary.NewBudgetEnforcer(budget, gen, now)
	cr.aborter = canary.NewAbortController(gen)
	cr.health = canary.NewHealthMonitor(gen)
	if err := canaryRuntimePersist(rt, capb, cr); err != nil {
		// The activation was never durably established — DISARM in memory (fail closed) so no
		// execution path can reserve work for an activation that does not durably exist (Codex P1).
		// The generation stays bumped (monotonic), so a later begin cannot reuse it.
		cr.active = false
		cr.enforcer = nil
		cr.aborter = nil
		cr.health = nil
		cr.budget = canary.Budget{}
		// The persist may have left a VISIBLE Active record on disk (e.g. an AtomicWrite that replaced
		// the target but could not fsync — ErrReplacedNotSynced). Durably remove it so a restart cannot
		// re-arm an activation the caller was told never became durable (Codex P1).
		_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "begin", err) // in-memory already disarmed; residual risk is logged
		return gen, err
	}
	// Arm the traffic-independent automatic stop for the new activation. It is armed AFTER the
	// durable persist, so a begin that never became durable never leaves a watchdog behind for an
	// activation that does not exist. The same call also latches immediately if the derived
	// deadline is somehow already past (a clock jump between the activation instant and now).
	reconcileWindowDeadlineLocked(rt, capb, cr)
	return gen, nil
}

// demoteCanary invalidates the current activation: it disarms the enforcer and controller so no
// further execution can be reserved, and persists. The generation is NOT reused — the next
// beginCanaryActivation bumps it, so the demoted generation's budget/abort snapshots can never be
// restored into, or reused by, the new activation. This is the runtime half of a rollback/demotion.
//
// A demotion is a SAFETY narrowing, so the durable state MUST fail closed: if persisting the
// disarmed record fails, the on-disk file would still say Active:true for this generation and a
// restart would re-arm it, silently undoing the rollback (Codex P1). To prevent that revival the
// durable file is best-effort REMOVED on a persist failure — a missing file restores to the dormant
// default (nothing armed), which is the safe direction. Only if BOTH the disarmed write and the
// remove fail is the demotion not durably fail-closed, and that is RETURNED so the caller never
// reports a durable rollback that a restart could reverse.
func (rt *canaryRuntime) demoteCanary(capb rollout.Capability) error {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	stopWindowWatchdogLocked(cr)
	cr.active = false
	cr.enforcer = nil
	cr.aborter = nil
	cr.health = nil
	cr.budget = canary.Budget{}
	if err := canaryRuntimePersist(rt, capb, cr); err != nil {
		// Persisting the disarmed record failed — remove the durable file so a restart cannot restore
		// the prior Active:true record and undo the rollback. The error is RETURNED so the caller
		// never reports a durable rollback that a restart could reverse.
		_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "demote", err) // in-memory already disarmed; residual risk is logged
		return err
	}
	return nil
}

// currentGeneration returns the capability's current activation generation (0 = never activated).
func (rt *canaryRuntime) currentGeneration(capb rollout.Capability) uint64 {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.generation
}

// activeBudget returns the budget the active generation is enforcing, and whether an activation is
// currently armed. It lets a same-mode live update detect an authoritative-budget change that the
// running generation would otherwise never pick up (Codex P2 round-6).
func (rt *canaryRuntime) activeBudget(capb rollout.Capability) (canary.Budget, bool) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.budget, cr.active
}

// generationActive reports whether the SPECIFIC activation generation gen is still the current, armed,
// execution-eligible generation. It is the final-boundary revalidation the live side-effect gate runs
// right before the irreversible upstream call: a request admitted (budget-reserved) under generation gen
// must be REFUSED if that generation was demoted (cr.active=false), superseded by a re-activation
// (cr.generation != gen), or aborted (ExecutionEligible false) AFTER admission but before the call
// (Codex P1 round-8, PR #1290). Fail-closed: a not-armed / nil-controller / generation-mismatch reads
// false. It does NOT consume budget or evaluate the window — the reservation already did — so it can
// only ever make an admitted request MORE restrictive, never admit one the reserve denied.
func (rt *canaryRuntime) generationActive(capb rollout.Capability, gen uint64) bool {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.aborter == nil || cr.generation != gen {
		return false
	}
	if !cr.aborter.ExecutionEligible(gen) {
		return false
	}
	// THE WINDOW IS RE-CHECKED HERE, not merely at admission and not left to the watchdog.
	//
	// Reserve refuses a request that arrives past the deadline, but a request admitted one
	// millisecond BEFORE it can sit between admission and preCallGuard for arbitrarily long — a
	// scheduler pause, a slow credential path — and by the time it reaches the boundary the window
	// may be over. The watchdog is asynchronous and time.AfterFunc offers no ordering guarantee
	// against that goroutine, so relying on the latch having already happened is relying on a race
	// (Codex round 2 P1). The deadline is absolute and cheap to evaluate, so the boundary evaluates
	// it under the same lock rather than trusting that something else got there first.
	//
	// This makes the watchdog what it was always described as — a convenience that stops an IDLE
	// experiment — rather than the only thing standing between an expired window and an upstream
	// call.
	// WindowOpen, not merely "before the deadline": the window has TWO ends. Reserve and the
	// eligibility read both treat now < the activation instant as CLOSED, because a clock that has
	// rolled back behind the activation cannot be used to reason about elapsed time at all. Testing
	// only the upper bound here would let an already-admitted request cross during exactly that
	// rollback (Codex round 3 P2) — the one condition every other gate in this file refuses.
	if cr.enforcer != nil && !cr.enforcer.WindowOpen(canaryNow()) {
		return false
	}
	return true
}

// armed reports whether the capability's runtime is currently armed (an activation record was
// restored/begun and not demoted). It is distinct from executionEligible, which is additionally false
// once an abort has latched — a restored aborted activation is still "armed" and must be reconciled.
func (rt *canaryRuntime) armed(capb rollout.Capability) bool {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.active
}

// reconcileCanaryRuntimeAfterRestore disarms any restored Canary runtime whose capability's rollout
// mode is NOT a live-execution mode. At startup r.restore() clamps a restored Canary/Production mode
// to Disabled unless it passes the full activation preflight (a prerequisite removed while the process
// was down fails it), but the canary runtime (budget/abort) is restored independently from its own
// durable record — so without this a restart could re-arm an execution-eligible runtime under a mode
// that was just clamped, resuming executions a fresh commit would reject. Fail-closed: an armed
// runtime with no live-execution rollout mode is demoted (disarmed + durable record made dormant), so
// the two durable domains cannot disagree after a restart (Codex P1). Must run AFTER both
// r.restore() and globalCanaryRuntime.restore().
func reconcileCanaryRuntimeAfterRestore() {
	r := getMCPRollout()
	for _, capb := range []rollout.Capability{rollout.CapabilityGateway, rollout.CapabilityManagement} {
		if !globalCanaryRuntime.armed(capb) {
			continue // dormant — nothing to reconcile
		}
		if r.stateFor(capb).CurrentMode().RequiresLiveExecution() {
			continue // a ready live-execution mode legitimately keeps its armed runtime
		}
		if err := globalCanaryRuntime.demoteCanary(capb); err != nil {
			logger.Printf("MCP canary runtime: restore reconcile: disarm %s (rollout mode not live-execution) failed: %q", capb.String(), sanitizeLog(err.Error()))
		} else {
			logger.Printf("MCP canary runtime: restore reconcile: disarmed %s runtime (rollout mode is not a live-execution mode after restore)", capb.String())
		}
	}
}

// reserveCanaryExecution is the pre-side-effect gate a live Canary would call: it refuses unless an
// activation is armed AND the abort controller is execution-eligible AND the budget grants a slot
// for the execution's identity ident (enforcing the distinct principal/tool/server ceilings). A
// whole-Canary budget exhaustion (total spent / window elapsed) OR an identity/blast-radius breach
// trips the abort controller so the Canary stops, not just the request. The budget spend is
// persisted BEFORE returning a grant so a restart cannot replay it. It returns the outcome AND the
// activation generation the reservation was made under, so the caller can Release against the SAME
// generation (a stale release after a demotion/reactivation is rejected). Fail-closed: any
// not-armed / aborted / persist failure denies.
func (rt *canaryRuntime) reserveCanaryExecution(capb rollout.Capability, now time.Time, ident canary.ExecutionIdentity) (outcome canary.BudgetOutcome, generation uint64) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.enforcer == nil || cr.aborter == nil {
		return canary.BudgetDeniedInvalid, 0
	}
	generation = cr.generation
	if !cr.aborter.ExecutionEligible(generation) {
		return canary.BudgetDeniedInvalid, generation // the Canary is aborted — no execution
	}
	outcome = cr.enforcer.Reserve(generation, now, ident)
	switch {
	case outcome.WholeCanaryExhaustion():
		// The blast-radius budget is spent — a whole-Canary breach. Latch the abort.
		cr.aborter.Trip("budget_exhausted", generation, now)
	case outcome.IdentityCapExceeded():
		// An execution for an identity beyond the enumerated blast radius — a scope escape.
		cr.aborter.Trip("scope_escape", generation, now)
	}
	// Persist the spend/abort BEFORE the caller could cross the side-effect boundary. On a persist
	// failure the in-memory spend is already consumed (monotonic — never replayed), and we deny.
	if err := canaryRuntimePersist(rt, capb, cr); err != nil {
		logger.Printf("MCP canary runtime: persist after reserve for %s failed (fail-closed): %q", capb.String(), sanitizeLog(err.Error()))
		// If this reserve latched a WHOLE-CANARY abort (budget exhaustion or an identity/blast-radius
		// breach) that did not durably persist, remove the durable record so a restart cannot revive
		// the (pre-abort) Active/not-aborted activation and let previously-admitted work run again —
		// the same fail-closed handling as tripCanaryAbort/demoteCanary (Codex P1).
		if outcome.WholeCanaryExhaustion() || outcome.IdentityCapExceeded() {
			_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "reserve-abort", err) // in-memory already disarmed; residual risk is logged
		}
		if outcome.Granted() {
			// The grant is being turned into a denial (no side effect will cross the boundary), but
			// Reserve already took an in-flight concurrency slot and the caller — seeing a denial — will
			// NOT call releaseCanaryExecution. Release the unstarted slot here so a single transient write
			// failure cannot permanently wedge concurrency (with MaxConcurrentExecutions:1, a leaked slot
			// denies every later reserve on concurrency until restart). The monotonic TOTAL spend stays
			// consumed (Release never decrements it), so the budget is never replayed (Codex P2).
			cr.enforcer.Release()
			return canary.BudgetDeniedInvalid, generation
		}
	}
	return outcome, generation
}

// releaseCanaryExecution returns one in-flight concurrency slot after an execution reserved under
// generation gen completes. It is GENERATION-BOUND: a stale release (one whose gen no longer matches
// the current activation — e.g. an execution that finishes after a demotion/reactivation) is a
// no-op, so it can never decrement a DIFFERENT generation's concurrency counter and admit an extra
// request beyond MaxConcurrentExecutions (Codex P1). It does not persist (the monotonic total was
// already made durable at reserve).
func (rt *canaryRuntime) releaseCanaryExecution(capb rollout.Capability, gen uint64) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if cr.enforcer == nil || cr.generation != gen {
		return
	}
	cr.enforcer.Release()
	// AUTHORITY CONSUMED (blocker #7 §7). This is the ONE place the exhaustion latch belongs,
	// because it is the one place every authorized reservation ends up — including the ones that
	// never sent anything.
	//
	// It was previously driven from the settled-attempt path, which excludes definitely-not-sent by
	// design: an emergency kill or a tool-drift refusal at the final boundary releases the slot
	// without settling an attempt. If that refusal took the LAST slot, the allowance was spent,
	// nothing could execute again, and yet nothing latched — so the status surface kept reporting
	// granted authority until an N+1 request arrived to discover it (Codex P2). Execution was
	// already denied by the spent budget, so this is a truthfulness fix, not a containment one, and
	// the traffic-independence claim is only true from here.
	//
	// BOTH conditions are required. Remaining()==0 is true the moment the last slot is RESERVED,
	// which with N concurrent requests for N slots is while N-1 are still in flight; latching there
	// would revoke authority the experiment had already granted. Inflight()==0 says the final
	// authorized attempt has finished — and because this runs INSIDE the release, the check sees
	// the post-release count.
	if cr.enforcer.Remaining() <= 0 && cr.enforcer.Inflight() == 0 {
		tripAutoStopLocked(rt, capb, cr, "budget_exhausted", canaryNow())
	}
}

// tripCanaryAbort feeds a safety-trip code to the capability's abort controller and persists if the
// state may have changed. It returns the TripResult so a caller can distinguish a per-request
// fail-closed (Canary continues) from a whole-Canary latch. A not-armed runtime fails closed to a
// latch result.
//
// A whole-Canary abort is a SAFETY stop, so it MUST fail closed durably: if persisting the latched
// abort fails, the on-disk record still says Active:true, Aborted:false, and a restart would restore
// it and make the same generation execution-eligible again (Codex P1). To prevent that revival the
// durable file is best-effort REMOVED on a persist failure — a missing file restores to the dormant
// default (no execution), the safe direction. The in-memory abort is in effect regardless.
func (rt *canaryRuntime) tripCanaryAbort(capb rollout.Capability, code string, now time.Time) canary.TripResult {
	return rt.tripCanaryAbortForGeneration(capb, 0, code, now)
}

// tripCanaryAbortForGeneration is tripCanaryAbort bound to the activation the caller OBSERVED.
// A wantGen of 0 means "whatever is current" and is reserved for callers with no originating
// activation to name.
//
// The generation is checked under the SAME cr.mu acquisition that latches. Checking it separately
// first is not equivalent and was the defect: a watchdog callback, or an in-flight request's
// deferred report, can pass a check and then be descheduled while the activation is demoted and
// replaced — and the trip that follows would latch the REPLACEMENT for something the previous
// activation did. Stop() cannot help, because a callback already running cannot be cancelled. So
// the expectation travels with the trip and is verified where the decision is made.
func (rt *canaryRuntime) tripCanaryAbortForGeneration(capb rollout.Capability, wantGen uint64, code string, now time.Time) canary.TripResult {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.aborter == nil {
		return canary.TripCanaryLatched
	}
	if wantGen != 0 && cr.generation != wantGen {
		// The observation belongs to an activation that is gone. Discarding it is the fail-closed
		// direction: that activation already has no execution authority, and the current one has
		// done nothing to lose its own.
		return canary.TripCanaryLatched
	}
	res := cr.aborter.Trip(code, cr.generation, now)
	if res == canary.TripCanaryLatched {
		if err := canaryRuntimePersist(rt, capb, cr); err != nil {
			_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "abort", err) // in-memory already disarmed; residual risk is logged
		}
	}
	return res
}

// executionEligible reports whether a live Canary execution could proceed right now (armed,
// eligible, budget remaining). Read-only.
func (rt *canaryRuntime) executionEligible(capb rollout.Capability, now time.Time) bool {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.enforcer == nil || cr.aborter == nil {
		return false
	}
	// Eligibility must match what a Reserve would actually do right now, so it consults the full
	// non-consuming budget gate (Reservable): window open, total slot remaining, a free concurrency
	// slot, AND rate budget in the current window. An activation that has outlived its Window/clock
	// rolled back, is out of total budget, has filled MaxConcurrentExecutions, or has spent
	// MaxExecutionsPerMinute this window would deny every reserve, so the status surface reports false
	// rather than true (Codex P2). Identity caps are not evaluated here — an eligibility read has no
	// execution identity — so this can only err permissively on that one dimension, never on window,
	// total, concurrency, or rate.
	return cr.aborter.ExecutionEligible(cr.generation) && cr.enforcer.Reservable(now)
}

// persistLocked writes the capability's durable runtime state. Caller holds cr.mu.
func (rt *canaryRuntime) persistLocked(capb rollout.Capability, cr *canaryCapRuntime) error {
	st := canaryRuntimeState{
		SchemaVersion: canaryRuntimeSchemaVersion,
		Capability:    capb.String(),
		// Bind to the COMPOSED build identity (version+commit), same as the attestation/rehearsal
		// records, so a live budget/abort/generation cannot resume on a different commit that happens to
		// share a release tag (Codex round-20 P1). currentRuntimeIdentity() composes version+buildCommit.
		BuildVersion: currentRuntimeIdentity().BuildVersion,
		Generation:   cr.generation,
		Active:       cr.active,
		Budget:       cr.budget,
	}
	if cr.enforcer != nil {
		st.BudgetSnapshot = cr.enforcer.Snapshot()
	}
	if cr.aborter != nil {
		st.AbortSnapshot = cr.aborter.Snapshot()
	}
	if cr.health != nil {
		st.HealthSnapshot = cr.health.Snapshot()
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if werr := canaryAtomicWrite(canaryRuntimeStatePath(capb), raw, 0o600); werr != nil {
		// Any write error — INCLUDING fileutil.ErrReplacedNotSynced, where the replacement is visible
		// but not durably synced and an immediate crash can lose it — is a persist FAILURE here. The
		// reserve path grants a budget slot only AFTER a durable persist, so a lost write would replay
		// the slot on restart and break the monotonic, non-replayable total (Codex P1). Unlike a
		// best-effort cache, the canary budget MUST fail closed on a not-synced replacement.
		return werr
	}
	return nil
}

// restore re-establishes both capabilities' Canary activation runtime from durable state. A missing
// file is a fresh runtime (generation 0, nothing armed). A corrupt/unknown-schema/capability-
// mismatched file is QUARANTINED and treated as fresh (fail-closed). A build-version mismatch
// disarms the enforcer/controller (a materially changed runtime does not resume a live budget) while
// preserving the monotonic generation, so a re-activation on the new build bumps past it.
func (rt *canaryRuntime) restore() {
	for _, capb := range []rollout.Capability{rollout.CapabilityGateway, rollout.CapabilityManagement} {
		rt.restoreCapability(capb)
	}
}

func (rt *canaryRuntime) restoreCapability(capb rollout.Capability) {
	path := canaryRuntimeStatePath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed operator-owned path under dataDir
	if err != nil {
		return // missing (fresh) or unreadable — keep the safe zero runtime
	}
	var st canaryRuntimeState
	if derr := strictDecodeCanaryRuntimeJSON(raw, &st); derr != nil {
		quarantineCorruptStateFile("mcp_canary_runtime", path, derr)
		return
	}
	if st.SchemaVersion != canaryRuntimeSchemaVersion || st.Capability != capb.String() {
		quarantineCorruptStateFile("mcp_canary_runtime", path, fmt.Errorf("schema/capability mismatch"))
		return
	}
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.generation = st.Generation
	// A build-version mismatch disarms the runtime: a live budget/abort from a different build must
	// not resume on a materially changed runtime (fail-closed). The comparison is against the COMPOSED
	// version+commit identity (currentRuntimeIdentity), so a different commit under the same release tag
	// disarms too — matching the commit-bound attestation/rehearsal records (Codex round-20 P1). The
	// monotonic generation is kept so a fresh activation bumps past the stale one.
	if !st.Active || st.BuildVersion != currentRuntimeIdentity().BuildVersion || st.Generation == 0 {
		cr.active = false
		cr.enforcer = nil
		cr.aborter = nil
		cr.budget = canary.Budget{}
		return
	}
	// An active record MUST carry generation-matched budget AND abort snapshots. A missing or
	// foreign-generation snapshot on an otherwise-active record is corruption: RestoreBudgetEnforcer
	// returns nil for a mismatched budget snapshot (→ disarm below), but RestoreAbortController
	// returns a FRESH not-aborted controller for a mismatched abort snapshot, which would silently
	// CLEAR a latched abort and re-arm execution. Require both snapshot generations to match this
	// record's generation and disarm (fail-closed) otherwise (Codex P1).
	if st.BudgetSnapshot.Generation != st.Generation || st.AbortSnapshot.Generation != st.Generation {
		cr.active = false
		cr.enforcer = nil
		cr.aborter = nil
		cr.budget = canary.Budget{}
		logger.Printf("MCP canary runtime restore for %s: active record has a foreign-generation budget/abort snapshot; disarmed (fail-closed)", capb.String())
		return
	}
	// Rebuild the enforcer + controller for the SAME generation. RestoreBudgetEnforcer /
	// RestoreAbortController are generation-strict, so a snapshot from a different generation cannot
	// resurrect state here. A budget that no longer validates (or a corrupt snapshot) disarms.
	cr.budget = st.Budget
	cr.enforcer = canary.RestoreBudgetEnforcer(st.Budget, st.Generation, st.BudgetSnapshot)
	cr.aborter = canary.RestoreAbortController(st.Generation, st.AbortSnapshot)
	// The health snapshot is held to the SAME standard as the budget and abort snapshots, and for
	// the same reason: it is safety state, not telemetry. A snapshot that is semantically damaged
	// (more failures than samples, a negative counter), names a different activation, or is simply
	// ABSENT against a non-zero generation would restore an activation whose detector reads clean —
	// execution authority with the evidence wiped. "No evidence" is not "no failures", so the
	// activation does not come back at all (Codex P1).
	healthOK := false
	cr.health, healthOK = canary.RestoreHealthMonitor(st.Generation, st.HealthSnapshot)
	// CROSS-RECORD invariant, which HealthSnapshot.Valid cannot see: every health sample comes from
	// an attempt that consumed a reservation, so the sample count can never exceed the reservations
	// this activation actually made. Inflating Samples is the one damaged shape that makes the
	// detector LESS likely to fire rather than more — 100 fabricated clean samples turn a real 1-of-2
	// failure rate into 1-of-102 and hand the experiment back the execution the detector should have
	// stopped (Codex round 2 P1). The two snapshots are written together atomically, so they cannot
	// legitimately disagree.
	if healthOK && st.HealthSnapshot.Samples > st.BudgetSnapshot.TotalReserved {
		healthOK = false
	}
	if cr.enforcer == nil || cr.aborter == nil || !healthOK {
		cr.active = false
		cr.enforcer = nil
		cr.aborter = nil
		cr.health = nil
		cr.budget = canary.Budget{}
		if !healthOK {
			logger.Printf("MCP canary runtime restore for %s: health snapshot missing, foreign-generation, damaged, or claiming more samples than reservations; disarmed (fail-closed)", capb.String())
		}
		return
	}
	cr.active = true
	// The window is absolute and generation-bound. A restart NEVER restarts the clock: the
	// deadline is re-derived from the persisted activation instant, so a process that comes back
	// after expiry latches window_expired HERE — before any admission path can observe an
	// execution-eligible activation — and one that comes back before expiry re-arms a watchdog
	// for the REMAINING time only.
	reconcileWindowDeadlineLocked(rt, capb, cr)
}

// strictDecodeCanaryRuntimeJSON decodes exactly one JSON value into v, rejecting unknown fields and
// trailing data (the tooltrust/attestation discipline — a tampered record is corruption).
func strictDecodeCanaryRuntimeJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Require EOF after the value: dec.More() is NOT a reliable top-level end check — a trailing "}" or
	// "]" makes it report false, so junk like `{...}}` would slip past. A SECOND decode must fail with
	// io.EOF for the input to be exactly one value; any trailing token invalidates the record (Codex P2
	// round-7, PR #1290).
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}
