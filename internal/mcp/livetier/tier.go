package livetier

import (
	"errors"
	"sync"
	"time"
)

// Lifecycle transition errors (bounded, fail-closed).
var (
	// ErrNotComposed is returned by Arm when the live executor has not been composed —
	// arming a non-existent tier is refused.
	ErrNotComposed = errors.New("mcp live tier: not composed")
	// ErrNotReady is returned by Arm when the node-readiness gate is not satisfied.
	ErrNotReady = errors.New("mcp live tier: node not ready to arm")
)

// State is the observable lifecycle state (absent/composed/armed/quiescing).
type State int

// The four lifecycle states. Absent is the zero value and the shipped default.
const (
	Absent State = iota
	Composed
	Armed
	Quiescing
)

// String is the bounded name published on the status surface; an unknown value reads "absent".
func (s State) String() string {
	switch s {
	case Composed:
		return "composed"
	case Armed:
		return "armed"
	case Quiescing:
		return "quiescing"
	default:
		return "absent"
	}
}

// Tier tracks one capability's live-tier lifecycle. It is deliberately SEPARATE from
// the readiness registry's armed bit: that bit (main's liveExecDepsConfigured, reached here
// only through Options.SetArmed and Options.DepsReady) governs mode transitions and
// the Canary readiness facts, while this object owns the richer composed/armed/quiescing
// lifecycle and the in-flight accounting the quiesce drain needs. The two are kept consistent
// by Arm and the three revocations, which are the ONLY writers of the armed bit for the live tier.
type Tier struct {
	// The three composition-supplied collaborators (Options); never nil after New.
	setArmed   func(armed bool)
	depsReady  func() bool
	commitLock func() sync.Locker

	mu    sync.Mutex
	state State
	// composeReason is a bounded, fixed classification code for the read-only status surface
	// (never a secret/path/raw error).
	composeReason string

	// inFlight counts live executions that have crossed the admission gate but not yet
	// released. Quiesce reads it to decide when a bounded drain is complete. It is only ever
	// incremented while armed (a quiescing/composed tier admits no new live execution).
	inFlight int
	// admitClosed, when true, rejects every new live-execution admission regardless of the
	// armed bit — the quiesce "reject new" guarantee that holds even mid-transition.
	admitClosed bool
	// drainWaiters are signaled when inFlight reaches zero during a quiesce.
	drainCond *sync.Cond
}

// Options are the collaborators the composition layer supplies. The tier owns the
// lifecycle state, the in-flight accounting and the order in which the armed bit, the
// admission bit and the state change; the composition owns the readiness registry the
// mode gate reads and the lock its rollout commits hold.
type Options struct {
	// SetArmed mirrors the armed bit into the authoritative readiness registry (the single
	// place the mode gate reads). The tier calls it with its own lock held, from Arm
	// (true) and from every revocation — Quiesce, UnarmForDemote, DisarmForRestart
	// (false) — and from nowhere else. Nil leaves the registry untouched: a tier built
	// without it can change state but can never make a live mode transition authorizable.
	SetArmed func(armed bool)
	// DepsReady reads that same bit back for Status, under the tier lock, so the status
	// row reports the lifecycle state and the registry bit as of one instant. Nil reads
	// false.
	DepsReady func() bool
	// CommitLock returns the lock that serializes rollout commits. Quiesce holds it across
	// the revocation (and only the revocation; see Quiesce). It is resolved on every
	// Quiesce, not captured at construction, because the composition may replace the
	// rollout owner. Nil means no commit path exists to serialize against.
	CommitLock func() sync.Locker
}

// noCommitLock is the Locker a tier built without Options.CommitLock takes.
type noCommitLock struct{}

// Lock does nothing: there is no commit path to exclude.
func (noCommitLock) Lock() {}

// Unlock does nothing.
func (noCommitLock) Unlock() {}

// New returns a tier in the absent state (nothing composed, nothing armed, admission
// refused). Each Tier owns its own state: two tiers share nothing unless their owner
// hands both the same collaborators.
func New(o Options) *Tier {
	lt := &Tier{
		state: Absent, composeReason: "not_composed",
		setArmed: o.SetArmed, depsReady: o.DepsReady, commitLock: o.CommitLock,
	}
	if lt.setArmed == nil {
		lt.setArmed = func(bool) {}
	}
	if lt.depsReady == nil {
		lt.depsReady = func() bool { return false }
	}
	if lt.commitLock == nil {
		lt.commitLock = func() sync.Locker { return noCommitLock{} }
	}
	lt.drainCond = sync.NewCond(&lt.mu)
	return lt
}

// State returns the current lifecycle state (read-only).
func (lt *Tier) State() State {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state
}

// IsComposed reports whether the live executor object exists (composed or beyond). It is
// distinct from armed: a composed-but-unarmed tier holds the executor but permits no live
// execution.
func (lt *Tier) IsComposed() bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state == Composed || lt.state == Armed || lt.state == Quiescing
}

// IsArmed reports whether the live readiness tier is armed. It is the lifecycle-object view;
// the execdeps registry (liveExecDepsConfigured) is the authoritative bit the mode gate
// reads, and arm/quiesce keep the two in lock-step.
func (lt *Tier) IsArmed() bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state == Armed
}

// AdmissionOpen reports whether the tier would admit a new live invocation right now —
// the exact condition AdmitExecution tests, WITHOUT taking an in-flight slot.
//
// It exists for the auxiliary admission (SEC-MCP-AUX-1), which needs the lifecycle
// answer twice: once to admit, and once as the final-boundary revalidation immediately
// before the irreversible call, so a disarm or a quiesce that lands between the two
// still refuses. Re-running AdmitExecution there would take a SECOND in-flight slot
// that the drain would then wait on forever, so the predicate is read-only.
//
// It is deliberately NOT `IsArmed()`: admitClosed is set by UnarmForDemote and by
// enterQuiesceLocked and is the bit that actually closes admission, so a predicate
// that ignored it would report a quiescing tier as open.
func (lt *Tier) AdmissionOpen() bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state == Armed && !lt.admitClosed
}

// MarkComposed records that the live executor object was composed and installed. It moves
// absent→composed. It never arms. A second call is idempotent. The bounded reason is fixed
// ("composed") — a composition that does NOT proceed records its reason via setComposeReason.
func (lt *Tier) MarkComposed() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state == Absent {
		lt.state = Composed
	}
	lt.composeReason = "composed"
}

// ResetForStartupFailure moves a COMPOSED (never armed) tier back to absent when the runtime
// listener failed to start AFTER composition, so the status surface stops reporting a composed
// live executor for a listener that never started and an in-process retry starts clean. It is
// fail-closed and idempotent: it acts ONLY on the composed state and refuses to touch an armed
// or quiescing tier (arming is a separate act that never runs during config load, so a live
// tier is at most composed here; refusing an armed tier avoids desyncing the execdeps armed bit
// from the lifecycle). An already-absent tier is a no-op.
func (lt *Tier) ResetForStartupFailure() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state != Composed {
		return
	}
	lt.state = Absent
	lt.composeReason = "runtime_start_failed"
}

// SetComposeReason records a bounded classification for a composition that did NOT proceed
// (opt-out, missing dependency), leaving the state absent.
func (lt *Tier) SetComposeReason(reason string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.composeReason = reason
}

// Reason returns the bounded composition classification for the status surface.
func (lt *Tier) Reason() string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.composeReason == "" {
		return "not_composed"
	}
	return lt.composeReason
}

// Status builds the bounded, read-only status for the admin/health surface. It distinguishes
// composed from armed from Canary-active (the last is the rollout mode, read elsewhere), and
// carries no secret/tenant/subject.
func (lt *Tier) Status() map[string]any {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return map[string]any{
		"state":           lt.state.String(),
		"composed":        lt.state == Composed || lt.state == Armed || lt.state == Quiescing,
		"armed":           lt.state == Armed,
		"compose_reason":  lt.composeReason,
		"in_flight":       lt.inFlight,
		"admit_closed":    lt.admitClosed,
		"live_deps_ready": lt.depsReady(),
	}
}

// --- lifecycle transitions -------------------------------------------------

// Arm moves composed→armed and, as its ONLY authoritative side effect on the mode gate,
// sets the registry's armed bit (Options.SetArmed(true); main's liveExecDepsConfigured) so a
// Canary MODE transition can be authorized. It is the SOLE path that sets that bit: main binds
// SetArmed to its one dispatcher, and the execution-posture wall pins that nothing else calls
// it. It refuses fail-closed unless the tier is composed and the caller
// asserts node readiness (ready==true). Arming NEVER activates Canary: it begins no Canary
// generation, reaches no upstream, and leaves the rollout mode untouched — a later
// independently-accepted Shadow→Canary transition is still required (§16).
//
// ready is computed by the authoritative arming path (main's mcp_live_arming.go) from live node
// state; passing it in keeps this transition pure and testable while the readiness gate stays
// the real, node-derived one in production.
func (lt *Tier) Arm(ready bool, reason string) error {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state != Composed {
		return ErrNotComposed
	}
	if !ready {
		return ErrNotReady
	}
	lt.state = Armed
	lt.admitClosed = false
	lt.composeReason = reason
	// Mirror the armed bit into main's execdeps registry — the single place modeExecReady and
	// the Canary preflight read. This is the one authoritative arming toggle.
	lt.setArmed(true)
	return nil
}

// Quiesce moves armed→quiescing→composed. It is the inverse of arm: it un-arms the readiness
// tier FIRST (so no new Canary transition can be authorized and modeExecReady refuses live
// modes), closes new-execution admission, then BOUNDS the drain of in-flight executions to
// waitFn (a caller-supplied bounded wait that returns when inFlight==0 or a deadline elapses).
// It returns the number of executions still in flight when the drain bound elapsed (0 on a
// clean drain). Quiesce preserves evidence and trust records (it touches neither) and never
// widens scope. Emergency kill remains authoritative regardless of quiesce.
//
// The un-arm is durable-in-effect immediately: SetArmed(false) means a concurrent
// rollout commit into a live mode fails closed at modeExecReady, and admitClosed=true means a
// concurrent gate admission is rejected even before the armed bit is observed — the two
// together are the "reject new" guarantee that holds mid-transition.
func (lt *Tier) Quiesce(waitFn func(inFlight func() int) int) int {
	// SERIALIZE the readiness revocation with rollout commits (Codex P1 round-5, PR #1290). A Canary
	// transition reads liveExecDepsConfigured under mcpRollout.durableMu (Options.CommitLock) and then installs+persists
	// Canary while still holding it; if quiesce cleared the armed bit under lt.mu alone it could
	// interleave between that read and the install, so the commit would be acknowledged and the runtime
	// armed AFTER the tier reached composed/unarmed — and a later arm would resume that Canary with no
	// fresh activation transition. Taking durableMu here forces the revocation to land either wholly
	// before the commit's armed read or wholly after its install. Lock order is durableMu → lt.mu, which
	// is deadlock-free: no durableMu holder (the commit path, kill switch, rehearsal) ever takes lt.mu.
	// durableMu is held ONLY for the fail-closed revocation phase and is released BEFORE the bounded
	// (possibly slow) in-flight drain, so quiesce never blocks a commit for the drain duration.
	commit := lt.commitLock()
	commit.Lock()
	lt.mu.Lock()
	needDrain := lt.enterQuiesceLocked()
	lt.mu.Unlock()
	commit.Unlock()
	return lt.drainAndLeaveQuiesce(needDrain, waitFn)
}

// UnarmForDemote forces the tier to composed/unarmed and CLOSES admission WITHOUT draining — the
// leaving-live demotion posture (Codex P1 round-8, PR #1290). It is the inverse of arm reduced to its
// fail-closed half: no new execution can be admitted after it, while already-admitted in-flight work is
// invalidated at the executor's FINAL BOUNDARY (its reserved Canary generation is no longer current once
// demoteCanary runs), not by a drain. A drain is deliberately avoided here: a bounded drain could time
// out and still let a residual request cross the boundary after the demotion committed, and holding
// mcpRollout.durableMu across a drain would block the emergency kill from engaging. It takes only lt.mu,
// so the rollout commit that calls it (holding durableMu) releases durableMu promptly. Safe on any state.
func (lt *Tier) UnarmForDemote() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state == Armed || lt.state == Quiescing {
		lt.state = Composed
	}
	lt.admitClosed = true
	lt.composeReason = "demoted"
	lt.setArmed(false)
}

// enterQuiesceLocked performs the fail-closed revocation half of a quiesce and reports whether a drain
// is required. Caller holds lt.mu (and durableMu). An armed tier transitions to quiescing, closes
// admission, and un-arms the mode gate. A tier that is NOT armed but still carries residual in-flight
// work — a prior bounded quiesce whose drain bound elapsed left it composed/unarmed with inFlight>0 —
// re-enters the quiescing state, keeps admission closed, and still needs a drain: a retry MUST NOT
// report a clean drain (0) while an upstream request is still running (Codex P2 round-7). Re-entering
// quiescing (not staying composed) is load-bearing: while a retry drains, a concurrent authoritative
// re-arm must stay REFUSED (arm requires Composed), so the retry's drainAndLeaveQuiesce landing
// back at composed cannot leave the lifecycle state and the armed exec-deps bit inconsistent with a
// re-arm that slipped in (Codex P2 round-8). A truly idle not-armed tier needs no drain (idempotent).
func (lt *Tier) enterQuiesceLocked() (needDrain bool) {
	switch {
	case lt.state == Armed:
		lt.state = Quiescing
		lt.admitClosed = true
		lt.composeReason = "quiescing"
		// Un-arm the mode gate BEFORE draining: a request that has not already been admitted can
		// never be admitted now, and no new Canary transition can be authorized.
		lt.setArmed(false)
		return true
	case lt.inFlight > 0:
		// Residual in-flight under a composed/unarmed tier (a prior bounded quiesce timed out). Re-enter
		// quiescing so a concurrent re-arm stays refused for the retry's duration, keep admission closed,
		// and drain/report the residual rather than falsely reporting a clean drain. The armed bit is
		// already false from the prior quiesce; keep it false.
		lt.state = Quiescing
		lt.admitClosed = true
		lt.composeReason = "quiescing"
		lt.setArmed(false)
		return true
	default:
		return false
	}
}

// drainAndLeaveQuiesce runs the bounded drain (when needed) and lands the tier composed/unarmed. It is
// the second half of quiesce (the first is enterQuiesceLocked), run after durableMu is released so a
// slow drain never holds it. A not-needed drain is an idempotent no-op returning 0.
func (lt *Tier) drainAndLeaveQuiesce(needDrain bool, waitFn func(inFlight func() int) int) int {
	if !needDrain {
		return 0
	}
	// Bounded drain of in-flight executions. The caller owns the deadline; the wait reads the
	// live in-flight count under the lock via InFlightCount.
	remaining := 0
	if waitFn != nil {
		remaining = waitFn(lt.InFlightCount)
	}

	lt.mu.Lock()
	// Land in composed/unarmed regardless of drain outcome — the tier is no longer armed and
	// no new work is admitted; a residual in-flight execution (if the bound elapsed) still
	// holds its own budget slot and completes under the emergency-kill authority.
	lt.state = Composed
	lt.composeReason = "quiesced"
	lt.drainCond.Broadcast()
	lt.mu.Unlock()
	return remaining
}

// InFlightCount returns the current in-flight live-execution count.
func (lt *Tier) InFlightCount() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.inFlight
}

// AdmitExecution is called by the live side-effect gate at the boundary. It admits a new live
// execution ONLY when the tier is armed AND admission is not closed, incrementing the in-flight
// count and returning a release callback (invoked exactly once when the execution completes).
// A quiescing/composed/absent tier — or one with admission closed — refuses (release is nil,
// ok is false), so a quiesce reliably rejects new executions. The release decrements the count
// and signals a draining quiesce when it reaches zero.
func (lt *Tier) AdmitExecution() (release func(), ok bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state != Armed || lt.admitClosed {
		return nil, false
	}
	lt.inFlight++
	var once sync.Once
	return func() {
		once.Do(func() {
			lt.mu.Lock()
			if lt.inFlight > 0 {
				lt.inFlight--
			}
			if lt.inFlight == 0 {
				lt.drainCond.Broadcast()
			}
			lt.mu.Unlock()
		})
	}, true
}

// DisarmForRestart forces the tier to composed/unarmed WITHOUT draining — the fail-closed
// restart posture (§17): a re-composed tier is never automatically re-armed. It clears the
// armed bit and closes admission. Safe to call on any state.
func (lt *Tier) DisarmForRestart() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state == Armed || lt.state == Quiescing {
		lt.state = Composed
	}
	lt.admitClosed = false
	lt.composeReason = "restart_unarmed"
	lt.setArmed(false)
}

// DrainWait returns a bounded drain wait for Quiesce: it blocks until the in-flight count reaches
// zero (signaled by each execution's release via drainCond) or the deadline elapses, and returns
// the residual in-flight count. A deadline that is already past returns the current count
// immediately (no wait). It re-reads the count under the lock, so the release path's broadcast
// races cleanly with the wait.
func (lt *Tier) DrainWait(deadline time.Time) func(inFlight func() int) int {
	return func(_ func() int) int {
		lt.mu.Lock()
		defer lt.mu.Unlock()
		for lt.inFlight > 0 {
			now := time.Now()
			if !now.Before(deadline) {
				return lt.inFlight // bound elapsed — residual in flight
			}
			// Timed wait: a timer broadcasts at the deadline so a stalled in-flight execution can
			// never wedge the drain past its bound. The release path also broadcasts on reaching zero.
			timer := time.AfterFunc(deadline.Sub(now), func() {
				lt.mu.Lock()
				lt.drainCond.Broadcast()
				lt.mu.Unlock()
			})
			lt.drainCond.Wait()
			timer.Stop()
		}
		return 0
	}
}
