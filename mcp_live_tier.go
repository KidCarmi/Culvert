package main

import (
	"errors"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Lifecycle transition errors (bounded, fail-closed).
var (
	// errLiveTierNotComposed is returned by arm when the live executor has not been composed —
	// arming a non-existent tier is refused.
	errLiveTierNotComposed = errors.New("mcp live tier: not composed")
	// errLiveTierNotReady is returned by arm when the node-readiness gate is not satisfied.
	errLiveTierNotReady = errors.New("mcp live tier: node not ready to arm")
)

// MCP live-execution tier LIFECYCLE (Live Tier Composition, Arming & Quiesce).
//
// This is the composition-layer owner of the THREE states the program's core principle
// requires never collapse into one:
//
//	Live tier COMPOSED  !=  Live tier ARMED  !=  Canary ACTIVE
//
//	absent      — nothing is composed. No live executor exists. The shipped default.
//	  ↓ compose (opt-in, fail-closed)
//	composed    — the real *execution.Executor + UpstreamCaller + broker exist and are
//	              installed as runtime.Deps.Executor, but the LIVE readiness tier is NOT
//	              armed. modeExecReady still refuses every Canary/Production transition, so
//	              the executor resolves record-only and can never cross the side-effect
//	              boundary. Composition creates CAPABILITY, never permission.
//	  ↓ arm (explicit, authoritative, node-readiness gated)
//	armed       — the LIVE readiness tier is armed (liveExecDepsConfigured==true), so a
//	              Canary MODE transition can now be authorized by the full activation
//	              preflight. Arming grants READINESS, never activation: it composes no
//	              executor (already composed), begins no Canary generation, issues no
//	              approval, and reaches no upstream. Canary is still Observe/Shadow until an
//	              independently-accepted Shadow→Canary transition commits.
//	  ↓ quiesce (explicit)
//	quiescing   — disarm in progress: the tier is un-armed (liveExecDepsConfigured flips
//	              back to false so no new Canary transition can be authorized and no new
//	              live execution can be admitted), in-flight executions are bounded/drained,
//	              and evidence + trust records are preserved. Emergency kill remains
//	              authoritative regardless.
//	  ↓ (drain complete)
//	composed    — back to composed/unarmed. Re-arming is a fresh explicit act.
//
// SEPARATION IS THE WHOLE POINT. This object never begins a Canary activation and never
// reaches an upstream; arming only flips the readiness tier the rollout commit gate and the
// Canary preflight consult. The armed bit is derived here and mirrored into the execdeps
// registry (mcp_rollout_execdeps.go), the single place modeExecReady reads, so exactly one
// authoritative arming path (armLiveTier) toggles liveExecDepsConfigured.
//
// ARMED BY DEFAULT: NO. absent by default; composition is a disabled-by-default opt-in and
// arming is a separate explicit act. A stock build composes nothing and arms nothing.

// liveTierState is the observable lifecycle state (absent/composed/armed/quiescing).
type liveTierState int

const (
	liveTierAbsent liveTierState = iota
	liveTierComposed
	liveTierArmed
	liveTierQuiescing
)

func (s liveTierState) String() string {
	switch s {
	case liveTierComposed:
		return "composed"
	case liveTierArmed:
		return "armed"
	case liveTierQuiescing:
		return "quiescing"
	default:
		return "absent"
	}
}

// mcpLiveTier tracks one capability's live-tier lifecycle. It is deliberately SEPARATE from
// the execdeps armed bit: the armed bit (liveExecDepsConfigured) governs mode transitions and
// the Canary readiness facts, while this object owns the richer composed/armed/quiescing
// lifecycle and the in-flight accounting the quiesce drain needs. The two are kept consistent
// by arm/quiesce, which are the ONLY writers of the armed bit for the live tier.
type mcpLiveTier struct {
	capb rollout.Capability

	mu    sync.Mutex
	state liveTierState
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

// globalMCPLiveTier is the process-global Gateway live-tier lifecycle. Management never
// executes an upstream tools/call, so only the Gateway tier is composed/armed; a Management
// object exists for symmetry and stays absent.
var (
	globalMCPLiveTier     = newMCPLiveTier(rollout.CapabilityGateway)
	globalMCPLiveTierMgmt = newMCPLiveTier(rollout.CapabilityManagement)
)

func newMCPLiveTier(capb rollout.Capability) *mcpLiveTier {
	lt := &mcpLiveTier{capb: capb, state: liveTierAbsent, composeReason: "not_composed"}
	lt.drainCond = sync.NewCond(&lt.mu)
	return lt
}

// mcpLiveTierFor returns the lifecycle object for a capability.
func mcpLiveTierFor(capb rollout.Capability) *mcpLiveTier {
	if capb == rollout.CapabilityManagement {
		return globalMCPLiveTierMgmt
	}
	return globalMCPLiveTier
}

// State returns the current lifecycle state (read-only).
func (lt *mcpLiveTier) State() liveTierState {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state
}

// composed reports whether the live executor object exists (composed or beyond). It is
// distinct from armed: a composed-but-unarmed tier holds the executor but permits no live
// execution.
func (lt *mcpLiveTier) composed() bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state == liveTierComposed || lt.state == liveTierArmed || lt.state == liveTierQuiescing
}

// armed reports whether the live readiness tier is armed. It is the lifecycle-object view;
// the execdeps registry (liveExecDepsConfigured) is the authoritative bit the mode gate
// reads, and arm/quiesce keep the two in lock-step.
func (lt *mcpLiveTier) armed() bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.state == liveTierArmed
}

// markComposed records that the live executor object was composed and installed. It moves
// absent→composed. It never arms. A second call is idempotent. The bounded reason is fixed
// ("composed") — a composition that does NOT proceed records its reason via setComposeReason.
func (lt *mcpLiveTier) markComposed() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state == liveTierAbsent {
		lt.state = liveTierComposed
	}
	lt.composeReason = "composed"
}

// setComposeReason records a bounded classification for a composition that did NOT proceed
// (opt-out, missing dependency), leaving the state absent.
func (lt *mcpLiveTier) setComposeReason(reason string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.composeReason = reason
}

// Reason returns the bounded composition classification for the status surface.
func (lt *mcpLiveTier) Reason() string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.composeReason == "" {
		return "not_composed"
	}
	return lt.composeReason
}

// status builds the bounded, read-only status for the admin/health surface. It distinguishes
// composed from armed from Canary-active (the last is the rollout mode, read elsewhere), and
// carries no secret/tenant/subject.
func (lt *mcpLiveTier) status() map[string]any {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return map[string]any{
		"state":           lt.state.String(),
		"composed":        lt.state == liveTierComposed || lt.state == liveTierArmed || lt.state == liveTierQuiescing,
		"armed":           lt.state == liveTierArmed,
		"compose_reason":  lt.composeReason,
		"in_flight":       lt.inFlight,
		"admit_closed":    lt.admitClosed,
		"live_deps_ready": liveExecDepsConfigured(lt.capb == rollout.CapabilityManagement),
	}
}

// --- lifecycle transitions -------------------------------------------------

// arm moves composed→armed and, as its ONLY authoritative side effect on the mode gate,
// sets liveExecDepsConfigured for this capability so a Canary MODE transition can be
// authorized. It is the SOLE caller of markGatewayExecDepsReady (pinned by the evolved
// execution-posture wall). It refuses fail-closed unless the tier is composed and the caller
// asserts node readiness (ready==true). Arming NEVER activates Canary: it begins no Canary
// generation, reaches no upstream, and leaves the rollout mode untouched — a later
// independently-accepted Shadow→Canary transition is still required (§16).
//
// ready is computed by the authoritative arming path (mcp_live_arming.go) from live node
// state; passing it in keeps this transition pure and testable while the readiness gate stays
// the real, node-derived one in production.
func (lt *mcpLiveTier) arm(ready bool, reason string) error {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state != liveTierComposed {
		return errLiveTierNotComposed
	}
	if !ready {
		return errLiveTierNotReady
	}
	lt.state = liveTierArmed
	lt.admitClosed = false
	lt.composeReason = reason
	// Mirror the armed bit into the execdeps registry — the single place modeExecReady and
	// the Canary preflight read. This is the one authoritative arming toggle.
	setLiveExecDepsArmed(lt.capb, true)
	return nil
}

// quiesce moves armed→quiescing→composed. It is the inverse of arm: it un-arms the readiness
// tier FIRST (so no new Canary transition can be authorized and modeExecReady refuses live
// modes), closes new-execution admission, then BOUNDS the drain of in-flight executions to
// waitFn (a caller-supplied bounded wait that returns when inFlight==0 or a deadline elapses).
// It returns the number of executions still in flight when the drain bound elapsed (0 on a
// clean drain). Quiesce preserves evidence and trust records (it touches neither) and never
// widens scope. Emergency kill remains authoritative regardless of quiesce.
//
// The un-arm is durable-in-effect immediately: setLiveExecDepsArmed(false) means a concurrent
// rollout commit into a live mode fails closed at modeExecReady, and admitClosed=true means a
// concurrent gate admission is rejected even before the armed bit is observed — the two
// together are the "reject new" guarantee that holds mid-transition.
func (lt *mcpLiveTier) quiesce(waitFn func(inFlight func() int) int) int {
	// SERIALIZE the readiness revocation with rollout commits (Codex P1 round-5, PR #1290). A Canary
	// transition reads liveExecDepsConfigured under mcpRollout.durableMu and then installs+persists
	// Canary while still holding it; if quiesce cleared the armed bit under lt.mu alone it could
	// interleave between that read and the install, so the commit would be acknowledged and the runtime
	// armed AFTER the tier reached composed/unarmed — and a later arm would resume that Canary with no
	// fresh activation transition. Taking durableMu here forces the revocation to land either wholly
	// before the commit's armed read or wholly after its install. Lock order is durableMu → lt.mu, which
	// is deadlock-free: no durableMu holder (the commit path, kill switch, rehearsal) ever takes lt.mu.
	// durableMu is held ONLY for the fail-closed revocation phase and is released BEFORE the bounded
	// (possibly slow) in-flight drain, so quiesce never blocks a commit for the drain duration.
	r := getMCPRollout()
	r.durableMu.Lock()
	lt.mu.Lock()
	needDrain := lt.enterQuiesceLocked()
	lt.mu.Unlock()
	r.durableMu.Unlock()
	return lt.drainAndLeaveQuiesce(needDrain, waitFn)
}

// quiesceHoldingDurableMu is quiesce for a caller that ALREADY holds mcpRollout.durableMu — the
// rollout commit path, which quiesces the live tier before invalidating the Canary generation on a
// leaving-live demotion (Codex P1 round-7, PR #1290). quiesce() would self-deadlock re-acquiring the
// non-reentrant durableMu, so the revocation runs under the already-held lock. Unlike quiesce, the
// bounded drain therefore runs while durableMu is still held — acceptable because a demotion is a
// terminal safety action bounded by the caller's drain deadline, and lock order stays durableMu → lt.mu
// (the drain waits on lt.mu's drainCond; the release path takes only lt.mu, never durableMu).
func (lt *mcpLiveTier) quiesceHoldingDurableMu(waitFn func(inFlight func() int) int) int {
	lt.mu.Lock()
	needDrain := lt.enterQuiesceLocked()
	lt.mu.Unlock()
	return lt.drainAndLeaveQuiesce(needDrain, waitFn)
}

// enterQuiesceLocked performs the fail-closed revocation half of a quiesce and reports whether a drain
// is required. Caller holds lt.mu (and, for the commit path, durableMu). An armed tier transitions to
// quiescing, closes admission, and un-arms the mode gate. A tier that is NOT armed but still carries
// residual in-flight work — a prior bounded quiesce whose drain bound elapsed left it composed/unarmed
// with inFlight>0 — keeps admission closed and still needs a drain: a retry MUST NOT report a clean
// drain (0) while an upstream request is still running (Codex P2 round-7, PR #1290). A truly idle
// not-armed tier needs no drain (idempotent no-op).
func (lt *mcpLiveTier) enterQuiesceLocked() (needDrain bool) {
	switch {
	case lt.state == liveTierArmed:
		lt.state = liveTierQuiescing
		lt.admitClosed = true
		lt.composeReason = "quiescing"
		// Un-arm the mode gate BEFORE draining: a request that has not already been admitted can
		// never be admitted now, and no new Canary transition can be authorized.
		setLiveExecDepsArmed(lt.capb, false)
		return true
	case lt.inFlight > 0:
		// Residual in-flight under a composed/unarmed tier (a prior bounded quiesce timed out). Admission
		// is already closed from that quiesce; keep it closed and drain/report the residual rather than
		// falsely reporting a clean drain.
		lt.admitClosed = true
		return true
	default:
		return false
	}
}

// drainAndLeaveQuiesce runs the bounded drain (when needed) and lands the tier composed/unarmed. It is
// shared by quiesce and quiesceHoldingDurableMu; the only difference between them is whether durableMu
// is held across it (see quiesceHoldingDurableMu). A not-needed drain is an idempotent no-op returning 0.
func (lt *mcpLiveTier) drainAndLeaveQuiesce(needDrain bool, waitFn func(inFlight func() int) int) int {
	if !needDrain {
		return 0
	}
	// Bounded drain of in-flight executions. The caller owns the deadline; the wait reads the
	// live in-flight count under the lock via inFlightCount.
	remaining := 0
	if waitFn != nil {
		remaining = waitFn(lt.inFlightCount)
	}

	lt.mu.Lock()
	// Land in composed/unarmed regardless of drain outcome — the tier is no longer armed and
	// no new work is admitted; a residual in-flight execution (if the bound elapsed) still
	// holds its own budget slot and completes under the emergency-kill authority.
	lt.state = liveTierComposed
	lt.composeReason = "quiesced"
	lt.drainCond.Broadcast()
	lt.mu.Unlock()
	return remaining
}

// inFlightCount returns the current in-flight live-execution count.
func (lt *mcpLiveTier) inFlightCount() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.inFlight
}

// admitExecution is called by the live side-effect gate at the boundary. It admits a new live
// execution ONLY when the tier is armed AND admission is not closed, incrementing the in-flight
// count and returning a release callback (invoked exactly once when the execution completes).
// A quiescing/composed/absent tier — or one with admission closed — refuses (release is nil,
// ok is false), so a quiesce reliably rejects new executions. The release decrements the count
// and signals a draining quiesce when it reaches zero.
func (lt *mcpLiveTier) admitExecution() (release func(), ok bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state != liveTierArmed || lt.admitClosed {
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

// disarmForRestart forces the tier to composed/unarmed WITHOUT draining — the fail-closed
// restart posture (§17): a re-composed tier is never automatically re-armed. It clears the
// armed bit and closes admission. Safe to call on any state.
func (lt *mcpLiveTier) disarmForRestart() {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if lt.state == liveTierArmed || lt.state == liveTierQuiescing {
		lt.state = liveTierComposed
	}
	lt.admitClosed = false
	lt.composeReason = "restart_unarmed"
	setLiveExecDepsArmed(lt.capb, false)
}
