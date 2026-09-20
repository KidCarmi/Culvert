package main

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// mcpLiveSideEffectGate is the composition-layer implementation of execution.LiveExecutionGate.
// It runs the three gates that must live OUTSIDE the execution package — at the side-effect
// boundary, immediately before the executor's own tool-freshness + emergency-kill re-check:
//
//	(1) LIFECYCLE admission — reject a new live execution once quiesce has started (§6). This is
//	    FIRST so a quiescing tier never even reaches the budget/trust work.
//	(2) READ-FIRST (§9) — only OpRead/OpDiscovery may cross the boundary, decided from Culvert's
//	    own operation class, never the server-provided readOnlyHint.
//	(3) RUNTIME LIVE-TRUST revalidation (§10) — an active, unexpired live_execution approval must
//	    bind the EXACT current (tenant, server, tool, fingerprint) at THIS instant. A preflight
//	    approval that was revoked/expired, or a tool that drifted, fails closed here even though
//	    the transition preflight passed. No shadow-approval fallback.
//	(4) BUDGET reservation (§8) — the Canary blast-radius budget must grant a slot for this
//	    execution identity. A denied budget means Upstream.Call == 0. The reservation persists the
//	    spend BEFORE the grant, so a restart never replays it.
//
// Every seam is an injectable func so the deterministic race/mutation tests drive the exact
// admission logic with controlled inputs; the production constructor wires the real singletons.
// The gate performs NO upstream call and NO credential materialization.
type mcpLiveSideEffectGate struct {
	capb rollout.Capability

	// admit is the lifecycle admission (globalMCPLiveTier.admitExecution): returns a release and
	// ok==true only while armed and not quiescing.
	admit func() (release func(), ok bool)
	// admitOpen is the read-only form of the same question (globalMCPLiveTier.admissionOpen),
	// used as the auxiliary admission's final-boundary revalidation so a disarm or quiesce that
	// lands after admission still refuses. It takes no in-flight slot.
	admitOpen func() bool
	// readFirst decides whether the operation class may cross the boundary.
	readFirst func(policy.OperationClass) bool
	// trustPrecheck is the LOCK-FREE half of live-execution trust revalidation, bound to the
	// DECISION's fingerprint (the fingerprint the request was actually decided against). It is the
	// only half that can report a whole-Canary DRIFT code, and it reads only pointer-published
	// inventory state — which is what makes it legal to run inside the activation critical section
	// (§5). It is called TWICE per admission by design: once before the lock to decide whether the
	// approval lookup is worth doing, and once INSIDE the lock, where its verdict is the one the
	// latch is actually charged to.
	trustPrecheck func(tenant, serverID, toolName, fingerprint string) liveTrustPrecheck
	// approvalOK is the BLOCKING half: it consults the durable approval store, so it runs OUTSIDE
	// the activation lock. It can only ever produce a request-scoped verdict — it never reports
	// drift and never latches anything, which is exactly why it does not need to be attributed to
	// an activation generation.
	// It also takes the CLASS IN FORCE, because a satisfying approval is not enough: an approval
	// carries its own reviewed operation class, and a later approval for the same exact fingerprint
	// can state a DIFFERENT one — a reviewer correcting an earlier determination. Matching "any live
	// grant" would then let a tool the current review calls MUTATING keep executing read-first on
	// the strength of the activation's older immutable record (Codex P1, PR #1370, round 5).
	approvalOK func(tgt canary.LiveTarget, class policy.OperationClass, now time.Time) (satisfied bool, driftCode string)
	// admitUnderActivation is THE atomic activation-bound admission transaction: it verifies an
	// armed activation, captures its exact generation, evaluates the trust probe, latches an
	// authoritative drift against that generation, and reserves the budget — all under one
	// acquisition of the activation lock, which it owns and never exposes.
	//
	// It replaces the reserve / tripBreach / currentGeneration trio this gate used to sequence
	// itself. That composition was the defect: no ordering of unlocked reads can establish that the
	// generation being latched was continuously active across the trust observation, and Codex
	// rounds 15-19 produced a P1 against every arrangement of them.
	//
	// It takes the request's DECIDED operation class so the transaction can revalidate it against
	// the activation it is about to charge — see step (5b) in admitLiveExecution. The class is not
	// recomputed here; it is the one the decision carries, handed to the only place that knows
	// which activation is paying.
	admitUnderActivation func(now time.Time, opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission
	// currentScopeHash reports the rollout scope in force for this capability. It is handed to
	// the transaction as a PROBE so the read happens inside the activation lock, at the moment
	// budget authority is decided — a hash read out here could already be stale by then.
	currentScopeHash func() string
	// releaseBudget returns the in-flight concurrency slot for a reservation made under gen.
	releaseBudget func(gen uint64)
	// generationCurrent is the final-boundary revalidation: it reports whether the activation
	// generation a reservation was made under is STILL the current, armed, execution-eligible
	// generation. A concurrent Canary demotion between admission and the upstream call makes it
	// return false so the executor refuses at the boundary (§10 completeness; Codex P1 round-8).
	generationCurrent func(gen uint64) bool
	// note records a bounded denial reason for metrics/telemetry (never a secret). Optional.
	note func(reason mcperr.Reason)
	// now is the clock the FINAL-BOUNDARY revalidation reads. It is deliberately separate from
	// LiveGateInput.Now, which is stamped when the gate input is built: the boundary predicate may
	// run much later — after the durable commit, after credential materialization, and after an
	// unbounded wait for an upstream pool slot — and an approval's validity must be judged at the
	// instant it is about to be spent, not at the instant the request was admitted. Nil ⇒ the
	// admission instant is reused, which is the pre-existing behaviour and never falsely refuses.
	now func() time.Time
}

var _ execution.LiveExecutionGate = (*mcpLiveSideEffectGate)(nil)

// newMCPLiveSideEffectGate wires the production gate for the Gateway capability from the real
// composition-layer singletons.
func newMCPLiveSideEffectGate(capb rollout.Capability) *mcpLiveSideEffectGate {
	lt := mcpLiveTierFor(capb)
	return &mcpLiveSideEffectGate{
		capb:          capb,
		admit:         lt.admitExecution,
		admitOpen:     lt.admissionOpen,
		readFirst:     canary.IsReadFirstOperation,
		trustPrecheck: mcpLiveTrustPrecheck,
		approvalOK:    mcpLiveApprovalSatisfied,
		admitUnderActivation: func(now time.Time, opClass policy.OperationClass, resolvedScope string, scopeNow canaryScopeProbe, ident canary.ExecutionIdentity, trust canaryTrustProbe) canaryAdmission {
			return globalCanaryRuntime.admitLiveExecution(capb, now, opClass, resolvedScope, scopeNow, ident, trust)
		},
		currentScopeHash:  func() string { return getMCPRollout().stateFor(capb).ScopeHash() },
		releaseBudget:     func(gen uint64) { globalCanaryRuntime.releaseCanaryExecution(capb, gen) },
		generationCurrent: func(gen uint64) bool { return globalCanaryRuntime.generationActive(capb, gen) },
		note:              noteMCPLiveGateDenied,
		now:               func() time.Time { return canaryNow() },
	}
}

// AdmitSideEffect implements execution.LiveExecutionGate. It runs the four gates in order and
// fails closed on any of them, releasing every slot it acquired along the way, so a denial can
// never leak a lifecycle in-flight count or a budget concurrency slot.
func (g *mcpLiveSideEffectGate) AdmitSideEffect(in execution.LiveGateInput) execution.LiveGateDecision {
	deny := func(reason mcperr.Reason) execution.LiveGateDecision {
		if g.note != nil {
			g.note(reason)
		}
		return execution.LiveGateDecision{Admit: false, Reason: reason}
	}

	// (1) Lifecycle admission — rejects a new execution during quiesce/unarmed (§6).
	releaseAdmit, ok := g.admit()
	if !ok {
		return deny(mcperr.ReasonRolloutModeInvalid)
	}

	// (2) Read-first (§9).
	if !g.readFirst(in.Operation) {
		releaseAdmit()
		return deny(mcperr.ReasonRolloutOutOfScope)
	}

	// (3+4) ATOMIC activation-bound trust revalidation, drift latch and budget reservation.
	//
	// These were three steps this gate sequenced itself, reading the activation generation around
	// them. That is the shape Codex rounds 15-19 defeated five times: no arrangement of unlocked
	// reads proves the generation being latched was continuously active across the trust
	// observation, and counter equality proves only that the value did not change — not that it was
	// ever live (the rollout publication gap, §6). They are now ONE transaction that owns the
	// activation lock for its whole duration and hands back facts.
	//
	// The gate does not manage activation locking and never sees the mutex. The probe it supplies
	// is local control-plane state only — no network I/O, no credential materialization, no DNS, no
	// upstream call — which is what makes holding the lock across it legitimate (§5).
	//
	// EVERY PART OF TRUST IS EVALUATED INSIDE THE TRANSACTION, INCLUDING THE APPROVAL.
	//
	// An earlier revision hoisted the approval lookup out of the lock to keep the durable
	// approval store's mutex off the critical section (§5). That was a real hazard, but hoisting
	// was the wrong fix and it bought a worse one: a request that read approved=true and then
	// waited for cr.mu could be admitted after the approval was REVOKED in that window, and
	// nothing downstream would catch it — the final boundary re-reads tool freshness, generation
	// and kill state, not approval status. Revoking a LIVE approval does not disturb the
	// fingerprint or eligibility either, because catalog promotion is derived from SHADOW-purpose
	// approvals (rederiveTool), so the in-lock precheck would still report Eligible. A stale
	// yes would have authorized an irreversible call (Codex round 22).
	//
	// The store read is now LOCK-FREE at the source (tooltrust publishes a copy-on-write snapshot
	// through an atomic pointer), so the §5 hazard is removed rather than relocated, and the
	// admission transaction can evaluate the whole predicate under one lock exactly as it did
	// before the split.
	adm := g.admitUnderActivation(in.Now, in.Operation, in.ResolvedScopeHash, g.currentScopeHash, canary.ExecutionIdentity{
		Principal: in.Principal,
		Tool:      in.ToolName,
		Server:    in.ServerID,
	}, func() canaryTrustObservation {
		live := g.trustPrecheck(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint)
		if !live.Eligible && live.Resolved {
			// RESOLVED BUT NOT AUTHORIZED, in one shape for all three reasons — the anchor is
			// gone, the target changed hands, or this request's decision fingerprint is not the
			// one in force. Every fact the transaction needs is carried and none of them is
			// pre-classified: canaryDriftCause decides scope first and cause second, and Trusted
			// stays false so nothing here authorizes anything.
			return canaryTrustObservation{
				DriftCode: live.DriftCode, Found: true,
				Current: live.Authoritative, AnchorLost: live.AnchorLost,
			}
		}
		if !live.Eligible {
			// NOTHING RESOLVED — the only ineligible case left, because the branch above already
			// reported every one that did. There is nothing to compare against, and a transient
			// inventory gap must not stop the experiment (Codex P1, PR #1360, round 6).
			//
			// Round 31 left a second, unreachable copy of the resolved case here. It was harmless
			// in production (the branch above returns first) and NOT harmless in the campaign: the
			// mutation that deletes the live branch was still satisfied by the dead one, so M36
			// survived while claiming to prove that a target under a new owner is carried out.
			return canaryTrustObservation{}
		}
		// The CURRENT authoritative target, including the pinned server identity, for the
		// transaction to compare against the activation's reviewed record. The identity read is
		// the same pointer-published inventory the precheck just used.
		cur := canary.ReviewedTarget{
			Tenant:            live.Target.Tenant,
			ServerID:          live.Target.ServerID,
			ToolName:          live.Target.ToolName,
			Fingerprint:       live.Target.Fingerprint,
			FingerprintFormat: live.Target.FingerprintFormat,
			ServerIdentity:    live.ServerIdentity,
		}
		trusted, _ := g.approvalOK(live.Target, in.Operation, in.Now)
		return canaryTrustObservation{Found: true, Current: cur, Trusted: trusted}
	})
	// The denial class is read from an EXPLICIT field, never inferred from which other field is
	// zero: an already-aborted Canary and an untrusted request both leave Trusted false, and
	// inferring from that reported a stopped experiment to the client as a trust failure.
	//
	// The switch is EXHAUSTIVE BY CONSTRUCTION: only canaryAdmitGranted continues to the admitted
	// path, and any denial class this gate does not recognise falls to a fail-CLOSED default. An
	// earlier shape listed the known denials and let everything else fall through to "admitted",
	// so adding a denial to the transaction silently ADMITTED the requests it was written to
	// refuse — a new refusal reason arriving as a grant is the one direction this boundary must
	// never fail in.
	switch adm.Denial {
	case canaryAdmitNoActivation:
		// No activation owned this transaction — the rollout publication gap, a demotion, or an
		// unarmed runtime. Admission fails CLOSED, and because there was no generation to attribute
		// to, NOTHING was latched: a drift seen here can never stop an activation created later (§6).
		releaseAdmit()
		return deny(mcperr.ReasonRolloutModeInvalid)
	case canaryAdmitDrift:
		// AUTHORITATIVE DRIFT (blocker #7 §17). The reviewed tool/server is no longer the one the
		// approval was granted against — proof the experiment's premise no longer holds, so the
		// request fails closed AND the whole Canary latches. The latch already happened INSIDE the
		// transaction, against the exact generation the probe ran under.
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	case canaryAdmitUntrusted:
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	case canaryAdmitNotReviewed:
		// The activation was never reviewed for this target. Request-scoped (nothing latched, per
		// the transaction), and reported as a trust-revalidation failure: from the caller's side
		// the target it named is not one this experiment is authorized to execute.
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	case canaryAdmitScopeNotInForce:
		// The authorization envelope this request resolved under is no longer installed — a
		// scope edit landed between resolution and the boundary. Request-scoped: NOTHING is
		// latched, because an operator changing a scope is the system working, not evidence
		// that the reviewed target drifted. Reported as out-of-scope, which is literally what
		// happened from the caller's side: it is not in the scope that is in force.
		releaseAdmit()
		return deny(mcperr.ReasonRolloutOutOfScope)
	case canaryAdmitClassNotInForce:
		// The activation that would be charged does not bind this request's operation class to this
		// target — a read-first decision taken under an activation that has since been replaced by
		// one whose review says otherwise. Request-scoped (nothing latched: the TARGET did not
		// move, the review of it changed), and reported with the read-first gate's own bounded
		// reason, because from the caller's side that is exactly what happened — this operation is
		// not read-first here.
		releaseAdmit()
		return deny(mcperr.ReasonRolloutOutOfScope)
	case canaryAdmitAborted, canaryAdmitBudget:
		releaseAdmit()
		return deny(mcperr.ReasonRolloutBudgetExhausted)
	case canaryAdmitGranted:
		// The one class that authorizes a physical attempt. Named explicitly so
		// the default below can be what it should be.
	default:
		// FAIL CLOSED on a class this gate does not know. Reaching the admit
		// path by falling out of a switch is how a denial added to
		// canaryAdmissionDenial later would silently authorize an irreversible
		// upstream call: every existing class is handled above, so this branch
		// changes nothing today and is the whole point — the boundary must deny
		// what it cannot classify, not admit it.
		//
		// This branch and canaryAdmitNotReviewed above arrived from two sides at
		// once: main closed the fall-through generically (PR #1298) while this
		// branch hit it concretely, by adding a denial class the switch did not
		// list and watching the requests it was written to refuse be ADMITTED.
		// Both halves are kept — the new class is handled explicitly, and the
		// default still catches the next one.
		releaseAdmit()
		return deny(mcperr.ReasonRolloutModeInvalid)
	}
	if !adm.Granted() {
		// Belt-and-braces against the two halves disagreeing: Granted() is the
		// single authority on whether a physical attempt is authorized.
		releaseAdmit()
		return deny(mcperr.ReasonRolloutModeInvalid)
	}
	gen := adm.Generation

	// Admitted. Revalidate is the final-boundary re-check the executor runs right before the kill
	// re-read: it fails closed if the generation this reservation was made under is no longer current
	// (a concurrent demotion), so an already-admitted request cannot cross the boundary after a
	// leaving-live transition returned (Codex P1 round-8). The release runs exactly once after the
	// upstream leg (executor defers it), and returns BOTH the budget concurrency slot and the lifecycle
	// in-flight count — including the §11 case where a later kill/freshness/demotion abort occurs after
	// this admit.
	// Reservation identity (review §5/§6). The budget enforcer meters COUNTS, not
	// identities, so the grant itself carries no name. Minting one here — at the
	// single admission point, after the slot is actually granted — binds each
	// physical attempt to the exact slot that paid for it, so an effect can never be
	// attributed to an unauthorized reservation and an orphan can be traced back to
	// its grant. Failing to mint fails CLOSED: an unnameable reservation must not be
	// allowed to authorize an unattributable side effect.
	resID, rerr := newCanaryReservationID()
	if rerr != nil {
		g.releaseBudget(gen)
		releaseAdmit()
		return deny(mcperr.ReasonEventEvidenceMissing)
	}

	return execution.LiveGateDecision{
		Admit:                true,
		ReservationID:        resID,
		ActivationGeneration: gen,
		Revalidate: func() mcperr.Reason {
			// THREE AUTHORITIES, ALL RE-ASKED AT THE FINAL BOUNDARY — and the answer NAMES which
			// one was withdrawn, because the same withdrawal must be diagnosed identically whether
			// admission or the boundary caught it (Codex P2, PR #1370, round 4).
			//
			// Admission is one atomic transaction under cr.mu, but none of these three facts is
			// frozen by it. The scope is published under rollout.State's OWN lock (swapMu), which
			// this transaction does not hold and must not (taking a rollout lock inside the
			// activation lock would invert the order every other caller uses). The approval lives
			// in the durable tooltrust store, which an operator can revoke at any moment. The
			// generation moves on a demotion. So admission can only ever prove all three were in
			// force AT THAT INSTANT — and between that instant and Upstream.Call the request still
			// has to get through credential materialization, the durable decision commit, and an
			// unbounded wait for an upstream pool slot.
			//
			// That window is exactly why the kill state is re-read here (PREREQ-MCP-KILL-1), and a
			// withdrawn envelope, a demoted generation and a revoked four-eyes grant all deserve
			// the same treatment (Codex P1, PR #1370, rounds 3 and 4).
			//
			// Serializing any of these with the admission transaction was the alternative remedy
			// and is deliberately NOT taken: it would make an operator's scope edit or revocation
			// block behind every in-flight admission, and it would still leave the post-admission
			// window open, since the request continues long after the transaction returns.
			// Re-asking at the boundary closes the window instead of narrowing it.
			//
			// ORDER: generation, then scope, then approval — and the order is part of the
			// contract, not a performance choice. Asking "is there still an activation" FIRST
			// matches admission's own precedence and is what makes the other two answers
			// meaningful: they describe a live experiment rather than reporting on one that has
			// already ended. See the generation branch below for the leaving-live window that
			// makes a scope-first order report a diagnosis a fresh request would never get
			// (Codex P3, PR #1370, round 6 — this line still said scope-first after the order
			// was changed, which is exactly the stale instruction beside a security predicate
			// that invites a future maintainer to restore the defect).
			//
			// The durable approval store is consulted last, so it is reached only for a request
			// the other two still authorize.
			//
			// No "unwired ⇒ allow" escape hatch is needed on the scope half, unlike the generation
			// seam: an admitted request has already passed step (5c), which fails closed on a nil
			// probe and on an empty envelope, so neither degenerate input can reach this closure.
			// GENERATION FIRST, matching admission's own precedence (step (1): no activation owns
			// the transaction at all). A Canary→non-live commit un-arms the tier and publishes the
			// new scope BEFORE demoteCanary invalidates the generation, so in that window BOTH are
			// withdrawn — and a scope-first order would report `rollout_out_of_scope` for an
			// already-admitted request while a fresh request in the identical final state is
			// refused `rollout_mode_invalid` by the unarmed lifecycle gate. That is the same
			// diagnosis-depends-on-timing defect the reason plumbing was added to remove, one layer
			// in (Codex P2, PR #1370, round 5). Asking "is there still an activation" first makes
			// the scope and approval answers meaningful: they describe a LIVE experiment.
			if g.generationCurrent != nil && !g.generationCurrent(gen) {
				return mcperr.ReasonRolloutModeInvalid
			}
			if !canaryScopeInForce(in.ResolvedScopeHash, g.currentScopeHash) {
				return mcperr.ReasonRolloutOutOfScope
			}
			// THE APPROVAL IS RE-ASKED AT A FRESH INSTANT, AND MUST STILL STATE THIS CLASS. Round 22
			// moved the approval lookup INTO the admission transaction so a revocation racing the
			// lock could not be admitted, and recorded in this file that "the final boundary re-reads
			// tool freshness, generation and kill state, not approval status". That residual is this
			// branch: a grant revoked or expired after admission — while the request waited on the
			// durable commit or a pool slot — otherwise still authorized an irreversible call.
			// ToolStillCurrent does not cover it (it checks catalog freshness), and neither the scope
			// nor the generation moves when an approval is withdrawn.
			//
			// The CLASS is part of the question for the reason on approvalOK's declaration: an
			// approval states its own reviewed class, so a later approval for the same fingerprint
			// can correct an earlier determination, and "some live grant exists" would let the
			// correction be ignored for the rest of the activation's window.
			//
			// The target is re-resolved from the SAME lock-free pointer-published inventory the
			// admission probe used, never from a request-supplied claim, and the time is read NOW
			// rather than at admission — an approval that expired while this request waited must not
			// be spent on the strength of how fresh it was when the wait began.
			//
			// PEER FRESHNESS IS THE FOURTH AUTHORITY, AND IT IS THE ONE THAT EXPIRES BY ITSELF
			// (blocker #11). The three above all go false because something HAPPENED — a
			// demotion, a scope edit, a revocation. This one goes false with no state change at
			// all, purely by the clock advancing past the last authenticated sighting of the
			// peer. That is precisely why activation-time readiness cannot stand in for it: an
			// observation can satisfy the preflight and expire while the request is still in
			// flight, and the window is not small — a request waits through credential
			// materialization, the durable decision commit, and an unbounded wait for an upstream
			// pool slot.
			//
			// It rides the SAME trustPrecheck capture as the approval check below, so the
			// evidence and the target it describes come from one snapshot. Re-reading the catalog
			// for it would judge the freshness of a record this request is not about to execute
			// against — the two-publication window pinnedIdentity's comment describes, one field
			// over.
			//
			// THE GUARD IS ON trustPrecheck ALONE, where it used to require approvalOK too. That
			// is deliberate: peer freshness does not depend on the approval seam, so gating it on
			// approvalOK being wired would mean forgetting to wire the approval silently disables
			// freshness as well — the permissive direction, and the failure mode a composition
			// seam must never have. Production wires both, so nothing changes there; a partially
			// composed gate now refuses more, never less.
			return g.revalidateTargetTrust(in)
		},
		Release: func() {
			g.releaseBudget(gen)
			releaseAdmit()
		},
	}
}

// AdmitAuxiliary implements execution.LiveExecutionGate for NON-side-effect-bearing traffic —
// MCP lifecycle (initialize / notifications/initialized / ping / notifications/cancelled) and
// discovery (tools/list). SEC-MCP-AUX-1.
//
// It runs gate (1) ONLY — the lifecycle admission. The other three are deliberately absent, and
// each absence is a decision rather than an omission:
//
//   - READ-FIRST (2) is not asked, because the operation class carried by session lifecycle
//     traffic is not the tool-call class the read-first rule was written for; asking it here is
//     the gate answering a question about a tool that does not exist.
//   - LIVE-TRUST REVALIDATION (3) is not asked for the same reason and more sharply: it binds
//     (tenant, server, TOOL, fingerprint), and auxiliary traffic has no tool binding, so the
//     production predicate refuses every time. That refusal is what made an armed Canary node
//     unable to complete a session handshake or list tools.
//   - BUDGET RESERVATION (4) is not taken, because the budget counts AUTHORIZED TOOL
//     EXECUTIONS. Spending a slot on a call that can cause no side effect makes
//     MaxTotalExecutions stop measuring physical invocations, which is exactly the accounting
//     property the physical-effect ledger exists to establish.
//
// What remains is the half that DOES apply: a tier the operator has disarmed, or has begun
// quiescing, must not open a session to a third-party upstream, read its catalog, or carry a
// materialized credential to it. That is the same fail-closed posture a restart deliberately
// leaves behind (a re-composed tier is never automatically re-armed), and it must not depend on
// which method the client happened to send.
//
// The returned Revalidate re-asks the SAME question read-only at the final boundary, so a
// disarm or quiesce landing between admission and the irreversible call still refuses; Release
// returns the lifecycle in-flight count exactly once, so a quiesce drain always completes.
// No ReservationID and no ActivationGeneration are returned: an auxiliary invocation has no
// attempt, so naming a slot it never consumed could only misattribute a physical effect.
func (g *mcpLiveSideEffectGate) AdmitAuxiliary(_ execution.LiveGateInput) execution.LiveGateDecision {
	releaseAdmit, ok := g.admit()
	if !ok {
		if g.note != nil {
			g.note(mcperr.ReasonRolloutModeInvalid)
		}
		return execution.LiveGateDecision{Admit: false, Reason: mcperr.ReasonRolloutModeInvalid}
	}
	return execution.LiveGateDecision{
		Admit: true,
		Revalidate: func() mcperr.Reason {
			if g.admitOpen == nil {
				return mcperr.ReasonNone // no revalidation seam wired ⇒ preserve the admission decision
			}
			if !g.admitOpen() {
				return mcperr.ReasonRolloutModeInvalid
			}
			return mcperr.ReasonNone
		},
		Release: releaseAdmit,
	}
}

// mcpLiveTrustRevalidate is the runtime live-execution trust revalidation (§10). It resolves the
// CURRENT authoritative target for (serverID, toolName) from the tool-trust coordinator (never a
// request-supplied claim) and requires an active, unexpired live_execution approval that binds
// that EXACT (tenant, server, tool, fingerprint, format) under the full first-Canary governance
// (canary.SatisfiesLiveExecution). It is fail-closed: an uncomposed coordinator, a missing tool,
// a tenant mismatch, an unusable server, a fingerprint that no longer matches the decision, or no
// satisfying approval all deny. It NEVER consults a shadow approval (SatisfiesLiveExecution rejects
// a non-live purpose) and NEVER materializes a credential.

// liveTrustPrecheck is the LOCK-FREE half of live-execution trust revalidation: everything that can
// produce an authoritative whole-Canary DRIFT verdict, and nothing that can block.
type liveTrustPrecheck struct {
	// DriftCode is non-empty only for an AUTHORITATIVE drift — the whole-Canary breach codes.
	DriftCode string
	// Eligible reports that the target is present, is this tenant's, is usable, and still carries
	// the decision's fingerprint. False with an empty DriftCode is a request-scoped denial.
	Eligible bool
	Target   canary.LiveTarget
	// Resolved reports that the (server, tool) resolves to an authoritative target AT ALL —
	// independently of whether that target belongs to the REQUESTING tenant. Authoritative carries
	// it when true.
	//
	// The two facts are separate because conflating them loses a breach. A reviewed (server, tool)
	// reassigned from tenant A to B makes an A-request ineligible, and reporting that as "nothing
	// resolves" discards the very evidence the reviewed comparison needs: the target IS the
	// reviewed one, under a different owner. Admission would then issue a request-scoped denial,
	// never compare, and reassigning back to A would resume the activation with nothing latched
	// (Codex P1, PR #1360, round 6).
	Resolved bool
	// AnchorLost reports that the trust anchor is no longer in force — the server is not usable,
	// or the registry pins an identity the catalog record was not built against. It is a FACT, not
	// a verdict: whether it may stop the activation depends on the reviewed set, which only the
	// admission transaction can consult (canaryDriftCause). Pre-classifying it here as a drift
	// code is what let an unreviewed target's disabled server abort a healthy Canary.
	AnchorLost bool
	// Authoritative is the CURRENT authoritative target, from the SAME loadTarget snapshot as
	// every other field here — never a second read. Meaningful only when Resolved.
	Authoritative canary.ReviewedTarget
	// ServerIdentity is the server's PINNED, verified identity as currently published. It rides
	// along here rather than in Target because Target is canary.LiveTarget — the key an approval is
	// matched on — and approvals record no identity, so widening it would break exact-target
	// approval matching. It is what makes server_identity_drift decidable against what was
	// REVIEWED rather than only against "is the server usable right now".
	ServerIdentity string
	// Observed is the PEER OBSERVATION carried on the catalog record this verdict describes, and
	// RegistryPin is the registry's current pinned identity — both from the SAME loadTarget
	// snapshot as every field above (blocker #11). They ride along so the side-effect boundary can
	// re-ask peer freshness from the capture it is already making, rather than re-reading the
	// catalog and judging the freshness of a record it is not about to execute against.
	//
	// A zero Observed is the shipped default and the fail-closed answer: an operator-seeded record
	// has never been backed by a peer, and a restart returns every record to exactly that state.
	Observed    canary.PeerObservationFacts
	RegistryPin string
}

// mcpLiveTrustPrecheck decides everything the whole-Canary latch depends on, reading ONLY
// pointer-published inventory state.
//
// WHY THIS IS SPLIT OUT, and it is a safety property rather than a tidiness one. The activation
// critical section latches aborts and gates demotion, so anything that can BLOCK inside it can
// block the controls that stop the experiment. The approval lookup can: Store.ActiveLiveApprovals
// takes Store.mu, and every approval mutation holds that same mutex across persistLocked and its
// atomic file write — so one stuck disk would sit in front of automatic abort, demotion and
// generation revalidation (Codex round 21). §5 forbids exactly that, and an audited lock ORDER
// would not have helped: the hazard is duration, not deadlock.
//
// The separation is clean because of what each half decides. Every authoritative drift signal —
// the server no longer usable, the fingerprint no longer the decision's — is derived from the
// inventory, which is published through atomic pointers (catalog.Current / registry.Current) behind
// one RLock that returns immediately. The approval lookup NEVER produces a drift code; it only
// distinguishes an authorized request from an unauthorized one, which is request-scoped and needs
// no activation attribution at all. So the latch keeps its atomic binding while the blocking read
// moves out of the critical section entirely — removing the edge rather than ordering it.
func mcpLiveTrustPrecheck(tenant, serverID, toolName, decisionFP string) liveTrustPrecheck {
	if mcpToolTrust == nil {
		return liveTrustPrecheck{}
	}
	ti := mcpToolTrust.loadTarget(serverID, toolName)
	if !ti.found {
		// Nothing resolves. Not drift: indistinguishable from a transient inventory gap.
		return liveTrustPrecheck{}
	}
	// Resolved BEFORE the tenant gate, so a target that exists under another owner is still
	// reported to the caller. See the Resolved/Authoritative field comments.
	authoritative := canary.ReviewedTarget{
		Tenant:            ti.target.Tenant,
		ServerID:          serverID,
		ToolName:          toolName,
		Fingerprint:       ti.target.Fingerprint,
		FingerprintFormat: ti.target.FingerprintFormatVersion,
		ServerIdentity:    ti.pinnedIdentity,
	}
	// ANCHOR STATE IS CHECKED BEFORE THE TENANT GATE, and the order is the finding.
	//
	// Both of the branches below say the same thing — the trust anchor the experiment was
	// authorized against is no longer the one in force — and the scope-independent observation
	// path (latchReviewedDriftUnderActivation) has always checked exactly these two facts BEFORE
	// its reviewed comparison, on the recorded reasoning that an absent anchor outranks whatever
	// the target happens to compare as. This path returned at the tenant gate first, so for ONE
	// published state carrying BOTH transitions — a reviewed pair reassigned A→B whose registry
	// identity is then repinned before the catalog re-ingests — admission compared the carried
	// target and latched reviewed_target_tenant_drift while the observation sink latched
	// server_identity_drift. Whichever request arrived first decided the immutable first cause
	// (Codex P2, PR #1360, round 30).
	//
	// Neither branch carries Resolved/Authoritative, deliberately: reviewedFirstCause can only
	// sharpen a cause when a target rides along, and here there is nothing to sharpen TO — an
	// anchor-class cause already outranks every verdict Compare could return, so carrying the
	// target could only downgrade it.
	//
	// This does not widen what latches. The observation sink runs for every dispatched request
	// naming a tool and already latches this state; only the recorded cause differed.
	//
	// WHOLE-CANARY. The usability signal conflates two causes — an operator disabling the server
	// and the server losing identity verification — and they are not separable from the data
	// available here (a distinguishable peer-freshness source is blocker #11). The conservative
	// reading is taken deliberately: in BOTH cases the approved anchor is gone, and the safe
	// response is to stop changing reality, not to keep going because one of the two possible
	// causes was benign. An operator disable or a lost identity verification after runExecute
	// snapshotted in.Server fails closed here (P1b).
	if !ti.target.ServerUsable {
		return liveTrustPrecheck{Resolved: true, Authoritative: authoritative, AnchorLost: true}
	}
	// The registry currently pins an identity the catalog record was NOT built against — the
	// repin/re-ingest window. A request would be routed to the registry's pin while every approval
	// and reviewed record describes the catalog's, so the workload about to be called is not the
	// one that was reviewed. Same code, same reason as an unusable anchor: the approved anchor is
	// not the one in force (Codex P1, PR #1360, round 4).
	if ti.registryPinDiverged {
		return liveTrustPrecheck{Resolved: true, Authoritative: authoritative, AnchorLost: true}
	}
	// The anchor is sound; only now does ownership decide. Request-scoped for AUTHORIZATION — this
	// request is not the owner — but the target is carried out so the reviewed comparison can still
	// see that the reviewed pair changed hands. Eligible stays false, so nothing here authorizes
	// anything.
	if ti.target.Tenant == "" || ti.target.Tenant != tenant {
		return liveTrustPrecheck{Resolved: true, Authoritative: authoritative}
	}
	// Bind trust to the DECISION's fingerprint, not merely whichever fingerprint is current (P1a): the
	// current target must STILL equal the fingerprint this request was decided against, so an
	// F1→F2→F1 flap cannot let an F2 approval authorize an F1 request.
	//
	// WHOLE-CANARY when a fingerprint EXISTS and differs: that is the rug-pull the taxonomy names —
	// the executed tool is not the reviewed tool. A MISSING decision fingerprint is request-scoped:
	// it means this request never carried one, which is a malformed request, not evidence the
	// target changed.
	if decisionFP == "" {
		return liveTrustPrecheck{}
	}
	if hex.EncodeToString(ti.target.Fingerprint[:]) != decisionFP {
		// Resolved/Authoritative ride along with the code. The code alone says only what THIS
		// request could see — its decision fingerprint against current inventory — and that is not
		// always the strongest available statement about the breach. Carrying the target lets the
		// activation's own reviewed record speak too, so the recorded first cause is decided from
		// state rather than from which transition window the request landed in. See
		// reviewedFirstCause in mcp_canary_admission.go (Codex P2, PR #1360, round 29).
		return liveTrustPrecheck{
			DriftCode: "tool_fingerprint_drift", Resolved: true, Authoritative: authoritative,
		}
	}
	return liveTrustPrecheck{
		Eligible: true,
		Target: canary.LiveTarget{
			Tenant:            tenant,
			ServerID:          serverID,
			ToolName:          toolName,
			Fingerprint:       ti.target.Fingerprint,
			FingerprintFormat: ti.target.FingerprintFormatVersion,
		},
		// From the SAME snapshot loadTarget resolved the fingerprint from, never a second lookup:
		// a Registry.Repin landing between two reads composes an (F1, I2) pair that was never
		// simultaneously authoritative. See the pinnedIdentity field comment in mcp_tooltrust.go.
		ServerIdentity: ti.pinnedIdentity,
		// Resolved/Authoritative are deliberately NOT set on this path, matching the pre-existing
		// shape. They feed the whole-Canary drift LATCH (mcp_canary_admission.go reads
		// live.Resolved without an Eligible guard), so setting them here would hand the
		// observation sink a target on a path that previously carried none — changing what
		// latches. The boundary's peer-freshness check therefore keys its own Resolved off
		// Eligible, which is the fact it actually depends on.
		//
		// Blocker #11, from the same snapshot as everything above.
		Observed: canary.PeerObservationFacts{
			At:       ti.observed.At,
			Identity: string(ti.observed.Identity),
		},
		RegistryPin: ti.registryPin,
	}
}

// mcpLiveApprovalSatisfied answers the APPROVAL half of live-execution trust: is THIS request
// authorized right now?
//
// It reports authorization and nothing else. It used to also report a drift verdict — an approval
// that was valid in every respect except that it pinned a different fingerprint for this exact
// (tenant, server, tool) was read as the rug-pull. That inference was correct whenever it fired,
// and it was the wrong instrument, because it could only fire while such an approval still
// EXISTED. An activation may run for FirstCanaryMaxWindowCeiling (7 days) and an approval may live
// at most MaxInitialCanaryApprovalTTL (24 hours), so once the reviewing approval expired the
// evidence was simply gone: a later F2 request read as an ordinary missing-approval denial, and a
// later F2 approval could resume execution across an intervening breach (Round-24 P1).
//
// Drift is now decided against the ACTIVATION's own immutable reviewed-target snapshot, inside the
// same atomic admission transaction, which is independent of approval lifetime by construction —
// see internal/mcp/canary/reviewed.go and admitLiveExecution step (5). The two questions are
// separate security facts and are no longer conflated:
//
//	approval   — is this request authorized NOW?
//	activation — is this still the exact target the experiment was reviewed against?
//
// The driftCode result is retained as always-empty so the seam's shape is unchanged for callers
// and a future authorization-scoped drift has somewhere to go; nothing produces one today.
func mcpLiveApprovalSatisfied(tgt canary.LiveTarget, class policy.OperationClass, now time.Time) (satisfied bool, driftCode string) {
	if mcpToolTrust == nil {
		return false, ""
	}
	for _, a := range mcpToolTrust.activeLiveApprovals(now) {
		if canary.SatisfiesLiveExecution(a, tgt, now) != canary.TrustOK {
			continue
		}
		// THE SATISFYING APPROVAL MUST STATE THE CLASS IN FORCE.
		//
		// An approval carries its own reviewed operation class, and nothing stops a later approval
		// for the SAME exact fingerprint from stating a different one — that is precisely how a
		// reviewer corrects an earlier determination. Accepting "any live grant" meant the
		// activation's older immutable record kept saying OpRead while the only live approval said
		// MUTATING, and both admission and the boundary let it execute read-first (Codex P1,
		// PR #1370, round 5).
		//
		// A class the approval cannot state at all (unset, or outside the reviewable vocabulary)
		// fails CLOSED here rather than being read as agreement, the same discipline the activation
		// gate applies at arming time.
		got, ok := canary.OperationClassFromReviewed(a.ReviewedOperationClass)
		if !ok || got != class {
			continue
		}
		return true, ""
	}
	// No satisfying approval: request-scoped. This request simply is not authorized (expired,
	// revoked, never granted).
	return false, ""
}

// mcpLiveGateDenials counts live side-effect gate denials by bounded reason code, for the
// read-only status/metrics surface (§14 evidence truth: budget vs trust vs read-first vs
// quiescing are separately countable). It is process-global, never a secret.
var mcpLiveGateDenials = struct {
	mu sync.Mutex
	m  map[string]uint64
}{m: map[string]uint64{}}

// noteMCPLiveGateDenied increments the denial counter for a bounded reason code.
func noteMCPLiveGateDenied(reason mcperr.Reason) {
	mcpLiveGateDenials.mu.Lock()
	mcpLiveGateDenials.m[reason.Code()]++
	mcpLiveGateDenials.mu.Unlock()
}

// mcpLiveGateDenialSnapshot returns a copy of the denial counters for the status surface.
func mcpLiveGateDenialSnapshot() map[string]uint64 {
	mcpLiveGateDenials.mu.Lock()
	defer mcpLiveGateDenials.mu.Unlock()
	out := make(map[string]uint64, len(mcpLiveGateDenials.m))
	for k, v := range mcpLiveGateDenials.m {
		out[k] = v
	}
	return out
}

// canaryReservationIDBytes is the entropy width for a reservation identity: 128
// bits, matching the attempt identity, so neither is the weaker link when the two
// are correlated in evidence.
const canaryReservationIDBytes = 16

// newCanaryReservationID mints the identity for one granted budget slot. It is
// non-secret (it appears in evidence and is reconciled against), Culvert-minted,
// and never derived from request content — deriving it from caller input would let
// two distinct grants share one name and collapse them in the ledger.
func newCanaryReservationID() (string, error) {
	b := make([]byte, canaryReservationIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rsv_" + hex.EncodeToString(b), nil
}

// revalidateTargetTrust is the target half of the final-boundary re-check: the trust precheck,
// peer freshness, and the durable approval, in that order and on ONE capture.
//
// It is a method rather than three nested blocks inside the Revalidate closure because the
// closure already carries the generation and scope halves; the nesting made the one path that
// touches three authorities the hardest part of the file to read.
//
// THE GUARD IS ON trustPrecheck ALONE, where it used to require approvalOK too. That is
// deliberate: peer freshness does not depend on the approval seam, so gating it on approvalOK
// being wired would mean forgetting to wire the approval silently disables freshness as well —
// the permissive direction, and the failure mode a composition seam must never have. Production
// wires both, so nothing changes there; a partially composed gate now refuses more, never less.
func (g *mcpLiveSideEffectGate) revalidateTargetTrust(in execution.LiveGateInput) mcperr.Reason {
	if g.trustPrecheck == nil {
		return mcperr.ReasonNone
	}
	live := g.trustPrecheck(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint)
	if !live.Eligible {
		return mcperr.ReasonLiveTrustRevalidationFailed
	}
	// ONE CLOCK SAMPLE for this whole revalidation attempt, shared by the freshness bound and the
	// approval expiry below. Two samples could put the two answers at two instants, and the
	// freshness boundary would stop being testable at all.
	at := in.Now
	if g.now != nil {
		at = g.now()
	}
	if r := boundaryPeerFreshness(in, live, at); r != mcperr.ReasonNone {
		return r
	}
	// THE APPROVAL IS CONSULTED LAST, so the durable store is reached only for a request every
	// cheaper authority still admits. Unchanged from before the freshness row existed, except
	// that it now shares the capture and the clock sample above.
	if g.approvalOK != nil {
		if ok, _ := g.approvalOK(live.Target, in.Operation, at); !ok {
			return mcperr.ReasonLiveTrustRevalidationFailed
		}
	}
	return mcperr.ReasonNone
}

// boundaryPeerFreshness is the side-effect boundary's peer-observation re-check (blocker #11).
//
// IT REUSES THE ACTIVATION VERDICT VERBATIM. canary.EvaluatePeerObservedFresh is the ONE
// definition of missing / future-dated / stale / fresh, and of what it means for an observation to
// back an exact target; there is deliberately no second algorithm, no second TTL constant and no
// bespoke time comparison here. An activation-time bound and a send-time bound that could drift
// apart would be two answers to one question, and the one that mattered would be whichever ran
// last.
//
// WHAT IS RE-ASKED FROM THE REQUEST'S SIDE. `Reviewed` is built from the identity this request was
// AUTHORIZED against — the tenant, server, tool and decision fingerprint the executor carries —
// and `Current` from the authoritative capture taken microseconds ago. So the binding is genuinely
// re-established at the boundary rather than assumed from the precheck's own gates: a fresh
// observation of F2 cannot satisfy a request authorized against F1, on this path any more than on
// the activation path.
//
// FingerprintFormat is the one field that cannot be sourced independently from the request, which
// carries the digest as hex and no format number. It is therefore taken from Current — and that is
// sound rather than a gap, because tooltrust's Sum() folds FormatVersion INTO the digest, so a
// format change produces a different digest and is caught by the fingerprint comparison itself.
// Stating it here rather than leaving the reader to notice the field is trivially equal.
//
// NO I/O. Everything it reads was already resolved into `live` from pointer-published inventory.
// It dials nothing, and it must never learn to: a discovery call at the send boundary would put an
// unbounded network wait inside the last authority check, which is the exact shape of defect the
// PreSend re-ask exists to close.
func boundaryPeerFreshness(in execution.LiveGateInput, live liveTrustPrecheck, at time.Time) mcperr.Reason {
	reviewed := canary.ReviewedTarget{
		Tenant:            in.Tenant,
		ServerID:          in.ServerID,
		ToolName:          in.ToolName,
		Fingerprint:       live.Target.Fingerprint,
		FingerprintFormat: live.Target.FingerprintFormat,
	}
	// The decision's fingerprint is what the request was authorized against; live.Eligible above
	// already required it to equal the current record's, so decoding it here would re-derive a
	// value we know to be equal. What this DOES re-establish is the rest of the tuple, and the
	// observation's own binding to it.
	current := canary.ReviewedTarget{
		Tenant:            live.Target.Tenant,
		ServerID:          live.Target.ServerID,
		ToolName:          live.Target.ToolName,
		Fingerprint:       live.Target.Fingerprint,
		FingerprintFormat: live.Target.FingerprintFormat,
		ServerIdentity:    live.ServerIdentity,
	}
	verdict := canary.EvaluatePeerObservedFresh(canary.PeerFreshnessInput{
		// Eligible is the fact this check depends on — the precheck resolved an authoritative
		// target, it is this tenant's, the server is usable, the registry pin has not diverged,
		// and it still carries the decision's fingerprint. Keyed off Eligible rather than
		// live.Resolved, which the eligible path deliberately does not set (see its comment).
		Resolved:               live.Eligible,
		Now:                    at,
		Observed:               live.Observed,
		Reviewed:               reviewed,
		Current:                current,
		ActivationTenant:       in.Tenant,
		RegistryPinnedIdentity: live.RegistryPin,
		ServerUsable:           live.Eligible,
	})
	if verdict == canary.PeerFreshOK {
		return mcperr.ReasonNone
	}
	// ONE bounded reason for the gate, mapped from the verdict rather than passed through. The
	// verdict's classes are finer because an OPERATOR needs to know whether to refresh or to
	// re-review; the wire does not, and every one of those classes would otherwise carry the
	// shape of the peer's identity, fingerprint or endpoint out to a caller. The fine class stays
	// where it is safe: the activation surface and the log.
	return mcperr.ReasonPeerObservationNotFresh
}
