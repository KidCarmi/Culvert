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
	// readFirst decides whether the operation class may cross the boundary.
	readFirst func(policy.OperationClass) bool
	// trustOK revalidates the exact current live approval for (tenant, server, tool) as of now,
	// bound to the DECISION's fingerprint (the fingerprint the request was actually decided against).
	trustOK func(tenant, serverID, toolName, fingerprint string, now time.Time) bool
	// reserve reserves a Canary budget slot for the execution identity, returning the outcome and
	// the generation the reservation was made under.
	reserve func(now time.Time, ident canary.ExecutionIdentity) (canary.BudgetOutcome, uint64)
	// releaseBudget returns the in-flight concurrency slot for a reservation made under gen.
	releaseBudget func(gen uint64)
	// generationCurrent is the final-boundary revalidation: it reports whether the activation
	// generation a reservation was made under is STILL the current, armed, execution-eligible
	// generation. A concurrent Canary demotion between admission and the upstream call makes it
	// return false so the executor refuses at the boundary (§10 completeness; Codex P1 round-8).
	generationCurrent func(gen uint64) bool
	// note records a bounded denial reason for metrics/telemetry (never a secret). Optional.
	note func(reason mcperr.Reason)
}

var _ execution.LiveExecutionGate = (*mcpLiveSideEffectGate)(nil)

// newMCPLiveSideEffectGate wires the production gate for the Gateway capability from the real
// composition-layer singletons.
func newMCPLiveSideEffectGate(capb rollout.Capability) *mcpLiveSideEffectGate {
	lt := mcpLiveTierFor(capb)
	return &mcpLiveSideEffectGate{
		capb:      capb,
		admit:     lt.admitExecution,
		readFirst: canary.IsReadFirstOperation,
		trustOK:   mcpLiveTrustRevalidate,
		reserve: func(now time.Time, ident canary.ExecutionIdentity) (canary.BudgetOutcome, uint64) {
			return globalCanaryRuntime.reserveCanaryExecution(capb, now, ident)
		},
		releaseBudget:     func(gen uint64) { globalCanaryRuntime.releaseCanaryExecution(capb, gen) },
		generationCurrent: func(gen uint64) bool { return globalCanaryRuntime.generationActive(capb, gen) },
		note:              noteMCPLiveGateDenied,
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

	// (3) Runtime live-trust revalidation (§10), bound to the DECISION's fingerprint.
	if !g.trustOK(in.Tenant, in.ServerID, in.ToolName, in.Fingerprint, in.Now) {
		releaseAdmit()
		return deny(mcperr.ReasonLiveTrustRevalidationFailed)
	}

	// (4) Budget reservation (§8). The spend is persisted before the grant; a denial trips the
	// whole-Canary abort inside reserveCanaryExecution for a blast-radius breach.
	outcome, gen := g.reserve(in.Now, canary.ExecutionIdentity{
		Principal: in.Principal,
		Tool:      in.ToolName,
		Server:    in.ServerID,
	})
	if !outcome.Granted() {
		releaseAdmit()
		return deny(mcperr.ReasonRolloutBudgetExhausted)
	}

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
		Revalidate: func() bool {
			if g.generationCurrent == nil {
				return true // no revalidation seam wired ⇒ preserve prior behavior (never falsely refuse)
			}
			return g.generationCurrent(gen)
		},
		Release: func() {
			g.releaseBudget(gen)
			releaseAdmit()
		},
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
//
// decisionFP is the DECISION's composite fingerprint (hex) — the fingerprint the request was
// actually decided against. Two boundary bindings close the F1→F2→F1 catalog-flap and stale-server
// gaps (Codex P1, PR #1290):
//   - the reviewed SERVER must still be USABLE now (a disable / lost identity verification after the
//     decision snapshot fails closed here, even if a stale approval exists), and
//   - the CURRENT target fingerprint must still EQUAL the decision fingerprint, so an approval issued
//     for a DIFFERENT fingerprint (e.g. an F2 approval when this request was decided under F1) can
//     never authorize this side effect. The approval is then validated against that same fingerprint.
func mcpLiveTrustRevalidate(tenant, serverID, toolName, decisionFP string, now time.Time) bool {
	if mcpToolTrust == nil {
		return false
	}
	ti := mcpToolTrust.loadTarget(serverID, toolName)
	if !ti.found || ti.target.Tenant == "" || ti.target.Tenant != tenant {
		return false
	}
	// The reviewed server must still be usable at the boundary (P1b): an operator disable or a lost
	// identity verification after runExecute snapshotted in.Server fails closed here.
	if !ti.target.ServerUsable {
		return false
	}
	// Bind trust to the DECISION's fingerprint, not merely whichever fingerprint is current (P1a): the
	// current target must STILL equal the fingerprint this request was decided against, so an
	// F1→F2→F1 flap cannot let an F2 approval authorize an F1 request.
	if decisionFP == "" || hex.EncodeToString(ti.target.Fingerprint[:]) != decisionFP {
		return false
	}
	tgt := canary.LiveTarget{
		Tenant:            tenant,
		ServerID:          serverID,
		ToolName:          toolName,
		Fingerprint:       ti.target.Fingerprint,
		FingerprintFormat: ti.target.FingerprintFormatVersion,
	}
	for _, a := range mcpToolTrust.activeLiveApprovals(now) {
		if canary.SatisfiesLiveExecution(a, tgt, now) == canary.TrustOK {
			return true
		}
	}
	return false
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
