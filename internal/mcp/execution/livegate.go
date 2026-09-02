package execution

import (
	"errors"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// LiveExecutionGate is the OPTIONAL composition-layer gate the live Executor consults at the
// side-effect boundary. It exists so the gates that must live OUTSIDE this package —
// Canary blast-radius BUDGET reservation, runtime live-execution TRUST revalidation, and
// READ-FIRST operation enforcement — can run immediately before the irreversible upstream
// call WITHOUT this package importing the composition layer (rollout-runtime / tooltrust /
// canary singletons).
//
// PLACEMENT IS A SAFETY INVARIANT. The executor invokes the gate at the TOP of callUpstream,
// BEFORE preCallGuard's tool-freshness + emergency-kill re-check, so the kill re-read remains
// the LAST authoritative check before Upstream.Call (PREREQ-MCP-KILL-1): nothing the gate does
// (which may block on a durable budget persist) sits between the kill re-read and the side
// effect. A gate DENIAL therefore fails the execution closed and Upstream.Call is never
// reached; a gate ADMIT returns a Release the executor runs exactly once after the upstream leg
// (success, failure, or a later boundary refusal), so a reserved concurrency slot is never
// leaked — including the §11 case where a subsequent kill/freshness abort occurs AFTER the gate
// admitted (and after any credential materialization).
//
// The gate is nil in every non-live composition (the ShadowEvaluator has no LiveGate, and the
// disabled-by-default build composes no live executor), so the executor is byte-identical to
// the pre-gate path when it is unset.
type LiveExecutionGate interface {
	// AdmitSideEffect decides whether this request may cross the irreversible upstream
	// boundary. It performs NO upstream call and NO credential materialization.
	AdmitSideEffect(in LiveGateInput) LiveGateDecision
}

// LiveGateInput carries the authoritative, already-resolved facts the composition-layer gate
// needs. Every field derives from the pre-resolved decision (never a request-supplied claim):
// the executor builds it from runtime.ExecInput at the boundary.
type LiveGateInput struct {
	Capability protocol.Capability
	// Operation is the policy-engine operation class (read-first is decided from THIS, never
	// the server-provided readOnlyHint).
	Operation policy.OperationClass
	// Tenant / Principal identify the authenticated subject for the blast-radius ceilings.
	Tenant    string
	Principal string
	// ServerID / ToolName / Fingerprint are the exact reviewed target the live-trust
	// revalidation binds against (Fingerprint is the hex composite fingerprint the decision
	// was computed against; tool freshness separately proves it still matches the live tool).
	ServerID    string
	ToolName    string
	Fingerprint string
	Now         time.Time
}

// LiveGateDecision is the gate's verdict. Admit==false fails closed with Reason and Upstream.Call
// is never reached. Release (non-nil only when Admit) is run exactly once after the upstream leg.
type LiveGateDecision struct {
	Admit  bool
	Reason mcperr.Reason
	// Revalidate (non-nil only when Admit) is a FINAL-BOUNDARY re-check the executor runs inside
	// preCallGuard, immediately before the emergency-kill re-read. It returns false when the
	// activation this request was admitted under is no longer current — e.g. a concurrent Canary
	// demotion invalidated the reserved generation AFTER admission but BEFORE the irreversible call.
	// Because the admission-time reservation cannot see a later demotion, and preCallGuard's kill
	// re-read does not consult the Canary generation, WITHOUT this an already-admitted request could
	// still reach the upstream after a leaving-live transition returned success (Codex P1 round-8,
	// PR #1290). It is a composition-layer concern (the generation lives in the canary runtime), so it
	// enters this package only as an injected predicate — the executor stays generic and byte-identical
	// when the gate (or Revalidate) is nil.
	Revalidate func() bool
	Release    func()
}

// errLiveGateRefused aborts callUpstream when the composition-layer gate denied the side effect.
// Like the drift/kill sentinels it never escapes the package: callUpstream captures the gate's
// bounded Reason in a local and classifyBoundaryRefusal surfaces it.
var errLiveGateRefused = errors.New("mcp: live side-effect gate refused")

// errLiveGenerationDemotedAtBoundary aborts callUpstream when the gate's final-boundary Revalidate
// reports the reserved activation generation is no longer current (a concurrent demotion). Like the
// other boundary sentinels it never escapes the package: callUpstream maps it to a bounded rollout
// reason via classifyBoundaryRefusal so a client and block telemetry read a fail-closed refusal, never
// a transport/durability fault or ReasonNone.
var errLiveGenerationDemotedAtBoundary = errors.New("mcp: live activation generation demoted before upstream call")

// liveGateInput builds the gate input from the already-resolved ExecInput at the boundary. It
// reads ONLY resolved decision facts (principal/tool/server/operation), never a raw request
// value. in.Server is guaranteed non-nil here (runExecute blocks a nil/unusable server before
// callUpstream); in.Input.Tool may be nil for a non-tool method, in which case the target fields
// are empty and the gate's trust revalidation fails closed (no tool to approve).
//
// Now is read from the EXECUTOR'S CLOCK at this call — the boundary instant — NOT the request-entry
// timestamp in.Now. liveGateInput is built inside callUpstream, AFTER the durable decision commit and
// any credential materialization, which can each block; reusing in.Now would let the gate's live-trust
// revalidation treat an approval that expired during that delay as still valid, and evaluate the Canary
// budget window at an earlier instant (Codex P1, PR #1290). e.cfg.Clock is guaranteed non-nil (New
// defaults it to time.Now), so this evaluates trust/expiry/budget against the actual side-effect time.
func (e *Executor) liveGateInput(in runtime.ExecInput) LiveGateInput {
	var toolName, fp string
	if in.Input.Tool != nil {
		toolName = in.Input.Tool.Name
		fp = in.Input.Tool.FingerprintHash
	}
	var serverID string
	if in.Server != nil {
		serverID = string(in.Server.ID)
	}
	return LiveGateInput{
		Capability:  in.Capability,
		Operation:   in.Input.Operation.Class,
		Tenant:      in.Input.Principal.Tenant,
		Principal:   in.Input.Principal.SubjectID,
		ServerID:    serverID,
		ToolName:    toolName,
		Fingerprint: fp,
		Now:         e.cfg.Clock(), // the boundary instant, not the request-entry in.Now (see doc above)
	}
}
