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
	Admit   bool
	Reason  mcperr.Reason
	Release func()
}

// errLiveGateRefused aborts callUpstream when the composition-layer gate denied the side effect.
// Like the drift/kill sentinels it never escapes the package: callUpstream captures the gate's
// bounded Reason in a local and classifyBoundaryRefusal surfaces it.
var errLiveGateRefused = errors.New("mcp: live side-effect gate refused")

// liveGateInput builds the gate input from the already-resolved ExecInput at the boundary. It
// reads ONLY resolved decision facts (principal/tool/server/operation), never a raw request
// value. in.Server is guaranteed non-nil here (runExecute blocks a nil/unusable server before
// callUpstream); in.Input.Tool may be nil for a non-tool method, in which case the target fields
// are empty and the gate's trust revalidation fails closed (no tool to approve).
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
		Now:         in.Now,
	}
}
