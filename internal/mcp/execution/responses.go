package execution

import (
	"encoding/json"
	"strconv"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// Disposition aliases onto the runtime's observe dispositions.
const (
	dispObserve  = runtime.DispObserveOnly
	dispReject   = runtime.DispRejected
	dispExecuted = runtime.DispPolicyAllowed
)

const executionErrorCode = -32055

// idJSON renders a JSON-RPC id as its exact wire form.
func idJSON(id jsonrpc.ID) string {
	switch id.Kind {
	case jsonrpc.IDInt:
		return strconv.FormatInt(id.Int, 10)
	case jsonrpc.IDString:
		b, _ := json.Marshal(id.Str)
		return string(b)
	default:
		return "null"
	}
}

// observeResult is the decision-only body: the true policy action, not executed.
func observeResult(id jsonrpc.ID, d policy.Decision) []byte {
	env := map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"execution_state": "not_implemented",
			"policy_action":   d.Action.String(),
			"policy_reason":   string(d.Reason),
			"mode":            "observe",
		},
	}
	return withID(env, id)
}

// shadowResult is the Shadow-evaluation body: the truthful Model-1 verdict, explicitly
// NOT executed. It never carries an upstream response because a Shadow evaluation makes
// no upstream call. It preserves the raw policy action (evaluated_policy_action)
// SEPARATELY from the enforcement prediction (shadow_outcome), so a policy DENY /
// REQUIRE_APPROVAL / REQUIRE_CONFIRMATION is never laundered into a plain WOULD_EXECUTE.
// Credential and inspection readiness are reported truthfully (§12/§13): Plan proves
// metadata only, so materialization_readiness is "not_evaluated"; there is no upstream
// response, so response_inspection is "not_evaluated".
func shadowResult(id jsonrpc.ID, d ShadowDecision) []byte {
	env := map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"execution_state":         "shadow_evaluated",
			"executed":                false,
			"evaluated_policy_action": d.EvaluatedAction,
			"shadow_outcome":          string(d.Outcome),
			"shadow_override":         d.ShadowOverride,
			"credential_plan":         d.CredentialPlan,
			"materialization_ready":   d.MaterializeReady,
			"request_inspection":      d.RequestInspection,
			"response_inspection":     d.ResponseInspection,
			"mode":                    "shadow",
		},
	}
	return withID(env, id)
}

// errorResult is a terminal classified JSON-RPC error (sanitized reason code only).
func errorResult(id jsonrpc.ID, reason mcperr.Reason) []byte {
	env := map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    executionErrorCode,
			"message": reason.Code(),
		},
	}
	return withID(env, id)
}

// executedResult wraps the (already inspected/redacted) upstream result.
func executedResult(id jsonrpc.ID, result json.RawMessage) []byte {
	env := map[string]any{"jsonrpc": "2.0"}
	if len(result) > 0 {
		env["result"] = result
	} else {
		env["result"] = map[string]any{}
	}
	return withID(env, id)
}

// upstreamErrorResult forwards a bounded, sanitized upstream JSON-RPC error.
func upstreamErrorResult(id jsonrpc.ID) []byte {
	return errorResult(id, mcperr.ReasonUpstreamCallFailed)
}

func withID(env map[string]any, id jsonrpc.ID) []byte {
	raw := json.RawMessage(idJSON(id))
	env["id"] = raw
	b, err := json.Marshal(env)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"marshal"}}`)
	}
	return b
}
