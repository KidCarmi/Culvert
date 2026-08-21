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
