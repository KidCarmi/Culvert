package runtime

import (
	"encoding/json"
	"strconv"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// idJSON renders a decoded JSON-RPC id back to its wire form for a response
// envelope. A non-correlatable id (absent/null — never valid on an admitted
// request) renders as null.
func idJSON(id jsonrpc.ID) json.RawMessage {
	switch id.Kind {
	case jsonrpc.IDInt:
		return json.RawMessage(strconv.FormatInt(id.Int, 10))
	case jsonrpc.IDString:
		b, err := json.Marshal(id.Str)
		if err != nil {
			return json.RawMessage("null")
		}
		return b
	default:
		return json.RawMessage("null")
	}
}

// initializeResult builds the kernel-generated InitializeResult for the negotiated
// version. PR-5 is observe-only, so serverInfo/capabilities are a fixed, empty
// kernel identity — never a fabricated upstream capability set.
func initializeResult(id jsonrpc.ID, v protocol.Version) []byte {
	env := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    struct{}        `json:"capabilities"`
			ServerInfo      json.RawMessage `json:"serverInfo"`
		} `json:"result"`
	}{JSONRPC: "2.0", ID: idJSON(id)}
	env.Result.ProtocolVersion = string(v)
	env.Result.ServerInfo = json.RawMessage(`{"name":"culvert-mcp","version":"observe"}`)
	b, _ := json.Marshal(env) //nolint:errcheck // fixed-shape struct, marshal cannot fail
	return b
}

// pingResult builds the empty-result response to a ping.
func pingResult(id jsonrpc.ID) []byte {
	env := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct{}        `json:"result"`
	}{JSONRPC: "2.0", ID: idJSON(id)}
	b, _ := json.Marshal(env) //nolint:errcheck // fixed-shape struct, marshal cannot fail
	return b
}

// observeOnlyError builds the deterministic JSON-RPC error for a decision-point
// method that reached the observe boundary. It is a stable, typed rejection — never
// a fabricated success — carrying the machine reason "observe_only".
func observeOnlyError(id jsonrpc.ID) []byte {
	env := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: idJSON(id)}
	env.Error.Code = observeOnlyErrorCode
	env.Error.Message = mcperr.ReasonObserveOnly.Code()
	b, _ := json.Marshal(env) //nolint:errcheck // fixed-shape struct, marshal cannot fail
	return b
}

// policyError builds the deterministic JSON-RPC error for a policy DENY /
// QUARANTINE / REQUIRE_* / snapshot-unavailable decision. The machine-readable
// policy reason code is the message; the data carries the action + matched rule
// (safe metadata only — never arguments, tokens or the policy document).
func policyError(id jsonrpc.ID, reason policy.ReasonCode, action policy.Action, rule policy.RuleID) []byte {
	env := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				PolicyAction string `json:"policy_action"`
				MatchedRule  string `json:"matched_rule,omitempty"`
			} `json:"data"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: idJSON(id)}
	env.Error.Code = policyErrorCode
	env.Error.Message = string(reason)
	env.Error.Data.PolicyAction = action.String()
	env.Error.Data.MatchedRule = string(rule)
	b, _ := json.Marshal(env) //nolint:errcheck // fixed-shape struct, marshal cannot fail
	return b
}

// executionNotAvailable builds the JSON-RPC result for an ALLOW-class policy
// decision in PR-6: it records the TRUE policy action but states that execution is
// NOT implemented in this slice — it never fabricates a tool result.
func executionNotAvailable(id jsonrpc.ID, d policy.Decision) []byte {
	env := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			ExecutionState string `json:"execution_state"`
			PolicyAction   string `json:"policy_action"`
			PolicyRevision uint64 `json:"policy_revision"`
			Reason         string `json:"reason"`
		} `json:"result"`
	}{JSONRPC: "2.0", ID: idJSON(id)}
	env.Result.ExecutionState = "not_implemented"
	env.Result.PolicyAction = d.Action.String()
	env.Result.PolicyRevision = uint64(d.PolicyRevision)
	env.Result.Reason = string(d.Reason)
	b, _ := json.Marshal(env) //nolint:errcheck // fixed-shape struct, marshal cannot fail
	return b
}

// statusForAuth maps an authentication/binding rejection reason to an HTTP status.
// Every authentication failure class is a 401 except the immutable-binding conflict,
// which is a 409, and the forbidden query-string location, which is a 400.
func statusForAuth(r mcperr.Reason) int {
	switch r {
	case mcperr.ReasonSessionIdentityRebind, mcperr.ReasonSessionIdentityBound:
		return 409
	case mcperr.ReasonCredentialInQuery:
		return 400
	default:
		return 401
	}
}

// statusForAdmission maps a method-admission rejection reason to an HTTP status.
// An unsupported/unadmitted method is a 405; a lifecycle or wire-class violation is
// a 400; a resource cap is a 429.
func statusForAdmission(r mcperr.Reason) int {
	switch r {
	case mcperr.ReasonUnsupportedMethod:
		return 405
	case mcperr.ReasonResourceLimit:
		return 429
	default:
		return 400
	}
}
