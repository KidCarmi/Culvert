package canary

import (
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// IsReadFirstOperation reports whether a policy operation class is admissible for a read-first
// first Canary (§5). It is the REQUEST-TIME authoritative read-first gate, and it exists
// because the scope-level read-first check (ScopeReadFirst, over rollout.RiskClass) is
// necessary but NOT sufficient:
//
// rollout.RiskClass has only four buckets (Unknown/Read/Write/Destructive), and the root
// mapRisk() folds Culvert's OpControl AND OpDiscovery both into RiskRead. So a scope whose
// admitted RiskClasses are read-only still admits a CONTROL-plane operation once the policy
// engine has classified an individual request — a control-plane action is not a read, and a
// read-first Canary must never perform one (Codex P1-A, PR #1249). The RiskClass axis cannot
// express that distinction; only the finer policy.OperationClass can.
//
// This predicate consults Culvert's OWN authoritative operation class (assigned by the policy
// engine from Culvert's rules), never the server-provided MCP readOnlyHint. It is fail-closed:
// only OpRead and OpDiscovery qualify. OpControl, OpWrite, OpDestructive, and OpUnset (the
// zero value / unclassified) are all rejected. A future live executor's admission path must
// call this on every candidate request in addition to the scope match — the scope bounds WHICH
// tools, this bounds WHICH operation on the tool as the request is actually classified.
func IsReadFirstOperation(c policy.OperationClass) bool {
	switch c {
	case policy.OpRead, policy.OpDiscovery:
		return true
	default:
		// OpControl / OpWrite / OpDestructive / OpUnset — never read-first.
		return false
	}
}
