package upstreamclient

// retryable reports whether an upstream attempt may be retried. The rules are
// strict (MCP-PR-11 retry contract):
//   - a write/destructive tools/call is NEVER auto-retried after an ambiguous
//     transport outcome (at-most-once);
//   - a read-only call may be retried ONLY when explicitly classified idempotent,
//     within a bounded budget, and ONLY for a transport-ambiguous failure that
//     occurred BEFORE any response was received (a dial/handshake/timeout error) —
//     never after a JSON-RPC response was decoded.
//
// A retry never consumes an approval/allow-once twice: the executor consumes the
// allowance once and the same (already-consumed) plan is reused across the bounded
// retry attempts, so the transport-level retry here cannot re-consume anything.
func retryable(idempotent bool, attempt, budget int, preResponse bool) bool {
	if !idempotent {
		return false
	}
	if !preResponse {
		return false
	}
	return attempt < budget
}
