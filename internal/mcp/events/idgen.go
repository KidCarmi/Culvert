// Package events is the composition root of the PR-8 durable decision-event
// pipeline. It wires, per MCP capability, a fully isolated stack — encrypted
// spool (internal/mcp/events/spool), denial lane (…/denial), degraded-state
// machine (…/state) and export foundation (…/export) — behind a Manager that the
// runtime uses to durably commit sanitized decision events BEFORE any represented
// irreversible action, and to route attacker-mintable denials into the isolated
// denial lane.
//
// PR-8 is DECISION-ONLY and DORMANT: the Manager commits durable evidence and
// hands back an unforgeable receipt, but it never calls a business MCP server,
// creates an upstream client, invokes tools/call, materializes a credential,
// contacts a provider, publishes a CP→DP snapshot, or mutates Management state.
// An inspected ALLOW still returns execution_state "not_implemented"; the receipt
// is evidence that a FUTURE execution stage may proceed, not an execution itself.
//
// Capability isolation is load-bearing: Gateway and Management own separate
// spools, denial aggregators, state machines, reserves, counters and export
// cursors, so a failure in one capability's durability domain cannot degrade the
// other (MCP-OPS-005 / MCP-EVENT-002 §4b.2).
package events

import (
	"crypto/rand"
	"encoding/base32"
)

// idAlphabet is a Crockford-like base32 without padding, yielding safe, opaque,
// URL-safe correlation handles.
var idEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// randID mints a safe, unpredictable, prefixed id (evt_/rpl_/cor_). IDs are
// correlation handles, NOT security tokens: they are generated from crypto/rand
// (never a predictable counter exposed as a token) and are bounded and
// charset-safe so they satisfy the model's id validation.
func randID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A crypto/rand failure is catastrophic and extremely rare; fall back to a
		// fixed marker so the event still validates and the failure is visible rather
		// than producing a colliding empty id. The caller's commit will still record
		// the event; id uniqueness is best-effort under a broken RNG.
		return prefix + "0000000000000000000000000000"
	}
	return prefix + idEncoding.EncodeToString(b[:])
}
