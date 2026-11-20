// Package revsync plans which session-revocation entries ride one
// SyncRevocations message when the full set does not fit that leg's byte
// budget (AU-50 request leg, AU-71 reply leg; IM-015, ADR-0049).
//
// THE RULE. A leg that does not fit is DEFERRED, never dropped:
//
//   - Nothing is removed from any revocation list. The planner only chooses
//     which entries ride THIS tick; the rest ride later ones. Dropping an entry
//     from the list to make the message fit would un-revoke a session, which
//     is the fail-open direction this control may not take.
//   - Half of the budget is a strict priority PREFIX, so the entries that
//     matter most go out on the very next tick however large the backlog: on
//     the request leg that is the node's OWN logouts first (no other node can
//     tell the fleet about them), then account revocations, then learned
//     tokens; each class latest-expiry first, which is the newest session and
//     the longest remaining protection.
//   - The other half is a ROTATING WINDOW over everything the prefix did not
//     carry, resuming where the previous tick stopped. That is what makes
//     "deferred" true rather than a polite word for "dropped": every live entry
//     is sent within ceil(backlog / window) ticks, including the oldest local
//     one, which a fixed prefix would starve for as long as the backlog stayed
//     large.
//
// The common case pays exactly one marshal, measured, and sent unchanged when
// it fits. The planner runs only on the over-budget path.
//
// Ownership: package main owns the byte budgets (derived from the cluster gRPC
// frame limits), the Cursor instances (one on the Data Plane client, one per
// requesting node on the Control Plane's aggregator), the deferral counters,
// the rate-limited log line and the RPC itself. This package owns the priority
// order, the rotation and the request wire envelope. It holds no package-level
// state, starts no goroutines and does no I/O or logging; its only Culvert
// import is internal/session, for the RevocationEntry wire type.
package revsync
