// Package evidenceview is the PR-UX-6 Production Qualification evidence read
// model for the MCP rollout (IM-009, ADR-0046). Build projects a capability's
// rollout.EvidenceSummary, at a server clock reading, into the JSON View the
// admin GET /api/mcp/rollout/evidence handler returns.
//
// Truth model: this is a REPORTING projection over the real rollout.EvidenceSummary.
// It never asserts Production qualification (this build ships no qualification
// issuer or verifier, so Production is permanently locked), never mutates evidence
// on a read, never converts synthetic origin into production origin, and never marks
// a synthetic clock-window as qualifying. Elapsed durations are computed on the
// SERVER with the real rollout clock semantics (rollout.EvidenceSummary.*Elapsed,
// which clamps negative to zero and treats a zero start as zero elapsed); the
// browser only formats the server value.
//
// At runtime the only evidence field with a write path is RollbackRehearsed (via the
// rehearse-rollback endpoint); windows are never stamped, defect/review counters
// never move, and origin stays production (the seed). A truthful UI therefore shows
// unmeasured windows as not_started rather than implying measured evidence.
//
// Ownership: package main owns the handler, the RoleViewer gate, capability
// selection, the rollout state that supplies the EvidenceSummary, and the clock
// reading. This package owns only the pure projection and its wire shape. It
// holds no package-level state, starts no goroutines and does no I/O or logging.
package evidenceview
