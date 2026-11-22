// Package qualarchive owns the node-local qualification archive of MCP durable
// events: the batch files an export step hands it and the per-partition export
// cursors that record how far a partition has been archived (IM-024, ADR-0056).
//
// Exporter implements internal/mcp/events/export.Exporter. A batch is one
// file, <root>/<capability>/<partition>/<batch id>.json, written with
// fileutil.AtomicWrite, so Export returns len(batch) only after the bytes are
// fsynced. It is all-or-nothing, idempotent for an identical batch, rejects a
// different batch under the same identity, and refuses a write that would pass
// the byte cap instead of dropping events. It stores the safe event envelope
// only and performs no network activity.
//
// CursorStore keeps one file per partition, <dir>/<partition>.cursor. Advance
// writes the file before the in-memory value moves and ignores a backward or
// equal value, so a persisted cursor never runs ahead of an acknowledgement.
//
// Ownership: package main decides whether telemetry is configured, validates
// and clamps the operator's directories and cap, opens the events manager,
// runs the flush and export loops, and decides WHEN a cursor advances (only
// after Export accepted the batch). It also reduces this package's errors to a
// reason class by substring, so the phrases here are part of that contract.
// This package owns the bytes under the two directories it is handed and the
// counters of the instances it returns. It holds no package-level state,
// starts no goroutine and logs nothing; every instance is independent.
package qualarchive
