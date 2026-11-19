// Package shadowmetrics is the bounded, low-cardinality telemetry sink for the
// non-executing MCP Shadow evaluator (SHADOW-ACTIVATION.md §12; IM-011,
// ADR-0047). A Sink counts each Shadow evaluation by its Model-1 outcome and
// each evaluation that failed closed; Snapshot returns the read-only View the
// status surface serializes, and WritePrometheus appends the
// culvert_mcp_shadow_* series for /metrics.
//
// Every label is a FIXED enum — the eight Model-1 shadow outcomes plus the
// fail-safe "other" bucket — never a tenant, subject, server, tool or argument,
// so the series cardinality is constant regardless of traffic.
//
// Sink implements internal/mcp/execution.Metrics structurally. The package does
// not import internal/mcp/execution: the MCP execution-posture wall
// (mcp_execution_posture_test.go) permits only the composition files to import
// it, so conformance is pinned by a test instead.
//
// Ownership: package main owns the process-wide instance (constructed only when
// Shadow is actually composed, so a node that never armed Shadow emits no
// series), hands the same instance to the Shadow evaluator and to the live
// executor's embedded evaluator, and owns the nil gate on the /metrics and
// status paths. This package owns only the counters, the outcome bucketing and
// the wire shape. It holds no package-level state, starts no goroutines and
// does no I/O or logging.
package shadowmetrics
