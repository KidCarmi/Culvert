# ADR-0047: The MCP Shadow metrics sink is owned by internal/mcp/shadowmetrics

- Status: Proposed for review with the implementation PR (IM-011, 2026-11-18).
- Numbering: ADR-0045 is the highest merged; ADR-0040 is reserved by open
  PR #1526 and ADR-0046 by open PR #1941 (IM-009). No other open PR adds a file
  under `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-011
  (split from IM-009 in #1941). Related: ADR-0002, ADR-0038 (instance-owned
  state), ADR-0042..0046.

## Context

`mcp_shadow_metrics.go` (164 lines, package main) held two responsibilities:

1. **An engine.** `mcpShadowMetrics`, eleven `atomic.Int64` counters that
   implement `internal/mcp/execution.Metrics` for the non-executing Shadow
   evaluator; the outcome bucketing (eight Model-1 outcomes plus a fail-safe
   `other`); the `shadowMetricsView` snapshot whose JSON tags are the status
   wire shape; and the `culvert_mcp_shadow_*` Prometheus serializer. It
   referenced no root symbol; its only Culvert imports were `mcperr` and
   `rollout` (the interface's argument types).
2. **Composition.** A `sync.Once` process singleton, constructed only when
   Shadow is actually composed (`mcp_shadow_startup.go`), reused by the live
   executor's embedded evaluator (`mcp_live_startup.go`, Codex P1 PR #1291),
   and read through a nil gate by `/metrics` (`metrics.go`) and the status map.
   The nil-ness is a contract: a node that never armed Shadow emits no series.

ADR-0002 does not list this file as main-owned. #1941 recorded that the
singleton needs an instance owner in main before any move.

## Decision

Move the engine (1) to `internal/mcp/shadowmetrics` with 2 exported
identifiers: `Sink` (zero value ready; methods `Observe*`, `Snapshot`,
`WritePrometheus`) and `View`. Keep the composition (2) in main, unchanged:
`globalMCPShadowMetrics`, its `sync.Once`, `newMCPShadowMetrics`,
`mcpShadowMetricsSnapshotOrNil` and the nil-gated `writeMCPShadowMetrics`.
Main is therefore the instance owner; the package holds no package-level
state. Root keeps `mcpShadowMetrics` and `shadowMetricsView` as type aliases so
no test changed beyond two `snapshot()` → `Snapshot()` call sites.

The package must not import `internal/mcp/execution`: the execution-posture
wall (`mcp_execution_posture_test.go`, fact 4) scans every production file in
the module and admits only the composition files. Conformance to
`execution.Metrics` is pinned by a compile-time assertion in the package's
test file instead. A deliberate production import was verified to fail both
the new boundary test and the root wall.

Lifecycle, in one sentence: main constructs the single Sink when Shadow is
composed and hands that pointer to both evaluators and both read surfaces; the
package starts no goroutines and does no I/O or logging.

Unchanged: the Prometheus bytes and the status JSON (both pinned by goldens
captured from main `348a2cf`), the never-armed-emits-nothing nil gate, the
live-executor sink reuse and its genuine-nil `execution.Metrics` return,
outcome bucketing, the no-op live-execution observations, and the
execution-posture wall.

## Tests

No root test moved: every existing test of this code reads the root singleton
or drives the composed evaluator (`shadow_controlled_run_test.go`,
`shadow_soak_test.go`, `shadow_exit_gap_test.go`, `mcp_live_tier_test.go`),
so they are integration tests and stay root. New engine tests: Prometheus and
JSON goldens, zero-sink rows, block-is-not-an-outcome, live observations are
no-ops, instance independence, concurrent accounting, `execution.Metrics`
conformance, and a boundary test (imports, package state, `init`,
exported-surface cap) with negative controls.

## Consequences

Shadow telemetry accounting is testable without compiling the application,
and an accidental shared counter across two Sinks is now impossible by
construction. The process-wide pointer remains a root global by design; a
later lifecycle change could pass the Sink through composition instead, but
that is a startup-ownership change, not part of this move.
