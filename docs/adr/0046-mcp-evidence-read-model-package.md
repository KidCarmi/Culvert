# ADR-0046: The MCP Production Qualification evidence read model is owned by internal/mcp/evidenceview

- Status: Proposed for review with the implementation PR (IM-009, 2026-11-18).
- Numbering: ADR-0045 is the highest merged; ADR-0040 is reserved by open
  PR #1526; no other open PR adds a file under `docs/adr/`.
- Program: [Package isolation](../../roadmap/PACKAGE-ISOLATION.md), task IM-009.
  Related: ADR-0002, ADR-0038 (instance-owned state pattern), ADR-0042..0045.

## Context

`mcp_evidence_readmodel.go` (317 lines, package main) held the PR-UX-6
Production Qualification evidence read model: a pure projection of a
capability's `rollout.EvidenceSummary`, at a server clock reading, into the
JSON body of `GET /api/mcp/rollout/evidence`. It referenced no root symbol; its
only dependency is `internal/mcp/rollout`, the owner of the evidence it
projects. It had one production caller (`apiMCPRolloutEvidence` in
`ui_mcp_rollout.go`) and one build-tagged fixture caller
(`ui_mcp_ux6_e2e_test.go`, `uie2e`). It also held one package-level mutable
slice (`mcpUnsupportedQualificationCategories`) that every response aliased.

ADR-0002 does not list this file as a main-owned responsibility; the roadmap
carried it as a lead (IM-009) pending an overlap check with open MCP PRs. On
2026-11-18 no open PR touches MCP code.

## Decision

Move the projection to `internal/mcp/evidenceview` with 5 exported
identifiers: `Build`, `View`, `Requirement`, `Summary` and the `State` type.
The state values stay unexported constants: outside the package they are a
wire contract (the JSON strings `met`, `not_met`, `not_started`,
`synthetic_non_qualifying`, `unavailable`, `not_applicable`), and the tests
that compare them as Go values moved with the engine. The shared slice becomes
a function that returns a fresh slice per call, so no caller can alias or
mutate a shared list; the JSON output is identical.

Main keeps: the handler, `requireRole(w, r, RoleViewer)`, the GET-only method
check, capability selection, the rollout state that supplies the summary, and
the clock reading (`time.Now()`). The two callers call `evidenceview.Build`
directly; there was no wide caller surface to preserve with a root alias.
Lifecycle: the package holds no state, starts no goroutines and does no I/O or
logging; main owns every input and the response write.

Unchanged: the wire bytes (pinned by `TestEvidenceView_WireBytesUnchanged`,
captured from `buildMCPEvidenceDTO` at main `348a2cf`, and by a five-case
before/after byte comparison recorded in the PR), the no-qualification-claim
invariant, the synthetic-never-qualifies rule, the not-started-versus-not-met
distinction, authorization, and the read-only handler.

## Tests

Engine-only tests moved with their names unchanged:
`TestMCPUX6_Evidence_NotStartedProduction`, `_WindowBoundaries`,
`_SyntheticNonQualifying`, `_DefectsAndRehearsal`, `_NoQualificationClaim`.
New: wire-bytes golden, result independence (no aliasing between two
`Build` results or into a later one), and a boundary test (imports, package
state, `init`, exported-surface cap) with negative controls. The handler
tests `TestMCPUX6_EvidenceHandler` and `TestMCPUX6_ApprovalListsReadContract`
stay in root because they need the admin mux, RBAC and rollout state.

## Consequences

The truth model of the evidence card can be tested without compiling the
application. `mcp_shadow_metrics.go`, carried with this task in the roadmap,
is a different responsibility (a process-wide telemetry sink with a
`sync.Once` singleton read by `/metrics`); it is split out as IM-011 and needs
an instance owner in main before any move, per ADR-0038.
