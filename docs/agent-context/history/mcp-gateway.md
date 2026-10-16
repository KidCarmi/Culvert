# Preserved source: Mcp Gateway

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [MCP Agent Security Gateway (ADR-0024, disabled-by-default)](#claude-main-l267-l267)
- [MCP CP/DP production composition + rollout transaction (PR-12, `mcp_distribution_startup.go` + the `applyMCPCapabilityEnvelope` coordinator in `mcp_distribution.go`)](#claude-main-l268-l268)

<a id="claude-main-l267-l267"></a>

## MCP Agent Security Gateway (ADR-0024, disabled-by-default)

[Original lines 267–267](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L267-L267) · `claude-main-L267-L267`

<!-- BEGIN preserved-block: claude-main-L267-L267 -->
- **MCP Agent Security Gateway (ADR-0024, disabled-by-default)**: `internal/mcp` (27 subpackages, ~47k LOC excluding tests) is Culvert's MCP (Model Context Protocol) agent gateway — a physically-isolated Gateway + Management capability pair (proxy-side tool-call inspection/policy/credential-broker vs. fleet-side MCP-server discovery/rollout) shipped across PR-1 through PR-11. Disabled-by-default at every layer: with no MCP configuration, no listener binds, no upstream pool starts, no executor runs, no credential is materialized, and the existing Secure Web Gateway request path is byte-identical. Root wiring: `mcp_runtime.go` (listener runtime), `mcp_distribution.go`/`mcp_distribution_adapters.go` (CP→DP signed-snapshot distribution, PR-10) + `mcp_distribution_startup.go`/`mcp_distribution_startup_config.go` (PR-12 production DP-applier composition + rollout/distribution transaction, see below), `mcp_rollout.go` (Disabled→Observe→Shadow→Canary→Production ladder, PR-11); admin surface: `ui_mcp.go`/`ui_mcp_rollout.go` plus the Command Center/Activity GUI panels. Design authority: `docs/design/mcp/` (the PR-0 baseline package) and `docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md` (Accepted 2026-07-31) — the trust-boundary, threat-model, and rollout design are recorded there, not re-derived here.
<!-- END preserved-block: claude-main-L267-L267 -->

<a id="claude-main-l268-l268"></a>

## MCP CP/DP production composition + rollout transaction (PR-12, `mcp_distribution_startup.go` + the `applyMCPCapabilityEnvelope` coordinator in `mcp_distribution.go`)

[Original lines 268–268](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L268-L268) · `claude-main-L268-L268`

<!-- BEGIN preserved-block: claude-main-L268-L268 -->
- **MCP CP/DP production composition + rollout transaction (PR-12, `mcp_distribution_startup.go` + the `applyMCPCapabilityEnvelope` coordinator in `mcp_distribution.go`)**: closes the two mechanical gaps that left the signed-distribution rollout path unreachable in production. **P1-A (composition)**: `initMCPDistribution` (wired in `main.go` AFTER `initMCPRollout`, disabled-by-default) is the production caller that was missing — it composes the Gateway + Management DP appliers from env-provisioned PUBLIC ed25519 trust (`CULVERT_MCP_DISTRIBUTION_TRUST_KEYS`; empty ⇒ no applier, byte-identical default; invalid ⇒ fail-closed), `Recover`s durable state, and registers them; `setDPApplier` now has a production caller, so `applySnapshotMCP` (called from `controlplane_snapshot.go`) can reach the durable rollout commit. Composition is idempotent (guards double-registration), capability-isolated, and fail-closed (a per-capability `Recover` error registers NO applier for either). **P1-B (transaction)**: `applyMCPCapabilityEnvelope` makes distribution activation and the node-local rollout commit ONE truthful transaction — the invariant is that an `AckApplied` is IMPOSSIBLE unless BOTH the distribution active state AND the local rollout state accepted the same rollout revision, and a locally-rejected rollout never leaves an applied distribution revision. Ordering (crash-boundary reasoning, §8): (1) a pure, node-local rollout precondition PRE-CHECK rejects an executing target mode (Shadow/Canary/Production) with the guarded-execution plane not composed, or a capability-mismatched rollout, BEFORE any distribution activation (so the shipped Shadow fail-closed path never stages distribution state, produces no `AckApplied`, and leaves no split); (2) `Applier.Apply` verifies signature+epoch+revision then persists+activates (the signature is verified HERE, before any rollout config is trusted — no unsigned local shortcut); (3) the rollout commit is the coupled second durable half; (4) on a rollout persistence failure AFTER distribution activated, `Applier.AbortApplied` reverts the distribution activation (persist-before-swap) and replaces the pending Applied ack with a Rejected one, so no `AckApplied` is delivered and no new-distribution/old-rollout split remains. A double persistence fault is logged and converged at the next restart by `reconcileRolloutWithDistribution` (distribution active envelope is the source of truth for mode/scope; the rollout projection is re-committed idempotently from it). `AbortApplied`/`RejectAck` are additive `internal/mcp/cpdp/apply` primitives; existing `Apply`/`Rollback`/`Recover` behavior is byte-identical. The signed distribution path CANNOT bypass the Production lock (a signed Production envelope fails closed at the same execution-dependency gate). This is composition + transaction + durable-state mechanics ONLY; real Shadow still requires separately-composed guarded execution + credential containment, a stable host, real scope, parity evidence, monitoring, ownership, and fresh identity. Proofs: root `mcp_distribution_transaction_test.go` (production compose, non-executing success, Shadow/Production fail-closed, persistence-failure revert, capability isolation, restart/recompose, idempotent reapply) + `internal/mcp/cpdp/apply/apply_test.go` (`AbortApplied`/`RejectAck`). See `docs/operator/mcp-rollout-durable-state.md`.
<!-- END preserved-block: claude-main-L268-L268 -->
