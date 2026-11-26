# Culvert Language & Terminology Governance Review — 2026-11-26

> **Status:** Point-in-time review. **Window:** `1836a2d..HEAD` (maintenance agent ADR-0062 slices 3b–7: intent fence,
> gate checkpoints, `restore_prior`, resumed health gates).

## Executive Summary

One Low-priority, documentation-only finding. Terminology Health Score: 92/100 (was 93).

## Finding: health gate vs health check

- **Business concept:** the maintenance agent's pass/fail check that a restarted proxy is healthy.
- **Current names:** "health gate" (ADR-0061/0062, `docs/OPERATIONS.md`, config example, agent status messages such as
  `interrupted.go`); "health check" / "health-checked" (40+ uses in `docs/operator/release-management-agent.md`);
  `gate` in wire identifiers (`gate_checkpoint`, `resume_interrupted_gate`, `target_live_ungated`).
- **Problem:** an operator reading the agent's message ("never passed the health gate") could not find the term in the
  runbook, which used "health check" for the same stage.
- **Canonical name:** **health gate** for the stage; "health check" stays valid for a generic probe. Recorded in
  `docs/design/PRODUCT-TERMINOLOGY.md`.
- **Change:** runbook prose and two config-example comments aligned; glossary entry added.
- **Not changed:** identifiers, reason codes, audit details, API strings, tests.
- **Affected:** documentation and a config-example comment only. Migration complexity: low. Compatibility risk: none.
  PR size: small.

## Other checks

No new GUI label, metric, alert or audit action was introduced in the window. Retired-term sweep found no regressions.

## Priority

Critical none · High none · Medium none · Low 1.
