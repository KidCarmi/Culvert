# MCP First Controlled Canary — Runbook (future; NOT yet executable)

**Status:** FUTURE protocol. Canary is architecturally defined but **not activatable** in the
shipped build (`live_executor_absent`; `live_execution` approvals unissuable). This runbook is
the reviewable procedure the separately-approved Canary *activation* phase must follow. It must
never involve customer traffic.

**Authority:** ADR-0035, `CANARY-READINESS-MATRIX.md`, `ROLLOUT-AND-ROLLBACK.md` §1.4.

## Core principle

The first real MCP upstream side effect must be **smaller, more observable, more reversible,
and harder to reach** than any normal execution that will ever exist later. Everything below is
in service of that: one of everything, synthetic, recorded, time-boxed, instantly reversible.

## Preconditions (all must be machine-verified READY before starting)

Run the Canary preflight (`GET /api/mcp/rollout` → `canary`) and confirm `node_ready` plus an
activation preflight (`evaluateCanaryActivationPreflight`) returns `Ready:true` — i.e. the Unmet
set is empty. This requires the separately-reviewed activation to have:

1. **Armed the live tier** — composed a live `execution.Executor` + bounded `UpstreamCaller` +
   materialize-broker + inspection, and called `markGatewayExecDepsReady` (edits the
   execution-posture wall — the reviewer sees it).
2. **Made `live_execution` issuable** under four-eyes + short-TTL governance.
3. **Attested the Shadow Exit Review** (`shadowExitReviewAttested`).
4. **Confirmed** durable events, inspection, registry, catalog, policy healthy; kill clear;
   rollback path healthy.

## The experiment (one of everything)

| Dimension | First-Canary value |
|---|---|
| nodes | **1** (the controlled Canary node) |
| identity | **1** synthetic/non-production principal |
| MCP server | **1** controlled server that **independently records every received invocation** |
| tool | **1** exact tool |
| fingerprint | **1** exact reviewed fingerprint (rug-pull invalidates the approval) |
| approval | **1** `live_execution` ToolApproval — four-eyes, ≤24h TTL, exact target |
| operation class | **read/discovery only** (Culvert's own classification, not `readOnlyHint`) |
| credential | synthetic/non-production credential **only if the tool requires one** |
| request count | bounded by the machine-enforced `canary.Budget` (total/rate/concurrency/window) |
| controls | immediate kill switch + Canary→Shadow/Observe rollback rehearsed first |

## Procedure

1. **Rehearse rollback first** (`ROLLOUT-AND-ROLLBACK.md` §1.4 entry criterion): drive
   Canary→Shadow and Canary→Observe on the node, record the rollback time, confirm no new
   executions admitted and durable evidence preserved.
2. **Stand up the recording upstream**: a controlled MCP server that logs every invocation it
   receives independently of Culvert, so "did Culvert cause exactly the executions we expect?"
   is answerable from the upstream side, not only Culvert's evidence.
3. **Issue the live approval**: four-eyes (distinct requester + approver), exact
   tenant+server+tool+fingerprint, ≤24h expiry. Confirm `canary.SatisfiesLiveExecution` accepts
   it against the current observed target.
4. **Set the budget**: `canary.Budget` with tight total/rate/concurrency caps and a short window;
   confirm `ValidateBudget` accepts it.
5. **Preflight**: confirm `evaluateCanaryActivationPreflight` returns `Ready:true` (empty Unmet).
6. **Activate** Canary for the bounded scope. Drive the bounded request corpus from the synthetic
   identity.
7. **Observe** continuously: Culvert outcome evidence (executed=true/false, upstream
   success/failure, response-inspection result, abort class, duration) reconciled against the
   recording upstream's independent log. Any mismatch is a whole-Canary breach → auto-stop.
8. **Stop** on budget exhaustion, window expiry, or any `AbortCanary` condition (§16) — auto-demote
   to Shadow and/or engage the kill switch.
9. **Roll back** at the first sign of any whole-Canary breach; the kill generation remains
   authoritative for requests already admitted (PREREQ-MCP-KILL-1).

## Automatic-abort conditions (whole-Canary; §16)

out_of_scope_execution · scope_escape · tool_fingerprint_drift · server_identity_drift ·
outcome_evidence_loss · credential_safety_failure · budget_exhausted · elevated_error_rate ·
latency_pathology · unexpected_upstream_response.

## Explicit non-goals

- No customer traffic, no production credential, no production upstream.
- No wildcard/percentage scope, no write/destructive/control operation.
- No standing Canary — it is a time-boxed experiment that auto-stops.
- Graduation (read → bounded write → destructive/control, or wider scope) is a **new** Canary for
  the added delta, under its own review (`ROLLOUT-AND-ROLLBACK.md`).
