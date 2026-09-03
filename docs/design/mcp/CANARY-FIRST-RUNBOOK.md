# MCP First Controlled Canary — Runbook (future; NOT yet executable by default)

**Status:** FUTURE protocol. This runbook is the reviewable procedure the separately-approved
Canary *activation* phase must follow. It must never involve customer traffic. The precise
current posture (do NOT collapse these into "done" or "not done"):

| Layer | State today |
|---|---|
| Canary architecture — preflight, budget ceiling, trust firewall | **IMPLEMENTED** |
| Canary architecture — scope gate (`ValidateScope`) | **PARTIAL** — forbids percentage/group/wildcard and caps server & tenant at 1, but `MaxCanaryTools`/`MaxCanaryPrincipals` are **2** and `principalCount` sums Principals+Clients+Agents, so the machine gate does NOT enforce the one-tool/one-synthetic-principal experiment; that must be imposed as an external authorization prerequisite (review §10) |
| Canary architecture — whole-Canary AUTOMATIC abort | **PARTIAL / DEFECTIVE** — only `budget_exhausted` and `scope_escape` have automatic trippers; the other eight declared breaches do not auto-stop (see §16 below and the review §16) |
| Canary architecture — durable invocation evidence | **PARTIAL / DEFECTIVE** — events carry no `OutcomeEvidence`; the post-call outcome commit is success-only (upstream errors + DLP blocks emit no post-call event) and a post-send crash is indeterminate, so the executed/status/duration reconciliation the procedure below assumes is not fully backed (review §15/§18) |
| Production live-tier dependency composition | **COMPOSABLE** — opt-in behind `CULVERT_MCP_LIVE_DEPS` (`composeProductionGatewayLiveTier`); default OFF |
| Live tier arming | **NOT OPERATOR-PERFORMABLE YET** — the governed, node-readiness-gated `armLiveTier` function exists and is correct, but has NO production caller (no startup path, admin API, or other non-test code invokes it); arming is reachable only from tests today |
| Manual controls — graceful rollback | **NOT OPERATOR-REACHABLE** — only the emergency kill (`POST /api/mcp/rollout/emergency`) is wired; `quiesceLiveTier` has no production caller and `apiMCPRolloutTransition` returns `distribution_not_configured` for a Canary→Shadow/Observe target, so the "rollback rehearsed first" control below is not admin-invokable today (review §17) |
| Canary activation (forward transition) | **NOT OPERATOR-REACHABLE** — `apiMCPRolloutTransition` returns `distribution_not_configured` for a Canary target (`ui_mcp_rollout.go:116`) and nothing in non-test code constructs the distribution publication coordinator (`publication.New`) or calls `coord.Publish`, so an operator cannot transition the node into Canary mode even with arming + activation inputs closed (review §13/§17, blocker 12 — the forward twin of the graceful-rollback gap above) |
| Armed by default | **NO** — a stock build composes nothing and arms nothing (`live_executor_absent`) |
| Canary active | **NO** — no production path begins a Canary generation or reaches an upstream |
| A controlled upstream reachable under the supported production trust model | **NOT AVAILABLE TODAY** — see the connectivity blocker below |
| The exact tool `catalog.Usable` at request time | **NO** — `seedTools` lands every inventory tool `catalog.Quarantined` and the policy engine hard-overrides a quarantined tool to `ActionQuarantine` BEFORE any user rule (`internal/mcp/policy/engine.go:132-135`); `ApproveLive` deliberately never promotes ("live trust never materializes `catalog.Usable`"). A `shadow_evaluation` approval or another governed promotion path is required, else every exact-tool request is denied (review §6/§7, blocker 13) |
| The exact request resolves to an ALLOW-class policy decision | **NOT ESTABLISHED** — a no-`CredentialProfile` rule may itself be DENY, an unmatched request default-denies (`engine.go:170-173`), and `resolveEnforcing` blocks every non-allow-class decision; the preflight's `PolicyHealthy` fact only proves a snapshot exists (review §4/§13, blocker 14) |

> **What changed (PR #1291):** the production live-tier dependency graph is now composable
> (`composeProductionGatewayLiveTier`, opt-in via `CULVERT_MCP_LIVE_DEPS`) and the tier is armable
> through the single governed path (`armLiveTier`). This does **not** activate a Canary and does
> not arm anything on a stock node.
>
> **What changed earlier:** `live_execution` ToolApprovals are **issuable** under governance
> (four-eyes, ≤24h TTL, exact-current-state) — step 3 below is executable today, and readiness row
> 16 (`live_execution_approval_invalid`) is satisfiable. Issuing an approval is a TRUST decision
> only: it arms no executor and does not clear `live_executor_absent`.
>
> **Connectivity blocker (recorded, fail-closed — PR #1291 + First Controlled Canary Review).**
> The production upstream client (`newProductionUpstreamClient`) uses `DefaultGatewayPolicy`
> (https-only, no-private, no-downgrade) and the default SPKI verifier (base64 SHA-256 of the leaf
> SubjectPublicKeyInfo). The registry stores an endpoint/identity as OPAQUE tokens, so a controlled
> server registered with a plain `https://` endpoint, a PUBLIC host, and a real base64 SHA-256 SPKI
> pin IS dialable under this model. But the only documented controlled inventory
> (`docs/operator/mcp-qualification-inventory.md`) fails closed on **three independent axes**: the
> `mcp+https://` scheme is rejected by the https-only policy at `destination.Canonicalize`; the
> `*.qual.svc` host is private/internal and rejected at `destination.Resolve` (SSRF), and
> `AllowPrivate` has **no production caller** (enabling it is a design change, not a flag flip); and
> the SPIFFE-format identity is read as an SPKI digest and rejected by the verifier. No public-HTTPS
> controlled MCP server with an SPKI pin is provisioned today. Every axis fails toward NO
> connection, never toward an unauthenticated one.
>
> **Reachable is not usable.** Even a dialable HTTPS+SPKI+public target may reject every request:
> Culvert's client drives no MCP `initialize`/`notifications/initialized` handshake, no version
> negotiation (`NegotiateVersion` has no production caller), and no `MCP-Protocol-Version`/
> `Mcp-Session-Id` headers, so a spec-compliant server rejects the sessionless `tools/list`/
> `tools/call`. Closing connectivity therefore also needs a target that permits sessionless calls OR a
> Culvert-side upstream lifecycle implementation (review §5, blocker 1).

**Authority:** ADR-0035, `CANARY-READINESS-MATRIX.md`, `ROLLOUT-AND-ROLLBACK.md` §1.4.

## Core principle

The first real MCP upstream side effect must be **smaller, more observable, more reversible,
and harder to reach** than any normal execution that will ever exist later. Everything below is
in service of that: one of everything, synthetic, recorded, time-boxed, instantly reversible.

## Preconditions (all must be machine-verified READY before starting)

Run the Canary preflight (`GET /api/mcp/rollout` → `canary`) and confirm `node_ready` plus an
activation preflight (`evaluateCanaryActivationPreflight`) returns `Ready:true` — i.e. the Unmet
set is empty. This requires the separately-reviewed activation to have:

1. **Armed the live tier** — composed the production live-tier dependency graph
   (`composeProductionGatewayLiveTier`, opt-in via `CULVERT_MCP_LIVE_DEPS`: a live
   `execution.Executor` + bounded `UpstreamCaller` + materialize-broker + inspection) and then
   armed it through the single governed, node-readiness-gated path (`armLiveTier`, the sole caller
   of `markGatewayExecDepsReady`). **Gap:** `armLiveTier` currently has NO production caller — no
   startup path or admin API invokes it (only tests do), so an operator cannot actually perform this
   step in the shipped process. A governed production arming entry point must be wired first. Arming
   is NOT a hand edit of the posture wall and is NOT Canary activation — the rollout mode is
   untouched and no upstream is reached. On a stock node this step has not run, so the facts report
   `live_executor_absent`.
2. **Made `live_execution` issuable** under four-eyes + short-TTL governance — **shipped**; the
   governed issue/approve path (`RequestLiveApproval`/`ApproveLive`) is available today.
3. **Attested the Shadow Exit Review** (`shadowExitReviewAttested`).
4. **Confirmed** durable events, inspection, registry, catalog, policy healthy; kill clear;
   rollback path healthy.

## The experiment (one of everything)

| Dimension | First-Canary value |
|---|---|
| nodes | **1** (the controlled Canary node) — **NOT machine-enforced**: `ScopeSpec` has no node dimension and the publication coordinator's `pushAll` delivers the signed envelope to EVERY `Dist.Nodes()` entry, so a generic publication path would activate every armed/ready DP. An exactly-one intended-node constraint + acknowledgement check is required (review §3/§13, blocker 15) |
| identity | **1** synthetic/non-production principal |
| MCP server | **1** controlled server that **independently records every received invocation** |
| tool | **1** exact tool |
| fingerprint | **1** exact reviewed fingerprint (rug-pull invalidates the approval) — but the shipped provisioning (`seedServer`/`seedTools`/`Ingest`) seeds the fingerprint from OPERATOR-DECLARED JSON and verifies the pinned identity against its own register stamp, and nothing re-observes the live peer (`execution.Discovery.Discover` has no non-test caller), so `ToolStillCurrent` re-checks only the seeded record — the peer drifting behind the same identity is NOT caught (review §7, blocker 11) |
| approval | **1** `live_execution` ToolApproval — four-eyes, ≤24h TTL, exact target |
| operation class | **read/discovery only** (Culvert's own classification, not `readOnlyHint`) |
| credential | synthetic/non-production credential **only if the tool requires one** |
| request count | bounded by the machine-enforced `canary.Budget` (total/rate/concurrency/window) — but the budget bounds RESERVATIONS, not physical POSTs: `upstreamclient.Call` retries an idempotent read up to `MaxReadRetries` times per reservation (~3 physical POSTs). Retry-disablement is **not representable today** (`NewLimits` coerces `MaxReadRetries==0`→2, rejects negatives; `newProductionUpstreamClient` hard-codes `DefaultLimits()`), so bounding physical POSTs is a **required CODE-CHANGE prerequisite**, not an operator config (review §9/§14) |
| controls | immediate kill switch + Canary→Shadow/Observe rollback rehearsed first |

## Procedure

1. **Rehearse rollback first** (`ROLLOUT-AND-ROLLBACK.md` §1.4 entry criterion): drive
   Canary→Shadow and Canary→Observe on the node, record the rollback time, confirm no new
   executions admitted and durable evidence preserved.
2. **Stand up the recording upstream**: a controlled MCP server that logs every invocation it
   receives independently of Culvert, so "did Culvert cause exactly the executions we expect?"
   is answerable from the upstream side, not only Culvert's evidence. The server must be reachable
   AND usable: a plain `https://` endpoint on a PUBLIC host with a base64 SHA-256 SPKI pin AND a
   supported protocol that permits Culvert's sessionless `tools/list`/`tools/call` (Culvert drives no
   MCP `initialize`/version/session lifecycle — review §5); otherwise a Culvert-side lifecycle
   implementation is required first.
3. **Issue the live approval** (executable today): `POST /api/mcp/tool-approvals` with
   `purpose=live_execution`, a finite `expires_in_seconds` ≤ 86400, and the exact reviewed
   `fingerprint`+`catalog_revision` — attributed to the requester's authenticated session
   principal (operator+). A DISTINCT admin principal then `POST /api/mcp/tool-approval-decision`
   with `action=approve` (four-eyes is enforced on the canonical session subject, not display
   names or IPs; self-approval is refused). The approval re-verifies exact current state at approve
   time and fails closed on any drift. Confirm `canary.SatisfiesLiveExecution` accepts it against
   the current observed target. Issuing the grant promotes nothing to `catalog.Usable` and arms no
   executor — it only makes readiness row 16 satisfiable.
4. **Set the budget**: `canary.Budget` with tight total/rate/concurrency caps and a short window;
   confirm `ValidateBudget` accepts it.
5. **Preflight**: confirm `evaluateCanaryActivationPreflight` returns `Ready:true` (empty Unmet).
6. **Activate** Canary for the bounded scope. Drive the bounded request corpus from the synthetic
   identity. **NOT OPERATOR-REACHABLE TODAY:** `apiMCPRolloutTransition` returns
   `distribution_not_configured` for a Canary target (`ui_mcp_rollout.go:116`) and nothing in non-test
   code constructs the distribution publication coordinator (`publication.New`) or calls `coord.Publish`,
   so the signed-distribution apply that begins the Canary generation is never fed — a governed
   forward-transition/publication entry point must be wired first (review §13/§17, blocker 12).
7. **Observe** continuously: Culvert outcome evidence (executed=true/false, upstream
   success/failure, response-inspection result, abort class, duration) reconciled against the
   recording upstream's independent log. Any mismatch is a whole-Canary breach → auto-stop.
8. **Stop** on budget exhaustion, window expiry, or any `AbortCanary` condition (§16) — auto-demote
   to Shadow and/or engage the kill switch.
9. **Roll back** at the first sign of any whole-Canary breach; the kill generation is authoritative at
   the admission boundary (PREREQ-MCP-KILL-1) — but NOT across the transport retry loop:
   `upstreamclient.Call` retries an idempotent read without re-checking the kill, so a retry POST can
   land after a kill engaged mid-flight. Until the retry loop is made retry-free or kill-revalidating
   (review §9/§20, blocker 6), an admitted request's retries are outside the kill's authority.

## Automatic-abort conditions (whole-Canary; §16)

out_of_scope_execution · scope_escape · tool_fingerprint_drift · server_identity_drift ·
outcome_evidence_loss · credential_safety_failure · budget_exhausted · elevated_error_rate ·
latency_pathology · unexpected_upstream_response.

> **Current wiring (do not assume all are automatic).** As of this baseline only
> `budget_exhausted` and `scope_escape` auto-trip the whole Canary (from `reserveCanaryExecution`);
> `tool_fingerprint_drift`/`server_identity_drift` only DENY the offending request, `outcome_evidence_loss`
> only increments a metric, and `unexpected_upstream_response`/`elevated_error_rate`/`latency_pathology`
> plus witness reconciliation have no automatic tripper yet. Wiring the rest is a pre-Canary
> product-defect prerequisite — see `docs/operator/mcp-first-controlled-canary-review.md` §16.

## Explicit non-goals

- No customer traffic, no production credential, no production upstream.
- No wildcard/percentage scope, no write/destructive/control operation.
- No standing Canary — it is a time-boxed experiment that auto-stops.
- Graduation (read → bounded write → destructive/control, or wider scope) is a **new** Canary for
  the added delta, under its own review (`ROLLOUT-AND-ROLLBACK.md`).
