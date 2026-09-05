# MCP First Controlled Canary — Runbook (future; NOT yet executable)

**Status:** FUTURE protocol. This runbook is the reviewable procedure the separately-approved
Canary *activation* phase must follow. It must never involve customer traffic. It is **NOT executable
in ANY supported configuration** — not merely "not by default": `CULVERT_MCP_LIVE_DEPS` only COMPOSES
dependencies, and there is still no production caller for arming (`armLiveTier`, blocker 3) and no
Canary activation entry point (blocker 12), so no opt-in makes this a usable path today. The precise
current posture (do NOT collapse these into "done" or "not done"):

| Layer | State today |
|---|---|
| Canary architecture — preflight, budget ceiling, trust firewall | **IMPLEMENTED** |
| Canary architecture — scope gate (`ValidateScope`) | **PARTIAL** — forbids percentage/group/wildcard and caps server & tenant at 1, but `MaxCanaryTools`/`MaxCanaryPrincipals` are **2** and `principalCount` sums Principals+Clients+Agents, so the machine gate does NOT enforce the one-tool/one-synthetic-principal experiment; that must be imposed as an external authorization prerequisite (review §10) |
| Canary architecture — whole-Canary AUTOMATIC abort | **IMPLEMENTED** (review blocker 7 CLOSED) — every declared `AbortCanary` code has a production trip path onto the ONE `canary.AbortController`; the two rate detectors are reachable inside the 3-execution corpus, and the time box stops the experiment with NO further request arriving. The latch revokes EXECUTION AUTHORITY, not the node's mode: demotion stays governed by blockers 10 and 12, so `ModeCanary + ABORTED` is the truthful state. Two codes have wired funnels but no production PRODUCER yet — `credential_safety_failure` (blocker 9) and `unexpected_upstream_response` (blocker 8). See §16 below and the review §16/§25a |
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
| nodes | **1** (the controlled Canary node) — **NOT machine-enforced**: `ScopeSpec` has no node dimension and the publication coordinator's `pushAll` delivers the signed envelope to EVERY `Dist.Nodes()` entry, so a generic publication path would activate every armed/ready DP. Constraining the node list is NOT enough: `mcpPullDistributor.Push` discards its node argument and the shared `ConfigSnapshot` reaches every DP, and the apply path has no intended-node check, so non-target DPs ACTIVATE before any acknowledgement reveals it. A PREVENTIVE control is required — a signed node audience rejected at DP apply, or a per-node delivery channel (review §3/§13, blocker 15) |
| identity | **1** synthetic/non-production principal |
| MCP server | **1** controlled server that **independently records every received invocation**, and can **distinguish the authorized `tools/call` invocations from auxiliary lifecycle/discovery traffic** (`initialize`, `notifications/initialized`, `tools/list`) and attribute each side-effect-bearing call to its reservation — otherwise all initialization/discovery MUST occur outside the measured window (review §9/§14) |
| tool | **1** exact tool |
| fingerprint | **1** exact reviewed fingerprint (rug-pull invalidates the approval) — but the shipped provisioning (`seedServer`/`seedTools`/`Ingest`) seeds the fingerprint from OPERATOR-DECLARED JSON and verifies the pinned identity against its own register stamp, and nothing re-observes the live peer (`execution.Discovery.Discover` has no non-test caller), so `ToolStillCurrent` re-checks only the seeded record — the peer drifting behind the same identity is NOT caught (review §7, blocker 11) |
| approval | **1** `live_execution` ToolApproval — four-eyes, ≤24h TTL, exact target |
| operation class | **read/discovery only** (Culvert's own classification, not `readOnlyHint`) |
| credential | synthetic/non-production credential **only if the tool requires one** |
| request count | **EXACTLY: `MaxTotalExecutions=3`, `MaxExecutionsPerMinute=1`, `MaxConcurrentExecutions=1`, `Window=15m`** (review §9 — not "tight": `ValidateBudget` would accept up to 1000 executions over 7 days, so a generic "bounded" budget is a materially different experiment). The witness invariant is over the **side-effect-bearing tool invocations only**: **exactly 3 reservations and exactly 3 authorized `tools/call` invocations**. Auxiliary MCP lifecycle/discovery traffic (`initialize`, `notifications/initialized`, `tools/list`) consumes NO reservation and must be counted and attributed **separately** — never folded into the three, and never counted as a breach (review §9). Blocker 6's **retry-free** remedy is now in place (review §25a): retry-disablement is representable (`upstreamclient.RetryMode`/`RetryDisabled`) and `newProductionUpstreamClient` builds from `RetryFreeLimits`, so one reservation ⇒ at most one side-effect-bearing physical invocation, proven at the wire under concurrency and ambiguous transport failure. **Charging attempts to the budget is NOT an accepted alternative** (review §9/§14/§26) |
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
4. **Set the budget**: `canary.Budget` with the EXACT reviewed values — `MaxTotalExecutions=3`,
   `MaxExecutionsPerMinute=1`, `MaxConcurrentExecutions=1`, `Window=15m` (review §9). Do NOT substitute
   a merely "tight" budget: `ValidateBudget` accepts totals up to 1000 and windows up to 7 days, so any
   other value is a different experiment with a different blast radius and a different expected witness
   count. Confirm `ValidateBudget` accepts it.
5. **Preflight**: confirm `evaluateCanaryActivationPreflight` returns `Ready:true` (empty Unmet).
6. **Activate** Canary for the bounded scope. Drive the bounded request corpus from the synthetic
   identity. **NOT OPERATOR-REACHABLE TODAY:** `apiMCPRolloutTransition` returns
   `distribution_not_configured` for a Canary target (`ui_mcp_rollout.go:116`) and nothing in non-test
   code constructs the distribution publication coordinator (`publication.New`) or calls `coord.Publish`,
   so the signed-distribution apply that begins the Canary generation is never fed — a governed
   forward-transition/publication entry point must be wired first (review §13/§17, blocker 12).
7. **Observe** continuously: Culvert outcome evidence (executed=true/false, upstream
   success/failure, response-inspection result, abort class, duration) reconciled against the
   recording upstream's independent log — **partitioned by class**: exactly 3 side-effect-bearing
   `tools/call` invocations, with auxiliary lifecycle/discovery traffic counted separately and never
   folded into that total (review §9). Any mismatch WITHIN the side-effect-bearing class is a
   whole-Canary breach → auto-stop.
8. **Stop** on budget exhaustion, window expiry, or any `AbortCanary` condition (§16) — demote to
   Shadow and/or engage the kill switch. **Window expiry is NOT an automatic transition today:**
   `budget_exhausted` is tripped only from `reserveCanaryExecution` (`mcp_canary_runtime.go:391`) and
   `BudgetDeniedWindow` is produced only by `BudgetEnforcer.Reserve` — both request-driven — so if no
   further request arrives after the window elapses, nothing trips and the node stays in Canary mode
   indefinitely. Expiry ends the authority to ADMIT, it does not stop the experiment. Until a
   deadline-driven stop exists, the operator MUST explicitly demote/kill at the window boundary
   (review §16, blocker 7).
9. **Roll back** at the first sign of any whole-Canary breach; the kill generation is authoritative at
   the admission boundary (PREREQ-MCP-KILL-1) — but NOT across the transport retry loop:
   `upstreamclient.Call` retries an idempotent read without re-checking the kill, so a retry POST can
   land after a kill engaged mid-flight. Until the retry loop is made retry-free or kill-revalidating
   (review §9/§20, blocker 6 — now CLOSED: the retry-free path removes the window entirely, so an
   admitted request has no retry that could land outside the kill's authority).

## Automatic-abort conditions (whole-Canary; §16)

out_of_scope_execution · scope_escape · tool_fingerprint_drift · server_identity_drift ·
outcome_evidence_loss · credential_safety_failure · budget_exhausted · elevated_error_rate ·
latency_pathology · unexpected_upstream_response · independent_witness_mismatch · window_expired.

> **Wiring (review blocker 7 CLOSED).** Every code above now has a production trip path, and they all
> converge on the ONE `canary.AbortController` — there is no second latch. Drift denies the request AND
> stops the experiment; outcome-evidence loss stops it (the metric remains in parallel); a
> reconciliation conflict stops it. What the latch revokes is EXECUTION AUTHORITY: no new reservation,
> and a request already admitted fails the final live revalidation before `Upstream.Call`.
> It does NOT demote the node — demotion stays governed by review blockers 10 and 12, so the truthful
> state is `ModeCanary + ABORTED` and `activation_runtime.auto_stop` reports `execution_authority`
> separately from mode. Two codes have no production PRODUCER yet:
> `credential_safety_failure` (blocker 9) and `unexpected_upstream_response` (blocker 8); their funnels
> are wired and gated. See `docs/operator/mcp-first-controlled-canary-review.md` §16.
>
> **Threshold reachability (review §16/§26) — satisfied.** `sample_floor = 2`; the error rate trips iff
> `2 × failures ≥ samples` (≥ 50%) over the current activation generation; a single attempt at or above
> 15s trips `latency_pathology` with NO floor, and a mean at or above 10s trips it at the floor. All are
> reachable within `MaxTotalExecutions = 3`, and `TestHealth_SampleFloorFitsTheFirstCanaryCorpus` fails
> if the floor drifts beyond the corpus. These are First-Canary safety thresholds derived from the 30s
> upstream request timeout — they are NOT product SLAs. The error-rate numerator counts ordinary
> post-admission execution failures only; request-scoped policy/scope denials carry their own
> classification and are never counted here.
>
> **What counts as a failure (rounds 5 and 6).** The UPSTREAM LEG's own verdict, in all three shapes
> it arrives in: a transport error, a nil response, or a decoded JSON-RPC `error` object — the last
> being the peer answering that the tool failed, which Culvert already classifies
> `ReasonUpstreamCallFailed`. It is deliberately NOT Culvert's disposition: a response-DLP block after
> a successful peer answer is this gateway's own policy working, and counting it would let a healthy
> Canary abort itself for its own controls firing.
>
> **The operator surface is never more optimistic than admission.** `activation_runtime.auto_stop`
> derives `window_expired` and `execution_authority` from the same two-ended `WindowOpen` predicate
> the reservation path uses, so a clock rolled behind the activation instant is reported as a closed
> window immediately rather than at the next watchdog fire. That is reporting, not deciding — nothing
> in the admission path reads it, and `AbortController` remains the one abort authority.

## Explicit non-goals

- No customer traffic, no production credential, no production upstream.
- No wildcard/percentage scope, no write/destructive/control operation.
- No standing Canary — it is a time-boxed experiment. **The time box is self-enforcing** (blocker 7):
  the deadline is absolute, derived from the persisted activation instant, and a watchdog latches
  `window_expired` with NO further request arriving; a restart never grants a fresh window and a
  restart after expiry latches before any admission is possible. The operator MUST still perform the
  governed demotion at the boundary, because the latch revokes execution authority but does not change
  the node's mode (blockers 10/12).
- Graduation (read → bounded write → destructive/control, or wider scope) is a **new** Canary for
  the added delta, under its own review (`ROLLOUT-AND-ROLLBACK.md`).
