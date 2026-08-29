# First Controlled MCP Shadow Activation — Evidence Bundle (WORKING DRAFT)

> Sanitized. No credentials, tokens, or secrets. Runtime evidence produced by an
> in-process controlled harness that drives the REAL Culvert MCP production code
> paths (real listener socket + TLS + OAuth JWT + real ShadowEvaluator +
> real durable schema-v2 evidence spool). See "Nature of the environment" below.

## 1. Baseline (established before activation)

- Repository: `KidCarmi/Culvert`
- `main` SHA (resolved from `origin/main`): `c6e071c9cbd40ee93b85f6315b60a1e3e26983a3`
  - Identical to the known merge commit for PR #1236 ("mcp-tool-trust-approval").
  - `main` has NOT advanced past #1236 at run time.
- Working branch: `claude/culvert-mcp-shadow-activation-0ahtqn` (at same SHA)
- Toolchain: go1.26.6 linux/amd64
- Node/env: single ephemeral container ("vm"); no prebuilt culvert binary.
- `CULVERT_MCP_SHADOW_READY`: unset at container start (default OFF, fail-closed).

## 2. Nature of the controlled environment (honesty statement)

The task frames this as an operational activation of a running node driven by
operator HTTP APIs against a separately-deployed node. That exact topology is not
available in this container, and reproducing it would require MORE mocking (a fake
external OAuth IdP), not less. The genuine, controlled, reproducible way to drive
the REAL production pipeline here is an in-process Go harness that exercises the
actual production code paths with real cryptography and a real listener socket:

- real Gateway listener binding a real TCP socket on 127.0.0.1 with real
  server TLS and real RFC-9728/OAuth JWT (ES256) bearer-token validation
  (`mcpTestPKI` builds a real CA, server cert, and a JWKS signer). The run uses
  the `bearer` sender-constraint posture (`ClientCertMode="none"`), which
  isolates the policy/rollout behavior from sender binding; the mTLS
  client-auth and DPoP sender-binding postures are exercised by the QUAL-1
  auth tests, not re-run here;
- the REAL non-executing `*execution.ShadowEvaluator` composed via the production
  `composeGatewayShadowIntoConfig` path (`CULVERT_MCP_SHADOW_READY=1`);
- the REAL tool-trust approval → `catalog.Usable` projection (PR #1236);
- the REAL signed CP→DP rollout activation (`applySnapshotMCP` → preflight →
  distribution commit → rollout commit);
- the REAL durable schema-v2 evidence spool and the REAL `culvert_mcp_shadow_*`
  metric singleton;
- a REAL controlled upstream HTTP server (owned by the harness) with an
  invocation counter, so the central differential — Culvert shadow evaluations > 0
  while the protected upstream observes 0 invocations — is independently measured.

This is real-runtime, in-process, single-node evidence over the production code —
NOT evidence from a production-like fleet with a real Control Plane and external
IdP. The verdict is scoped to that explicitly.

## 3. Pre-activation safety proof (from the code, structural)

- Shadow composition (`mcp_shadow_startup.go`) composes ONLY
  `*execution.ShadowEvaluator` (no `UpstreamCaller`, no materialize-capable broker;
  `ShadowConfig` structurally cannot carry either — Layer B / #1226).
- It arms ONLY the shadow readiness tier (`markGatewayShadowDepsReady`) and NEVER
  calls `markGatewayExecDepsReady`. The two tiers are independent atomics
  (`mcp_rollout_execdeps.go`): Shadow readiness cannot imply live-execution
  readiness. `liveExecDepsConfigured(false)` stays false.
- Shadow metric sink (`mcp_shadow_metrics.go`): `ObserveUpstream`,
  `ObserveExecution`, `ObserveDLPBlock`, `ObserveOutcomeEvidenceLoss` are hardcoded
  no-ops — "a non-zero value on any of them would itself be a bug."
- Durable `ShadowEvidence` (`internal/mcp/events/model/model.go`):
  `MaterializationReadiness` and `ResponseInspection` are ALWAYS `not_evaluated`
  (any other value is invalid at Validate).

## 4. Precondition-8 resolution (was the runbook blocker)

The operator runbook (`docs/operator/mcp-shadow-activation.md`) precondition 8
requires at least one `Usable` scoped tool, and its text at this SHA still says the
approval slice is unshipped and this "REMAINS OPEN." That text is stale relative to
PR #1236, which shipped the tool-trust approval → `catalog.Usable` projection
(`mcp_tooltrust.go`): a tool becomes `Usable` IFF an active, unexpired, unrevoked,
shadow-purpose `ToolApproval` binds its CURRENT fingerprint on a usable server.
Precondition 8 is therefore SATISFIABLE post-#1236, and Controlled Shadow
activation is genuinely reachable. (Runbook line is a documentation lag, not a
functional gap — noted, not patched, per the no-code-change rule.)

## 5. Controlled target + MCP server + identity (this run)

- Target: ONE controlled in-process node (this container), dedicated to the experiment.
- Controlled MCP server: `controlled-test-server`, owned by the harness, exposing two
  harmless deterministic tools — `echo` (policy ALLOW) and `danger` (policy DENY). It is
  backed by a REAL controlled upstream TLS server (httptest) **registered as the server's
  inventory endpoint**, so a regressed upstream dial would land on its handler; its
  invocation counter is the independent zero-side-effect witness.
- Synthetic identity: tenant `qualification`, principal/sub `synthetic-shadow-principal`,
  client_id `client-gw`, auth = ES256 bearer (RFC-9728 audience), scope `gateway.tools.call`.
- Tool fingerprint (deterministic from the tool definition): `8f7e32e0c4fa380a9ae085a0a306ca3a8552252ffdbb6e7795973e7fd011043c`
  (format version 1). ToolApproval id is per-run (e.g. `71303ced…`), purpose `shadow_evaluation`.
- Canonical Shadow scope (bounded, enumerable — no wildcard):
  `capability=gateway, servers=[controlled-test-server], principals=[synthetic-shadow-principal],
  operations=[write], high_risk=true, scope_revision=1`.
- Activation config: signed Gateway `SignedConfig` (selector_schema=1, capability=1,
  mode=2/Shadow), applied through the real `applySnapshotMCP` CP→DP path; config epoch 0,
  config revision 2.

## 6. Runtime results — `TestFirstControlledShadowRun` (PASS)

Verbatim runtime EVIDENCE (sanitized):

```
baseline: gateway_mode=disabled canary=off production=off live_exec_ready=false
pre-activation: shadow_mode=NO shadow_evaluator_composed=YES live_executor_composed=NO
                shadow_deps_ready=true live_execution_ready=false reason="composed"
gateway listener LIVE and serving at https://127.0.0.1:<port> (real TLS+OAuth)
tool trust: approval=<id> purpose=shadow_evaluation tool=controlled-test-server/echo
            fingerprint=8f7e32e0… eligibility=Usable
preflight READY (real usable-tool gate satisfied via #1236 approval); reasons=[]
ACTIVATED Observe->Shadow: mode=shadow shadow_window_stamped=true distribution_active=true
            canary=off production=off live_exec_ready=false
A first request echo: execution_state=shadow_evaluated executed=false
            shadow_outcome=would_execute mode=shadow mat_ready=not_evaluated resp_insp=not_evaluated
A metrics: evaluations 0->1 would_execute 0->1 evaluation_errors=0
ZERO side effects: controlled_upstream_invocations=0 upstream_call_count=0
            materialize_count=0 live_executions=0 evaluation_errors=0
durable v2 evidence: schema_version=2 execution_state=shadow_evaluated outcome=would_execute
            override=false credential_plan=no_credential_profile
            mat_ready=not_evaluated resp_insp=not_evaluated digest_ok=true parity=response==durable
B danger request: execution_state=shadow_evaluated executed=false shadow_outcome=would_block
            shadow_override=true would_block 0->1 durable_outcome=would_block
out-of-scope containment: principal=outsider-principal execution_state=not_implemented
            shadow_evaluations UNCHANGED 2 (behaves as Observe)
kill drill: emergency engaged -> error=rollout_emergency_active evaluation_errors 0->1
            not_would_execute no_shadow_eval upstream=0 -> kill cleared
revocation drill: approval revoked -> eligibility!=Usable
            -> echo shadow_outcome=would_fail_hard_control would_fail_hard_control 0->1
            durable_outcome=would_fail_hard_control
rollback Shadow->Observe: mode=observe post_rollback_execution_state=not_implemented
            shadow_evaluations UNCHANGED live_executor=absent canary=off production=off
operator observability: /metrics culvert_mcp_shadow_* rows parsed 1:1 == live singleton
            (evaluations=3 would_execute=1 would_block=1 would_fail_hard_control=1 other=0
            evaluation_errors=1); status.evaluator_composed=true
            status.live_execution_ready=false status.metrics==singleton
FINAL: controlled_upstream_invocations=0 shadow_evaluations=3 would_execute=1 would_block=1
            evaluation_errors=1 live_executions=0 materializations=0
```

### Outcome matrix exercised
- **A — WOULD_EXECUTE**: in-scope `echo`, policy ALLOW, Usable → `would_execute`,
  `executed=false`, upstream=0. ✔
- **B — WOULD_BLOCK**: in-scope `danger`, default DENY, Usable → `would_block`,
  `shadow_override=true` (a restrictive policy is never laundered into would_execute). ✔
- **Out-of-scope containment**: `outsider-principal` → `not_implemented` (Observe),
  shadow evaluations UNCHANGED — the out-of-scope subject never enters Shadow. ✔
- **Kill switch**: emergency disable → request not `would_execute`, not `shadow_evaluated`,
  upstream=0; then cleared. ✔
- **Revocation (withdrawal drill, equivalent of the fingerprint rug-pull)**: revoke the
  `echo` ToolApproval → reconcile demotes it below Usable → the same in-scope `echo` call now
  predicts `would_fail_hard_control` (the quarantine hard-override), no longer `would_execute`.
  The withdrawn trust takes effect immediately; no automatic restoration. ✔
- **Rollback Shadow→Observe**: signed `mode=observe` envelope → mode returns to Observe; a
  subsequent in-scope call is `not_implemented` (Observe), shadow evaluations UNCHANGED,
  live executor absent. ✔

### Note on `evaluation_errors=1`
This single increment is the deliberate emergency-kill fail-closed block (the shadow sink's
`ObserveBlock` counts a kill/durability/invalid-mode block as an evaluation error, NOT a
`would_block`). It is correct accounting for the kill drill — not a durability gap or evidence
loss. Durable-commit failures would also appear here; none occurred.

## 7. Runtime results — `TestControlledShadowRestartDrill` (PASS)

```
restart boot#1: Shadow ACTIVE, echo Usable, committed schema-v2 event id=<evt-id> under durable dataDir
[ clean shutdown; in-memory singletons dropped; fresh rollout+distribution ]
restart boot#2: Shadow RESTORED (mode=shadow) approval_store_recovered=true
            echo_reDerived=Usable evidence_record_recovered(id=<evt-id>)=true live_executor=absent upstream=0
restart post-request: execution_state=shadow_evaluated executed=false
            shadow_outcome=would_execute upstream_invocations=0
```

Boot #1 activates Shadow AND commits one identifiable schema-v2 shadow event (capturing its
event id) before shutdown. Across a clean restart against the same durable dataDir: Shadow
mode restored (via the real restore-clamp + activation preflight), the ToolApproval store
recovered and re-derived `echo` to Usable, **the exact same committed schema-v2 evidence
record was read back from the recovered spool by its event id**, the LiveExecutor stayed
absent, and no side effect occurred during startup/reconciliation. A fresh in-scope request
is still `shadow_evaluated` / `executed=false` / upstream=0.

## 8. Drills NOT performed at runtime (honest accounting)

- **Fingerprint rug-pull (F1→F2, step 13-E)**: NOT re-run as a live catalog re-ingest. The
  equivalent runtime withdrawal was proven via the **revocation drill** (tool loses Usable →
  `would_fail_hard_control`, fail-closed, no auto-restore). The exact-fingerprint binding /
  F1→F2 invalidation is exhaustively covered by PR #1236's tool-trust tests
  (`mcp_tooltrust_test.go`).
- **Wall-clock expiry (step 16)**: NOT exercised as a real time-elapsed run. The short-TTL
  expiry → loss-of-usability path is covered by #1236's clock-injected tests; the runbook
  itself marks runtime wall-clock expiry optional when revocation is proven (it is, above).

## 9. Safety invariants — structural + runtime

- Live-execution tier never armed (`markGatewayExecDepsReady` uncalled): pinned by the
  execution-posture wall (`TestExecPosture_*`, all green) AND observed at runtime
  (`live_execution_ready=false` throughout).
- No LiveExecutor / UpstreamCaller / materialize broker composed: structural (Layer B type) +
  runtime (`upstream=0`, `materialize=0`, `live_executions=0`).
- Durable evidence is truthful and matches the response (parity), digest verifies, schema v2,
  `materialization_readiness`/`response_inspection` = `not_evaluated`.
- Scope did not expand; out-of-scope subject never entered Shadow.
- No product code was modified. The only file added is a package-main `_test.go` harness
  (the experiment instrument); one harness-only ordering fix was made to the restart drill
  (resetting the in-memory policy holder to simulate a fresh process) — no product behavior
  was touched, and the existing MCP suite (shadow/tooltrust/preflight/runbook/posture/policy-e2e)
  stays green.

## 10. Pass criteria (§22)

```
Shadow explicitly activated                        YES
Activation scope bounded                           YES
Exact fingerprint approval active                  YES
Real Shadow evaluations observed                   YES (3)
Shadow reflected on operator /metrics + status     YES (rows parsed 1:1 == live counters)
Schema-v2 durable evidence observed                YES
Response <-> durable evidence parity               YES
Upstream calls caused by Shadow                    0
Credential Materializations caused by Shadow       0
Live executions                                    0
Out-of-scope Shadow evaluations                    0
Unexpected scope expansion                         0
Evidence gaps                                      0
Canary enabled                                     NO
Production enabled                                 NO
LiveExecutor composed                              NO
Shadow -> Observe rollback                         PASS
Restart survival + durable recovery                PASS
```

## 11. VERDICT

**FIRST CONTROLLED SHADOW RUN PASSED** — scoped to a real-runtime, in-process, single-node
controlled experiment over the production code paths (see §2). Every mandatory safety
invariant was observed at runtime: Culvert ingested real authenticated MCP requests,
evaluated them through the full security pipeline, produced correct ShadowDecisions,
committed truthful schema-v2 durable evidence matching the responses, reflected Shadow on
the operator-facing surfaces — the `/metrics` `culvert_mcp_shadow_*` serialization and the
status map, both asserted equal to the live evaluation counters (not merely the internal
metrics singleton) — contained scope, performed ZERO upstream side effects and ZERO credential
materializations, never armed live execution, and rolled back Shadow→Observe deterministically
(and survived a restart). The protected upstream observed 0 invocations while Culvert recorded
3 Shadow evaluations — the central differential.

