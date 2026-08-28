# Security regression review — Controlled Shadow activation + bounded shutdown window (2026-08-28)

**Scope:** everything merged into `main` after the predecessor artifact, i.e. `e698a12..cc9479f`
— PR #1228, #1230, #1232, #1233, #1229, #1234 (MCP Controlled Shadow activation) and #1235
(durable ShadowDecision evidence, schema v2). 89 files, +8709/−557; 35 non-test Go files,
+2631/−251.
**Branch:** `claude/epic-bardeen-xyru67` · baseline `cc9479f`
**Predecessor:** `2026-08-25-shadow-layerb-and-ldap-window.md`
**Method:** read every non-test file in the window (all 35), then trace each changed control to
its call sites and its downstream re-validation. One hardening was written and
mutation-verified: the fix's gate was proven failing against the pre-fix arm before the fix
landed (§7).

> **Verdict (§9): no security regression in this window.** The MCP changes are net
> **tightenings** — three of them close latent permissive shapes that predate the window (§4).
> One defence-in-depth weakness was found in a fail-closed gate (`modeExecReady`'s catch-all
> `default: return true`), proven **not exploitable today** because every caller re-validates
> the mode downstream, and closed anyway (§5, SRR-01). The shutdown, TLS-boot and file-block
> changes are availability/cost work that preserves every security decision they touch.
>
> **This document does not authorise enabling MCP execution.** Shadow became *activatable*
> in this window; it is still unreachable in a shipped build (§8), and Canary/Production
> remain fail-closed at an untouched gate.

---

## 1. What this window changed, and in which direction

| Area | Change | Direction |
|---|---|---|
| `internal/mcp/rollout` (config) | Shadow now requires an **enumerable** scope, like Canary/Production | **Tightening.** An empty or percentage-only Shadow scope used to validate and silently behave as Observe. "No scope shadows everything" is now structurally impossible *and* rejected at validation. |
| `mcp_rollout_execdeps.go` | `execDepsConfigured` split into `shadowDepsConfigured` / `liveExecDepsConfigured`, selected by `modeExecReady` | **Widening, deliberate + gated.** Shadow no longer requires the live tier. Canary/Production still require `liveExecDepsConfigured`, which nothing in this build arms. |
| `mcp_shadow_preflight.go` (new) | Shadow activation preflight — 10 bounded fail-closed reasons | **Tightening.** Layered *on top of* the tier gate at every activation path (§3). |
| `internal/mcp/rollout/scope.go` | `AdmitsToolForEvaluation` + unsatisfiable-scope detection | **Narrowing-only.** Preflight-side helper; never consulted at request time (`Contains` stays the per-request authority). |
| `internal/mcp/runtime/{execute,policy}.go` | `ExecutionProvider` gains `Resolve` / `KillActive`; the disposition is resolved **once** and carried into `Execute` | **Tightening ×2** (§4.1, §4.2). |
| `internal/mcp/execution/shadow_evaluator.go` | New upstream-server-usability step; `credentialReadiness` / `policyClassOutcome` extracted | **Tightening.** Closes a `WOULD_EXECUTE` prediction for a server live enforcement would refuse. |
| `internal/mcp/execution/allowance.go` | `wouldSatisfy` no longer treats an **expired** session slot as capacity-exempt | **Tightening** (prediction-only path; §4.3). |
| `internal/mcp/events/model` | Additive `SchemaVersionV2` + `ShadowEvidence`; +377 lines of write- and recovery-time validation | **Tightening.** v1 digests byte-identical (§6). |
| `main_shutdown.go`, `runtime_shutdown.go`, `controlplane_server.go` | CHAOS-56: three bounded phases, per-hook watchdog, bounded `GracefulStop` | Neutral-to-positive. Protects the **audit-log flush** with a reserve. |
| `ui_tls_custom.go` | A mismatched persisted UI cert/key pair falls back to self-signed instead of `logFatalf` | Availability over identity; **no new attacker capability** (§5, SRR-02). |
| `internal/fileblock` | Lock-free published view; MIME pre-filter before `mime.ParseMediaType` | Cost-only. Equivalence verified against the stdlib (§4.4). |
| `ha_lease.go` | Self-fence recorded into the failover ring **inside** `h.mu` | Tightening (observability atomicity). Ring mutex verified leaf (`ha_failover_ring.go:62`). |
| `logguard.go` | `diskUsageFn` test seam | Test-only; production default unchanged. |

---

## 2. Threat model applied

Culvert is an inline Secure Web Gateway; the MCP Gateway is an *agent* security gateway
sharing the same process. The assets at stake in this window are: (a) the irreversible
upstream side-effect boundary, (b) credential materialization, (c) the durable evidence
archive's integrity, (d) the audit log's durability across shutdown, (e) the admin-UI TLS
identity, and (f) the response-content file-block control. The adversaries considered are an
unauthenticated MCP client reaching the Gateway listener, a malicious or compromised upstream
MCP server, a compromised/limited CP publishing a signed rollout envelope, an operator error,
and a local attacker with `dataDir` write access.

---

## 3. Verified explicitly: Shadow cannot be activated by a path that skips the preflight

Every path that can install `ModeShadow` was enumerated and traced:

| Path | Gate | File |
|---|---|---|
| CP→DP signed envelope | `modeExecReady` **then** `evaluateShadowActivationPreflight` before `Apply` — rejects with **no `AckApplied`** | `mcp_distribution.go:270,281` |
| Shared durable commit (used by the CP→DP apply *and* startup reconciliation) | `modeExecReady` then the same preflight, before `SetConfig` | `mcp_rollout.go:189,203` |
| Restart restore | `modeExecReady` clamp, then `shadowPreflightUnreadyIgnoringKill` clamp to Disabled | `mcp_rollout.go:275,292` |
| Admin API transition | admin RBAC → `ParseMode` (fail-closed) → Production forbidden → `modeExecReady` → terminal `409 distribution_not_configured` (no transition is possible from this surface at all) | `ui_mcp_rollout.go:88,99,105` |

`grep` confirms there is no fifth caller of `commitRolloutTransitionAt` or `SetConfig` on the
rollout state outside these. **Ordering was verified, not assumed:** `initMCPRuntime`
(`main.go:221`) composes the evaluator and calls `rt.Start()` — which sets `PhaseReady`
synchronously — *before* `initMCPRollout` (`main.go:222`) runs `restore()`, so the preflight's
live-listener probe is meaningful at restore time rather than always-false.

---

## 4. The four changes that required the most scrutiny

### 4.1 The record-only fall-through is a tightening, not a bypass

`dispatchPolicy` used to hand **every** request to the executor whenever one was wired. It now
routes only a **non-record-only** disposition there and keeps the inline decision-only path for
record-only. The obvious regression question is whether the inline path is weaker than
`Executor.recordOnly`. It is strictly stronger:

- `recordOnly` (`executor.go:177`) returns a **200 `observe` result for a DENY action** and
  performs **no durable commit**. With an executor composed in Observe mode, a policy denial
  was therefore answered with an observe envelope and the canonical decision event was never
  written.
- The inline path enforces the `ALLOW_WITH_REDACTION` real-transform requirement, performs the
  **commit-before-response** durable decision commit (failing closed when it cannot commit),
  and routes every non-allow-class action into the typed JSON-RPC denial + the isolated denial
  lane.

`EffectRecordOnly` is produced only by Disabled/Observe and by an out-of-scope
Shadow/Canary/Production subject (`resolve.go:123,141,171`), none of which perform an upstream
call — so no enforcement is skipped by the reroute. The one thing record-only no longer runs is
`refuseOnToolDrift`, which is now inside `dispatchExecute`; that is evidence fidelity, not
enforcement, on a path with no side effect, and it restores the pre-PR-11 (no-executor)
baseline exactly.

### 4.2 Single resolution closes a routing TOCTOU without opening a kill-switch gap

Routing and execution previously resolved the mutable rollout state twice. They now resolve
once (`Resolve`) and carry the resolution into `Execute`. The only state re-read afterwards is
the emergency kill — monotonic, and it can only make the outcome *more* restrictive — and the
new `KillActive()` re-check extends the emergency admission stop to the inline Observe path,
which previously had none. Both directions verified: `resolveDisposition` returns
`EffectBlock`/`ReasonRolloutEmergencyActive` for a killed capability, so a killed request is
never routed to the inline path in the first place.

### 4.3 `wouldSatisfy` — prediction-only, and it got stricter

`slotSurvivesSweep` now excludes an **expired** session slot, matching `consume`'s
sweep-then-capacity-check order. `wouldSatisfy` is called from exactly one place
(`shadow_evaluator.go:277`) and never mutates, so this cannot affect live enforcement; it
removes a prediction that was *more permissive than the enforcement it exists to predict*.

### 4.4 The file-block MIME pre-filter is exactly equivalent

`CheckContentType` now short-circuits on `mediaTypeOf(contentType)` before calling
`mime.ParseMediaType`. Checked against the Go 1.26.6 toolchain source
(`$GOROOT/src/mime/mediatype.go`): `ParseMediaType` computes
`mediatype = strings.TrimSpace(strings.ToLower(base))` over `base, _, _ := strings.Cut(v, ";")`
and returns either that exact value or `("", nil, err)`. So `mediaTypeOf(v) ∉ blockedMIMETypes`
⇒ the pre-fix body returned `""` for every input, malformed ones included. The pre-filter is a
pure **negative** filter: every *block* still goes through the unchanged parse. The lock-free
view was audited for the republish contract — all five writers of `fb.extensions`
(`SetPath`/`Add`/`ReplaceAll`/`Remove`/`ClearAll`) call `publishLocked()` under the write lock,
and `SetPath`'s three early-return paths do not mutate the map, so no path leaves a stale view.

---

## 5. Findings

### SRR-01 — `modeExecReady` admitted an unrecognised rollout mode by default *(FIXED in this PR)*

- **Severity:** Low (defence-in-depth). **CWE-1188** (insecure default) / **CWE-636** (failure
  to fail securely). **OWASP A05:2021 — Security Misconfiguration.** **Exploitability:** none
  today. **Regression risk of the fix:** none — behaviour is identical for all five real modes.
- **What:** `modeExecReady` is the single gate deciding whether a rollout mode's required
  execution-readiness tier is composed. Its final arm was a bare `default: return true`, so any
  `rollout.Mode` value that was neither Canary/Production nor Shadow — **including a value
  outside the five-token taxonomy** — was admitted without proving any tier. Its own doc
  comment claimed the opposite ("only admitted if it is Disabled/Observe"), so the code and its
  stated contract disagreed in the permissive direction.
- **Attack scenario / preconditions:** an unknown mode would have to reach the gate and then
  survive downstream. It cannot: the commit path calls `SetConfig` → `SignedConfig.Validate`,
  which rejects `!Mode.Valid()` with `ReasonRolloutModeInvalid`; the admin surface parses
  through the fail-closed `ParseMode`; the restore clamp only ever sees an already-validated
  restored mode; and at request time `rollout.Resolve`'s own `default` arm emits
  `EffectBlock`/`ReasonRolloutModeInvalid`. **No exploitable path exists in this tree.**
- **Impact if it were reachable:** a mode value would bypass the readiness precondition that is
  the sole thing keeping Canary/Production fail-closed in a build that composes no live
  executor. Affected assets: the irreversible upstream side-effect boundary and credential
  materialization.
- **Likelihood:** the realistic trigger is not an attacker but a future `rollout.Mode` added
  without classifying it here — it would be **silently admitted** rather than failing closed.
- **Fix (applied):** enumerate the admitted modes; `default` now returns `false`.
  `mcp_rollout_execdeps.go:105`.
- **Tests (added):** `TestReadinessSplit_UnknownModeFailsClosed` (negative + boundary:
  **every** unrecognised value of the `uint8` domain, with nothing armed *and* with every tier
  armed, both capabilities) and `TestReadinessSplit_EveryValidModeIsExplicitlyClassified`
  (positive/completeness: every valid mode reaches a named arm).
  **Both loops are driven from the authoritative taxonomy**, not a hand-copied table —
  `validModes`/`invalidModes` exhaust the `uint8` domain against `rollout.Mode.Valid()`, which
  answers from the rollout package's own `modeToken` registry. That is what makes the
  completeness gate a real build-time signal rather than a self-fulfilling loop: a sixth mode
  added to `modeToken` but omitted from `modeExecReady` would otherwise have kept the test
  green (Codex P2 on PR #1240 — the finding was correct and is closed here).
- **Mutation-verified, both directions:**
  - restoring `default: return true` → `TestReadinessSplit_UnknownModeFailsClosed` fails
    (`SECURITY: unrecognised rollout mode 5 must fail closed`);
  - adding `Mode(5): "experimental"` to `rollout.modeToken` without classifying it →
    `TestReadinessSplit_EveryValidModeIsExplicitlyClassified` fails
    (`rollout mode "experimental" is in the taxonomy but this test does not classify it`).

### SRR-02 — UI-TLS fallback trades a boot DoS for a visible identity downgrade *(accepted, no change)*

- **Severity:** Informational. **CWE-757** (negotiation of weaker algorithm/identity).
- `resolveUITLSCertKey` now ignores a persisted custom admin-UI cert/key pair that does not
  `tls.LoadX509KeyPair`, and falls back to the auto self-signed certificate rather than
  `logFatalf`-ing the process.
- **Analysed as a downgrade:** an attacker who can mismatch the pair (write access to
  `dataDir`) can force the admin UI onto a self-signed certificate and then rely on an operator
  clicking through the browser warning. But that same attacker can already **replace both
  files with their own pair**, which is strictly stronger and produces *no* warning. So the
  change grants no new capability, and the previous behaviour was an unrecoverable boot loop
  from an interrupted upload (two separate atomic writes). The fallback is loud (a startup line
  naming the cause) and honest on the admin API (`uiCustomTLSActive` stays false).
- **Residual:** the degraded state is only reported as "not using the custom cert"; there is no
  alert or operator-contract row distinguishing "never uploaded one" from "uploaded one that is
  now unusable". Recorded, not fixed — same class as the `alert_webhook_signing` row that
  exists for exactly this distinction on the webhook path.

### SRR-03 — the inline Observe path no longer refuses a drifted decision *(accepted, no change)*

- **Severity:** Informational (evidence fidelity). A record-only request no longer passes
  through `refuseOnToolDrift` (§4.1). No side effect is performed on that path, and the
  behaviour matches the no-executor baseline. Recorded so a future move of enforcement onto the
  Observe path revisits it.

---

## 6. Evidence-integrity review (schema v2)

The v2 envelope was checked specifically for a digest/rollback hazard, since that is the
failure mode the *previous* review deferred this work over:

- `Event.Shadow` is a `*ShadowEvidence` with `json:"shadow,omitempty"`. `CanonicalBytes` does
  `c := e; c.EventDigest = ""; json.Marshal(c)` — a shallow copy, so the pointer is carried and
  the field **is** digest-covered on a v2 event, and **omitted entirely** on every v1 event.
  v1 digests are therefore byte-identical across this change.
- `SupportedSchemaVersion` is applied at all three boundaries that matter: `Validate` (write),
  `spool.replaySegmentRecordsLocked` (recovery), and `validateBatch` (archive export). The
  export change is load-bearing rather than cosmetic — the pump retries an all-or-nothing batch
  without advancing its cursor, so a hardcoded `!= v1` would have wedged a whole partition out
  of the durable archive at the first Shadow event.
- The +377 lines of validation are all **refusals**: enum membership, the two architectural
  `not_evaluated` constants, four biconditionals mirroring `decide()`, Gateway-only + non-denial
  routing, and an Action↔Override binding. `ValidateShadowEvidence` (recovery) is deliberately
  narrower than `Validate` (write) so recovery never "repairs" malformed evidence and never
  newly rejects a pre-existing non-shadow event.
- The model-local action classifier (`action_class.go`) exists because the leaf event model may
  not import `internal/mcp/policy`. Its table was checked by hand against
  `policy.Action.IsAllowClass()` (`action.go:163`) and `policy.AllActions()` (`action.go:173`):
  it agrees on all nine codes. The cross-package parity wall
  (`internal/mcp/execution/shadow_action_class_parity_test.go`) exists and pins both directions.
- No field in `ShadowEvidence` can carry a secret, credential value, tool argument or tenant —
  every one is a bounded enum, and each is additionally length-bounded in `validateFieldBounds`.

---

## 7. Regression analysis

- **Backward compatibility:** v1 events are unchanged on the wire and in digest. The documented
  downgrade posture (a pre-v2 binary refuses a v2 record rather than partially interpreting it)
  is deliberate and has a runbook; it is unreachable in practice because no shipped build can
  produce a v2 event (§8).
- **Feature interaction — the one to watch:** open PR **#1236 (MCP tool-trust approval +
  promotion, ADR-0034)** is what makes `catalog.Usable` reachable, which is the *only* remaining
  reason `shadowScopeHasUsableTool` returns false in production. That PR therefore converts
  Shadow from "activatable in principle" to "activatable in fact" on a node with
  `CULVERT_MCP_SHADOW_READY` set. It must be reviewed as an activation change, not as a catalog
  change.
- **Default posture:** unchanged. With `CULVERT_MCP_SHADOW_READY` unset the evaluator is nil and
  the runtime keeps its byte-identical Observe/SWG path; with MCP unconfigured nothing binds.
- **Fail-closed behaviour:** preserved or strengthened at every gate examined. The one arm that
  was not fail-closed is SRR-01, now closed.
- **Non-MCP surfaces:** the SWG data plane is untouched by this window except for
  `internal/fileblock` (cost-only, equivalence-verified) and the shutdown sequence.

---

## 8. Why Shadow is still unreachable in a shipped build

Four independent conditions must all hold, and one cannot be satisfied today:

1. `CULVERT_MCP_SHADOW_READY` explicitly set (default OFF, fail-safe parse).
2. A composed durable events manager, policy, registry+catalog, request inspection, and a
   **live `PhaseReady`** Gateway listener.
3. A signed CP→DP Shadow envelope carrying an **enumerable** scope.
4. `shadowScopeHasUsableTool` — the scope must target at least one catalog tool whose
   eligibility is `catalog.Usable`. **Catalog ingestion never yields `Usable`**, so this returns
   false in production and the activation fails closed with `no_usable_shadow_tools`.

Canary and Production are gated on `liveExecDepsConfigured`, and `markGatewayExecDepsReady` /
`markManagementExecDepsReady` have **no production caller** — pinned by the execution-posture
wall. Production is additionally refused outright at the admin surface.

---

## 9. Verdict and residual risk

**No security regression was introduced by `e698a12..cc9479f`.** All 35 non-test files were
read. Three latent permissive shapes that predate the window were closed by it (the observe
record-only denial softening, the expired-allowance prediction, and the missing
server-usability prediction step). One defence-in-depth weakness (SRR-01) was found, proven
non-exploitable, and fixed with a mutation-verified gate.

Residual risk carried forward:

- **SRR-02** — no dedicated operator surface distinguishing "no custom admin-UI cert" from
  "custom cert present but unusable".
- **SRR-03** — record-only requests are not drift-refused (no side effect on that path).
- **Shadow evidence downgrade** — a v1 binary refuses a v2 spool record. Documented with a
  runbook; unreachable while §8 holds.
- **#1236 interaction** — the tool-approval slice is the activation prerequisite for Shadow and
  needs its own activation-grade review.
- Everything already recorded in the predecessor artifacts remains open and unchanged by this
  window.

---

## 10. Files

Changed by this review:

- `mcp_rollout_execdeps.go` — SRR-01 fix: `modeExecReady` enumerates the admitted modes and
  fails closed by default.
- `mcp_shadow_readiness_test.go` — `TestReadinessSplit_UnknownModeFailsClosed`,
  `TestReadinessSplit_EveryValidModeIsExplicitlyClassified`.
- `docs/engineering/security-reviews/2026-08-28-shadow-activation-and-shutdown-window.md` —
  this artifact.

Reviewed unchanged (all 35 non-test files in the window): `controlplane_server.go`,
`ha_lease.go`, `internal/fileblock/fileblock.go`, `internal/mcp/adminapi/health.go`,
`internal/mcp/events/decide.go`, `internal/mcp/events/model/{action_class,model,validate}.go`,
`internal/mcp/events/spool/recovery.go`,
`internal/mcp/execution/{allowance,executor,metrics,responses,shadow_evaluator}.go`,
`internal/mcp/rollout/{config,rollout,scope}.go`, `internal/mcp/runtime/{execute,policy}.go`,
`logguard.go`, `main.go`, `main_shutdown.go`, `mcp_distribution.go`, `mcp_observe_health.go`,
`mcp_observe_startup.go`, `mcp_rollout.go`, `mcp_shadow_metrics.go`, `mcp_shadow_preflight.go`,
`mcp_shadow_startup.go`, `mcp_telemetry.go`, `metrics.go`, `runtime_shutdown.go`,
`ui_mcp_rollout.go`, `ui_tls_custom.go`.

## 11. Verification run

```
go build ./...                                                          OK
go vet ./...                                                            OK
go test ./internal/fileblock/... ./internal/mcp/events/... \
        ./internal/mcp/rollout/... ./internal/mcp/execution/... \
        ./internal/mcp/runtime/...                                      all ok
go test -run 'TestMCP|TestShadow|TestReadiness|TestChaos56|TestRollout' .  ok
go test -run 'TestReadinessSplit|TestShadow|TestRollout' -count=2 -shuffle=on .  ok
mutation A: restore `default: return true` in modeExecReady          → FAIL (expected)
mutation B: add Mode(5) to rollout.modeToken, leave it unclassified  → FAIL (expected)
```
