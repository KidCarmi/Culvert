# MCP First Controlled Canary — Review (GO / NO-GO / BLOCKED)

**Purpose.** This document is the final review phase before Culvert is allowed to cause its
*first real MCP upstream side effect*. Its only job is to determine whether ONE exact, tightly
bounded First Controlled Canary experiment is safe and fully specified enough to authorize
separately. **This review does not perform the Canary experiment.** It activates no Canary,
performs no `Upstream.Call`, retrieves no production credential, uses no customer traffic, no
production MCP server, and arms no production node.

**Baseline reviewed.** `c20c17b45796e6e11fc3a2518ac48f19882f3f1c` (origin/main; merge of PR
#1291, "Production Live Dependency Composition & Arming Preflight"). Branch:
`claude/mcp-first-canary-review`.

**Verdict (see §26): `BLOCKED — NO SAFE FIRST CANARY TARGET`.** The Canary machinery is sound
and fail-closed on every axis reviewed, but there is no controlled upstream MCP server reachable
under the *supported production trust model available today*, and the production activation
preflight cannot return `Ready:true` on a stock node. Both are recorded, intentional, fail-closed
pre-Canary gaps — not safety defects and not something to "fix" inside this review. The experiment
is specified below up to the exact point where it becomes unauthorizable, and the precise
provisioning that would unblock it is named.

---

## §1 Baseline and re-derivation

All surfaces were re-inspected at the baseline SHA (not from stale assumptions). Sources of record:
`mcp_canary_preflight.go`, `internal/mcp/canary/*` (`readiness.go`, `scope.go`, `trust.go`,
`approval.go`, `budget.go`, `budget_enforce.go`, `abort.go`, `abort_control.go`, `operation.go`),
`mcp_live_tier.go`, `mcp_live_arming.go`, `mcp_live_startup.go`, `mcp_live_production_deps.go`,
`mcp_live_gate.go`, `internal/mcp/execution/run.go`, `internal/mcp/upstreamclient/transport.go`,
`internal/mcp/inspection/destination/{canon,policy}.go`, `internal/mcp/registry/record.go`,
`mcp_inventory.go`, `internal/mcp/tooltrust/*`, `internal/mcp/events/*`.

Confirmed current posture: **`Live tier COMPOSED != ARMED != Canary ACTIVE`** (`mcp_live_tier.go:22`).
A stock build composes nothing, arms nothing, begins no Canary generation, reserves no execution.
Production dependency composition exists but is opt-in behind `CULVERT_MCP_LIVE_DEPS` (default OFF),
and arming is a separate governed act (`armLiveTier`).

**Connectivity re-derivation (verdict-critical).** The registry stores an endpoint and pinned
identity as OPAQUE tokens — `registry.validateEndpoint` (`internal/mcp/registry/record.go:161`)
is a canonical-token check (non-empty, byte-bounded, no control/whitespace); it does NOT parse a
URL and does NOT require the `mcp+https://` scheme. At execution the endpoint reaches
`destination.Canonicalize(target.Endpoint, DefaultGatewayPolicy, …)`
(`internal/mcp/upstreamclient/transport.go:59`) VERBATIM, and `DefaultGatewayPolicy` allowlists
only literal `https` (`internal/mcp/inspection/destination/policy.go:92`). The authoritative
private/loopback/metadata (SSRF) rejection happens at `destination.Resolve`
(`transport.go:81`) under the same client-wide policy, whose `AllowPrivate` is documented as
having **no production caller** — "adding [a per-target private policy] is a design change, not a
flag flip" (`transport.go:67-76`). The pinned-identity trust anchor is the base64 SHA-256 of the
leaf `SubjectPublicKeyInfo` (`spkiVerifier`, `transport.go:242-255`).

Consequence: a controlled server registered with a plain `https://` endpoint, a PUBLIC host, and a
real base64 SHA-256 SPKI pin IS dialable under the supported model. The two gaps documented in PR
#1291 (`mcp+https://` scheme; SPIFFE-format identity) plus a third (private `*.qual.svc` host) are
properties of the only *documented* controlled inventory
(`docs/operator/mcp-qualification-inventory.md`), and each fails CLOSED toward "no connection,"
never toward an unauthenticated one. No public-HTTPS controlled MCP server with an SPKI pin is
provisioned today.

---

## §2 Runbook truth reconciled

`docs/design/mcp/CANARY-FIRST-RUNBOOK.md` and `docs/design/mcp/CANARY-READINESS-MATRIX.md` were
reconciled with current reality (documentation-only; no security semantics changed). The distinct
layers are now stated explicitly: architecture IMPLEMENTED; production deps COMPOSABLE (opt-in,
default OFF); live tier ARMABLE (governed, not a posture-wall edit); armed-by-default NO;
Canary-active NO; and a supported-trust-model controlled upstream NOT AVAILABLE TODAY. The stale
"no production caller composes the tier" claim and the stale "call `markGatewayExecDepsReady`"
precondition were corrected.

---

## §3 The ONE exact experiment (specified up to the blocking point)

The experiment is reduced to *one of everything*, synthetic, recorded, time-boxed, instantly
reversible:

| Dimension | Exact value |
|---|---|
| nodes | **1** controlled Canary node |
| tenants | **1** synthetic / non-production tenant (`OwnerScope`) |
| principals | **1** synthetic principal (canonical session `Sub`), no customer identity |
| MCP servers | **1** controlled server that independently records every received invocation |
| tools | **1** exact tool |
| fingerprints | **1** exact reviewed fingerprint (F2); rug-pull invalidates the approval |
| operation | **read / discovery only** (Culvert's own classification, never `readOnlyHint`) |
| credential | **none** (`CredentialProfile=""` — see §4) |
| customer data / traffic / prod creds | **none** |
| request count | machine-enforced tiny `canary.Budget` (see §9) |

No percentages, groups, wildcards, or a second of anything (`canary.ValidateScope` enforces this — §10).

---

## §4 Credential: a no-credential tool (`CredentialProfile=none`)

Verified in `internal/mcp/execution/run.go:128-146`: the credential profile is a policy
*obligation* (`Obligations.CredentialProfile`), not an automatic per-tool attachment. For a tool
whose matched rule attaches no credential profile, `profileRef == ""`, so `useBroker=false` and the
executor takes `callUpstream("")` — the broker's `Plan`/`Materialize` are never called, and no
`Authorization` header is set (`transport.go:108-110`). Provider *absence* therefore does NOT block
a no-credential tool: providers are consulted only inside `Broker.Materialize`, which this path
never reaches. (A credential-REQUIRING tool with no broker fails closed with
`ReasonCredentialProfileMissing` at `run.go:135`; with the zero-provider production broker it fails
closed inside `Broker.Plan`.) **No credential Provider is implemented in this review.** If the
chosen tool required any credential, the verdict would be NO-GO on this axis; the specified tool
requires none.

---

## §5 A safe controlled upstream — **THE BLOCKING SECTION**

Requirements (from the review contract): a non-production MCP server, HTTPS, cert valid under the
production trust model available today, independently observable, no production access, that
independently records every invocation.

**Finding: no such server is available today.** The only documented controlled inventory
(`docs/operator/mcp-qualification-inventory.md`) is unreachable under the production trust model on
three independent, fail-closed axes:

1. **Scheme.** Endpoints use `mcp+https://`. `DefaultGatewayPolicy` allows only literal `https`, so
   `destination.Canonicalize` returns `ClassBlockedScheme` and the client refuses with
   `ReasonUpstreamEndpointInvalid` (`transport.go:77-78`).
2. **Host.** Hosts are `*.qual.svc` (cluster-internal / private). `destination.Resolve` rejects
   private/loopback/metadata destinations under the production policy; `AllowPrivate` is
   test/env-scoped with **no production caller** and enabling it is a design change (`transport.go:67-76`).
3. **Identity.** Pinned identities are SPIFFE-format. The default verifier compares a base64 SHA-256
   SPKI digest, so a SPIFFE string is read as a digest and fails closed (`mcp_live_production_deps.go:288-291`).

A controlled server *could* satisfy the model if provisioned as: plain `https://` endpoint + PUBLIC
host (publicly resolvable, not private) + valid leaf whose base64 SHA-256 SPKI is the registered
pin + exactly one harmless read tool + an independent invocation log + no production access. **None
is provisioned.** Per the review contract, "if the only available server requires unsupported pin
provisioning or private/internal trust semantics, verdict is NO-GO" — which the documented
inventory does on all three axes. This is the primary blocker.

---

## §6 A harmless, deterministic tool

The tool must be read-only, no mutation, no outbound side effect, no write-on-read, deterministic.
Culvert must classify it as `OpRead`/`OpDiscovery` — **never** relying on MCP `readOnlyHint`.
Verified: `internal/mcp/runtime/policy.go:270-291` derives `OperationClass` from the JSON-RPC method
(`tools/list → OpDiscovery`; `tools/call → OpWrite` conservatively — destructive never assumed).
`readOnlyHint` is not consumed anywhere in the security path (only referenced in tests/comments
asserting it is NOT used). Read-first is enforced twice: the scope fact `ScopeReadFirst`
(`scope.go:274`, necessary-but-not-sufficient) and the request-time boundary gate
`canary.IsReadFirstOperation` (`operation.go:25-33`) wired at `mcp_live_gate.go:96-100`. A `tools/call`
defaulting to `OpWrite` is refused read-first at the boundary. For a First Canary this constrains
the harmless operation to a discovery-class method (or a tool a finer classifier proves `OpRead`);
that is a further constraint on §5's yet-to-exist server, not an independent blocker.

---

## §7 Real inventory / exact fingerprint

Fingerprints must come from normal registry/catalog discovery
(`seedServer`/`seedTools`/`VerifyIdentity`/`Ingest`), never hand-authored. The reviewed fingerprint
(F2, `FingerprintFormatVersion`+32-byte digest) is what the live approval and scope must both name;
`tooltrust` re-verifies exact current state at approve time and the boundary re-checks tool freshness
(`ToolStillCurrent`, `run.go:201`). This is specifiable but presupposes the §5 server exists to be
discovered against; it does not exist today.

---

## §8 Shadow trust and live trust are separate (verified)

- A `shadow_evaluation` approval alone ⇒ Canary preflight FAILs `live_execution_approval_invalid`.
  `ValidateScopeApprovals → SatisfiesLiveExecution` rejects a non-live purpose first
  (`canary/trust.go:74-77`); pinned by `mcp_canary_preflight_test.go` (`shadow_approval` flip).
- Issuing a `live_execution` approval does NOT activate Canary. `ApproveLive` performs no catalog
  promotion (`mcp_tooltrust.go:449-450`); `productionCanaryActivationInputs` wires only
  `ToolApprovals` as a pure read and leaves `Budget`/`ServerUsable`/`FingerprintCurrent` fail-closed
  (`mcp_canary_preflight.go:246-257`); node fact `LiveExecutorComposed` stays false. Pinned by
  `TestLiveTrust_NoActivationCoupling`. The shadow `Usable` projection
  (`ActiveApprovals→activeAsOf→PermitsShadowEvaluation`) and the live read
  (`ActiveLiveApprovals→activeLiveAsOf→PermitsLiveExecution`) share no code path.

This axis is GO.

---

## §9 A tiny budget

`canary.Budget` with `MaxTotalExecutions` in [3,10], `MaxConcurrentExecutions=1`, a minutes-scale
`Window`, and per-dimension caps consistent with the scope (`MaxTools=1`, `MaxServers=1`,
`MaxPrincipals=1`). `ValidateBudget` (`budget.go:64`) rejects any non-positive cap and enforces
`FirstCanaryMaxTotalCeiling=1000` / `FirstCanaryMaxWindowCeiling=7d`. Runtime enforcement
(`BudgetEnforcer.Reserve`, `budget_enforce.go:177`) is atomic, generation-bound, monotonic
(`total` never rolled back), persist-before-grant, and restart-safe: **exactly N grants, N+1
impossible** (`e.total >= MaxTotalExecutions → BudgetDeniedTotal`). Specifiable and GO in isolation;
but no *authoritative* budget input path feeds `productionCanaryActivationInputs`, so the
`BudgetConfigured` activation fact stays false in production today (contributes to §13).

---

## §10 Exact tight scope; near-miss stays outside

`canary.ValidateScope` (`scope.go:62`) forbids percentages (`ScopeUsesPercentage`), wildcards
(empty/fingerprint-less tools, non-enumerable scopes), groups (`ScopeUsesGroups` — membership can
change without a scope edit), empty tenants, and unbounded identity; it requires ≥1 exact server,
≥1 exact tool with a fingerprint, a concrete tenant, and a named principal, all within the
First-Canary bounds (`MaxCanaryServers=1`, `MaxCanaryTools=2`, `MaxCanaryPrincipals=2`,
`MaxCanaryTenants=1`) and read-first operations. Every near-miss (a second server/tool/tenant, a
percentage, a group, a wildcard tool, a different fingerprint/format, a control op) is rejected by a
distinct sub-reason. Specifiable and GO in isolation.

---

## §11 Full node preflight with real authorities

`evaluateCanaryNodeReadiness` / `evaluateCanaryActivationPreflight` read AUTHORITATIVE node state
only (`canaryNodeFactsWith`, `mcp_canary_preflight.go:64`) — no request-supplied fact can set an
activation fact, and no fact is manually forced true. On a stock node the node preflight reports
`live_executor_absent` (and, until arming, the four sibling live-plane facts) because
`liveExecDepsConfigured` is false. The arming node preflight `evaluateLiveArmReadiness`
(`mcp_live_arming.go:44`) checks node prerequisites (durable events, inspection, registry, catalog,
policy healthy; kill clear; shadow-exit attested; rollback path + coordinator rehearsal) and is
fail-closed/deterministic. Correct and GO as a mechanism.

---

## §12 Arming review — arm != Canary activation, and no node left armed

Sequence verified: `composeProductionGatewayLiveTier` (opt-in) → `evaluateLiveArmReadiness` PASS →
explicit `armLiveTier` (the sole caller of `markGatewayExecDepsReady`). Arming leaves the rollout
mode untouched, begins no Canary generation, reaches no upstream (`mcp_live_arming.go:83-91`), and
`quiesceLiveTier` is its inverse. **This review arms nothing** and leaves no real node armed:
arming is exercised only in existing test seams, never against production deps here. Correct and GO
as a mechanism; not exercised live.

---

## §13 Full activation preflight — cannot reach `Ready:true` today (STOP, no bypass)

The review requires `evaluateCanaryActivationPreflight` to return `Ready:true, Unmet:[]`. On a stock
production node this is unreachable, by design and fail-closed:

- Node facts: `live_executor_absent` (+ `upstream_caller_absent`, `credential_path_not_ready`,
  `kill_boundary_guard_absent`, `tool_freshness_guard_absent`) until the live tier is armed.
- Activation facts: `productionCanaryActivationInputs` deliberately leaves `ServerUsable`,
  `ToolFingerprintCurrent`, and `Budget` fail-closed (`mcp_canary_preflight.go:246-257`), so
  `server_not_usable`, `tool_fingerprint_stale`, and `canary_budget_not_configured` cannot clear
  in production today.

Per the contract, "if a prerequisite is missing: STOP, don't bypass." The review STOPS here without
bypassing. This is a second, independent reason the experiment is not authorizable today, on top of
§5.

---

## §14 Independent upstream witness

Reconciliation plan: Culvert's executed count (`ExecOutput.Executed`, set only on real execution,
`run.go`) MUST equal the controlled server's independently-recorded received count MUST equal the
expected count. Any mismatch is a whole-Canary breach (`outcome_evidence_loss` /
`unexpected_upstream_response`) → auto-stop. The witness is the §5 server's own invocation log,
which does not exist today; the reconciliation procedure is specified for when it does.

---

## §15 Evidence plan (no secrets)

Per attempted request, the durable event carries: correlation ID + digest (`events/decide.go`),
action + reason code + matched rule ID + policy revision + operation class + execution state +
`PolicySnapshotHash`, identity (tenant/principal/type/client/server/tool + tool fingerprint), the
live approval binding, the budget reservation outcome, the upstream outcome + response-inspection
result, `Executed` bool, and the final reason. **No secrets, no `Authorization`, no credential
material**: `DecisionFacts` is a typed-facts-only API (a secret cannot reach it by construction),
`backstopScan` marshals and scrubs every event and rejects on any secret pattern
(`ReasonEventSecretPresent`), and credential evidence is a digest only (`events/gate.go:52`). GO as
a mechanism.

---

## §16 Abort plan

Whole-Canary breaches (a single occurrence stops the Canary): `out_of_scope_execution`,
`scope_escape`, `tool_fingerprint_drift`, `server_identity_drift`, `outcome_evidence_loss`,
`credential_safety_failure`, `budget_exhausted`, `elevated_error_rate`, `latency_pathology`,
`unexpected_upstream_response` (`abort.go:54-86`). The controller latches monotonically and
generation-bound; an unknown code fails closed to `AbortCanary` (`abort_control.go:35-40`).
`budget_exhausted`/`scope_escape` are tripped from the reservation path (`mcp_canary_runtime.go:388-395`).
**Applicability note (not fabricated):** the two THRESHOLD-based conditions — `elevated_error_rate`
and `latency_pathology` — are present in the taxonomy but their runtime threshold wiring to an
automatic tripper is not established in this build the way `budget_exhausted`/`scope_escape` are;
they would rely on operator/observer-driven trips today. This is recorded as an applicability gap
for the eventual experiment, not fabricated as an automatic control. The scope/budget/drift/kill
controls ARE automatic.

---

## §17 Manual emergency controls

Available and admin-gated: emergency kill engage/clear (`POST /api/mcp/rollout/emergency`,
`emergencyDisable`/`clearEmergency`, monotonic `killGen`, narrows only), quiesce
(`quiesceLiveTier` → un-arm first, close admission, bounded drain), and Canary→Shadow/Observe
demotion (`demoteCanary`). A GO decision is forbidden unless rollback and kill are currently
available; they are, as mechanisms. (They cannot be *exercised against a live Canary* today because
none can be activated.)

---

## §18 Crash / restart

Verified fail-closed: on restart the rollout restore re-runs the FULL activation preflight from
authoritative state and clamps any live mode to Disabled on failure (`mcp_rollout.go:550-614`); the
canary runtime disarms on build-version or generation mismatch (`mcp_canary_runtime.go:527-586`);
`reconcileCanaryRuntimeAfterRestore` disarms an armed runtime with no live mode; the live tier
forces composed/unarmed (`disarmForRestart`). The monotonic generation and monotonic budget `total`
are preserved, so an old generation/budget cannot become fresh allowance, and a pre-crash upstream
invocation is determinable from the durable decision/outcome events (§15). GO as a mechanism.

---

## §19 Pre-experiment negative controls

For when the experiment is eventually authorized, the required "no execution" negative controls map
to existing gates: wrong principal / wrong tool / wrong F2 fingerprint → scope or approval
mismatch (`ValidateScopeApprovals`, `SatisfiesLiveExecution`, `preCallGuard` freshness); revoked /
expired approval → terminal status / expiry; `OpControl`/write → read-first boundary refusal;
budget-exhausted → `BudgetDeniedTotal`; kill-active → `preCallGuard` kill re-read; evidence-degraded
→ commit failure blocks the side effect; quiescing → admission closed. All fail closed. These are
specified as the pre-flight negative-control suite; they are not run live in this review.

---

## §20 Last red-team (against the exact experiment)

Attacks considered and where each is stopped:

- *Register the controlled server under `mcp+https://` to match the docs* → refused at
  `Canonicalize` (blocked scheme). No downgrade, no insecure dial.
- *Point at a private/internal controlled host* → refused at `Resolve` (SSRF); `AllowPrivate` has no
  production caller.
- *Pin a SPIFFE identity* → read as SPKI digest, verify fails closed.
- *Approve a shadow grant and ride it into live* → `SatisfiesLiveExecution` rejects non-live purpose.
- *Widen scope via a group or percentage* → `ValidateScope` rejects.
- *Smuggle a longer approval TTL by sitting pending* → TTL measured from `ApprovedAt`, ceiling ≤24h.
- *Rug-pull the tool after approval* → `MatchesTool` exact-fingerprint + boundary `ToolStillCurrent`.
- *Force an activation fact true via a signed config* → activation facts are node-authoritative, not
  request-supplied.
- *Reach `Upstream.Call` past an emergency kill* → final monotonic kill-generation re-read is the
  last check (`preCallGuard`), paramount over drift/demotion.
- *Get a no-credential call to leak a header* → `callUpstream("")` sets no `Authorization`.

No "probably safe" path was left open. Every concern maps to an existing gate. **The one concern
that does NOT resolve to a gate is the absence of a supported-trust-model controlled target (§5) and
the unreachable activation preflight (§13)** — these become the blockers, not residual risks.

---

## §21 No code changes during the eventual experiment

No product code is changed by this review (documentation-only; see §23). The connectivity gap is a
documented, intentional, fail-closed pre-Canary capability gap, explicitly "NOT a defect"
(`mcp_live_production_deps.go:293-309`), so §21's "if a product defect is found, stop and fix in a
dedicated PR" is not triggered. If the eventual experiment reveals a defect, it must be fixed in a
dedicated PR, Codex-reviewed and merged, and this review re-run against the new exact SHA — no
hot-fixing during a live experiment.

---

## §22 This artifact

This document is the review artifact required by the contract.

---

## §23 Change discipline

This review changes only documentation (this file plus the §2 reconciliation of
`CANARY-FIRST-RUNBOOK.md` and `CANARY-READINESS-MATRIX.md`). No product code and no security
semantics were changed. Because the verdict is BLOCKED (not PASS), no implementation PR is opened.

---

## §24 Adversarial review

The re-derivation and this artifact were stress-tested for any path by which the exact experiment
could cause more, different, or less-observable side effects than claimed (§20). The dominant
adversarial finding is that the *only documented* controlled target is unreachable fail-closed on
three axes and would tempt an operator toward `AllowPrivate` / a scheme hack / a SPIFFE shim — each
of which is a design change this review forbids. That finding is what fixes the verdict at BLOCKED
rather than GO.

---

## §25 Mandatory GO criteria

| Criterion | Status |
|---|---|
| Exactly one node / tenant / principal / server / tool / fingerprint, read-only, synthetic | Specifiable — YES |
| Tool requires no production credential | YES (§4) |
| Supported upstream trust model for a controlled server available today | **NO** (§5) |
| Shadow trust ≠ live trust proven; live approval does not activate Canary | YES (§8) |
| Tight scope validated; every near-miss outside scope | YES (§10) |
| Tiny budget; N allowed / N+1 impossible | YES (§9) |
| Activation preflight returns `Ready:true, Unmet:[]` on a real node | **NO** (§13) |
| Independent upstream witness reconcilable | Depends on §5 server — NOT AVAILABLE |
| Evidence carries no secrets/credentials | YES (§15) |
| Automatic abort + manual kill/rollback currently available | Mechanisms YES; not live-exercisable (§16/§17) |
| Crash/restart does not silently re-arm/resume | YES (§18) |
| Unresolved P0/P1 finding | None found — the blockers are intentional capability gaps, not defects |

Two mandatory criteria are NO. A GO is therefore forbidden.

---

## §26 Final verdict

### `FIRST CONTROLLED CANARY REVIEW: BLOCKED — NO SAFE FIRST CANARY TARGET`

The Canary architecture is sound and fail-closed across preflight, scope, trust firewall, budget,
abort, evidence, kill/rollback, and crash-restart. It is BLOCKED — not FAILED — because two
intentional, fail-closed prerequisites are unmet today:

1. **No controlled upstream is reachable under the supported production trust model (§5).** The only
   documented controlled inventory fails closed on scheme (`mcp+https://`), host (private
   `*.qual.svc`), and identity (SPIFFE). No public-HTTPS controlled MCP server with a base64 SHA-256
   SPKI pin, a plain `https://` endpoint, and one harmless read tool is provisioned.
2. **The production activation preflight cannot return `Ready:true` (§13).** The live tier is unarmed
   by default and `productionCanaryActivationInputs` leaves `ServerUsable`/`ToolFingerprintCurrent`/
   `Budget` fail-closed.

**To unblock (each a separately-reviewed change, none performed here):** provision a public-HTTPS,
non-production, independently-recording controlled MCP server exposing exactly one harmless
read/discovery tool, register it with a plain `https://` endpoint and its real base64 SHA-256 SPKI
pin; OR land the recorded connectivity work (endpoint-scheme translation at the execution boundary
and/or an identity-type-aware verifier) plus a per-target private-destination policy in a dedicated,
Codex-reviewed PR; AND wire an authoritative `ServerUsable`/`FingerprintCurrent`/`Budget` input path
for the activation preflight; AND arm the live tier on the controlled node via the governed path.
Then re-run this review against the new exact SHA.

**This review did not activate Canary, did not execute any tool, did not arm any production node,
retrieved no credential, and used no production server or customer traffic. Real Canary side effects
in this phase: 0.**
