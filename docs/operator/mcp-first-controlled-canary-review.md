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

**Verdict (see §26): `BLOCKED — NO SAFE FIRST CANARY TARGET`.** The Canary CORE is fail-closed on
several axes (scope validation, shadow≠live trust firewall, budget ceiling / N-allowed-N+1-impossible,
per-request kill re-read, restart re-arm/allowance, no-secret evidence). But a safe first experiment
cannot be assembled today on **TEN independent blockers** (exhaustive as a set — together they cover
every mandatory NO/CONDITIONAL row in §25, though the mapping is grouped, not strictly 1:1: the
witness-reconciliation row folds under blocker 7 and also depends on blockers 1 and 6): (1) no controlled upstream reachable under the supported
production trust model; (2) the production activation preflight cannot return `Ready:true` on a stock
node; (3) no governed production arming entry point — `armLiveTier` has no production caller, so an
operator cannot arm the tier; (4) the read-first classifier refuses the one-exact-tool call and
discovery cannot bind one tool; (5) the machine gate does not enforce exactly-one tool/principal
(`MaxCanaryTools`/`MaxCanaryPrincipals` = 2); (6) the budget does not bound physical upstream
invocations (idempotent read retries send the POST up to ~3× per reservation); and — genuine PRODUCT
DEFECTS, not merely capability gaps — (7) whole-Canary auto-abort is unwired for the eight declared
breaches beyond `budget_exhausted`/`scope_escape` (so later requests stay eligible after a breach)
and (8) the durable outcome record is success-only with an unclosable post-send crash window, so a
pre-crash invocation is not always determinable; and (9) the credential path is unresolved — selection
comes from the matched policy rule and the production broker has zero providers, so it must be closed
explicitly by a no-`CredentialProfile` rule or a working provider/path (§4); and (10) no
operator-reachable graceful rollback — §17 requires rollback AND kill, but only the emergency kill is
reachable (quiesce has no caller; `apiMCPRolloutTransition` returns `distribution_not_configured`, §17).
Blockers 1–6, 9, and 10 are gaps/prerequisites; 7–8 are defects recorded here for dedicated PRs (§21).
The experiment is specified below up to the exact point where it becomes unauthorizable, and the
precise provisioning that would unblock it is named.

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
| operation | **read / discovery only** (Culvert's own classification, never `readOnlyHint`) — but NOT executable today: a `tools/call` is `OpWrite` (refused read-first) and `tools/list` binds no exact tool (§6) |
| credential | **UNRESOLVED** — intended none, but `CredentialProfile` is a policy obligation, not a tool property; unverifiable until the exact tool + rule are fixed (§4) |
| customer data / traffic / prod creds | **none** |
| request count | machine-enforced tiny `canary.Budget` (see §9) |

No percentages, groups, or wildcards (`canary.ValidateScope` enforces these — §10). **But
`ValidateScope` does NOT enforce "exactly one" of everything:** `MaxCanaryServers`/`MaxCanaryTenants`
are 1 (so servers/tenants are capped at one), while `MaxCanaryTools` and `MaxCanaryPrincipals` are
**2** — a two-tool or two-principal scope passes the gate. The exact one-tool/one-principal shape is
therefore an EXTERNAL authorization prerequisite (or the activation path must additionally require
exactly one), not a machine-enforced property. This table is the *intended* shape; §4–§6 and §10
record why it is not yet executable, fully resolvable, or fully enforced.

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
closed inside `Broker.Materialize` — the `doFetch` provider lookup returns not-found — NOT in
`Broker.Plan`, which is pure and "consults no provider" (`broker.go:119-120`) and so SUCCEEDS. The
failure therefore lands AFTER `Plan` and after the credential gate has authorized and committed its
evidence, still fail-closed but at a later stage.) **No credential Provider is implemented in this
review.**

**Correction (Codex P2).** `CredentialProfile` is a policy-decision *obligation*
(`policy/obligation.go:80`), not an intrinsic tool property. The no-credential *code path* is proven
safe (empty `profileRef` ⇒ broker skipped ⇒ no `Authorization`). But the experiment does not name a
concrete server/tool AND its matched policy rule (it cannot — no server exists, §5), so the review
CANNOT yet establish that the proposed request selects the empty-profile branch. Credential
readiness is therefore an **additional unresolved prerequisite**, not a settled YES: it is
verifiable only once the exact tool and its matched rule are fixed against a provisioned target.

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
defaulting to `OpWrite` is refused read-first at the boundary.

**Blocker (Codex P1) — the read-first classifier makes the "one exact harmless tool call"
unexecutable today.** `policyOperation` classifies ONLY `tools/list` as `OpDiscovery`; every
`tools/call` is `OpWrite`, which the live gate rejects at its read-first check. So a "one exact
tool" call — the experiment's §3 shape — cannot pass read-first. The only read-first-admissible
method, `tools/list`, resolves no specific tool, so `liveGateInput` supplies an empty tool
name/fingerprint and the exact-tool live-approval revalidation (`mcpLiveTrustRevalidate`) fails.
Consequently NO request can execute the claimed one exact harmless tool even after the §5 target and
§13 activation inputs are provided: a **shipped finer operation classifier** (proving a specific
tool `OpRead`) OR a **separately designed discovery-trust path** is an additional, independent
prerequisite. This is a first-class blocker in §26, not "a further constraint."

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
impossible** (`e.total >= MaxTotalExecutions → BudgetDeniedTotal`). Specifiable in isolation; but no
*authoritative* budget input path feeds `productionCanaryActivationInputs`, so the `BudgetConfigured`
activation fact stays false in production today (contributes to §13).

**Correction (Codex P1) — the budget bounds LOGICAL reservations, not PHYSICAL upstream invocations.**
`mcpLiveSideEffectGate` reserves the budget ONCE (`reserveCanaryExecution`), then calls
`Upstream.Call` once — but `upstreamclient.Client.Call` (`client.go:130-141`) runs its OWN retry loop
bounded by `MaxReadRetries()`, retrying an IDEMPOTENT call on a pre-response failure. `runExecute`
marks `OpRead`/`OpDiscovery` idempotent, so under production `DefaultLimits` a single budgeted
request can send the POST up to `1 + MaxReadRetries` times (≈3). A pre-response failure can occur
AFTER the server already received and processed the POST, so those retries are REAL additional
invocations. Consequently "N allowed / N+1 impossible" bounds reservations, NOT upstream side effects,
and the §14 executed==received reconciliation would diverge by retry amplification. For a First
Canary this must be closed, and **every option is a CODE CHANGE — retry-disablement is not
representable today** (Codex P1, verified). `newProductionUpstreamClient` hard-codes
`upstreamclient.DefaultLimits()` (2 retries), and `NewLimits` COERCES `MaxReadRetries == 0` to the
default `2` and REJECTS negatives (`limits.go:98-99,107`), so no config value disables retries.
Closing this requires code, and only TWO options actually bound the physical POSTs: make
retry-disablement representable (an explicit zero/sentinel or a no-retry flag) and wire a retry-free
`Limits` into the Canary's production client, OR charge each physical attempt to the budget. A
per-reservation correlation key is NOT a third bound — it only enables witness correlation and (with
an upstream dedup protocol) server-side de-duplication of side-effects; it does not stop the retry
loop, so the server still records up to ~3 POSTs (§14/§26). Not GO until then.

---

## §10 Exact tight scope; near-miss stays outside

`canary.ValidateScope` (`scope.go:62`) forbids percentages (`ScopeUsesPercentage`), wildcards
(empty/fingerprint-less tools, non-enumerable scopes), groups (`ScopeUsesGroups` — membership can
change without a scope edit), empty tenants, and unbounded identity; it requires ≥1 exact server,
≥1 exact tool with a fingerprint, a concrete tenant, and a named principal, all within the
First-Canary bounds (`MaxCanaryServers=1`, `MaxCanaryTools=2`, `MaxCanaryPrincipals=2`,
`MaxCanaryTenants=1`) and read-first operations. Rejected near-misses: a second SERVER or second
TENANT (caps are 1), a percentage, a group, a wildcard/fingerprint-less tool, a different
fingerprint/format, a control op — each by a distinct sub-reason.

**Correction (Codex P1) — `ValidateScope` does NOT enforce exactly-one tool/principal, and a plain
count==1 remedy is insufficient.** `MaxCanaryTools` and `MaxCanaryPrincipals` are **2**, so a
two-tool or two-principal scope PASSES the scope gate. Worse, `principalCount` sums `Principals` +
`Clients` + `Agents`, so a `count==1` remedy is satisfiable by ONE shared `Client` or `Agent` with
ZERO `Principals` — which leaves the principal dimension unrestricted, letting any non-synthetic user
of that client/agent become the admitted caller. The correct external prerequisite is therefore:
**exactly one `Principals` entry, zero `Clients`/`Agents`/`Groups`, and exactly one tool** (or a
proof that the selected client/agent maps one-to-one to the synthetic principal). The machine gate
alone enforces none of this — it is an external constraint on the unblock list (§26).

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
`quiesceLiveTier` is its inverse. **This review arms nothing** and leaves no real node armed.

**Correction (Codex P1) — `armLiveTier` has NO production caller.** A repo-wide search of non-test
Go finds only the definition of `armLiveTier` (and its sole would-be effect `markGatewayExecDepsReady`);
it is invoked ONLY from tests. No startup path and no admin API triggers arming, so even after
composing the production deps (`CULVERT_MCP_LIVE_DEPS`) an operator CANNOT actually arm the tier in
the shipped process. The arming logic is correct as a mechanism, but "armable" is function-level
only — a governed production arming entry point (startup wiring or an admin endpoint) must be added
before precondition 1 is performable. Added to the §26 unblock list.

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

Reconciliation plan: Culvert's executed count MUST equal the controlled server's
independently-recorded received count MUST equal the expected count. The witness is the §5 server's
own invocation log, which does not exist today; the reconciliation procedure is specified for when
it does.

**Correction (Codex P1) — naive count-equality is broken by retry amplification, and the current wire
ID cannot fix it.** Because the transport retries idempotent reads (§9), one budgeted logical request
can produce up to `1 + MaxReadRetries` physical POSTs the controlled server records. So Culvert's
per-Reserve executed count and the server's received count need NOT be equal even when nothing is
wrong. Correlating/deduplicating on the JSON-RPC wire ID does NOT work today: the executor sets
`WireID = "u-" + target.ServerID` (`run.go:112`), which is per-SERVER — with the experiment's single
server, ALL reservations AND their retries share ONE id, so witness records cannot be mapped to
individual reservations and dedup by that id would collapse the WHOLE corpus, not just retries. NO
remedy works with today's code — all require a code change (§9/§26): disabling retries is not
representable (`NewLimits` coerces `MaxReadRetries==0`→2 and rejects negatives; the production client
hard-codes `DefaultLimits()`), and charging each attempt to the budget is likewise code. A
unique-per-reservation, stable-across-retries key would let the witness be *correlated* to reservations,
but a key ALONE does NOT bound physical POSTs — it neither stops the retry loop nor charges its
attempts, so the server still records up to ~3 POSTs per reservation; only disabling retries or
charging each attempt actually bounds the physical invocations (§26).

**Correction (Codex P1) — reconciliation and its breach are NOT automatic.** `outcome_evidence_loss`
and `unexpected_upstream_response` are declared abort codes (`abort.go`) but NO production code
reconciles an independent witness or trips either. So a witness divergence would NOT auto-stop the
Canary — it would have to be caught by an operator out of band. This is a product-defect
prerequisite (see §16), and it also means the "any mismatch → auto-stop" property this section would
rely on is **not present today**. Additionally, `ExecOutput.Executed` is an in-memory return value,
not a durable event field (see §15), so Culvert's own "executed count" is not reconstructible from
the durable record alone.

---

## §15 Evidence plan (no secrets)

**No-secrets property — GO.** `DecisionFacts` is a typed-facts-only API (a secret cannot reach it by
construction, `events/decide.go:10-15`), `backstopScan` marshals and scrubs every event and rejects
on any secret pattern (`ReasonEventSecretPresent`, `decide.go:138-147`), and credential evidence is
a digest only (`events/gate.go:52`). No `Authorization` header value ever enters a fact. This axis
holds.

**Correction (Codex P1) — the durable evidence inventory was OVERstated.** Every committed event is
a single `Phase: PhaseDecision` envelope (`decide.go:90-110`) carrying only: correlation ID + digest,
`SnapshotHash`, and the `Identity` / `Decision` / `Inspection` / `Credential` evidence structs.
There is **no** `OutcomeEvidence`, and the following claimed fields are NOT carried as distinct
durable evidence: the live approval binding, the budget reservation outcome, request duration, and a
durable `Executed` flag (`Executed` is an in-memory `ExecOutput` field only). Worse, the post-call
outcome commit runs ONLY on the success path (`finishUpstream:281` calls `CommitDecision(outcomeFacts)`);
the upstream-error, nil-response, and DLP-block paths return through `e.blocked` and commit **no**
post-call event, and an ordinary outcome-commit failure is only metered
(`ObserveOutcomeEvidenceLoss`, `run.go:282`), never tripped. The pre-call decision commits durably
before the side effect (good), but the OUTCOME record is incomplete and success-only. Consequence
for §18: the durable record alone cannot always tell an operator whether the upstream invocation
occurred. This is a product-defect prerequisite (§26), NOT a GO mechanism.

---

## §16 Abort plan

Whole-Canary breaches (a single occurrence stops the Canary): `out_of_scope_execution`,
`scope_escape`, `tool_fingerprint_drift`, `server_identity_drift`, `outcome_evidence_loss`,
`credential_safety_failure`, `budget_exhausted`, `elevated_error_rate`, `latency_pathology`,
`unexpected_upstream_response` (`abort.go:54-86`). The controller latches monotonically and
generation-bound; an unknown code fails closed to `AbortCanary` (`abort_control.go:35-40`).
**Correction (Codex P1) — most whole-Canary trips are NOT wired to an automatic tripper.** A
repository-wide search finds exactly TWO production `aborter.Trip` sites in the execution path, both
in `reserveCanaryExecution` (`mcp_canary_runtime.go:391,394`): `budget_exhausted` and `scope_escape`.
The generic `tripCanaryAbort` wrapper (`mcp_canary_runtime.go:453`) has NO production caller (Codex
P1, verified), so ALL the other declared `AbortCanary` codes are NOT auto-tripped:
- `out_of_scope_execution`: no auto-trip (the per-request read-first/scope gate denies the request
  but does not stop the Canary).
- `tool_fingerprint_drift` / `server_identity_drift`: drift only DENIES the single request at
  `preCallGuard` (`errToolDriftedBeforeCall`); it does not trip the whole Canary.
- `credential_safety_failure`: no auto-trip.
- `outcome_evidence_loss`: only increments a metric (`ObserveOutcomeEvidenceLoss`, `run.go:282`).
- `unexpected_upstream_response`: nothing reconciles the witness (see §14); no auto-trip.
- `elevated_error_rate` / `latency_pathology`: no threshold tripper wired.

So the ONLY whole-Canary breaches that auto-stop are `budget_exhausted` and `scope_escape`; the other
EIGHT declared breaches do not. After any of them, LATER requests could still reach the upstream
instead of the Canary auto-stopping. The automatic controls that DO hold are the budget ceiling, the
identity/blast-radius cap (`scope_escape`), the per-request kill re-read, per-request tool-drift
denial, and the operator emergency kill (the graceful demotion/quiesce rollback is NOT
operator-reachable — §17, blocker 10). The gap is a **product-defect prerequisite** (§26): whole-Canary
auto-abort must be wired for ALL eight remaining declared breaches
(`out_of_scope_execution`, `tool_fingerprint_drift`, `server_identity_drift`,
`credential_safety_failure`, `outcome_evidence_loss`, `unexpected_upstream_response`,
`elevated_error_rate`, `latency_pathology`) before a First Canary is authorized. My earlier
"scope/budget/drift/kill controls ARE automatic" claim was wrong for everything except budget and
scope_escape.

---

## §17 Manual emergency controls

The ONLY operator-reachable control today is the **emergency kill** engage/clear
(`POST /api/mcp/rollout/emergency`, `emergencyDisable`/`clearEmergency`). **Note — only the ENGAGE
direction narrows.** Engaging the kill advances the monotonic `killGen` and disables execution;
`clear` (`clearEmergency`/`ClearKillSwitch`) clears the kill flag but leaves the rollout mode and
active Canary runtime UNCHANGED, so subsequent requests can become eligible again. Clearing is a
RE-ENABLING action — treat it with the same caution as any widening, not as part of a "narrows only"
pair.

**Correction (Codex P1) — NEITHER graceful rollback path is operator-invokable, so §17's bar is not
met.** Two earlier claims were wrong:
- **Quiesce.** `quiesceLiveTier` (live-tier un-arm-and-drain) has NO production caller — only its
  definition exists; no route or startup hook invokes it.
- **Canary→Shadow/Observe demotion.** `demoteCanary` IS reached from the rollout-commit core
  (`mcp_rollout.go:511`), but that core is driven ONLY by the signed-distribution apply path, NOT by
  an operator. The operator-facing admin handler `apiMCPRolloutTransition` always returns
  `distribution_not_configured` for a non-Production target (`ui_mcp_rollout.go:114-116`) and never
  calls the commit path, so an admin cannot drive a Canary→Shadow/Observe demotion in the
  disabled-default posture.

So the review-contract §17 bar — "no GO unless **rollback AND kill** are available" — is met only on
the KILL side; there is no operator-reachable graceful rollback today. This is a **GO blocker**
(blocker 10 in §26), not recommended hardening: a governed operator-reachable rollback control must
be wired (either `quiesceLiveTier`, or the demotion/publication path so `apiMCPRolloutTransition`
reaches the commit core). None can be *exercised against a live Canary* today anyway because none can
be activated.

---

## §18 Crash / restart

Verified fail-closed: on restart the rollout restore re-runs the FULL activation preflight from
authoritative state and clamps any live mode to Disabled on failure (`mcp_rollout.go:550-614`); the
canary runtime disarms on build-version or generation mismatch (`mcp_canary_runtime.go:527-586`);
`reconcileCanaryRuntimeAfterRestore` disarms an armed runtime with no live mode; the live tier
forces composed/unarmed (`disarmForRestart`). The monotonic generation and monotonic budget `total`
are preserved, so an old generation/budget cannot become fresh allowance. **No silent re-arm** and
**no stale allowance** are GO.

**Correction (Codex P1) — pre-crash invocation is NOT reliably determinable.** As established in
§15, the only durable pre-side-effect record is the `PhaseDecision` event (`ExecutionState:"executing"`);
the post-call outcome event is committed only on the success path. A crash after the controlled
server receives the request but before/around the success-path outcome commit leaves only the
"executing" record — so "did the upstream invocation occur before the crash?" is NOT always
answerable from the durable events. This contradicts the review-contract §18 requirement and is part
of the durable-evidence product-defect prerequisite (§26). The re-arm/allowance guarantees hold; the
determinability guarantee does not, today.

**Further (Codex P1) — completeness alone cannot close the post-send window.** Making the
normal-return outcome record complete and non-success-only is necessary but NOT sufficient: a crash
AFTER the controlled server receives the POST but BEFORE `Upstream.Call` returns can emit no post-call
event at all, so the `executing` record stays ambiguous no matter how rich the outcome record is.
Resolving the post-send window additionally requires a durable pre-send intent correlated to an
independent upstream receipt (or an idempotency-key reconciliation) — reflected in the §26 unblock
item.

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

No "probably safe" path was left open for the attacks that DO resolve to a gate. **The concerns that
do NOT resolve to a gate become the blockers, not residual risks (§26):** (a) no supported-trust-model
controlled target (§5); (b) the unreachable activation preflight (§13); (c) the read-first classifier
refuses the one-exact-tool call and discovery cannot bind an exact tool (§6, Codex P1); (d) most
whole-Canary aborts are declared-but-unwired, so a witness divergence or evidence loss does not
auto-stop later requests (§14/§16, Codex P1); and (e) the durable outcome record is incomplete and
success-only, so a pre-crash invocation is not always determinable (§15/§18, Codex P1).

---

## §21 No code changes during the eventual experiment

No product code is changed by this review (documentation-only; see §23). The connectivity gap (§5)
is a documented, intentional, fail-closed pre-Canary capability gap, explicitly "NOT a defect"
(`mcp_live_production_deps.go:293-309`). **However, this review DID identify genuine product-defect
prerequisites** (Codex adversarial round, §24): the incomplete whole-Canary auto-abort wiring
(§14/§16) and the incomplete/success-only durable outcome evidence (§15/§18). Per §21, these are
RECORDED here and must each be fixed in a **dedicated, Codex-reviewed PR** — not in this
documentation PR and never as a hot-fix during a live experiment — after which this review is re-run
against the new exact SHA. This is a further reason no Canary may be authorized from the current SHA.

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
could cause more, different, or less-observable side effects than claimed (§20), including successive
Codex adversarial review rounds (PR #1292), each finding accepted only after verification against the
code:

- **P1 — read-first classifier (§6):** a `tools/call` is `OpWrite` and refused read-first; discovery
  (`tools/list`) cannot bind one exact tool for the live-approval revalidation. Confirmed.
- **P2 — credential conditional (§4):** `CredentialProfile` is a policy obligation, so no-credential
  status is unverifiable until the exact tool + rule are fixed. Corrected.
- **P1 — durable outcome evidence (§15/§18):** every event is a `PhaseDecision` with no
  `OutcomeEvidence`; the outcome commit is success-only, so a pre-crash invocation is not always
  determinable, and the post-send crash window cannot be closed by outcome records alone. Confirmed
  against `events/decide.go` + `execution/run.go`.
- **P1 — unwired whole-Canary aborts (§14/§16):** only `budget_exhausted`/`scope_escape` auto-trip;
  the other eight declared breaches do not. Confirmed against `mcp_canary_runtime.go`.
- **P1 — scope not exactly-one (§10):** `MaxCanaryTools`/`MaxCanaryPrincipals` are 2; the machine
  gate does not enforce the one-of-everything shape. Confirmed against `scope.go`.
- **P1 — budget vs physical invocations (§9/§14):** idempotent read retries send the POST up to ~3×
  per single budget reservation. Confirmed against `upstreamclient/client.go`.
- **P1 — no production arming caller (§12):** `armLiveTier` is invoked only from tests, so an
  operator cannot arm the tier in the shipped process. Confirmed by repo-wide search.
- **P2 — consistency:** propagation of the above into the summary, the §3 table, the §25 census, and
  the §26 blocker enumeration (kept exhaustive and aligned with §25).

The dominant adversarial finding remains that the only documented controlled target is unreachable
fail-closed on three axes and would tempt an operator toward `AllowPrivate` / a scheme hack / a
SPIFFE shim — each a design change this review forbids. Codex's findings did not weaken the verdict;
they ADDED independent blockers and two product-defect prerequisites, reinforcing BLOCKED (see the
BLOCKED-vs-FAILED note in §26).

---

## §25 Mandatory GO criteria

| Criterion | Status |
|---|---|
| Exactly one node / tenant / principal / server / tool / fingerprint, read-only, synthetic | Specifiable — YES |
| Tool requires no production credential | **CONDITIONAL — unverifiable until tool + rule fixed (§4)** |
| A read-first-admissible one-exact-tool operation exists | **NO — classifier refuses `tools/call`; discovery cannot bind one tool (§6)** |
| Supported upstream trust model for a controlled server available today | **NO** (§5) |
| Shadow trust ≠ live trust proven; live approval does not activate Canary | YES (§8) |
| Tight scope validated (no percentage/group/wildcard; server & tenant capped at 1) | YES (§10) |
| Machine gate enforces exactly-one tool AND exactly-one principal | **NO — caps are 2; must be an external prerequisite (§10)** |
| Tiny budget; N reservations allowed / N+1 impossible | YES for reservations (§9) |
| Budget bounds PHYSICAL upstream invocations (retries charged/disabled) | **NO — idempotent read retries up to ~3× per reservation (§9)** |
| Activation preflight returns `Ready:true, Unmet:[]` on a real node | **NO** (§13) |
| Governed production arming entry point exists (operator can arm) | **NO — `armLiveTier` has no production caller (§12)** |
| Independent upstream witness reconcilable AND auto-stops on divergence | **NO — no reconciliation/auto-trip; retry amplification; §5 server absent (§14)** |
| Evidence carries no secrets/credentials | YES (§15) |
| Durable record determines whether a pre-crash upstream invocation occurred | **NO — success-only outcome evidence + unclosable post-send crash window (§15/§18)** |
| Whole-Canary auto-abort covers drift / evidence-loss / unexpected-response / thresholds | **NO — only budget/scope auto-trip (§16)** |
| Operator-reachable graceful rollback (quiesce or Canary→Shadow/Observe demotion) — §17's "rollback AND kill" bar | **NO — quiesce has no caller; `apiMCPRolloutTransition` returns `distribution_not_configured` (§17)** |
| Crash/restart does not silently re-arm/resume | YES (§18) |
| Unresolved P0/P1 finding | **YES — two product-defect prerequisites (auto-abort wiring, durable outcome evidence), each a dedicated PR (§21/§24)** |

Multiple mandatory criteria are NO and two P1 product-defect prerequisites are open. A GO is
therefore forbidden.

---

## §26 Final verdict

### `FIRST CONTROLLED CANARY REVIEW: BLOCKED — NO SAFE FIRST CANARY TARGET`

The Canary core is fail-closed across scope, trust firewall, budget ceiling, per-request kill
re-read, restart re-arm/allowance, and no-secret evidence. But a safe first experiment cannot be
assembled today on **ten independent blockers** — some are intentional capability gaps, some are
prerequisites, and two are genuine product defects the Codex adversarial rounds (§24) surfaced and
this review verified against the code. The list below is exhaustive AS A SET: together the ten cover
every mandatory NO/CONDITIONAL row in §25, so closing ALL of them is necessary and sufficient to pass
§25 — but the mapping is grouped, not strictly 1:1 (e.g. §25's independent-witness row folds under
blocker 7's auto-abort and also depends on blockers 1 and 6).

1. **No controlled upstream reachable under the supported production trust model (§5).** The only
   documented controlled inventory fails closed on scheme (`mcp+https://`), host (private
   `*.qual.svc`), and identity (SPIFFE). No public-HTTPS controlled MCP server with a base64 SHA-256
   SPKI pin, a plain `https://` endpoint, and one harmless read tool is provisioned.
2. **The production activation preflight cannot return `Ready:true` (§13).** The live tier is unarmed
   by default and `productionCanaryActivationInputs` leaves `ServerUsable`/`ToolFingerprintCurrent`/
   `Budget` fail-closed.
3. **No governed production arming entry point (§12).** `armLiveTier` has no production caller (only
   tests invoke it), so an operator cannot arm the tier in the shipped process.
4. **The read-first classifier refuses the one-exact-tool call (§6).** `tools/call` is `OpWrite`
   (refused read-first); `tools/list` binds no exact tool for the live-approval revalidation. A
   finer classifier or a designed discovery-trust path is required.
5. **The machine gate does not enforce exactly-one tool/principal (§10).** `MaxCanaryTools`/
   `MaxCanaryPrincipals` are 2, so the one-of-everything shape is an external prerequisite.
6. **The budget does not bound physical upstream invocations (§9).** Idempotent read retries can
   send the POST ~3× per single budget reservation.
7. **Whole-Canary auto-abort is incomplete (§14/§16) — a product defect.** Only
   `budget_exhausted`/`scope_escape` auto-trip; the other eight declared breaches do not, and nothing
   reconciles the independent witness — so a divergence would not auto-stop later requests.
8. **Durable outcome evidence is incomplete/success-only, with an unclosable post-send crash window
   (§15/§18) — a product defect.** A pre-crash upstream invocation is not always determinable.
9. **Credential path unresolved (§4).** Credential selection comes from the tool's matched policy
   RULE, not from provisioning a server/tool, and the production broker has ZERO providers, so a
   `CredentialProfile`-bearing rule fails closed at `Broker.Materialize`. Provisioning a target
   (blocker 1) does NOT by itself establish no-credential status; it must be closed explicitly by
   verifying a no-`CredentialProfile` matched rule OR implementing a working credential provider/path.
10. **No operator-reachable graceful rollback (§17).** §17's contract bar is "no GO unless rollback
   AND kill are available." Only the emergency kill is reachable: `quiesceLiveTier` has no production
   caller, and the operator-facing `apiMCPRolloutTransition` returns `distribution_not_configured` for
   a Canary→Shadow/Observe target (the demotion runs only via the unwired signed-distribution path). A
   governed operator-reachable rollback control (wire quiesce, or wire the demotion/publication path)
   must be added.

**Why BLOCKED and not FAILED.** The review contract's FAILED verdict is for a specified, assemblable
experiment judged unsafe; BLOCKED is "no safe first canary target." Here, no experiment can even
execute — nothing is reachable (1), no Canary can activate (2), no operator can arm (3), and no
admissible one-tool operation exists (4). Blockers 5–10 are unmet *prerequisites*/defects, not a live
unsafe path, precisely because 1–4 mean zero real side effects are possible from this SHA. So the
honest label is BLOCKED — a safe first experiment cannot be *assembled* — and the two product defects
(7, 8) must be closed as dedicated PRs before any authorization, reinforcing rather than weakening
that verdict. (Had a target been reachable and a Canary activatable, defects 7–8 would have made the
verdict FAILED.)

**To unblock (each a separately-reviewed change, none performed here):**
- provision a public-HTTPS, non-production, independently-recording controlled MCP server exposing
  exactly one harmless read/discovery tool, registered with a plain `https://` endpoint and its real
  base64 SHA-256 SPKI pin; OR land the recorded connectivity work (endpoint-scheme translation and/or
  an identity-type-aware verifier + a per-target private-destination policy) in a dedicated PR;
- wire an authoritative `ServerUsable`/`FingerprintCurrent`/`Budget` input path for the activation
  preflight;
- wire a **governed production arming entry point** (startup path or admin API) that invokes
  `armLiveTier` — it has no production caller today, so an operator cannot arm the tier in the shipped
  process (§12) — and then arm the live tier on the controlled node via that path;
- ship a finer operation classifier (or a designed discovery-trust path) so exactly one harmless
  operation is read-first-admissible AND bindable to one exact tool;
- resolve the credential path explicitly (§4): either verify the chosen tool's matched policy rule
  attaches NO `CredentialProfile` (so the no-credential branch is proven for this exact request), OR
  implement a working credential provider/path — the production broker composes zero providers, so a
  credential-requiring rule fails closed;
- impose the exact one-of-everything identity shape as an authorization prerequisite: **exactly one
  `Principals` entry, zero `Clients`/`Agents`/`Groups`, exactly one tool** (or prove the selected
  client/agent maps one-to-one to the synthetic principal). A plain count==1 check is INSUFFICIENT —
  `principalCount` sums Principals+Clients+Agents, so one shared client/agent with no Principals would
  satisfy it while leaving the principal dimension unrestricted; and `ValidateScope` permits up to two
  of each (`MaxCanaryTools`/`MaxCanaryPrincipals` = 2), so the machine gate enforces none of this (§10);
- **[code change]** bound PHYSICAL upstream invocations to the budget — `upstreamclient.Call` retries
  an idempotent read up to `MaxReadRetries` times outside the single budget `Reserve`, so one budgeted
  request can hit the server up to ~3 times (§9). Only TWO options actually bound the physical POSTs,
  and BOTH are code: (a) make retry-disablement representable and wire a retry-free `Limits` into the
  Canary client — it is not representable today (`NewLimits` coerces `MaxReadRetries==0`→`2` and rejects
  negatives; `newProductionUpstreamClient` hard-codes `DefaultLimits()`); or (b) charge each physical
  attempt to the budget. A per-reservation correlation key is NOT a third option: it only lets the
  witness be reconciled and (with an upstream dedup protocol) lets the SERVER ignore duplicate
  side-effects — it neither stops the retry loop nor charges its attempts, so the physical POSTs the
  server records are unbounded by it (§14);
- **[dedicated PR]** wire whole-Canary auto-abort for ALL eight remaining declared breaches —
  `out_of_scope_execution`, `tool_fingerprint_drift`, `server_identity_drift`,
  `credential_safety_failure`, `outcome_evidence_loss`, `unexpected_upstream_response`,
  `elevated_error_rate`, `latency_pathology` — plus an automatic witness-reconciliation trip;
- **[dedicated PR]** durable invocation determinability — a complete, non-success-only outcome record
  is necessary but NOT sufficient: a crash AFTER the server receives the POST but BEFORE `Upstream.Call`
  returns can emit no post-call event at all, so the `executing` record stays ambiguous. Closing the
  post-send window additionally requires a durable pre-send intent record correlated to an independent
  upstream receipt (or an idempotency-key reconciliation protocol) — determinability cannot be
  promised from Culvert-side outcome records alone.
- wire a **governed operator-reachable graceful rollback control** (blocker 10, §17) — the review
  contract requires rollback AND kill before GO, and today only the emergency kill is reachable:
  `quiesceLiveTier` has no production caller, and `apiMCPRolloutTransition` returns
  `distribution_not_configured` for a Canary→Shadow/Observe target (the demotion runs only via the
  unwired signed-distribution path). Wire `quiesceLiveTier`, OR wire the demotion/publication path so
  an admin can drive Canary→Shadow/Observe.

Then re-run this review against the new exact SHA.

**This review did not activate Canary, did not execute any tool, did not arm any production node,
retrieved no credential, and used no production server or customer traffic. Real Canary side effects
in this phase: 0.**
