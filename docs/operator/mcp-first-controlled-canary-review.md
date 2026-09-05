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
cannot be assembled today on **FIFTEEN independent blockers** (exhaustive as a set — together they cover
every mandatory NO/CONDITIONAL row in §25, though the mapping is grouped, not strictly 1:1: the
witness-reconciliation row folds under blocker 7 and also depends on blockers 1 and 6): (1) no controlled upstream reachable AND usable under the supported
production trust model (a provisioned HTTPS+SPKI target must ALSO speak a protocol that permits Culvert's sessionless calls — a standard initialization-requiring server is rejected because the client drives no MCP initialize/version/session lifecycle); (2) the production activation preflight cannot return `Ready:true` on a stock
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
reachable (quiesce has no caller; `apiMCPRolloutTransition` returns `distribution_not_configured`, §17);
and (11) the reviewed fingerprint is operator-declared, not peer-observed — `seedServer`/`seedTools`/
`Ingest` compute it from operator JSON and no non-test caller of `Discovery.Discover` re-observes the
peer, so exact-current fingerprint + rug-pull invalidation bind only the seeded record (§7); and (12)
no operator-reachable governed Canary ACTIVATION entry point — `apiMCPRolloutTransition` returns
`distribution_not_configured` and no non-test code constructs/`Publish`es the distribution publication
coordinator, so even with arming + activation inputs closed nothing transitions the node into Canary
mode (§13/§17); and (13) the seeded controlled tool is `catalog.Quarantined` and nothing promotes it —
the policy engine hard-quarantines it BEFORE any user rule and `ApproveLive` deliberately never calls
`catalog.Promote`, so every exact-tool request is denied even with 1–12 closed (§6/§7); and (14) the
exact request must resolve to an ALLOW-class decision with satisfiable obligations — a
no-`CredentialProfile` rule may still be DENY, an unmatched request default-denies, and `PolicyHealthy`
only proves a snapshot exists (§4/§13); and (15) the one-NODE bound is not enforced by anything —
`ScopeSpec` has no node dimension and the publication coordinator pushes the signed envelope to EVERY
`Dist.Nodes()` entry, so closing blocker 12 generically could activate every armed DP while the
checklist still reads "nodes = 1" (§3/§13). Blockers 1–6 and 9–15 are gaps/prerequisites; 7–8 are
defects recorded here for dedicated PRs (§21).
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
layers are now stated explicitly: architecture preflight + budget ceiling + trust firewall
IMPLEMENTED, while the scope gate (`ValidateScope`), automatic-abort coverage, and durable invocation
evidence are PARTIAL/DEFECTIVE (matching the split runbook posture table — see §10, §14–§16, §18);
production deps COMPOSABLE (opt-in, default OFF); live tier ARMABLE (governed, not a posture-wall
edit); armed-by-default NO; Canary-active NO; and a supported-trust-model controlled upstream NOT
AVAILABLE TODAY. The stale
"no production caller composes the tier" claim and the stale "call `markGatewayExecDepsReady`"
precondition were corrected.

---

## §3 The ONE exact experiment (specified up to the blocking point)

The experiment is reduced to *one of everything*, synthetic, recorded, time-boxed, instantly
reversible:

| Dimension | Exact value |
|---|---|
| nodes | **1** controlled Canary node — but NOT machine-enforced: `ScopeSpec` has no node dimension and the publication coordinator's `pushAll` delivers the signed envelope to EVERY `Dist.Nodes()` entry, so one-node blast radius is a deployment assumption, not a gate (§13, blocker 15) |
| tenants | **1** synthetic / non-production tenant (`OwnerScope`) |
| principals | **1** synthetic principal (canonical session `Sub`), no customer identity |
| MCP servers | **1** controlled server that independently records every received invocation |
| tools | **1** exact tool |
| fingerprints | **1** exact reviewed fingerprint (F2); rug-pull invalidates the approval — BUT the shipped provisioning seeds the fingerprint from operator-declared JSON, not an observed peer, and nothing re-observes the server, so this binds only the seeded record (§7, blocker 11) |
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

**Reachable ≠ usable (Codex P1) — the MCP protocol lifecycle is not driven by the client.**
Even a provisioned HTTPS+SPKI+public target may reject every request: `execution.Discover` sends
`tools/list` directly, `upstreamclient.Call` explicitly leaves version negotiation "to the caller"
(`client.go:160-161`) and NO production path invokes `NegotiateVersion` (referenced only in tests),
and `roundTrip` sends a single JSON-RPC message with only `Content-Type`/`Accept` headers — no
`initialize`/`notifications/initialized` handshake, no `MCP-Protocol-Version`, no `Mcp-Session-Id`
(`transport.go:103-110`). A spec-compliant MCP server that requires initialization would reject
discovery and every tool call as pre-initialization / missing-session traffic. So satisfying blocker
1 additionally requires EITHER a target whose supported protocol legitimately permits these
sessionless `tools/list`/`tools/call` requests, OR a Culvert-side upstream lifecycle implementation
(initialize handshake + version negotiation + protocol/session headers) — the latter a code change.

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

The reviewed fingerprint (F2, `FingerprintFormatVersion`+32-byte digest) is what the live approval
and scope must both name; `tooltrust` re-verifies exact current state at approve time and the
boundary re-checks tool freshness (`ToolStillCurrent`, `run.go:201`). **But the only shipped
provisioning path binds that fingerprint to OPERATOR-DECLARED JSON, not to the observed live peer,
and nothing re-observes the peer (blocker 11).** `seedTools` (`mcp_inventory.go:447`) re-encodes the
operator-supplied tool metadata and lets `catalog.Ingest` recompute the fingerprint from THOSE fields;
`seedServer` (`:421`) calls `VerifyIdentity` with the configured `PinnedIdentity` checked against its
own register stamp, not against a dialed server. And `execution.NewDiscovery`/`Discovery.Discover` —
the only path that would refresh the catalog FROM a live server — has NO non-test caller
(`mcp_tooltrust.go:138` installs a reconcile hook but nothing invokes discovery), so `ToolStillCurrent`
validates the unchanged LOCAL record indefinitely. Consequence: "exact reviewed fingerprint" and
"rug-pull invalidates the approval" only bind the seeded record — an operator editing the inventory is
caught, but the actual upstream drifting behind the same identity is NOT. Treating exact-current
fingerprint + rug-pull invalidation as satisfied requires either authenticated production
discovery/freshness verification (a non-test `Discover` caller) OR an externally-verified ingestion
procedure that establishes seeded-fingerprint == the live peer's advertised tool. This is also gated
on the §5 server existing to be discovered against, which it does not today.

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

**A RANGE IS NOT AN EXACT EXPERIMENT (Codex round 31).** This section previously specified
`MaxTotalExecutions` in [3,10], left `MaxExecutionsPerMinute` unstated, and described the `Window`
only as "minutes-scale" — so two authorizations could both pass §25 with materially different blast
radii, and §14's witness reconciliation had no expected count to reconcile AGAINST. The review
therefore fixes the exact triple as its specification: **`MaxTotalExecutions=3`,
`MaxExecutionsPerMinute=1`, `MaxConcurrentExecutions=1`, `Window=15m`** — the smallest total that can
still distinguish a repeatable success from a one-off, serialized so no two requests are ever in
flight, in a window short enough to bound an unattended experiment. The authorization MUST adopt this
exact triple or re-review a different one; it may not be left open.

### The witness invariant is over TOOL EXECUTIONS, not HTTP POSTs

**The invariant is scoped to the authorized tool invocations, and the classes must be independently
observable (Codex round 33).** A total-POST count is the wrong unit: when blocker 1 is closed with a
Culvert-side MCP lifecycle implementation, or blocker 11 with authenticated discovery near each call,
the recording server ALSO receives `initialize`, `notifications/initialized` and `tools/list` POSTs
that consume no execution reservation — so a perfectly correct retry-free run would exceed three POSTs
and be misclassified as a breach. The reconciliation therefore partitions the upstream's log into two
classes that must each be independently attributable:

| Class | Expected in the First Canary | Consumes a reservation |
|---|---|---|
| **Side-effect-bearing tool invocations** (the one authorized `tools/call`) | **EXACTLY 3** | yes |
| **Auxiliary lifecycle/discovery** (`initialize`, `notifications/initialized`, `tools/list`, …) | unbounded but SEPARATELY counted and attributable | no |

The authorization must make this partition machine-checkable — either the recording server
distinguishes the classes by method and correlates each side-effect-bearing call to its reservation,
or ALL initialization/discovery is required to occur OUTSIDE the measured window so the in-window log
contains nothing but the three authorized invocations. A witness that can only report a total POST
count cannot satisfy §14.

**The invariant also forces blocker 6's retry-FREE remedy, and admits no alternative.** Within the
side-effect-bearing class:
* **Before blocker 6 is closed** the witness cannot attribute invocations to reservations at all — the
  wire identifier is PER-SERVER (`WireID: "u-" + target.ServerID`,
  `internal/mcp/execution/run.go:112`), so 3 reservations retried 3× each and 1 reservation retried 9×
  are indistinguishable. A missing or duplicated invocation would classify as expected.
* **Under a "charge each physical attempt to the budget" remedy** retries consume the same 3 slots, so
  the budget can be exhausted by FEWER than 3 logical reservations (one request retried three times
  spends the whole experiment). "Exactly 3" is then simply false.
* **Under the retry-FREE remedy** — make retry-disablement representable and wire a retry-free `Limits`
  into the Canary client — logical and physical counts COINCIDE: **one reservation yields at most one
  side-effect-bearing invocation**, so the class contains exactly 3, and a 4th or a missing 3rd is
  unambiguously a breach.

**The first Canary therefore REQUIRES an explicitly retry-free execution path. Charging attempts to
the budget is NOT an accepted closure for blocker 6 in this experiment — there is no alternate
charging-based remedy** — because it destroys the invariant §14 depends on.

`canary.Budget` with the exact values above, and per-dimension caps consistent with the scope
(`MaxTools=1`, `MaxServers=1`, `MaxPrincipals=1`). `ValidateBudget` (`budget.go:64`) rejects any non-positive cap and enforces
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
Closing this requires code. Two mechanisms could bound the physical invocations in principle — make
retry-disablement representable (an explicit zero/sentinel or a no-retry flag) and wire a retry-free
`Limits` into the Canary's production client, or charge each physical attempt to the budget — **but
only the RETRY-FREE path is an accepted closure for this first experiment** (see the witness invariant
below: charging can spend all three slots on one logical reservation and destroys the
exactly-three-invocations contract). A per-reservation correlation key is not a bound at all — it only
enables witness correlation and (with an upstream dedup protocol) server-side de-duplication; it does
not stop the retry loop, so the server still records up to ~3 invocations (§14/§26). Not GO until
then.

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
but a key ALONE does NOT bound physical invocations — it neither stops the retry loop nor charges its
attempts, so the server still records up to ~3 per reservation. **For this experiment the accepted
closure is the retry-free path only** (§9/§26): charging is rejected because it can spend all three
slots on one logical reservation. Note also that the witness invariant is scoped to the
side-effect-bearing tool invocations — auxiliary `initialize`/`notifications/initialized`/`tools/list`
traffic consumes no reservation and must be counted and attributed SEPARATELY, never folded into the
three (§9).

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

**Threshold REACHABILITY is part of the prerequisite (Codex round 33).** `elevated_error_rate` and
`latency_pathology` are defined only in prose (`abort.go:72-74`: "over threshold", "sustained"), so the
authorization must name the numeric limit, observation window, minimum sample size, and below-floor
behavior — AND the sample floor must be REACHABLE inside the exact corpus (`MaxTotalExecutions=3`), or
the below-floor behavior must stop fail-closed. A reviewed floor above three combined with a permitted
below-floor `no-trip` means neither detector can ever evaluate: elevated errors or pathological latency
would persist for the entire experiment while the automatic-abort prerequisite was recorded as closed.
A detector that cannot possibly evaluate within the authorized corpus does not satisfy the
prerequisite. The same rule governs the witness-reconciliation trip, which is evaluated over the
side-effect-bearing invocation class only (§9) — auxiliary lifecycle/discovery traffic is counted
separately and is never itself a mismatch.
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
- *Rug-pull the tool after approval* → `MatchesTool` exact-fingerprint + boundary `ToolStillCurrent`
  catch a change to the SEEDED record; but the seed is operator-declared and never re-observed from the
  peer (no non-test `Discovery.Discover` caller), so a live server drifting behind the same identity is
  NOT caught (blocker 11, §7).
- *Force an activation fact true via a signed config* → activation facts are node-authoritative, not
  request-supplied.
- *Reach the FIRST `Upstream.Call` POST past an emergency kill* → the final monotonic kill-generation
  re-read (`preCallGuard`) is the last check before it, paramount over drift/demotion. **But this
  holds only for the FIRST physical POST (Codex P1):** `preCallGuard` runs ONCE, then
  `upstreamclient.Client.Call` retries an idempotent read inside its own loop (`client.go:132-141`)
  with NO kill/generation re-check between attempts, so a kill engaged AFTER the first POST but before
  a retry does NOT stop the retry POST. The kill is therefore authoritative at admission, NOT across
  the retry window — a real gap folded into blocker 6 (§9/§26): a retry-free client closes it, and
  merely charging each attempt to the budget does NOT (the POST still fires after the kill) — and
  charging is in any case not an accepted closure for this experiment (§9/§26).
- *Get a no-credential call to leak a header* → `callUpstream("")` sets no `Authorization`.

No "probably safe" path was left open for the attacks that DO resolve to a gate. **The concerns that
do NOT resolve to a gate become the blockers, not residual risks (§26):** (a) no supported-trust-model
controlled target (§5); (b) the unreachable activation preflight (§13); (c) the read-first classifier
refuses the one-exact-tool call and discovery cannot bind an exact tool (§6, Codex P1); (d) most
whole-Canary aborts are declared-but-unwired, so a witness divergence or evidence loss does not
auto-stop later requests (§14/§16, Codex P1); (e) the durable outcome record is incomplete and
success-only, so a pre-crash invocation is not always determinable (§15/§18, Codex P1); and (f) the
transport retry loop bypasses the kill re-read, so an admitted request's retry POSTs can land after
an emergency kill (§9/blocker 6, Codex P1).

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
- **P1 — fingerprint operator-declared, not peer-observed (§7, blocker 11):** the shipped provisioning
  (`seedServer`/`seedTools`/`Ingest`, `mcp_inventory.go`) computes the fingerprint from operator JSON and
  verifies the pinned identity against its own register stamp; `execution.Discovery.Discover` has no
  non-test caller, so `ToolStillCurrent` re-checks only the seeded record. Exact-current fingerprint +
  rug-pull invalidation therefore bind the SEED, not the live peer. Confirmed against `mcp_inventory.go`
  + a repo-wide `Discover` search. Added as blocker 11.
- **P1 — node targeting must be enforced BEFORE DP apply (§3/§13, blocker 15, round 28):** even with
  `Dist.Nodes()` limited to one entry, `mcpPullDistributor.Push` discards its node argument and installs
  the envelope so the shared `ConfigSnapshot` "carries it to every DP"
  (`mcp_distribution_adapters.go:74-88`), and `applyMCPCapabilityEnvelope` has no intended-node check —
  so non-target DPs ACTIVATE before acknowledgements could reveal the escape. This review's earlier
  "intended node + acknowledgement" remedy was INSUFFICIENT and was corrected to require a signed node
  audience rejected at DP apply (or a per-node delivery channel). Confirmed against
  `mcp_distribution_adapters.go`, `mcp_distribution.go`.
- **P1 — one-node bound unenforced (§3/§13, blocker 15):** `ScopeSpec` carries no node dimension and
  `publication.pushAll` delivers the signed envelope to every `Dist.Nodes()` entry, so a generic
  publication entry point (blocker 12) could activate every armed DP while the checklist still reads
  "nodes = 1". Confirmed against `rollout/scope.go`, `cpdp/publication/publication.go`. Added as
  blocker 15.
- **P1 — seeded tool stays catalog-quarantined (§6/§7, blocker 13):** `seedTools` lands tools
  Quarantined and `engine.go:132-135` hard-overrides a `DispQuarantined` tool to `ActionQuarantine`
  before any user rule; `ApproveLive` deliberately performs no promotion and the only non-test
  `catalog.Promote` callers are the shadow `promoteFor` path. Confirmed against `mcp_inventory.go`,
  `policy/engine.go`, `mcp_tooltrust.go`. Added as blocker 13.
- **P1 — allow-class decision not required (§4/§13, blocker 14):** a no-`CredentialProfile` rule may
  still be DENY, an unmatched request default-denies (`engine.go:170-173`), `resolveEnforcing` blocks
  non-allow-class decisions, and `PolicyHealthy` is only `mcpPolicy.composed()`. Confirmed against
  `policy/engine.go`, `rollout/resolve.go`, `mcp_canary_preflight.go:83`. Added as blocker 14.
- **P1 — no Canary activation entry point (§13/§17, blocker 12):** `apiMCPRolloutTransition` returns
  `distribution_not_configured` for a Canary target (`ui_mcp_rollout.go:116`) and no non-test code
  constructs the distribution publication coordinator (`publication.New`) or calls `coord.Publish`, so
  even with arming + activation inputs closed nothing transitions the node into Canary mode. Confirmed
  against `ui_mcp_rollout.go` + a repo-wide `publication.New`/`Publish` search. Added as blocker 12.
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
| Exactly one tenant / principal / server / tool / fingerprint, read-only, synthetic | Specifiable — YES |
| Exactly one NODE, enforced PREVENTIVELY (before or at DP apply) | **NO — `ScopeSpec` has no node dimension, `pushAll` delivers to every `Dist.Nodes()` entry, `mcpPullDistributor.Push` discards its node argument (shared `ConfigSnapshot` reaches every DP), and the apply path has no intended-node check; a post-apply ack is detective, not preventive (§3/§13, blocker 15)** |
| Tool requires no production credential | **CONDITIONAL — unverifiable until tool + rule fixed (§4)** |
| A read-first-admissible one-exact-tool operation exists | **NO — classifier refuses `tools/call`; discovery cannot bind one tool (§6)** |
| Supported upstream trust model for a controlled server available today | **NO** (§5) |
| A provisioned target is USABLE (MCP initialize/version/session lifecycle) | **NO — client sends no `initialize`/version/session; a spec-compliant server rejects sessionless calls (§5)** |
| Reviewed fingerprint bound to the OBSERVED live peer (not operator-declared) | **NO — seeded from operator JSON; identity verified against its own register stamp; no non-test `Discovery.Discover` caller (§7, blocker 11)** |
| Shadow trust ≠ live trust proven; live approval does not activate Canary | YES (§8) |
| Tight scope validated (no percentage/group/wildcard; server & tenant capped at 1) | YES (§10) |
| Machine gate enforces exactly-one tool AND exactly-one principal | **NO — caps are 2; must be an external prerequisite (§10)** |
| Tiny budget; N reservations allowed / N+1 impossible | YES for reservations (§9) |
| Budget bounds PHYSICAL side-effect-bearing invocations via a RETRY-FREE path (charging not accepted) | **YES — `RetryMode`/`RetryDisabled` is representable and wired into the ONLY production upstream client; N reservations ⇒ ≤ N physical POSTs measured AT THE WIRE under concurrency and ambiguous transport failure (blocker 6 CLOSED)** |
| Witness distinguishes side-effect-bearing tool invocations from auxiliary lifecycle/discovery traffic | **NO — no such controlled recording server exists; without the partition a correct run's `initialize`/`tools/list` POSTs misclassify as a breach (§9/§14)** |
| Rate-based abort thresholds are REACHABLE within the 3-execution corpus (or fail closed below the floor) | **NO — no numeric limit, window, or sample floor exists; an unreachable floor with below-floor `no-trip` disables both detectors for the whole experiment (§16/§26, blocker 7)** |
| Activation preflight returns `Ready:true, Unmet:[]` on a real node | **NO** (§13) |
| The exact tool is `catalog.Usable` (not Quarantined) at request time | **NO — `seedTools` lands it Quarantined; the engine hard-quarantines before any rule; `ApproveLive` never promotes (§6/§7, blocker 13)** |
| The exact request resolves to an ALLOW-class rule with satisfiable obligations | **NO — a no-`CredentialProfile` rule may be DENY; an unmatched request default-denies; `PolicyHealthy` only proves a snapshot exists (§4/§13, blocker 14)** |
| Operator-reachable governed path to TRANSITION the node into Canary mode | **NO — `apiMCPRolloutTransition` returns `distribution_not_configured`; no non-test `publication.New`/`Publish` caller (§13/§17, blocker 12)** |
| Governed production arming entry point exists (operator can arm) | **NO — `armLiveTier` has no production caller (§12)** |
| Independent upstream witness reconcilable AND auto-stops on divergence | **NO — no reconciliation/auto-trip; retry amplification; §5 server absent (§14)** |
| Evidence carries no secrets/credentials | YES (§15) |
| Durable record determines whether a pre-crash upstream invocation occurred | **NO — narrowed. Internal durable truth/recovery/reconciliation COMPLETE (terminal outcome on every exit path, durable pre-send intent, orphan derivation, typed witness contract); the authoritative production witness adapter REMAINS unwired, so the answer is `reconciliation_required`, not determinate (§15/§18, blocker 8)** |
| Whole-Canary auto-abort covers drift / evidence-loss / unexpected-response / thresholds | **NO — only budget/scope auto-trip (§16)** |
| Operator-reachable graceful rollback (quiesce or Canary→Shadow/Observe demotion) — §17's "rollback AND kill" bar | **NO — quiesce has no caller; `apiMCPRolloutTransition` returns `distribution_not_configured` (§17)** |
| Crash/restart does not silently re-arm/resume | YES (§18) |
| Unresolved P0/P1 finding | **YES — the auto-abort wiring prerequisite remains; the durable-outcome-evidence prerequisite is narrowed to the authoritative production witness adapter (§21/§24/§25a)** |

Multiple mandatory criteria are NO and P1 product-defect work remains open. A GO is therefore
forbidden. (§25a records the only two post-adoption status changes: blocker 6 CLOSED, blocker 8
narrowed but still OPEN. The other thirteen are untouched and the §26 verdict is unchanged.)

---

## §25a Blocker 6 closure and blocker 8 status (post-review evidence)

This section records the ONLY two status changes made to the frozen ledger since it was adopted.
The other thirteen blockers are untouched. Nothing here changes the §26 verdict.

### Blocker 6 — CLOSED

The closure bar was: on the real Canary-shaped path, N authorized reservations must imply at most N
physical side-effect-bearing tool POSTs; N+1 must be denied with zero N+1 POST; no transparent
retry; a unique attempt identity per authorized tool effect; auxiliary traffic excluded from the
effect count — all under concurrency and ambiguous transport failure. Each clause is now mechanically
proven:

| Clause | Evidence |
|---|---|
| No transparent retry | `RetryMode`/`RetryDisabled` in `internal/mcp/upstreamclient`; `newProductionUpstreamClient` builds from `RetryFreeLimits`; `TestRetryFree_ExactlyOnePhysicalSendOnAmbiguousDrop`, with `TestRetryDefault_ControlMultipleSendsOnAmbiguousDrop` proving the same peer shape DOES re-send under the historical defaults |
| N reservations ⇒ ≤ N physical POSTs | `TestConc01` (equality at capacity), `TestConc02` (over-subscribed), `TestHTTPSE2E_BudgetBoundsPhysicalPOSTs` — all counted AT THE CONTROLLED PEER, not at a Go seam |
| N+1 ⇒ zero N+1 POST | `TestHTTPSE2E_BudgetBoundsPhysicalPOSTs`, `TestHTTPSE2E_GateDenialSendsNoBytes` |
| Unique attempt identity per effect | `TestHTTPSE2E_EachPOSTCarriesADistinctAttemptID`, `TestConc03`; a reservation bound to two attempts is now NAMED as a breach (`RecoveryReport.ReservationBreaches`, `TestRedTeam08`) |
| Auxiliary traffic excluded | `upstreamclient.ClassifyMethod`; `TestHTTPSE2E_AuxiliaryTrafficIsNotMetered`, `TestRedTeam13`, with an unknown method failing CLOSED as side-effect-bearing |
| Under ambiguous transport failure | `TestHTTPSE2E_AmbiguousDropIsStillExactlyOnePOST`, `TestRedTeam01`, `TestRedTeam14` |

The measurement is at the WIRE deliberately. Every pre-existing live-tier E2E counted invocations at
the `UpstreamCaller` interface, which measures what the executor INTENDED to send; the retry loop
lives below that seam, so an interface-level counter reads 1 while the peer is POSTed twice.

**Charging each attempt to the budget remains REJECTED** as a closure route, unchanged from the
frozen review: it bounds the count but lets three retries of one logical reservation consume the
whole experiment, destroying the exactly-N-invocations witness invariant.

### Blocker 8 — OPEN (narrowed)

    internal durable truth / recovery / reconciliation: COMPLETE
    production authoritative witness integration:        REMAINS

Complete: a terminal `PhaseOutcome` on every one of `runExecute`'s exit paths (previously one — the
success path); a durable `PhaseSendIntent` committed before the irreversible send and after the
budget reservation; orphan derivation from the durable stream alone with no second ledger; a typed
witness contract that takes FACTS and derives the verdict, never a caller-supplied boolean; and
append-only reconciliation evidence in the same event stream.

Not complete, and the reason this stays OPEN: **the authoritative production witness adapter is
intentionally unwired.** It belongs to the controlled-upstream work (blocker 1). Until it exists, a
post-send crash resolves to `reconciliation_required` — the correct conservative answer, but not a
determinate one, which is what the closure bar asks for.

Note that "every normal path emits `PhaseOutcome`", "orphan recovery exists", and "the local
controlled witness reconciles correctly" are ALL true here and are explicitly NOT sufficient for
closure.

### One defect found and fixed while proving the above

The terminal outcome event carried no `DecisionRef`. `model.Event.Validate` requires one, so the
event was rejected — and because the outcome commit is deliberately best-effort (it must never block
a response for work that already happened), the record simply vanished. Every unit test passed
throughout, because they commit through a sink that does not validate.

The consequence was blocker 8's failure mode reintroduced by the mechanism meant to close it: on
restart, EVERY completed execution looked exactly like a crash, so the one signal that means "a
physical invocation's fate is unknown" was also produced by the success path.

This is now a permanent proof rule for this program:

> Any security-critical evidence test used to close blocker 8 must exercise the REAL validator
> and/or read the committed record back from the REAL spool. A permissive fake sink is useful for
> unit isolation; it is NOT proof of durable evidence truth.

### Durability of the new evidence across a version rollback

The attempt-identity and physical-send fields, and the reconciliation sub-fact, are covered by the
canonical digest. Writing them under the pre-existing schema stamp made every such record
**unreadable to a build that predates them**: that build drops the fields it does not know,
recomputes a different digest, and reports the record as SPOOL CORRUPTION — the condition that means
tampering or disk damage — aborting recovery. An ordinary version rollback would have raised the
wrong alarm and stopped the node reading its own ledger.

Two changes, following the existing v2 (Shadow) precedent exactly:

* the shapes are stamped `SchemaVersionV3`, derived from the assembled event so the version can
  never disagree with what is about to be digested, and paired in BOTH directions by validation
  (attempt evidence requires v3; a v3 stamp requires attempt evidence). Records carrying none of the
  new fields stay v1, so no pre-existing digest moves;
* recovery reads the version from the ALREADY-AUTHENTICATED plaintext **before** the strict decode
  and the digest check, both of which structurally cannot pass on a newer record. The posture is
  unchanged — the partition is still held degraded, and a node must not serve from a ledger it
  cannot read — but the reason an operator acts on changes from "record event invalid" to
  "unsupported schema version": roll the binary forward, rather than suspect the disk.

Proven end to end by forging a record that is cryptographically intact, chain-consistent, and of an
unknown version (`TestAttemptV3_ARollbackReportsASchemaFaultNotCorruption`), with a control proving
the forge itself is sound when the version IS supported, and mutation M30 restoring the old ordering.

**Residual, stated plainly:** a binary built BEFORE this change still reports corruption when it
meets a v3 record, because its strict decoder rejects unknown fields before any version check. That
is not fixable from here — already-shipped readers cannot be changed — and it is inherent to strict
decoding plus an intrinsic digest; the v2 Shadow change carries the identical property. What is
fixed is every rollback from this build forward.

### Two further evidence-truth corrections

**A peer that answers badly has still run the tool.** Receipt was inferred from a successfully
DECODED response, so a non-200, an unreadable body or undecodable bytes — all of which arrive as a
nil response plus an error, the same shape a dial failure produces — were recorded as
`may_have_been_sent`. Conservative, but false: response headers arrived, so the side effect has
already happened, and the attempt was being sent for witness reconciliation with nothing left to
establish. The transport now carries the observed-response fact out with the error
(`upstreamclient.ResponseObserved`). This only ever moves uncertainty DOWN a step real evidence
supports; `definitely_not_sent` stays reachable only before the call begins.
Gates: `TestHTTPSE2E_AnUnusableAnswerIsStillAnAnswer` with
`TestHTTPSE2E_AFailureBeforeTheAnswerStaysUncertain` as its control; mutation M31.

**`Outcome.Executed` stays derived from the send state — a proposed change was REJECTED.** Deriving
it from the terminal disposition instead reads better locally (`executed=true` beside a "blocked"
execution state looks contradictory), but it writes `executed=false` into the durable record for
invocations that demonstrably reached the peer — an ambiguous transport failure, and a DLP block
after the peer answered, are both dispositionally not-executed and in both the tool HAS run. That is
precisely the conversion this work exists to prevent. The apparent contradiction is the design:
`Decision.ExecutionState` is CULVERT's disposition, `Outcome.Executed` and `PhysicalSendState` are
the PEER's reality. Pinned by `TestOutcomeTruth_*` (with the boundary-refusal control proving the
flag is not simply hardcoded true) and mutation M28.

### Two more, from the round after that

**Definitive absence needs a binding that matches.** The witness-binding check guarded only the
"observed exactly once" branch, so a witness reporting a COMPLETE view of a DIFFERENT reservation,
server or method — containing zero invocations — resolved the attempt to `reconciled_not_received`.
That is not contradictory evidence but INAPPLICABLE evidence, an answer to a question nobody asked,
and it was invisible downstream because `ReconcileOrphan` records the orphan's OWN reservation on
the evidence, so recovery's binding check compared a value against itself. The verdict for a
mismatch is `reconciliation_required`, deliberately NOT a conflict: a conflict asserts a breach of
the exactly-once invariant, and zero observations of some other authorization is no evidence of a
breach — reporting one would manufacture an alarm from inapplicable data, the mirror of
manufacturing absence, and would be the easier direction for a misdirected witness to trigger.
Gates: `TestReconcile_DefinitiveAbsenceRequiresAMatchingBinding` (with the matching-binding control)
and `TestReconcile_MismatchedAbsenceIsNotReportedAsAConflict` (with the observed-once control);
mutation M32.

**A rejected redirect is still an answer.** `net/http` returns a non-nil response together with an
error in exactly one case — `CheckRedirect` refused — which is the retry-free client rejecting a 3xx.
The peer answered, so the send state is `peer_response_received`. Both facts had to move together:
leaving `preResponse` true told the retry classifier nothing had been received yet, which under the
DEFAULT (retrying) limits would authorize re-sending an idempotent request the peer had already
answered. Gate: `TestHTTPSE2E_ARejectedRedirectIsStillAnAnswer`, which also asserts the peer saw
exactly one POST; mutation M33.

### Three more, from the round after that

**"Exactly one" needs the same completeness proof "never happened" does.** Requiring it for absence
but not for receipt was an asymmetry with a real consequence: `reconciled_received` is DEFINED as
exactly one and is treated as RESOLVED, so a partial view containing one invocation settled an
attempt whose duplicate simply lay outside the observed set — hiding the precise thing blocker #6
exists to detect. A duplicate is still a conflict at any completeness (a duplicate seen is a
duplicate, and a wider view could only find more), which is pinned separately so completeness can
never become a way to downgrade an observed breach. Gate:
`TestReconcile_ExactlyOneNeedsTheSameCompletenessProofAsAbsence`; mutation M34.

**Not contradicting is weaker than applying to this attempt.** The binding check treated an EMPTY
LOCAL value as agreement, so a legacy or nil-gate orphan carrying no durable `ReservationID` could be
resolved by a witness view scoped to some other authorization: nothing contradicted, but nothing
corroborated either. The two tests are now distinct — `bindingContradicts` (both sides name it,
differently ⇒ conflict) and `bindingCorroborated` (every dimension the witness names is confirmed by
a matching non-empty local value ⇒ required for ANY resolved verdict, in either direction). Gate:
`TestReconcile_AnUnboundOrphanCannotBeResolvedByAnotherAuthorization`; mutation M35.

**Reconciliation evidence for a settled attempt was discarded.** Only the orphan branch consulted the
index, so a witness saying "never received" beside an outcome recording that the peer ANSWERED was
reported as a clean settled attempt — one of two authoritative claims about the same physical effect
silently dropped, reachable whenever a late terminal outcome races an orphan reconciliation. It now
fails closed on a binding mismatch, on a witness-observed duplicate, and on either direction of
contradiction; `reconciliation_required` asserts nothing and agreement is just corroboration. Gate:
`TestRecovery_ReconciliationAgainstASettledAttemptIsNotDiscarded`; mutation M36.

### Two more, from the round after that

**Idempotence must key on identity, not just verdict.** A repeated reconciliation record was
deduped on `Result` alone, so a second record agreeing on the verdict but naming a DIFFERENT
reservation or generation was discarded at index time — before the binding rule downstream could
ever see it. Two records under one attempt id describing two authorizations is the ledger fault
whatever verdict they share. Gate:
`TestRecovery_RepeatedReconciliationMustAgreeOnIdentityNotJustVerdict`, with controls proving a
genuinely identical repeat is still idempotent and an unresolved record is still superseded;
mutation M37.

**Two states prove non-receipt, not one.** The contradiction check tested
`== definitely_not_sent`, but `reconciled_not_received` is equally a positive proof that the peer
was not reached — so a ledger asserting BOTH receipt and definitive non-receipt passed as cleanly
settled. `MayHaveReachedPeer()` is the predicate that owns the distinction, and a settled outcome
always carries a valid state, so its false branch is exactly "proven not reached" rather than
"unknown". Gate: `TestRecovery_ReceiptAgainstEitherProvenNonReceiptFailsClosed`; mutation M38.

### Three more, from the round after that

**Auxiliary traffic was admitted through the side-effect gate.** `openAttempt` refuses to mint an
attempt identity for lifecycle and discovery methods, and its own comment states the contract — such
traffic "must never consume an execution reservation or inflate the physical-effect count". The
composition-layer gate ran ABOVE that check, unconditionally, so the contract held for the durable
intent and not for the reservation it names. Both directions were wrong: the production gate
validates tool trust against a tool binding auxiliary traffic does not have and REFUSES, so an armed
Canary node could not complete a session handshake or list tools; a gate that admitted instead
permanently spent a Canary slot on a call that can cause no side effect, and `MaxTotalExecutions`
stopped measuring physical invocations. Admission now consults the SAME fail-closed classifier
`openAttempt` uses, whose default is side-effect-bearing, so an unclassified method is metered rather
than exempted. The boundary is unchanged: tool freshness and the FINAL emergency-kill re-read read
authoritative state directly, not through the gate, so they still run for every method. Gates:
`TestAuxiliaryTraffic_NeverReachesTheSideEffectGate` and `TestAuxiliaryTraffic_SurvivesARefusingGate`,
with `tools/call` controls on both fixtures and `TestUnclassifiedMethodIsStillMetered` for the
fail-closed direction; mutation M39.

**A resolved verdict was committable against facts that deny it.** The durable validator checked only
enum membership, so a record claiming `reconciled_not_received` while reporting one observation and
no completeness proof could be persisted — and recovery TRUSTS the stored result rather than
re-deriving it, so contradictory or incomplete witness data became definitive knowledge. Each
resolved verdict is now constrained to exactly what `deriveReconResult` requires to reach it: absence
needs zero observations AND a completeness proof, receipt needs exactly one AND a completeness proof.
`reconciliation_required` asserts nothing and stays unconstrained; `reconciliation_conflict` stays
unconstrained deliberately, since it is reachable both from a duplicate and from a single observation
whose binding contradicts the intent, and refusing to record a breach is a worse failure than
recording one whose count looks unusual. Gates:
`TestReconciliation_ResolvedVerdictNeedsACompletenessProof`,
`TestReconciliation_ResolvedVerdictMustMatchItsCount`, with the well-supported control and the
explicit conflict-is-unconstrained gate; mutation M40.

**Unmatched reconciliation evidence was never examined.** `deriveAttempts` iterates INTENTS, so a
reconciliation record whose `AttemptID` matched no intent was read by nothing: recovery returned a
clean, EMPTY report while the ledger held an authoritative claim about an invocation no durable
authorization covers. That is the same fault the terminal-outcome rule already refuses, and the same
silence this path exists to remove. Gate:
`TestRecovery_ReconciliationWithoutAnIntentFailsClosed`, including the dangerous shape where a
healthy attempt makes the report look populated, plus a matched-record control; mutation M41.

### One from the round after that, recorded rather than fixed

**The unmatched-record rules assume an unreclaimed ledger.** Both sweeps in
`deriveAttempts` — the terminal-outcome one and the reconciliation one added above — read an
unmatched record as a ledger fault. That is sound only for a COMPLETE ledger, and the spool does not
guarantee one: send intents, terminal outcomes and reconciliation records are all `CritOrdinary` and
therefore all land in P-ORD, and reclamation deletes whole sealed P-ORD segments oldest-first with no
relational retention. A legitimately retained SUFFIX can hold a record whose intent was reclaimed,
and these rules would call that corruption.

The two are not equally exposed, and the one Codex flagged is the safer: nothing in production
commits a `PhaseReconciliation` event while the authoritative witness adapter stays unwired, whereas
outcomes have a producer on every executed attempt — so the OUTCOME sweep is the reachable one, and
it was not flagged.

**Deliberately not resolved here.** Distinguishing "reclaimed" from "unauthorized" needs information
the read seam does not carry — a retention floor or a tombstone — and no in-band ordering argument
recovers it, because reclamation removes a PREFIX: if an intent was reclaimed then every surviving
record is newer than it, which is consistent with both explanations. Adding that capability is spool
work belonging to the witness integration, and weakening the rules to a report would trade a
detection that catches an invocation with no durable authorization for an availability property no
caller needs yet — `RecoverAttempts` has NO production caller.

**This is now a named precondition of blocker #8's remaining work:** wiring `RecoverAttempts` into
production requires closing it first, by relational retention (never reclaim an intent while later
records for its attempt survive) or a retention floor on `EvidenceReader`. Pinned by
`TestRecovery_UnmatchedRecordRulesAssumeAnUnreclaimedLedger`, whose failure message says so.

### Three from the round after that, two of which hid each other

**An unanswered POST could never be reconciled, and two independent defects caused it.**
`settledReconOK` rejected `reconciled_not_received` whenever `MayHaveReachedPeer()` was true — but that
is the CONSERVATIVE predicate and answers true for `may_have_been_sent`, which is uncertainty, not
receipt. Separately, `ReconcileOrphan` gated on `State != AttemptReconciliationRequired`, which reads
"settled" as "known" — two different questions, since an upstream POST that ends without a response
settles as `may_have_been_sent` whose own `ReconciliationRequired()` answers true. So the single most
important case a witness exists for was both un-askable and, had it been asked, un-recordable. Fixing
either alone leaves it unresolvable, which is why the gate is end-to-end
(`TestReconcile_AnUnansweredPostIsResolvableEndToEnd`).

`PhysicalSendState.ProvesReceipt()` is now the positive predicate and is deliberately **NOT** the
negation of `MayHaveReachedPeer()`: the middle ground — neither proven-received nor
proven-not-received — is real and is exactly what a witness resolves. Collapsing the two would
silently re-break this case, so the distinction is pinned structurally
(`TestPhysicalSendState_ProvesReceiptIsNotTheNegationOfMayHaveReachedPeer`). The gate is now
`RecoveredAttempt.NeedsReconciliation()`, which also refuses in the OTHER direction: once a witness
has RESOLVED an attempt, asking again can only move knowledge backwards — an outage answers
`reconciliation_required`, the append-only ledger rightly refuses that downgrade, and the query would
turn a healthy resolved attempt into a recovery failure. Mutations M42 and M43.

**A rule made its own correct answer unrecordable.** `deriveReconResult` deliberately answers
`ReconRequired` for a malformed (negative) witness count, but the producer copied that count onto the
evidence and the round-6 validator rejects a negative count for EVERY verdict — so the documented
fail-closed record could not reach the append-only ledger at all. The count is now omitted rather
than recorded as a falsehood; the record still names the witness and still resolves nothing, which is
exactly what is true. Pinned from both sides — producer
(`TestReconcile_AMalformedCountYieldsACommittableRecord`) and the real validator
(`TestReconciliation_TheFailClosedRecordIsCommittable`, with the negative count still refused as its
control). Mutation M44.

**Two tests that pinned these defects were rewritten, not deleted.** The fail-closed table in
`TestRecovery_ReconciliationAgainstASettledAttemptIsNotDiscarded` listed "not_received against an
ambiguous send" as a contradiction; it is now a RESOLUTION control on the same fixture.
`TestReconcile_SettledAttemptIsRejected` asserted that any settled attempt is refused; it is now
`TestReconcile_GateIsUnresolvedKnowledgeNotSettledness`, which pins both directions of the corrected
gate plus an unreconciled-orphan control.

### One from the round after that: a verdict may not understate its own facts

**A duplicate could be recorded as "asserts nothing".** Round 6 constrained the two
RESOLVED verdicts against their facts and deliberately left `reconciliation_required`
unconstrained, because it asserts nothing. But observing more than one matching invocation
is a definitive exactly-once breach at ANY completeness — a rule this review already
states — so a record reporting `count > 1` under `reconciliation_required` is not
"asserts nothing", it is a breach wearing a shrug. And `reconciliation_required` is the one
verdict `settledReconOK`'s switch ignores entirely, so recovery reported the attempt
cleanly settled while its own facts recorded the duplicate physical effect the whole
mechanism exists to detect.

Fixed in BOTH directions, because the read side is the one that matters more: the durable
validator refuses to commit `count > 1` under any non-conflict verdict, and
`effectiveReconResult` refuses at READ time to let a stated verdict understate its own
facts. The read-side guard is not redundant — the spool's read path runs the schema and
shadow checks, **not** the full `Event.Validate` — so a record from an importer, an
alternate producer or an older binary is read back and trusted. The conflict direction is
NOT re-constrained: it still accepts any count, since it is also reachable from a single
observation whose binding contradicts the intent. Gates:
`TestReconciliation_ADuplicateMustSayConflict` and
`TestRecovery_ADuplicateIsNotSilencedByAWeakerVerdict` (settled and orphan shapes, with a
single-observation control proving the fix did not start calling everything a conflict).
Mutations M45 and M46.

### Two from the round after that: the read path had to mirror the whole validator

Round 9 documented the read-path asymmetry — the spool's read path runs the schema and
shadow checks, **not** the full `Event.Validate` — and then defended exactly ONE rule
against it. Both round-10 findings are the rest of that bill.

**An unsupported RESOLVED verdict was trusted on the read path.** A record claiming
definitive absence with an observation in it, or receipt without exactly one, or either
without a completeness proof, bypasses commit-time validation and was returned unchanged;
`orphanFrom` then converted it into definitive non-receipt — manufacturing certainty, the
one thing this engine must never do. `effectiveReconResult` is now the read path's mirror
of `validateVerdictAgainstFacts`, folding in ONE direction per rule: a duplicate is
UPGRADED to conflict, an unsupported resolved verdict is DOWNGRADED to
`reconciliation_required`. Gate: `TestRecovery_ReadPathMirrorsTheDurableValidator`, five
unsupported shapes with supported controls in both directions. Mutation M47.

**Idempotence compared the stated string, not the knowledge.** Two records can share an
attempt, an authorization and a verdict while carrying materially different FACTS — a
`reconciliation_required` reporting zero observations, then another reporting TWO. The
second was dropped as a harmless repeat *before* the fold could upgrade it, so a duplicate
physical invocation was silenced one layer above the guard that exists to catch it. Both
sides are folded before comparison now, so a record is dropped only when it adds nothing,
and an observed duplicate cannot be walked back by a later weaker record. Gate:
`TestRecovery_IdempotenceComparesKnowledgeNotTheStatedString`. Mutation M48.

**Test fixtures were corrected, not the rule.** Several fixtures built resolved verdicts
carrying no supporting facts — records that could never have been committed — and the fold
correctly degrades them. `reconFacts` now fills the facts that support a verdict, so those
tests measure the rule under test rather than the fold.

### And two more of the same class, on the record SHAPE

Rounds 9 and 10 mirrored the durable validator's VERDICT rules on the read path. Round 11
is the same asymmetry applied to the record SHAPE, and both findings corrupt attempt
derivation rather than merely looking odd:

- **Outcome evidence smuggled onto a reconciliation record.** `Event.Validate` rejects the
  combination outright, but the indexer dispatched on phase and dropped the outcome on the
  floor — so a SUPPORTED `reconciled_not_received` carrying an embedded
  `peer_response_received` outcome was reported as definitive non-receipt with the
  contradictory receipt silently discarded.
- **A terminal outcome with no `DecisionRef`.** The validator requires one on every
  outcome, because an outcome never replaces the pre-execution decision commit. Without
  it `settledFrom` still settles the attempt and suppresses reconciliation, closing out a
  physical effect with no link to the decision that authorized it.

`readPathAttemptRulesOK` mirrors both at the indexer's entry. **Its scope is stated rather
than implied**: it is a mirror of specific COUPLING rules, not a call to `Event.Validate`.
Running the full validator there would reject records for reasons unrelated to attempt
derivation (capability, criticality, decision fields) and turn recovery — the thing an
operator runs to find out what happened — into a hard failure over an unrelated field. The
bar for mirroring a rule is that its absence makes the derived answer WRONG. Gate:
`TestRecovery_ReadPathMirrorsTheStructuralCouplingRules`, both violations plus two
controls — well-formed records of both shapes still recover, and a SEND INTENT may still
carry outcome evidence (the coupling rule is phase-specific; a blanket "outcome evidence
only on PhaseOutcome" rule would break every intent). Mutation M49.

### Three more, closing the coupling rules symmetrically

Round 12 answered the questions the round-11 request put, and all three answers were yes:

- **The coupling was one-directional.** Round 11 rejected outcome evidence on a
  reconciliation record; `Event.Validate` rejects reconciliation evidence on EVERY
  non-reconciliation phase. A `PhaseOutcome` carrying an embedded
  `reconciliation_conflict` was indexed as an outcome with the conflict dropped — a
  duplicate physical invocation reported as a cleanly settled attempt.
- **`DecisionRef` was checked for EMPTINESS, not validity.** `"decision_1"` names no
  committed decision any more than `""` does, and `settledFrom` would close the attempt on
  the strength of it. The rule is now mirrored through `model.ValidDecisionRef`, an
  EXPORTED predicate over the writer's own `checkID`, rather than a second copy of the
  prefix/body/charset/length checks — a drifting mirror is worse than no mirror, because
  it looks enforced. `TestValidDecisionRef_IsTheSameRuleValidateApplies` asserts the
  predicate and `Validate` agree on the same input.
- **`PhysicalSendState` was uncoupled from the phase.** A send intent is committed BEFORE
  the call begins and cannot know a send state — "in flight or interrupted" is precisely
  the absence of a terminal outcome — yet a v3 intent claiming `peer_response_received`
  validated, and recovery then dropped the claim on the floor. The inverse was also open:
  an attempt-bearing outcome could carry an unset or unknown state, which does not fail at
  commit but much later inside recovery, on an attempt whose physical effect is already
  done. Both directions are now enforced at the writer. Mutations M50-M52.

### And the rule that should have been written that way three rounds ago

Round 13 found the SAME coupling leaking a third time — a `PhaseRecoveryMarker` or
`PhaseHealth` record carrying an attempt-bearing outcome, which recovery dispatches past
without indexing, leaving a send intent reported as an unresolved orphan while the ledger
holds its `peer_response_received` terminal outcome — plus the round-12 send-intent
send-state rule, added at the writer and not mirrored on the read path.

**The lesson is the shape of the rule, not the two shapes reported.** Reconciliation
evidence has had a GLOBAL coupling check since it was introduced; outcome evidence was
policed only by the phases that happened to look for it, so each round closed one more
forbidden phase. Both couplings are now stated ONCE over their **allowed set** — outcome
evidence on `PhaseOutcome` or `PhaseSendIntent`, reconciliation evidence on
`PhaseReconciliation` — at the writer AND on the read path. A rule written that way holds
for phases nobody has written yet.

The gates are enumerations over ALL phases rather than the reported shapes
(`TestRecovery_PayloadCouplingIsStatedOverTheAllowedSet`,
`TestValidate_OutcomeEvidenceCouplingIsStatedOverTheAllowedSet`), so adding a phase
without deciding which payloads it may carry now fails a test. Mutations M53-M55.

**Convergence note, recorded honestly.** Rounds 9-13 are one class: the spool read path
validates less than the commit path, so a record NO PRODUCTION PRODUCER EMITS could be read
back and trusted. They are real and worth closing, and round 12-13 moved part of the rule
to the writer where it belongs — but they are defense-in-depth for the future witness
integration rather than defects in the shipped path. Nothing commits a `PhaseReconciliation`
event today and `RecoverAttempts` has no production caller.

### Round 14: back on the live path, and one deployment prerequisite

**A local refusal is not an ambiguous send.** `sendState` is set to `may_have_been_sent`
immediately before `Upstream.Call`, which is right for anything that can put bytes on a
wire — but `Call` refuses some invocations before any leg begins: method not admitted, an
invalid target, pool admission refused, an endpoint that will not canonicalize, a resolve
failure, a request that will not build. Recording those as ambiguous was conservative but
FALSE, and it cost twice: the durable outcome claimed `executed` for an invocation that
never happened, and the attempt was routed to witness reconciliation with nothing to
establish.

`preResponse` could not serve as the signal and that is the subtle part — a DNS resolve
failure sets it and sent nothing, while a peer that reads the whole request and hangs up
also sets it and demonstrably did. The client now carries a distinct `neverSent` fact out
on the error (`SendNeverStarted`), the mirror of `ResponseObserved`, and like it the fact
is **absent by default**: an unmarked error — from a path nobody classified, or a test
double — keeps the conservative state. That is the CONTROL
(`TestPhysicalSendState_AnUnmarkedFailureStaysAmbiguous`), and both gates read the
DURABLE record rather than the ExecOutput, because `ExecOutput.Executed` is Culvert's
disposition while `Outcome.PhysicalSendState` is the peer's reality. Mutation M56.

**A deployment prerequisite, promoted from a recorded residual.** §25a already recorded
that a binary built BEFORE the v3 change reports `event_spool_corrupt` when it meets a v3
record, because its strict decoder rejects unknown fields before any version check. What
was recorded as a residual is really an **ordering requirement**: a forward-compatible
(peek-first) reader must be deployed to every node that could perform recovery BEFORE any
release starts writing v3 records. Rolling back past that reader turns a schema fault into
a corruption alarm on a healthy ledger. No code change can reach already-shipped readers —
the only lever is ordering, and it now says so where an operator will read it.

### Round 15: a Call is not a leg

**`neverSent` is a whole-Call fact, and it was being reported per leg.** Round 14 added the
never-sent fact so `definitely_not_sent` becomes reachable only from positive evidence. Round
15 found the fact escaping at the wrong granularity: `Client.Call` owns a retry loop, and
`lastErr` was overwritten each iteration, so whichever leg failed LAST spoke for the whole
Call.

The reachable sequence is ordinary rather than contrived, and both halves of it already
existed in the code. Leg 1 is read in full by the peer and then fails before a response —
transport.go's `preResponse` leg, which is exactly the `(idempotent, preResponse)`
classification that AUTHORIZES a re-send. A later leg fails at resolve, and transport.go
marks that leg `{preResponse: true, neverSent: true}`: retry-classified AND
certainty-claiming at the same time. `SendNeverStarted` then reported true for a Call whose
first leg demonstrably put an invocation on the wire, and `run.go` turned that into
`definitely_not_sent` — `MayHaveReachedPeer()` false, `Outcome.Executed` false. Uncertainty
converted into `executed=false`, which is the one conversion this accounting exists to
prevent.

`foldLegFacts` aggregates across legs, and the two facts fold in OPPOSITE directions because
each direction is the conservative one. `responseObserved` is a **disjunction** — any leg
that saw the peer answer proves receipt, and no later leg can un-prove it. `neverSent` is a
**conjunction** — it is the strongest claim in the send-state lattice, the one an operator
acts on by re-running the invocation, so it requires unanimity across every attempted leg.
`preResponse` is deliberately NOT folded: it is a per-leg input to retry classification, not
evidence carried to the caller, and the `retryable()` call site still reads the per-leg
value.

**On the shipped live path this was not reachable**, and that is stated here rather than used
to dismiss it: `RetryFreeLimits` pins the budget to zero and `Call` short-circuits on
`RetriesDisabled`, so a live execution has exactly one leg. It is fixed anyway, because a
per-leg fact escaping as a whole-Call claim manufactures certainty, and that safety must not
rest on one caller's choice of limits. Mutations M57–M59.

### A red race gate that was not this PR's, fixed here anyway

The Fast gate's `-race` job went red with a data race in `TestShadowSoak`. It is **not this
PR's defect** — both racing lines are byte-identical on `origin/main`, and this PR's only
edit to `shadow_soak_test.go` is an unrelated schema-version constant — but it made a
required check red, there was no fix elsewhere to port, and the fix is small, local and
test-only.

`mcpToolTrustCoordinator.now()` reads `nowFn` under `mu.RLock`, and its own comment says
why: *"the background reconcile loop may call it concurrently with a test swapping the
coordinator"*. Two soak helpers assigned the field directly, upholding one half of that
contract. Every other writer in the tree already locks, which is what makes this an
oversight rather than a design question.

The other side is a **goroutine leak**: `newGapEnv` starts a reconcile loop bound to the
process-lifecycle ctx and nothing cancels it when the test ends, so it ticks for the rest
of the binary's life — over a 1365s race run a 30s ticker gets ~45 chances to land inside a
later test's clock swap. **Recorded, not fixed**: giving `newGapEnv` a cancellable lifecycle
is a separate change, and locking the writers closes the race regardless.

**The first draft of the gate passed against the unsynchronised shape**, and was therefore
worthless. It observed ZERO concurrent reads — the main goroutine finished every swap before
the scheduler started the reader. The gate now waits for the reader before swapping and
asserts a non-zero read count, so an overlap-free variant fails loudly instead of passing
vacuously. `run_mutation` also gained a `--race` flag: a mutation whose defect is a data race
is invisible without the detector, so the mutated build passes and scores as a survivor —
the campaign's worst failure mode. Mutation M60.

### Round 17: a mutation must be caught for the RIGHT reason

Round 16 was clean. Round 17 then found the weakness in the `--race` scoring added the round
before — and it answers a question that had been put to the review rather than checked
first, which is the wrong way round.

`run_mutation` scored any nonzero exit as CAUGHT. For an ordinary mutation that is
defensible; for a `--race` mutation it is not, because the entire proof is *the detector
reported it*. `go test` compiles and vets before running, so a build break, a vet failure, a
panic, a timeout, or an **unrelated** race all exit nonzero — and every one of them would
have scored M60 as caught while proving nothing about the lock that was removed.

Scoring for `--race` mutations is now **evidence-based rather than exit-code-based**: the
output must carry a race report, and that report must name the mutated access. Attribution
requires **both** sides of the intended pair — the mutated writer and the guarded reader —
because a single-sided pattern would still admit an unrelated race that happened to touch the
same function.

The attribution pattern had to be discovered rather than guessed: a first attempt matched on
the field name `nowFn`, which never appears in a race report at all. Reports name functions
and addresses, not struct fields, so that check rejected the *real* race as unattributable.

Verified three ways, because a scoring change that cannot reject anything is worse than no
check: the real race mutation scores CAUGHT naming both symbols; a mutation that breaks the
build scores NOT PROVEN; a mutation that fails the test without racing scores NOT PROVEN.
**Both negatives scored CAUGHT before the change.**

### Round 18: the campaign was measuring the compiler

Round 17 tightened `--race` scoring. Round 18 answered the scope question that change left
open — one I had put to the review rather than settled myself — and answered it against me.

The header has always said: *"A COMPILE FAILURE IS NOT PROOF unless the mutation targets a
structural wall whose stated purpose is compile-time prevention. Mutations here are written to
compile and change behavior, so the failure comes from an assertion."* **The scoring never
enforced it.** `go test` compiles and vets before running, so a mutation that fails to build
exits nonzero without any gate having executed, and `run_mutation` counted the bare exit code.
The stated rule and the implementation disagreed — the same class of defect this review keeps
finding in the product, sitting in the instrument used to measure the product.

Default is now: a build or vet failure scores **NOT PROVEN**. A mutation whose proof genuinely
IS the compile failure declares itself with `--compile-wall`, and for it a build failure is
required while anything else is a SURVIVOR.

**Then the change was measured rather than assumed, and it found two mutations that had never
proven anything.**

**M59** was added two rounds earlier, by this work. The `||` in its perl pattern is
ALTERNATION, not a literal, so the pattern carried an empty alternative — which matches at
offset 0. Perl rewrote the TOP OF THE FILE instead of the struct literal
(`observed.go:1:3: expected 'package', found responseObserved`), and the mutation scored CAUGHT
across three campaign runs purely because it corrupted the file. An audit of every mutation
pattern in the script found this is the **only** instance of that hazard.

**M05** blanked `ReservationID` but left `resID` declared and unused, so the package did not
compile and `TestMeteredExecution_` / `TestHTTPSE2E_EachPOSTCarriesADistinctAttemptID` /
`TestConc03_` never ran. It now drops the binding too, so the mutation compiles and the
assertion is what rejects it.

Both were reported CAUGHT by every earlier campaign run in this PR. The tally was honest for
58 of 60; for those two it was measuring the compiler. This is the strongest argument in the
whole review for the rule that a gate must be run against the shape it claims to reject —
**a mutation campaign measures the gates, and a mutation that does not compile measures
nothing.**

### Round 19: the fix for round 18 had two holes of its own

**The build-failure check could not fire on a large build failure.** `set -o pipefail` is on,
and every search of captured output used `printf '%s' "$out" | grep -q`. `grep -q` exits at the
first match, `printf` then dies of SIGPIPE (141), and pipefail reports the PIPELINE as failed
even though the pattern matched. All four uses were mis-scoring, each in a different direction:
a matched build failure did not set `build_broke` (so it scored CAUGHT), a matched
"no tests to run" did not raise BROKEN GATE, a matched race report read as "no race reported",
and a matched attribution symbol read as missing.

Compiler output begins with the `# github.com/KidCarmi/...` header, so the match is at the
FRONT — the worst case for this bug. Demonstrated rather than argued: a 460 KB output of exactly
that shape gives `build_broke=0` through the pipe and `1` through a herestring. `has_re` /
`has_fixed` now feed grep from a herestring, which has no producer to kill, so the exit status
is grep's alone.

**The rule was enforced in one place and not the other.** M02 and M17 must drive `go test`
themselves (M02 removes two independent enforcement points; M17 is the two-sided proof-rule
demonstration), and both scored a nonzero exit as CAUGHT with no build check — the exact defect
round 18 had just fixed inside `run_mutation`, still live one function away. `build_or_vet_failed`
is now a shared helper used by all three, and M17 applies it to BOTH sides it drives.

This is the second consecutive round in which the instrument, not the product, was wrong — and
the second in which a fix introduced the shape it was fixing. That is worth recording plainly:
the campaign is the evidence this review rests on, so a defect in it is not a lesser class of
defect.

### Campaign state

`scripts/mcp-canary-mutation-campaign.sh` now carries **60 mutations: 60 caught, 0 survived, 0
skipped, 0 not-proven** — every one rejected by a named assertion, the race mutation by an
attributed detector report, and none by a build failure. Each reintroduces one specific defect and must fail a NAMED gate; a compile failure is
not counted as proof unless the mutation targets a structural wall whose purpose is compile-time
prevention, a gate matching no tests is a hard campaign failure, and a mutation whose pattern no
longer matches the source is scored as a FAILURE rather than a pass.

That last rule earned its keep SEVEN times, every one of them against a fix made *inside this work*.
M03, M04 and M12 drifted against refactors done here — the `runExecute` decomposition made to satisfy
the complexity linters, and the `RecoverAttempts` split. M20 drifted against the binding fix above,
in the very same file the mutation M32 targets. M45 drifted when round 11's checks were folded into
one helper, M50 when round 13 restated a coupling over the allowed set and flipped the operand, and
M31 when round 14 renamed `markResponseObserved` to `markLegFacts`. A campaign that scored a skip as
a pass would have reported a clean run over seven dead gates — and the last three would have gone
dead in exactly the rounds that were hardening the code they measured. The rule is not defensive
tidiness: a mutation campaign measures the GATES, and a pattern that no longer matches measures
nothing at all.

---

## §26 Final verdict

### `FIRST CONTROLLED CANARY REVIEW: BLOCKED — NO SAFE FIRST CANARY TARGET`

The Canary core is fail-closed across scope, trust firewall, budget ceiling, per-request kill
re-read, restart re-arm/allowance, and no-secret evidence. But a safe first experiment cannot be
assembled today on **fifteen independent blockers** — some are intentional capability gaps, some are
prerequisites, and two are genuine product defects the Codex adversarial rounds (§24) surfaced and
this review verified against the code. The list below is exhaustive AS A SET: together the fifteen cover
every mandatory NO/CONDITIONAL row in §25, so closing ALL of them is necessary and sufficient to pass
§25 — but the mapping is grouped, not strictly 1:1 (e.g. §25's independent-witness row folds under
blocker 7's auto-abort and also depends on blockers 1 and 6).

**Post-adoption status (see §25a).** The baseline remains **fifteen**; the list below is preserved
as adopted. Exactly two entries have changed status since: **blocker 6 is CLOSED**, and **blocker 8
is narrowed but still OPEN**. Thirteen are untouched, and the verdict above is unchanged — closing
blocker 6 removes one of fifteen reasons a GO is forbidden, not the prohibition.

1. **No controlled upstream reachable AND usable under the supported production trust model (§5).**
   The only documented controlled inventory fails closed on scheme (`mcp+https://`), host (private
   `*.qual.svc`), and identity (SPIFFE). No public-HTTPS controlled MCP server with a base64 SHA-256
   SPKI pin, a plain `https://` endpoint, and one harmless read tool is provisioned. And even a
   provisioned target may be UNUSABLE: the client sends no MCP `initialize` handshake / version
   negotiation / protocol+session headers, so a spec-compliant server would reject the sessionless
   `tools/list`/`tools/call` — closing this also needs a target that permits sessionless calls OR a
   Culvert-side upstream lifecycle implementation.
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
6. ~~**The budget does not bound physical upstream invocations (§9).**~~ **CLOSED** — see
   "Blocker 6 closure" below. Idempotent read retries could send the POST ~3× per single budget
   reservation; the Canary path is now retry-free and the bound is proven at the wire.
7. **Whole-Canary auto-abort is incomplete (§14/§16) — a product defect.** Only
   `budget_exhausted`/`scope_escape` auto-trip; the other eight declared breaches do not, and nothing
   reconciles the independent witness — so a divergence would not auto-stop later requests.
   **The time-box is not self-enforcing either (Codex round 31).** `budget_exhausted` has exactly ONE
   production trip site (`mcp_canary_runtime.go:391`), reached from `reserveCanaryExecution`, and
   `BudgetDeniedWindow` is produced only by `BudgetEnforcer.Reserve` (`budget_enforce.go:197`) — both
   REQUEST-DRIVEN. So if no further request arrives after the window elapses, nothing trips: the abort
   controller stays unlatched and the node remains in Canary mode indefinitely. Window expiry is
   therefore an expiry of AUTHORITY TO ADMIT, not an automatic stop. Closing this needs a
   deadline-driven stop/rollback (a timer that demotes without needing another request), or the
   authorization must require explicit operator cleanup and stop describing expiry as automatic.
8. **Durable outcome evidence is incomplete/success-only, with an unclosable post-send crash window
   (§15/§18) — a product defect.** **STILL OPEN, narrowed** — see "Blocker 8 status" below. The
   internal half (terminal outcome on every exit path, durable send intent, orphan recovery,
   typed witness reconciliation) is complete and proven against the real spool; the AUTHORITATIVE
   PRODUCTION WITNESS ADAPTER remains unwired, and until it is, a post-send crash resolves to
   `reconciliation_required` rather than to a determinate answer.
9. **Credential path unresolved (§4).** Credential selection comes from the tool's matched policy
   RULE, not from provisioning a server/tool, and the production broker has ZERO providers, so a
   `CredentialProfile`-bearing rule fails closed at `Broker.Materialize`. Provisioning a target
   (blocker 1) does NOT by itself establish no-credential status; it must be closed explicitly by
   verifying a no-`CredentialProfile` matched rule OR implementing a working credential provider/path.
   A no-`CredentialProfile` rule is NOT sufficient on its own — see blocker 14: the matched rule must
   also be ALLOW-class with satisfiable obligations, or the request is denied anyway.
10. **No operator-reachable graceful rollback (§17).** §17's contract bar is "no GO unless rollback
   AND kill are available." Only the emergency kill is reachable: `quiesceLiveTier` has no production
   caller, and the operator-facing `apiMCPRolloutTransition` returns `distribution_not_configured` for
   a Canary→Shadow/Observe target (the demotion runs only via the unwired signed-distribution path). A
   governed operator-reachable rollback control (wire quiesce, or wire the demotion/publication path)
   must be added.
11. **The reviewed fingerprint is operator-declared, not peer-observed (§7).** The only shipped
   provisioning path (`seedServer`/`seedTools`/`Ingest`, `mcp_inventory.go`) computes the fingerprint
   from operator-supplied JSON and verifies the pinned identity against its own register stamp, and
   `execution.Discovery.Discover` has no non-test caller, so nothing re-observes the live peer.
   `ToolStillCurrent` therefore validates the unchanged local record — "exact reviewed fingerprint" and
   "rug-pull invalidation" bind the SEED, not the actual upstream. Closing this needs authenticated
   production discovery/freshness verification OR an externally-verified ingestion procedure proving
   seeded-fingerprint == the live peer's advertised tool.
12. **No operator-reachable governed Canary ACTIVATION entry point (§13/§17).** Even with arming
   (blocker 3) and the activation inputs (blocker 2) closed, nothing lets an operator TRANSITION the
   node into Canary mode: the admin `apiMCPRolloutTransition` ends with `distribution_not_configured`
   for a Canary target (`ui_mcp_rollout.go:116`), and the only production path that begins the Canary
   generation is the signed-distribution apply, which merely CONSUMES an already-signed snapshot —
   nothing in non-test code constructs the distribution publication coordinator (`publication.New`) or
   calls `coord.Publish` to PRODUCE that snapshot (repo-wide search: callers are test-only; the
   `gw.Publish` at `mcp_policy.go:173` is the gateway *policy* store, unrelated). This is the forward
   twin of blocker 10 (which is the same unwired path in the rollback direction), and it means the
   §25 checklist — wire arming + activation inputs — is NOT sufficient to start the Canary. A governed
   operator-reachable forward-transition/publication entry point must be wired.
13. **The seeded controlled tool is `catalog.Quarantined` and nothing promotes it (§6/§7).** `seedTools`
   lands every inventory tool Quarantined (`mcp_inventory.go:15-17`) — the correct record-only Observe
   disposition — and the policy engine hard-overrides a `DispQuarantined` tool to `ActionQuarantine`
   BEFORE any user rule is evaluated (`internal/mcp/policy/engine.go:132-135`). `ApproveLive`
   DELIBERATELY performs no promotion ("live trust never materializes `catalog.Usable`",
   `mcp_tooltrust.go:413-450`), and the only non-test `catalog.Promote` callers are the shadow
   `promoteFor` path (`mcp_tooltrust.go:536`, `:629`). So even with blockers 1–12 closed and a finer
   read-first classifier (blocker 4), every exact-tool request is hard-denied at the quarantine
   override. Catalog USABILITY must be a mandatory criterion: a `shadow_evaluation` approval (which
   promotes) or another governed promotion path must make the exact tool `catalog.Usable`.
14. **The exact request must resolve to an ALLOW-class decision with satisfiable obligations (§4/§13).**
   Closing the credential condition (blocker 9) by choosing a rule with no `CredentialProfile` does not
   make the request executable: that rule may itself be DENY-class, and if NO enabled rule matches,
   `matchRules` falls through to default-deny (`engine.go:170-173`); `resolveEnforcing`
   (`internal/mcp/rollout/resolve.go:168`) blocks every non-allow-class decision. The preflight's
   `PolicyHealthy` fact is only `mcpPolicy.composed()` (`mcp_canary_preflight.go:83`) — it proves a
   snapshot EXISTS, never that the exact request resolves to an allow. The authorization must therefore
   require the exact (principal, tenant, server, tool, operation) to resolve to an ALLOW-class rule with
   every execution obligation satisfiable.
15. **The one-NODE bound is not enforced by anything (§3/§13).** `ScopeSpec` has no node dimension at all
   (`internal/mcp/rollout/scope.go:100-119`: tenants/servers/tools/principals/agents/clients/groups/
   percent + exclusions — no node selector), and the publication coordinator's `pushAll` delivers the
   signed envelope to EVERY node the distributor lists ("delivers the signed envelope to every intended
   DP", `internal/mcp/cpdp/publication/publication.go:196-203`). So if blocker 12 is closed with a
   GENERIC publication entry point, a single Canary publish activates every armed/ready DP while the
   documented checklist still reads "nodes = 1". **The transport is BROADCAST BY CONSTRUCTION, so
   constraining `Dist.Nodes()` is not enough**: the production `mcpPullDistributor.Push` DISCARDS its
   node argument (`func (mcpPullDistributor) Push(_ string, env *cpdp.Envelope)`) and installs the
   envelope into the CP publication seam "so the next captured ConfigSnapshot carries it to every DP"
   (its own comment, `mcp_distribution_adapters.go:74-88`) — every DP pulls the SAME shared snapshot.
   Limiting the node list would only limit which nodes are counted/acked, never which receive it. And
   `applyMCPCapabilityEnvelope` verifies signature + epoch + revision + bounds with NO intended-node
   check (`mcp_distribution.go:225-245`), so a non-target DP applies and ACTIVATES. An acknowledgement
   check is therefore DETECTIVE, not preventive — the escape has already happened by the time acks
   reveal it. Closing this requires a PREVENTIVE control: a signed node AUDIENCE in the envelope that
   the DP apply path REJECTS when it is not the intended node, or a genuinely per-node delivery
   channel. (Corrected in review round 28 — the earlier "intended node + acknowledgement" remedy this
   review proposed was insufficient for exactly this reason.)

**Why BLOCKED and not FAILED.** The review contract's FAILED verdict is for a specified, assemblable
experiment judged unsafe; BLOCKED is "no safe first canary target." Here, no experiment can even
execute — nothing is reachable (1), the activation preflight cannot go Ready (2), no operator can arm
(3), no admissible one-tool operation exists (4), the seeded tool is catalog-quarantined and hard-denied
before any rule runs (13), and no operator-reachable path even transitions the node into Canary mode
(12). Blockers 5–12, 14 and 15 are unmet *prerequisites*/defects, not a live
unsafe path, precisely because 1–4 mean zero real side effects are possible from this SHA (blocker 11
adds that even a reachable+usable target would carry a fingerprint bound to operator-declared JSON, not
the observed peer). So the
honest label is BLOCKED — a safe first experiment cannot be *assembled* — and the two product defects
(7, 8) must be closed as dedicated PRs before any authorization, reinforcing rather than weakening
that verdict. (Had a target been reachable and a Canary activatable, defects 7–8 would have made the
verdict FAILED.)

**To unblock (each a separately-reviewed change, none performed here):**
- provision a public-HTTPS, non-production, independently-recording controlled MCP server exposing
  exactly one harmless read/discovery tool, registered with a plain `https://` endpoint and its real
  base64 SHA-256 SPKI pin; OR land the recorded connectivity work (endpoint-scheme translation and/or
  an identity-type-aware verifier + a per-target private-destination policy) in a dedicated PR. AND
  ensure the target is USABLE, not just reachable: the client drives no MCP `initialize` handshake /
  version negotiation / protocol+session headers (§5), so either the target must legitimately permit
  sessionless `tools/list`/`tools/call`, or a Culvert-side upstream lifecycle implementation is
  required (a code change);
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
  credential-requiring rule fails closed. This is NOT sufficient alone: the same rule must also be
  ALLOW-class with satisfiable obligations (blocker 14);
- make the exact tool **`catalog.Usable`** (blocker 13, §6/§7) — `seedTools` lands it Quarantined and
  the engine hard-overrides a quarantined tool to `ActionQuarantine` before any user rule runs, while
  `ApproveLive` deliberately never promotes ("live trust never materializes `catalog.Usable`"). Issue a
  `shadow_evaluation` approval (the promoting path) or wire another governed promotion path, and treat
  catalog usability as a MANDATORY criterion — without it every exact-tool request is denied even with
  all other blockers closed;
- require the exact request to resolve to an **ALLOW-class policy decision with every execution
  obligation satisfiable** (blocker 14, §4/§13) — verify the exact (principal, tenant, server, tool,
  operation) matches an enabled ALLOW-class rule; an unmatched request default-denies
  (`engine.go:170-173`) and `resolveEnforcing` blocks every non-allow-class decision. The preflight's
  `PolicyHealthy` fact (`mcpPolicy.composed()`) does NOT prove this;
- impose the exact one-of-everything identity shape as an authorization prerequisite: **exactly one
  `Principals` entry, zero `Clients`/`Agents`/`Groups`, exactly one tool** (or prove the selected
  client/agent maps one-to-one to the synthetic principal). A plain count==1 check is INSUFFICIENT —
  `principalCount` sums Principals+Clients+Agents, so one shared client/agent with no Principals would
  satisfy it while leaving the principal dimension unrestricted; and `ValidateScope` permits up to two
  of each (`MaxCanaryTools`/`MaxCanaryPrincipals` = 2), so the machine gate enforces none of this (§10);
- **[code change]** bound PHYSICAL upstream invocations to the budget AND keep the emergency kill
  authoritative across retries — `upstreamclient.Call` retries an idempotent read up to `MaxReadRetries`
  times outside the single budget `Reserve` AND without re-checking kill/generation between attempts
  (`client.go:132-141`), so one budgeted request can hit the server up to ~3 times (§9) and a retry POST
  can land after an emergency kill (§20). **For this first Canary the ONLY accepted closure is an
  explicitly RETRY-FREE execution path**: make retry-disablement representable and wire a retry-free
  `Limits` into the Canary client — not representable today (`NewLimits` coerces `MaxReadRetries==0`→`2`
  and rejects negatives; `newProductionUpstreamClient` hard-codes `DefaultLimits()`) — so that **one
  logical reservation can produce at most one side-effect-bearing physical tool invocation**. That
  single change closes the count gap AND the kill gap together. **Charging each attempt to the budget is
  NOT an accepted alternative here** (with or without per-attempt kill revalidation): it can spend all
  three slots on one logical reservation and so destroys the exactly-three-invocations witness invariant
  §9/§14 require. A per-reservation correlation key is not a bound at all: it only lets the witness be
  reconciled and (with an upstream dedup protocol) lets the SERVER ignore duplicates — it neither stops
  the retry loop nor re-checks the kill (§14/§20);
- **[dedicated PR]** wire whole-Canary auto-abort for ALL eight remaining declared breaches —
  `out_of_scope_execution`, `tool_fingerprint_drift`, `server_identity_drift`,
  `credential_safety_failure`, `outcome_evidence_loss`, `unexpected_upstream_response`,
  `elevated_error_rate`, `latency_pathology` — plus an automatic witness-reconciliation trip.
  **"A tripper exists" is NOT a closure criterion for the two RATE-based breaches.** `abort.go:72-74`
  defines `elevated_error_rate` and `latency_pathology` only in prose ("over threshold", "sustained")
  and no numeric limit, observation window, or minimum sample size exists anywhere, so an immediate
  single-error trip and an effectively unreachable threshold would BOTH satisfy the wording. This
  matters most at Canary scale: against a tiny budget (single-digit requests) a rate threshold with no
  minimum sample size is either trigger-happy (one error reads as 100%) or never reachable. The
  authorization must therefore name, as explicit reviewed inputs: the numeric limit, the observation
  window, the minimum sample size before the rate is evaluated at all, and the defined behavior BELOW
  that sample floor. **The sample floor MUST be REACHABLE inside the exact First-Canary corpus, or the
  below-floor behavior MUST stop fail-closed (Codex round 33).** With `MaxTotalExecutions=3`, a reviewed
  floor above three combined with a permitted below-floor `no-trip` means NEITHER detector can ever
  evaluate during the experiment — elevated errors or pathological latency would persist for its entire
  duration while the automatic-abort prerequisite was nonetheless recorded as closed. A detector that
  cannot possibly evaluate within the authorized corpus does not satisfy the prerequisite: either
  floor ≤ 3, or below-floor is a fail-closed stop. The same reachability rule applies to the
  witness-reconciliation trip (what counts as a mismatch, and after how many — evaluable within three
  invocations, or fail-closed);
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
- bind the reviewed fingerprint to the OBSERVED live peer (blocker 11, §7) — the shipped provisioning
  (`seedServer`/`seedTools`/`Ingest`) computes the fingerprint from operator-declared JSON and verifies
  the pinned identity against its own register stamp, and `execution.Discovery.Discover` has no non-test
  caller, so `ToolStillCurrent` re-checks only the seeded record. Add authenticated production
  discovery/freshness verification (a non-test `Discover` caller), OR require an externally-verified
  ingestion procedure proving seeded-fingerprint == the live peer's advertised tool, before treating
  exact-current fingerprint and rug-pull invalidation as satisfied. **The ingestion-procedure
  alternative must ALSO carry a freshness guarantee through the side-effect boundary**: it proves
  equality only at INGESTION time, and the runtime drift check re-reads the LOCAL catalog only
  (`runtime.toolHasDrifted` compares the request fingerprint against `Catalog.Current()`,
  `internal/mcp/runtime/execute.go:201-215`) — so a peer that changes its advertised tool AFTER
  ingestion but BEFORE the Canary request is not detected, and the seeded fingerprint still validates.
  Closing blocker 11 by that route therefore additionally requires authenticated re-observation near
  each call, a bounded freshness window, or an equivalent immutable peer attestation; without one,
  "rug-pull invalidates the approval" cannot be claimed.
- wire a **governed operator-reachable Canary ACTIVATION (forward transition) entry point** (blocker 12,
  §13/§17) — arming (blocker 3) and the activation inputs (blocker 2) are NOT sufficient to start the
  Canary: `apiMCPRolloutTransition` returns `distribution_not_configured` for a Canary target
  (`ui_mcp_rollout.go:116`) and nothing in non-test code constructs the distribution publication
  coordinator (`publication.New`) or calls `coord.Publish`, so the signed-distribution apply that begins
  the generation is never fed. Wire a governed forward-transition/publication path (the same wiring that
  closes blocker 10's rollback direction, but for →Canary) — and it MUST target exactly one node, not
  the whole fleet (blocker 15);
- make the **one-NODE bound a PREVENTIVE, apply-time control** (blocker 15, §3/§13) — `ScopeSpec` has
  no node dimension and `publication.pushAll` delivers to EVERY `Dist.Nodes()` entry, so a generic
  publication path would activate every armed/ready DP while the checklist still reads "nodes = 1".
  Constraining the node LIST is not sufficient: `mcpPullDistributor.Push` discards its node argument and
  installs the envelope so "the next captured ConfigSnapshot carries it to every DP"
  (`mcp_distribution_adapters.go:74-88`), and `applyMCPCapabilityEnvelope` has no intended-node check,
  so a non-target DP applies and ACTIVATES before any acknowledgement could reveal the escape. Require a
  signed node AUDIENCE that the DP apply path REJECTS when it is not the intended node, OR a genuinely
  per-node delivery channel. A post-apply acknowledgement check is detective, not preventive, and does
  not close this on its own;

Then re-run this review against the new exact SHA.

**This review did not activate Canary, did not execute any tool, did not arm any production node,
retrieved no credential, and used no production server or customer traffic. Real Canary side effects
in this phase: 0.**
