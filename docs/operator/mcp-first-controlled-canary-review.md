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
cannot be assembled today on **FIFTEEN independent blockers** (five since CLOSED — 4, 5, 6, 7, 13; this review's set — together they cover
every mandatory NO/CONDITIONAL row in §25, though the mapping is grouped, not strictly 1:1: the
witness-reconciliation row folds under blocker 7 and also depends on blockers 1 and 6). **The fifteen
are what THIS review found against §25; they are not the complete set of what must be closed before a
First Canary.** Later adversarial rounds have found further defects that no §25 criterion names — they
are tracked in §24 under their own headings, are NOT renumbered into the fifteen, and must also be
closed (see §26): (1) no controlled upstream reachable AND usable under the supported
production trust model (a provisioned HTTPS+SPKI target must ALSO speak a protocol that permits Culvert's sessionless calls — a standard initialization-requiring server is rejected because the client drives no MCP initialize/version/session lifecycle); (2) the production activation preflight cannot return `Ready:true` on a stock
node; (3) no governed production arming entry point — `armLiveTier` has no production caller, so an
operator cannot arm the tier; (4) **CLOSED** — the read-first classifier refused the one-exact-tool
call and discovery cannot bind one tool; an exact reviewed fingerprint-bound `tools/call` now
classifies `OpRead` while every unknown/unreviewed/drifted case stays non-read (§25a); (5) the machine gate does not enforce exactly-one tool/principal
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
mode (§13/§17); and (13) **CLOSED** — the seeded controlled tool was `catalog.Quarantined` with
nothing in the activation gate saying so; catalog usability is now a machine-checked activation
fact bound to the exact scoped target and pinned fingerprint, satisfied only by the governed
`shadow_evaluation` promotion lifecycle (§25b); and (14) **CLOSED** — the exact request had to
resolve to a decision that can actually execute and nothing checked it; the activation preflight now
runs the REAL shared policy engine over the exact First-Canary tuple and requires a plain ALLOW with
satisfiable obligations and a verdict invariant over every unbound policy field (§25c); and (15) the one-NODE bound is not enforced by anything —
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

~~**Blocker (Codex P1) — the read-first classifier makes the "one exact harmless tool call"
unexecutable today.**~~ **CLOSED (blocker 4) — the exact read-first tool classification.** The
finding was correct and is preserved verbatim for the record: `policyOperation` classified ONLY
`tools/list` as `OpDiscovery`, every `tools/call` as `OpWrite`, and the live gate rejected the
latter at its read-first check — so the experiment's §3 shape could not pass read-first, while the
one read-first-admissible method resolved no specific tool and therefore failed the exact-tool
live-approval revalidation.

The remedy taken is the FIRST of the two the finding named — a finer operation classifier — and
deliberately not the second. A discovery-trust path would have made `tools/list` stand in for an
invocation, which is §7's explicit prohibition: blocker 4 is not closed by pretending a listing is
the live tool execution.

The conservative default is UNCHANGED. `tools/call` is still `OpWrite` unless one narrow,
authoritative fact says otherwise, and that fact is the activation's own immutable reviewed record
(blocker 7's snapshot, now carrying the reviewed operation class beside the fingerprint it was
reviewed at). See §25a for the full closure argument and proofs.

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
proof that the selected client/agent maps one-to-one to the synthetic principal).

**CLOSED (blocker 5) — the exact shape is now a machine gate.** `canary.ValidateFirstCanaryScope`
(`internal/mcp/canary/firstcanary_scope.go`) is a SEPARATE predicate layered on top of
`ValidateScope`: `MaxCanaryTools`/`MaxCanaryPrincipals` stay 2 (they bound the Canary architecture a
later graduation phase may use; tightening them would redefine that architecture rather than this
experiment), while the first experiment must be exactly 1 tenant + 1 server + 1 fully-pinned tool ON
that server + 1 explicitly named `Principals` entry, with `Clients`/`Agents`/`Groups`/
`Environments`/`ToolFingerprints`/all four `Exclude*` empty, `Percent` 0, no duplicate, empty,
over-long or glob-shaped identifier. Identity is counted on `Principals` ALONE — the
`principalCount` aggregate named above can never satisfy it. The verdict is taken on the SIGNED
activation scope (raw, never compiled — `Compile` would deduplicate `[P1,P1]` into validity) inside
the authoritative activation preflight, so a wider signed scope yields `Ready:false` and cannot
activate at all. Near-misses that were external prerequisites are now named rejections: a second
tool, a second principal, a client- or agent-only identity, a duplicate, a bare fingerprint
dimension, an exclusion carve-out. See §26 blocker 5 for the full closure argument and proofs.

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
**Correction (Codex P1), and its closure.** When this section was written, a repository-wide search
found exactly TWO production `aborter.Trip` sites, both in `reserveCanaryExecution`
(`budget_exhausted`, `scope_escape`), and the generic `tripCanaryAbort` wrapper had NO production
caller — so eight of the ten declared `AbortCanary` codes were declared but never tripped, and after
any of them LATER requests could still reach the upstream. **That gap is now closed (blocker 7).**
The taxonomy is twelve `AbortCanary` codes and every one has a wired trip path that converges on
the SAME `AbortController` — there is no second latch, no parallel registry, no per-breach stop.
NINE of the twelve also have a production PRODUCER; the three that do not are marked in the table and
explained in the honesty note below. Read the column as "where a report of this code goes", not as
"this node can currently generate it":

| Whole-Canary code | Automatic trip path |
|---|---|
| `budget_exhausted` | `reserveCanaryExecution` on `BudgetDeniedTotal`, AND — traffic-independently — `observeAttemptSettled` once the allowance is spent and nothing is still in flight, AND `reconcileWindowDeadlineLocked` at restore |
| `scope_escape` | `reserveCanaryExecution` on `BudgetDeniedScope` |
| `window_expired` | `reconcileWindowDeadlineLocked` — a watchdog armed for the REMAINING time at begin and at restore, plus a synchronous latch when the deadline has already passed |
| `tool_fingerprint_drift` | THREE detection points, all routed: the runtime's pre-executor `refuseOnToolDrift` (through the optional `Deps.CanaryBreach` seam, resolving the activation admitting now), `mcpLiveTrustRevalidate` at admission (through `tripBreach`), and the executor's final-boundary `ToolStillCurrent` refusal (through `CanarySafety`, carrying the attempt's generation) |
| `server_identity_drift` | the same path, on loss of the approved server identity |
| `outcome_evidence_loss` | `execution`'s outcome-commit failure branch, through the `CanarySafety` seam (the metric remains in parallel, for observability) |
| `independent_witness_mismatch` | `Executor.ReconcileAndReport` on `ReconConflict` — an authoritative reconciliation contradicting Culvert's own record |
| `credential_safety_failure` | reported through the `CanarySafety` seam; denies AND stops (no production producer exists yet — see the honesty note below) |
| `elevated_error_rate` | `HealthMonitor.Observe`: `sample_floor = 2`, trips iff `2 × failures ≥ samples` (≥ 50%) over the CURRENT activation generation |
| `latency_pathology` | `HealthMonitor.Observe`: one attempt at or above `HealthLatencyHardLimit` (15s) trips with NO floor; a mean at or above `HealthLatencyMeanLimit` (10s) trips at the floor |
| `out_of_scope_execution` | reported through the `CanarySafety` seam; denies AND stops. **No production producer exists yet** — the identity-cap breach beside it is `scope_escape`, a DIFFERENT code, and a read-first/scope refusal of a single request stays request-scoped by design. A side effect outside the enumerated scope is prevented by the scope gate rather than detected, so an independent witness (blocker 8) is what would report one — see the honesty note below |
| `unexpected_upstream_response` | reserved for the authoritative production witness (blocker 8); reachable through the same funnel once that adapter is wired |

**Reachability inside the 3-execution corpus.** `HealthSampleFloor = 2`, and the hard-latency rule has
NO floor, so both rate detectors can evaluate — and trip — within `MaxTotalExecutions = 3`.
`TestHealth_SampleFloorFitsTheFirstCanaryCorpus` pins that as an anti-drift gate: it fails if the floor
is raised beyond the corpus, or if the hard latency limit is pushed past the 30s upstream request
timeout that is what makes it observable at all. Below the floor the error-rate detector does not
trip, which is acceptable only because the floor is reachable; the hard-latency rule covers the
single-sample case regardless. The numerator is ordinary post-admission execution failures — NOT
request-scoped policy or scope denials, which already carry their own classification. These are
First-Canary safety thresholds derived from the 30s upstream timeout; they are NOT product SLAs.

**The time-box is now self-enforcing (closes Codex round 31).** The deadline is ABSOLUTE and derived
from the persisted activation instant (`BudgetSnapshot.StartUnixNano + Budget.Window`), never from a
countdown restarted at boot. So: expiry stops the experiment with NO request arriving; a restart never
grants a fresh window; a restart AFTER expiry latches `window_expired` synchronously under the same
lock the admission path takes, so a restored activation is never even briefly execution-eligible; and
a clock rolled backwards cannot manufacture authority, because the remaining time is measured against
that same absolute deadline. The timer is a convenience, not the authority — the watchdog callback
re-derives the deadline and refuses to act early, and it is generation-guarded so a timer outliving
its activation cannot abort the activation that replaced it.

**What the latch does, and does not, do.** It revokes EXECUTION AUTHORITY: no new reservation is
granted, and a request ALREADY admitted fails the final live revalidation inside `preCallGuard`
BEFORE `Upstream.Call` (the emergency kill remains the last check before the boundary). It does NOT
demote the node to Shadow — automatic demotion is governed by blockers 10 and 12, and an internal path
around them would be a lie told in code. `ModeCanary + ABORTED` is the truthful state, and
`activation_runtime.auto_stop` reports `execution_authority: "revoked"` beside the first cause, so an
operator cannot read a stopped experiment as a running one. Budget exhaustion is deliberately NOT
latched when the final slot is merely RESERVED: the Nth request must be allowed to make the invocation
it was authorized to make, and the latch waits for that attempt to settle.

**Honesty note — `credential_safety_failure` has no production producer.** The broker prevents
client-token passthrough BY CONSTRUCTION rather than detecting it at runtime, and credentials are
blocker 9. What is proven here is the part that IS in scope: when such a signal is reported it denies
AND stops the whole experiment, with no "continue because the next tool may not need a credential"
path. The same holds for `unexpected_upstream_response`, which awaits blocker 8's authoritative
witness adapter; the funnel it will report through is wired and gated today.

The line this section draws, and a gate pins: a merely UNAUTHORIZED request fails closed WITHOUT
stopping the experiment. A Canary that aborted on every unauthorized request would be useless. Only
authoritative evidence that the experiment's PREMISE no longer holds is whole-Canary.

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
  **Since CLOSED as blocker 4 (§25a)** by the first of the two remedies the finding named — a finer
  classifier bound to the reviewed fingerprint. The second, a discovery-trust path, was deliberately
  refused: it would make `tools/list` stand in for the live tool execution.
- **P1 — THE RESOLVED SCOPE IS NOT REVALIDATED AT THE ADMISSION BOUNDARY (NEW, NOT ONE OF THE
  FIFTEEN; Codex on PR #1370, round 2). FOUND AND CLOSED IN #1370.** Confirmed against the code, and
  recorded here rather than filed under a nearby blocker precisely because it is not one of them —
  the fifteen are what §25's criteria produced, and this is a defect no §25 criterion names.

  The sequence, as it stood before the fix: a request from principal A resolves to execute under a
  Canary scope naming A, then
  pauses before the side-effect boundary; a SAME-MODE scope update replaces A with B;
  `reconcileCanaryRuntimeAfterCommit` (`mcp_rollout.go:509-530`) refuses only a changed BUDGET and a
  changed REVIEWED-TARGET SET, and `canary.ReviewedTarget` carries no principal — so the update
  proceeds and the generation is unchanged. The request resumes and is admitted: scope membership
  lives in `internal/mcp/rollout/scope.go` (`s.principals`, via `Contains` ← `resolveEnforcing`) and
  was decided at RESOLUTION only, `admitLiveExecution` never re-checked it, and `MaxPrincipals` is a
  COUNTER of distinct principals rather than a membership test — A is already counted, so the cap
  cannot catch it. `genAtResolve` is captured (`internal/mcp/runtime/policy.go:123`) but reaches only
  `refuseOnToolDrift` for evidence attribution; neither it nor the resolved scope identity reaches
  admission.

  **Same defect class as blocker 4's own round-1 finding** — a fact decided at resolution and never
  revalidated at the boundary — applied to scope membership instead of operation class. Blocker 4's
  fix (step 5b) does NOT close it and does not claim to: the equality holds whenever the current
  activation binds the same target to the same class, which an A→B principal swap does not disturb.

  PRE-EXISTING and UNWIDENED by that fix, which only ADDS an admission condition. Unreachable in the
  shipped build, since the sequence needs a live scope update on an armed Canary and therefore
  blockers 2, 3 and 12 closed first — an ordering statement, not a severity one.

  **REMEDY, SHIPPED IN PR #1370.** The finding is pre-existing, but it is in the exact live admission
  boundary that PR was already hardening and is the same defect class as its round-1 P1, so it was
  closed there rather than left standing behind a fix for its sibling.

  `rollout.Scope` already had a content hash (`scope.go:621`). `State.ResolveFor` now stamps it onto
  the `Resolution` **from the same atomic snapshot that decided `InScope`** — reading it from a
  second `s.cur.Load()` would be the very time-of-check/time-of-use gap this closes. It travels as a
  BOUNDARY FACT, never as policy semantics, and is deliberately absent from `policy.DecisionInput`:
  `Resolution.ScopeHash` → `ExecInput.ResolvedScopeHash` (stamped inside `Executor.Execute` from the
  resolution that execution is acting on, so a caller holding both values cannot forget to copy one)
  → `LiveGateInput` → admission. Step **(5c)** of `admitLiveExecution`, under the same activation lock
  that revalidates the reviewed target and the operation class, requires the installed scope's hash to
  equal the one the request resolved under before any budget authority is granted. On mismatch:
  denied, no reservation, no upstream call, no physical effect, bounded denial
  `canaryAdmitScopeNotInForce`, reported to the caller as out-of-scope.

  **Exact hash equality, not a re-run of `Contains`.** Re-checking principal membership closes the
  headline case and leaves every sibling open — a tool removed, a server removed, a tenant changed,
  an exclusion added, a percentage or bucket-salt edit. One comparison closes the whole family at
  once, and fails closed on the dimensions nobody enumerated. A request resolved under one
  authorization envelope cannot spend authority under another.

  **An empty hash is a refusal, not a wildcard** — it is what a request carries when it never went
  through `State.ResolveFor`, which is exactly the set that must not be exempted from the comparison.

  **Request-scoped; nothing is latched.** An operator narrowing a scope is the system working, not
  evidence that the reviewed target drifted, so it must not stop a healthy experiment (the
  round-15/31 rule).

  Conservative in one direction, deliberately: `Scope.Hash()` folds the scope REVISION, so a revision
  bump with identical selectors also refuses the stale request. That hash is already the definition of
  "did the scope change" used by `sameModeSameScope` (`mcp_rollout.go:435`), and a second
  selector-only hash would create two definitions of scope identity that can disagree.

  Gates (`mcp_canary_scope_in_force_test.go`): the exact stale sequence (G active, S1 permits A, a
  request resolves under H1, a same-mode update installs S2 with A→B while the reviewed target, the
  budget and the generation are unchanged, and the stale request is refused before any reservation);
  the mandatory positive control (an unchanged envelope still proceeds through the normal read-first
  path); an identical reapply does not reject; any selector edit — principal, server set, tool set,
  exclusion, tenant — refuses the stale request; a missing envelope fails closed; demote/reactivate
  cannot reuse an old envelope as fresh authority; the class revalidation still works independently;
  emergency kill remains the last check before `Upstream.Call`; and an end-to-end gate proving the
  envelope is CARRIED from a real `Resolve` to the boundary rather than only compared there.
  Mutations M17–M21 (the hash is never captured; admission ignores it; a missing hash is treated as a
  match; only the generation is compared; a principal-only recheck) each fail a named gate.

  **ROUND 3 CLOSED THE OTHER HALF OF THE SAME FINDING: THE POST-ADMISSION WINDOW.** Codex observed
  that step (5c) can only ever prove the envelope was in force AT ITS OWN INSTANT — admission is
  atomic under `cr.mu`, but the scope is published under `rollout.State`'s own `swapMu`, which that
  transaction does not hold and must not (taking a rollout lock inside the activation lock would
  invert the order every other caller uses). The request then travels on through credential
  materialization, the durable decision commit and connection setup before anything physical
  happens, and the final-boundary `Revalidate` re-read only the ACTIVATION GENERATION — which a
  same-mode scope update deliberately leaves alone, which is the whole premise of this finding. So
  a scope withdrawn in that window was invisible.

  The remedy is the one this boundary already uses for the emergency kill (PREREQ-MCP-KILL-1): the
  window is not narrowed, it is RE-ASKED. `Revalidate` now requires BOTH authorities — the reserved
  generation still current AND the resolved envelope still installed — immediately before
  `Upstream.Call`. Serializing scope publication with the admission transaction was the alternative
  Codex offered and is deliberately NOT taken: it would make an operator's scope edit block behind
  every in-flight admission AND would still leave the post-admission window open, since the request
  continues long after the transaction returns.

  The internal sentinel was renamed with it (`errLiveGenerationDemotedAtBoundary` →
  `errLiveAuthorityWithdrawnAtBoundary`, `boundaryRefusal.demoted` → `.withdrawn`): a name that says
  "generation demoted" while also meaning "scope replaced" is the quiet drift this ledger exists to
  prevent. WHICH of the two withdrew the authority is deliberately not distinguished at that layer —
  `internal/mcp/execution` must not learn to reason about scopes or generations to decide that a
  physical attempt is no longer authorized; the client reason is unchanged.

  Gates: `TestScopeInForce_ScopeWithdrawnAfterAdmissionRefusesBeforeUpstream` (the swap is injected
  through `ToolStillCurrent`, which `preCallGuard` evaluates immediately before `Revalidate` — the
  narrowest place a test can stand inside the window; the upstream must see ZERO calls) with
  `..._UnchangedEnvelopeSurvivesThePostAdmissionWindow` as its mandatory control, because a
  `Revalidate` wired to refuse unconditionally would satisfy the first while deleting live
  execution entirely. Mutation M22 removes only the final-boundary half, leaving step (5c) intact so
  every direct-admission gate still passes.

  **ROUND 4 FOUND THAT THE WINDOW WAS STILL TOO SHORT, AND THE PREDICATE STILL TOO NARROW.** Three
  findings, each confirmed against the code before acting, and all closed in #1370.

  **(a) The pool wait is unbounded.** `preCallGuard`'s comment claimed nothing blocking sits between
  it and the send. That was true of THAT function and false of the one it calls: `Client.Call`
  blocks in `pool.acquire` on a per-server semaphore until a slot frees or the context is done, so a
  kill, a demotion, a scope withdrawal or an approval revocation could land, return successfully,
  and the waiting request would then send anyway. The retry loop had the same shape one level in — a
  second leg re-sent on the strength of a check made before the first. **This exposure was not new
  with the scope work: the emergency kill re-read, the flagship "last authoritative state read
  before `Upstream.Call`" of PREREQ-MCP-KILL-1, sat behind the same wait.** `CallOptions.PreSend`
  now carries the executor's predicate into the client, where it is re-run holding the slot, before
  EVERY physical attempt. The hook is deliberately OPAQUE — `internal/mcp/upstreamclient` learns
  nothing about generations, scopes, approvals or kill state. Serializing publication with the
  admission transaction was the alternative remedy and is again NOT taken: it would block an
  operator's edit behind every in-flight admission and would still leave this window open.

  **(b) The live approval was never re-asked.** Round 22 moved the approval lookup INTO the admission
  transaction so a revocation racing the lock could not be admitted, and recorded in
  `mcp_live_gate.go` that the final boundary re-reads *"tool freshness, generation and kill state,
  not approval status"*. That residual is now closed: the grant is re-checked at a FRESH instant
  (not the admission instant — an approval that expired while the request waited must not be spent
  on the strength of how fresh it was when the wait began), against the same lock-free
  pointer-published inventory the admission probe used. Neither the scope nor the generation moves
  when an approval is withdrawn, and `ToolStillCurrent` only checks catalog freshness, so nothing
  else could have caught it.

  **(c) A withdrawal was diagnosed by a fixed reason.** The SAME scope mismatch read
  `rollout_out_of_scope` when admission caught it and `rollout_mode_invalid` when the boundary did —
  two contradictory answers for one fact, separated only by timing, in the block telemetry an
  operator reads during an incident, while the mode stayed a perfectly valid Canary throughout.
  `Revalidate` now returns the gate's own bounded `mcperr.Reason` instead of a bool, and ONE shared
  `applyBoundaryRefusal` classifies both refusal sites so they cannot drift apart. Which authority
  withdrew is still not distinguished INSIDE `internal/mcp/execution` — that package must not learn
  to reason about scopes, generations or approvals to decide a physical attempt is unauthorized; the
  gate names the reason and the executor carries it.

  Gates: `TestBoundaryAuthority_ApprovalRevokedAfterAdmissionRefusesBeforeUpstream`,
  `..._ScopeWithdrawnDuringThePoolWaitRefusesBeforeSend` (which also pins the reason), and
  `..._ValidApprovalSurvivesThePreSendReAsk` as the mandatory control — a `Revalidate` wired to
  refuse unconditionally would satisfy both negative gates while deleting live execution. The
  client's half of the contract is pinned separately in `internal/mcp/upstreamclient`
  (`TestPreSend_*`: a refusal stops the call with nothing sent and is provably never-sent; a
  permitting hook does not interfere; the hook runs AFTER the pool slot is held, proven
  deterministically by saturating the pool and waiting for exactly that many handler entries; and it
  runs on EVERY retry leg). Mutations M23–M26.

  **ROUND 5 CLOSED TWO MORE AND DREW THE LINE ON A THIRD.**

  **(d) A satisfying approval was not required to state the class in force.**
  `mcpLiveApprovalSatisfied` matched any live grant for the target and never compared
  `ReviewedOperationClass`. An approval carries its own class, and a later approval for the SAME
  exact fingerprint can state a different one — that is precisely how a reviewer corrects an earlier
  determination. So with the read-only approval that armed the activation gone and only a MUTATING
  one live, both admission and the boundary kept executing read-first on the strength of the
  activation's older immutable record, and the correction never landed for the rest of the
  activation's window. The class is now part of the question at BOTH sites, and a class no review
  can bind to a tool (`OpUnset`/`OpDiscovery`/`OpControl`) fails closed rather than reading as
  agreement.

  **(e) The boundary predicate asked about scope before the generation.** A leaving-live commit
  un-arms the tier and publishes the new scope BEFORE `demoteCanary` invalidates the generation, so
  for a window both are withdrawn — and scope-first reported `rollout_out_of_scope` for an
  already-admitted request while a fresh request in the identical final state reads
  `rollout_mode_invalid` from the unarmed lifecycle gate. That is the same
  diagnosis-depends-on-timing defect (c) removed, one layer in. The order now matches admission's own
  precedence: is there still an activation, and only then what it authorizes.

  **(f) "Revalidate at the actual request-write boundary" — PARTIALLY ACCEPTED, and the rest
  REFUSED with reasons.** `destination.Resolve` sits between the pool-boundary re-ask and the
  transport, and a DNS lookup is the least bounded of the three things that happen before any
  request byte exists, so the predicate is re-asked once more in `roundTrip`, after resolution and
  immediately before `client.Do`. What remains is TCP connect plus the TLS handshake, and that is
  where re-asking stops buying anything: `net/http` exposes no hook there that can ABORT cleanly —
  an `httptrace` callback observes but cannot refuse, and cancelling the request context from
  underneath RACES THE WRITE, turning a deterministic refusal into `may_have_been_sent`, which is
  strictly worse evidence than the window it would close. Both remaining steps are bounded by
  CONFIGURED timeouts (`ConnectTimeout`, `TLSHandshakeTimeout`, and the whole attempt by
  `RequestTimeout`), unlike the pool wait, which was bounded only by another request finishing.
  **That bounded-vs-unbounded distinction is the principled stopping point**, and it is recorded
  here rather than left implicit so a later round does not have to re-derive it.

  Gates: `TestBoundaryAuthority_ApprovalMustStateTheClassInForce` and
  `..._ApprovalWithNoStatedClassSatisfiesNothing` (both with the control that the MUTATING approval
  still satisfies a MUTATING request — a matcher that stopped matching anything would pass the
  refusal gate); `..._GenerationOutranksScopeWhenBothAreWithdrawn` with
  `..._ScopeStillNamedWhenTheGenerationIsCurrent` as its control, because "generation first" must
  not become "generation only". Mutations M27–M29.

  **ROUND 6 OVERTURNED (f), AND THAT IS THE RIGHT OUTCOME.** The refusal above rested on two claims
  and Codex falsified both: `net/http`'s `DialTLSContext` IS a cleanly abortable seam — perform the
  pinned dial and the handshake there, re-ask, and close/return before handing the connection to the
  transport, with no race against the write and `neverSent` evidence preserved exactly — and
  "bounded by configured timeouts" does not mean bounded by anything small, since the defaults allow
  seconds per phase and `NewLimits` accepts arbitrarily large positive durations. The invitation to
  disagree was explicit and the disagreement was correct; the window is closed rather than argued
  away.

  The shape settled at **TWO re-ask sites**, each covering a different unbounded wait and neither
  able to stand in for the other: `roundTrip` before `client.Do` (after the pool wait, which ends
  only when another request finishes, and after DNS resolution), and `pinnedDialTLS` after the TCP
  connect and the TLS handshake. They BRACKET DIFFERENT PHASES — the two waits are already behind
  the first site and the dialer never sees them, while the connect and the handshake are still
  ahead of it and only the dialer can sit after them. The **pool-boundary
  site added in round 4 was REMOVED as redundant** — `roundTrip`'s re-ask is strictly later on the
  same path with nothing between them that can have an effect — because a site that can only ever be
  absorbed by another is a liability in a mutation campaign, not defence in depth.

  Two implementation notes worth keeping. The TLS config is the transport's own with `ServerName`
  filled in: `net/http` derives SNI from the request host when it owns the handshake, and it no
  longer does, so omitting it would silently stop sending SNI on a path whose entire point is pinned
  identity. And the dialer's refusal rides out in a typed error (`preSendRefusalErr`) rather than a
  captured variable: `net/http` may dial on its own goroutine, so reading a value the dialer wrote
  after `Do` returns is a data race — carrying the fact IN THE ERROR needs no synchronisation, and
  `roundTrip` recovers the caller's verdict verbatim instead of classifying it as a connect failure
  and reporting `may_have_been_sent` for a leg that demonstrably wrote nothing.

  Round 6 also caught a **stale instruction beside the security predicate**: the summary line still
  read "scope, then approval, then generation" after (e) changed the order. Exactly the kind of
  comment that invites a future maintainer to restore a just-fixed defect; corrected, with the
  reason for the order stated rather than implied.

  Gates: `TestPreSend_RefusalBeforeTheTransportOpensNoConnection` (no TCP connection is even
  accepted) and `..._RefusalAfterTheHandshakeStillSendsNothing` (a connection IS accepted, no HTTP
  request is served, and the refusal is still provably never-sent), with
  `..._PermittingHookDoesNotInterfere` as the control. **Each site is pinned by an observable the
  other cannot produce** — counting hook invocations was the earlier instrument and it could not say
  WHICH site ran, which is what let one absorb the other. Mutations M25, M29, M30.

  **A SIXTH instance of the guarded-twice pattern, self-inflicted in the round that created it.**
  Adding the second pre-send re-ask immediately made M25 (remove the pool-boundary one) absorbable
  by the new site. The per-leg re-ask count is therefore pinned EXACTLY (`preSendsPerLeg`), both
  removals verified failing independently, and M29 added for the new site. The rule has now earned
  a stronger form: **adding a second guard for an invariant is itself a reason to re-check every
  mutation that targeted the first.**

  **A fifth instance of the guarded-twice pattern, and a new form of it.** M22's perl pattern stopped
  matching when round 4 rewrote the closure it targeted, so the campaign reported it SKIPPED rather
  than silently passing — the check that exists for exactly this. The lesson recorded last round
  ("a refactor that moves a guard is a reason to re-read the mutation that targeted it") is now
  itself load-bearing: it happened again, in the same file, one round later.

  **ROUND 7 RETURNED NO FINDINGS**, on the head carrying all six remedies. That is the closure
  evidence for this whole sub-section: six consecutive rounds each found the next place the previous
  fix did not reach, and the seventh found none. It is evidence and not proof — a clean round bounds
  what one reviewer found, not what is there — which is why the standing claim below remains what
  the gates and the campaign establish, not what the review failed to object to.

  Self-audit on that same head corrected a SEVENTH instance of the stale-comment class, found here
  rather than by review: the two-site rationale claimed the dialer site was needed because "a
  connection reused across retry legs never reaches the dialer". That reuse cannot occur —
  `roundTrip` builds its own `http.Transport` per leg and releases its idle connections when the leg
  ends, so every leg dials. The real reason the sites are independent is that they bracket different
  phases, which is what both comments and this paragraph now say. The per-leg transport is the
  stronger fact and is recorded in its place: no leg can inherit a connection another leg opened,
  which is why the dialer site reaches every leg. Checking it also re-confirmed that a redirect
  follow-up cannot become a second unguarded physical send on this path, since `RetryFreeLimits`
  forces `MaxRedirects = 0` — closed in an earlier round for exactly that reason.

  **AN EIGHTH INSTANCE, AND A NEW FORM: THE WRONG OBSERVABLE.** The same self-audit ran the boundary
  gates under `-race` and `TestPreSend_RefusalAfterTheHandshakeStillSendsNothing` FAILED — the defect
  being in the test, not the code. `pinnedTestServer` exposes `conns` as a GAUGE (+1 on accept, -1 on
  close), and both pre-send site tests read it as if it were a cumulative accept counter. That is
  wrong in BOTH directions, and only one of them is noisy: the post-handshake test asserted
  `live >= 1` AFTER `Call` returned, which races the server's own `StateClosed` — our refusal has
  already closed the socket by then — and its sibling asserted `live == 0` to mean "no connection was
  opened", which is equally true of a connection opened and then closed, so it could pass while
  proving nothing. One direction fails loudly under `-race`; the other is SILENT, and a silent
  false-pass on a security gate is the worse of the two. `pinnedTestServerCounting` now exposes both
  observables with their meanings named, and each gate reads the one it needs; the leak test keeps
  the gauge. The post-handshake premise is now carried by two facts that cannot both be satisfied by
  accident — `asks >= 2` proves OUR side of the handshake completed (the second ask is unreachable
  until `HandshakeContext` returns nil) and a non-zero ACCEPT COUNT proves the peer established a
  connection. Both repaired gates were re-verified against M25 and M30, so fixing the instrument did
  not weaken what they catch. The rule this adds to the guarded-twice family: **a gate can be wrong
  about WHAT IT MEASURES rather than about what it asserts, and a gauge read as a counter fails one
  way and lies the other.**
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
| A read-first-admissible one-exact-tool operation exists | ~~**NO**~~ **YES (blocker 4 CLOSED, §25a)** — an exact reviewed fingerprint-bound `tools/call` classifies `OpRead`; the conservative `OpWrite` default and the `tools/list`-binds-no-tool fact are both unchanged, so nothing was widened to get here (§6) |
| Supported upstream trust model for a controlled server available today | **NO** (§5) |
| A provisioned target is USABLE (MCP initialize/version/session lifecycle) | **NO — client sends no `initialize`/version/session; a spec-compliant server rejects sessionless calls (§5)** |
| Reviewed fingerprint bound to the OBSERVED live peer (not operator-declared) | **NO — seeded from operator JSON; identity verified against its own register stamp; no non-test `Discovery.Discover` caller (§7, blocker 11)** |
| Shadow trust ≠ live trust proven; live approval does not activate Canary | YES (§8) |
| Tight scope validated (no percentage/group/wildcard; server & tenant capped at 1) | YES (§10) |
| Machine gate enforces exactly-one tool AND exactly-one principal | **YES — `canary.ValidateFirstCanaryScope`, a separate predicate layered on `ValidateScope` (the architecture caps stay 2 by design). Exactly 1 tenant/server/tool/named principal from the SIGNED scope; clients/agents/groups/environments/bare-fingerprints/exclusions/percentages forbidden; identity counted on `Principals` ALONE; no dedup of an ambiguous signed object. Enforced in the activation preflight, so a wider scope yields `Ready:false` (blocker 5 CLOSED, §10/§25a)** |
| Tiny budget; N reservations allowed / N+1 impossible | YES for reservations (§9) |
| Budget bounds PHYSICAL side-effect-bearing invocations via a RETRY-FREE path (charging not accepted) | **YES — `RetryMode`/`RetryDisabled` is representable and wired into the ONLY production upstream client; N reservations ⇒ ≤ N physical POSTs measured AT THE WIRE under concurrency and ambiguous transport failure (blocker 6 CLOSED)** |
| Witness distinguishes side-effect-bearing tool invocations from auxiliary lifecycle/discovery traffic | **NO — no such controlled recording server exists; without the partition a correct run's `initialize`/`tools/list` POSTs misclassify as a breach (§9/§14)** |
| Rate-based abort thresholds are REACHABLE within the 3-execution corpus (or fail closed below the floor) | **YES — `sample_floor = 2`, error rate trips at ≥ 50% (`2 × failures ≥ samples`) over the current activation generation, hard per-attempt latency ≥ 15s trips with NO floor, mean ≥ 10s trips at the floor; `TestHealth_SampleFloorFitsTheFirstCanaryCorpus` fails if the floor drifts beyond the corpus (§16, blocker 7 CLOSED)** |
| Activation preflight returns `Ready:true, Unmet:[]` on a real node | **NO** (§13) |
| The exact tool is `catalog.Usable` (not Quarantined) at request time | ~~**NO**~~ **YES (blocker 13 CLOSED, §25b)** — usability is now a MACHINE-CHECKED ACTIVATION FACT (`canary.ReasonToolNotCatalogUsable`), resolved from the authoritative catalog for the exact scoped target at the exact pinned fingerprint. It is satisfied only by the governed `shadow_evaluation` promotion lifecycle; `ApproveLive` still never promotes, and a structural wall proves no data-plane caller can (§6/§7) |
| The exact request resolves to an ALLOW-class rule with satisfiable obligations | ~~**NO**~~ **YES (blocker 14 CLOSED, §25c)** — a MACHINE-CHECKED ACTIVATION FACT (`canary.ReasonExactPolicyNotExecutable`), decided by the REAL shared policy engine over the exact First-Canary tuple. The bar is stricter than this row's wording: a plain `policy.ActionAllow`, never `Action.IsAllowClass()`, because MONITOR reaches `EffectExecute` and ALLOW_ONCE / ALLOW_FOR_SESSION / ALLOW_WITH_REDACTION are gated by runtime state no preflight can observe. Obligations are judged satisfiable-HERE against a closed allow-list, and the verdict must be invariant over every unbound policy field |
| Operator-reachable governed path to TRANSITION the node into Canary mode | **NO — `apiMCPRolloutTransition` returns `distribution_not_configured`; no non-test `publication.New`/`Publish` caller (§13/§17, blocker 12)** |
| Governed production arming entry point exists (operator can arm) | **NO — `armLiveTier` has no production caller (§12)** |
| Independent upstream witness reconcilable AND auto-stops on divergence | **NO — no reconciliation/auto-trip; retry amplification; §5 server absent (§14)** |
| Evidence carries no secrets/credentials | YES (§15) |
| Durable record determines whether a pre-crash upstream invocation occurred | **NO — narrowed. Internal durable truth/recovery/reconciliation COMPLETE (terminal outcome on every exit path, durable pre-send intent, orphan derivation, typed witness contract); the authoritative production witness adapter REMAINS unwired, so the answer is `reconciliation_required`, not determinate (§15/§18, blocker 8)** |
| Whole-Canary auto-abort covers drift / evidence-loss / unexpected-response / thresholds | **YES — every declared `AbortCanary` code has a wired trip path onto the ONE `AbortController`; the latch revokes execution authority (no new reservation, and an already-admitted request fails the final revalidation before `Upstream.Call`) and the time-box stops with no request arriving. Three codes have no production PRODUCER: `unexpected_upstream_response` (awaits blocker 8's authoritative witness adapter), `credential_safety_failure` (blocker 9), and `out_of_scope_execution` (prevented by the scope gate before execution rather than detected) — all three funnels are wired and gated (§16, blocker 7 CLOSED)** |
| Operator-reachable graceful rollback (quiesce or Canary→Shadow/Observe demotion) — §17's "rollback AND kill" bar | **NO — quiesce has no caller; `apiMCPRolloutTransition` returns `distribution_not_configured` (§17)** |
| Crash/restart does not silently re-arm/resume | YES (§18) |
| Unresolved P0/P1 finding | **YES — the durable-outcome-evidence prerequisite remains, narrowed to the authoritative production witness adapter (blocker 8). The auto-abort wiring prerequisite is CLOSED (blocker 7, §25a) (§21/§24/§25a)** |

Multiple mandatory criteria are NO and P1 product-defect work remains open. A GO is therefore
forbidden. (§25a and §25b record the only post-adoption status changes: blockers 4, 5, 6, 7 and 13
CLOSED, blocker 8 narrowed but still OPEN. The other nine are untouched and the §26 verdict is
unchanged.)

---

## §25a Blocker 4, 5, 6 and 7 closure, blocker 8 status (post-review evidence)

This section records the ONLY status changes made to the frozen ledger since it was adopted:
blockers 4, 5, 6 and 7 are CLOSED and blocker 8 is narrowed but still OPEN. The other ten blockers
are untouched, the baseline is still fifteen, and nothing here changes the §26 verdict.

### Blocker 4 — CLOSED

The closure bar was: the machine must be able to prove that ONE exact reviewed fingerprint-bound
`tools/call` classifies as `OpRead`, while every unknown, unreviewed, hinted, drifted or ambiguous
case stays non-read and fail-closed. The governing invariant, stated once:

> a `tools/call` may become `OpRead` only when Culvert itself holds authoritative reviewed evidence
> that exact tenant / exact server / exact tool / exact fingerprint / exact fingerprint format /
> exact reviewed operation class = read-only. Unknown or ambiguous ⇒ `OpWrite` / deny.

| Clause | Evidence |
|---|---|
| Culvert's own authority, never the server's | `tooltrust.ReviewedOperationClass` is stated by a REVIEWER on the four-eyes live approval; `ParseReviewedOperationClass` is strict and total, so no hint spelling (`true`, `readonly`, `readOnlyHint`) parses into a determination (`TestReadFirstClass_C03_ServerHintIsNotAnInputToClassification`). A live approval that states no class is refused at creation (`TestRequest_LiveExecutionRequiresReviewedOperationClass`), with the shadow control beside it |
| No NEW authority — the fact lives on the existing reviewed record | `canary.ReviewedTarget.OperationClass`, on blocker 7's activation-bound immutable snapshot. There is no separate classifier store that could disagree with the activation about the same tool |
| Bound to the FINGERPRINT, not the name | `ReviewedTargetSet.OperationClassFor` delegates to `Compare` and answers only on `ReviewedMatches`, so F2 inherits nothing from F1 (`TestReadFirstClass_C04_F2DoesNotInheritF1ReadClassification`). The FORMAT version is part of the binding (`TestReadFirstClass_FingerprintFormatIsPartOfTheBinding`) |
| The caller cannot assert its own class | `Compare` never reads `cur.OperationClass`; an asserted class is ignored and the reviewed one returned (same test) |
| No unstated class can arm | `CanonicalizeReviewedTargets` refuses `OpUnset` (`reviewed_target_no_operation_class`) and any class outside the reviewable vocabulary (`reviewed_target_invalid_operation_class`) — so `OpDiscovery`/`OpControl` can never be bound to a TOOL and reach the read-first predicate (`TestReadFirstClass_C02`, `TestReadFirstClass_C08`) |
| Arguments cannot upgrade authority | the classifier seam takes `(capability, serverID, toolName)` and nothing else; the root resolves fingerprint, format, tenant and identity from its own authoritative inventory. Pinned on the TYPE (`TestReadFirstWall_ClassifierTakesNoServerSuppliedInput`), because a behavioural test can only show an input is ignored, not that there is none to give |
| Unknown / unusable targets are never classified | `TestReadFirstClass_C06_UnreviewedToolIsNeverRead`, `TestReadFirstClass_C07_UnusableServerIsNotClassified`, `TestReadFirstRuntime_UnknownToolIsNeverClassified` |
| Discovery stays discovery | `tools/list` keeps `OpDiscovery` and is never routed through the classifier at all (`TestReadFirstRuntime_DiscoveryNeverReachesTheClassifier`) — blocker 4 is not closed by substituting a listing for an invocation |
| ONE classification, flowing through the decision tuple | `TestReadFirstWall_OperationClassHasExactlyOneClassificationSite` (AST: exactly one site in `internal/mcp/runtime` may write a tool call's class) and `TestReadFirstParity_ClassIsReadFromTheDecisionAndNowhereElse` (AST: `liveGateInput` reads `in.Input.Operation.Class`), with the behavioural parity across the whole class vocabulary in `TestReadFirstParity_GateReceivesTheDecidedClass`. So the policy engine, the activation gate and the live side-effect gate read ONE value rather than three that agree today |
| Durable across restart, immutable within a generation | `canaryRuntimeSchemaVersion` 3; a record that cannot state its class from its own bytes does not restore armed (`TestReadFirstClass_DurableRecordWithoutAClassDoesNotRestoreArmed`), a restart restores the same classification (`C11`), and a same-generation update that changes only the class is refused (`C12`) |
| The freshness boundary is not weakened | `TestReadFirstClass_StaleF1DecisionIsRefusedAfterF2` — a decision computed under F1 does not reach upstream once the target is F2; the promotion is not the last word |
| The classification does not outlive the activation that made it | `admitLiveExecution` step (5b): the decided class must EQUAL the one the activation being charged binds to this target, decided inside the lock that decides which activation that is. `TestReadFirstClass_StaleReadClassIsRefusedAfterAReviewSaysMutating` (the full G1→G2 sequence through the real gate) + `TestAtomicBinding_I_ClassNotInForceIsRefused` (the transaction-level half, with its own positive control) |
| Anti-vacuity (MANDATORY positive controls) | `TestReadFirstClass_C01_ExactReviewedReadOnlyToolClassifiesAsRead`, `TestReadFirstRuntime_ReviewedReadAnswerPromotesTheToolCall` and `TestReadFirstClass_LiveGateAdmitsTheReadClassAndRefusesTheWriteClass` — a classifier that answered "no" to everything would satisfy every negative gate while being the feature deleted |
| Campaign | `scripts/mcp-canary-read-first-classification-mutations.sh` — 30 mutations, 30 caught, 0 survived, 0 skipped (M17–M30 belong to the §24 boundary finding below, not to blocker 4's own criteria) |

**Two things the campaign taught, recorded because they change how a survivor should be read.**
A single-edit mutation of the stale-decision boundary SURVIVED, and the reason was not a missing
gate: that boundary is guarded twice and independently (the trust precheck revalidates the
decision's fingerprint; the approval binds the exact tool it was granted for), so removing either
alone changes nothing observable. The same held for the unset-class guard, which is enforced both by
its own named case and by the reviewable-vocabulary membership test. A mutation that never managed
to break anything is not evidence of a hole — but it is also not evidence of a gate, so both were
rewritten to remove BOTH guards — and then a THIRD instance appeared, in the other direction: the
boundary revalidation added for the P1 above independently refuses a write-class request, so the
mutation that disables the read-first gate stopped reintroducing anything the moment that guard
landed. A FOURTH appeared when naming the boundary revalidation as its own predicate moved a
mutation's target and quietly narrowed what it proved: the predicate's `!ok` clause — "the record
cannot speak for this target" — has no independently reachable case, because step (5)'s
out-of-scope refusal and the trust probe both refuse first. It is kept as defense in depth, the
mutation was restored to disabling the predicate outright, and its description now says so.
Four instances in one campaign is a pattern, not a coincidence: on this path most invariants are
guarded twice, so a surviving single-edit mutation is re-read before it is believed — and a
refactor that moves a guard is a reason to re-read the mutation that targeted it.

**The sharpest finding came from adversarial review, not from the campaign** (Codex P1, PR #1370).
The class is decided ONCE, at policy time, under whatever activation is armed at that instant — but
"decided once" is a statement about how many times it is COMPUTED, not about how long it stays
true, and the request carrying it is charged, at the boundary, to whatever activation is armed
THEN. So: G1 reviewed a tool read-only and a request was decided `OpRead`; the request paused; G1
was demoted and G2 armed for the SAME tool at the SAME fingerprint with a review stating MUTATING —
a reviewer correcting the earlier determination; the request resumed and crossed, because gate 2
read `OpRead` off its own decision and every drift control was correctly silent (the target did not
move; the review of it did). The correction landed in the one window where it mattered most.

`admitLiveExecution` now revalidates the class inside the transaction. That is REVALIDATION, not a
second classification, and the distinction is why it does not violate the one-classification rule:
nothing recomputes a class from different inputs and hopes it agrees — it re-reads the SAME
authority under the lock that decides which activation is paying, exactly as the trust probe and
the drift comparison already do at this boundary. Equality rather than "read is still read", so it
stays correct if a later phase admits a non-read class and so a record that cannot speak for the
target fails closed instead of reading as agreement.

It also corrected a fixture error the campaign had not caught: several fixtures armed a MUTATING
reviewed target and then asserted "the reviewed request must be admitted" — a state the product
cannot reach, since a tool call crosses the side-effect gate as `OpRead` or not at all. The
revalidation exposed every one of them on the first run.

**And one the campaign found rather than confirmed.** `in.Operation = op` sits AFTER the call that
may promote it, and the ordering is load-bearing in the quietest possible way: reversed, the
classifier is still consulted and still answers correctly, nothing refuses, nothing fails to
compile, and every fail-closed gate still passes — the exact reviewed call is simply denied
read-first forever, with no signal anywhere. Only a gate that reads the class the EXECUTOR received
can see it, which is why the positive control asserts on the executor's `DecisionInput` rather than
on the classifier's answer (M14).

**Default posture unchanged.** No activation arms in the shipped build, so the classifier answers
`false` for every request and every `tools/call` stays `OpWrite` — byte-identical to the behaviour
before this work.

**What this does NOT close.** A read-first-EXECUTABLE classification says nothing about whether a
controlled upstream exists (blocker 1), the activation preflight can reach `Ready:true` (2), an
operator can arm (3), the target is `catalog.Usable` (13 — **since CLOSED, §25b**), or the request
resolves to an exact policy ALLOW with satisfiable obligations (14). Those remain open and untouched
by THIS closure; blocker 13 was closed later, by its own PR and its own gates.

**A SECOND, SEPARATE defect was closed in the same PR, and it is NOT part of this closure.** Codex
round 2 found that the resolved SCOPE was never revalidated at the admission boundary — the same
stale-resolution class as the P1 above, one axis over. It is recorded in §24 with its own remedy and
its own gates, and it is deliberately not folded into blocker 4: blocker 4's criteria are the table
above and they stand or fall on their own. It was fixed there rather than deferred because it sits in
the exact admission boundary this work was already hardening, and a known P1 in that boundary is not
carried across a merge merely because it predates the branch. Its gates are
`mcp_canary_scope_in_force_test.go`, `internal/mcp/upstreamclient/presend_test.go`, and campaign mutations M17–M30.

It also does not close the SCOPE half of the same defect class: step (5b) revalidates the operation
class at the boundary, and nothing revalidates the resolved SCOPE there — a request that resolved
under a scope naming principal A can still be admitted after a same-mode update replaced A with B.
That is a NEW finding, not one of the fifteen, pre-existing on `main` and unwidened by this work;
see §24 for the evidence and the proposed remedy. Do not read blocker 4's closure as covering it.

### Blocker 5 — CLOSED

The closure bar was: the machine gate must enforce the ONE exact reviewed experiment — one tenant,
one server, one tool, one explicitly named principal — from the SIGNED activation scope, in the
authoritative activation preflight, without aggregate identity counting and without deduplicating an
ambiguous signed object into a valid one. Each clause is now mechanically proven:

| Clause | Evidence |
|---|---|
| A separate predicate, not a global tightening | `canary.ValidateFirstCanaryScope` layered ON TOP of `ValidateScope`; `MaxCanaryTools`/`MaxCanaryPrincipals` stay 2 and `TestFirstCanary_ArchitectureBoundsAreNotRedefined` fails if a future change "simplifies" exactness into those architecture caps |
| Exactly 1 tenant / server / tool / principal | `TestFirstCanary_RejectionMatrix` (zero, two and duplicate rows for each dimension, each asserting its OWN named reason) |
| Zero clients / agents / groups / environments / bare fingerprints / exclusions / percentages | same matrix; each forbidden class carries its own reason so a rejection is never attributed to an unrelated prerequisite |
| No aggregate identity counting | `TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal` — asserts the base contract's `principalCount` DOES accept a lone client/agent (the hazard is real), that the exact gate refuses it by its own reason, and that removing it leaves the scope still refused for having no principal (it contributed nothing) |
| Never deduplicated into validity | `TestFirstCanary_NeverDeduplicatesAnInvalidSignedScope` — proves `rollout.Compile` collapses the duplicate to the same content hash as its deduplicated counterpart, then requires the raw-slice gate to refuse anyway |
| Every selector class explicitly ruled on | `TestFirstCanary_GovernsEverySelectorClass` (reflection over all 19 `rollout.ScopeSpec` fields) + `TestFirstCanary_EveryGovernedFieldIsDecisive` (a governed field must actually change the verdict) |
| Decided from the signed scope alone | `TestFirstCanary_ValidatorReadsNoClockOrIO` (import + AST purity wall) and `TestFirstCanary_IsPureAndDeterministic` (same verdict at every revision; the input is never mutated) |
| Enforced in the authoritative activation preflight | `TestExactScope_EnforcedInTheAuthoritativePreflightNotOnlyAtRuntime` — the verdict is taken exactly once in the root package, inside `evaluateActivationOnFacts`, on `in.Scope`, and BOTH preflight entry points route through that body |
| A wider scope cannot activate at all | `TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied` — every other prerequisite true (with a positive control proving that fact set IS Ready for the exact experiment), twenty widenings each `Ready:false` carrying `canary_scope_not_exact_first_canary` |
| Anti-vacuity | `TestFirstCanary_CanonicalExperimentPasses` and `TestExactScope_CanonicalExperimentSatisfiesTheActivationRow` — the ONE reviewed experiment (T1/S1/Tool1/P1) must PASS, so a reject-everything gate cannot score as exact |
| Campaign | `scripts/mcp-first-canary-exact-scope-mutations.sh` — 30 mutations covering every widening, the bypass routes (skip the check, validate a request-derived scope, drop the readiness row, assert the fact at node level, substitute the base contract), and the two hollowing-out failure modes |

Runtime scope matching still denies an out-of-scope principal/server/tool
(`TestExactScope_RuntimeStillDeniesOutOfScopeIdentities`) and is DEFENSE-IN-DEPTH, explicitly not the
closure argument: the argument is that the broader scope never activates.

**What this does NOT close.** Exactly one tool being AUTHORIZED BY SCOPE says nothing about whether
`tools/call` for it is read-first EXECUTABLE (blocker 4, the operation-classifier problem — since
CLOSED separately, see "Blocker 4" above; it was open when this closure was written), nor that the
target is `catalog.Usable`, resolves to an exact policy ALLOW, or has satisfiable obligations
(blockers 13/14). Those last two remain open and untouched.

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

### Blocker 7 — CLOSED

The closure bar, stated as the invariant the work had to produce:

```
first authoritative whole-Canary breach
             ↓
monotonic abort latch
             ↓
no new Canary execution admission
             ↓
automatic stop / demotion path
```

with the additional requirement that **the abort must not depend on another request arriving**.

| Clause | Evidence |
|---|---|
| Every declared whole-Canary breach reaches ONE abort authority | `canarySafetyFunnel` (`mcp_canary_autostop.go`) and the gate's `tripBreach` (`mcp_live_gate.go`) both converge on `rt.tripCanaryAbort` → `AbortController.Trip`; `tripAutoStopLocked` reaches the same controller inline because the caller already holds `cr.mu`. There is no second latch. Mutations M64, M65, M66, M67, M68, M69, M70, M77 each remove one trip path and are caught |
| The latch is monotonic and first-cause-wins | `AbortController.Trip` latches once; `TestAutoStop_FirstCausePreservedAcrossLaterBreaches` and `TestAutoStopConc03_TwoBreachesRaceForFirstCause` pin it under contention; mutations M62, M75 caught |
| No new execution admission after the latch | `reserveCanaryExecution` consults `ExecutionEligible`; `TestAutoStop_LatchedAbortMakesNewReservationImpossible`, `TestAutoStopConc02_BreachWhileManyAwaitAdmission`; mutation M61 caught |
| An ALREADY-admitted request makes no further physical side effect | The final live revalidation (`LiveGateDecision.Revalidate`, run inside `preCallGuard` BEFORE the emergency-kill re-read) consults the same latch; `TestAutoStop_LatchedAbortStopsAnAlreadyAdmittedRequestBeforeTheCall` with its unaborted control, and `TestAutoStopConc11_LatchDuringInflightAdmissionSendsNothingMore`; mutation M76 caught |
| The stop does not depend on another request arriving | The absolute window deadline is derived from the persisted activation instant and armed as a watchdog at begin and at restore; `TestAutoStop_WindowExpiresWithNoTrafficAtAll` proves a stop with ZERO traffic, `TestAutoStop_BudgetExhaustionStopsWithoutAnNPlusOneRequest` proves exhaustion latches on the final SETTLE rather than on an N+1 request; mutations M71, M77, M78 caught |
| A restart never resets or extends the window | The deadline is `BudgetSnapshot.StartUnixNano + Budget.Window`, so it survives restart by construction; `TestAutoStop_RestartNeverGrantsAFreshWindow`, `TestAutoStop_RestartAfterExpiryRestoresAborted` (which also proves the latch happens BEFORE any admission is possible), `TestAutoStopConc05_DeadlineVersusRestart`; mutations M63, M72 caught |
| A clock rollback grants no authority | `TestAutoStop_ClockRollbackGrantsNoExtraAuthority` |
| A clock rolled BEHIND the activation closes the window at BOTH ends | The boundary, the arm path and the watchdog callback all use the enforcer's `WindowOpen` predicate rather than a bare upper-bound test, so a backwards clock latches `window_expired` instead of arming a watchdog for a phantom hour; `TestAutoStop_ClockRollbackBehindActivationClosesTheBoundary`, `TestAutoStop_ClockBehindActivationLatchesAtRestoreInsteadOfArming`, `TestAutoStop_WatchdogFiringUnderRollbackLatchesInsteadOfReArming`, with `TestAutoStop_ClockInsideTheWindowStillArmsNormally` as the control; mutations M92, M93 caught |
| The closed time box is named the same whichever path notices it | A window denial at admission records `window_expired`, not `budget_exhausted` — the first cause is immutable, so without this the operator-visible reason depended on a race between the admission and the watchdog; `TestAutoStop_WindowDenialAtAdmissionRecordsWindowExpired`, control `TestAutoStop_TotalExhaustionStillRecordsBudgetExhausted`; mutation M95 caught |
| A peer that answers BADLY counts as a failure | `upstreamLegFailed` names all THREE shapes — a transport error, a nil response, and a decoded JSON-RPC error object — because each was reached by a different wrong predicate: deriving failure from receipt made two HTTP 500s read as successes (round 5), and a transport-only test made two JSON-RPC tool errors read as successes (round 6). `TestAttemptSettled_PeerErrorResponseCountsAsAFailure`, `TestAttemptSettled_PeerJSONRPCErrorCountsAsAFailure`, control `TestAttemptSettled_SuccessfulExecutionIsNotAFailure`; mutations M94, M96 caught |
| The settled sample is durable BEFORE the terminal outcome | A crash between the two writes must over-count an outcome record rather than erase failure evidence, because restore legitimately accepts fewer samples than reservations; `TestAttemptSettled_IsReportedBeforeTheTerminalOutcomeCommit`; mutation M91 caught |
| The settled sample is counted BEFORE the reservation is released | The settle may latch `elevated_error_rate`; the release is what admits the next request. They are one decision, so they are one defer with an explicit order — not two defers relying on LIFO; `TestAttemptSettled_IsReportedBeforeTheReservationIsReleased`; mutation M99 caught |
| The slot is held through EVERY authority decision | The ordered defer runs trust-breach → settle → terminal outcome → release, so no step that can stop the Canary races the step that admits the next request; `TestBreach_OutcomeEvidenceLossIsReportedBeforeTheReservationIsReleased`; mutation M100 caught |
| A pinned-identity mismatch is a breach, a caller cancellation is not a failure | `server_identity_drift` trips on the first occurrence and is reported before the settle so it wins the immutable first cause; `context.Canceled` is excluded from the POPULATION entirely (not merely from the numerator — a padded denominator dilutes a real failure below the threshold) while `DeadlineExceeded` stays a charged sample; `TestBreach_TLSIdentityMismatchTripsServerIdentityDrift`, `TestAttemptSettled_CallerCancellationIsNotASampleAtAll`, with `TestBreach_OrdinaryUpstreamFailureIsNotIdentityDrift` as the control; mutations M101, M102 caught |
| The rate detectors can evaluate inside the authorized corpus | `HealthSampleFloor = 2`; error rate trips iff `2 × failures ≥ samples`; hard latency ≥ 15s trips with no floor; mean ≥ 10s trips at the floor. `TestHealth_SampleFloorFitsTheFirstCanaryCorpus` is the anti-drift gate; mutations M73, M74 caught |
| Request-scoped refusals do NOT stop the experiment | `TestAutoStop_RequestScopedRefusalsNeverStopTheCanary` and `TestAutoStop_MerelyUnauthorizedRequestDoesNotStopTheCanary` are the controls that keep the closure from being achieved by aborting on everything |
| Breaches are capability-isolated | `TestAutoStop_BreachIsCapabilityIsolated`; the funnel refuses a capability that is not its own |
| An unknown breach code fails closed | `TestAutoStop_UnknownBreachCodeFailsClosed`; `AbortConditions` resolves an unrecognised code to `AbortCanary` |
| Corrupt persisted state never loads as executable | `TestAutoStop_CorruptPersistedStateNeverLoadsAsExecutable` |
| The operator can see that authority is revoked | `TestAutoStop_StatusReportsRevokedAuthorityWhileStillModeCanary`; `activation_runtime.auto_stop` on the preflight surface |
| The operator surface is never more optimistic than the admission gate | `window_expired` and `execution_authority` derive from the SAME two-ended `WindowOpen` predicate admission uses, so a closed window is reported before anything latches — reporting, never deciding: nothing in the admission path reads it; `TestAutoStop_StatusIsNeverMoreOptimisticThanAdmission`; mutations M97, M98 caught on separate assertions |

**What was deliberately NOT done, and why.** Automatic DEMOTION to Shadow is not part of this closure.
Demotion is a governed lifecycle transition owned by blockers 10 and 12; building a hidden internal
path around them would have produced a system whose code said something its governance did not. What
the latch revokes is EXECUTION AUTHORITY, and `ModeCanary + ABORTED` is the truthful state until that
governed transition exists — which is why the status surface reports `execution_authority` separately
from mode rather than letting `Mode: Canary` imply a running experiment.

THREE declared codes have no production PRODUCER yet, and this is stated rather than papered over —
it was two until an audit of the taxonomy against the code found the third, which is exactly the
class of drift the rest of this section exists to prevent:

* `out_of_scope_execution` — an out-of-scope request is refused by the scope gate BEFORE execution,
  so a real side effect outside the enumerated scope is prevented by construction rather than
  detected. The code stays declared because that is the one thing a node cannot prove about itself:
  an independent witness (blocker 8) reporting an effect we never authorized is what would produce
  it. `scope_escape` — the neighbouring code — DOES have a producer, because an identity beyond the
  enumerated blast radius is something this node can observe at its own admission gate.
* `credential_safety_failure` — the broker prevents client-token passthrough by construction rather
  than detecting it (blocker 9).
* `unexpected_upstream_response` — awaiting blocker 8's authoritative witness adapter.

All three funnels are wired and gated, so what is proven is the in-scope half: when such a signal is
reported, it denies AND stops. What is NOT claimed is that this node can currently generate them. `independent_witness_mismatch` is wired to the
reconciliation conflict that DOES exist today (`Executor.ReconcileAndReport` on `ReconConflict`);
that does not close blocker 8 and does not introduce a fake production witness.

**Fifteen adversarial rounds hardened this closure, and what they found is the useful record.** Each
round's fix exposed the next layer inward, which is convergence rather than churn — but every one of
the thirty-three findings was a way the latch could be right and the surrounding machinery still wrong.
Rounds 4 through 6 found defects that rounds 3, 4 and 5 had themselves introduced, which is the
honest shape of this kind of work: a fix that tightens one predicate is a new opportunity to get the
adjacent one wrong. Both round-6 findings are of that kind, and both are the SAME predicate one
shape further out — the failure classifier and the window classifier each had one caller left that
had not been brought along.

**Round 7 is the one to read if you only read one.** Rounds 5 and 6 made the error-rate detector
able to SEE a failing peer; round 7 found that seeing it did not yet STOP anything, because the
reservation went back before the sample was counted. A reachable threshold that does not prevent the
next physical invocation is not a safety control, and nothing in rounds 1–6 would have caught it:
every one of them asked whether the right thing was eventually recorded, and this asks whether it
was recorded in time.

Round 8 then showed that the round-7 fix had been drawn one step too narrow: the terminal outcome
commit is ITSELF a breach producer, so holding the slot only until the health sample was counted
left the same window open for `outcome_evidence_loss`. The lesson is worth stating as a rule rather
than an anecdote — **the slot must be held through every step that decides whether the Canary keeps
its authority, not through the one step that happened to be under discussion.** The ordered sequence
is now written out at the defer, and each of its four steps names the round that put it there.

Round 9 then did the same to round 8's OTHER fix, and the pattern is worth naming because it caught
me three times in a row. Round 8 established that a caller cancellation is not the target's fault
and marked it non-failing — but still RECORDED it, so it padded the DENOMINATOR: a cancellation plus
one good response plus one real failure is 1-of-3, under the 1-of-2 threshold. **"Not a failure" and
"not a sample" are different statements**, and each of rounds 7, 8 and 9 was a case of fixing the
statement I had in mind rather than the one the control actually needed. Round 10 completed the set
by finding that the cancellation exclusion, now correctly scoped to the population, still tested only
ONE of the two shapes a cancellation arrives in.

| Round | Finding | Why it mattered |
|---|---|---|
| 1 | Safety reports carried no activation generation | A demote-and-reactivate while a request was in flight charged its outcome to whichever activation was current when it reported: an old failure in a new detector, or an old breach latching a new experiment. `safety.go`'s own header already stated the requirement; the code did not implement it |
| 1 | The watchdog trip was not atomic with its generation check | A callback already running cannot be cancelled, so passing the check and then being descheduled latched the REPLACEMENT activation |
| 1 | An early watchdog fire disarmed the activation | A clock moving backwards fires the timer while the absolute deadline is still future; a one-shot timer that returned left NO watchdog — the exact defect this work exists to close |
| 1 | Restore turned a missing or foreign health snapshot into a FRESH monitor | Execution authority with the evidence wiped. "No evidence" is not "no failures" |
| 1 | A crash between persisting the counters and latching the abort | The counters proved a breach; the controller said all was well. Restore now RE-DERIVES the verdict |
| 1 | A failed health persist only logged | One restart away from treating the next bad attempt as the first sample |
| 1 | Exhaustion could not latch when the final slot never sent | The settled-attempt path excludes definitely-not-sent, so a boundary refusal of the LAST reservation left the status surface reporting granted authority |
| 2 | The final boundary trusted the watchdog | `time.AfterFunc` gives no ordering guarantee against the request goroutine, so "the latch will have happened" was a race |
| 2 | Restored samples were not bounded by reservations | The one damaged shape that makes the detector LESS likely to fire: fabricated clean samples dilute a real failure rate below the threshold |
| 3 | A snapshot could ERASE a hard-latency observation | `{Samples:1, Sum:15s, Hard:0}` is impossible for this writer and hid a breach the live path had already proved |
| 3 | The health sample could lag the terminal outcome | A crash between them made a failed FIRST attempt vanish, since restore legitimately accepts fewer samples than reservations |
| 3 | The health latch was not atomic with the observation | A third request could reserve and cross the boundary between the sample that proved the breach and the latch acting on it |
| 3 | The boundary tested only the upper end of the window | Every other gate treats a clock rolled back behind the activation as closed; the boundary did not |
| 4 | The ARM path still tested only the upper end | Round 3's own asymmetry. With the clock behind the activation instant every admission is closed, but `now.Before(deadline)` reads "an hour left" — so nothing latched, a watchdog was armed for a distant deadline, and its callback re-armed through the same one-ended check. `auto_stop` reported GRANTED authority indefinitely on a Canary that could not execute at all |
| 5 | The error-rate detector could not see the peer failing | `failed` was derived from the send state, and a non-200, an unreadable body and an undecodable one all record `peer_response_received` — because a peer that answers badly has still RUN the tool. Two consecutive HTTP 500s produced ZERO failures, never reached the 1-of-2 threshold, and a third execution was admitted against a demonstrably unhealthy target |
| 5 | A window denial at admission was named `budget_exhausted` | `WholeCanaryExhaustion` groups the window denial with the total denial, and the first cause is immutable — so the operator-visible reason for a closed time box depended on which path noticed first, this admission or the watchdog |
| 6 | A JSON-RPC `error` object counted as a success | Round 5's replacement predicate was transport-only. The peer answering "the tool failed" arrives as a non-nil response with a nil Go error — and `finishUpstream`, two hundred lines below, already classifies exactly that response as `ReasonUpstreamCallFailed`. The detector disagreed with the code beside it about the most ordinary tool failure there is |
| 6 | The operator surface was more optimistic than the admission gate | Rounds 3 and 4 taught the boundary, the arm path and the callback the two-ended window predicate; the STATUS builder kept the upper-bound test. Under a clock rolled behind the activation it rendered `window_expired:false` and `execution_authority:"granted"` while every reservation was denied — for the whole remaining timer duration, which is exactly when an operator reads it |
| 7 | The reservation was released before the health sample was counted | The settle rode the outer defer while `release()` rode the leg's, so the release necessarily ran first. At `MaxConcurrentExecutions = 1` a third request could reserve and cross `Upstream.Call` before the second failure was counted — the 1-of-2 threshold was reachable, and still did not prevent the next physical invocation. The round-3 latch-atomicity finding one level further out: there the latch was not atomic with the OBSERVATION, here the observation was not ordered against the RELEASE |
| 8 | The release still preceded the terminal outcome commit | Round 7's fix was one step too narrow. A failed outcome commit IS the `outcome_evidence_loss` breach, and it runs after the settle, so the same window stayed open for it |
| 8 | A pinned-identity mismatch was reduced to one failed sample | The request-scoped live-trust check reads the CATALOG before the dial, so the ACTUAL peer's identity is judged only at the transport. `server_identity_drift` is single-occurrence, but as a sample the FIRST mismatch stopped nothing and another invocation could be admitted against a server we can no longer identify |
| 8 | A caller cancellation was charged against the target | `context.Canceled` means the CLIENT went away. Two of them reached the 1-of-2 threshold and would have stopped a Canary that had nothing wrong with it — the direction a safety threshold must never err in for the opposite reason to all the others |
| 9 | The cancellation was excluded from the NUMERATOR but not the population | Round 8's own fix, one notch short. Recorded as a non-failing sample it padded the denominator, so a cancellation plus a success plus a real failure was 1-of-3 and the Canary stayed active. "Not a failure" and "not a sample" are different statements |
| 10 | Only one of the two cancellation SHAPES was matched | The transport treats everything after response headers as "a failure of the ANSWER, never of delivery", so a caller who hangs up during the BODY read is wrapped as `ReasonUpstreamCallFailed`. A reason-only test read that as the target failing, and two such hang-ups would trip `elevated_error_rate` on a peer that answered both times |
| 11 | The runbook's PROCEDURE step still described request-driven expiry | The status table and §16 were updated when the blocker closed; step 8 — the one an operator follows at the window boundary — was not, so the same file gave two mutually exclusive accounts of the same behaviour |
| 12 | The watchdog callback read the clock four times | Openness, "is the deadline ahead", the re-arm duration and the trip timestamp were separate samples. A wall-clock step between any two lets the callback pick contradictory branches and re-arm the only traffic-independent stop for a duration measured from an instant it had already rejected |
| 12 | The §16 trip-path table still gave `out_of_scope_execution` a producer | It mapped the code to the identity-cap breach, which the enforcer actually reports as `scope_escape`. An operator auditing producer coverage there would have reached the conclusion the previous commit existed to remove |
| 13 | A directly classified breach was ALSO counted as a health sample | Round 8 added the identity breach and left the settle unconditional, so a pinned-identity mismatch was both a whole-Canary stop and an ordinary target failure in the rate population — the laundering `HealthMonitor`'s own contract forbids in as many words. One event feeding two different stop decisions, and an identity breach shown as a target failure on the persisted counters |
| 14 | Two of the THREE tool-drift detections reported nothing | Drift is caught before the executor (`refuseOnToolDrift`), at admission (the gate's classifier) and at the final boundary (`ToolStillCurrent`), and only the middle one routed anywhere. A rug-pull landing in either other window refused the request and left the Canary holding execution authority — and every later request against the new fingerprint then merely failed approval validation, which reads as routine denial rather than proof the reviewed target is gone |
| 14 | The real-peer rig leaked abort state between tests | Found by the determinism gate, not by a review: the rig resets every global it touches except `globalCanaryRuntime`, which did not matter while only reservation paths latched. Once a REFUSAL could latch, a stop set by one test was visible to whatever the shuffle ran next. The gate exists for exactly this, and it earned its keep the first time a latch moved onto a new path |
| 15 | A drift observed alongside an emergency kill was dropped | The breach was keyed on which refusal WON. The kill deliberately wins the reason reported to the CLIENT, but the drift is a fact about the world — and since a kill can be CLEARED, the activation would resume unlatched against the new fingerprint |
| 15 | Drift on shadow-evaluated traffic stopped the whole Canary | With Shadow fallback, an OUT-OF-SCOPE Canary request still reaches the pre-executor refusal, so a catalog change for a tool the experiment never reviewed aborted it. The one finding of the fifteen in the FALSE-POSITIVE direction, and the most dangerous kind: a healthy experiment stopped for something outside its blast radius is indistinguishable, to an operator, from a broken control |
| 15 | An eligibility change was reported as fingerprint drift | `toolHasDrifted` is true for two different facts, and the code was hard-coded. `DisableServer` preserves the fingerprint on purpose, and the admission-time classifier calls that condition `server_identity_drift` — so the IMMUTABLE first cause depended on which detection window won, and could tell an operator the tool's shape changed when they had disabled the server themselves |

Two of these deserve to be remembered past this PR. The generation finding and the health-latch
finding were both **gaps my own comments described and my own code did not implement** — the header
of `safety.go` stated the generation requirement verbatim, and `observeAttemptSettled` justified
splitting the latch from the observation with deadlock reasoning that `tripAutoStopLocked` had
already made obsolete. A comment that states an invariant is not the invariant.

A third deserves to be remembered for a different reason. The round-5 error-rate fix was first
proven by a gate that **passed against the defective predicate as well as the fixed one**: a bare
`errors.New` leaves the send state at `may_have_been_sent`, where the OLD predicate also reports a
failure, so the fixture never reproduced the defect it was written for. The mutation campaign caught
the GATE, not the code. It was fixed by adding `upstreamclient.MarkResponseObservedForTest` — the
mirror of the existing never-sent seam — so an executor-side double can produce the exact error
shape the production client returns for a non-200. A gate that cannot fail against the defect is
not evidence, and only a mutation that restores the defect can tell you which kind you have.

**And it repeated one round later, which is why it is written down twice.** The round-6 status gate
first attempted a reservation before reading the surface — but a reservation under a closed window
LATCHES `window_expired` (round 5's own fix), after which the surface reports revoked authority for
the ORDINARY reason. The assertion passed against a status builder that had never learned the window
at all, and M98 survived. The finding is about the interval where NOTHING has arrived to latch — no
traffic, no timer — so the gate now reads the status first. A fixture that reaches the right answer
through the wrong path proves nothing, and the second time you make that mistake it is a habit, not
an accident.


**This closure changes nothing about the verdict.** Blocker 7 was one of fifteen reasons a GO is
forbidden. Twelve remain open and blocker 8 remains open-but-narrowed.


### Blocker 7 — deterministic concurrency matrix

Eleven cases, in `mcp_canary_autostop_conc_test.go`, all barrier-driven (no sleeps) and all run under
`-race`. The matrix exists because the abort latch and the admission path are the same lock's two
sides, and "the latch wins" is only true if it is true at every interleaving.

| Case | What it pins |
|---|---|
| CONC-01 breach vs. simultaneous reservation | the reservation either predates the latch or is denied; never both granted and latched-before |
| CONC-02 breach while many await admission | every waiter that arrives after the latch is denied; none slips through on the lock handoff |
| CONC-03 two breaches race for first cause | exactly one code latches, and it is stable — the loser never rewrites the reason |
| CONC-04 deadline vs. reservation | a reservation racing the window boundary cannot land past it |
| CONC-05 deadline vs. restart | a restart racing expiry restores as aborted, never as a fresh window |
| CONC-06/07/08 breach vs. next request | the request after the breach is denied on all three arrival orders |
| CONC-09 budget exhaustion vs. N+1 | the N+1 is denied and exhaustion latches once, not per racer |
| CONC-10 status read under concurrent trip | the operator surface is consistent under contention — it never reports `granted` after the latch |
| CONC-11 latch during in-flight admission | an admitted request that has NOT yet called upstream sends nothing more; the final revalidation catches it |

### Blocker 7 — red team

Thirty-four adversarial scenarios, each answered by a named gate rather than by argument.

| Scenario | Outcome | Gate |
|---|---|---|
| Evidence disk fails AFTER the peer executed | `outcome_evidence_loss` latches the whole Canary (the metric still fires, in parallel) | `TestAutoStop_OutcomeEvidenceLossAbortsTheWholeCanary` |
| Two breaches arrive simultaneously | one latches; the first cause is stable and the second is dropped, not merged | `TestAutoStop_FirstCausePreservedAcrossLaterBreaches`, `TestAutoStopConc03_TwoBreachesRaceForFirstCause` |
| The clock moves BACKWARD | no additional authority: remaining time is measured against the same absolute deadline | `TestAutoStop_ClockRollbackGrantsNoExtraAuthority` |
| Crash 1 ms BEFORE the deadline | restore re-derives the absolute deadline and arms a watchdog for the REMAINING time only | `TestAutoStop_RestartNeverGrantsAFreshWindow` |
| Restart 1 ms AFTER the deadline | `window_expired` latches synchronously under the same lock the admission path takes, before any admission is possible | `TestAutoStop_RestartAfterExpiryRestoresAborted`, `TestAutoStopConc05_DeadlineVersusRestart` |
| NO request arrives for the whole window | the watchdog stops the experiment anyway — this is the case the pre-fix design could not handle | `TestAutoStop_WindowExpiresWithNoTrafficAtAll` |
| A breach lands between reservation and the final kill boundary | the request fails the final live revalidation and makes no upstream call; the unaborted control still crosses | `TestAutoStop_LatchedAbortStopsAnAlreadyAdmittedRequestBeforeTheCall` + `TestAutoStop_ControlUnabortedRequestStillCrosses`, `TestAutoStopConc11_LatchDuringInflightAdmissionSendsNothingMore` |
| The witness reports a receipt contradicting our record | `independent_witness_mismatch` latches | `TestAutoStop_WitnessConflictAbortsTheWholeCanary` |
| A physical AttemptID appears twice at the peer | same path — the duplicate is a reconciliation conflict, not a tolerated retry | `TestAutoStop_WitnessConflictAbortsTheWholeCanary` (duplicate-witness fixture) |
| Requests keep arriving after the abort | every one is denied at reservation; nothing reaches the upstream | `TestAutoStop_LatchedAbortMakesNewReservationImpossible`, `TestAutoStopConc06to08_BreachVersusNextRequest` |
| The persisted abort/deadline state is corrupted | the record never restores into an executable activation, and the status surface does not report `granted` | `TestAutoStop_CorruptPersistedStateNeverLoadsAsExecutable` |
| A stale watchdog from a previous activation fires | it aborts nothing: the callback is generation-guarded AND re-derives the deadline | `TestAutoStop_StaleWatchdogCannotAbortALaterActivation` |
| An unrecognised breach code is reported | fails closed to whole-Canary | `TestAutoStop_UnknownBreachCodeFailsClosed` |
| A breach is reported for the OTHER capability | ignored; Gateway and Management are physically isolated | `TestAutoStop_BreachIsCapabilityIsolated` |
| The clock is rolled back BEHIND the activation instant | the boundary AND the arm path both read the window as closed, so the activation latches `window_expired` instead of arming a watchdog for a phantom hour | `TestAutoStop_ClockRollbackBehindActivationClosesTheBoundary`, `TestAutoStop_ClockBehindActivationLatchesAtRestoreInsteadOfArming` |
| The watchdog fires while the clock is behind the activation | it latches rather than re-arming; the callback consults the window-open-aware accessor, not the bare upper bound | `TestAutoStop_WatchdogFiringUnderRollbackLatchesInsteadOfReArming` (control: `TestAutoStop_ClockInsideTheWindowStillArmsNormally`) |
| The wall clock steps WHILE the watchdog callback is deciding | every branch is decided from one sample, so the callback cannot both call the window open and measure the remainder from before the activation began | `TestAutoStop_WatchdogDecidesEveryBranchFromOneClockSample` |
| The target answers every call with HTTP 500 | each is a settled attempt and a FAILURE, so the second trips `elevated_error_rate` at the 1-of-2 threshold — the peer answering badly is exactly the population the detector exists to judge | `TestAttemptSettled_PeerErrorResponseCountsAsAFailure` (control: `TestAttemptSettled_SuccessfulExecutionIsNotAFailure`) |
| Culvert's own DLP blocks a request AFTER the peer answered | NOT a failure: the target is healthy and the policy is working. A Canary must not abort itself for its own controls firing | `TestAttemptSettled_SuccessfulExecutionIsNotAFailure`, `TestAutoStop_RequestScopedRefusalsNeverStopTheCanary` |
| The time box closes and an admission notices before the watchdog | both name `window_expired`; the immutable first cause no longer depends on which path won the race | `TestAutoStop_WindowDenialAtAdmissionRecordsWindowExpired` (control: `TestAutoStop_TotalExhaustionStillRecordsBudgetExhausted`) |
| A crash lands between the settled sample and the terminal outcome | the sample is persisted FIRST, so the crash over-counts an outcome record rather than erasing failure evidence — and a missing outcome is already a breach | `TestAttemptSettled_IsReportedBeforeTheTerminalOutcomeCommit` |
| The persisted health record claims more samples than reservations | refused: fabricated clean samples are the one damaged shape that makes the detector LESS likely to fire | `TestAutoStop_InflatedSampleCountNeverRestoresAsExecutable` (control: `TestAutoStop_HonestSampleCountsStillRestore`) |
| The target answers with a JSON-RPC tool error rather than an HTTP error | the same failure: the peer ran nothing useful and said so, so the second one trips `elevated_error_rate` | `TestAttemptSettled_PeerJSONRPCErrorCountsAsAFailure` (control: `TestAttemptSettled_SuccessfulExecutionIsNotAFailure`) |
| An operator reads the surface during a rollback, before any request or timer | it reports `window_expired` and revoked authority — reporting the closed window WITHOUT latching, so the abort controller stays the one authority | `TestAutoStop_StatusIsNeverMoreOptimisticThanAdmission` (in-test control: an open window still reports a live experiment) |
| A third request is waiting while the second attempt fails | it cannot reserve: the sample is counted and the latch decided BEFORE the slot goes back, so the 1-of-2 threshold actually prevents the next invocation rather than merely recording it | `TestAttemptSettled_IsReportedBeforeTheReservationIsReleased` (in-test control: the slot is still released exactly once — an ordering fix that leaked the reservation would otherwise pass) |
| The evidence volume dies and the terminal outcome cannot be written | `outcome_evidence_loss` latches, and the slot is still held while it does — the next request cannot reach the upstream while that breach is being recorded | `TestBreach_OutcomeEvidenceLossIsReportedBeforeTheReservationIsReleased` |
| The connected peer's TLS identity no longer matches its pin | `server_identity_drift` latches on the FIRST occurrence, before the slot goes back — not after a second sample | `TestBreach_TLSIdentityMismatchTripsServerIdentityDrift` (control: `TestBreach_OrdinaryUpstreamFailureIsNotIdentityDrift`) |
| That same identity breach reaches the rate detector too | it does not: a condition with its own immediate classification is excluded from the population, so one event cannot feed two stop decisions | `TestBreach_TLSIdentityMismatchTripsServerIdentityDrift` (control: `TestBreach_OrdinaryUpstreamFailureIsStillASample` — an ordinary failure IS still a sample) |
| The reviewed tool is redefined BEFORE the request reaches the executor | the pre-executor refusal reports `tool_fingerprint_drift` through the runtime's narrow seam; the request fails AND the experiment stops | `TestCanaryBreach_PreExecutorToolDriftIsReported` (controls: `TestCanaryBreach_CurrentFingerprintReportsNothing`, and `TestCanaryBreach_NoSeamComposedIsAPlainRefusal` for the disabled-by-default posture) |
| The reviewed tool is redefined AFTER admission, at the final boundary | the same code, carried with the ATTEMPT's generation so a demote-and-reactivate cannot charge it to a fresh experiment | `TestBreach_BoundaryToolDriftTripsFingerprintDrift` (control: `TestBreach_UndriftedBoundaryRaisesNoDriftBreach`), and end to end against the real peer in `TestConc07_ToolDriftAfterIntentRefusesTheSend` |
| The tool drifts AND the emergency kill engages in the same pass | the client is told the kill is the reason (its precedence is unchanged) and the Canary is still told about the drift | `TestBreach_DriftIsReportedEvenWhenTheKillWinsTheRefusal` |
| A tool the experiment never reviewed drifts, under Shadow fallback | the request is refused and the Canary keeps running — the stop is bound to the enforcing execute disposition, not to every request that reaches the refusal | `TestCanaryBreach_ShadowEvaluationDoesNotStopTheCanary` |
| The operator disables the server, leaving the fingerprint intact | `server_identity_drift`, the same name the admission-time classifier gives it — not `tool_fingerprint_drift` | `TestCanaryBreach_EligibilityDriftIsNotCalledFingerprintDrift` |
| The client hangs up mid-call, twice | nothing stops, AND nothing is recorded: a cancellation is not evidence about the target in either direction, so it never enters the population to dilute it. A deadline overrun still is a charged sample | `TestAttemptSettled_CallerCancellationIsNotASampleAtAll` (a five-row table covering BOTH cancellation shapes — reason-classified and wrapped-during-body-read — each ⇒ 0 samples, against a deadline wrapped the SAME way, a plain deadline and a connect failure ⇒ 1 charged sample each) |

The three controls that keep this from being a proof of "abort on everything": a healthy population
never stops the Canary (`TestAutoStop_HealthyPopulationNeverStopsTheCanary`), request-scoped refusals
never stop it (`TestAutoStop_RequestScopedRefusalsNeverStopTheCanary`), and a merely unauthorized
request never stops it (`TestAutoStop_MerelyUnauthorizedRequestDoesNotStopTheCanary`).


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

### Round 20: three holes in three rounds is a structural signal

M17's CAUGHT condition is `sink_rc == 0 && spool_rc != 0` — the sink side must PASS while the
real-spool side FAILS. But an unmatched `-run` pattern also exits 0, so if M17's sink gate ever
drifted, a genuinely failing spool side would score the mutation CAUGHT **while its required
control never ran**. Round 19 had added the build check to both of M17's sides and left the
no-tests check off.

That is the third consecutive round finding a hole in a hand-rolled copy of the same
classification: round 18 found the build check missing from `run_mutation`, round 19 found it
missing from M02 and M17, round 20 found the no-tests check still missing from M17. **Three
holes in three rounds is a structural signal, not three coincidences** — duplicated
classification is what kept producing them — so this round replaces the duplication rather than
patching it again.

`gate_ran` is now the single answer to *"did this invocation actually reach an assertion?"*.
There are exactly two ways it does not, and each is misread by a bare status check: the pattern
matched no tests (exit 0, indistinguishable from a pass) or the package did not build (nonzero,
indistinguishable from a caught mutation). `run_mutation`, M02 and M17 all route through it, and
M17 applies it to both sides it drives. The one deliberate exception is `--compile-wall`, decided
before `gate_ran` because a build failure is that case's proof rather than its absence.

Demonstrated in all three directions rather than asserted: the defect shape (drifted sink
pattern + failing spool) scored CAUGHT before and is rejected now, and a genuine two-sided
demonstration still scores CAUGHT.

### Campaign state

`scripts/mcp-canary-mutation-campaign.sh` now carries **110 mutations** (M61–M78 are the blocker-7
auto-abort set; M79–M110 were added by the fifteen adversarial rounds above — 107 driven through
`run_mutation`, plus M02, M17 and M80, which stay hand-written because they mutate more than one
site; M91 stopped needing a helper when round 8 collapsed the three orderings into one block). The 78-mutation state recorded below was clean on its second run;
M79–M110 were each verified failing against their own reintroduced defect as they were written. The
first scored 71/3/4 and every one of the seven was a defect in the PROOF, not in the abort wiring —
which is the campaign doing its job, so it is recorded rather than quietly re-run:

- M62/M63/M72/M75 named ROOT-package gates but ran them in `./internal/mcp/canary`, where they
  matched no tests. The mutated package is a dependency of the root package, so the root gate
  exercises it; the package argument was simply wrong. The `gate_ran` classifier caught all four as
  BROKEN GATE rather than scoring them as passes — the reason it exists.
- M65/M66 SURVIVED because the drift gates stubbed `trustOK`, the very classifier those mutations
  target. They proved the trip ROUTING and nothing about the CLASSIFICATION. They now drive the real
  `mcpLiveTrustRevalidate` through a real inventory and a real four-eyes live approval, stubbing only
  the live-tier lifecycle seam (that tier is deliberately never armed in this build, so the
  production `admit` would reject before the trust check is reached). **Stub the smallest thing that
  is in the way, never the thing under test** — the same lesson as round 17's "a mutation must be
  caught for the RIGHT reason", arriving this time through a test double rather than a compiler.
- M70 SURVIVED because this PR's own traffic-independent settle-site latch covers for the
  reserve-site trip: with the reserve trip deleted the experiment still stops, one event later.
  `TestAutoStop_DeniedReservationItselfTripsBudgetExhausted` isolates it — nothing settles (the
  single slot is still in flight), so only the refusal itself can stop the Canary. Two paths to the
  same code need two gates, or either can be deleted unnoticed.

One incidental hole surfaced with them: `TestAutoStop_LatchedAbortMakesNewReservationImpossible`
never read the latch, only that admission had closed. Those are different questions — a latch that
cleared itself when read would leave admission correctly shut while the node reported a healthy
experiment — so it now asserts the latch is observable and stays observable across reads — every one rejected by a named assertion, the race mutation by an
attributed detector report, and none by a build failure. Each reintroduces one specific defect and must fail a NAMED gate; a compile failure is
not counted as proof unless the mutation targets a structural wall whose purpose is compile-time
prevention, a gate matching no tests is a hard campaign failure, and a mutation whose pattern no
longer matches the source is scored as a FAILURE rather than a pass.

That last rule earned its keep TEN times, every one of them against a fix made *inside this work*.
M03, M04 and M12 drifted against refactors done here — the `runExecute` decomposition made to satisfy
the complexity linters, and the `RecoverAttempts` split. M20 drifted against the binding fix above,
in the very same file the mutation M32 targets. M45 drifted when round 11's checks were folded into
one helper, M50 when round 13 restated a coupling over the allowed set and flipped the operand, and
M31 when round 14 renamed `markResponseObserved` to `markLegFacts`. Round 15 then killed three more
at once, because it changed the shape of the very code the round-14 gates measure: M07 against the
new two-value `preCallGuard` signature, M106 against the pre-executor breach moving inside
`if canaryScoped { … }`, and M107 against the boundary condition becoming `driftObserved` rather
than `cls.stale`. A campaign that scored a skip as a pass would have reported a clean run over ten
dead gates — and six of the ten would have gone dead in exactly the rounds that were hardening the
code they measured. The rule is not defensive tidiness: a mutation campaign measures the GATES, and
a pattern that no longer matches measures nothing at all.

Two repairs carry a second rule with them. M107 cannot simply delete its target: `driftObserved` is
bound from `preCallGuard` and deleting its only use stops the tree compiling, and a build failure
proves nothing under this campaign's own header rule. It substitutes `_ = driftObserved`, the same
guard M108 already needed. Every repair here was verified end to end before the run that counted it
— the pattern APPLIES (the file actually changes), the tree BUILDS, and the gate fails by a NAMED
security assertion — because the failure mode being guarded against is a mutation that looks caught
while proving something other than what it claims.

---

## §25b Blocker 13 closure (governed catalog usability as a First-Canary activation fact)

This section records ONE status change: **blocker 13 is CLOSED**. Nothing else in the ledger moves.
Blocker 8 remains OPEN (narrowed), blocker 14 remains OPEN, the baseline is still fifteen, and the
§26 verdict is unchanged — `BLOCKED — NO SAFE FIRST CANARY TARGET`.

**The defect.** `seedTools` lands every ingested tool `catalog.Quarantined`, and the policy engine
hard-overrides a `DispQuarantined` tool to `ActionQuarantine` BEFORE any operator rule is consulted.
Nothing in the activation preflight said so. A node could hold a valid four-eyes live approval, a
reviewed target, an exact one-of-everything scope and a read-first classification, report
`Ready:true`, and then have every single request die at that override. That is the worst shape a
readiness verdict can take: not a wrong answer to a question that was asked, but a green light for
an experiment nobody had asked the deciding question about.

**The closure bar.** The machine — not a runbook, not an operator attestation — must refuse to
report an activation ready when the exact scoped tool is not `catalog.Usable` at the exact
fingerprint the activation binds, and it must do so without inventing a second authority over
usability.

| Clause | Evidence |
|---|---|
| A machine-visible activation fact, not a runbook step | `canary.Facts.ToolCatalogUsable` / `canary.ReasonToolNotCatalogUsable`, an `factActivation` row in the one readiness table. `TestCatalogUsable_ProductionPreflightCarriesTheRow` drives the whole production path — `productionCanaryActivationInputs` → `evaluateCanaryActivationPreflight` → the table — and requires the reason present for a Quarantined tool and absent after a governed promotion |
| THE EXACT CURRENT SCOPED TARGET, never general catalog health | `ReasonCatalogUnhealthy` already answers "is the catalog readable". This answers "did THIS ONE governed target pass the trust lifecycle": a perfectly healthy catalog whose record for the scoped tool is Quarantined satisfies the first and fails this one (`TestCatalogUsable_SeededToolIsQuarantinedAndNotUsable`) |
| Fingerprint-bound: F2 inherits nothing from F1 | `TestCatalogUsable_F2DoesNotInheritF1Usability` (the sticky Quarantined floor half) and `TestCatalogUsable_UsableRecordDoesNotSatisfyAScopePinnedElsewhere` (the other half — a genuinely Usable record whose digest is not the pinned one), so neither guard can hide behind the other |
| Format-bound | Not by a second comparison, which against the same record would be a self-comparison no test could distinguish. `catalog.Fingerprint.Sum` writes `FormatVersion` before any other segment, so the digest comparison is format-bound by construction; the property is pinned directly by `TestCatalogUsable_FingerprintFormatIsFoldedIntoTheBoundDigest` |
| Tenant-bound | `TestCatalogUsable_TenantThatDoesNotOwnTheServerIsNotUsable` — ownership is read DIRECTLY from the single registry snapshot the resolver already holds (`servers.Get(...).OwnerScope`), an independent source from the catalog record. It is deliberately NOT resolved through `loadTarget`, which re-reads both current snapshots and would put the decision back across two reads — see the one-read row below |
| NO SECOND TRUST AUTHORITY (§2/§3) | The governed `shadow_evaluation` lifecycle (`ApproveShadow` → `promoteFor` → `catalog.Promote`) remains the only writer. `ApproveLive` still deliberately promotes nothing: `TestCatalogUsable_LiveApprovalAloneNeverPromotes`, with `TestCatalogUsable_ExactShadowApprovalPromotes` as its positive control and `TestCatalogUsable_ShadowAndLiveAreIndependentFacts` proving the two are separately satisfiable rather than one standing in for the other |
| NO DATA-PLANE PROMOTION (§8), anti-vacuously | `TestCatalogUsable_OnlyTheGovernedCoordinatorPromotes` is an AST wall by CALLER: every `catalog.Promote`/`Demote` reference in the root package must live in `mcp_tooltrust.go`. It additionally asserts the governed path IS still visible to the test, so a wall that found zero callers because the promotion lifecycle had been deleted fails instead of passing |
| Blocker 7 is not bypassed (§6) | `TestCatalogUsable_UsableF2StillRefusedByAnF1ReviewedActivation` — a freshly promoted, live-approved F2 does NOT match an activation whose immutable reviewed snapshot binds F1. Usability is LIVE governance state and is deliberately never copied into that snapshot; F2 requires a new activation generation |
| Revocation and expiry (§7) | `TestCatalogUsable_RevokingLastPromotionDemotes` (the last valid promotion going away demotes) paired with `TestCatalogUsable_RevokingOneOfTwoPromotionsStaysUsable` (another valid authority still qualifies, so the tool stays Usable) — the two directions of the same rule, each the other's control |
| Restart durability without a second ledger (§9) | Usability is a PROJECTION of the durable tool-trust store, re-derived by the coordinator's reconcile. `TestCatalogUsable_RestartDoesNotResurrectStaleUsability` — a revoked promotion stays demoted across the reconcile a restart performs. No catalog-usability ledger was added |
| TOCTOU: a preflight verdict is about its own instant | `TestCatalogUsable_WithdrawnAfterPreflightStillHardQuarantines` — a promotion withdrawn after a Ready verdict makes the fact false on re-observation (it is never cached), and the runtime consequence is delivered by the EXISTING policy hard-override, so closing this blocker did not move enforcement out of the policy engine |
| Why it matters, end to end | `TestCatalogUsable_PolicyQuarantineOverrideClearsAfterGovernedPromotion` — same policy, same rule, same request; the only variable is the governed catalog disposition. Before: `ActionQuarantine` / `MCP.TOOL.UNKNOWN`, no rule consulted. After: ordinary evaluation is reached |
| Fail-closed on the degenerate inputs | `TestCatalogUsable_EmptyScopeIsNotVacuouslyUsable` (a scope admitting no tool must not satisfy a fact about its tools) and `TestCatalogUsable_AbsentInventoryFailsClosed` (the condition under which nothing is known about the tool is the condition under which the fact must not be claimed) |
| The fact reaches every activation call site | `TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall` — an AST wall requiring every field of `canaryActivationInputs` to be forwarded at every `CanaryActivationInput` literal in `mcp_rollout.go` (the transition commit and the restart reconcile). It is deliberately WIDER than blocker 13: dropping any activation fact at a commit site is the same defect. It is structural because no behavioural test can reach either site in this build — the live tier is never armed, so the commit refuses at an earlier gate and a dropped field is invisible |
| Expiry is materialized before the read | `TestCatalogUsable_ExpiredPromotionIsNotUsableBeforeTheReconcileTick` — expiry is PASSIVE, so a grant past its `ExpiresAt` leaves its tool `Usable` until the 30-second reconcile tick. The resolver reconciles before snapshotting, as `shadowScopeHasUsableTool` does under ADR-0034 D7, with `TestCatalogUsable_ReconcilingToReadNeverPromotes` as the control that a read path did not become a promotion path (Codex P2 round 1) |
| ONE read of each source per decision | `TestCatalogUsable_ResolverReadsEachSnapshotExactlyOnce` — the verdict is derived from exactly one catalog snapshot and one registry snapshot, and `loadTarget` (which re-reads both) is not called, so a republish landing mid-scan cannot pair an old Usable record with newer ownership (Codex P2 round 2) |
| The registry/catalog PAIR is detected, not assumed | `TestCatalogUsable_RepinWindowIsNotUsable` — `Registry.Repin` and the catalog re-ingest that follows it are SEPARATE publications, so between them the registry pins I2 while the record describes I1. One snapshot of each source (row above) is NECESSARY AND NOT SUFFICIENT: it makes the decision consistent AS A READ and cannot reconcile two publications that disagree, because the inconsistency is in the published state rather than in the reading of it. The resolver therefore compares `rec.Fingerprint.Identity` against `srv.PinnedIdentity` — `loadTarget`'s own formula, over the two snapshots already held, so no read is added. Without it the row reports met for a target whose every request the runtime refuses as `AnchorLost`/`RegistryPinDiverged` (`TestReviewedBinding_C18`) — a Canary that activates and cannot execute (Codex P2 round 6). `TestCatalogUsable_CoherentPairStillUsable` is the control, since the cheapest way to pass is to refuse everything |
| The registry window is DRIVEN, not asserted | `TestCatalogUsable_DisabledServerInTheRegistryWindowIsNotUsable` + M22. **The round-7 claim that this could only be pinned structurally — "reaching it needs a production seam purely to let a test drive a race" — EXPIRED in round 8**, which added `mcpToolTrustReconcileSnapshot` for the coherence fix. That seam hands the resolver BOTH snapshots, i.e. its entire view of the world, so the divergent state is injectable with no new production surface: promote under governance, `SetEnabled(false)` on the REGISTRY only, then inject (disabled registry, still-Usable catalog) and require `false`, with the healthy pair as the control. Recorded because the reasoning generalises — **an "unreachable without a new seam" argument is only valid until some other change adds the seam, and nothing re-examines it automatically** (Codex P2 round 11) |
| `srv.Usable()` — LOAD-BEARING, and the only check rejecting one interleaving | This row previously said UNREACHABLE. That was WRONG (Codex P2 round 7). `TestCatalogUsable_DisabledServerIsNotUsable` does pass with and without the line, but it is SEQUENTIAL: its disable lands before the reconcile, which demotes the record, so the eligibility check rejects it and this guard is never reached. The registry publishes INDEPENDENTLY of the resolver, so a disable — or, sharply, a mismatching `Registry.VerifyIdentity`, whose branch clears `Enabled` but DOES NOT TOUCH `PinnedIdentity` (`registry.go:136-148`) — can instead land AFTER `mcpToolTrustReconcile()` returns and BEFORE `reg.Current()` is read three lines later. In that window the record is still `Usable`, the tenant still owns the server, the digest still matches, and the identity comparison above still passes because the pin never moved: `srv.Usable()` is the ONLY check that rejects it. Reaching it behaviourally needs a production seam interposing between the reconcile and the registry read purely to let a test drive a race — the worse trade, and the same call made for the snapshot race in round 2 — so it is pinned by `TestCatalogUsable_ServerUsabilityGuardIsPresent` and campaign M18 |
| The trust-store/catalog pair is PREVENTED, not detected | `TestCatalogUsable_ResolverReadsEachSnapshotExactlyOnce` (structural) + M19. `Revoke` holds `deriveMu` across `store.Revoke` AND the catalog demotion so the pair moves together; a reader that reconciles, RELEASES the lock, then reads `cat.Current()` can be scheduled into the middle of that section and see a durably-revoked approval whose tool is still `catalog.Usable` — every other check passes and the row reports met (Codex P2 round 8). `mcpToolTrust.reconcileAndSnapshot()` now reconciles and captures BOTH snapshots under ONE hold. **TWO PAIRS, TWO REMEDIES:** the registry/catalog pair CANNOT be closed by locking — the inconsistency is in the published state — so it is DETECTED; this pair CAN be, because one writer owns both halves, so it is PREVENTED. Which remedy applies depends on whether a single writer owns the pair |
| The gate asserts the CRITICAL SECTION, not the lock call count | `TestCatalogUsable_ResolverReadsEachSnapshotExactlyOnce` + M20. The round-8 gate counted any selector named `Lock` and any `Current()`. That shape PASSES against a `reconcileAndSnapshot` whose unlock is moved AHEAD of the two captures — one lock, one read of each source, gate green — while `Revoke` can persist a revoked approval in the window between the unlock and the captures, restoring exactly the interleaving the round-8 fix exists to prevent (Codex P2 round 10, raised against my own gate; verified by building that function and running the gate against it: `ok, 0.096s`). The gate now requires the lock to be `deriveMu` BY NAME, its unlock to be DEFERRED, and no bare `deriveMu.Unlock` to appear — a deferred unlock runs after the return expression is evaluated, so both captures are inside the section BY CONSTRUCTION rather than by reading statement order. **This is the SECOND wall on this PR that pinned something weaker than the invariant it advertised** (the first counted `Current()` by receiver identifier and scored zero against a mutation reading through `rg`), so the standing rule is: a structural wall must assert the PROPERTY the fix rests on — call counts are a proxy for it, not the thing itself |
| The coherence gate is structural, and the behavioural one is labelled as a control | `TestCatalogUsable_ResolverDoesNotDeadlockUnderDerivation` proves liveness only — no deadlock, row not emptied. It is NOT the coherence gate: `mcpToolTrustReconcile` also takes `deriveMu`, so the PRE-FIX shape blocks identically. Measured, not assumed — the first version of it was written as the proof and PASSED against the reintroduced defect. The structural wall was verified to discriminate ("the resolver reads the inventory directly 2 time(s)") |
| The read-path seams cannot be half-wired | `installToolTrustReadHooks` / `clearToolTrustReadHooks` install and clear BOTH seams together. Installing only the reconcile hook leaves the coherent seam at its fail-closed default, which does not error — it silently makes this row unsatisfiable. Test wiring mirrors production by calling these rather than assigning the vars |
| An interrupted campaign restores its mutation | The harness records the file under mutation before the first edit and clears it after the revert, with an EXIT/INT/TERM trap restoring whatever is still recorded (Codex P2 round 8). Verified by killing a live run mid-mutation and watching the file come back clean. SIGKILL cannot be trapped, so the residual is bounded by the pre-existing dirty-tree refusal: a stranded mutation stops the NEXT run rather than being silently re-measured |
| Campaign | `scripts/mcp-first-canary-catalog-usable-mutations.sh` — 32 mutations, 32 caught, 0 survived, 0 skipped |

**What the campaign taught, recorded because it changes how a first run should be read.** The FIRST
run scored 7 caught, 5 survived, 2 not-proven, and every one of those seven was worth having.

Three survivors were genuine missing gates. Two were degenerate-input cases nothing covered — an
empty scope satisfying "every tool the scope admits is Usable" by vacuous truth, and an absent
inventory failing OPEN on the exact condition under which nothing is known about the tool. The third
was structural and would not have been found any other way: the production path resolves activation
facts once and HAND-SPREADS them into a `CanaryActivationInput` at two call sites, and dropping a
field at either was invisible to every behavioural test, because in this build the live tier is never
armed and the commit refuses at an earlier gate. That is the shape a survivor is most valuable in —
not a gate that was weak, but a site no gate could reach.

Two were defects in the campaign itself, and the second is the one worth carrying forward. M08 left
two imports unused, so it failed to BUILD, which under this campaign's own header rule proves
nothing. M09 targeted a line that also occurs, IDENTICALLY AND EARLIER IN THE SAME FILE, inside
`buildLiveApprovalBindings`: an unanchored substitution mutated that function instead, the gate
passed for an entirely correct reason, and the result read as a hole in the gates. A pattern that is
not unique in its file mutates whichever occurrence comes first, which may be code the named gate
does not watch — so a survivor whose mutation is not anchored is re-read before it is believed. The
same lesson as §25a's "four instances in one campaign", reached from the opposite direction: there,
a mutation looked caught while proving less than claimed; here, one looked survived while proving
nothing at all.

The repaired campaign scores **32 caught, 0 survived, 0 skipped** on the closing head. M15 through
M32 were added later, for the seventeen defects adversarial review found on the PR itself (passive
expiry; a decision straddling two snapshots; the registry repin window; a guard this ledger had
wrongly written off as unreachable; a snapshot capture that left the derivation section; and a
capture that unlocks before it captures) — all real, and none reachable by the twelve cases the
specification enumerated.

**Round 11 found the same defect in three more walls, and the count is the finding.** Asked to take
an adversarial pass over the OTHER structural walls this PR relies on, it returned three P2s, each
reproduced by building the evading shape and watching the wall PASS: the activation-input wall
recorded only the KEYS in each literal, so `ToolCatalogUsable: true` satisfied it at both call sites
while discarding the probe's verdict; the server-usability wall required only some selector named
`Usable`, so `_ = srv.Usable()` satisfied it while rejecting nothing; and the promotion-ownership
scan matched only calls whose callee is a selector, so `promote := cat.Promote` followed by
`promote(key, fp)` was invisible. Fixes: the value must be the probe field of the same name; the call
must be on `srv`, negated, guarding a `return false` (plus the behavioural test above); the scan
walks selectors rather than call callees. M21/M22/M23 cover the three shapes.

**Round 12 found the same defect in the BEHAVIOURAL gates, which is the answer to whether the
pattern stopped at the AST walls: it did not.** Three more P2s, each reproduced: the pure-package
tests flip ONE fact off an all-true fixture, so an accessor reading
`f.ToolCatalogUsable || !f.LiveExecutorComposed` passes the whole package while reporting the tool
usable on any node where the executor is absent — i.e. the shipped one; the preflight fixture carried
no live approval on either side, so a wiring of `in.ToolCatalogUsable || len(in.ToolApprovals) > 0`
passed it while letting any real activation bypass catalog usability via the approval it already
carries; and the policy E2E paired `ActionQuarantine` with ONE reason, so a quarantine under any
other reason read as "ordinary evaluation was reached". Fixes: a DERIVED all-false gate reading its
expected reason set off `readinessChecks`; a valid live approval issued first and held constant, with
an anti-vacuity check that it reaches the inputs; and rejection of EVERY `ActionQuarantine` — which
still stops short of blocker #14, since ordinary evaluation reaching default-DENY satisfies it too.
M24/M25/M26 cover the three.

**One correction to that round, recorded because agreeing with a finding is not the same as
accepting its demonstration.** Codex proposed proving (3) by mapping the promoted tool to
`policy.DispReviewRequired`. That mutant does NOT reproduce: `engine.go`'s quarantine arm is
`DriftUnknownTool || DispQuarantined`, there is no review-required override, and a review-required
disposition falls through to ordinary matching — so it passes the FIXED gate too. The finding is
nonetheless right, and the engine's SECOND quarantine arm demonstrates it exactly:
`DriftPrivilegeExpansion` quarantines under `ReasonToolPrivilegeExpansion`, which the old assertion
accepted (`ok`) and the new one refuses (`Got action=QUARANTINE reason=MCP.TOOL.PRIVILEGE_EXPANSION`).

**Round 13 found the assumption UNDER the round-12 fix, which is the sharpest turn of the sweep.**
The all-false gate is sound only if every accessor is a plain positive field read; without that,
all-false is merely a THIRD vertex, and
`f.ToolCatalogUsable || (!f.LiveExecutorComposed && !f.UpstreamCallerPresent && f.PolicyHealthy)`
agrees at all-true, at every single-false and at all-false while suppressing the reason on a
partially composed node with healthy policy. 2^23 combinations is not enumerable and any hand-picked
subset is another proxy, so `TestReadinessChecks_EveryAccessorReadsOnlyItsOwnFact` asserts the
accessor SHAPE — a single `return f.<Field>` — making the property true BY CONSTRUCTION instead of
sampled. The same round closed the preflight fixture's remaining three axes (`ServerUsable`,
`FingerprintCurrent`, `Budget` were still zero-valued, so `in.ToolCatalogUsable || in.ServerUsable`
passed), with anti-vacuity checks that the other inputs really are valid. M27/M28.

**And the round's P3 is the one to keep.** The test comment written in the round-12 fix still
recorded `policy.DispReviewRequired` as a measured alternate quarantine — the very mutation that
round had just established does NOT reproduce. The ledger and the review thread were corrected and
the EXECUTABLE GATE was left carrying a false provenance claim, where the next maintainer would read
it. *A gate whose comment names a mutation that proves nothing has a false provenance claim: the
same defect as a gate asserting a proxy, one level up, in the documentation of the fix rather than
the fix.* Corrected in place, naming the reproducing case and why the proposed one does not.

**Round 14 found the THIRD level, and it is the one this sweep should be remembered for.** The
coherence gate infers BEHAVIOUR — the captures are inside the critical section — from SYNTAX — one
`deriveMu.Lock`, one deferred `Unlock`, one read of each source. That inference does not hold:
reconciling, reading BOTH snapshots UNLOCKED, and only then taking `deriveMu` with a deferred unlock
leaves every count unchanged (`ok, 0.104s`) while `Revoke` runs freely between the captures and the
lock — the round-8 fail-open reopened from the side M20 never looked at. The gate now compares
POSITIONS (the lock precedes both reads) and requires the capture to be STRAIGHT-LINE, since a read
placed after the lock inside a closure or goroutine satisfies source order while a structural gate
cannot prove when it runs. M29/M30, the second of which was found by asking the question of my own
fix rather than waiting to be told.

The same question was put to the OTHER structural gate and it survives with evidence:
`TestReadinessChecks_EveryAccessorReadsOnlyItsOwnFact` infers "reads only its own fact" from the body
shape, and the cheapest shape satisfying it while carrying a bug is a plain read of the WRONG field —
which the single-flip tests catch. The two gates are complementary, not redundant: flips pin
field-to-reason correspondence, the shape gate pins single-fact accessors.

**Round 15 found the FOURTH level — mutex aliasing — which is the exact assumption round 14's fix
rested on.** `mu := &c.deriveMu`, unlock through the alias before both captures, re-lock after: one
direct Lock, one deferred direct Unlock, zero bare direct unlocks, correct order, no closure
(`ok, 0.105s`), and `Revoke` interleaving with the captures as before. **Following aliases was the
offered remedy and is the wrong shape** — four rounds running, each escape has been a different
syntax (unlock moved, captures moved, closure, alias), and an alias-tracking gate merely names the
fifth. The mutex is now UNALIASABLE: mentioned exactly twice, in its two canonical statements, with
no Lock/Unlock permitted on anything else. There is no syntax for releasing a lock you may not name.

The FIFTH level was then found by asking the question of that fix rather than waiting: a HELPER
METHOD can unlock `deriveMu` in a body the gate never parses (`ok, 0.099s`). The capture is allowed
exactly one collaborator, `reconcileLocked`, so every lock operation is visible in the function the
gate reads. M31/M32.

**THE GENERAL LESSON OF THE LAST FOUR ROUNDS, which is the durable one:** a structural gate can only
assert what the syntax it reads makes visible. Widening the gate until it can follow wherever the
code went is an arms race it loses every round. **SHRINK WHAT THE FUNCTION IS PERMITTED TO DO until
the invariant is readable from it** — that is what "unaliasable, straight-line, one collaborator"
buys, and why it is total where "track aliases" would have been the next enumeration.

**Thirteen instances across seven rounds, one defect.** The AST walls pinned a key name, a call count, a
callee's syntax and a method name; the behavioural gates pinned a fixture that could only vary one
way, an input the fixture never supplied, and one reason standing in for an action. A wall that pins something CORRELATED with the
invariant — a key name, a call count, a callee's syntax, a method name — rather than the invariant.
Every one passed its own tests and would have shipped. The question that finds them is not *"does
this fail against the defect I just fixed"* but ***"what is the cheapest shape that satisfies these
assertions and still has the bug"*** — and it should be asked of a wall when it is written, not
three rounds later.

**M20's own verification reproduced the mis-anchoring trap, one run after it was written down.** The
three shapes the hardened gate claims to catch were each built and run; the middle one — dropping
the derivation lock entirely — PASSED. That was not a gate gap: `reconcile()` carries the identical
three lines (`Lock` / `defer Unlock` / `reconcileLocked()`), so a first-occurrence replace landed
there instead of on the function under test. Re-anchored to `reconcileAndSnapshot`'s body, it fails
with `takes deriveMu 0 time(s), want exactly 1`. A mutation that does not describe its target proves
nothing, whether the harness reports it as a skip or a human writes it by hand.

**That score was recorded here once before it had been measured, and it was wrong.** After M16 was
added, this row was written as 16/16 by extrapolation — every prior run had been clean and the new
gate had been verified by hand — and the first actual run returned **15 caught, 0 survived, 1
SKIPPED**. M09 had stopped matching: the round-2 fix replaced the `loadTarget` ownership lookup with
a direct registry-snapshot read, so the mutation no longer described the code it targeted, and the
tenant-ownership check had no working proof at that head. It was re-anchored (and written to COMPILE
— the naive deletion leaves two variables unused, which under the campaign's header rule proves
nothing) and re-run to the score above.

Two things are worth keeping from that. **A campaign score is a measurement, not a property of the
suite**: it must be re-run after any change to the code OR the campaign, because the thing that
silently breaks is the mutation's grip on its target, not the gate. And **the failure mode is a SKIP,
not a survivor** — a skipped mutation is scored as "nothing to see" by a reader skimming for
survivors, so `skipped: 0` is as load-bearing as `survived: 0`, which is why the harness exits
non-zero on either.

**It happened a third time, and taught the rest of the rule.** The round-6 repin fix added two
further uses of `srv`, which stopped M16's mutation from COMPILING — reported as `NOT PROVEN`, a
third silent outcome alongside `SKIPPED`, and the one that can also ABORT the run before later
mutations execute: that run never reached M17 and printed no summary at all. It was missed for a
worse reason than the miss itself — the invocation piped the script through `| tail -8`, and a
pipeline's exit status is the LAST command's, so `tail`'s `0` was read as the campaign's. M16 is
re-anchored to express its defect directly (a per-iteration `reg.Current()` IS the second read) and
written to compile, which needed the M08 repair a second time. So: **three times on this PR a code
change silently moved a mutation's target** — M08's unused-variable trap, M09 after the
single-snapshot fix, M16 after the repin fix — and **a campaign result is never read through a pipe
that discards its exit status.**

**A fourth way, and the one that imitates the third.** Two later runs died — one mid-M12, leaving its
mutation UNREVERTED in the working tree (a live `ApproveLive`-promotes defect, caught by `git status`
rather than by the harness), and one reporting `NOT PROVEN` at M15. The second looked exactly like the
M16 class and invited the same repair; it was neither. Both were `no space left on device`: the Go
build cache had reached 21 GB against 124 MB free, so the linker could not map its output and a
perfectly good mutation "did not compile". So: **when a campaign aborts without a summary, or reports
NOT PROVEN with a linker or mapping error, check the disk before touching a mutation** — and after any
abort, `git status` first, because a dead harness does not revert.

**And the round-7 lesson, which is the same shape as round 2's and points the opposite way.**
Reasoning sequentially about state that is PUBLISHED CONCURRENTLY is unsound in BOTH directions: it
deleted a guard as vacuous that was not, and then declared `srv.Usable()` unreachable when it is the
last line of defence for the reconcile/registry-read window. *"I measured it"* was true both times and
still produced a false claim, because a measurement over one interleaving says nothing about the
others.

**A wall can pin a SPELLING instead of an invariant, and only a mutation found it.** Re-anchoring
M16 after the round-8 fix produced a form that reads the inventory through a variable named `rg`
rather than `reg` — and the snapshot wall, which counted `Current()` calls keyed on the RECEIVER'S
IDENTIFIER, scored ZERO violations against a mutation that reintroduces exactly the defect it exists
to reject. It now counts every `Current()` inside the resolver regardless of receiver name, and any
`sharedInventory()` call. The weaker wall passed its own tests and would have shipped; what exposed
it was being forced to re-express a mutation whose target had moved.

**Sweep the whole campaign after a code change, not one run at a time.** Two consecutive runs each
burned a full campaign to surface a single SKIP (M11, then M15). Checking every mutation's pattern
against the current source at once found both remaining drifts plus one false positive in a few
seconds. The running tally of targets silently moved is M08, M09, M16, M11, M15 and M16 again —
**five of six moved by this PR's own fixes**, which is why the rule is to re-run everything after any
change to the code OR the campaign.

**Deliberately NOT closed here, and the boundary is exact.** The policy E2E above stops at "ordinary
policy evaluation became reachable". Whether the exact request then resolves to an ALLOW-class
decision with satisfiable obligations was **blocker 14**, which remained OPEN at the time of this
section and has **since been closed in §25c**. Reaching evaluation is a precondition for it, not a
substitute: `TestCatalogUsable_PolicyQuarantineOverrideClearsAfterGovernedPromotion` asserts only
that the catalog-quarantine hard override stops pre-empting evaluation, never that a rule allows —
that second question is answered by `canary.ReasonExactPolicyNotExecutable`, a separate row.

**Two things this closure deliberately did not do.** It did not introduce a third promotion
authority — §3's instruction was to reuse the governed `shadow_evaluation` lifecycle if it could
safely serve this role, and re-derivation showed it already does: it is exact-fingerprint CAS-guarded
against a rug-pull, it demotes on revocation, and its reconcile re-derives from the durable store, so
the only thing missing was that the activation gate never asked. And it did not persist usability
into the activation's immutable reviewed snapshot: a revoked or expired promotion must be able to
make the next FULL ACTIVATION PREFLIGHT refuse, which a frozen copy could not express. (NOT
"un-ready" on the node surface — `EvaluateNode` excludes every activation row; see §25d.)

**A removal that was WRONG, and the correction.** The first shape of the resolver cross-checked the
catalog record's digest and format against `loadTarget`'s re-read. That check was deleted mid-PR on
the reasoning that *"both sides come from the same catalog, so no test could ever distinguish the
check from its absence"* — a guard whose only future is silent rot.

**The reasoning was wrong, and adversarial review caught it** (Codex P2, round 2). Same catalog,
DIFFERENT READS: `loadTarget` re-reads `cat.Current()` AND `reg.Current()`, so under a concurrent
re-ingest the two sides genuinely differ. The deleted cross-check was the snapshot-consistency
guard, and removing it opened a fail-open — an old `Usable` F1 record satisfying eligibility and the
F1-pinned digest while ownership came from the newer snapshot, so the resolver answered "usable" for
a target the current catalog had already re-quarantined at F2. The comment sitting above the loop at
the time asserted the very single-snapshot invariant the code broke.

The repair does not restore the cross-check. A cross-check between two reads can only DETECT an
inconsistency that one read cannot produce, so the SECOND READ is gone instead: the registry
snapshot taken alongside the catalog snapshot answers ownership directly, and
`TestCatalogUsable_ResolverReadsEachSnapshotExactlyOnce` pins that the function reads each source
once and never calls `loadTarget`.

The transferable lesson is the one the first reasoning missed: **"one snapshot" is a statement about
one READ, not one source.** Two reads of the same authority are two snapshots, and a guard that
looks redundant because both sides "come from the same place" may be the only thing making that true.
Before deleting a check as vacuous, establish that no test could distinguish it *because the states
cannot differ* — not merely because you could not think of a test.

The format binding is genuinely not a second check, and that part stands: `Sum` folds
`FormatVersion` in before any other segment, so the digest comparison is format-bound by
construction, pinned by `TestCatalogUsable_FingerprintFormatIsFoldedIntoTheBoundDigest`.

---

## §25c Blocker 14 closure (the exact First-Canary policy permit)

This section records ONE status change: **blocker 14 is CLOSED**. Nothing else in the ledger moves.
Blocker 8 remains OPEN (narrowed), **blocker 9 remained OPEN at the time of this section** (see the
overlap note below; it was closed later on its own evidence in §25d), the
baseline is still fifteen, and the §26 verdict is unchanged — `BLOCKED — NO SAFE FIRST CANARY
TARGET`.

**The defect.** The readiness table's only policy row was `PolicyHealthy`, which is
`mcpPolicy.composed()` — a snapshot EXISTS. Nothing asked what the exact request RESOLVES to. A
node could hold an exact one-of-everything scope, a reviewed read-first target, a four-eyes live
approval, a `catalog.Usable` tool (blocker 13) and a valid budget, report `Ready:true`, and then
have every request answered by default deny because no enabled rule matched the tuple at all.
Blocker 13 stopped the request dying at the catalog hard override; it said nothing about whether an
operator rule then ALLOWs it.

**The closure bar.** The machine must refuse to report an activation ready unless the exact
First-Canary request, evaluated by the REAL shared policy engine against the CURRENT snapshot,
resolves to a decision that can actually execute — and that verdict must be a statement about the
EXPERIMENT, not about one imagined request.

### What was re-derived rather than inherited from prose

Two things current `main` does that the earlier review text would have gotten wrong, and both
changed the design:

- **`ActionMonitor` maps to `rollout.ActionKindAllow` and DOES resolve to `EffectExecute`**
  (`internal/mcp/execution/mapping.go`), despite `action.go` documenting MONITOR as "non-blocking
  policy intent; still no upstream execution in PR-6". A first experiment must not rest on a
  documented/behavioural divergence.
- **`resolveDisposition` passes `obligationsSatisfied = true` unconditionally**
  (`internal/mcp/execution/executor.go`), so `resolve.go`'s `!ObligationsSatisfied` branch is dead
  from the production call site. `ALLOW_ONCE`/`ALLOW_FOR_SESSION` reach `EffectExecute` and are
  gated only afterwards by a RUNTIME-ONLY allowance store; `ALLOW_WITH_REDACTION` reaches
  `EffectExecute` and is then unconditionally blocked (`ReasonRedactionFailed`).

Neither is preflightable. That is why the permit demands exactly `policy.ActionAllow` and
deliberately NOT `Action.IsAllowClass()` — the single most plausible wrong turn, and campaign
mutation M04.

### What closes it

| Clause | Evidence |
|---|---|
| A machine-visible activation fact | `canary.Facts.ExactPolicyPermit` / `canary.ReasonExactPolicyNotExecutable`, a `factActivation` row; the activation set is now **nine** facts |
| `PolicyHealthy` stays separate | The two rows fail for opposite reasons: a healthy snapshot in which no rule matches satisfies the first and fails this one. Campaign M01 rebuilds the substitution |
| The REAL shared engine decides | `mcpruntime.EvaluateExactPermitTuple` builds the engine with the same `newPolicyEngine` and `Limits` the live pipeline uses. No second evaluator, no hand-written rule matching — walled by `TestPermitWall_ResolverUsesTheSharedEvaluator` |
| The tuple is the one the runtime would build | `GatewayServerRef` / `GatewayToolRef` are now SHARED by `attachGatewayRefs` and `ExactPermitTuple`, so the server and tool halves are identical by construction |
| One classification authority | `classifyReadFirstToolCall` became a free function both callers route through, so "exactly one site writes `Operation.Class`" stays literally true (`TestReadFirstWall_OperationClassHasExactlyOneClassificationSite` caught the first attempt to add a second) |
| The positive verdict is explicit | `HardOverride == false` AND `MatchedRule != ""` AND `Action == policy.ActionAllow`. Campaign M02–M09 |
| Obligations are satisfiable, not merely well-formed | A CLOSED allow-list: only `Logging` and `Observation` may ride the permit. `RateLimitProfile`, `Destination` and `TicketRequired` are refused because they have **no runtime consumer at all** — "satisfied" would mean "not enforced". `TestPermit_EveryObligationFieldIsClassified` derives the field list by reflection, so a new obligation fails the build until someone decides |
| One coherent capture | The resolver reads the authoritative inventory exactly once, through the same reconciled seam blocker 13 uses; `TestPermitWall_ResolverTakesOneCoherentCapture` |
| The policy decides which rule wins | No rule id appears in product logic; `TestPermitWall_NoHardCodedRuleIdentity` |
| Not persisted into the reviewed snapshot | The permit is LIVE governance state, re-observed at every evaluation — the same decision blocker 13 made for catalog usability, for the same reason. `TestPermitWall_FactIsNotPersistedIntoTheReviewedSnapshot` |

### The part that makes it a proof rather than a sample

A preflight has no request, so the tuple must CHOOSE values for the fields a real request would
carry. A verdict computed over those choices is evidence about one imagined request and nothing
else — unless the verdict does not depend on them.

So the permit additionally requires the verdict to be INVARIANT over every field the activation
does not bind (`canary.PermitBoundFields`). The engine's own `ExplainTrace` makes this decidable:
it names the decisive condition of every rule it rejected, so the permit requires

- the WINNER to read only bound fields (`Snapshot.Rule(id).ConditionFields()`), and
- every rule rejected before it to have been rejected ON a bound field (the engine reports the
  FIRST failing condition, so naming a bound field means a bound field decided it), and
- the trace not to be truncated — a truncated trace is silent about the rules it dropped, so "no
  entry says otherwise" stops being evidence.

Given all three, the same rule wins with the same action for every request the scope admits.

**The check ORDER is load-bearing, and it was found by running the engine rather than by reading
it.** `permitVerdictInvariant` covers only the RULE LOOP. The hard-override band runs first and is
not a rule; almost all of its inputs are bound, but `subjectOverride` denies a WRITE-or-higher
operation whose principal assurance is unknown (MCP-ID-005), and `principal.assurance` is
request-variable. Requiring the class to be read-first BEFORE the hard-override test makes that
branch unreachable — and with it unreachable, every remaining hard override is decided by bound
fields alone. `TestPermitE2E_WriteClassIsNotAPermit` fails against the other order, and campaign
mutation M20 restores it.

### Two holes the campaign found, not the review

Recorded because both survived a run and neither was visible to any behavioural gate:

- **M27** — the resolver could take two inventory captures instead of one. Every behavioural gate
  passes against a two-read resolver on a quiescent fixture, because nothing changes between the
  reads. The invariant needed a structural gate, and counting is the assertion: a second call to
  the SAME seam is two reads just as surely as a call to a different one, which no allow/deny list
  can express.
- **M15** — `operation.operand` could be replaced with a literal and nothing noticed, because no
  fixture rule read that field. The lesson generalises past the one field: `PermitBoundFields()` is
  the set the invariance proof rests on, so that guarantee is worth nothing unless every one of
  them actually CARRIES the exact target's value.
  `TestPermitE2E_EveryBoundFieldCarriesTheExactTarget` now drives the real engine once per bound
  field, with a completeness declaration so a new bound field cannot arrive unproven.

### The blocker-9 OVERLAP — reported, NOT acted on

Blocker 9's recorded closure criterion is *"verifying a no-`CredentialProfile` matched rule OR
implementing a working credential provider/path"*. This PR's fact **does** machine-check the first
disjunct: the permit refuses any matched rule carrying a `CredentialProfile`, at activation time,
re-evaluated on every read, which is strictly stronger than the runbook verification the criterion
describes.

**How strong the overlap actually is, stated plainly rather than minimised.** Because the permit
additionally requires INVARIANCE, the credential-free finding is not merely a statement about one
constructed tuple: a rule that reads any request-variable field yields `PermitVerdictNotInvariant`
instead of a permit, so a certified permit means the SAME rule wins — carrying no
`CredentialProfile` — for every request the exact scope admits. On a literal reading of blocker 9's
first disjunct, that is the verification it asks for, done by machine and re-evaluated on every
read.

**Blocker 9 is nevertheless left OPEN, and its ledger status is unchanged.** Three reasons, the
first two substantive and the third procedural:

1. **The permit is an ACTIVATION-time fact; blocker 9 is about the EXECUTION path.** The permit is
   not consulted per request. If policy is edited mid-window to a credential-bearing rule, the
   request fails closed at `executePreconditionFailure` (`ReasonCredentialProfileMissing`, because
   the production broker composes ZERO providers) — safe, but it means the Canary silently stops
   executing rather than the credential path having been resolved.
2. **Blocker 9 also names the broker/provider path itself**, which nothing in this PR exercises:
   `mcp_live_production_deps.go` still constructs the broker with no provider registered, which is
   the truthful pre-Canary posture and the second half of what blocker 9 describes. The node-level
   `CredentialPathReady` row remains tied to live-tier composition, not to "no credential needed".
3. **A blocker closed as a side effect of another PR inherits that PR's evidence instead of being
   held to its own.** Whether (1) and (2) are acceptable for the first experiment is an owner
   decision about the credential path, not a consequence of this one.

`TestPermitE2E_CredentialFreeRuleIsRequired` records the overlap executably, with its positive
control. **If the owner judges the first disjunct satisfied, closing blocker 9 is a one-line ledger
change with this section as its evidence — but it is deliberately not taken here.**

> **SUPERSEDED BY §25d.** Blocker 9 was subsequently closed on its own evidence, and NOT by adopting
> this overlap. Re-deriving the credential path found that the reading above was too generous: the
> policy obligation is one of THREE authoritative credential statements and the only one any
> enforcement path reads, so the permit can be satisfied while the authoritative server record
> requires a credential. §25d records what that actually took — a separate activation row over all
> three layers, plus an execution-side proof — and keeps the closure scoped to *the First Canary
> requires no production credential*. This section is left as written because the reasoning it
> records, including the part that turned out to be incomplete, is the reason the follow-up looked
> at the code instead of adopting it.

### What this does NOT close

- **Blocker 9 stays OPEN** (above).
- The end-to-end proof stops at *"policy ALLOW ⇒ rollout `EffectExecute`"* under controlled test
  composition (`TestPermitE2E_AllowResolvesToEffectExecute`). **No upstream is contacted, no
  executor is composed, no Canary is activated.** Blockers 1, 2, 3, 8, 10, 11, 12 and 15 are
  untouched.
- Enforcement did not move. The policy engine still decides every real request; this row only stops
  the next FULL ACTIVATION PREFLIGHT admitting an experiment whose every call would be refused — not
  the node readiness surface, which skips it (`factActivation`).

**Campaign:** `scripts/mcp-first-canary-policy-permit-mutations.sh` — **30 mutations, 30 caught,
0 survived, 0 skipped**, measured on the closing head.

## §25d Blocker 9 closure (the credential-free First-Canary path)

This section records ONE status change: **blocker 9 is CLOSED**. Nothing else in the ledger moves.
Blocker 8 remains OPEN (narrowed), blockers 1, 2, 3, 10, 11, 12 and 15 are untouched, the baseline
is still fifteen, and the §26 verdict is unchanged — `BLOCKED — NO SAFE FIRST CANARY TARGET`.

**The closure is narrow and its wording matters: *the First Canary requires no production
credential*.** This does NOT claim a production credential provider exists, that the broker path is
production-ready, or that Culvert cannot support authenticated MCP servers. It closes blocker 9's
FIRST disjunct — "the exact executable policy path requires no credential" — and leaves the second
("a real production credential provider/materialization path exists and is safe") unimplemented and
unclaimed. `mcp_live_production_deps.go` still composes the broker with ZERO providers, which
remains the truthful pre-Canary posture.

### Why §25c's overlap note was not sufficient, and what changed

§25c recorded that blocker 14's `ExactPolicyPermit` already refuses a matched rule carrying a
`CredentialProfile` obligation, and — because of the permit's invariance requirement — that the
refusal holds for every request the exact scope admits. It then left blocker 9 OPEN for three
stated reasons. All three are now answered, and the FIRST of them turned out to be understated.

**Re-deriving the credential path from the code found the real gap: the policy obligation is one of
THREE authoritative credential statements, and it is the only one any enforcement path reads.**

| layer | source | read by enforcement? |
|---|---|---|
| policy | `Decision.Obligations.CredentialProfile` | YES — `run.go` `profileRef`, `executePreconditionFailure`, the shadow evaluator |
| registry | `registry.ServerRecord.CredentialProfile` | **NO. Zero enforcement readers.** |
| catalog | `catalog.Fingerprint.CredentialProfile` | only through fingerprint equality/drift; it is a COPY of the registry value taken at ingest |

So a snapshot in which policy says "no credential" while the authoritative server record says one
is required is not a contradiction the engine can see. Execution reads the obligation, finds it
empty, takes the no-broker branch (`useBroker := Broker != nil && profileRef != ""`) and reaches a
credential-REQUIRED upstream with NO Authorization header — which either fails (an activation that
cannot execute) or, the case that matters, succeeds against an upstream that accepts ambient
access, performing a credential-required operation with no planning, no broker gate and no
`CREDENTIAL_SELECT` event.

`TestCredFreeE2E_ServerCredentialProfileIsRefused` asserts exactly this as its PREMISE: in that
state the policy permit is still **satisfied**. That assertion is what makes this a separate
readiness row rather than a duplicate of blocker 14's, and it is why §25c's "proven by the permit"
reading would have been too generous.

### The closure bar

An ACTIVATION PREFLIGHT must not return Ready unless the exact First-Canary request is provably
credential-free at EVERY authoritative layer — and the runtime must be unable to acquire or send a
credential for it.

### What was built

- **`canary.EvaluateCredentialFree`** — the pure verdict over the three layers, with a bounded
  reason naming which one objected (`policy_requires_credential` / `server_requires_credential` /
  `reviewed_target_requires_credential`). No profile reference, tenant or host ever appears; an
  opaque profile id is still a name an operator chose.
- **`canary.ReasonCredentialPathRequired` / `Facts.FirstCanaryCredentialFree`** — a `factActivation`
  row. The activation set is now **ten**. It is deliberately distinct from the node-level
  `ReasonCredentialPathNotReady`, which asks whether this node COULD do credentials at all; this row
  asks whether this EXPERIMENT needs one, which the First Canary forbids outright.
- **`canaryExactRequestFacts`** — resolves the permit and the credential fact from ONE coherent
  capture. Two captures would let each verdict be individually true about a DIFFERENT inventory,
  since the registry and catalog publish independently; their conjunction would then describe no
  state that ever existed. Pinned structurally by
  `TestCredFreeWall_BothFactsComeFromOneCapture`.

An engine error is reported as NOT ESTABLISHED (`credential_facts_unavailable`), never as
credential-free, and that is self-contained rather than resting on the permit row also refusing.

**The reviewed layer is structural, not a fourth field.** `CredentialProfile` is a hashed
`catalog.Fingerprint` field, so "the reviewed target needs no credential" IS the catalog statement,
given the digest match the reviewed-target binding already enforces. There is deliberately no
separate reviewed-credential authority that could drift against the fingerprint.

### §10 — the credential profile IS fingerprint-relevant, and that is the whole runtime guarantee

`Fingerprint.CredentialProfile` is declared, hashed into `Sum()` and compared in `Equal()`, and
`catalog/drift.go` classifies a change as `expansion` ("unprovable as narrowing"). So
`none -> profile-X` produces a DIFFERENT tool identity: the scope pin, the governed promotion and
the four-eyes live approval all stop matching, and the existing reviewed-target drift machinery
refuses the stale activation. **No separate credential-drift authority was invented and no
request-local check was added.** Campaign mutation M09 removes the field from the hash and is
caught, so the dependency is executable rather than asserted.

`TestCredFreeWall_CatalogCredentialDerivesFromTheRegistryRecord` records the other half: the
fingerprint's credential profile is DERIVED from the registry record (never from the upstream's
own `tools/list` response, which is attacker-influenced data), and the registry exposes no mutator
for it. That is why the registry and catalog cannot disagree today — and the wall fails if a
credential-profile mutator is ever added, forcing the divergence question to be answered again
instead of silently opening a window.

### The execution-side proof (§6/§7/§8)

Everything runs through the REAL composed live executor, the REAL side-effect gate, and a REAL
broker — **never a nil broker**, because production composes a real one and a proof against a
composition production does not use would be vacuous. The broker's profile store is EMPTY, so ANY
consultation of the credential path fails and blocks the request; the canonical request still
reaching the upstream IS the zero-use proof, with the upstream call count as the positive control
that the request got to the boundary at all.

- `TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery` — upstream reached exactly once,
  no Authorization header, provider calls 0.
- `TestCredZeroUse_CredentialRequiredFailsClosedWithUpstreamZero` — the control that this
  composition CAN block, which is what makes the gate above a signal rather than a tautology.
- `TestCredZeroUse_CredentialRequiredWithNoBrokerFailsClosed` — the pre-existing
  `ReasonCredentialProfileMissing` guard is intact for the other composition shape.
- `TestCredZeroUse_AuxiliaryTrafficCarriesNoAuthorization` — lifecycle methods are kernel-terminal
  (asserted through the production `protocol.Admit`, so they never reach `upstreamclient` at all),
  and `tools/list` discovery sends no `AuthHeader`. Discovery runs OUTSIDE the policy decision, so
  a credential there would ride no decision and be covered by no obligation.

### §25c's three reasons, answered

1. **"Activation-time fact vs execution path."** Answered by §6/§7/§8 above: the execution path is
   now proven to send no credential on the canonical path and to fail closed on a credential-
   required one, under both composition shapes.
2. **"Blocker 9 also names the broker/provider path."** NOT implemented, and deliberately not
   claimed. The closure statement is scoped to *the First Canary requires no production
   credential*; a provider remains future work and is not a First-Canary prerequisite precisely
   because the experiment needs none.
3. **"A blocker closed as a side effect inherits another PR's evidence."** Answered procedurally:
   this is blocker 9's own change, with its own matrix, walls and campaign.

### The §14 answers, including the one residual

**"Can any request eligible under the exact First-Canary activation cause credential planning,
materialization, provider access, or an Authorization header?"** — Materialization, provider access
and an Authorization header: **no**, on any path, proven by
`TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery` and its credential-required
control. Credential PLANNING: **not for any request the certified policy admits** — the permit's
invariance requirement means the same no-`CredentialProfile` rule wins for every such request — but
there is ONE way to enter it, recorded rather than hidden.

**THE RESIDUAL — a mid-window policy edit.** The permit is an ACTIVATION-time fact over the policy
as it stood. The runtime re-evaluates per request against whatever snapshot is then current, and
nothing revalidates "the policy is still the one the permit certified" at the side-effect boundary
(`SnapshotHash` is carried into evidence, never compared). So an operator editing policy mid-window
to a credential-bearing rule produces a decision the permit never certified. What that can cause is
bounded and asserted: `Broker.Plan` — metadata only, against a profile store with nothing in it —
fails, and the request is blocked with the upstream never reached, no provider touched and no
Authorization constructed, and the block is METERED with its reason (`Metrics.ObserveBlock`,
`executor.go`), so the execution plane does carry the evidence.

**WHAT IS NOT OBSERVABLE, corrected (Codex P2, round 2).** This paragraph previously said "the
readiness row then reports the node un-ready on the next read". **That was FALSE**, and the way it
was reached is the finding worth keeping. The evidence behind it,
`TestCredDrift_ReadinessIsReEvaluatedNotFrozen`, proves something NARROWER: the credential FACT is
re-observed from authoritative state rather than frozen into the reviewed snapshot. It says nothing
about WHICH READ SURFACE exposes it — and the operator-facing one does not. `mcpCanaryStatus`
(`GET /api/mcp/rollout`, the "canary" sub-view) reports `evaluateCanaryNodeReadiness` →
`canary.EvaluateNode` → `evaluate(f, nodeOnly=true)`, whose loop SKIPS every `factActivation` row;
`FirstCanaryCredentialFree` is one, so `credential_path_required` can never appear in that surface's
`unmet`. It appears only in the static `all_prerequisites` vocabulary — which is precisely why the
distinction misleads: an operator sees the prerequisite advertised and may infer the surface would
report it unmet. The only non-test caller of the full `canary.Evaluate` is the activation preflight,
reached from the rollout commit gate and the startup restore reconcile. So the drift is observable
at the NEXT TRANSITION or restart, and as a metered block on the execution plane — **not on a status
read**.

This is the same defect shape as campaign M17: a gate proves one proposition and the prose claims a
stronger one built on it. The rule to carry forward is that **an observability claim names the
SURFACE, and the surface is checked** — so the boundary is now asserted rather than described, by
`TestCredWall_NodeStatusSurfaceCannotReportActivationReasons` (campaign M19), which derives the
activation set from exported evaluator behaviour and fails in BOTH directions: if `EvaluateNode`
stops excluding activation rows, and if the status surface starts reporting them.

`EvaluateNode`'s exclusion is deliberate and is NOT changed here: it exists because activation facts
default false, so a node-level surface that included them would report every node permanently
not-ready (Codex P2, PR #1249). Making this drift visible on a read therefore needs a separate
activation-scoped status field, which is new surface for a build where no Canary is ever armed —
out of scope for blocker 9 and recorded rather than done.

This is the same activation-time-vs-execution-path seam §25c named for blocker 14; it is narrowed
here to "planning can be entered, nothing else can" and is NOT claimed closed.

**"Can policy say no credential while authoritative server/tool state says one is required and
still reach `Ready:true`?"** — No. `TestCredFreeE2E_PolicyNoneServerRequiresIsNotReady` drives the
production probe into exactly that state and asserts the readiness verdict is unmet for exactly
`credential_path_required`.

**"Can a credential requirement appear after activation without being caught by the existing
immutable reviewed-target / fingerprint drift path?"** — No, for a structural reason:
`registry.ServerRecord.CredentialProfile` has no mutator, so it can only change by republishing the
whole inventory, which replaces the catalog in the same publication and therefore changes the
fingerprint. The reviewed binding then stops matching. A POLICY-side credential appearing after
activation is the residual above, not a drift-path gap.

### What this does NOT close

- **No production credential provider exists.** Any FUTURE experiment that needs a credential is
  blocked on work this PR does not do.
- **The mid-window policy-edit residual above.** Bounded to credential planning, fail-closed, and
  not claimed closed.
- Blocker 8 stays OPEN (narrowed); blockers 1, 2, 3, 10, 11, 12, 15 are untouched.
- No upstream is contacted outside the controlled test composition, no Canary is activated, and
  enforcement did not move.

**Matrix:** the §11 twelve-case matrix is indexed and machine-checked by
`TestCredMatrix_EveryRequiredCaseHasALivingGate`, which requires each case's gate — and each
negative's positive control — to exist.

**Campaign:** `scripts/mcp-first-canary-no-credential-mutations.sh` — 39 mutations,
**39 caught, 0 survived, 0 skipped, measured on `6392283c`**. A run that reaches its summary has
necessarily passed `selfcheck_site_counter`, which refuses before anything else prints.

It took FOUR runs on this round's code to get there, and the three discarded runs are the argument
for re-measuring rather than asserting: M23 came back NOT PROVEN (the payload did not compile),
then SURVIVED (its control had been silently disarmed), then M24 came back SKIPPED (its payload
named a symbol this round deleted). Review found none of the three.

The fourth is the one worth recording, because the defect was in the INSTRUMENT. **M30 came back
SURVIVED, and there was no hole.** The payloads are applied with perl in slurp mode, so an `s///`
without `/g` replaces the first match IN THE WHOLE FILE. M30's pattern matched four lines of this
document and the first is blocker 4's campaign row, roughly 1500 lines outside §25d. The mutation
applied, edited an unrelated section, and the correctly-scoped gate saw nothing — so it reported a
hole in a suite that did not have one. That is the same defect as missing a hole that does exist:
the score had stopped describing the suite. In both directions the failure is the section's one
recurring shape, now at the level of the measuring instrument for the second time — **a gap between
what the apparatus proves and what its number claims.**

Anchoring M30 fixed the instance. The runner now proves the property for all thirty: `apply_payload`
counts how many SITES a payload matches and the runner requires exactly one; a miss (0) and an
overreach (>1) are both NOT PROVEN. The count is taken from a `/g` run against an untouched copy,
and that detail is load-bearing — counting SUBSTITUTIONS would not work, because a plain `s///`
returns 1 whether the pattern matched one site or forty, and the first version of this guard duly
reported the ambiguous M30 payload as a clean single hit.

**And then the guard had the same defect the guard was for**, which Codex round 10 found. Every one
of the thirty payloads matches exactly one site, so nothing in the campaign ever asked the counter
to report anything else: drop the `/g`, or replace the count with a constant `1`, and all thirty
still pass while the guard is silently disabled and the M30 ambiguity is free to recur (measured —
with the `/g` the ambiguous payload reports 4 sites, without it 1). The counter had been verified by
hand and the verification written down **here**, in prose, which protects no later run. That is this
section's one recurring shape reaching the third level: the apparatus that measures the suite had
itself become a record that claimed more than it proved.

So the verification is now part of every run. `selfcheck_site_counter` builds a fixture and requires
the counter to report **4** for an ambiguous payload, **1** for an anchored one that actually
applies, and **0** for one that matches nothing and leaves the file alone; a disagreement makes the
campaign **refuse to start**, for the same reason a dirty tree and a red baseline do — a broken
counter makes every score after it unverified. It was checked against three injected defects (the
dropped `/g`, a constant `1`, and a counter that counts correctly but stops applying), each
rejected, with a healthy counter accepted as the control. All thirty payloads were also
differentialled against the previous apply for byte-identical output.

There is deliberately **no opt-out** for a payload that wants several sites. `run_mutation` already
takes multiple payloads, so a mutation needing several edits spells out each one — and the earlier
`--multi <n>` escape hatch was removed rather than kept, because nothing used it, nothing tested it,
and an untested branch that loosens a guard is the next round's finding.

> **The previously recorded score here — "21 caught, 0 survived, 0 skipped, measured on
> `5d0e8055`" — was VOID, and the way it was void is the most important thing in this section.**
>
> Codex round 5 found `TestCredWall_EveryClaimedSurfaceIsScanned` RED on the unmodified head:
> the round-4 fix widened `nodeReadyPromise`, and §25d itself quotes the very phrase the widened
> matcher had just learned to recognise. The campaign was then run against that tree and every
> mutation pointed at that gate scored CAUGHT — **because the gate was already failing**, not
> because the mutation was detected. A campaign scores a mutation CAUGHT when the named gate fails;
> that inference is worthless unless the gate PASSES unmutated, and nothing checked.
>
> The campaign now checks. `baseline_ok` runs each named gate on the clean tree before mutating and
> scores a red or empty baseline as **NOT PROVEN** — the same verdict a non-compiling mutation gets,
> for the same reason: no gate ran that could tell the mutated tree from the clean one. Cached per
> (gate, package) so it does not double the run.
>
> The lesson is the one this section keeps re-learning, now at the level of the measuring
> instrument rather than the thing measured: **a campaign score is a measurement, and a measurement
> with an unverified baseline is not a weak result — it is not a result.** M14 is the anti-vacuity mutation: a
constant-false resolver passes every negative gate while making the First Canary permanently
impossible, and is rejected by a POSITIVE control rather than by a negative. M15/M16 target the two `CanaryActivationInput` call sites in
`mcp_rollout.go`, which every behavioural gate is blind to because they call the resolver directly;
they are caught by the PRE-EXISTING
`TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall`, whose field list is derived
from the struct — so the new row was covered at both sites the moment it was declared. M17 covers a
defect SELF-REVIEW found rather than a test: an engine error left the credential input marked
resolved with an empty POLICY statement, so a tuple whose policy verdict could not be computed
reported as credential-free. It was defended by "the permit row refuses that tuple anyway", which is
true today and is exactly the wrong shape of argument — it makes this row's soundness depend on
another row staying required. `Resolved` is now `err == nil`.

M18 covers a defect a REVIEW found rather than a test, and the fix it named was too small. Codex
flagged ONE stale cross-reference to the renumbered activation rows in
`docs/design/mcp/CANARY-READINESS-MATRIX.md`. Checking the whole document found EIGHT: the table had
been renumbered without the prose that points into it. Fixing only the reported line would have left
seven live wrong pointers beside it, so the class is closed by machine —
`TestCredWall_MatrixDocActivationRowsMatchTheTable` parses the table and requires every activation
row's number AND reason to match what the engine's own `Evaluate`/`EvaluateNode` behaviour reports,
so a future renumbering that touches the table without the prose fails the build. It was verified
failing against the exact pre-fix prose, naming both halves.

M19 covers the SECOND review-found defect, recorded in the residual paragraph above: an
observability claim that named no surface. It guards the boundary that paragraph now depends on —
`mcpCanaryStatus` reports `EvaluateNode`, which skips every `factActivation` row, so the status read
can never carry `credential_path_required`. The mutation makes `EvaluateNode` stop excluding those
rows; the gate fails in BOTH directions (the derived activation set going empty, and the surface
reporting an activation reason), because checking only "no activation reason appears" would pass
VACUOUSLY under exactly that mutation — the derived set would be empty and the check would inspect
nothing.

M20 covers the THIRD review-found defect, and it is the same lesson one level up. M19 stops the
status surface from REPORTING an activation reason; it does not stop the code from CLAIMING
otherwise — and round 3 found the claim in EIGHT places: three `canary.Facts` field comments
(`ToolCatalogUsable`, `ExactPolicyPermit`, `FirstCanaryCredentialFree`), matrix row 21, this
document's catalog-usable paragraph, and three test comments. Every one of those is a
`factActivation` row `EvaluateNode` excludes, so none can make the NODE surface un-ready; `node_ready`
is a literal field on that surface, which is what makes the wording a claim rather than loose prose.

**THE ROUND-2 SWEEP MISSED THEM BECAUSE IT SEARCHED FOR THE PHRASING, NOT THE PROPOSITION.** It
grepped `next read` and `readiness row reports`; these sites say *"must be able to make a node
un-ready"*, so they did not match — one formula, written once and copied. The rule to carry
forward: **when a review names one instance, search for the CLAIM it makes, not the words it
happens to use.** `TestCredWall_NoActivationFactPromisesNodeReadiness` derives the activation set
from exported behaviour and AST-reads the real `Facts` doc comments, with
`TestCredWall_NodeLevelFactsMayStillSpeakOfNodeReadiness` as its CONTROL — a node-level
prerequisite genuinely does make the node un-ready, and a gate that banned the phrase outright
would be a spell-checker rather than a wall.

M21 covers the FOURTH review-found defect, and it is the M20 entry above being wrong about itself.
Round 4 found TWO faults in that wall, both the same overclaim shape as the class it closes:

1. **It parsed only `readiness.go` while this record claimed six surfaces.** Reintroducing the
   promise in the matrix, this ledger or any of the three test files left the gate green — so M20
   did not close the class it records. `TestCredWall_EveryClaimedSurfaceIsScanned` now reads every
   surface the claim names, and permission to speak of node readiness is an EXPLICIT allowlist with
   a stated reason per entry, kept honest by `TestCredWall_AllowlistIsNotStale` (an entry matching
   nothing is a standing permission nobody uses). The wall's OWN file is deliberately excluded and
   says why: it defines the matcher and the allowlist needles, so a scanner reading itself reports
   its own machinery forever — and it was never one of the eight sites.
2. **Its control was vacuous.** It compared two derived classifications, never applied the matcher,
   and cited `RollbackCoordinatorRehearsed` as the legitimate node-level case — whose wording
   ("a rehearsed-mechanics node is still not ready") the matcher did not even recognise. The
   matcher now recognises that phrasing, and the control DRIVES it against the real doc, asserting
   both halves: it fires on legitimate node-level wording, and the wall permits it anyway because
   the field is node-level. Turning the wall into a blanket phrase ban now fails, flagging that
   legitimate field — verified.

**A control that cannot fail is decoration**, and this one could not: it exercised no matcher and
quoted text the matcher could not see. That is the anti-vacuity discipline this campaign applies to
every other gate, not applied to a gate of mine.

M22 and M23 cover the FIFTH review round, which found two things — one of them about the
measuring instrument itself.

**The claim has a negation, and the sweep only knew one polarity (M22).** Round 3 recorded the rule
*"search for the CLAIM, not the words"* and fixed eight sites, every one phrased negatively —
"makes a node un-ready" — because that is what it searched for. The identical proposition stated
the other way round, *"this row only stops a node reporting Ready"*, survived in **four** more
places, including the doc comment on `ReasonExactPolicyNotExecutable`: the reason string of an
ACTIVATION-level fact, in the engine's own source. Codex named one instance (a test comment); the
widened matcher found six lines in total. So round 3's lesson had been applied to the words of one
polarity, which is the same mistake one level in. `nodeReadyPromise` now carries a positive branch
anchored on the VERB (report / reach), so "the verdict is Ready — node readiness AND the
activation-level facts", a true statement ABOUT node readiness, is not swept up.

**A wall must not push an author away from the correcting sentence (M23).** Widening the matcher
made it flag the CORRECTED wording too — "EvaluateNode skips it and node status can still report
Ready" is the one sentence that makes an activation fact's scope unambiguous, and it contains the
same words as the defect while asserting the opposite. Suppressing it to satisfy a regex would be
the wall degrading the documentation it exists to protect, and allowlisting each correction
one-by-one would grow a permission list with every fix. `nodeReadyIndependence` exempts the shape
that asserts the node surface is UNAFFECTED, keyed on "still". M23 broadens that exemption until it
swallows the defect, and
`TestCredWall_CorrectedWordingExemptionDoesNotSwallowTheDefect` rejects it — the exemption is a
hole the moment it cannot tell the two apart. The residual is stated in the code rather than
hidden: a false claim contrived to contain "still … report … ready" would be exempted.

**A list of places to look rots the same way the claim does (the seventh surface).** Round 4's
finding was that the wall read ONE file while its record claimed six; the fix made it read the six.
Asking the round-5 question *"is there a seventh?"* against the whole repository rather than
against that list found one immediately: `mcp_canary_policy_permit.go`, ROOT PRODUCTION SOURCE,
carrying the same sentence as `readiness.go` — a file no version of the wall had ever read. So the
scan is now INVERTED: it walks every Go and Markdown file in the repository and names its
exceptions — `nodeReadyScanExcluded` (one entry: the wall's own file, which defines the matcher)
and `nodeReadyScanExcludedDirs` (`.git`, `node_modules`). A new file is covered the moment it
exists. Campaign scripts are out of scope by extension, because a mutation payload contains the
claim BY CONSTRUCTION.

The DIRECTORY axis was itself an unrecorded gap for one round. The first inverted scan also skipped
`frontend`, `dist` and `testdata` and wrote none of them down, while this paragraph claimed every
Go and Markdown file was covered — the same overclaim, on the axis introduced to close it, invisible
to every staleness check because nothing represented it. Codex round 6 found it. Those three are now
SCANNED (2,608 files), and the two that remain excluded are named with a reason each.

That number was wrong by one for a round, in two different ways at once, and both are worth
keeping. It was TRANSCRIBED as 2,555 when the walk returns one fewer — it removes the wall's own
file — so the sentence recording the coverage fix committed the coverage overclaim. And it was
MEASURED by adding a temporary probe test to the tree, which the walk then counted: the observer
was in the sample. `TestCredWall_LedgerStatesTheRealScanCount` now reads the number back out of
this document and compares it to what the walker returns, so it cannot be right by hand and wrong
in fact.

The allowlist got the same treatment for the same reason. `TestCredWall_AllowlistIsNotStale` used
to ask whether an entry's needle still appeared in the file; it now asks whether the scan REACHES
that entry, and caught a dead one on its first run — an entry added minutes earlier in this same
session, made unreachable by the quotation rule written just after it. Present is not reached.

The P1 of that round was separate and is recorded with the campaign score above: the wall was RED
on the unmodified head, so the recorded 21/0/0 measured nothing. That is now a campaign
precondition rather than a thing a reviewer has to notice.

**Round 7 found four, and two of them ended a strategy rather than patching one.**

1. **Negating the exemption's own wording bypassed it.** *"It is FALSE THAT node status can still
   report Ready…"* matched both the promise pattern and the exemption. The round-6 fix had been
   justified here as *"self-limiting — a sentence containing this phrase asserts the node surface is
   UNAFFECTED"*; that is simply wrong, because any assertion can be negated and a pattern that
   recognises a phrase cannot see the operator in front of it. **Two tightenings, two bypasses, both
   found by a reviewer rather than by a gate** — the signature of a losing game, not of a nearly
   correct rule. `nodeReadyIndependence` is DELETED. The two real corrective sentences are named in
   the allowlist like every other permitted claim, which is the conclusion round 6 reached for the
   quotation rule, now applied consistently instead of one mechanism at a time.
2. **An allowlist needle permitted the whole LINE it appeared on.** Appending a fresh claim after an
   allowlisted quotation stayed green: a permission to QUOTE one historical claim had become a
   permission to ASSERT a new one beside it. The reachability check could not see it, and that gap
   is the general lesson — **reachability proves an entry is USED; it says nothing about whether it
   is NARROW.** Matching is now by SPAN: an entry permits exactly the text it quotes, and a second
   claim elsewhere on the line is flagged. Switching to spans immediately exposed a live instance —
   the round-4 entry quoted the REFUTATION (`**That was FALSE**`) rather than the claim, so it had
   been permitting its line while covering nothing at all.
3. **The file count was wrong by one, and measured with the observer in the sample** — see above.
4. **The quotation-permission count understated itself** — see above.

**M24 then scored SKIPPED for the same root cause, one mutation later.** Its perl still matched a
line mentioning `nodeReadyIndependence` — deleted in this very round — so it changed nothing and
proved nothing. M23 had been repointed for that deletion and M24 had not, which is the recurring
shape again at the smallest possible scale: **a change that removes a symbol has to be carried to
everything naming it, and a campaign's own payloads are part of the tree.** SKIPPED is deliberately
not CAUGHT for exactly this reason — a mutation that does not apply is a gate nobody ran.

**M23 was NOT PROVEN, then SURVIVED, and the campaign found what review had not.** Its first
form replaced the span-containment test with `if true {`, which orphaned two loop variables and did
not compile — the M10 verdict, recorded in this very section, walked into again: a mutation that
cannot build runs no gate and proves nothing. Rewritten to compile, it then SURVIVED, and the
reason was in the control rather than the mutation.

`TestCredWall_AnAllowlistEntryPermitsOnlyWhatItQuotes` had been written around the needle
`**That was FALSE**`. That needle was repointed at the claim an hour later — because under span
matching a needle quoting the REFUTATION covers nothing — and the control was not re-checked. Its
sample line then contained no claim and no needle, so "permitted" was true because there was
nothing to permit, and no mutation of the containment test could change the verdict. **The control
had been decoration from the moment its dependency moved, and every run of it since had passed for
that reason.** It is now built on the real ledger line and asserts non-vacuity explicitly: the
sample must carry exactly one claim, be covered by a real entry, and the appended form must carry
two.

The general point is the one this section keeps paying for: **a control is coupled to the data it
samples, and changing that data silently disarms it.** Review found none of this; the campaign did,
which is the whole reason a score is re-measured rather than asserted.

**Round 6 found three more, and the second was larger than reported.** All three landed on
mechanisms built during round 5, which is what a review is for.

1. **The `still` exemption swallowed a negated claim.** *"This activation prerequisite PREVENTS the
   node from STILL REPORTING Ready"* matched both the promise pattern and the exemption, so the
   scan skipped it. The residual had been recorded here as contrived; it was one rephrasing away
   from ordinary documentation. The exemption now anchors on the full corrective subject
   (*"node status can still …"*), which is self-limiting: a sentence containing it asserts the node
   surface is UNAFFECTED.
2. **A quoted claim is still a claim — and in Go, "quoted" means STRING LITERAL.** Codex reported
   the scare-quote case (subject outside the quotes, predicate inside). Measuring which lines the
   rule actually exempted found six, and **three were not citations at all**: an `errors.New`, a
   `t.Fatal` and a `t.Fatalf`. The rule was exempting the contents of every error message, log line
   and test-failure string in the repository — so a false claim shipped to an operator in an error
   string was invisible to the wall. No syntactic rule can separate citing a claim from asserting
   one, so there is no general rule any more: the ledger's quotations and the genuine node-level Go
   strings are each named in the allowlist with a reason, kept honest by the reachability check.
   The COUNT is stated once, below, and gated — stating it twice is how this paragraph said three
   while the next sentence said four, two lines apart, with the gate green because it parsed only
   the other phrase (Codex round 8). **10 allowlist entries name ledger lines** — the two from round 4, the
   four quotations this removal required, and the four more that became VISIBLE in round 17 once
   the scan stopped reading one line at a time, counted by
   `TestCredWall_LedgerCountsItsOwnQuotationPermissions` rather than by hand, because the first
   version of this paragraph said three and understated the permissions it had introduced.
3. **The directory axis, above.**

**M25 SURVIVED its first run, and that is the most useful result of the round.** The mutation
weakens the allowlist staleness check from REACHED back to merely present. With every entry
currently reachable, the weakened form returns the same verdict on all of them — so the gate passed
with the defect in place. It was not enforcing reachability; it was riding on the allowlist
happening to be clean, and would have started enforcing only once something was already wrong.

That is this section's own recurring shape reaching the newest gate in it, hours after the gate was
written to close the previous instance. A check whose claim holds only when the tree happens to
violate it proves nothing on a healthy tree, which is every tree a reviewer looks at. The predicate
is now the named `allowlistEntryReached`, and
`TestCredWall_ReachabilityCheckCanActuallyFail` drives it in BOTH directions against the real
source — a needle on a line the scan never flags must read unreachable, the genuine node-level
claim must read reachable — so the mutation has something to break. Verified: M25 now fails that
control on the assertion, not on a build error.

**A survivor is a finding, not a failure of the run.** The campaign did its job here: it found a
hole a passing test suite could not, which is the entire reason the score is re-measured rather
than carried forward.

**The rounds, in order.** This list is the ENUMERATION the total below is checked against — both
derive from it, so neither can drift from the other (Codex round 9: the previous gate compared the
total to the largest `round N` numeral anywhere in the section, which a new entry headed differently
would not move, and a deleted entry would not shrink).

- **Round 1** — one stale matrix row reference reported; eight were present. Gated by M18.
- **Round 2** — the ledger claimed an observability property of a surface that reports nothing of
  the kind. Gated by M19.
- **Round 3** — three sites reported; eight present, every one of them in a single polarity.
  Gated by M20.
- **Round 4** — the wall read ONE file while its record claimed six, and its control was vacuous.
  Gated by M21.
- **Round 5** — the wall was RED on the unmodified head, so the recorded score measured nothing;
  and the claim stated POSITIVELY survived in five more places, plus a SEVENTH surface in root
  production source. Gated by M22 and by `baseline_ok`.
- **Round 6** — the `still` exemption swallowed a negated claim; quoted-means-cited was exempting
  every Go STRING LITERAL; the directory axis was an unrecorded gap. Gated by M23 and M24.
- **Round 7** — negating the exemption's own wording bypassed it; a needle permitted the WHOLE
  LINE; two ledger counts were wrong, one measured with a probe file in the tree. Gated by M23,
  M26 and M27.
- **Round 8** — a count stated twice disagreed with itself while its gate stayed GREEN; the round
  total was stale. Gated by M28.
- **Round 9** — the round gate derived the total from the largest `round N` numeral in the
  section rather than from its enumeration, so an added or deleted entry would not move it; and a
  second paragraph carried its own account of the campaign's growth, stopping at M21 while the
  script reached M28. Gated by M29 and M30.
- **Round 10** — the payload site counter added one round earlier could not fail. All 30 payloads
  match exactly one site, so dropping the `/g` from the counting run left every one of them passing
  with the guard disabled; the counter had been verified by hand and the verification written into
  this section, which protects no later run. Gated by `selfcheck_site_counter`, which refuses the
  campaign rather than scoring it.
- **Round 11** — this section described round 10 in a new paragraph while the enumeration below
  stopped at 9 and the total still read "9 rounds", and the round gate stayed GREEN because it
  compared only those two with each other. Round 9's finding one level out: the gate checked the
  two things it derived from each other and never asked whether they covered what the section
  talks about. Every round §25d NAMES must now be enumerated. Gated by M31.
- **Round 12** — the clause added in round 11 read only the SINGULAR form, so `rounds 7 and 8` —
  a phrasing this section had contained all along — matched nothing at all, not merely its first
  number, because `round\s+` cannot match the `s`. The gate passed on that text by luck: 7 and 8
  happen to be enumerated. One mutation per FORM, not one per rule. Gated by M32, which is M31's
  plural twin and was verified to PASS against the pre-fix extractor.
- **Round 13** — the comma-list arm of that same parser accepted only ONE separator token between
  numbers, so an Oxford comma — the form `rounds 7, 8, and 9` — stopped the list at the serial
  comma and returned only the first two, dropping the third. The dropped one went unseen whether or
  not it was enumerated, and in the case that matters it is not. (This entry cannot spell the
  original example, because the fixed parser reads any number it names as a round this section
  claims — the gate rejected an earlier draft of this very paragraph for naming an unenumerated
  one, which is the clearest demonstration available that it now reads the form.) Round 12's
  own rule, unapplied to itself: "comma list" and "comma list with a serial `and`" are different
  syntaxes. A separator is now a SEQUENCE, which is what `, and` is. Gated by M33.
- **Round 14** — a serial `or` was a third separator the parser could not read, after the plural
  `and` and the Oxford comma, and every one of the three truncated the list SILENTLY. Measured:
  `or`, `&` and `through` all dropped everything after the first number. Adding a fourth token
  would have invited a fifth round, so the FAILURE MODE changed instead: an unrecognised connector
  between two round numbers is now a build failure that names the connector, and the next form is
  reported rather than quietly dropping a round. Gated by M34 and M35.
- **Round 15** — that refusal matched ONE short token, so multi-word connectors (`as well as`,
  `followed by`, `alongside`) evaded BOTH the parser and the refusal: M35 claimed to close a
  failure mode it did not. Four rounds of the same finding with a different word in it is evidence
  that a connector VOCABULARY cannot be completed, so there is no longer one. Every one- or
  two-digit number inside a bounded window after a `round` token is a named round, whatever joins
  it to the previous one; the window stops at the first sentence terminator, and the two-digit
  bound keeps ordinary prose out. Verified against the live section: it collects EXACTLY the
  enumerated set. Gated by M36.
- **Round 16** — the collector treated ANY newline as a sentence boundary, and this section is
  hard-wrapped Markdown, so a list of rounds that straddles a newline truncated at the wrap and the
  round named after it was invisible while the gate stayed green. Four rounds had asked what JOINS
  the numbers; none had asked what SEPARATES the lines. The stop is now a paragraph break (a blank line), never a line
  wrap — a change that can only WIDEN each window, so the collected set is a superset of what it
  was and the gate can get stricter but cannot go blind. The live section still yields exactly the
  enumerated set. Gated by M37, whose payload changes no words at all, only where the line breaks.
- **Round 17** — two findings, both the same axis one step further. (a) The round collector also
  carried a fixed BYTE cutoff on top of its sentence bound, so an ordinary long sentence naming a
  round past that offset truncated silently: an arbitrary number cannot be a statement about where
  a sentence ends, and the terminators already are one, so the cutoff is deleted. Measured before
  and after against the live section: the same set. Gated by M38. (b) The whole-tree CLAIM scan
  still read LINE BY LINE, so a forbidden claim split across a wrap matched neither line and the
  wall stayed green with the claim present — round 16's defect one layer up, in the scanner that
  reads the same wrapped files. The rule is now stated once and applied in both: a line wrap is
  not a boundary, a blank line is. The scan unit is a SENTENCE, not a paragraph: every branch of
  the matcher is bounded by `[^.]`, so splitting there cannot lose a match, while a paragraph-wide
  unit lets an earlier unrelated `node` start the match and widen its span past the needle that
  quotes the claim — which made the wall report live, reasoned permissions as unreachable. Joining
  immediately exposed SEVEN mentions no per-line scan could ever have seen; each is legitimate and
  each is now named in the allowlist with a reason. Gated by M39.

**17 rounds, one defect shape.** Every finding on this branch has been a gap between what a gate
PROVES and what its record CLAIMS — the readiness fact vs the surface (round 2), the surface vs the
class (round 3), one file vs six (round 4), one polarity vs the proposition and a score vs its
baseline (round 5), a general rule vs Go string literals (round 6), an anchored phrase vs its own
negation and a needle vs the line it sat on (round 7), and a gated number vs the same number stated
again two lines away (round 8), a gate that derived a count from prose beside it rather than from
the list it claimed to check (round 9), a guard whose counter could not fail because every input
expected the same answer (round 10), and a list and a total that agreed with each other while both
understated the section they described (round 11), and a rule stated over several syntaxes that
was only ever tested in one of them (round 12), and that same rule left unapplied to the rule
itself one round later (round 13), and three separators in three rounds that each truncated a list
without saying so (round 14, where the fix was to stop truncating silently rather than to learn a
fourth word), and a refusal that could read one word but not two (round 15, where the connector
vocabulary was deleted rather than extended a fifth time), and a parser tested only on single-line
input against a document that is hard-wrapped (round 16, where the blind spot was the line break
itself rather than any word), and that same blindness left unfixed in the scanner beside it while
the collector was taught to see (round 17, where the rule was finally stated once and applied to
both readers of the same wrapped files).

The gates get stronger every round; what keeps failing is the accounting around them, so the
discipline that matters is not "add a gate" but **"state exactly what the gate establishes, and no
more"** — and, learned the hard way in rounds 7 and 8, **state each fact ONCE.** A number repeated
is a number that will drift, and gating one of its two statements is worse than gating neither,
because the audit then reports green while the document contradicts itself.
`TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration` keeps this very sentence honest: the total
must equal the enumeration, the enumeration must be contiguous from 1, and every round the section
NAMES — in the singular, plural, comma-list or range form, each pinned directly by
`TestCredWall_RoundNamesAreParsedInEveryFormTheLedgerUses` — must appear in it.

That last clause was added in round 11 and this sentence is why it is worth recording separately.
The description here previously read *"comparing its total against the highest round the section
actually discusses"* — which is the behaviour round 9 REMOVED for being unsound, still written down
as though it were the contract, two paragraphs below the entry recording its removal. Nothing
checked it, because a gate's prose description is exactly the kind of claim this section keeps
finding unbacked.

> A campaign score is a **measurement, not a property of the suite** — it must be re-run after any
> change to the code *or* to the campaign. The first run of this campaign scored M10 as NOT PROVEN
> rather than caught: the mutation left a variable unused, the package did not build, and no gate
> ran. A build failure proves nothing, so the mutation was corrected to compile and re-measured.
> The campaign has grown once per review finding ever since, so every earlier score described a
> campaign that no longer existed. Each growth blanked the recorded number back to a placeholder
> rather than carrying it forward, which is the whole point of the rule.
> The CURRENT size is stated once, with the score above, and
> `TestCredWall_LedgerStatesTheCampaignSize` ties it to the number of mutations the script actually
> runs — this paragraph used to carry its own enumeration and stopped at M21 while the script
> reached M28, giving §25d two incompatible accounts of the same history (Codex round 9).

## §26 Final verdict

### `FIRST CONTROLLED CANARY REVIEW: BLOCKED — NO SAFE FIRST CANARY TARGET`

The Canary core is fail-closed across scope, trust firewall, budget ceiling, per-request kill
re-read, restart re-arm/allowance, and no-secret evidence. But a safe first experiment cannot be
assembled today on **fifteen independent blockers** — some are intentional capability gaps, some are
prerequisites, and two are genuine product defects the Codex adversarial rounds (§24) surfaced and
this review verified against the code. The list below is complete AGAINST §25: together the fifteen
cover every mandatory NO/CONDITIONAL row there, so closing ALL of them is necessary and sufficient to
pass §25 — but the mapping is grouped, not strictly 1:1 (e.g. §25's independent-witness row folds
under blocker 7's auto-abort and also depends on blockers 1 and 6).

**Passing §25 is not the same as being safe to run, and this list is not a complete inventory of what
must be closed.** Later adversarial rounds have found real defects that no §25 criterion names — they
are recorded in §24 under their own headings, deliberately NOT renumbered into the fifteen (which
would let them inherit a neighbour's closure) and NOT filed as a sixteenth blocker (the original
fifteen are preserved exactly as adopted). A First Canary requires the fifteen closed AND every such
§24 finding closed.

**Post-adoption status (see §25a, §25b, §25c).** The baseline remains **fifteen**; the list below is
preserved as adopted, and nothing is renumbered or deleted. Seven entries have changed status since:
**blocker 4 is CLOSED**, **blocker 5 is CLOSED**, **blocker 6 is CLOSED**, **blocker 7 is CLOSED**,
**blocker 13 is CLOSED**, **blocker 14 is CLOSED**, and **blocker 8 is narrowed but still OPEN**.
Eight are untouched, and the verdict above is unchanged — closing blockers 4, 5, 6, 7, 13 and 14
removes six of fifteen reasons a GO is forbidden, not the prohibition.

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
4. ~~**The read-first classifier refuses the one-exact-tool call (§6).**~~ **CLOSED** — exact
   read-first tool classification. The finding stands as written: `tools/call` WAS `OpWrite` with
   no exception, and `tools/list` binds no exact tool. Of the two remedies it named, the finer
   classifier was taken and the discovery-trust path was deliberately NOT — substituting a listing
   for an invocation is the thing §7 forbids.

   A `tools/call` now becomes `OpRead` if and only if the ACTIVE activation's immutable reviewed
   record binds this exact (tenant, server, tool), at this exact fingerprint AND fingerprint
   format, under this exact pinned server identity, to a four-eyes reviewed read-only class.
   Everything else — no activation, no reviewed entry, a moved fingerprint, a moved identity, a
   moved tenant, an unstated class, an unknown or unusable tool — stays `OpWrite`. The reviewed
   class rides on blocker 7's activation snapshot rather than a classifier of its own, so there is
   no second authority to diverge from it; the seam the runtime is handed carries
   `(capability, serverID, toolName)` and nothing a request, an argument or a server could supply.
   Classification happens once and flows through the existing decision tuple, walled structurally
   at both ends. See §25a for the full closure argument and proofs.
5. ~~**The machine gate does not enforce exactly-one tool/principal (§10).**~~ **CLOSED** — the
   exact First-Canary scope gate. `MaxCanaryTools`/`MaxCanaryPrincipals` are still 2 and are
   deliberately UNCHANGED: they bound the Canary ARCHITECTURE, which a later graduation phase may
   use, and tightening them would silently redefine that architecture as exact-only. The FIRST
   experiment is a separate, narrower question, so it gets a separate predicate —
   `canary.ValidateFirstCanaryScope` (`internal/mcp/canary/firstcanary_scope.go`) — layered ON TOP
   of `ValidateScope`, never instead of it.

   **What it requires**, on all 19 fields of `rollout.ScopeSpec` (the enumeration is machine-checked
   by `TestFirstCanary_GovernsEverySelectorClass`, so a new selector class cannot arrive un-ruled):
   exactly 1 `Tenants`, 1 `Servers`, 1 fully-pinned `Tools` entry **hosted by that one server**, and
   1 `Principals` entry; `Clients`, `Agents`, `Groups`, `Environments`, `ToolFingerprints` (the
   second, server-unbound tool-selecting class) and all four `Exclude*` dimensions EMPTY; `Percent`
   0 with no `BucketSalt` and the default `BucketKey`; `HighRisk` false and `Operations` empty or
   exactly one `RiskRead`; no duplicate, empty, over-long or glob-shaped identifier.

   **No aggregate identity counting.** This is the specific hazard §10's correction named: the base
   contract's `principalCount` sums `Principals`+`Clients`+`Agents`, so a `count==1` remedy is
   satisfiable by one shared `Client` with zero `Principals`. The exact gate judges each identity
   class on its own — `Principals` must be exactly one, and the other classes must be absent — and
   `TestFirstCanary_NonPrincipalClassCannotSatisfyExactPrincipal` proves both halves: a lone client
   or agent is refused by its own named reason, and removing it leaves the scope still refused for
   having no principal, so it contributed nothing positive.

   **It is decided on the SIGNED activation scope, and never deduplicated.** `rollout.Compile`
   builds sets, so validating a COMPILED scope would collapse `[P1,P1]` into one principal and turn
   an ambiguous signed object into a valid one. The gate therefore reads the RAW slices;
   `TestFirstCanary_NeverDeduplicatesAnInvalidSignedScope` pins that the compiled form genuinely
   collapses (the hazard) while the gate still refuses. Runtime telemetry is never proof either: if
   the signed scope COULD authorize two identities, the First Canary is not exact even if only one
   request ever arrives.

   **It runs in the authoritative activation preflight, not at a runtime side-effect gate.** The
   verdict is taken exactly once in the root package — inside `evaluateActivationOnFacts`, on
   `in.Scope` — and both preflight entry points (the serialized commit gate and the restart
   reconcile) route through that body. A wider signed scope therefore yields `Ready:false`, which is
   what "cannot activate at all" means mechanically. The structural wall
   `TestExactScope_EnforcedInTheAuthoritativePreflightNotOnlyAtRuntime` pins the call site, the
   argument spelling, and both entry points; runtime scope matching stays defense-in-depth
   (`TestExactScope_RuntimeStillDeniesOutOfScopeIdentities`) and is explicitly NOT the closure proof.

   **Primary closure proof:** `TestExactScope_WiderScopeCannotBeReadyEvenWithEverythingElseSatisfied`
   asserts EVERY other prerequisite true — node and activation alike, a state unreachable in the
   shipped build — with a positive control proving that fact set IS `Ready` for the one exact
   experiment, then shows twenty widenings each return `Ready:false` carrying
   `canary_scope_not_exact_first_canary`. Full rejection matrix in
   `internal/mcp/canary/firstcanary_scope_test.go`; anti-vacuity control
   `TestFirstCanary_CanonicalExperimentPasses` (T1/S1/Tool1/P1). Campaign:
   `scripts/mcp-first-canary-exact-scope-mutations.sh` (30 mutations).

   **Scope discipline.** This establishes only that exactly one tool is AUTHORIZED BY SCOPE. It does
   NOT establish that `tools/call` for that tool is read-first executable (blocker 4 — the
   operation-classifier problem, untouched by THIS entry and closed separately in its own), nor that
   the target is `catalog.Usable`, exact-policy ALLOWed, or has satisfiable obligations
   (blockers 13/14, untouched).
6. ~~**The budget does not bound physical upstream invocations (§9).**~~ **CLOSED** — see
   "Blocker 6 closure" below. Idempotent read retries could send the POST ~3× per single budget
   reservation; the Canary path is now retry-free and the bound is proven at the wire.
7. ~~**Whole-Canary auto-abort is incomplete (§14/§16) — a product defect.**~~ **CLOSED** — the
   activation-bound reviewed-target snapshot closes the last open Round-24 P1. The five closure rows
   now hold:

   | row | state | where it is proven |
   |---|---|---|
   | atomic activation binding | COMPLETE | `admitLiveExecution` decides the whole predicate under ONE acquisition of `cr.mu`; `mcp_canary_atomic_binding_test.go`. The comparison is ALSO reached on a scope-independent path, because a Canary scope pins the reviewed fingerprint and a fingerprint move therefore removes the request from every scope-gated path — `Deps.CanaryTargetObserved` + `latchReviewedDriftUnderActivation`, proven reachable in `internal/mcp/runtime/canary_reviewed_target_test.go` (Codex P1, PR #1360) |
   | durable reviewed-target binding | COMPLETE | `canaryRuntimeState.ReviewedTargets` (schema 2), canonicalized before persistence; `mcp_canary_reviewed_durable_test.go` |
   | approval-lifetime independence | COMPLETE | drift is decided against the activation's own record, never against an approval; matrix cases 2/4/5 |
   | restart preservation | COMPLETE | restore re-canonicalizes and fails closed; matrix case 7 + the durable suite |
   | same-generation immutability | COMPLETE | a same-mode update that would rebind the set is refused (`errRolloutCanaryReviewedTargetsChanged`); matrix case 10 |

   **What was still missing when this was REOPENED, and why it mattered.** The atomic transaction
   was correct, but the fact it compared was the wrong one: drift was inferred from an approval
   still pinned to the reviewed fingerprint. Approval lifetime was therefore doing duty as drift
   memory — and those are different security facts. An approval answers *is this request authorized
   right now?*; the activation's snapshot answers *is this still the exact target this experiment
   was reviewed against?* A first Canary window may run for `FirstCanaryMaxWindowCeiling` (7 days)
   while a live-execution approval may live at most `MaxInitialCanaryApprovalTTL` (24 hours), so for
   six of those seven days the approval store could no longer say what the activation had been
   reviewed against. An attacker who simply WAITED OUT the TTL and then republished the tool met an
   ordinary "not approved" denial instead of a whole-experiment abort. Worse, a later valid approval
   for the NEW fingerprint could make the moved target look authorized to a generation that was
   never reviewed for it.

   **The fix, in one line:** an activation now carries an immutable, durable snapshot of the exact
   targets it was reviewed and authorized to execute (`canary.ReviewedTargetSet` —
   tenant/server/tool/fingerprint/format plus the pinned server identity), the comparison is made
   against THAT inside the same activation transaction, and the approval-pinned proxy has been
   removed. Empty or non-canonical reviewed targets fail the activation CLOSED; a durable active
   record that cannot prove what it was reviewed for — including one written by a build predating
   the field — does not restore executable authority; and generation G's set is immutable for its
   whole life, so a change requires demote → re-activate. Proofs: `mcp_canary_reviewed_binding_test.go`
   (the 12-case deterministic matrix), `mcp_canary_reviewed_durable_test.go` (durable compatibility),
   `mcp_canary_reviewed_antivacuity_test.go` (every negative gate proves the request produced the
   expected observation first, and the drifted target reaches zero upstream calls beside a positive
   control that crosses exactly once).

   The record of how the transaction itself was arrived at is kept below, because each correction
   was a wrong turn taken in good faith and is worth not repeating. The first pass wired every declared `AbortCanary` code
   onto the one `AbortController`, made both rate detectors reachable inside the 3-execution corpus,
   and made the deadline absolute and self-enforcing — but it shipped with two open Round-19 P1
   findings in the pre-admission drift path, and was merged in that state. It was recorded as
   REOPENED rather than quietly amended, because for a release-readiness gate "CLOSED with two open
   P1s" is not a status, it is a contradiction.

   The defect both findings named is one thing: the activation generation was read AROUND an
   unlocked trust observation and the two reads compared. Counter equality proves the value did not
   CHANGE; it does not prove any activation was ACTIVE throughout — during the rollout publication
   gap both reads are a stale value. Five review rounds produced a P1 against five different
   arrangements of those reads, which is the signal that the invariant was not expressible that way.

   It is now expressed by construction. `admitLiveExecution` verifies an armed activation, captures
   its exact non-zero generation, evaluates live trust IN FULL — including the approval — latches an
   authoritative drift against that generation, and reserves the budget, under ONE acquisition of
   the activation lock, which it owns and never exposes. "Trust under G, reserve under G+1" is not a
   race made unlikely; it is a state the code cannot express.

   Three further review rounds reshaped the parts around that transaction, and each correction is
   worth recording because each was a wrong turn taken in good faith:

   - The pre-executor refusal was first left EVIDENCE-ONLY, on the reasoning that an observation
     binding to no activation must not latch one. That reasoning was half right and the conclusion
     was wrong: after a rug-pull, later requests resolve cleanly against the NEW fingerprint and are
     denied for a missing approval — request-scoped, not drift — so nothing downstream ever latched
     and a declared whole-Canary breach stopped nothing. The answer was to GIVE the observation a
     binding, not to drop the latch: the pipeline reports the drift with its target, and the root
     re-derives it live INSIDE the activation critical section.
   - Consulting the durable approval store inside that section coupled automatic abort, demotion and
     generation revalidation to disk health, because every approval mutation holds the store mutex
     across an atomic file write. Hoisting the lookup out of the lock fixed that and bought a worse
     defect — a revocation landing during the lock wait was missed, and no later boundary re-reads
     approval status. The edge was removed at its source instead: `internal/mcp/tooltrust` publishes
     a copy-on-write snapshot through an atomic pointer, so the read never takes the store mutex and
     the whole predicate is evaluated under one lock.
   - The latch is bound to the activation the observation was made under. The activation runtime
     holds no scope, so a stale observation could otherwise stop a REPLACEMENT activation whose
     scope excludes the target. The generation in force is captured before the rollout resolution
     and compared inside the lock; generations are strictly monotonic, so a mismatch means an
     activation intervened, and a mismatch skips the latch — the safe direction, since an in-scope
     request under the new activation observes the same drift and latches it there.

   Bounded pre-admission drift evidence is counted and surfaced read-only on `GET /api/mcp/rollout`
   regardless of whether the latch fires, so an operator always learns the catalog moved under a
   decision. The latch revokes EXECUTION AUTHORITY; it does not demote the node, which stays
   governed by blockers 10 and 12.
8. **Durable outcome evidence is incomplete/success-only, with an unclosable post-send crash window
   (§15/§18) — a product defect.** **STILL OPEN, narrowed** — see "Blocker 8 status" below. The
   internal half (terminal outcome on every exit path, durable send intent, orphan recovery,
   typed witness reconciliation) is complete and proven against the real spool; the AUTHORITATIVE
   PRODUCTION WITNESS ADAPTER remains unwired, and until it is, a post-send crash resolves to
   `reconciliation_required` rather than to a determinate answer.
9. **[CLOSED — see §25d] Credential path unresolved (§4).** Credential selection comes from the tool's
   matched policy RULE, not from provisioning a server/tool, and the production broker has ZERO
   providers, so a `CredentialProfile`-bearing rule fails closed at `Broker.Materialize`. Provisioning
   a target (blocker 1) does NOT by itself establish no-credential status; it must be closed explicitly
   by verifying a no-`CredentialProfile` matched rule OR implementing a working credential
   provider/path. A no-`CredentialProfile` rule is NOT sufficient on its own — see blocker 14: the
   matched rule must also be ALLOW-class with satisfiable obligations, or the request is denied anyway.
   **CLOSED (§25d) on the FIRST disjunct only, and the closure statement is narrow: *the First Canary
   requires no production credential*.** The second disjunct is NOT claimed — no production credential
   Provider adapter exists and the broker still composes zero providers. Re-derivation found that the
   finding's own wording understates the problem: a "no-`CredentialProfile` matched rule" is a
   statement about the POLICY layer, which is the only one of three authoritative credential
   statements any enforcement path reads, so it is satisfiable while the authoritative
   `registry.ServerRecord.CredentialProfile` requires one — the state in which execution takes the
   no-broker branch and reaches a credential-required upstream with NO Authorization header. The
   preflight therefore carries `canary.ReasonCredentialPathRequired`, MET only when the policy
   obligation, the registry record and the reviewed catalog fingerprint are ALL empty, resolved from
   the same coherent capture as blocker 14's permit. Runtime drift is answered by the EXISTING
   reviewed-target machinery, because `CredentialProfile` is a hashed fingerprint field; and the
   execution path is separately proven to touch no broker, reach no provider and send no
   Authorization on the canonical path, while failing closed with upstream=0 on a credential-required
   one. **Any FUTURE experiment that needs a credential remains blocked on the unimplemented provider
   path.**
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
13. **[CLOSED — see §25b] The seeded controlled tool is `catalog.Quarantined` and nothing promotes it (§6/§7).** `seedTools`
   lands every inventory tool Quarantined (`mcp_inventory.go:15-17`) — the correct record-only Observe
   disposition — and the policy engine hard-overrides a `DispQuarantined` tool to `ActionQuarantine`
   BEFORE any user rule is evaluated (`internal/mcp/policy/engine.go:132-135`). `ApproveLive`
   DELIBERATELY performs no promotion ("live trust never materializes `catalog.Usable`",
   `mcp_tooltrust.go:413-450`), and the only non-test `catalog.Promote` callers are the shadow
   `promoteFor` path (`mcp_tooltrust.go:536`, `:629`). So even with blockers 1–12 closed and the
   finer read-first classifier now shipped (blocker 4, CLOSED), every exact-tool request is still
   hard-denied at the quarantine override — a read-first CLASSIFICATION is not catalog USABILITY,
   and the classifier deliberately declines to speak for an unusable target rather than substituting
   for this control. Catalog USABILITY must be a mandatory criterion: a `shadow_evaluation` approval (which
   promotes) or another governed promotion path must make the exact tool `catalog.Usable`.
   **CLOSED (§25b).** It is now a mandatory MACHINE-CHECKED activation criterion rather than a
   runbook step: the activation preflight carries `canary.ReasonToolNotCatalogUsable`, resolved from
   the authoritative catalog for the exact scoped target at the exact pinned fingerprint. No new
   trust authority was introduced — the governed `shadow_evaluation` lifecycle remains the only
   writer of `catalog.Usable`, `ApproveLive` still deliberately promotes nothing, and a structural
   wall proves no data-plane caller can. ENFORCEMENT is unchanged and still lives in the policy
   engine; what changed is that an ACTIVATION PREFLIGHT can no longer return Ready for an
   experiment every request would die in.
14. **[CLOSED — see §25c] The exact request must resolve to an ALLOW-class decision with satisfiable obligations (§4/§13).**
   Closing the credential condition (blocker 9) by choosing a rule with no `CredentialProfile` does not
   make the request executable: that rule may itself be DENY-class, and if NO enabled rule matches,
   `matchRules` falls through to default-deny (`engine.go:170-173`); `resolveEnforcing`
   (`internal/mcp/rollout/resolve.go:168`) blocks every non-allow-class decision. The preflight's
   `PolicyHealthy` fact is only `mcpPolicy.composed()` (`mcp_canary_preflight.go:83`) — it proves a
   snapshot EXISTS, never that the exact request resolves to an allow. The authorization must therefore
   require the exact (principal, tenant, server, tool, operation) to resolve to an ALLOW-class rule with
   every execution obligation satisfiable.
   **CLOSED (§25c).** It is now a mandatory MACHINE-CHECKED activation criterion: the preflight carries
   `canary.ReasonExactPolicyNotExecutable`, resolved by running the REAL shared policy engine over the
   exact First-Canary tuple built from authoritative state. The bar is deliberately STRICTER than the
   finding's own wording — a plain `policy.ActionAllow`, never `Action.IsAllowClass()` — because
   re-derivation against current code showed MONITOR reaches `EffectExecute` and ALLOW_ONCE /
   ALLOW_FOR_SESSION / ALLOW_WITH_REDACTION are gated afterwards by runtime state no preflight can
   observe. Obligations are judged SATISFIABLE-HERE against a closed allow-list, not merely
   well-formed, and the verdict must be invariant over every policy field the activation does not
   bind — so it is a statement about the experiment rather than about one imagined request.
   Enforcement is unchanged and still lives in the policy engine. The credential clause's overlap with
   blocker 9 is recorded in §25c and deliberately NOT acted on; **blocker 9 stays OPEN.**
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
(12). (Blockers 4 and 13 have since been CLOSED — §25a, §25b — which changes which of these reasons
still bites, not the verdict: 1, 2 and 3 alone still mean no experiment can execute.) Blockers 5–12,
14 and 15 are unmet *prerequisites*/defects, not a live
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
  ALLOW-class with satisfiable obligations — which blocker 14 (CLOSED, §25c) now machine-checks,
  including that the matched rule carries no `CredentialProfile`. **That overlap is recorded, not
  acted on: blocker 9 stays OPEN**, because the permit binds the tuple the preflight can construct
  and says nothing about the broker/provider path (see §25c);
- ~~make the exact tool **`catalog.Usable`**, and treat catalog usability as a MANDATORY
  criterion~~ **DONE AS A MACHINE CRITERION (blocker 13 CLOSED, §25b)** — it is no longer an
  external prerequisite anyone could forget or attest to by hand. The activation preflight resolves
  usability for the exact scoped target and reports `tool_not_catalog_usable` when it does not hold,
  so a Quarantined tool yields `Ready:false` instead of a green light for an experiment the policy
  engine would hard-quarantine. The OPERATOR step that remains is the one the gate now enforces:
  issue a `shadow_evaluation` approval (the only promoting path) for the exact tool at the exact
  fingerprint. `ApproveLive` still never promotes;
- ~~require the exact request to resolve to an **ALLOW-class policy decision with every execution
  obligation satisfiable**~~ **DONE AS A MACHINE CRITERION (blocker 14 CLOSED, §25c)** — it is no
  longer an external prerequisite anyone could forget or attest to by hand. The activation preflight
  runs the REAL shared policy engine over the exact First-Canary tuple and reports
  `exact_policy_not_executable` unless the verdict is a plain `policy.ActionAllow` with no hard
  override, a matched rule, a read-first class, satisfiable obligations, and invariance over every
  unbound policy field. `PolicyHealthy` (`mcpPolicy.composed()`) remains a separate row and still
  proves only that a snapshot exists. The OPERATOR step that remains is the one the gate now
  enforces: author an enabled plain-ALLOW rule matching the exact target on BOUND fields only, with
  no obligation beyond logging/observation;
- ~~impose the exact one-of-everything identity shape as an authorization prerequisite~~ **DONE
  (blocker 5 CLOSED, §25a)** — it is no longer an external prerequisite. `canary.ValidateFirstCanaryScope`
  enforces exactly one `Principals` entry, zero `Clients`/`Agents`/`Groups`, and exactly one tool (plus
  one tenant and one server) as a MACHINE gate in the activation preflight. The count==1 insufficiency
  named here is what the design avoids: identity is counted on `Principals` alone, so the
  `principalCount` aggregate can never satisfy it, and `MaxCanaryTools`/`MaxCanaryPrincipals` stay 2
  deliberately — they bound the Canary architecture, not this experiment (§10);
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
