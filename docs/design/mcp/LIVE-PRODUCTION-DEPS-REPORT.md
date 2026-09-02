# MCP Live-Tier Production Dependency Composition — Security Posture Report

This phase wires the REAL production dependency graph for the MCP Gateway live-execution tier so a
node can reach the COMPOSED (and explicitly ARMABLE) state through production authorities — not only
through synthetic collaborators injected in tests. It changes exactly ONE capability (the guarded
graph is now production-composable and armable) and holds every safety invariant. **It is NOT the
First Controlled Canary.**

## The core invariant this phase satisfies

> Synthetic collaborators may prove the live executor works. They can never be the reason a
> production node believes it is safe to execute.

The single production caller of the composition seam (`composeProductionGatewayLiveTier`) constructs
only real collaborators from production authorities, is pinned to one call site, and the anti-synthetic
wall forbids any root package-main reference to the test-only synthetic KEK/provider constructors.

## Posture (required report)

| Dimension | Value |
| --- | --- |
| Real production dependency composition | **YES** — `composeProductionGatewayLiveTier` builds KEK, credential broker, upstream client, durable events, response DLP from production authorities |
| Live tier production-composable | **YES** (opt-in `CULVERT_MCP_LIVE_DEPS`, disabled by default) |
| Live tier explicitly armable | **YES** (`armLiveTier`, node-readiness-gated; unchanged from the prior phase) |
| Armed by default | **NO** — composition never arms; the armed bit is not persisted and no startup path calls the arming hook |
| Canary active | **NO** |
| Production active | **NO** |
| Customer traffic | **0** |
| Production credentials used (this change + its tests) | **0** — every KEK is a random ephemeral 0600 file in a test temp dir |
| Uncontrolled upstream side effects | **0** — composition reaches no upstream; `Upstream.Call == 0` |

## Per-dependency composition (fail-closed)

| Dependency | Production source | Readiness token | Fail-closed on |
| --- | --- | --- | --- |
| Credential KEK | `secret.FileProvider` + `secret.ValidateProvider` (no ephemeral/insecure fallback) | `kek_ready` | missing / unreadable / world-readable / wrong-size / symlinked / relative / non-canonical path |
| Credential profiles | `profile.NewStore(limits.DefaultCredential())` | `profile_store_ready` | — |
| Credential broker | `broker.New` over the shared registry/catalog + real KEK, **ZERO providers registered** | `broker_composed_no_provider` | credential-requiring tool fails closed at the broker (honest pre-Canary gap) |
| Destination resolver | thin `net.Resolver` adapter; SSRF rejection owned by `destination.Resolve` | `resolver_ready` | — |
| Destination policy | `destination.DefaultGatewayPolicy()` (https only, no private, no cross-origin redirect, no scheme downgrade) | `gateway_policy_https_no_private` | — |
| Trust roots | system roots (`RootCAs == nil`); **never `InsecureSkipVerify`** | `system_roots` | — |
| Upstream client | bounded `upstreamclient.Client` (per-server pools, admitted method set, pinned destination) | `upstream_ready` | construction error |
| Durable events | `events.Manager` (required — evidence-before-side-effect) | `events_ready` | nil manager (telemetry not composed) |
| Response inspection | `inspection.DefaultGatewayProfile` (Gateway capability, positive output bound) | `response_profile_ready` | re-validated fail-closed at the seam |

## Fail-closed guarantees (verified)

- **Atomic composition (§14/§15).** Every collaborator is built into locals and validated BEFORE the
  seam is called once; any failure returns early with a bounded machine-readable reason and leaves
  `Deps.Executor` untouched. There is no half-composed tier, and a composition failure can never arm.
- **Disabled by default (§4).** Unset `CULVERT_MCP_LIVE_DEPS` ⇒ nothing composed, byte-identical to a
  build without the flag. A partial opt-in (enabled, no KEK) fails closed.
- **Never arms (§16/§17).** Composition records COMPOSED and stops; arming stays the separate
  `armLiveTier` act. A restart re-runs composition but never re-arms.
- **Anti-synthetic wall (§20).** `composeGatewayLiveTierInto` and `composeProductionGatewayLiveTier`
  are each pinned to one production call site; no root package-main file references
  `secret.MemoryProvider` / `provider.NewInMemory`.
- **No secret exposure (§21/§29).** The config DTO carries only a path; the status view carries only
  bounded tokens; the KEK is 0600 and never leaves the temp dir in tests.

## Test coverage

- **§23 E2E:** production-shaped composition (real FileProvider KEK, real events/registry/catalog) —
  composes, records every dependency ready, never arms.
- **§24 failure matrix:** 8 fail-closed rows (not requested, no KEK, relative KEK, non-canonical KEK,
  nil events, symlink KEK, world-readable KEK, wrong-size KEK) — each leaves `Deps.Executor` nil and
  records the bounded reason.
- **§25 concurrency:** 16 concurrent compositions + concurrent readers, clean under `-race`.
- **§26 mutation campaign:** 8 mutations, each with its catching assertion.
- **§27 red-team:** arm-without-compose refused, composed != Canary-ready, traversal cleaned,
  whitespace env rejected, double-compose idempotent.
- **§28 post-arming degradation:** a degraded dependency makes the arm gate not-ready (re-arm refused);
  quiesce disarms fail-closed.
- **§29 zero real credentials:** every KEK is ephemeral, synthetic, local (temp dir); status view
  carries no secret/path.

## What still gates the first real Canary (out of scope here)

1. **Production credential Provider adapter.** No production `provider.Provider` exists yet, so the
   broker is composed with ZERO providers and a credential-requiring tool fails closed. A read-first /
   no-credential Canary needs none; a credential-bearing one is blocked until this lands.
2. **SPKI pin-provisioning** for private/internal pinned MCP servers. The public-CA path needs no pin;
   a private pinned server does.

Both are fail-closed and are remaining blockers before the First Controlled Canary. Neither blocks
composing or arming the guarded graph for the public / no-credential read-first path.

## Verdict

**REAL PRODUCTION DEPENDENCY COMPOSITION LANDED — LIVE TIER PRODUCTION-COMPOSABLE AND EXPLICITLY
ARMABLE; ARMED-BY-DEFAULT NO, CANARY ACTIVE NO, PRODUCTION ACTIVE NO, CUSTOMER TRAFFIC 0, PRODUCTION
CREDENTIALS 0, UNCONTROLLED UPSTREAM SIDE EFFECTS 0.** The next phase is a separate First Controlled
Canary Review + experiment.
