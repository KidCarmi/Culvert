# ADR-0034: MCP Tool Trust — source of truth and approval-purpose binding

Status: Accepted (2026-08-28)
Supersedes: none
Subordinate to: ADR-0024 (MCP Agent Security Gateway — trust boundary)
Related: SHADOW-ACTIVATION.md §8b (the "usable scoped tool" prerequisite), ADR-0025-adjacent policy-learning trust posture

## Context

The MCP catalog (`internal/mcp/catalog`) discovers tools and classifies each into an
`Eligibility` state — `Quarantined`, `ReviewRequired`, `PendingNarrowing`,
`ServerDisabled`, `Usable` — but **no ingestion path can produce `Usable`** by design
(`catalog.go:14-16,30-33`, `dispositionFor`/`stickyFloor` never map to it). `Usable`
was deliberately reserved for "a later approval slice."

`Usable` is also the **last hard prerequisite** for the first Controlled Shadow
activation: `evaluateShadowActivationPreflight` fails closed with
`no_usable_shadow_tools` unless a scoped tool has `Eligibility == catalog.Usable`
(`mcp_shadow_preflight.go:52-60`). ADR-0024 mandates `Usable` = "an approved, known
tool" but does not decide **who/what promotes a record to `Usable`**, nor how a trust
decision is kept from becoming a live-execution authorization.

This ADR decides the MCP **tool-trust** primitive: a privileged human explicitly
trusts ONE exact observed tool fingerprint for ONE declared purpose, and that trust
disappears the instant the observed capability no longer matches what was reviewed.

## Decision

### D1 — Trust ≠ availability ≠ authorization (three separate concepts)

- **Tool trust** — is this exact observed tool eligible to be considered? (this ADR)
- **Tool availability** — can the tool appear/be selected in this environment? (scope)
- **Invocation authorization** — may THIS request execute now? (policy engine)

A tool becoming `Usable` MUST NOT bypass policy, approvals, confirmation, allowances,
inspection, rollout, kill switch, identity, or credential controls. In the policy
engine `DispUsable` trips **no** override band — a `Usable` tool merely *survives* to
the default-deny `matchRules` step (`engine.go:99-174`). Anti-weakening tests pin:
`Usable + DENY ⇒ DENY`, `Usable + REQUIRE_APPROVAL ⇒ REQUIRE_APPROVAL`,
`Usable + REQUIRE_CONFIRMATION ⇒ REQUIRE_CONFIRMATION`, `Usable + no-rule ⇒ default-deny`.

### D2 — Source of truth: durable approval store authoritative; catalog `Usable` is a materialized projection (Model B via a fold)

The live catalog is **in-memory only** (`atomic.Pointer[Snapshot]`, rebuilt every boot
from the static inventory that re-seeds every tool `Quarantined`). It therefore cannot
be the durable home of a trust decision. A new, dedicated, durable **`ToolApproval`
store** (`internal/mcp/tooltrust`) is the source of truth. The catalog's `Usable` state
is a **materialized projection** of the store: a tool is `Usable` iff an **active**
`ToolApproval` binds to the tool's **current** fingerprint. A trust **coordinator** owns
the derivation and reconciles the catalog on approve / revoke / expiry / post-ingest /
startup-recover.

Rejected alternatives: **Model A** (persist `Usable` on the catalog record) — the
catalog is not persisted and provenance/revoke/expiry become ad-hoc. **Pure runtime
derivation** threaded into the policy hot path — needless coupling and per-call cost.

### D3 — Durability = dedicated `fileutil.AtomicWrite` store + startup `Recover`

The approval store persists to `<dataDir>/mcp_tooltrust/approvals.json` via
`fileutil.AtomicWrite` (temp→fsync→rename), schema-versioned, bounded, tenant-scoped,
**secret-free** (never a token, credential, raw schema/body, or private identity
material — only safe references and the fingerprint digest). It is authoritative and
recoverable **independently of the MCP events spool** (which is armed only when MCP is
composed). The two durability guarantees this slice ships are: (1) the **AtomicWrite
store** is the recovery authority — startup `Recover` re-materializes trust from it; and
(2) every mutation writes the **root admin audit ring** (`mcp.tooltrust.<verb>`), the
queryable governance record.

**Deferred (NOT shipped in this slice):** a *supplementary* tamper-evident record in the
MCP events spool. The existing `events.Manager.CommitDecision` API is decision-point
specific (`DecisionFacts` with typed identity/decision/inspection/credential evidence) —
a tool-trust approval is a governance action, not a policy decision, so committing it
there would require a purpose-built tool-trust event type rather than a synthetic
decision event. That integration is a follow-up; it changes none of the authoritative
guarantees above (the AtomicWrite store stays the recovery authority and the audit ring
stays the governance record), so trust durability does not depend on it.

**Startup reconcile is load-bearing:** the boot inventory re-seeds every tool
`Quarantined`; `Recover` then re-applies each active, unexpired, unrevoked approval
whose bound fingerprint matches the freshly-seeded tool's current fingerprint. Without
it every restart silently revokes trust.

### D4 — Approval binds to the exact fingerprint digest, never a name

A `ToolApproval` binds to `Fingerprint.Sum()` (`fingerprint.go:121-148`) — the
length-prefixed SHA-256 over all 12 independently-hashed dimensions (server id, pinned
identity, name, input-schema, output-schema presence+content, description/title/
annotations, credential profile, destination class, format version). One approval can
authorize exactly one digest. Any change to any dimension changes `Sum()` and the
approval no longer matches (the rug-pull invariant).

### D5 — Approval purpose / trust ceiling; the live-execution firewall

`ToolApproval.Purpose` ∈ {`shadow_evaluation`, `live_execution`}. In this slice **only
`shadow_evaluation` was issuable**; `live_execution` was defined and **refused at issue**.
_Superseded by **Addendum 2026-09** below: `live_execution` is now issuable through a dedicated
governed path (four-eyes, ≤24h TTL, exact-current-state) — it remains a TRUST decision only and
never arms the live tier or makes a tool `catalog.Usable`._ A
`shadow_evaluation` approval satisfies ONLY `evaluateShadowActivationPreflight` (via
`catalog.Usable`); it can NEVER arm `liveExecDepsConfigured` / `modeExecReady` for a
`RequiresLiveExecution()` (Canary/Production) mode — that tier is armed only by the
separately-reviewed, deliberately-uncalled `markGatewayExecDepsReady`. A future live
phase MUST introduce and require a stronger execution-trust purpose; a structural test
asserts a shadow approval can never satisfy a live-execution prerequisite. **Shadow
approval ≠ live-execution approval.**

### D6 — Stale-target / exact-target semantics (fail closed)

Approval is optimistic-concurrency. The request carries the **expected fingerprint hex**
and **expected catalog (and registry) revision**; the backend loads the authoritative
current facts and, immediately before publication, re-verifies: server still exists,
belongs to the tenant, is enabled/usable, identity still matches; the tool still exists,
its fingerprint exactly matches the expected digest, it is still in an approvable state,
and the catalog revision has not advanced under the decision. Any mismatch fails closed
(`ReasonApprovalStaleTarget` / `ReasonToolFingerprintMismatch`). The backend never
silently approves the latest same-named tool and never retargets.

### D7 — Revocation and expiry are first-class

Revoke is durable, tenant-scoped, exact-`ApprovalID`, authorized, idempotent, race-safe,
restart-safe, fail-closed, and causes **immediate** loss of usability (Demote). A
revoked approval NEVER becomes valid again from a later identical `tools/list`;
re-approval requires a NEW human decision. Approvals carry an optional `ExpiresAt`
(injected clock); an expired approval keeps no tool `Usable`. The first Controlled
Shadow runbook prefers a short-lived shadow approval.

### D8 — Lifecycle (per exact fingerprint)

```
unknown → Quarantined
Quarantined + human approval of exact fingerprint → Usable (materialized)
Usable + identical rediscovery (same fingerprint) → Usable
Usable + privilege expansion → Quarantined     (approval no longer matches)
Usable + semantic drift → ReviewRequired        (approval no longer matches)
Server identity change → ServerDisabled          (overrides; approval cannot promote)
Approval revoked/expired → NOT Usable
```

**Sticky quarantine is preserved:** ingestion alone NEVER clears quarantine; only a
fingerprint-bound human approval does. A tool that drifts away from its approved
fingerprint loses `Usable` immediately; if the exact reviewed fingerprint is observed
again the approval re-satisfies (shadow-only, byte-identical to what was reviewed, and
never an auto-clear by ingestion). Revoked/expired approvals never re-satisfy.

### D9 — What this slice does NOT do

No server-wide/wildcard/bulk/auto approval; ~~no `live_execution` issuance~~ (governed
`live_execution` issuance landed subsequently — see Addendum 2026-09; it is trust only and still
performs no activation); no Shadow/Canary/Production activation; no live Executor / UpstreamCaller
/ Materialize; MCP
Management stays `mutation_tools: 0` (trust mutation is an admin-HTTP action, not a
Management MCP tool); MCP ToolAnnotations remain untrusted hints that can never flip
`Quarantined → Usable`.

## Consequences

Positive: the last hard Controlled-Shadow prerequisite closes with a provable
supply-chain trust primitive; trust is exact-fingerprint-bound, durable, revocable,
expirable, tenant-scoped, and stale-safe; a shadow approval structurally cannot become a
live-execution authorization.

Negative / residual: the coordinator adds a reconcile step on ingest and boot; the
flap-back (drift-away then exact-return) re-satisfies a non-revoked approval — accepted
because it is shadow-only and byte-identical to the reviewed capability (documented in
D8). The AtomicWrite store and the best-effort event evidence can momentarily disagree on
an abrupt crash between the two writes; the AtomicWrite store is the recovery authority
and the event is tamper-evidence only.

## Addendum (2026-09) — governed `live_execution` issuance

`live_execution` ToolApprovals are now issuable, but ONLY through a dedicated governed path that
enforces stronger requirements than shadow issuance — it does not simply flip `Issuable()` and
reuse shadow request semantics. This is a **trust decision only**: it composes no executor, wires
no `UpstreamCaller`, materializes no credential, never calls `markGatewayExecDepsReady` or
`beginCanaryActivation`, and never makes a tool `catalog.Usable` (that projection stays driven only
by active shadow-purpose approvals). "Trust is not availability, and neither is authorization —
runtime policy stays authoritative for every call."

- **Dedicated path + route isolation.** `RequestLiveApproval`/`ApproveLive` (coordinator) and
  `validateLiveApproveLocked` (store) own the live path. `ApproveShadow` refuses a non-shadow
  purpose and `ApproveLive` refuses a non-live one, so a live grant can never be minted through the
  shadow promotion path and vice-versa (`TestLiveTrust_RouteIsolation`).
- **Four-eyes, mandatory, on the canonical principal.** `RequestedBy != ApprovedBy`, both present,
  compared on the authenticated session subject (`mcpLivePrincipal`), never display names or client
  IP; a live request with no authenticated session is refused fail-closed.
- **Mandatory finite TTL ≤ 24h.** An explicit expiry is required at request (no silent default) and
  the window is capped by the single authority `MaxLiveExecutionApprovalTTL` (24h) — enforced at
  request (from now) and authoritatively at approval (from `approved_at`).
- **Exact-current-state at approval + rug-pull.** Approval revalidates the exact reviewed target
  (server/tool exist, identity+fingerprint+format match, catalog+server revision current, tenant)
  and fails closed on any drift; an F1→F2 fingerprint change never auto-upgrades the F1 grant.
- **Revoke/expiry fail closed across restart.** A revoked or expired live approval fails the Canary
  scope preflight, does not resurrect on reload (`validateStored` live invariants + fail-closed
  strict decode), and reapproval is a new decision (`now == expires_at` fails closed).
- **No broad forms.** No server-wide, wildcard, all-fingerprints, all-tenants, group-wide,
  purpose=both, or approve-future live grant is expressible.
- **Consumed only by the Canary preflight.** `productionCanaryActivationInputs` builds bindings
  from the authoritative store (`buildLiveApprovalBindings`); `canary.ValidateScopeApprovals`
  requires each admitted `(tenant, server, tool, fingerprint)` to carry its own valid live approval.
  Readiness row `live_execution_approval_invalid` becomes SATISFIABLE, not auto-satisfied.

Every lifecycle event (request/approve/reject/revoke) is durably audited and never persists a
credential or secret. See `docs/operator/mcp-tool-trust-approvals.md` for the operator procedure.
