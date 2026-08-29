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

`ToolApproval.Purpose` ∈ {`shadow_evaluation`, `live_execution`}. **Only
`shadow_evaluation` is issuable** in this slice; `live_execution` is defined and
**refused at issue** (`ReasonApprovalPurposeUnsupported`, fail closed). A
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

No server-wide/wildcard/bulk/auto approval; no `live_execution` issuance; no Shadow/
Canary/Production activation; no live Executor / UpstreamCaller / Materialize; MCP
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

## Amendment 2026-08-29 — D10: separation of duties on a trust grant

The slice as shipped had no separation-of-duties check: one principal could create a
tool-trust request and approve it, self-granting `Usable` for a fingerprint of its choosing.
That was an omission, not a decision — D9 does not list it among the deliberate exclusions,
and the sibling operational-approval plane in the same subsystem has always enforced
four-eyes with the same reason code.

**D10.** The requester of a `ToolApproval` MAY NOT approve it. `Store.Approve` refuses
`ReasonApprovalSelfApproval` (HTTP 403) on the pending→active transition, before any
mutation, so a refusal leaves the record undecided. The idempotent re-approve of an
ALREADY-active grant is deliberately out of scope — it re-verifies the target and changes
nothing.

The comparison is over an **authenticated identity**, never the client address: the admin
call sites build the principal with `mcpApprovalPrincipal` (session subject, else a
verified HTTP Basic username), because a principal that embeds the client IP lets one human
satisfy four-eyes from two addresses. `normalizePrincipal` additionally strips a trailing
`"@" + <IP literal>` from both sides so a durable record written by the pre-amendment build
is still compared identity-to-identity. Audit attribution is unchanged and still records
the address.

See `docs/engineering/security-reviews/2026-08-29-mcp-tooltrust-and-four-eyes-window.md`
(SEC-4E-1 / SEC-4E-2).
