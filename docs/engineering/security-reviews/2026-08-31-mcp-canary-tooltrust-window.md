# Security regression review — MCP tool-trust + Canary-gate window (2026-08-31)

**Scope:** everything merged into `main` after the predecessor artifact, i.e.
`e698a12..0336149` — PRs #1229 … #1258. 184 files (excluding `frontend/`),
+31,251/−743, 202 commits. The dominant areas are the new
`internal/mcp/tooltrust` (ADR-0034 tool-trust approval), `internal/mcp/canary`
(ADR-0035 Canary activation gate), the Shadow readiness split
(`mcp_rollout_execdeps.go`, `mcp_shadow_startup.go`), and the CHAOS-56 bounded
shutdown. Root admin-plane, `internal/fileblock`, `internal/mcp/catalog`,
`internal/mcp/runtime` and `internal/mcp/execution` were reviewed as modified
security-critical code.
**Branch:** `claude/epic-bardeen-iox87x` · baseline `0336149`
**Predecessor:** `2026-08-25-shadow-layerb-and-ldap-window.md`
**Method:** read the window, then REVIEW → PROVE → FIX → TEST → MUTATE. SEC-FE-1
and SEC-FE-2 were **reproduced against the unmodified `0336149` tree before either
fix was written** (§3 quotes the reproduction output); SEC-FE-3 and SEC-FE-4 were
raised by the Codex review bot against the first push and verified against the
source before being actioned (§4a). Every fix is **mutation-verified**: the fix was
reverted and the new gates were required to fail.

> **Verdict (§8): no security regression was introduced by this window. Four
> pre-existing or fix-adjacent separation-of-duty defects were found — one of them
> reachable on live admin routes today — and all are closed here. This document does not
> authorise enabling execution: Shadow stays env-gated and default-off, and
> Canary/Production remain fail-closed at an unarmed live-execution tier.**

---

## 1. Executive summary

The window is overwhelmingly **tightening**. It adds a fingerprint-bound,
durable, revocable supply-chain trust primitive (ADR-0034), a Canary activation
gate built almost entirely out of fail-closed predicates (ADR-0035), a
readiness-tier split that lets Shadow be composed **without** arming live
execution, and a bounded shutdown sequence. Nothing in it enables execution, and
the live-execution registration hooks (`markGatewayExecDepsReady`,
`markManagementExecDepsReady`) have **no production caller** — verified by source
sweep, so every Canary/Production transition still fails closed at
`modeExecReady`.

The findings are not regressions from this window. They are
**separation-of-duty (four-eyes) defects** that the window's own new code made
visible, because `internal/mcp/canary/trust.go` now states the four-eyes
requirement explicitly as a Canary-readiness predicate — and doing so exposed
that (a) the identity being compared cannot support the comparison, and (b) the
requirement was never enforced at the tool-trust decision boundary at all.

| ID | Severity | Finding | State |
|---|---|---|---|
| SEC-FE-1 | **High** | Every four-eyes gate in MCP compares a principal string that embeds a **client-controlled network coordinate** (`auditActor` = `"<identity>@<clientIP>"`). One authenticated admin defeats all of them by varying the source address — trivially, via `X-Forwarded-For`, when the admin UI sits behind a configured trusted proxy. Reachable on live admin routes today. | **Fixed** — stable `approvalPrincipal` |
| SEC-FE-2 | **Medium** | `tooltrust.Store.Approve` enforced no four-eyes check at all. A self-approved tool-trust grant became durably active and promoted the tool to `catalog.Usable` immediately; `canary.EvaluateTrust` only *observed* the violation later, at Canary-readiness time. | **Fixed** — enforced at the decision boundary |
| SEC-FE-3 | **Medium** | *(review follow-up)* A pending tool-trust record written before SEC-FE-1 carries an IP-bearing `RequestedBy`, so it compares unequal to the same human's now-coordinate-free principal — she could approve her own request and walk straight through the SEC-FE-2 gate. | **Fixed** — `SchemaVersion` 1→2, pre-change stores fail `Load` closed |
| SEC-FE-4 | **Low** | *(review follow-up)* `approvalPrincipal` decided identity presence by comparing against `sessionAdmin`'s `"unknown"` sentinel, which is also a legal username — a real user named `unknown` was read as unauthenticated and 403'd. | **Fixed** — presence decided from field lookup, not name |

---

## 2. What this window changed, and the security direction of each part

| Area | Change | Direction |
|---|---|---|
| `internal/mcp/tooltrust` (new, 1.3k LOC) | Durable, schema-versioned `ToolApproval` store; exact-fingerprint binding; optimistic-concurrency revision check; tenant scope; expiry; revoke | **New control.** `Approve` re-verifies the bound target against LIVE facts (`verifyTarget`) and refuses a revision advance (`revisionStale`), so the request→approve TOCTOU is closed and it never retargets |
| `internal/mcp/catalog` `Promote`/`Demote` (new) | The `Usable` projection writer/withdrawer | **Tightening.** Bounded CAS, `ServerDisabled` identity override wins over any approval, exact-fingerprint rug-pull guard, idempotent, never fails open |
| `internal/mcp/catalog` `buildIngest` | Withdraw records a **complete** discovery did not observe; enforce the per-server cap on the **merged** set | **Tightening.** Gated on `nextCursor` absence so a partial page never withdraws; closes an unbounded per-server accumulation on the partial path |
| `internal/mcp/canary` (new, ~2k LOC) | Shadow-Exit attestation, abort taxonomy + monotonic latch, budget enforcement, scope, trust predicates, rollback rehearsal | **New control**, all fail-closed: unknown abort code ⇒ whole-Canary latch; nil controller ⇒ latched; unset attestation status ⇒ not attested; build-identity binding requires a real lowercase-hex commit |
| `mcp_rollout_execdeps.go` | Split one exec-deps flag into independent **shadow** and **live** tiers | **Tightening.** `markGatewayExecDepsReady` is uncalled in production, so Shadow can be composed while Canary/Production still fail closed |
| `mcp_shadow_startup.go` | Compose the non-executing `ShadowEvaluator`; wire request inspection | **Neutral/tightening.** Env-gated, default OFF; type graph structurally cannot carry an `UpstreamCaller` or a materialize-capable broker |
| `internal/mcp/runtime` policy/execute | Resolve the rollout disposition **exactly once** and carry it into execution; honour the emergency kill on the record-only fall-through; re-check kill generation at the side-effect boundary | **Tightening.** Closes a routing TOCTOU and an emergency-kill gap on both the credential and no-credential paths |
| `internal/fileblock` | Per-transaction checks read an immutable view via `atomic.Pointer`; `CheckContentType` pre-filters before `mime.ParseMediaType` | **Cost-only, verified behaviour-preserving** — see §3 |
| `controlplane_server.go`, `main_shutdown.go`, `runtime_shutdown.go` | CHAOS-56 bounded shutdown, watchdogged hooks, bounded `GracefulStop` | Availability/durability; no authorization surface touched |
| `ui_middleware.go` / `ui_rbac.go` | Carry the Basic-auth username in context so admin actions attribute to the real actor | **Tightening** of audit attribution |
| `ui_tls_custom.go` | Validate the persisted custom UI cert/key actually loads as a matching pair before using it | **Tightening** — an interrupted two-file upload can no longer make `startUI` `logFatalf` |

### Verified safe (reviewed, no defect)

- **Execution posture.** `markGatewayExecDepsReady` / `markManagementExecDepsReady`
  have no production call site (source sweep); `Mode.RequiresLiveExecution()`
  covers exactly Canary+Production; the admin transition handler additionally
  hard-locks Production (403 `rollout_production_locked`) and terminates in
  `distribution_not_configured`. Nothing in this window arms execution.
- **`internal/fileblock` view publication.** All five mutation sites
  (`SetPath`, `Add`, `ReplaceAll`, `Remove`, `ClearAll`) call `publishLocked()`
  under the write lock; the missing-republish case is a silent *security*
  failure and is pinned per mutator by `TestBlockerView_EveryMutatorRepublishes`.
- **`CheckContentType` pre-filter equivalence.** `mediaTypeOf` reproduces
  `mime.ParseMediaType`'s first two lines verbatim; the pre-filter is purely
  negative (it can only return the allow answer early) and every block still
  routes through the unchanged parse, so the malformed-parameter case still
  declines to block exactly as before. Pinned against a verbatim copy of the
  pre-fix body plus a fuzz target.
- **`tooltrust.Store.Load` hostile-input handling.** Size bound before read;
  invalid UTF-8 rejected on the RAW bytes *before* decode (`encoding/json`
  silently substitutes U+FFFD); unpaired `\uXXXX` surrogate escapes rejected for
  the same reason; `DisallowUnknownFields`; a second decode required to report
  `io.EOF` so trailing data cannot ride along; schema equality exact; record
  count bounded. Fails closed at every branch.
- **Catalog withdrawal / trust flap-back.** A withdrawn-then-re-added tool
  re-ingests as unknown ⇒ Quarantined, and is only re-promoted by the
  coordinator's reconcile if a **non-revoked** approval still matches the exact
  fingerprint. That is the ADR-0034 D8 flap-back, explicitly accepted there.
- **Emergency kill precedence.** `preCallGuard` evaluates tool freshness first
  (the callback may itself change authoritative state) but reports the kill
  first, so an operator's emergency stop is never metered as staleness.

---

## 3. Finding SEC-FE-1 — the four-eyes principal carries a client-controlled coordinate

**Severity: High** · CWE-863 (Incorrect Authorization), CWE-807 (Reliance on
Untrusted Inputs in a Security Decision) · OWASP **A01:2021 Broken Access
Control** · Regression risk of the fix: **low**

### The defect

Every separation-of-duty gate in the MCP subsystem is a plain string equality on
the principal recorded for the request:

- `internal/mcp/approval/store.go:204` — `if approver == r.requester` →
  `ReasonApprovalSelfApproval`. This governs **operational approvals**
  (`POST /api/mcp/approval-decision`) and **policy-publication approvals**
  (`POST /api/mcp/publication-decision`), both live admin routes.
- `internal/mcp/canary/trust.go:79` — `a.RequestedBy == a.ApprovedBy` →
  `TrustNoFourEyes`, the Canary-readiness predicate added by **this window**.

Those principals came from `auditActor(r)` (`ui_helpers.go:27`), which is
deliberately `"<identity>@<clientIP>"`. The identity half is authenticated; the
appended half is a **network coordinate the acting principal controls**:

- `realClientIP` honours `X-Forwarded-For` whenever the request arrives through a
  **configured trusted proxy** — the ordinary enterprise shape for an admin UI
  behind a reverse proxy. The header is supplied by the caller.
- With no trusted proxy configured it is the peer address, so the same human on
  office vs VPN vs a new DHCP lease is a different "principal" anyway.

### Attack scenario

**Preconditions:** one account with `admin` on the Culvert admin UI (admin is
required for the decision route; `operator` suffices to create the request, and
admin ⊇ operator). For the one-request variant, a trusted-proxy CIDR configured
— i.e. the admin UI is behind a reverse proxy.

1. Alice (admin) authenticates once. She holds one session cookie.
2. `POST /api/mcp/publication` with `X-Forwarded-For: 198.51.100.1` →
   the request is recorded with requester `alice@198.51.100.1`.
3. `POST /api/mcp/publication-decision {"action":"approve"}` with
   `X-Forwarded-For: 198.51.100.2` → the approver is `alice@198.51.100.2`.
4. `approver != requester`, so four-eyes passes. **One human, one credential, one
   session, self-approved.**

Without a trusted proxy the same result needs only a second network egress
(VPN off/on, a second workstation, a mobile hotspot) — no header control at all.

**Exploitability:** trivial; a single header on an already-authorised request.
**Likelihood:** high wherever four-eyes is being relied upon as a control.
**Impact:** the four-eyes control on MCP policy publication and operational
approvals is void; a single compromised or malicious admin account performs both
halves of a two-person decision. The same defect makes the **Canary** readiness
fact `TrustNoFourEyes` satisfiable by one person, so a future live phase would
inherit it. It is also wrong in the *restrictive* direction: two genuinely
different unauthenticated callers behind one NAT egress collapse to the same
`unknown@<nat-ip>` principal.
**Affected assets:** MCP policy publication, MCP operational approvals, the
Canary trust predicate, and (via SEC-FE-2) tool-trust grants.

### Reproduction against the unmodified tree

```
requester="alice@198.51.100.1" approver="alice@198.51.100.2"
PROVEN: same authenticated admin "alice" yields distinct four-eyes principals
PROVEN: alice self-approved her own request; receipt valid=true
```

(One admin session cookie, two `X-Forwarded-For` values, trusted proxy
`10.0.0.0/8`; then the same pair driven end to end through
`approval.Store.Create` + `approval.Store.Approve`.)

### Fix

`approvalPrincipal(r)` (`ui_rbac.go`) returns the **stable authenticated subject
and nothing else** — session `Sub` → session `Email` → the Basic-auth username
`uiAuthMiddleware` places in context — and returns `""` when no identity can be
resolved. `mcpFourEyesPrincipal(w, r)` (`ui_mcp.go`) wraps it for handlers and
**fails closed** with `approval_not_authorized` (403) on an unattributable caller.

Three properties are load-bearing and are each pinned by a test:

1. **`auditActor` is unchanged.** The audit ring still records
   `"<identity>@<clientIP>"` — who acted *and from where* (RISK-019). Only the
   four-eyes principal changes.
2. **Absent ≠ `"unknown"`.** Before setup completes, `uiAuthMiddleware` grants
   `RoleAdmin` with no identity at all. Mapping that to a principal literally
   named `"unknown"` would make every anonymous caller the *same* principal, so
   a four-eyes gate would read as satisfied between two different anonymous
   callers while refusing one honest retry. Absent is the only correct answer,
   and the handler refuses.
3. **Distinct subjects stay distinct.** The fix must not collapse two humans
   into one principal, which would make four-eyes unsatisfiable.

---

## 4. Finding SEC-FE-2 — tool-trust approvals had no four-eyes enforcement

**Severity: Medium** · CWE-862 (Missing Authorization) / CWE-269 (Improper
Privilege Management) · OWASP **A01:2021** · Regression risk of the fix: **low**

### The defect

ADR-0034 makes a `ToolApproval` a *supply-chain trust* decision: approving it
materialises `catalog.Usable` for an exact tool fingerprint. `ui_mcp_tooltrust.go`
describes it as "reviewed by a privileged human", and this window's own
`canary.SatisfiesLiveExecution` **requires** `RequestedBy != ApprovedBy`
(`TrustNoFourEyes`).

But `tooltrust.Store.Approve` never checked it. The RBAC split alone does not
supply it: create is `operator`, decide is `admin`, and `admin ⊇ operator`, so a
single admin performs both. The requirement was therefore only ever **observed**,
at Canary-readiness time — long after the grant had already taken effect. A
self-approved grant became durably active, `promoteFor` flipped the tool to
`Usable` immediately, and the Canary gate merely refused Canary later.

### Attack scenario

**Preconditions:** one `admin` account; the tool-trust coordinator composed
(`initMCPToolTrust` succeeded).

1. Alice `POST /api/mcp/tool-approvals` — a pending request bound to a
   fingerprint she chose.
2. Alice `POST /api/mcp/tool-approval-decision {"action":"approve"}`.
3. The grant is durably active and the tool is `Usable` — the Shadow-activation
   preflight's `no_usable_shadow_tools` gate is satisfied by one person's
   unilateral supply-chain trust decision.

**Impact:** the two-person control over which MCP tools are trusted is absent at
the point where trust becomes effective. Bounded today by the shadow-only
purpose ceiling (`live_execution` is refused at issue) and by the unarmed live
tier — which is why this is Medium, not High.

### Fix

`tooltrust.Store.Approve` refuses `approver == a.RequestedBy` with the existing
`mcperr.ReasonApprovalSelfApproval`, on the **pending→active transition only**,
mirroring `internal/mcp/approval`. Placement is deliberate and tested:

- **After** the expiry and terminal-state gates, so those keep their precedence.
- **After** the already-active idempotent branch, so re-reading the outcome of a
  decision *somebody else* made is still allowed to the requester, and the
  original approver is never rewritten.
- **Before** `verifyTarget`, so a self-approval is reported as self-approval
  rather than masked by a co-occurring drift.
- An empty approver is already refused at entry and `RequestInput.validate`
  already requires a non-empty requester, so the check can never collapse into
  `"" == ""`.

---

## 4a. Review follow-ups (SEC-FE-3, SEC-FE-4)

Both were raised by the Codex review bot against the first push and verified against
the source before being actioned.

### SEC-FE-3 — a pre-upgrade pending record defeats the new gate

**Severity: Medium** · CWE-863 · Regression risk of the fix: **low**

Up to `SchemaVersion` 1, `RequestedBy`/`ApprovedBy` were written from `auditActor`.
The SEC-FE-2 gate compares `approver == RequestedBy`, and that comparison is only
meaningful between values in the **same** coordinate-free format: a v1 pending record
naming `alice@198.51.100.1` compares unequal to the very same human approving as
`alice`, so she walks straight through the gate.

**Fix:** `SchemaVersion` 1 → 2. A v1 store fails `Load` closed, `initMCPToolTrust`
composes nothing, and no tool is promoted.

The bump is deliberately **whole-store, not per-record**. A v1 record's four-eyes
evidence is untrustworthy whether it is pending or **already active** — an active v1
grant may itself have been self-approved under the old, bypassable comparison — so
keeping the active ones while refusing the pending ones would preserve exactly the
grants whose provenance this change calls into question.

`Load` names the pre-change version explicitly rather than reporting the generic
unknown-schema error: this is not corruption, and the two call for opposite operator
responses (retake the decisions vs. investigate a damaged file).

### SEC-FE-4 — `"unknown"` is a username, not a sentinel

**Severity: Low** (availability, fail-closed direction) · CWE-287 · Regression risk
of the fix: **low**

`approvalPrincipal` decided identity presence by filtering `sessionAdmin`'s `"unknown"`
sentinel. But `ui_auth.go` admits any 1–64 byte username with no reserved words, so
`unknown` is a creatable account — and that user was read as unauthenticated and 403'd
out of every decision route.

**Fix:** `approvalPrincipal` resolves the identity itself (session `Sub` → `Email` →
the context username) and reports presence from whether a field was **found**, never by
comparing the resolved name against a value a real user may hold. `sessionAdmin`'s own
contract is unchanged. A user named `unknown` and an unauthenticated caller must stay
distinguishable — collapsing them would let four-eyes read as satisfied between the two —
and that is pinned.


## 5. Files changed by this review

| File | Change |
|---|---|
| `ui_rbac.go` | `approvalPrincipal(r)` — the stable four-eyes principal (+ the reasoning that separates it from `auditActor`) |
| `ui_mcp.go` | `mcpFourEyesPrincipal(w, r)` fail-closed helper; publication create + publication decision + approval decision now use it |
| `ui_mcp_tooltrust.go` | tool-trust request `RequestedBy` and the approve/reject/revoke actor now use it |
| `internal/mcp/tooltrust/store.go` | four-eyes enforcement on the pending→active transition; precise pre-change-schema load error (SEC-FE-3) |
| `internal/mcp/tooltrust/tooltrust.go` | `SchemaVersion` 1→2 + the named pre-change version (SEC-FE-3) |
| `internal/mcp/tooltrust/store_foureyes_test.go` | **new** — 10 gates (below) |
| `mcp_four_eyes_principal_test.go` | **new** — 7 gates (below) |
| `ui_mcp_test.go` | `mcpReq` now injects a stable identity derived from the role, so the operator-requests/admin-approves pair is two distinct principals — which is what the documented workflow is |

## 6. Tests

**`internal/mcp/tooltrust/store_foureyes_test.go`** — negative (self-approval
refused, record left pending with no approver and no active grant), positive
(distinct approver succeeds), boundary (the comparison is exact and is documented
as *not* normalising), malformed input (empty approver, empty requester),
regression/ordering (self-approval outranks a co-occurring target mismatch;
expiry still outranks self-approval; the idempotent re-approve by the requester
of an already-four-eyes-approved grant stays reachable and does not rewrite the
approver), concurrency (32 concurrent self-approvals — all refused, record stays
pending; and a self-vs-peer race whose asserted invariant is the one that holds
under every interleaving), and durability (a refused self-approval leaves nothing
a later `Load` recovers as an active grant).

**`mcp_four_eyes_principal_test.go`** — the proven bypass as a regression gate
(one admin, three coordinates, one principal), distinct subjects stay distinct,
`auditActor` still carries the coordinate, authentication (unauthenticated ⇒
absent, not `"unknown"`; the handler 403s with `approval_not_authorized`;
an authenticated caller is admitted and the admit path writes nothing), the
Basic-auth transport yields the same principal as the browser one, and a source
**anti-drift wall** forbidding any four-eyes principal from being re-derived from
`auditActor`, and (SEC-FE-4) a user literally named `unknown` authenticating on both
the session and Basic-auth paths while staying distinguishable from an absent identity.

For SEC-FE-3: a verbatim v1 store fails `Load` closed with a message naming the cause,
recovers nothing, and leaves no record reachable; the bump is a real forward step; and a
store written by this build still round-trips. Schema fixtures elsewhere in the suite
were re-pinned to the live constant so a future bump cannot silently turn a
"valid envelope, other defect" test into a schema-rejection test that passes for the
wrong reason.

**Mutation verification.** Reverting the `tooltrust` guard fails 4 gates
(`RefusesSelfApproval`, `SelfApprovalOutranksTargetMismatch`,
`ConcurrentSelfApprovalsAllRefused`, `SelfApprovalLeavesNoDurableGrant`).
Reverting `approvalPrincipal` to `auditActor` fails 5 gates. Restoring the
sentinel-comparison shape fails 2 (SEC-FE-4); reverting the schema bump fails 2
(SEC-FE-3). Full suite: **105 packages ok**; `go vet ./...`, `gofmt`, `staticcheck` and
`gocritic` (repo tag set) all clean.

## 7. Residual risk

- **The anti-drift wall is a source scan.** It forbids the specific pre-fix
  spellings. A sufficiently different re-derivation would evade it; the
  behavioural gates remain the real backstop.
- **Exact string comparison.** The four-eyes check does not case-fold or
  canonicalise the subject. An identity provider that emits two spellings for one
  human would defeat it. Normalising is deliberately not attempted — a guess here
  could also *merge* two distinct principals, which is the worse direction. Pinned
  as a documented limitation, not a claim.
- **Tenant scope is a filter, not an authorization boundary.** `mcpTenant(r)`
  reads `?tenant=` verbatim; Culvert's admin roles are global, not tenant-scoped.
  This is the pre-existing convention across the whole MCP admin surface and was
  not changed here. It prevents accidental cross-tenant action, not malicious.
- **Pre-upgrade records are refused, not migrated.** A store written before this
  change carries IP-bearing `RequestedBy`/`ApprovedBy`, which the new comparison
  cannot trust. `SchemaVersion` is bumped to 2 so such a store fails `Load`
  closed; the operator retakes every decision. See SEC-FE-3.
- **Attestations are admin-created, not signed.** `ShadowExitAttestation` is
  durable local evidence bound to the build identity; it is not
  cryptographically attested by an external issuer. Consistent with the recorded
  design, and the live tier it gates is unarmed.
- **`internal/mcp/approval`'s four-eyes remains equality-based.** With SEC-FE-1
  fixed the comparison is now meaningful, but it is still a single-factor
  identity check — it does not prove two *people*, only two *accounts*.

## 8. Verdict

**No security regression was introduced by `e698a12..0336149`.** The window is
tightening throughout: new fail-closed trust and Canary machinery, a readiness
split that keeps live execution unarmed, a single-resolution fix that closes a
routing TOCTOU, an emergency-kill re-check at the side-effect boundary, and
faithful cost work in `internal/fileblock` and the shutdown path.

Four separation-of-duty defects were found and closed — two pre-existing
(SEC-FE-1, SEC-FE-2) and two raised by review against the fix itself (SEC-FE-3,
SEC-FE-4). SEC-FE-1 is the material one: it is reachable on live admin routes today and voided every
four-eyes gate in the MCP subsystem. It was surfaced *by* this window, because
`internal/mcp/canary/trust.go` is the first place the four-eyes requirement is
written down as a predicate — and writing it down is what made it checkable.

This document does not authorise enabling execution. Shadow remains env-gated and
default-off; Canary and Production remain fail-closed at an unarmed
live-execution tier; `live_execution` issuance remains refused.
