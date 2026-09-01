# Security regression review — 2026-08-29 · MCP tool-trust, kill boundary, Canary readiness

**Window reviewed:** everything merged to `main` after the previous review baseline
`cc9479f` up to `3f83ca9` — PRs #1236, #1240–#1249. 58 non-test Go files, +12,626/−96.
**Branch:** `claude/epic-bardeen-nbsjf7`
**Predecessor:** `2026-08-25-mcp-overnight-hardening-run.md`
**Method:** read the whole non-test diff; reproduce each candidate defect against the tree
before writing a patch; mutation-verify every new guard (revert the fix, require the test
to fail).

> **Verdict:** two findings, both in the MCP approval/trust plane, both fixed here. No
> regression found in the SWG data plane, TLS, policy, session, persistence, cluster or
> release surfaces — none of them was touched in this window.

---

## 1. Surfaces reviewed

| Surface | Change in window | Outcome |
|---|---|---|
| `internal/mcp/tooltrust` (new, ADR-0034) | Durable tool-approval store + catalog `Usable` projection | **SEC-4E-2** |
| `mcp_tooltrust.go`, `ui_mcp_tooltrust.go` (new) | Coordinator + admin API | **SEC-4E-1** (call sites) |
| `internal/mcp/approval` (unchanged) | — | **SEC-4E-1** (the control itself) |
| `internal/mcp/execution` (kill boundary, PREREQ-MCP-KILL-1) | Emergency-kill revalidation at the upstream side-effect boundary | No defect found — §3 |
| `internal/mcp/catalog` | Tool withdrawal on a complete discovery; per-server cap on the merged set | No defect found — §3 |
| `internal/mcp/canary` (new, ADR-0035) | Dormant readiness contract | No defect found — §3 |
| `internal/mcp/rollout` | Monotonic kill generation in the published snapshot | No defect found — §3 |

## 2. Findings

Severity: **P0** reachable today and security-relevant · **P1** reachable · **P2** latent.

| ID | Severity | Finding | State |
|---|---|---|---|
| SEC-4E-1 | P1 | **MCP four-eyes was keyed on network location, not identity.** `internal/mcp/approval` enforces four-eyes by comparing approver against requester, and documents `PrincipalID` as "a STABLE authenticated principal identifier". All three admin-HTTP call sites built that principal from `auditActor(r)` — an *attribution* string that is `realClientIP(r)`, prefixed with `"<sub>@"` **only when a UI session cookie is present**. | Fixed |
| SEC-4E-2 | P1 | **The ADR-0034 tool-trust plane had no separation of duties at all.** One principal could `POST /api/mcp/tool-approvals` and then `POST /api/mcp/tool-approval-decision action=approve` on its own request, self-granting `catalog.Usable` for a tool fingerprint of its choosing. | Fixed |

### SEC-4E-1 — the four-eyes principal was an address

**Attack scenario.** An admin who wants a decision that a second human would refuse — an
operational approval, an MCP policy publication, or (with SEC-4E-2) a tool-trust grant —
creates the request, then issues the approve from a different source address. The
four-eyes comparison sees two different strings and admits it. No second human is
involved, and the audit trail shows two "different" actors.

**Preconditions.** Admin role on the MCP admin API (the approve routes are `MinRole:
RoleAdmin`); the ability to reach the admin port from a second address. That is a second
NIC, a VPN, a jump host — or, where a trusted proxy is configured (`SetTrustedProxyCIDRs`),
a different `X-Forwarded-For` value, because `realClientIP` honours that header by design
once the peer is a trusted proxy. In that deployment the differentiator is a request
header the same caller supplies.

**Exploitability / likelihood.** Trivially exploitable by the one role that four-eyes
exists to constrain; requires no defect elsewhere and leaves no error. Likelihood is
raised by the control's *other* failure mode, below, which pushes operators toward exactly
this workaround.

**The fail-closed half.** `uiAuthMiddleware` accepts HTTP Basic as a first-class
programmatic admin path, and that path carries **no session cookie** — so on it the
principal was the address **alone** and the username never appeared. Two genuinely
different admins behind one bastion, NAT egress, or the reverse proxy itself are then one
principal, and a legitimate four-eyes approval is refused as a self-approval.

**Impact / affected assets.** MCP operational approvals, MCP policy publications, and MCP
tool-trust grants — the governance controls over what the gateway is allowed to do. Not
the SWG data plane.

**Fix.** `mcp_approval_principal.go` resolves the principal from the authenticated
identity, mirroring the middleware's own precedence: session `Sub` (else `Email`); else
the HTTP Basic username, trusted **only** when `cfg.IsConfigured()` — precisely when the
middleware reached its `VerifyUIUser` branch, since the pre-setup bootstrap branch admits
an *unverified* Basic header; else `auditActor(r)`, keeping the unauthenticated bootstrap
path byte-identical rather than introducing an empty principal the stores would reject.
`auditActor` is deliberately unchanged — attribution genuinely wants the address, and
every `auditEvent` call still records it.

**CWE / OWASP.** CWE-863 (incorrect authorization), CWE-807 (reliance on an untrusted
input in a security decision) for the `X-Forwarded-For` variant; OWASP A01:2021.

### SEC-4E-2 — tool trust had no separation of duties

**Attack scenario.** A single admin principal — or one compromised admin session — creates
a tool-trust request bound to an exact tool fingerprint and immediately approves it. The
tool becomes `catalog.Usable`, which is the last hard Controlled-Shadow prerequisite
(`evaluateShadowActivationPreflight`).

**Preconditions.** MCP tool trust composed (a Gateway qualification inventory loaded —
disabled by default), operator role to request, admin role to approve. Admin ≥ operator,
so one admin covers both.

**Impact.** `Usable` is a supply-chain trust decision, not an authorization: runtime policy
stays default-deny, the purpose firewall keeps a `shadow_evaluation` grant from ever
satisfying a live-execution prerequisite, and `catalog.Promote` still refuses a
`ServerDisabled` record. So the ceiling is *shadow evaluation of an unreviewed tool*, not
execution. What is lost is the review itself — ADR-0034's premise that "a privileged human
explicitly trusts" a capability, with the ADR's own claim of a second pair of eyes on a
tool's exact fingerprint.

**Why it is a finding and not a recorded decision.** ADR-0034 §D9 ("what this slice does
NOT do") does not list four-eyes among the deliberate omissions, and the Consequences
section does not record self-approval as an accepted residual. The sibling plane in the
same subsystem enforces it, with a reason code (`ReasonApprovalSelfApproval`) already
defined, named and HTTP-mapped. The gap is an omission, not a decision.

**Corroborated by the Canary design merged in the same window.**
`canary.SatisfiesLiveExecution` (ADR-0035, §3 clause 5) refuses a `ToolApproval` whose
`RequestedBy == ApprovedBy` with `approval_not_four_eyes` — the *consumer* of a
`ToolApproval` already assumes a distinct requester and approver, while the *producer* of
one never enforced it. The store-side check closes that asymmetry at issuance, so the
invariant now holds at both ends rather than resting on a dormant downstream predicate.
Note that the Canary predicate compares raw strings: under the pre-change IP-bearing
principals, a one-human approval issued from two addresses would have satisfied it too.
That path is unreachable today (a `shadow_evaluation` record fails
`PermitsLiveExecution` first, and `live_execution` is refused at issue), so the dormant
predicate is left as-is rather than changed speculatively.

**Fix.** `tooltrust.Store.Approve` refuses `samePrincipal(approver, RequestedBy)` with
`ReasonApprovalSelfApproval`, on the pending→active transition only (the idempotent
re-approve of an already-active grant re-verifies the target and changes nothing, so
refusing it would break idempotency without withholding trust). The check runs before
`verifyTarget` and before any mutation, so a refusal leaves the record byte-unchanged and
undecided. `mcpErr` maps the reason to **403** — a well-formed request that this principal
may not decide, not malformed input.

**Durable-record note.** The tool-trust store is durable, so a record written by the
pre-change build carries the IP-bearing requester. `normalizePrincipal` strips a trailing
`"@" + <IP literal>` from **both** sides of the comparison, so such a record is still
matched identity-to-identity and the bypass is not re-opened for one upgrade window. It
only strips a suffix that parses as an address, so `alice@example.com` is untouched; the
residual (`alice@10.0.0.1` as a literal identity would collapse to `alice`) fails **closed**
— it can only ever refuse an approval, never admit one.

## 3. Reviewed and refuted (no defect)

- **Emergency-kill boundary (`internal/mcp/execution`, PREREQ-MCP-KILL-1).** The
  admission-time generation capture, the `preCallGuard` ordering (freshness evaluated
  first so a callback that engages the kill is still caught; kill *paramount* in refusal
  precedence), the single classification+meter, and the same-pointer-swap publication of
  `killed`+`killGen` all hold. The residual paths where a boundary sentinel could escape
  unclassified all terminate in `blocked(...)`, never in a zero `ExecOutput` treated as an
  allow.
- **Catalog withdrawal on a complete discovery.** Withdrawal is correctly gated on the
  absence of a `nextCursor`, so a partial page cannot withdraw a later page's tool; the
  per-server cap is now evaluated on the merged key set, closing the unbounded
  first-page-accumulation shape. One documentation inaccuracy: the comment claims a
  re-added tool is "never silently re-Usable", but an *active, unexpired, exact-fingerprint*
  approval will legitimately re-promote it on the post-ingest reconcile. That is ADR-0034
  D8's recorded flap-back semantics; the comment, not the behaviour, is imprecise.
- **`Catalog.Promote`** refuses a `ServerDisabled` record, so the reconcile path — which
  derives coverage from server usability and fingerprint match alone — cannot promote a
  tool whose server carries the identity override.
- **Canary readiness (ADR-0035).** Pure, fail-closed, zero-valued to "nothing ready";
  `mcpCanaryStatus` reaches `getMCPRollout()` (a `sync.Once` constructor, never nil) and
  `stateFor` (never nil), so the new viewer-gated status block cannot nil-panic on the
  default disabled posture.
- **Tool-trust store recovery.** The raw-bytes UTF-8 check, the unpaired-surrogate-escape
  check, the trailing-data check, the per-status lifecycle invariants, and the
  distinct rejection/revocation evidence fields all fail closed as documented.
- **Discovery hook globals** (`execution.SetReconcileHook` / `SetIngestGuard`) are written
  at startup and read by `NewDiscovery`, which has **no production caller** in this build,
  so the documented "set once before any Discovery is constructed" convention holds.

## 4. Residual risk

- `Store.Reject` is tenant-scoped by the coordinator (`Get(id, tenant)` first) rather than
  inside the store, unlike `Get`/`Revoke`. Not exploitable — the tenant is immutable per
  record and approval ids are 128-bit `crypto/rand` — but it is a defence-in-depth
  asymmetry within one store, recorded rather than changed here.
- The four-eyes principal is only as strong as the admin identity behind it. Two admin
  accounts held by one human still satisfy it; that is inherent to four-eyes and is not
  claimed to be solved.
- `mcpToolTrustReconcile()` now runs on the viewer-gated `GET /api/mcp/tools`, so an
  authenticated viewer can drive a durable `ExpireDue` write and take `deriveMu`. Bounded
  by admin authentication and by the reconcile's O(active approvals) cost; recorded.

## 5. Tests added

| Test | Pins |
|---|---|
| `internal/mcp/tooltrust/selfapproval_test.go` · `TestApprove_SelfApprovalDenied` | Negative: the requester is refused with `approval_self_approval` |
| … `TestApprove_DistinctApproverSucceeds` | Positive control: a second human still succeeds |
| … `TestApprove_SelfApprovalLeavesRecordUndecided` | Fail-closed: record stays Pending, durable file byte-unchanged, a later valid approval still lands |
| … `TestApprove_SelfApprovalNotEvadedByClientAddress` | Regression: legacy/identity/two-address/IPv6 principal shapes all refuse |
| … `TestNormalizePrincipal_Boundaries` | Boundary + malformed: bare identity, IPv4/IPv6 suffix, email domain, multiple `@`, bare address, empty halves, invalid address |
| … `TestNormalizePrincipal_KeepsDistinctHumansDistinct` | Anti-over-stripping control |
| … `TestApprove_ConcurrentSelfApprovalRacesNeverGrant` | Concurrency: 16 racing self-approvals + one valid ⇒ exactly one grant, never the requester's |
| … `TestApprove_SelfApprovalRefusalSurvivesReload` | A restart cannot launder a refusal into a grant |
| … `TestApprove_IdempotentReapproveOfActiveGrantIsUnaffected` | Scope: the gate guards the transition, not idempotency |
| `mcp_approval_principal_test.go` · `TestMCPApprovalPrincipal_IsIdentityNotClientAddress` | The SEC-4E-1 core: one human, two addresses, one principal — while `auditActor` still differs |
| … `TestMCPApprovalPrincipal_DistinctHumansStayDistinct` | Two humans, one address, two principals |
| … `TestMCPApprovalPrincipal_NoIdentityFallsBackToAuditActor` | The documented bootstrap fallback |
| … `TestMCPApprovalPrincipal_UnverifiedBasicHeaderIsNotAnIdentity` | Authn: an unverified Basic header never becomes a principal |
| … `TestToolTrust_HTTP_SelfApprovalRefusedAcrossAddresses` | Authz, end to end over the real handlers: 403 from both addresses, no promotion, then a second human succeeds and the tool becomes `Usable` |
| … `TestToolTrust_HTTP_SelfApprovalStillAuditsNetworkLocation` | Attribution is not a casualty of the fix |
| `shadow_exit_gap_test.go` · `TestShadowExitC12_OperatorRunbookEndToEnd` | The operator runbook now runs as two named humans and asserts the self-approval refusal on the live surface |

**Mutation-verified.** With the `samePrincipal` refusal removed from
`tooltrust.Store.Approve`, all seven behavioural gates fail (five in the package, two at
the root, including the C12 runbook). Restoring it makes them pass.
