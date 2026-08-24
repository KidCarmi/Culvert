# MCP Agent Security Gateway — full backend security review

**Date:** 2026-08-24
**Baseline HEAD:** `9b1ba8645da80a1cb0a0da5e8fb3f8372e9050bb`
**Scope:** the entire MCP backend and control plane. Frontend explicitly excluded;
no frontend file was read or modified.
**Method:** six independent passes — architecture/trust-boundary, adversarial
security/state-machine, reliability/concurrency/failure-recovery,
protocol/interoperability, test-quality/anti-vacuity, and a final regression
review of this review's own diff.
**Posture constraint honoured throughout:** execution stays DISABLED. No mode was
advanced, `markGatewayExecDepsReady` was not called from production, and no real
upstream side effect was performed.

---

## 1. Executive summary

`internal/mcp` is ~37k lines across 25 subpackages plus ~14k lines of root wiring.
The engineering quality is high and unusually self-aware: fail-closed defaults are
pervasive, capability isolation is structural rather than conventional, and the
comments frequently name the defect a control exists to prevent.

The defects found are concentrated in one recurring shape, and it is worth naming
because it predicts where the next ones will be:

> **A control that is designed, documented, validated and tested in isolation, but
> never actually invoked by the request path.**

Six of the fifteen findings are instances of it — `RequestDeadline` bounding only
admission, `AuthConcurrency`/`DPoPConcurrency`/`MaxObservations`/`AdmissionBudget`
validated and never read, `protocol.Adapter` declared and never called,
`ReasonRequestDeadlineExceeded` mapped into the rollout hard-failure table and
never produced. In each case the package-level tests pass, the design document is
accurate, and the control does nothing. This is the failure mode the repository's
own anti-drift walls (`uiRoutes` C1 parity, `config_surfaces_test.go`) were built
to catch elsewhere in Culvert; MCP has no equivalent wall.

**One finding is reachable today on a shipped, valid configuration and defeats an
operator security control** (MCP-01, assurance escalation via an unverified `DPoP:`
header). It is fixed.

**Execution readiness verdict: READY FOR SEPARATE SHADOW ACTIVATION REVIEW.**
The reachable-today defects are fixed and the dormant execution plane's
prerequisites (context propagation, commit-before-side-effect on both paths,
truthful identity evidence, no transport leak) are materially better than at
baseline. That verdict is about the *code*, not about the deployment: activation
still requires everything §7 lists.

## 2. What is actually shipped — reachability matrix

Established from production composition (`main.go` → `initMCPRuntime` →
`loadMCPObserveRuntime` → `assembleGatewayConfig`), not from package existence.

| Surface | Composed in production? | Evidence |
|---|---|---|
| Gateway listener | YES, only when `mcp.gateway.enabled` and every prerequisite validates | `assembleGatewayConfig` sets `Gateway.Enabled: true` |
| Management listener | **NO — never** | No `Management: ListenerConfig` literal exists outside tests |
| `Deps.Policy` | YES, when a qualification policy file compiles | `composeGatewayPolicy` |
| `Deps.Events` | YES, when telemetry composes | `mcp_telemetry.go` |
| `Deps.Registry` / `Deps.Catalog` | YES (empty without a qualification inventory) | `mcp_inventory.go` |
| `Deps.Replay` | YES, only when the sender profile requires DPoP | `assembleGatewayConfig` |
| `Deps.Inspection` | **NO — never assigned** | grep: no production assignment |
| `Deps.Executor` | **NO — never assigned** | grep: no production assignment |
| `Deps.Introspector` | **NO — never assigned** ⇒ opaque tokens are structurally unusable | grep: no production assignment |
| `internal/mcp/execution` | **DORMANT — zero importers anywhere in the tree** | `grep -rl 'internal/mcp/execution"'` returns nothing |
| `markGatewayExecDepsReady` | **Called only from `mcp_rollout_durable_test.go`** | grep |
| Rollout modes reachable | Disabled / Observe only. Shadow, Canary and Production fail closed at the execution-dependency gate | `mcp_rollout_execdeps.go` + PR-12 transaction |
| Guarded execution | Not composed; `execution_state` is always `not_implemented` | `dispatchExecute` unreachable |
| Credential materialization | Not reachable (no executor) | — |
| Upstream client | Not reachable from the request path (no executor) | — |
| CP→DP distribution | Composed only when `CULVERT_MCP_DISTRIBUTION_TRUST_KEYS` holds a valid public trust store; unset/invalid ⇒ disabled | `mcp_distribution_startup.go` |
| Admin API | Fully live, all 24 routes | `registerMCPRoutes` |
| MCP on `/readyz` / `/healthz` / operator contract | **Absent** — MCP health exists only under `/api/mcp/*` | see MCP-14 |

**Restart-surviving state:** the encrypted event spool, the rollout durable state
(`<dataDir>/mcp_distribution/`), and the CP→DP active snapshot. **Node-local:** the
qualification policy snapshot, the inventory, and all runtime counters.

**Requested-but-invalid enablement** was checked specifically (hypothesis H10) and
is handled correctly: `mcpObserveRuntimeHealth` reports `state:"invalid"` with a
bounded reason and `listener_ready:false`, and
`invalidateMCPActivationOnStartupFailure` clears the published policy, inventory
and telemetry holders. **H10 is REFUTED.**

## 3. Finding ledger

| ID | Severity | Confirmed? | Reachable today? | Fixed? | Test evidence | Residual risk |
|---|---|---|---|---|---|---|
| MCP-01 | **P0** | CONFIRMED | **YES** | YES | `authn/assurance_test.go` (2 defect tests fail pre-fix) | A future caller with real out-of-band human assurance evidence must extend `assuranceCeiling`, not bypass it |
| MCP-02 | P1 | CONFIRMED | YES | YES | `runtime/context_test.go` + structural anti-weakening | Stages that take no ctx (durable commit, JWT verify) are bounded at stage boundaries, not preemptively |
| MCP-03 | P1 | CONFIRMED | No (dormant) | YES | `TestContext_ExecutorInheritsRequestCancellation` | None |
| MCP-04 | P1 | CONFIRMED | YES | YES | `runtime/header_ambiguity_test.go` | `Mcp-Method`/`Mcp-Name` must join the set if V2 lands |
| MCP-05a | P1 | CONFIRMED | YES | YES (`AuthConcurrency`, `DPoPConcurrency`) | `runtime/limits_enforcement_test.go` | — |
| MCP-05b | **P1** | CONFIRMED | YES | **NO — BLOCKER, see §4** | — | One source can still monopolize a capability's whole worker pool + queue, pre-auth |
| MCP-05c | P3 | CONFIRMED | YES | NO (documented) | — | `MaxObservations`, `CleanupPerOp`, `HandshakeTimeout`, `MaxOutstanding`, `MaxResponseBytes` are unenforced at the runtime layer |
| MCP-06 | P2 | CONFIRMED | YES | PARTIAL | `TestSecurity_CredentiallessRequestIsRejectedBeforeServerResolution` | A caller presenting a *syntactically valid* junk token still distinguishes known vs unknown server ids |
| MCP-07 | P2 | CONFIRMED | YES (latent) | YES | `mcp_policy_provider_test.go` | — |
| MCP-08 | P1 | CONFIRMED | No (dormant) | YES | `execution/evidence_test.go` (3 mutation-verified) | — |
| MCP-09 | P1 | CONFIRMED | No (dormant) | YES | `TestEvidence_CredentialPathCommitsTheDecisionBeforeAnySideEffect` | — |
| MCP-10 | P1 | CONFIRMED (reproduced) | No (dormant) | YES | `upstreamclient/leak_test.go` | `MaxConnsPerServer`/`MaxIdleConnsPerHost` remain effectively per-call, not per-server |
| MCP-11 | P2 | CONFIRMED | YES (doc) | YES (record corrected) | — | Culvert is pinned to a superseded protocol generation; migration is scheduled, not done |
| MCP-12 | P2 | CONFIRMED | YES | YES | `runtime/version_adapter_test.go` | — |
| MCP-13 | P2 | CONFIRMED | No (dormant) | YES | `TestTransport_RedirectOffTheApprovedHostIsRefused` | — |
| MCP-14 | P2 | CONFIRMED | YES | NO (documented) | — | MCP has no `/readyz` row, no operator-contract row, no `culvert_mcp_*` Prometheus series |
| MCP-15 | P2 | CONFIRMED | No (dormant) | YES | `broker/principal_test.go` | — |

**Refuted hypotheses:** H10 (activation truth — the status plane is honest);
admin-API RBAC completeness (every one of the 24 MCP routes has an explicit
`requireRole`, and every mutation is operator-or-admin); cross-server session
confusion (`computeFingerprint` includes the server id, so a session opened
against server A cannot be reused against server B — the immutable binding
rejects it).

## 4. Findings in detail

### MCP-01 — assurance escalation via an unverified request header (P0, FIXED)

**Files:** `internal/mcp/runtime/auth.go:buildAuthRequest`,
`internal/mcp/authn/authenticate.go:Authenticate`.

**Invariant violated:** effective assurance must be a property of what was
cryptographically verified on the request, never of what the caller asserted.

**Evidence.** `buildAuthRequest` computed
`assur = High if req.HasDPoP || req.PeerCertThumbprint != ""`, where `HasDPoP` is
`r.Header.Get("DPoP") != ""` — mere header presence. `Authenticate` then used
`subjectAssurance(req.Subject)` — the caller's assertion — for both the
`MinAssurance` floor check and `ResolveInput.Assurance`. Under a
`sender_constraint: bearer` profile the DPoP proof is **never verified at all**
(`verifySenderConstraint` returns `ConfirmNone` immediately).

**Reachability today: YES.** `sender_constraint: bearer` with
`min_assurance: high` is an accepted production configuration
(`mcpResolveSenderProfile` / `mcpResolveAssurance`).

**Exploit.** Holder of any valid bearer token that is otherwise denied by the
`min_assurance` floor adds `DPoP: x` and is admitted. Independently, any policy
rule keyed on `principal.assurance` or `session.assurance`
(`internal/mcp/policy/fields.go`, `compileAssuranceCond`) is satisfied at the
`high` floor for free. The forged level also reached the durable decision event
(`assuranceString(ctx.Assurance())`), so the archive recorded an assurance level
nothing had checked.

**Fix.** `effectiveAssurance` clamps the asserted level to `assuranceCeiling(sender)`
after `verifySenderConstraint`, and that value is used for the floor and the
resolved context. The clamp is scoped to **Human** subjects — the only free-form
caller assertion in this API. Workload assurance is already derived from evidence
`authn` checks (`Workload.Attestation`), so attested workloads keep High under any
profile; clamping them would have broken that contract without closing any seam.
The runtime no longer derives assurance from request shape at all.

**Residual risk.** A future caller with genuine out-of-band human assurance
evidence (a checked `amr`/`acr`, a verified step-up) must add it as a derivation
branch in `assuranceCeiling`, where it can be checked — never by re-admitting an
unchecked caller-supplied level. The doc comment says so.

### MCP-02 / MCP-03 — the request deadline bounded nothing expensive (P1, FIXED)

`Listener.ServeHTTP` built `context.WithTimeout(r.Context(), RequestDeadline)`,
passed it to `admit()`, and then called `l.pipe.Process(req, l.clock())` — no
context — while the deferred `cancel()` tore the deadline down. Everything that
actually costs something (JWT signature verification, opaque introspection, policy
evaluation, semantic inspection, durable event commits) ran unbounded. Separately,
`dispatchExecute` and `runInspection` used `context.Background()` explicitly.

`ReasonRequestDeadlineExceeded` already existed and was already mapped to
`HardAvailabilityBounds` in `rollout/hardfail.go` — and was never produced by any
code path.

**Fix.** `Process` takes the context and checks it at each stage boundary; the
executor and inspection receive it; the concurrency-slot wait selects on it. The
structural test `TestContext_NoDetachedContextInTheRequestPath` forbids
`context.Background()` anywhere in the runtime package except `Listener.bind`.

### MCP-04 — non-uniform anti-ambiguity on singleton security headers (P1, FIXED)

`Authorization` was rejected when duplicated ("ambiguous credential source"), but
`Origin`, `DPoP`, `Mcp-Session-Id` and `MCP-Protocol-Version` were read
first-value-wins. Each participates in a security decision (cross-origin,
sender-constraint, session resolution, version admission), and each is exactly the
shape where an intermediary and the gateway can resolve a conflict differently.

**Fix.** `extractRequest` rejects the request whole (400) when any guarded
singleton appears more than once, before any value is read. Duplication alone is
the trigger. `TestSecurity_GuardedSingletonSetIsComplete` prevents the set from
shrinking.

### MCP-05 — unenforced resource controls (P1/P3, PARTLY FIXED, one BLOCKER)

Eight of `runtime.Limits`' twenty-one knobs had **zero enforcement call sites** —
validated, ceiling-checked, exposed as accessors, never read:

| Knob | Status after this review |
|---|---|
| `AuthConcurrency` | **WIRED** — per-pipeline semaphore, ctx-bounded wait |
| `DPoPConcurrency` | **WIRED** — independent semaphore |
| `AdmissionBudget` | **STILL UNENFORCED — see below** |
| `MaxObservations` | Unenforced; in-flight records are bounded transitively by `MaxConcurrent` (the sink call is synchronous) |
| `CleanupPerOp` | Unenforced in `runtime`; the sweep is bounded by the live session set |
| `HandshakeTimeout` | Unenforced; `net/http` bounds the TLS handshake by `max(ReadHeaderTimeout, ReadTimeout)`, so the knob is redundant rather than a hole |
| `MaxOutstanding` | Unenforced at this layer; `limits.MaxOutstandingPerSession` is enforced in `session/ops.go` |
| `MaxResponseBytes` | Unenforced at this layer; responses are generated internally today |

#### MCP-05b — BLOCKER: no per-source admission

`AdmissionBudget` is documented as a "per-source admission budget (token bucket
size)". **There is no per-source admission of any kind.** `Listener.admit` takes a
queue slot then a worker slot with no notion of a source, and the runtime `Request`
carries no client address at all.

The consequence answers the review's own question — *can one client monopolize the
entire capability?* — with **yes**: a single source can hold all `MaxConcurrent`
(64) workers and all `QueueDepth` (256) queue slots, and does so **before
authentication**, since admission is step 1.

This is **not fixed**, deliberately. Implementing it requires an architectural
decision this review should not improvise:

- **Option A — per TCP peer (`r.RemoteAddr`, never `X-Forwarded-For`).** Correct
  for a directly-exposed listener. Wrong behind a load balancer or NAT, where all
  traffic shares one source and the budget throttles the whole fleet.
- **Option B — per authenticated principal.** Correct attribution, but admission
  happens before authentication by design (that ordering is what protects the
  expensive stages), so it cannot bound the pre-auth flood at all.
- **Option C — two-tier**: a coarse pre-auth per-peer budget plus a per-principal
  budget after authentication. Correct, and the most work.
- **Option D — remove the knob** and state plainly that per-source admission is
  not a control Culvert offers, relying on `MaxConns`/`MaxConcurrent` and an
  upstream rate limiter.

**Recommendation: Option C**, with the pre-auth tier keyed on the real TCP peer and
explicitly disabled when the listener is declared to be behind a trusted proxy
(mirroring `realClientIP`'s existing trusted-proxy contract on the SWG side). Until
then the knob is a **false control** and is recorded as such in the risk register.

### MCP-06 — pre-authentication server-existence oracle (P2, PARTLY FIXED)

Step 8 (registry resolution) ran before step 12 (authentication), so an
unauthenticated `POST /mcp/gateway/<id>` returned 404 for an unknown server id and
401 for a registered one — enumerating a tenant's registered MCP servers for free.
The same ordering let a credential-less request buffer up to `MaxBodyBytes`, run
the strict decoder, and open+close a session.

**Fix (partial).** The credential presence/shape check is hoisted ahead of registry
resolution and body buffering. A caller with no credential, a query credential, a
duplicated `Authorization` or a malformed scheme now gets a uniform 401 regardless
of whether the server exists, with no registry lookup, no body read and no session
churn — and with the same counter, denial-lane routing and reason the later stage
produced.

**Residual.** A caller presenting a *syntactically valid but invalid* token still
reaches registry resolution and therefore still distinguishes known from unknown
server ids. Fully closing it means authenticating before resolving the server,
which the resource-audience binding (`authReq.Server`) currently forbids. Recorded
as debt with a recommended direction: resolve the server id from the path for the
audience binding but defer the *registry existence* decision until after token
validation.

### MCP-07 — policy store pointer stability contract violated (P2, FIXED)

`mcp_policy.go` documents its Gateway `*policy.Store` pointer as stable for the
life of the holder, and the single-source-of-truth invariant (runtime evaluator,
`/api/mcp/policy`, simulator baseline, decision-evidence snapshot hash all agree)
rests on it. `invalidateForStartupFailure` and `resetForTest` both **replace**
`h.gw`, while `gatewayPolicyProvider` captured the pointer at compose time. A
captured pointer would keep evaluating the old store's snapshot while the admin
surface reported no active policy.

Production never reaches the divergence — the only replacement path runs when the
listener failed to start, and `Runtime.Start` is transactional — which is exactly
why it needed fixing: the invariant was true by coincidence. The provider now
reads the holder live.

### MCP-08 / MCP-09 — execution evidence and commit ordering (P1, FIXED)

Dormant path; reviewed as if it ships tomorrow, per the brief.

1. `execution/run.go:decisionFacts` hard-coded `PrincipalType: "workload"` while
   the runtime authenticates token subjects as **humans**. Every execution event
   would have misattributed a human actor, undetectably.
2. The same fact dropped client id, server id, tool name/fingerprint, matched
   rule, policy revision, operation class and snapshot hash.
3. `outcomeFacts` set `ActionClassRead` unconditionally, so the record of what a
   destructive call *did* contradicted its own decision event.
4. **Commit-before-side-effect held on only one branch.** The no-credential path
   used `CommitThenAct`; the credential-profile path — the ordinary enterprise
   shape — relied solely on the broker's `CREDENTIAL_SELECT` gate and never
   committed the decision event. A destructive `tools/call` with a credential
   profile would have reached the upstream server with **no critical decision
   event on record**.

All four are fixed; both paths now run through the same `CommitThenAct` with
materialization inside the callback. `TestEvidence_CommitFailureBlocksTheUpstreamCall`
proves the ordering against a spool backend whose durable append fails, on a
high-risk scope where the critical path is actually reachable.

> **Note discovered while building that fixture:** write and destructive
> operations do **not** execute in *any* rollout mode under a plain scope —
> `ScopeSpec.Operations` defaults to read-only and `HighRisk` must be set
> explicitly. That is a genuinely good fail-closed default and is now pinned by a
> test fixture that would notice if it changed.

### MCP-10 — one leaked `http.Transport` per upstream call (P1, FIXED)

`roundTrip` builds a fresh `http.Transport` per attempt. A Go `Transport` owns its
idle connections; this one sets no `IdleConnTimeout`, and nothing reclaims a
`Transport` that has gone out of scope while a connection's read/write loops still
reference it. **Reproduced:** six completed calls left six connections open on the
server. On a gateway making one upstream call per agent tool invocation that is an
unbounded file-descriptor and goroutine leak — and it silently made
`MaxConnsPerServer` meaningless, since no two calls ever shared a pool.

Fixed by releasing the transport's idle connections when the call completes.
`MaxConnsPerServer` remains effectively a per-call bound; recorded as debt.

### MCP-11 / MCP-12 — protocol baseline and the dead adapter seam (P2, FIXED/DOCUMENTED)

`protocol/version.go` described `2026-07-28` as "a non-final RC kept as comparison
material only". That was true of the 2026-05-21 release candidate; the
specification was **released as final on 2026-07-28**. Independently,
`protocol.Adapter`/`AdapterFor` — the documented boundary that keeps version out of
downstream code (MCP-PROTO-011) — was **never invoked by the request path**, so the
boundary a migration would land on did not exist.

The allowlist is **unchanged**: rejecting `2026-07-28` is now a dated, deliberate
decision. The adapter is now invoked from `processPost`, on the transport-declared
version, before any session logic; a present-but-unsupported revision is
deliberately not laundered to the primary. Full migration architecture:
`docs/design/mcp/PROTOCOL-MIGRATION-2026-07-28.md`.

The blocker recorded there: `2026-07-28` removes sessions entirely, and Culvert's
immutable session-identity binding, lifecycle admission, session cap and
per-session outstanding bound are all built on them. Converting
"one identity per session, immutable" into "one identity per request against a
caller-stable binding key" — including a replacement for the bounded cardinality
the session cap provides — is an **ADR-level decision and a hard prerequisite**.

### MCP-13 — redirects bounded by hop count only (P2, FIXED)

`CheckRedirect` checked only `len(via) > maxRedirects`. With `MaxRedirects` raised
above its safe default of 0, an upstream's own response data chose where a
credentialed request went next. The pinned dialer bounded the damage — but
"bounded two layers down" is not "refused". A redirect whose target host is not
the approved server is now refused outright; a same-host redirect within the
operator's budget is still followed.

### MCP-14 — MCP is absent from every process-level health surface (P2, NOT FIXED)

Every other Culvert subsystem with a failure mode has an operator-contract row, a
report-only `/readyz` row, a `/healthz` field, `culvert_*` metrics and a
`HasSubscriber`-gated alert (the pattern in `storage_health.go`, `ca_health.go`,
`socks5_health.go`, `cluster_ca_health.go`). MCP has **none of them**: its health
lives only under `/api/mcp/*`, behind admin authentication.

The `/api/mcp/*` surface is truthful (H10 refuted), so this is an operability gap,
not a correctness one — but it means a degraded or dead MCP listener is invisible
to the fleet monitoring that watches every other subsystem, and there is no
`culvert_mcp_*` series to alert on. Recorded as debt with the existing pattern as
the template; deliberately NOT implemented here, because deciding whether MCP
failure should influence `/readyz` (it should not — an MCP fault must never pull a
healthy SWG out of rotation) is an operator-contract decision.

### MCP-15 — credential events attributed a plan as a principal (P2, FIXED)

`events/gate.go` put the **plan id** in `Identity.PrincipalID` and asserted
`PrincipalType: "workload"` — a type nothing had determined — on the one event
class whose entire purpose is attributing a credential materialization. The plan
now carries the authenticated subject's id and type from the resolved identity
already passed to `Plan`, and the gate uses them plus the one-way token digest as
a session correlator.

## 5. Areas reviewed and found sound

Recorded so the next reviewer knows what was covered, not just what broke.

- **JSON-RPC decoding** (`internal/mcp/jsonrpc`) — strict, single-object only,
  top-level batch arrays rejected by name, bounded depth/members/string bytes,
  unpaired surrogate escapes rejected, `jsonrpc` member matched exactly.
- **Host/Origin validation** (`internal/mcp/hostcheck`) — mandatory non-empty host
  allowlist, `Decision` zero value is `Reject`, `null` origin rejected, origin
  normalization refuses userinfo/path/query/fragment, re-checked per request and
  per HTTP/2 stream.
- **Session identity binding** (`internal/mcp/identity`) — immutable, idempotent
  on an equal fingerprint, rejected on a different one, and the fingerprint
  includes the **server id**, so a session opened against server A cannot be
  reused against server B. Length-prefixed segments prevent field-boundary
  collisions.
- **Capability isolation** — structural at every layer: separate listeners,
  separate pipelines, separate session managers, separate binding stores, separate
  policy stores, separate event domains; the capability is signed into the CP→DP
  manifest **and** into the canonical hash, and verified as `ExpectCapability` on
  apply.
- **Denial lane** (`internal/mcp/events/denial`) — attacker-mintable by
  construction and therefore bounded by construction: O(1) coalescing, capped
  bucket cardinality, capped per-source, drops counted, never touches the critical
  track or the P-CRIT reserve.
- **Destination controls** (`internal/mcp/inspection/destination`) — canonicalize →
  resolve → pin → dial only pinned IPs → re-verify the peer at connect time,
  closing the DNS-rebinding window between validation and connect.
- **Admin API RBAC** — all 24 MCP routes carry an explicit `requireRole`; every
  mutation is operator-or-admin; `apiMCPManagementAccess` is GET-only and always
  reports `mutation_tools: 0`.
- **Rollout scope defaults** — `Operations` empty means read-only, and
  `HighRisk` must be set explicitly for write/destructive to enter a rollout at
  all.

## 6. Verification

| Gate | Result |
|---|---|
| `go build ./...` | **PASS** |
| `go vet ./...` | **PASS** |
| `go test ./internal/mcp/...` | **PASS** |
| `go test -race -count=1 ./internal/mcp/...` | **PASS** |
| `go test . -count=1` (root, incl. all MCP integration/e2e) | **PASS** |
| `go test -race` root package | see §6.1 |
| `golangci-lint` | **NOT AVAILABLE** in this environment |
| `govulncheck` | **NOT AVAILABLE** in this environment |
| `gitleaks` / `gosec` / `trivy` | **NOT AVAILABLE** in this environment |
| Culvert binary build | **PASS** |

No existing test was weakened, skipped, renamed or deleted. Two existing tests
were **updated, not relaxed**: `mcperr_test.go` pins the new reason code (its
exhaustiveness wall did its job), and `mcp_policy_test.go`'s seam assertion follows
the provider's field rename.

**Mutation verification.** Every new security guard was mutation-tested — the
guard was neutered, the test suite was confirmed to fail, and the guard restored:
the deadline check, the executor context, the ctx-bounded slot wait, the auth
semaphore, the credential pre-check, the transport release, the redirect host
check, the hard-coded principal type, the outcome action class, and the credential
commit ordering. The assurance and duplicate-header tests were additionally
verified failing against the unmodified baseline tree.

## 7. Execution readiness

**Verdict: READY FOR SEPARATE SHADOW ACTIVATION REVIEW** — for the code. The
following are *not* satisfied by this review and remain prerequisites for arming
anything beyond Observe:

1. **MCP-05b** — per-source admission is a false control; a single unauthenticated
   source can monopolize a capability. **Blocker for exposure**, not for Shadow on
   a controlled host.
2. **MCP-14** — no fleet-visible health signal for a degraded MCP listener.
3. Guarded execution has never run: `internal/mcp/execution` has zero importers,
   so its ~800 lines have only ever been exercised by their own package tests.
4. Credential containment, a stable host, real scope, parity evidence, monitoring,
   ownership and fresh identity — all as ADR-0024 and
   `docs/operator/mcp-rollout-durable-state.md` already require.
5. `Deps.Introspector` is never composed, so opaque tokens are structurally
   unusable; a deployment relying on them would fail every request.

**Do not read "tests are green" as production readiness.** The bar this review
applied is that each security promise is an executable invariant with a
mutation-verified test — not that the suite passes.

## 8. Governance

Registered rather than left in this document:

- Technical Risk Register: MCP-05b (per-source admission), MCP-14 (health
  invisibility), MCP-11 (protocol generation drift).
- Technical Debt Register: MCP-05c (unenforced limit knobs), MCP-06 residual
  (authenticated-caller oracle), MCP-10 residual (`MaxConnsPerServer` is per-call),
  and the missing MCP anti-drift wall (§1).
- Engineering Dashboard: MCP program row updated with this review as its evidence
  anchor. **No maturity score was raised** — the fixes remove defects; they do not
  by themselves demonstrate a higher maturity band.
