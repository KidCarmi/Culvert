# Security regression review — First Controlled Canary physical-effect window

**Date:** 2026-09-05
**Scope:** every change merged to `main` between `c20c17b` (PR #1291, *live production deps*)
and `290e376` (PR #1306, *canary physical-effect truth*) — 84 commits, 46 files,
+11 326 / −197.
**Branch:** `claude/epic-bardeen-xno6wu`
**Predecessor:** `2026-08-18-mcp-pr12-and-idp-registry-window.md`; PR #1296 reviewed the
previous window (live-execution trust + production deps).
**Method:** read every production diff hunk in the window; reproduce each candidate finding
against the pre-fix tree before writing a patch; mutation-verify every new guard by
reverting the fix and requiring the guard to fail.

---

## 1. Executive summary

The window is one coherent piece of work: the **physical-effect ledger** for the First
Controlled Canary. It answers, durably, "did Culvert cause exactly the tool invocations it
authorized, and does it know what happened to each one?" — a durable send intent before the
irreversible call, a conservative `PhysicalSendState` instead of a boolean `executed`, one
terminal outcome on all seven exit paths instead of one, attempt/reservation identity minted
from the CSPRNG, a retry-free production upstream client, a v3 event schema, and an
append-only witness-reconciliation contract with a fail-closed recovery derivation.

It is unusually well-defended work — 18 recorded rounds of adversarial review, a 702-line
mutation campaign, and defect gates that were each verified failing against their pre-fix
shape. **The overwhelming majority of this window strengthens security posture.** In
particular it removes two silent-fail-open shapes: a transport that could turn one accepted
reservation into three physical invocations with no emergency-kill re-read between them, and
an outcome record that converted "we do not know" into `executed=false`.

**One security regression was found and fixed: SEC-MCP-AUX-1.**

| ID | Severity | Reachable in a stock build? | State |
|---|---|---|---|
| SEC-MCP-AUX-1 | **Medium** (Canary-scoped) | No — the live tier has no production composition caller | **Fixed** in this PR, 3 execution-package walls + 5 composition-layer walls |
| SEC-MCP-AUX-2 | Informational | No | Recorded, not fixed — see §6 |

Nothing else in the window regressed. §5 records what was reviewed and why it is sound.

---

## 2. SEC-MCP-AUX-1 — auxiliary upstream traffic bypassed the live tier's arming and quiesce gate

**CWE-863 (Incorrect Authorization) · OWASP A01:2021 Broken Access Control · Medium.**

### What changed

Before this window, `runExecute` consulted the composition-layer gate
(`LiveExecutionGate.AdmitSideEffect`) for **every** method that reached the guarded
executor. The production gate runs four checks in order:

1. **lifecycle admission** — is the live tier armed, and has it begun quiescing?
2. **read-first** — may this operation class cross the boundary?
3. **live-trust revalidation** — does an active, unexpired `live_execution` approval bind
   this exact `(tenant, server, tool, fingerprint)` right now?
4. **budget reservation** — is there a Canary blast-radius slot?

That was wrong for MCP **lifecycle** (`initialize`, `notifications/initialized`, `ping`,
`notifications/cancelled`) and **discovery** (`tools/list`) traffic, in both directions, and
the window correctly identified it: checks (2)–(4) ask about a tool that auxiliary traffic
does not have, so the production gate refused every one of them (an armed Canary node could
not complete a session handshake or list tools), and a gate that admitted instead would have
spent a Canary execution reservation on a call that can cause no side effect — making
`MaxTotalExecutions` stop measuring physical invocations, the exact accounting property the
ledger exists to establish.

The fix (`internal/mcp/execution/run.go`, `admitSideEffect`) skipped the gate **entirely** for
those five methods:

```go
if !upstreamclient.ClassifyMethod(in.Method).SideEffectBearing() {
    return sideEffectAdmission{}, nil
}
```

That discards check (1) along with (2)–(4), and check (1) is not about tools. It is the
operator's **arming and wind-down control**.

### Attack scenario

1. An operator disarms the live tier — either explicitly (`unarmForDemote`, which sets
   `admitClosed`), by beginning a graceful quiesce (`enterQuiesceLocked`), or implicitly by
   restarting the process: `disarmForRestart` deliberately leaves a re-composed tier
   **composed but never automatically re-armed**, which the live-tier header names as the
   fail-closed restart posture (§17).
2. The persisted rollout mode is still Canary, so the pipeline still resolves
   `EffectExecute` and still reaches the guarded executor. Arming is enforced **only** by the
   gate — there is no second check.
3. Any MCP client the gateway already admits sends `initialize`, then `tools/list`.
   `ClassifyMethod` exempts both, so no admission runs.
4. Both reach the real third-party upstream: a session is opened and the peer's tool catalog
   is read. If the matching policy decision carries a `CredentialProfile` obligation, the
   broker materializes a real credential and it is sent as `Authorization` on that request —
   with **no** live-trust revalidation and on a tier the operator has disarmed.
5. `Revalidate` is `nil` for these calls, so the final-boundary activation-generation
   re-check that catches a demotion landing mid-flight is also skipped.

The client controls the method string, so the client chooses which admission (if any) its
request takes.

### Preconditions, exploitability, likelihood, impact

- **Preconditions:** the live execution tier is *composed* (an executor installed) while
  *unarmed or quiescing*, and the rollout mode still resolves `EffectExecute`. The requester
  needs only ordinary admitted MCP-gateway access — no special privilege.
- **Exploitability:** trivial once the precondition holds. Sending `tools/list` is normal
  client behaviour, not an exploit primitive.
- **Likelihood:** the precondition is a **restart**, which is the most ordinary event in the
  list. Quiesce and demote reach it too.
- **Impact:** loss of the operator's disarm/wind-down control for every method except
  `tools/call`. Concretely: outbound session establishment to a third-party endpoint,
  disclosure of the peer's tool catalog, egress of a materialized credential, and a
  connection that a graceful wind-down was meant to have stopped opening. It is **not** a
  tool-execution breach — no side-effect-bearing invocation is admitted this way, and the
  emergency kill (`preCallGuard`'s `KillGeneration` re-read) still stops all of it.
- **Affected assets:** the live-execution arming control, the Canary quiesce drain, upstream
  MCP server metadata, and brokered upstream credentials.

### Regression risk and reachability

This is a **regression introduced inside this window** — the pre-window tree refused
auxiliary traffic on an unarmed tier (over-broadly, for the wrong reason, but it refused).

It is **not reachable in a stock build today**: `mcp_live_startup.go` records that there is
deliberately **no production caller** of `composeGatewayLiveTierInto`, so a shipped binary
composes no live executor and the tier is absent. Reachability begins the moment the First
Controlled Canary is actually composed — which is what this window is preparing. That is why
it is fixed now rather than recorded: the deployment it affects is the next one.

### Fix

`AdmitAuxiliary` is added to `execution.LiveExecutionGate` as a **required** method, and
auxiliary traffic takes it instead of being exempted from admission. The production
implementation runs check (1) and nothing else:

- no budget reservation — the accounting property the window established is preserved;
- no read-first and no live-trust revalidation — the over-blocking the window fixed stays
  fixed;
- `Revalidate` re-asks the lifecycle question **read-only** at the final boundary, via a new
  `mcpLiveTier.admissionOpen()` that mirrors `admitExecution`'s condition without taking a
  second in-flight slot (re-running `admitExecution` there would take a slot nothing
  releases, and a quiesce drain waits on that count forever);
- `Release` returns the lifecycle in-flight count exactly once, so a drain always completes;
- **no** `ReservationID` and **no** `ActivationGeneration` are returned — an auxiliary
  invocation has no attempt, so naming a slot it never consumed could only misattribute a
  physical effect.

A refusal reaches the same fail-closed classification path as a side-effect refusal, so the
client sees the gate's bounded reason (`rollout_mode_invalid`) rather than a transport or
durability fault.

The method is on the **required** interface, not an optional one, deliberately: a gate that
does not answer this question must not be able to answer it by omission, because omission is
the permissive direction. There is exactly one production implementation.

### Safe-implementation notes

- The classifier is unchanged and still fail-closed: `ClassUnknown` is side-effect-bearing,
  so an unrecognised or case-mangled method (`"TOOLS/CALL"`, `"tools/call "`) is metered
  like a tool call, never diverted to the cheaper admission.
- `openAttempt` still returns `(nil, nil)` for auxiliary traffic on the same classifier, so
  no attempt identity is minted and the physical-effect count is unchanged.
- The emergency-kill re-read remains the **last** authoritative check before
  `Upstream.Call` (PREREQ-MCP-KILL-1); nothing was inserted between it and the call.

### Required tests (all present)

`internal/mcp/execution/auxiliary_admission_test.go`

| Test | Kind |
|---|---|
| `TestAuxiliaryTraffic_RefusedLifecycleNeverReachesTheUpstream` | negative — refused lifecycle, all five methods, upstream calls == 0, `Executed` false, bounded reason |
| `TestAuxiliaryTraffic_LifecycleRevalidationRefusesAtTheBoundary` | boundary/TOCTOU — admission closes *after* admit; the call must still refuse and the slot must still be released |
| `TestAuxiliaryTraffic_NeverReachesTheSideEffectGate` | positive + accounting — exactly one *auxiliary* admission, zero *side-effect* admissions |
| `TestAuxiliaryTraffic_SurvivesARefusingGate` | positive — a side-effect refusal must not block auxiliary traffic (the over-blocking regression stays fixed) |
| `TestToolCallStillReachesTheSideEffectGate` | control — a passing suite cannot mean the gate stopped being consulted |
| `TestUnclassifiedMethodIsStillMetered` | malformed input — an invented method is metered, not exempted |

`mcp_live_gate_auxiliary_test.go` (composition layer, real gate)

| Test | Kind |
|---|---|
| `TestAdmitAuxiliary_RefusesADisarmedOrQuiescingTier` | negative + no-leak |
| `TestAdmitAuxiliary_AdmitsAnArmedTierWithoutSpendingABudgetSlot` | positive + proves trust/read-first/reserve seams are **not** consulted (counted, not inferred) |
| `TestAdmitAuxiliary_RevalidatesTheLifecycleAtTheBoundary` | boundary |
| `TestAdmitAuxiliary_RevalidationIsReadOnly` | control — revalidation must take no in-flight slot, or a quiesce drain hangs |
| `TestAdmissionOpen_MatchesAdmitExecution` | equivalence across all five tier states, including `admitClosed` |

**Mutation-verified.** Restoring the pre-fix line (`return sideEffectAdmission{}, nil`) makes
all three new execution-package gates fail:

```
initialize reached the upstream 1 time(s) on a disarmed/quiescing tier
tools/list took 0 auxiliary admission(s); it must take exactly one (SEC-MCP-AUX-1)
auxiliary call reached the upstream 1 time(s) after admission closed mid-flight
```

### Files

- `internal/mcp/execution/livegate.go` — `AdmitAuxiliary` on the interface
- `internal/mcp/execution/run.go` — `admitAuxiliary`; `admitSideEffect` dispatches
- `mcp_live_gate.go` — production `AdmitAuxiliary`, `admitOpen` seam
- `mcp_live_tier.go` — `admissionOpen()`
- tests as listed above; three existing gate doubles updated to the widened interface

### Residual risk

An auxiliary invocation still materializes a credential **before** the gate runs (the
gate is invoked inside the broker's materialization callback). The credential never reaches
the wire on a refusal, and this ordering is pre-existing and identical for `tools/call`, so
it is unchanged by this fix and is not a new exposure. It is recorded here because the
credential does exist in process memory on a refused auxiliary call.

---

## 3. SEC-MCP-AUX-2 — a witness that names no binding dimension corroborates everything

**Informational. Not fixed; recorded.**

`reconcile.go`'s `bindingCorroborated` requires every dimension the witness **names** to
match a known local value, and `corroborates("", x)` is true. A witness that reports a
complete, zero-count view while naming *no* `ServerID`, `Method` or `ReservationID`
therefore corroborates every dimension vacuously, and a zero-count complete view resolves an
orphan to `reconciled_not_received` — definitive absence — on the strength of a lookup keyed
by `AttemptID` alone.

That is defensible (the lookup *is* keyed by the attempt) and it is not reachable: `Witness`
has no production implementation and `ReconcileOrphan` treats `w == nil` as the shipped
posture. It is recorded so that the witness integration (review blocker #1/#8) decides
explicitly whether a witness may omit its scope, rather than inheriting the answer.

---

## 4. Regression analysis of the window's own security-relevant changes

Each of these **strengthens** posture. They are listed because a reviewer of the next window
needs to know they are load-bearing.

- **Retry-free production upstream client** (`mcp_live_production_deps.go`,
  `upstreamclient/limits.go`). The default limits allowed 2 retries of an idempotent read,
  and a peer that reads the whole request then drops the connection produces exactly the
  `(idempotent, pre-response)` shape that authorizes a re-send — turning one accepted
  reservation into up to three physical invocations, with **no emergency-kill re-read
  between them**. `RetryDisabled` is checked *before* `retryable()`, so no peer- or
  attacker-influenced classification can reach a second attempt. `RetryFreeLimits` also
  **forces** `MaxRedirects = 0`, because a same-origin 307/308 makes `net/http` replay the
  POST body carrying the *same* `AttemptID` — a second physical invocation the retry loop
  never sees and no witness could tell apart. Verified: `fillLimitDefaults` no longer fills
  the retry budget under `RetryDisabled`, and an unknown `RetryMode` fails closed.
- **Uncertainty is no longer laundered into `executed=false`.** `PhysicalSendState` is a
  five-state lattice; `Outcome.Executed` is derived from `state.MayHaveReachedPeer()`, not
  from `out.Executed`, so an ambiguous transport failure and a DLP block after the peer
  answered both record that the tool **has** run. `definitely_not_sent` is reachable only
  from positive evidence (a boundary refusal, or a leg that provably never called
  `client.Do`), and both evidence facts are **absent by default** in the safe direction —
  an unwrapped error or a test double keeps the conservative state.
- **`foldLegFacts` aggregates across a retry correctly**: `responseObserved` is a
  disjunction (any leg that saw an answer proves receipt), `neverSent` a conjunction
  (unanimity). Carrying the last leg's facts would manufacture `definitely_not_sent` for an
  invocation an earlier leg may already have delivered.
- **One terminal outcome on all seven exit paths** (a single deferred commit) replaces a
  commit on the success path only. Loss is counted (`ObserveOutcomeEvidenceLoss`), not
  silent.
- **v3 schema stamping is derived from the assembled event**, not from the facts, so a
  record can never carry v3 fields under a v1 stamp — the shape that reads back on an older
  build as *spool corruption* rather than *unsupported schema*. `CanonicalBytes` is a
  whole-struct `json.Marshal`, so the new evidence is inside the intrinsic digest with no
  gap. `peekSchemaVersion` reads the version leniently from **already-AEAD-authenticated**
  plaintext, and an unsupported version still aborts recovery — the classification changes,
  the fail-closed behaviour does not.
- **`validateVerdictAgainstFacts`** makes the durable boundary refuse a verdict its own facts
  contradict, and `effectiveReconResult` mirrors every one of those rules on the read path —
  necessary because the spool's read path does not run the full `Validate`, so a record from
  an importer or an older binary would otherwise be read back and trusted. The fold moves in
  one direction per rule: duplicates are **upgraded** to a conflict at any completeness,
  unsupported resolved verdicts are **downgraded** to `reconciliation_required`.
- **Recovery fails closed on ambiguity** rather than picking a newest record, and both
  unmatched-record sweeps carry a stated retention precondition that must be closed before
  `RecoverAttempts` is wired into production.
- **Identifiers are CSPRNG-minted, never derived from request content** (`att_`/`rsv_`, 128
  bits each), so a caller cannot force two physical attempts to share one identity and
  collapse them in the witness. `newAttemptID` and `newCanaryReservationID` both fail closed.
- **`AttemptHeader`** is Culvert-minted and set on a request built from scratch; no client
  header is copied onto the upstream request, so it cannot be spoofed or used for header
  injection (hex charset).

## 5. Reviewed and found sound (no change made)

- Method admission (`admittedMethods`) is still enforced at `Client.Call`; the exempt set of
  the new classifier is exactly `admittedMethods` minus `tools/call`, with `ClassUnknown`
  fail-closed.
- `preCallGuard` ordering is unchanged: kill re-read **last**, `nil` `Revalidate` tolerated,
  tool-drift still evaluated for every method.
- `executePreconditionFailure` preserves all three prior fail-closed preconditions
  (nil `Events`, absent/unusable server, credential obligation with no broker) and moves them
  **before** any attempt accounting is armed.
- `classifyBoundaryRefusal` still maps kill ▸ drift ▸ gate, on both the credential and
  no-credential branches, so a refusal can never read as `none` or as a transport fault.
- `commitThenCall` keeps SEC-MCP-09: the decision commits durably before anything with a
  side effect, on **both** paths, through the same primitive.
- The `mcpLiveSideEffectGate` reservation-ID mint failure path releases both the budget slot
  and the lifecycle in-flight count before denying — no slot leak.
- The v3 additions do not change any pre-existing event's digest
  (`CarriesAttemptEvidence` deliberately excludes every v1 `OutcomeEvidence` field).
- `scripts/mcp-canary-mutation-campaign.sh` refuses to run against a dirty tree, uses no
  `eval`, no network fetch and no privileged operation; it reverts with `git checkout` on
  tracked files only.

## 6. Verification

```
go build ./...                       clean
go vet ./...                         clean
go test ./internal/mcp/...           pass
go test .   (MCP/Canary/Shadow/Live) pass — 165s
go test ./... -count=1               pass
```

Mutation verification for SEC-MCP-AUX-1 is recorded in §2.

## 7. Verdict

The window is sound apart from SEC-MCP-AUX-1, which is fixed here with eight regression
walls, three of them mutation-verified against the reintroduced defect. **This document does
not authorise arming the live execution tier**, and nothing in this PR composes, arms or
enables it.
