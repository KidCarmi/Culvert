# Security regression review — MCP live-execution trust, live-tier composition, and production dependency wiring

**Date:** 2026-09-02
**Reviewer role:** Security Regression Engineer (AppSec / secure code review / product security)
**Scope:** the three most recent merges into `main` —
`1285486` (PR #1289, *mcp-live-execution-trust*),
`32eac4e` (PR #1290, *mcp-live-tier-composition*),
`c20c17b` (PR #1291, *mcp-live-production-deps*).
**Diff reviewed:** 2,576 added / 121 removed lines of non-test production code across 30 files
(`git diff 1285486^1 c20c17b -- . ':(exclude)*_test.go' ':(exclude)docs/*' ':(exclude)roadmap/*'`).

---

## 1. Executive summary

**No security regressions were found**, and **one new MEDIUM finding (F-1) was**, on a code path
that is unreachable in a shipped build. This window moves the MCP Agent Security Gateway from
"live execution is structurally impossible" to "live execution is *composable* and its trust
model is *issuable*", which is the single largest posture change in the MCP program to date —
and it is the change class most likely to weaken a fail-closed boundary by accident. Every
gate I could find is still closed, and several are closed by more than one independent
mechanism.

F-1 (§3.0, §7.1) is the one exception to "everything is closed": the *new* credential-KEK
acquisition path accepts a key file from a directory it never validates, so a pre-created
`0600` 32-byte file is adopted verbatim as the key-encryption key. It is not a regression —
there was no MCP credential KEK before this window — and it cannot be reached today, but it is
a hard blocker on the deferred arming deployment, which is what would first seal credential
material under that key. *(This finding was raised by the Codex review bot on PR #1296 against
an earlier draft of this report that rated it "low" on an assumption the code does not enforce;
the analysis was re-done from the source and corrected. The audit trail is preserved in §7.1.)*

The three posture-relevant changes and the state they leave the shipped build in:

| Change | Before | After | Shipped-default reachability |
|---|---|---|---|
| `tooltrust.Purpose.Issuable()` widened to admit `live_execution` | live approvals unissuable | issuable only through `RequestLiveApproval` + `ApproveLive` under mandatory ≤24h expiry, four-eyes on canonical authenticated principals, exact-current-state revalidation | An operator can now *issue* a live grant. Issuing one arms nothing. |
| `productionCanaryActivationInputs` returns real per-tool live approvals | fail-closed empties | real `ToolApprovals`; `Budget` / `ServerUsable` / `FingerprintCurrent` still fail-closed zeros | Canary preflight still cannot be satisfied. |
| `composeProductionGatewayLiveTier` composes the real upstream/broker/events/DLP graph | no production caller of `composeGatewayLiveTierInto` | one production caller, behind `CULVERT_MCP_LIVE_DEPS` (default off) | Composed ≠ armed. `armLiveTier` has **no** production caller (verified by grep; pinned by `TestExecPosture_LiveArmingHooksHaveNoProductionCaller`). |

**Net effect on a stock build: byte-identical.** With `CULVERT_MCP_LIVE_DEPS` unset the
resolver returns `{Requested:false}`, the builder composes nothing, and the Observe/Shadow
executor path is untouched.

**Net effect on an opted-in build:** the live executor is installed as `Deps.Executor` but the
live tier is `composed`, never `armed`. `runExecute` is only reachable from
`rollout.EffectExecute`, which requires Canary/Production mode, which requires `modeExecReady`,
which reads the armed bit. Four independent layers stop it:

1. `modeExecReady` — the armed bit is false, so no live-mode transition commits.
2. `restore()` — a hand-crafted durable state file naming Canary is clamped to `Disabled`,
   twice (exec-deps tier, then the full activation preflight).
3. `evaluateCanaryActivationPreflight` — `Budget`, `ServerUsable`, `FingerprintCurrent` are
   fail-closed zeros and `LiveExecutorComposed` derives from the *armed* bit, not the composed
   state.
4. `mcpLiveSideEffectGate.AdmitSideEffect` step (1) — `admitExecution` requires
   `state == liveTierArmed`, so even a request that somehow reached `EffectExecute` is refused
   before the budget or trust work runs.

Two documentation-accuracy defects and three residual risks are recorded in §6/§7. Two
regression tests were added (§5) to wall invariants that were verified by reading but were not
pinned by any existing test.

---

## 2. What was reviewed, and how

Every non-test file in the window was read in full or in diff, and the reachability of each new
authority was traced to its callers:

- **Trust issuance / RBAC:** `ui_mcp_tooltrust.go`, `mcp_tooltrust.go`,
  `internal/mcp/tooltrust/{store.go,tooltrust.go}`
- **Side-effect boundary:** `internal/mcp/execution/{run.go,executor.go,livegate.go,shadow_evaluator.go}`,
  `mcp_live_gate.go`
- **Lifecycle / arming:** `mcp_live_tier.go`, `mcp_live_arming.go`, `mcp_live_startup.go`,
  `mcp_rollout_execdeps.go`
- **Production dependency composition:** `mcp_live_production_deps.go`,
  `mcp_live_production_deps_config.go`, `mcp_observe_startup.go`, `mcp_runtime.go`
- **Rollout commit / restore / runtime generation:** `mcp_rollout.go`, `mcp_canary_runtime.go`,
  `mcp_canary_preflight.go`
- **Supporting:** `internal/mcp/canary/{trust.go,approval.go,scope.go}`,
  `internal/mcp/mcperr/mcperr.go`, `internal/mcp/events/model/validate.go`,
  `internal/mcp/inspection/profile.go`, `mcp_live_quiesce_rehearsal.go`, `internal/secret/provider.go`

Verification performed: `go build ./...` (clean), `go test ./internal/mcp/...` (green),
`gofmt`/`go vet` on touched packages, plus two deliberate defect-reintroduction runs to prove
the new tests are non-vacuous (§5).

---

## 3. Security findings

### 3.0 Summary of findings

| ID | Finding | Severity | Reachable in a shipped build? |
|---|---|---|---|
| **F-1** | Credential KEK adopted from an unvalidated parent directory — attacker-chosen key material | **Medium** | **No** (requires `CULVERT_MCP_LIVE_DEPS`; nothing arms; broker composes zero providers) |
| D-1 | `canary/trust.go` doc claims `live_execution` is unissuable — no longer true | Informational | n/a |
| D-2 | `mcp_live_startup.go` doc claims no production caller of `composeGatewayLiveTierInto` — no longer true | Informational | n/a |

F-1 is **not a regression** — it is a *new* weakness on a *new*, currently unreachable code path
(there was no MCP credential KEK before this window). It is recorded here rather than fixed
because the remedy is a production security-behavior change whose policy choice belongs to an
owner; §7.1 carries the analysis, the patch, and the required tests.

### 3.1 No exploitable regression identified

The checklist below records each attack class I actively probed for in this diff and the
mechanism that closes it. "Verified" means I read the enforcing code and its callers, not that I
took a comment at its word.

| Attack class | Probe | Result |
|---|---|---|
| **Authorization bypass — live trust as shadow trust** | Does an active `live_execution` grant reach the `catalog.Usable` promotion? | **No.** `ActiveApprovals` filters on `activeAsOf` → `Purpose.PermitsShadowEvaluation()`, which is `p == PurposeShadowEvaluation`. Widening `Issuable()` did not widen `PermitsShadowEvaluation`. **Newly walled** — see §5.1. |
| **Authorization bypass — shadow trust as live trust** | Does a `shadow_evaluation` grant satisfy the live gate? | **No.** `activeLiveAsOf` → `PermitsLiveExecution()`; `canary.SatisfiesLiveExecution` re-rejects a non-live purpose at consumption. Two independent checks. |
| **Broken four-eyes / self-approval** | Can one principal both request and approve a live grant? | **No.** `RequestedBy` is forced to `mcpLivePrincipal(r)` (the session `Sub`, never a body field); `ApproveLive` supplies the approver from the same source; `validateLiveApproveLocked` refuses `approver == RequestedBy` or an empty requester; `SatisfiesLiveExecution` re-checks at consumption; `validateLiveInvariantsStored` refuses an *active* live record at rest without four-eyes evidence. Four layers. |
| **Privilege confusion — anonymous live trust** | Can an IP-only / unauthenticated actor be attributed a live grant? | **No.** `mcpLivePrincipal` fails closed (`ReasonApprovalNotAuthorized`) on a missing cookie or empty `Sub`. The shadow path keeps `auditActor`; the live path deliberately does not, because four-eyes over bare IP strings is not separation of duties. |
| **Route confusion** | Can a live grant be decided through the shadow route (gaining catalog promotion), or vice versa? | **No.** Routing is on the *stored* `Purpose`, never a request field; `ApproveShadow` refuses a non-shadow record and `ApproveLive` refuses a non-live one. Symmetric guards. |
| **Replay / stale authority** | Can an expired or revoked live grant still authorize a side effect? | **No.** Expiry is evaluated at the *boundary* clock (`liveGateInput` reads `e.cfg.Clock()`, not the request-entry `in.Now`), the TTL ceiling is measured from `ApprovedAt`, a future `ApprovedAt` is rejected, and revocation drops the grant from `ActiveLiveApprovals` immediately. **Newly walled** — see §5.1. |
| **TOCTOU — tool rug-pull between decision and call** | Can an approval for fingerprint F2 authorize a request decided under F1? | **No.** `mcpLiveTrustRevalidate` binds to the *decision's* fingerprint (`decisionFP`), requires the current target to still equal it, and requires `ServerUsable` now. |
| **TOCTOU — emergency kill vs. the new gate** | Does inserting the gate displace the kill re-read from being last? | **No.** The gate runs at the top of `callUpstream`; `preCallGuard` evaluates drift and the generation predicate but reads `KillGeneration()` *last* and returns `errKilledAtBoundary` first. **Newly walled** — see §5.2. |
| **TOCTOU — Canary demotion mid-flight** | Can an admitted request cross the boundary after a demotion committed? | **No.** `LiveGateDecision.Revalidate` → `generationActive(gen)` is re-checked inside `preCallGuard`; `unarmForDemote` closes admission without a drain precisely so a bounded drain cannot time out into a residual call. |
| **Resource leak → budget exhaustion DoS** | Does a kill/drift/demote abort after gate admission leak the reserved slot? | **No.** `defer release()` is armed immediately after admit and before `preCallGuard`; `release` returns both the budget concurrency slot and the lifecycle in-flight count, and is `sync.Once`-guarded. **Newly walled** — see §5.2. |
| **Fail-open on missing credential broker** | Does a credential-required tool reach the upstream with no `Authorization`? | **No — this window *closed* a fail-open.** `run.go` now blocks `profileRef != "" && Broker == nil` with `ReasonCredentialProfileMissing`; the Shadow evaluator was changed in lock-step so its prediction stays equivalent. This is a strict tightening. |
| **SSRF / MITM on the new upstream client** | Is the production upstream client permissive anywhere? | **No.** `DefaultGatewayPolicy` (https only, no private addresses, no cross-origin redirect, no scheme downgrade), destination pinned at resolve time, `InsecureSkipVerify` never set, per-server SPKI pin is the trust anchor. `prodDestinationResolver` performs no filtering of its own and cannot widen the guard. An unsupported endpoint scheme (`mcp+https://`) fails closed rather than downgrading. |
| **Secret exposure** | Does anything new log or serve key material, paths, or raw errors? | **No.** `mcpLiveProdStatusView` emits only bounded tokens (`kek_ready`/`kek_unavailable`/`pending`) — never the path or the key. Log lines pass `sanitizeLog`. The gate's denial counters are keyed on a fixed `mcperr.Reason` vocabulary (bounded map). |
| **Unsafe file / untrusted search path (KEK)** | Can the credential KEK be attacker-chosen? | ⚠️ **Partially — this is finding F-1 (MEDIUM), see §3.2 and §7.1.** `kekPathNotSymlink` is a genuine new guard, but it defends only the symlink variant. The parent directory is never validated and `secret.FileProvider` checks mode and size but **never ownership**, so a pre-created `0600` 32-byte file is adopted verbatim — no race, no symlink. Unreachable in a shipped build (nothing arms; the broker composes zero providers), but it is a new weakness this window introduces, not a residual of an old one. |
| **Unsafe deserialization** | Any new decode path? | **Tightened.** `strictDecodeCanaryRuntimeJSON` and `strictDecodeLiveQuiesceRehearsalJSON` replaced `dec.More()` with a second-decode-must-be-`io.EOF` check, closing a trailing-token acceptance (`{...}}`). Unknown fields already disallowed. |
| **Unauthenticated information disclosure** | Does the new status reach an unauthenticated surface? | **No.** `mcpLiveTierStatus()` is added only to `apiMCPRollout` (viewer-gated). Nothing was added to `/health`, `/ready`, `/readyz`, or `/healthz`. |
| **DoS — unbounded work on an admin read** | `buildLiveApprovalBindings` is `O(tenants × tools)`. | **Bounded.** `rollout.Limits.MaxSelectors` caps total selector entries at 256, so the worst case is ~16k in-memory map probes; `MaxCanaryTools`/`MaxCanaryTenants` bound a real Canary at 2 × 1. No I/O in the loop. |
| **Nil dereference → panic DoS** | New unguarded globals? | **No.** `mcpToolTrust` is a non-nil package global; `loadTarget` nil-guards the inventory; `mcpLiveExecutorMetrics` deliberately returns a genuine `nil` interface rather than a typed-nil pointer so `execution.New` falls back to `noopMetrics`. |
| **Backward-compat regression** | Does the widened `validateStored` weaken load-time integrity? | **No.** The predicate moved from `Purpose != PurposeShadowEvaluation` to `!Purpose.Issuable()` (still rejects `PurposeUnset` and unknown bytes) and *gained* `validateLiveInvariantsStored`. A downgraded binary rejects a live record fail-closed. |
| **Log injection (CWE-117)** | New log statements with attacker-influenced values? | **No.** Every new `logger.Printf` with a variable uses `sanitizeLog(...)` with `%q` or a bounded token. |

### 3.2 Reachability proof for the arming hook

The one control on which everything else rests is that nothing arms the tier. Verified by
enumeration:

```
$ grep -rn "armLiveTier" --include=*.go .
mcp_live_arming.go:83:  func armLiveTier(...)          # definition
mcp_live_production_deps_test.go:416, 581                # tests
mcp_live_tier_test.go:532, 550                           # tests
```

`armLiveTier` is the sole caller of `mcpLiveTier.arm`, which is the sole caller of
`setLiveExecDepsArmed(_, true)`, which is the sole caller of `markGatewayExecDepsReady`. The
chain has no production entry point and is pinned by the execution-posture wall
(`mcp_execution_posture_test.go`).

---

## 4. Risk rating

| Dimension | Rating |
|---|---|
| **Security severity of findings** | **Medium** — one finding (**F-1**, §7.1: attacker-choosable credential KEK via an unvalidated parent directory), unreachable in a shipped build. No exploitable *regression*. Two informational documentation defects (§6). |
| **Regression risk of the change itself** | **Medium** — the diff adds a new authority (live trust issuance) and a new code path in front of the irreversible side-effect boundary. Mitigated by four independent fail-closed layers and by a large existing test campaign; further mitigated by the two walls added in §5. |
| **Residual risk after this review** | **Low** for the shipped default (nothing arms, and F-1 is unreachable there). **Medium-High** for the deferred real-arming deployment, which must clear §7 — **F-1 is a hard blocker on it**, since arming is what first seals credential material under that KEK. |

---

## 5. Regression walls added

Both are pure test additions. **No production behavior was changed by this review** — consistent
with the standing rule that a regression review never weakens, and never gratuitously alters, a
security control.

### 5.1 `internal/mcp/tooltrust/projection_purpose_test.go`

Pins the **purpose-projection separation at the Store boundary** — the exact place the
`Issuable()` widening could have leaked authority across the live/shadow firewall:

- `TestActiveApprovalProjections_PurposeSeparation` — with one *active* shadow grant and one
  *active* live grant in the same store, `ActiveApprovals` (the `catalog.Usable` promotion
  source) projects only the shadow grant, and `ActiveLiveApprovals` (the Canary preflight and
  side-effect gate source) projects only the live grant.
- `TestActiveLiveApprovals_RevokedGrantLeavesProjection` — revocation withdraws side-effect
  authority immediately at the projection.
- `TestActiveLiveApprovals_ExpiredGrantLeavesProjection` — the grant projects one nanosecond
  before its deadline and stops *at* it, with no status write required.

**Why it was needed.** `TestPurpose_ShadowAndLiveIssuable` pins the `Purpose` predicates and
`TestLiveTrust_ApproveDoesNotPromoteUsable` pins the coordinator-level catalog effect, but
nothing exercised the two `Store` projections. **Non-vacuity verified:** relaxing `activeAsOf`
to `a.Status != StatusActive` alone — the shape the predicate had before the purposes diverged,
and a plausible "simplification" — leaves the *entire* `internal/mcp/tooltrust` package green
except for this new test, which fails with `ActiveApprovals ... got 2`. That is a live grant
materializing Shadow usability with no shadow review.

### 5.2 `internal/mcp/execution/livegate_boundary_order_test.go`

Pins the **side-effect boundary ordering and slot accounting** with the LiveGate wired:

- `TestLiveGate_EmergencyKillOutranksAdmittedGateAtBoundary` — the gate admits, the kill is
  engaged from inside the boundary hook; `Upstream.Call == 0`, reason is
  `rollout_emergency_active` (not the gate's), and `Release` ran exactly once.
- `TestLiveGate_ToolDriftOutranksAdmittedGateAndReleasesOnce` — the gate being consulted
  (`calls == 1`) on a request the drift check aborts is the *structural* proof the gate runs
  before `preCallGuard`.
- `TestLiveGate_DenialReachesNoUpstreamAndReleasesNothing` — table over all four denial reasons;
  no upstream call, the gate's own bounded reason surfaces (never `ReasonNone` or a transport
  fault), and `Release` never runs.
- `TestLiveGate_RevalidateFalseRefusesBeforeUpstreamAndReleasesOnce` — a concurrent demotion
  refuses at the final boundary with `rollout_mode_invalid` and releases once.
- `TestLiveGate_RevalidateTrueStillExecutes` — the **control**: without it, a `Revalidate` wired
  to always refuse would pass every refusal gate above while breaking live execution entirely.
- `TestLiveGate_NilGateLeavesBoundaryUnchanged` — the disabled-by-default path is unaffected.

**Non-vacuity verified** against two independently reintroduced defects:

| Reintroduced defect | Tests that fail |
|---|---|
| Drop `defer release()` after gate admit (slot leak → budget exhaustion) | 4 of 6 |
| Move the gate call *after* `preCallGuard` (kill re-read no longer last) | 2 of 6 |

---

## 6. Documentation defects (informational, no code impact)

**6.1 `internal/mcp/canary/trust.go:66–69` is now false.** The doc comment on
`SatisfiesLiveExecution` still states *"Issuance of live_execution remains refused fail-closed
elsewhere (tooltrust Issuable), so in this build no approval object of this purpose is producible
in production."* PR #1289 made it producible. A reader auditing the live path could conclude the
predicate is unreachable and skip it. Recommend updating to point at the governed issue path.

**6.2 `mcp_live_startup.go:18–26` is now false.** The `DEFERRED PRODUCTION DEPENDENCY WIRING`
block states *"There is deliberately NO production caller of `composeGatewayLiveTierInto` in this
build"*. PR #1291 added exactly one (`composeProductionGatewayLiveTier`). The claim it supports —
that a stock build composes nothing — remains true for a different reason (the env opt-in), so
the posture is unchanged, but the stated reason is stale.

Neither is a code defect and neither changes behavior; both are recorded rather than fixed here
so that this review changes no production file.

---

## 7. Residual risk

**7.1 The credential KEK is adopted from an unvalidated directory — attacker-chosen key material
(MEDIUM; corrected after review).**

> **Correction.** The first version of this section rated this *low* and justified it with
> "both require write access to a root-owned data directory, so the precondition is already a
> compromise." That was wrong, and the reasoning was an assumption I did not verify against the
> code. It was caught by the Codex review bot on PR #1296 and is corrected here. The original
> framing also described only a symlink TOCTOU; the primary variant needs neither a symlink nor
> a race.

**The path is unconstrained.** `CULVERT_MCP_LIVE_CREDENTIAL_KEK` is a free absolute path.
`validateMCPLiveProductionConfig` checks only `IsAbs` and `Clean`-idempotence; nothing confines
it to `dataDir`, and nothing validates the parent directory's owner or mode. An operator may
legitimately point it at a shared or group-writable location.

**The provider checks mode and size, never provenance.** `fileProvider.kek()` calls `os.Stat`;
if the file exists it calls `load()`, which rejects `perm & 0o077 != 0` and a length other than
`KEKLen`, then returns the bytes. There is **no ownership check** — `fileProvider` carries only
a `path` field. Empirically confirmed against `internal/secret`: a pre-created `0600`, 32-byte
file is adopted **verbatim** as the KEK, with `ValidateProvider` returning nil.

**Primary attack — no race, no symlink.** An attacker who can write the parent directory
pre-creates the KEK file with `0600` and 32 bytes they chose. `kekPathNotSymlink` does not fire
(it is a regular file). `load()` accepts it. Every credential subsequently sealed by the broker
is sealed under a key the attacker knows. This defeats the entire point of model-B at-rest
protection for MCP credential material.

**Secondary attack — the TOCTOU.** `acquireProductionKEK` lstats the final component and
`secret.FileProvider` then opens with `os.Stat`/`os.ReadFile` and no `O_NOFOLLOW`, so the final
component can also be swapped for a symlink between the two. The code documents only the
*parent-directory* race; this final-component swap is the same class and is not called out.

**Exploitability / impact.** Preconditions: write access to the KEK's parent directory, and an
operator who set `CULVERT_MCP_LIVE_DEPS` — which no shipped node does. Impact if reached:
attacker-known KEK for credential material at rest (CWE-427 untrusted search path / CWE-732
incorrect permission assignment; OWASP A04 Insecure Design). **Current exposure is nil** — the
tier never arms, and the broker composes with *zero* providers, so nothing is sealed under this
KEK yet. But that is a statement about today's reachability, not about the control, and this
section exists precisely for the deferred arming deployment.

**Recommended fix** (production change; deliberately not made in this review PR, because
choosing the acceptable-ownership policy is an owner decision — see §8). Add a parent-directory
guard beside `kekPathNotSymlink` in `mcp_live_production_deps.go`, so `internal/secret` and the
telemetry KEK are untouched:

```go
// kekParentTrusted rejects a KEK whose parent directory is writable by group or other, or is
// owned by neither the running process nor root — either lets a third party pre-create or swap
// the key file, which load() would accept (it checks mode and size, never ownership).
func kekParentTrusted(path string) error {
    fi, err := os.Stat(filepath.Dir(path))
    if err != nil { return err }
    if !fi.IsDir() { return errLiveDepsKEKParentNotDir }
    if fi.Mode().Perm()&0o022 != 0 { return errLiveDepsKEKParentWritable }
    st, ok := fi.Sys().(*syscall.Stat_t)
    if !ok { return errLiveDepsKEKParentUnverifiable } // fail closed
    if int(st.Uid) != os.Getuid() && st.Uid != 0 { return errLiveDepsKEKParentForeignOwner }
    return nil
}
```

Note the container runs as the non-root `proxy` user (`Dockerfile:99`), so a *root-owned-only*
rule would be wrong; owned-by-self-or-root with no group/other write is the correct policy and
mirrors the existing `0600` file doctrine. This closes the primary attack outright and narrows
the TOCTOU to a directory the attacker cannot write. Pushing an `O_NOFOLLOW` open into
`internal/secret` would additionally close the residual final-component race and would also
protect the telemetry KEK, which has no symlink guard at all today — but that changes a shared
credential path and belongs in its own reviewed change.

**Required tests for the fix:** positive (trusted parent accepted); negative (group-writable,
other-writable, foreign-owner parent each rejected with its own bounded reason); boundary
(parent `0755` root-owned accepted, `0775` rejected); malformed (parent missing, parent not a
directory); regression (a pre-created foreign 0600 32-byte KEK is refused — the test that fails
against today's tree).

**7.2 Live TTL ceiling is not enforced at rest (low).** `validateLiveInvariantsStored` enforces
four-eyes and the presence of an expiry for an *active* live record, but not
`ExpiresAt - ApprovedAt ≤ MaxLiveExecutionApprovalTTL`. A hand-edited store could therefore hold
an active live record claiming a 30-day window, and it would *display* as active on the admin
surface. It cannot authorize anything: `SatisfiesLiveExecution` re-checks the ceiling at
consumption and refuses. Deliberately **not** fixed here — `Load` fails the *whole* store closed
on any invalid record, so adding the check would convert one tampered record into a total
tool-trust outage, and the consumption path already fails closed. Recorded for an owner decision.

**7.3 Fingerprint comparison is case-strict in one path and case-insensitive in another (very
low).** `mcpLiveTrustRevalidate` compares `hex.EncodeToString(...) != decisionFP` exactly, while
`canary.ValidateScopeApprovals` uses `strings.EqualFold` for the same digest. Both producers emit
lowercase (`runtime/policy.go:214`), so the two agree today, and the divergence errs in the
fail-closed direction at the gate. Worth unifying if a third producer is ever added.

**7.4 Pre-Canary connectivity gaps are recorded, not defects.** The documented `mcp+https://`
endpoint scheme and SPIFFE-format `PinnedIdentity` are not consumable by the production upstream
client. Both fail *closed* (unsupported scheme rejected by `destination.Canonicalize`; a SPIFFE
identity read as an SPKI digest mismatches). They are correctly tracked as pre-Canary work.

**7.5 The deferred real-arming deployment remains the highest-risk future step.** Everything in
§1 rests on `armLiveTier` having no production caller. Whichever change adds one must be
reviewed as its own window, and should be gated on: **F-1 fixed** (§7.1 — arming is what first
seals credential material under the KEK, so an attacker-choosable KEK stops being theoretical at
exactly that moment), a real credential `Provider` adapter (the broker currently composes with
**zero** providers registered, which is the honest fail-closed posture), an authoritative budget
store, and a completed `CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL` for that build.

---

## 8. Verdict

The window is **safe to ship**, with F-1 tracked as a blocker on the *next* window rather than
this one. The changes consistently move in the restrictive direction: a new fail-closed branch
for a credential-required tool with no broker, a stricter JSON end-of-stream check in two
decoders, a response-profile capability + output-bound check at composition, a symlink guard on
the KEK path (partial — see F-1), four-eyes and a hard TTL ceiling enforced at three separate
layers for the new trust purpose, and a final-boundary generation revalidation that can only make
an admitted request more restrictive. The one genuinely new authority — issuable `live_execution`
trust — arms nothing on its own and is walled from the Shadow usability projection by a purpose
predicate that this review has now pinned with a test.

The one thing that must not be lost between windows: **F-1 is invisible today precisely because
the feature is off.** It will become live in the same change that turns the feature on, which is
the worst moment to discover it. §7.1 carries a ready-to-apply patch and its test roster.

**A note on this review's own process.** The first draft rated F-1 "low" and supported that with
"the precondition is already a compromise" — an assumption about directory ownership that the
code does not enforce and that I did not check. A review bot caught it. The lesson generalises
beyond this file: a residual-risk rating is a security claim like any other and needs the same
source-level verification as the findings, or it becomes the place where real issues go to be
quietly downgraded.

---

*Files added by this review:*
`internal/mcp/tooltrust/projection_purpose_test.go`,
`internal/mcp/execution/livegate_boundary_order_test.go`.
*No production file was modified.*
