# Security Regression Review — MCP PR-12 / IdP-Registry Window

- **Date:** 2026-08-18
- **Reviewer role:** Security Regression Engineer (standing charter, `docs/engineering/ENGINEERING-CONSTITUTION.md`)
- **Baseline:** `bc67b7b` (last reviewed clean point before this window)
- **Tip under review:** `b697cf3`
- **Window:** PRs #1117, #1120, #1122, #1125, #1126 — dominated by the MCP CP→DP
  production composition + distribution/rollout transaction (PR-12, #1126) and the
  CHAOS-49 identity-registry hardening (#1117).

## Verdict

**One security regression found and fixed** (SEC-JWKS-1, Medium — an unbounded
stale-JWKS trust window that silently disables IdP signing-key revocation).
Three lower-severity defects fixed alongside it. Everything else in the window is
either byte-faithful or strictly tighter than the baseline.

| ID | Finding | Severity | Class | Status |
|----|---------|----------|-------|--------|
| SEC-JWKS-1 | Cached JWKS keys authenticate **forever** once refreshes stop succeeding — an IdP key revocation never takes effect | **Medium** | CWE-672 / CWE-613 · OWASP A07 (Identification & Authentication Failures) | Fixed |
| SEC-MCP-1 | DP pre-check rejections nack with `ReasonNone` — a capability-confusion attempt is unclassifiable at the CP | Low | CWE-778 (insufficient logging) · OWASP A09 | Fixed |
| SEC-LOG-1 | Five new `logger.Printf` sites log an `error` without `sanitizeLog` | Low | CWE-117 · OWASP A09 | Fixed |
| SEC-RACE-1 | `resolveMCPDPNodeID` reads mutex-protected `clusterRole` without the lock | Low | CWE-662 (improper synchronization) | Fixed |

---

## SEC-JWKS-1 — Unbounded stale-JWKS trust window

**Files:** `auth_oidc_flow.go` (`jwksCache.getKey`, `refresh`)
**Introduced by:** PR #1117 (CHAOS-49), commit `af3fe90`

### What changed

CHAOS-49 correctly fixed two real state-corruption bugs: `refresh()` used to install
whatever it parsed, so an HTTP 503 with a JSON body, or a 200 carrying no *usable*
keys, **wiped** the cached key set — destroying `getKey`'s "return the stale key
rather than failing" fallback and producing a silent fleet-wide SSO outage. The fix
added a `resp.StatusCode != 200` guard and a `len(keys) == 0` guard, both of which
now return an error and **keep** the existing cache.

That is the right fix. What it also did, without intending to, was remove the only
bound — accidental though it was — on how long a stale key set may keep
authenticating.

### The defect

```go
if err := j.refreshOnce(); err != nil {
    if ok {
        return k, nil // return stale key rather than failing   ← no age limit
    }
    return nil, err
}
```

`fetchedAt` advances only on a *successful* refresh. Once refreshes fail
persistently, this branch serves the same keys indefinitely. There is no ceiling
anywhere in the type: `fetchedAt` is read in exactly one place, compared against
`jwksCacheTTL`, and that comparison only decides whether to *attempt* a refresh.

### Why it matters

Withdrawing a signing key from the JWKS document is the IdP's **only** revocation
lever over tokens it has already minted. A relying party that keeps a withdrawn key
forever has silently opted out of revocation — and the window closes only on a
successful refresh, which is precisely what is broken in the scenario where you need
revocation to work.

The affected consumer is `validateIDToken` (`auth_oidc_flow.go`), the OIDC
Authorization-Code + PKCE path: admin-UI SSO and the captive portal. Group claims
from that token drive RBAC, so the ceiling of impact is admin access.

### Attack scenario

1. An IdP signing key is compromised (leaked HSM export, a breached signing service,
   a mis-scoped CI secret). The IdP rotates and **removes** the old key from its JWKS
   document. Tokens already minted under it are now expected to stop being accepted
   once relying parties refresh.
2. Culvert's JWKS refresh fails persistently for this appliance. Any of:
   the JWKS host becomes unreachable from the appliance (egress policy, DNS, an
   expired origin certificate); the endpoint returns a non-200 (now rejected by the
   new status guard); or the response yields no keys this build can parse — e.g. a
   rotation to key types the parser does not handle, or a WAF/rate-limiter JSON body
   (now rejected by the new `len(keys) == 0` guard). **Both new guards make a
   "failed refresh" state more likely to persist**, which is correct for the outage
   they fix and is what makes the missing ceiling matter.
3. The attacker presents an ID token signed with the compromised, revoked key.
   `getKey` serves the cached key; `validateIDToken` verifies the signature and
   accepts. Issuer, audience, `exp`, and the RSA-only signing-method pin are all
   satisfied because the token is otherwise perfectly well-formed — none of those
   controls says anything about whether the *key* is still trusted.
4. Access persists for as long as the refresh stays broken. Indefinitely.

**Preconditions:** IdP signing-key compromise **and** a persistent JWKS refresh
failure from the appliance. Both are individually ordinary operational events.
**Exploitability:** Low-to-moderate — the attacker does not control step 2, but does
not need to: it is a naturally occurring failure state, and the attacker can simply
wait for one. **Likelihood:** Low. **Impact:** High — authentication bypass with
attacker-chosen group claims. **Affected assets:** admin UI sessions, captive-portal
identity, RBAC role assignment.
**Regression risk of the pre-fix code:** the fix *changed the security posture* of a
revocation-relevant path while fixing an availability bug, without a compensating
bound. This is exactly the class this review exists to catch.

### Fix

`auth_oidc_flow.go` — a hard ceiling on stale-key trust:

- `jwksStaleMaxAge = 24 * time.Hour`, a **constant**. An operator override would be
  a knob whose only use is widening a trust window; immutable beats configurable for
  a fail-closed bound (implementation rule: prefer immutable configuration).
- `staleServable(fetchedAt)` gates the stale branch. A zero `fetchedAt` (no fetch
  has ever succeeded) is never servable.
- Past the ceiling, `getKey` returns `errJWKSStaleCeiling` — **fail closed**.
- `logStaleRefusal` emits one rate-limited line at the transition. Without it, the
  move from "degraded but working" to "authentication is failing" is invisible:
  `refreshOnce`'s existing line says cached keys are still being served, which stops
  being true here.
- Recovery is on **observed evidence** only — one refresh that actually returns
  usable keys re-arms the full window by advancing `fetchedAt`. Elapsed time never
  does. This matches the recovery discipline in `storage_health.go`, `ca_health.go`,
  and the `identity_backend` contract row.

Inside the ceiling, behaviour is byte-identical to the post-#1117 code, so the
CHAOS-49 availability win is fully preserved: a blip, a rate-limiter body, or a
multi-hour outage still cannot cause an SSO outage.

### Required tests — `auth_oidc_jwks_stale_ceiling_test.go`

All five gates were run against the pre-fix behaviour; the three refusal gates
**failed there** and pass with the fix.

| Gate | Kind | Asserts |
|------|------|---------|
| `TestJWKS_StaleKeyStillServedInsideCeiling` | Positive | the availability contract survives — stale-but-inside still authenticates |
| `TestJWKS_StaleKeyRefusedPastCeiling` | Negative / regression | past the ceiling, a stale key is refused |
| `TestJWKS_StaleKeyRefusedPastCeilingWhenThrottled` | Boundary | the refresh rate limiter cannot widen the trust window |
| `TestJWKS_SuccessfulRefreshReArmsTrustWindow` | Regression | recovery is on observed evidence, and `fetchedAt` really advances |
| `TestJWKS_FreshKeySetNeverRefused` | Positive | a fresh key set is never subject to the ceiling |
| `TestJWKS_TrustWindowConstantsAreOrdered` | Boundary | `jwksMinRefreshInterval < jwksCacheTTL < jwksStaleMaxAge` |

Concurrency is already covered by the existing
`TestJWKS_ConcurrentMissesCoalesceIntoOneFetch`; the ceiling reads the same
`mu`-guarded `fetchedAt` and adds no new shared state beyond a rate-limit stamp.

### Residual risk

A compromised key is still accepted for up to 24 h of broken refreshes. Shortening
the constant trades revocation latency against SSO availability during an outage;
24 h absorbs any realistic outage while bounding what was previously unbounded. A
future improvement would route the refusal through the `identity_backend`
operator-contract row and the `identity_backend_unreachable` alert so the ceiling is
visible on `/api/diagnostics` before it starts denying — deferred because
`jwksCache` has no backend identity today and threading one through would change the
health-plane contract.

---

## SEC-MCP-1 — Pre-check rejections nack with no reason code

**Files:** `mcp_rollout.go`, `mcp_distribution.go` (`applyMCPCapabilityEnvelope`)
**Introduced by:** PR #1126

`applyMCPCapabilityEnvelope`'s two pre-check rejections passed bare
`errors.New` sentinels to `Applier.RejectAck`. The acknowledgement's `RejectReason`
is derived by `mcperr.ReasonOf(cause)`, which walks the chain for an `*mcperr.Error`
and otherwise yields `ReasonNone` — so **both** rejections reached the Control Plane
with the same empty classification. Worse, the capability-mismatch branch was passed
`errRolloutPersistFailed`, actively mislabelling it.

That branch is the capability-confusion case: a Gateway envelope carrying a
Management rollout config (or the reverse) — the exact shape the Gateway/Management
isolation boundary exists to reject, and the one a fleet operator most needs to
alert on. The *rejection* was always correct and fail-closed; only its reporting was
not. Fixed by giving both sentinels real reasons
(`ReasonSnapshotCapabilityMismatch`, `ReasonRolloutTransitionInvalid`); sentinel
identity is preserved, so the existing `err != errShadowExecDepsNotConfigured`
comparisons in `mcp_rollout_durable_test.go` are unaffected.

**Tests:** `mcp_distribution_reject_reason_test.go` — reasons are non-`None`,
distinct, correctly valued; sentinel identity survives; `RejectAck` propagates the
reason to the wire and stages no state.

## SEC-LOG-1 — Unsanitized error logging

**Files:** `mcp_rollout.go` (5 sites)
**Introduced by:** PR #1126

Five new `logger.Printf` sites logged an `error` with `%v` and no `sanitizeLog`,
against the project convention (CLAUDE.md: wrap user input with `sanitizeLog` and
use `%q`; CodeQL recognises the `strings.ReplaceAll` inside it). Adjacent new lines
in `mcp_distribution.go` do sanitize, so this is inconsistency rather than intent.

Practical exposure today is nil — the error chains carry fixed `mcperr` messages, a
constant path basename, and OS errors — with the partial exception of the restore
path, which wraps a `json.Unmarshal` error over on-disk state-file content. Fixed
uniformly rather than argued case-by-case: the convention is a defence-in-depth wall
and is worth more intact than reasoned around.

## SEC-RACE-1 — Unsynchronized `clusterRole` read

**Files:** `mcp_distribution_startup.go` (`resolveMCPDPNodeID`)
**Introduced by:** PR #1126

`clusterRole` is documented in `controlplane.go` as protected by `clusterRoleMu`.
The new shim read `clusterRole.nodeID` without it. Not a live data race today —
`nodeID` is written only by `startDataPlane` on the main goroutine, earlier in
startup, while `enableControlPlane` (reachable concurrently from the HA
auto-promote goroutine that `initCluster` already started) writes only *other*
fields. That is a coincidence of current field membership, not an invariant. Fixed
by taking the documented read lock.

---

## Surfaces reviewed and cleared

### MCP CP→DP distribution/rollout transaction (PR-12, #1126)
The core invariant holds: an `AckApplied` is impossible unless both the distribution
active state and the local rollout state accepted the same revision.

- **Pre-check ordering is sound.** The rollout precondition is evaluated on an
  *unverified* envelope, before `Apply` verifies the signature — but it can only ever
  *reject*, never accept or activate, so it grants no bypass. Everything that
  proceeds is still fully signature-, epoch-, revision-, and bounds-verified inside
  `Apply` before any rollout config is trusted. There is no unsigned local shortcut.
- **`AbortApplied` compensation is correct and fail-closed.** Persist-before-swap is
  preserved; the pending `Applied` ack is replaced by a `Rejected` one; the epoch
  ratchet is deliberately never moved backwards. Traced the post-abort recovery
  path: the persisted `Epoch` exceeds `Current.Manifest.Epoch`, which `verifyRecovered`
  does not object to, and `CheckEpoch` accepts an equal epoch while `CheckMonotonic`
  re-bases on a higher one — so a CP retry of the aborted envelope is accepted rather
  than permanently wedged. Verified, not assumed.
- **Fail-closed layering on executing modes is genuine and defence-in-depth.**
  `execDepsConfigured` is false in the shipped build and is enforced at three
  independent points: the transaction pre-check, `commitRolloutTransition`, and the
  `restore()` clamp that refuses a hand-crafted state file claiming an executing mode.
  A signed Production envelope fails closed at the same gate — the signed path cannot
  bypass the Production lock.
- **Trust resolution fails closed.** `resolveMCPDistributionStartupConfig` validates
  algorithm and `ed25519.PublicKeySize` and resolves every parse/decode/trust error
  to `Enabled=false` with a bounded reason; a per-capability `Recover` failure
  registers **no** applier for **either** capability. Unset ⇒ byte-identical
  disabled-by-default posture.
- **Status surface is secret-free** — `dp_trust_key_ids` carries public key ids only.
- **RBAC unchanged.** The new persisting write paths (`emergency`, `rehearse-rollback`)
  remain `RoleAdmin`; the metadata-driven C2 gate and handler `requireRole` are both
  intact, so the added disk-write side effect is not reachable below admin.
- **Persistence is safe.** `fileutil.AtomicWrite`, mode `0600`, fixed paths under
  `dataDir`; no traversal, no symlink follow, no temp-file predictability, no secret
  in the DTO. `LoadPersist` re-validates and degrades to `Disabled` on any error.
- **Kill switch is correctly non-widening.** `SetConfig` preserves `killed`, so a
  CP-pushed config cannot clear a local emergency disable, and `LoadPersist` restores
  it across a restart.

### IdP registry hardening (#1117 + `2d5b757`)
Cleared apart from SEC-JWKS-1. The status/4xx guards, single-flight, negative
window, introspection result cache, and probe gate are all correct. The
`isIntrospectClientError` classification is well-argued and lands on the right side
of the asymmetry: 401 is provider-wide (RFC 7662 §2.3 — a caller's token travels in
the POST body and cannot provoke it), while 403 is deliberately excluded because
treating an attacker-reachable status as provider-wide would hand an unauthenticated
caller a lever to arm the gate for everyone. Cache keys are HMACed (`cacheKey`), the
map is bounded by `maxAuthCacheSize`, TTL is clamped to the token's declared `exp`,
and only authoritative verdicts are cached. `validateIDToken` still pins issuer,
audience, `exp`, and RSA-only signing methods.

### Readiness-detail disclosure (#1122) and installer at-rest encryption (#1120)
Both are hardening in the correct direction — narrowing what an unauthenticated
`/readyz` publishes, and closing a path that left the CA key unencrypted when only
the log passphrase was pre-set. No regression; no change made.

---

## Not changed, and why

- **MCP evidence integrity (recorded as residual risk, not a finding).** PR-12
  correctly makes the rollout evidence window restart-durable — a window that reset
  on restart made any claimed ≥14-day continuous Shadow qualification mechanically
  invalid. The residual is that the evidence (`shadow_start_unix`,
  `rollback_rehearsed`, `origin`) is now restored verbatim from an unauthenticated
  node-local JSON file, so the module's "MEASURED, never fabricated" claim rests on
  file permissions alone. Not raised as a finding: the file is `0600` under an
  operator-owned `dataDir`, an attacker with that access already owns the appliance,
  and the qualification gate is a process control rather than a runtime enforcement
  boundary. Worth a signed or CP-anchored evidence record if the qualification gate
  ever becomes load-bearing for an automated promotion.
- **`sameModeSameScope` ignores the shadow scope.** `State.ScopeHash()` covers the
  primary compiled scope only, so a change confined to `ShadowScope` preserves the
  evidence window. Reviewed and left alone: the shadow scope never changes what is
  *enforced* (it only decides whether an out-of-canary subject gets Shadow rather
  than Observe behaviour), so it is not a material change for window-continuity
  purposes in either direction.
- **`AbortApplied` drops `Previous`.** Rollback retention for the pre-abort
  predecessor is lost, so a later signed rollback to it fails "target not retained".
  Fail-closed and availability-only; changing retention semantics is a design
  decision for the distribution owner, not a security fix.

## Method

Diffs read in full against their pre-images for every non-test file in the window.
Hypotheses about fail-closed behaviour were verified against the engine source
(`internal/mcp/cpdp/apply`, `internal/mcp/rollout`, `internal/mcp/mcperr`) rather
than trusting the commentary, which is unusually thorough in this window and
therefore unusually easy to take on faith. SEC-JWKS-1 was reproduced empirically:
the refusal gates were run against the pre-fix behaviour and observed to fail.
`go build ./...`, `go vet ./...`, and `gofmt -l` are clean; the full suite runs green
under `-race -count=1`.
