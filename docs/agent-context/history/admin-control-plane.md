# Preserved source: Admin Control Plane

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [Admin control plane, invariants, test pitfalls](#claude-main-l273-l346)

<a id="claude-main-l273-l346"></a>

## Admin control plane, invariants, test pitfalls

[Original lines 273–346](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L273-L346) · `claude-main-L273-L346`

<!-- BEGIN preserved-block: claude-main-L273-L346 -->
## Admin UI / Control Plane

The admin API is wired in three layers — `startUI()` only composes them, never registers routes itself.

**Route registration**
- `startUI()` MUST NOT contain `mux.HandleFunc` calls. All routes are registered through per-domain `register*Routes(mux, ...)` helpers (e.g. `registerPolicyRoutes`, `registerSecurityRoutes`).
- `uiRoutes` in `ui_routes_meta.go` is the **single source of truth** for route metadata. Adding a route means: (1) register it via a `register*Routes` helper, (2) add a corresponding `uiRouteMetadata` entry to `uiRoutes`.
- Metadata is **method-aware** via `Methods []uiRouteMethod`. Each entry declares `Method`, `MinRole`, `Mutating`, `AuditExpected`, plus an optional note. `MethodAny` (`"*"`) is the catch-all when a handler intentionally treats every method the same.

**Middleware chain (outer → inner)**

```
uiIPGuardMiddleware → securityMiddleware → uiAuthMiddleware → uiMetadataEnforcement → mux
```

- `uiAuthMiddleware` owns the public-route allowlist and injects `uiRoleKey{}` into the request context.
- `uiMetadataEnforcement` (C2) reads that role and gates the request against per-method `MinRole` from `uiRoutes`. **Active by default** — fail-closed.
- `securityMiddleware` still owns CSRF, body-limit, and rate-limit decisions based on the HTTP method. The `Mutating` flag in metadata is **informational only**; it does not alter middleware behavior.

**Kill switch**
- `CULVERT_C2_ENFORCE=false` (or `0`/`no`/`off`) reverts C2 to shadow mode (log-only, never blocks). Read once at startup; admin-API runtime mutation is intentionally not supported.

**AuditExpected (C2c)**
- Pure observability. After a 2xx/3xx response, if metadata says `AuditExpected=true` and no `auditEvent`/`auditEventDiff` ran, the middleware emits one `C2: audit missing ...` log line and increments `c2AuditMissingTotal`. Failed requests, hijacked responses, and public routes are skipped. C2c **never** blocks a request.

**Role-divergence detector (C4 — REPORT-ONLY)**
- Pure observability. When the C2 middleware admits a request whose per-method `MinRole` is *lower* than what the handler-level `requireRole` ultimately demands (e.g. `apiIdPRouter` declares `MethodAny=viewer` but `apiIdPItem`'s PUT branch calls `requireRole(RoleAdmin)`), C4 increments `c2RoleDivergenceTotal` and emits one `C2: role divergence ...` log line. The middleware injects the C2-evaluated `MinRole` into the request context; `requireRole`'s failure branch reads that value and compares against the role it just rejected.
- C4 **never** blocks, allows, or alters the response. The handler's existing `requireRole` writes the 403 itself; C4 only observes the decision after the fact. Defense-in-depth (invariant #6) is preserved; the handler is still the real backstop.
- Audit ring is intentionally untouched — divergence events are governance observability, not admin-action audit. They flow out via the structured logger and the C3 governance endpoint only.

**Governance surface (C3)**
- `GET /api/governance/control-plane` (admin-only) exposes route inventory, C2 mode, the six C2 counters, derived health (four axes), and the parity-test pyramid (D0/C1/C1.5/C2/C2c/C4). Read-only and side-effect-free; no Prometheus exposure, no AST replay, no schema mutation. The kill switch stays env-only and read-once.
- C3 health severity policy (`deriveGovernanceHealth`):
  - `missing_meta > 0` → `metadata_parity = drift`, status = `drift`. C1 reverse-parity should make this impossible at runtime, so any non-zero value is genuine governance/config drift.
  - `no_policy > 0` → `metadata_parity = warn`, status ≥ `warn`. The counter can be triggered by a client sending a method the route does not accept (e.g. PATCH against a GET-only route, scanner probes); reserving drift for `missing_meta` keeps the indicator from flipping to drift on benign client traffic.
  - `audit_missing > 0` → `audit_completion = warn`, status ≥ `warn`.
  - `enforce_denied > 0` while `mode = shadow` → `enforce_consistency = drift`, status = `drift` (the kill-switch contract is read-once at startup).
  - `role_divergence > 0` → `role_divergence = warn`, status ≥ `warn`. Triggered legitimately by viewers probing admin-only sub-actions on dynamic dispatchers; reserved for warn rather than drift to avoid noise on benign client traffic.
- The six C2 counters surfaced by C3 (one-line definitions):
  - `would_deny` — session role was below the per-method `MinRole`. Increments in BOTH shadow and enforce modes; tracks the policy decision regardless of action.
  - `enforce_denied` — request actually got a 403 from the metadata-driven gate. Stays at zero in shadow mode; in enforce mode it moves in lock-step with `would_deny`.
  - `missing_meta` — request path resolved through the mux but had no matching `uiRoutes` entry (the static `/` catch-all absorbs unknown paths, so this is rare in practice). Soft-fail; never blocks a request.
  - `no_policy` — path matched a `uiRoutes` entry but the HTTP method had no exact policy and no `MethodAny` fallback. Soft-fail; never blocks a request. Triggered both by genuine drift and by clients sending unsupported methods (see severity policy above).
  - `audit_missing` — successful request (2xx/3xx) on an `AuditExpected=true` route did not emit an `auditEvent`/`auditEventDiff` call (C2c observability).
  - `role_divergence` — handler-level `requireRole` rejected a request whose C2-evaluated `MinRole` was strictly lower (i.e. metadata was more permissive than the handler's actual contract). Increments at most once per request, on the failure branch of `requireRole`. Observability only; never blocks.

### Admin UI / Control Plane Invariants

These are non-negotiable for any change touching the admin API:

1. **No route without metadata.** Every `mux.HandleFunc` path must have a matching `uiRoutes` entry. C1 forward/reverse parity tests enforce this.
2. **Metadata must never be more permissive than handler behavior.** If the handler enforces admin, metadata cannot say viewer. C1.5 AST parity tests enforce this for directly detectable handler behavior; dynamic/delegated handlers must be documented and reviewed.
3. **Resolution order: specific method > MethodAny > soft-fail.** Don't use `MethodAny` to paper over a method-specific contract.
4. **Missing metadata / no method policy must NEVER block requests.** Both are soft-fail in shadow and enforce mode — they log + count, the handler-level `requireRole` remains the real backstop.
5. **Public routes are owned by `uiAuthMiddleware` only.** C2 stays out (`RolePublic` is documentation, not enforcement). Don't add public-route gates to C2.
6. **Do not remove handler-level `requireRole`.** C2 is an additional gate, not a replacement. Defense-in-depth is the contract.
7. **C2 must never allow what the handler denies.** If they ever disagree, the handler wins by design — C2's role is to add denials, never to widen access.
8. **A role requirement no build enrolls is unsatisfiable (SEC-RBAC-ROLE-1).** `rolePriority` membership *defines* an enrolled role, and `HasRole` fails closed on BOTH sides. The `min` side used to not: a map read of an unenrolled key yields 0, so a requirement nobody enrolled became one every authenticated role met — `MinRole: RolePublic` on a non-public route, or a typo like `"Admin"`, would have admitted a viewer to that method with only the handler's own `requireRole` left as a gate (and 12 route methods document that they have none). `TestRoleMetadata_MinRoleIsAlwaysEnrolled` pins that no non-public route carries an unenrolled `MinRole` and that `RolePublic` appears only on `Public: true` routes; `RolePublic` stays deliberately out of `rolePriority` — it is documentation, not an enforcement primitive, in either direction.

### Testing Guarantees

Each layer has its own test suite — keep them green when modifying the admin API.

- **D0** (`d0_*_test.go`) — route/auth/security baseline invariants: route inventory pinned at the canonical count, auth allowlist, CSRF, body-limit, and rate-limit checks.
- **C1** (`ui_routes_meta_test.go`) — bidirectional route/metadata parity layer: forward (every `uiRoutes` entry has a matching `mux.HandleFunc`) and reverse (every `mux.HandleFunc` has a matching `uiRoutes` entry), source-scan based.
- **C1.5** (`ui_routes_meta_audit_test.go`) — AST-walk parity between metadata `MinRole`/`Mutating` and the per-method behavior of each handler (`requireRole` calls, method switches).
- **C2** (`ui_metadata_enforcement_test.go`) — middleware enforcement: shadow mode is silent, enforce mode returns 403, kill switch toggles correctly, missing-meta and no-policy stay soft-fail.
- **C2c** (`ui_metadata_enforcement_test.go` — `TestC2c_*`) — audit-completion observability: warns on success without audit, silent on failure / hijacked / public / `AuditExpected=false`, never blocks the request.
- **C4** (`ui_metadata_divergence_test.go` — `TestC4_*`) — report-only role-divergence detector: increments `c2RoleDivergenceTotal` and emits a structured log line when the handler's `requireRole(R)` rejects a request whose C2-evaluated `MinRole` was strictly lower. Tests cover the canonical viewer-on-admin-route case via `apiIdPRouter`, the parity case (no event), the C2-stricter case (no event), and the response-decision invariance proof (C4 cannot change the 403 the handler already wrote).

### Test-authoring pitfalls

- **Audit ring saturation.** The in-memory audit ring is bounded at `maxAuditLogs = 500`. Tests MUST NOT assert on `len(auditGet())` deltas (e.g. `len(after) == len(before)+1`) because under `-count=2 -shuffle=on` the cumulative suite saturates the ring and `len()` stops growing — adding a new entry evicts the oldest. The determinism gate (`QA · Determinism`) re-runs the suite shuffled to flush these out. Instead, assert on entry **content**: scan `auditGet()` for an entry matching a unique discriminator (`Actor` IP from a TEST-NET-2 reserved range, plus `Action`/`Object`, plus a baseline `TS` captured before the call). See `security_feedsync_audit_test.go` for the canonical pattern.
- **`setupProxyTest` clears globals at test START, never at cleanup.** Its comment reads "resets all global state for a clean test run", which is true in one direction only: it stops a previous test's leaked rules flowing IN and does nothing to stop this test's rules flowing OUT. A test that adds a rule must register its own restore (`snapshotPolicyStoreForTest(t)`, or a helper that calls it such as `draftTestSetup`). **A partial cleanup is worse than none**: CHAOS-69's cost gate added a rule referencing a category group and cleaned up only the GROUP, so the surviving rule pointed at nothing and the next test whose path validates object references — a config import in `TestUpstreamV2D_R34_DryRunReturnsPlanAndDigestAppliesNothing` — refused with `dangling object reference`, reachable only under `-shuffle` and only as a red required determinism gate. Leaking BOTH would have left the reference resolvable. `t.Cleanup` is LIFO, so register the store restore AFTER the group delete so it runs BEFORE it. `TestChaos69_WallEveryGateThatMutatesPolicyRestoresIt` is the structural wall for that file (the failure is invisible to every behavioural assertion in it), and its allowance for `draftTestSetup` is self-checking — it re-reads that helper and fails if it stops restoring, so the allowance cannot become a hole. The same shape applies to any process-global a test writes: `requireCommitFlag` (a leaked armed Draft Mode makes `effectivePolicySnapshot` serve an empty candidate) and `authExemptDisabledRuntime` (a leaked kill switch suppresses every matching Exempt rule) are the two that bite the policy surfaces most often.
<!-- END preserved-block: claude-main-L273-L346 -->
